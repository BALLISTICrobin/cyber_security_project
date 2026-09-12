#!/usr/bin/env python3
"""
Educational web dashboard for the optimistic-TCP-ACK-attack project.

This is a thin control panel over the REAL project: it runs the exact same
`docker compose exec ...` commands the shell scripts and README use, just
from buttons instead of a terminal, and turns `ss -ti` polling into live
charts instead of raw text snapshots.

It does NOT run inside Docker -- it runs on your host and drives the
containers, so it needs `docker` and `docker compose` on your PATH and the
testbed's docker-compose.yml one directory up.

Zero third-party dependencies (stdlib only: http.server, subprocess,
threading, json, re) so there is nothing to `pip install` -- just:

    python3 dashboard/server.py
    open http://localhost:8787

For your own isolated lab testbed only -- see the project's ethics/scope
note in docs/Optimistic-TCP-ACK-Attacks.pdf and README.md.
"""
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PORT = int(os.environ.get("DASHBOARD_PORT", "8787"))
POLL_INTERVAL = 0.4  # seconds between ss -ti snapshots

PEER_NAMES = {
    "172.28.0.20": "attacker",
    "172.28.0.30": "observer",
}

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

# ---------------------------------------------------------------------------
# Shared state, updated by background threads, read by SSE handlers.
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_latest_metrics = {}      # {"attacker": {...} | None, "observer": {...} | None}
_prev_bytes = {}          # peer -> (bytes_acked, timestamp) for throughput deltas
_log_lines = []           # list of raw server log lines (grows for the session)
_state = {"cc_algo": "cubic", "defense": False, "shaped": False}


def dc(args, timeout=20):
    """Run a docker compose command from the project root; return (rc, stdout, stderr)."""
    proc = subprocess.run(
        ["docker", "compose"] + args,
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ---------------------------------------------------------------------------
# ss -ti parsing
# ---------------------------------------------------------------------------
CWND_RE = re.compile(r"\bcwnd:(\d+)")
SSTHRESH_RE = re.compile(r"\bssthresh:(\d+)")
RTT_RE = re.compile(r"\brtt:([\d.]+)/([\d.]+)")
MINRTT_RE = re.compile(r"\bminrtt:([\d.]+)")
RETRANS_RE = re.compile(r"\bretrans:(\d+)/(\d+)")
BYTES_ACKED_RE = re.compile(r"\bbytes_acked:(\d+)")
SEGS_OUT_RE = re.compile(r"\bsegs_out:(\d+)")
ALGO_RE = re.compile(r"\b(cubic|reno|bbr)\b")
SEND_RATE_RE = re.compile(r"\bsend (\d+(?:\.\d+)?)([KMG]?)bps")


def _rate_to_mbit(value, unit):
    mult = {"": 1.0, "K": 1e3, "M": 1e6, "G": 1e9}[unit]
    return float(value) * mult / 1e6


def parse_ss(text):
    """Parse `ss -ti` output into {peer_name: {cwnd, ssthresh, rtt, minrtt,
    retrans, retrans_total, bytes_acked, send_mbps, algo}}."""
    lines = text.splitlines()
    out = {}
    i = 0
    while i < len(lines):
        parts = lines[i].split()
        if len(parts) >= 5 and parts[0] == "ESTAB" and i + 1 < len(lines):
            peer_addr = parts[4]
            peer_ip = peer_addr.rsplit(":", 1)[0]
            name = PEER_NAMES.get(peer_ip, peer_ip)
            detail = lines[i + 1]

            rtt_m = RTT_RE.search(detail)
            send_m = SEND_RATE_RE.search(detail)
            retr_m = RETRANS_RE.search(detail)
            algo_m = ALGO_RE.search(detail)

            def _int(rx):
                m = rx.search(detail)
                return int(m.group(1)) if m else None

            def _float(rx):
                m = rx.search(detail)
                return float(m.group(1)) if m else None

            out[name] = {
                "algo": algo_m.group(1) if algo_m else None,
                "cwnd": _int(CWND_RE),
                "ssthresh": _int(SSTHRESH_RE),
                "rtt": float(rtt_m.group(1)) if rtt_m else None,
                "rttvar": float(rtt_m.group(2)) if rtt_m else None,
                "minrtt": _float(MINRTT_RE),
                "bytes_acked": _int(BYTES_ACKED_RE),
                "segs_out": _int(SEGS_OUT_RE),
                "send_mbps": _rate_to_mbit(send_m.group(1), send_m.group(2)) if send_m else None,
                "retrans_recent": int(retr_m.group(1)) if retr_m else 0,
                "retrans_total": int(retr_m.group(2)) if retr_m else 0,
            }
            i += 2
        else:
            i += 1
    return out


# ---------------------------------------------------------------------------
# Background pollers
# ---------------------------------------------------------------------------
def metrics_poller():
    while True:
        rc, out, _ = dc(["exec", "-T", "server", "ss", "-ti"], timeout=5)
        now = time.time()
        parsed = parse_ss(out) if rc == 0 else {}
        with _lock:
            for name in ("attacker", "observer"):
                m = parsed.get(name)
                if m is None:
                    _latest_metrics[name] = None
                    continue
                # Derive real throughput from bytes_acked deltas (steadier
                # than ss's own instantaneous `send` estimate).
                prev = _prev_bytes.get(name)
                if prev and m["bytes_acked"] is not None and now > prev[1]:
                    delta_bytes = max(m["bytes_acked"] - prev[0], 0)
                    delta_t = now - prev[1]
                    m["throughput_mbps"] = round(delta_bytes * 8 / delta_t / 1e6, 3)
                else:
                    m["throughput_mbps"] = m["send_mbps"]
                if m["bytes_acked"] is not None:
                    _prev_bytes[name] = (m["bytes_acked"], now)
                m["ts"] = now
                _latest_metrics[name] = m
        time.sleep(POLL_INTERVAL)


def log_tailer():
    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "compose", "logs", "-f", "--no-color", "--tail", "0", "server"],
                cwd=PROJECT_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            for line in proc.stdout:
                clean = _ANSI_RE.sub("", line.rstrip("\n")).strip()
                if not clean:
                    continue
                # Timestamp at the moment the line was actually produced, not
                # at SSE delivery time -- if the EventSource ever silently
                # reconnects (browser default retry on any drop) and the
                # backlog gets resent, each line still carries its true
                # original time instead of being re-tagged with "now".
                with _lock:
                    _log_lines.append((time.time(), clean))
        except Exception as e:  # noqa: BLE001 -- best-effort background tailer
            with _lock:
                _log_lines.append((time.time(), f"[dashboard] log tailer error: {e}"))
            time.sleep(2)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "OptAckDashboard/1.0"

    def log_message(self, fmt, *args):  # quieter default logging
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    def _static(self, path):
        fpath = os.path.join(STATIC_DIR, path.lstrip("/"))
        if not os.path.abspath(fpath).startswith(STATIC_DIR) or not os.path.isfile(fpath):
            self.send_error(404)
            return
        ctype = {
            ".html": "text/html", ".js": "application/javascript", ".css": "text/css",
            ".svg": "image/svg+xml", ".png": "image/png",
        }.get(os.path.splitext(fpath)[1], "application/octet-stream")
        with open(fpath, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- routing ------------------------------------------------------
    def do_GET(self):
        if self.path == "/" or self.path == "":
            self._static("index.html")
        elif self.path == "/api/events":
            self._sse()
        elif self.path == "/api/status":
            with _lock:
                self._json({"metrics": dict(_latest_metrics), "state": dict(_state)})
        elif self.path.startswith("/static/"):
            self._static(self.path[len("/static/"):])
        else:
            self._static(self.path)

    def do_POST(self):
        try:
            body = self._read_json()
            if self.path == "/api/testbed/up":
                # Named explicitly (not a bare `up -d`): when the dashboard
                # itself runs as a compose service, an unscoped `up -d` would
                # target it too and could recreate the very container serving
                # this request.
                rc, out, err = dc(["up", "-d", "server", "attacker", "observer"], timeout=60)
                self._json({"ok": rc == 0, "out": out, "err": err})
            elif self.path == "/api/testbed/down":
                # `rm -f -s` (stop + remove), scoped to the three testbed
                # services only -- NOT a bare `docker compose down`, which
                # would also stop/remove the dashboard's own container.
                rc, out, err = dc(["rm", "-f", "-s", "server", "attacker", "observer"], timeout=60)
                self._json({"ok": rc == 0, "out": out, "err": err})
            elif self.path == "/api/server/start":
                cc = body.get("cc_algo", "cubic")
                defense = bool(body.get("defense", False))
                env = dict(os.environ)
                env["CC_ALGO"] = cc
                env["DEFENSE"] = "on" if defense else "off"
                proc = subprocess.run(
                    ["docker", "compose", "up", "-d", "--force-recreate", "server"],
                    cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, timeout=30,
                )
                with _lock:
                    _state["cc_algo"] = cc
                    _state["defense"] = defense
                    _prev_bytes.clear()
                self._json({"ok": proc.returncode == 0, "out": proc.stdout, "err": proc.stderr})
            elif self.path == "/api/shape":
                target = body.get("target", "server")
                delay = int(body.get("delay_ms", 20))
                loss = float(body.get("loss_pct", 2))
                rc, out, err = dc([
                    "exec", "-T", target, "tc", "qdisc", "replace", "dev", "eth0", "root",
                    "netem", "delay", f"{delay}ms", "loss", f"{loss}%",
                ], timeout=10)
                with _lock:
                    _state["shaped"] = rc == 0
                self._json({"ok": rc == 0, "out": out, "err": err})
            elif self.path == "/api/shape/clear":
                target = body.get("target", "server")
                rc, out, err = dc(["exec", "-T", target, "tc", "qdisc", "del", "dev", "eth0", "root"], timeout=10)
                with _lock:
                    _state["shaped"] = False
                self._json({"ok": True, "out": out, "err": err})
            elif self.path == "/api/honest/start":
                duration = int(body.get("duration", 8))
                dc(["exec", "-d", "observer", "sh", "-c", f"timeout {duration} nc server 5000 > /dev/null"], timeout=10)
                self._json({"ok": True})
            elif self.path == "/api/attack/start":
                duration = int(body.get("duration", 10))
                args = ["exec", "-d", "attacker", "/work/attack", "--target", "server",
                        "--port", "5000", "--duration", str(duration)]
                if body.get("sack"):
                    args.append("--sack")
                if body.get("timestamps"):
                    args.append("--timestamps")
                if body.get("lazy"):
                    args.append("--lazy")
                if body.get("seed") not in (None, ""):
                    args += ["--seed", str(int(body["seed"]))]
                rc, out, err = dc(args, timeout=10)
                self._json({"ok": rc == 0, "out": out, "err": err})
            else:
                self.send_error(404)
        except Exception as e:  # noqa: BLE001 -- surface errors to the UI, don't crash the server
            self._json({"ok": False, "error": str(e)}, status=500)

    # -- Server-Sent Events -------------------------------------------
    def _sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        sent_logs = 0
        try:
            while True:
                with _lock:
                    metrics = dict(_latest_metrics)
                    state = dict(_state)
                    new_logs = _log_lines[sent_logs:]
                    sent_logs = len(_log_lines)
                payload = {"ts": time.time(), "metrics": metrics, "state": state, "logs": new_logs}
                chunk = f"data: {json.dumps(payload)}\n\n".encode()
                self.wfile.write(chunk)
                self.wfile.flush()
                time.sleep(POLL_INTERVAL)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    threading.Thread(target=metrics_poller, daemon=True).start()
    threading.Thread(target=log_tailer, daemon=True).start()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[dashboard] serving on http://localhost:{PORT}  (project root: {PROJECT_ROOT})")
    print("[dashboard] make sure 'docker compose up -d' has been run at least once.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
