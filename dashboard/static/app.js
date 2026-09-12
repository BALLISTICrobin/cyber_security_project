// Minimal dependency-free line chart on a <canvas>. Multiple named series,
// auto-scaling y-axis, rolling time window on x.
class LineChart {
  constructor(canvas, maxPoints = 150) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.series = {};
    this.maxPoints = maxPoints;
  }
  addSeries(name, color) {
    this.series[name] = { color, points: [] };
  }
  push(name, t, v) {
    const s = this.series[name];
    if (!s || v == null) return;
    s.points.push({ t, v });
    if (s.points.length > this.maxPoints) s.points.shift();
  }
  clear() {
    for (const k in this.series) this.series[k].points = [];
    this.render();
  }
  render() {
    const ctx = this.ctx, w = this.canvas.width, h = this.canvas.height;
    ctx.clearRect(0, 0, w, h);
    let allPts = [];
    for (const k in this.series) allPts = allPts.concat(this.series[k].points);
    const pad = 28;
    if (allPts.length < 2) {
      ctx.fillStyle = "#bbb"; ctx.font = "12px sans-serif";
      ctx.fillText("waiting for data...", pad, h / 2);
      return;
    }
    const tMin = Math.min(...allPts.map((p) => p.t));
    const tMax = Math.max(...allPts.map((p) => p.t));
    const vMax = Math.max(...allPts.map((p) => p.v), 1) * 1.1;
    const vMin = 0;
    const xScale = (t) => pad + (w - pad - 8) * (tMax > tMin ? (t - tMin) / (tMax - tMin) : 0);
    const yScale = (v) => h - 18 - (h - 18 - 10) * ((v - vMin) / ((vMax - vMin) || 1));

    ctx.strokeStyle = "#eee"; ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = 10 + (i * (h - 18 - 10)) / 4;
      ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - 8, y); ctx.stroke();
    }
    ctx.fillStyle = "#888"; ctx.font = "10px sans-serif";
    ctx.fillText(vMax.toFixed(vMax < 10 ? 2 : 0), 2, 16);
    ctx.fillText("0", 10, h - 18);

    for (const k in this.series) {
      const { color, points } = this.series[k];
      if (points.length < 2) continue;
      ctx.strokeStyle = color; ctx.lineWidth = 2;
      ctx.beginPath();
      points.forEach((p, i) => {
        const x = xScale(p.t), y = yScale(p.v);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  }
}

const COLORS = { attacker: "#c1292e", observer: "#13315c" };

function makeChart(id) {
  const c = new LineChart(document.getElementById(id));
  c.addSeries("attacker", COLORS.attacker);
  c.addSeries("observer", COLORS.observer);
  return c;
}
const cwndChart = makeChart("chart-cwnd");
const rttChart = makeChart("chart-rtt");
const thrChart = makeChart("chart-thr");

function setText(id, val) {
  document.getElementById(id).textContent = val;
}

function updateCard(prefix, m) {
  if (!m) {
    ["algo", "cwnd", "ssthresh", "rtt", "minrtt", "thr"].forEach((f) => setText(`${prefix}-${f}`, "—"));
    return;
  }
  setText(`${prefix}-algo`, m.algo ?? "—");
  setText(`${prefix}-cwnd`, m.cwnd ?? "—");
  setText(`${prefix}-ssthresh`, m.ssthresh ?? "—");
  setText(`${prefix}-rtt`, m.rtt != null ? m.rtt.toFixed(2) : "—");
  setText(`${prefix}-minrtt`, m.minrtt != null ? m.minrtt.toFixed(3) : "—");
  setText(`${prefix}-thr`, m.throughput_mbps != null ? m.throughput_mbps.toFixed(2) : "—");
}

function appendLogs(entries) {
  // entries: array of [tsSeconds, text] pairs, already de-duplicated by
  // History.recordLogs().
  if (!entries || !entries.length) return;
  const box = document.getElementById("log-box");
  for (const [, text] of entries) {
    const div = document.createElement("div");
    if (text.includes("OPTIMISTIC ACK DETECTED") || text.includes("flow reset")) {
      div.className = "hit";
    }
    div.textContent = text;
    box.appendChild(div);
  }
  box.scrollTop = box.scrollHeight;
}

// --- topology init -------------------------------------------------------
TopoView.init(document.getElementById("topo-svg"));

// --- live event stream -----------------------------------------------
const es = new EventSource("/api/events");
es.onmessage = (e) => {
  const data = JSON.parse(e.data);
  const t = data.ts;
  const am = data.metrics.attacker, om = data.metrics.observer;

  updateCard("a", am);
  updateCard("o", om);
  TopoView.update(data.metrics);

  if (am) {
    cwndChart.push("attacker", t, am.cwnd);
    rttChart.push("attacker", t, am.rtt);
    thrChart.push("attacker", t, am.throughput_mbps);
    History.record("attacker", { t, cwnd: am.cwnd, rtt: am.rtt, minrtt: am.minrtt, throughput_mbps: am.throughput_mbps });
  }
  if (om) {
    cwndChart.push("observer", t, om.cwnd);
    rttChart.push("observer", t, om.rtt);
    thrChart.push("observer", t, om.throughput_mbps);
    History.record("observer", { t, cwnd: om.cwnd, rtt: om.rtt, minrtt: om.minrtt, throughput_mbps: om.throughput_mbps });
  }
  cwndChart.render(); rttChart.render(); thrChart.render();

  if (data.logs && data.logs.length) {
    const fresh = History.recordLogs(data.logs); // dedups; entries are [tsSeconds, text]
    appendLogs(fresh);
  }
};
es.onerror = () => {
  setText("testbed-status", "(event stream disconnected -- is dashboard/server.py still running?)");
};

// --- manual/advanced controls -----------------------------------------
async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

function wireButton(id, handler) {
  const btn = document.getElementById(id);
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const original = btn.textContent;
    btn.textContent = "...";
    try {
      await handler();
    } catch (err) {
      alert("Error: " + err);
    } finally {
      btn.disabled = false;
      btn.textContent = original;
    }
  });
}

wireButton("btn-up", async () => {
  const r = await post("/api/testbed/up");
  setText("testbed-status", r.ok ? "testbed is up" : "failed to bring testbed up (see console)");
  if (!r.ok) console.error(r);
});

wireButton("btn-down", async () => {
  const r = await post("/api/testbed/down");
  setText("testbed-status", r.ok ? "torn down" : "teardown failed (see console)");
  if (!r.ok) console.error(r);
});

wireButton("btn-server-apply", async () => {
  const cc_algo = document.getElementById("cc-algo").value;
  const defense = document.getElementById("defense-on").checked;
  const r = await post("/api/server/start", { cc_algo, defense });
  setText("testbed-status", r.ok ? `server: CC_ALGO=${cc_algo} DEFENSE=${defense}` : "failed (see console)");
  if (!r.ok) console.error(r);
});

wireButton("btn-shape", async () => {
  const delay_ms = Number(document.getElementById("shape-delay").value);
  const loss_pct = Number(document.getElementById("shape-loss").value);
  const r = await post("/api/shape", { target: "server", delay_ms, loss_pct });
  setText("shape-status", r.ok ? `shaped: ${delay_ms}ms / ${loss_pct}% loss` : "failed (see console)");
  if (!r.ok) console.error(r);
});

wireButton("btn-shape-clear", async () => {
  const r = await post("/api/shape/clear", { target: "server" });
  setText("shape-status", r.ok ? "shaping cleared" : "failed (see console)");
});

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

wireButton("btn-honest", async () => {
  const duration = Number(document.getElementById("honest-duration").value);
  setText("honest-status", "starting...");
  const t0 = Date.now();
  const r = await post("/api/honest/start", { duration });
  if (!r.ok) {
    setText("honest-status", `FAILED: ${(r.err || r.error || "unknown error").trim()}`);
    console.error("honest pull failed:", r);
    return;
  }
  setText("honest-status", `pulling for ${duration}s -- watch the observer card/charts`);
  await sleepMs(duration * 1000 + 300);
  Stepper.recordRun(`Manual: honest pull (${duration}s)`, "observer", t0, Date.now());
  setText("honest-status", "done -- added to session report below");
});

wireButton("btn-attack", async () => {
  const sack = document.getElementById("atk-sack").checked;
  const timestamps = document.getElementById("atk-ts").checked;
  const lazy = document.getElementById("atk-lazy").checked;
  const duration = Number(document.getElementById("atk-duration").value);
  const seedRaw = document.getElementById("atk-seed").value;
  const seed = seedRaw === "" ? null : Number(seedRaw);
  setText("attack-status", "starting...");
  const t0 = Date.now();
  const r = await post("/api/attack/start", { sack, timestamps, lazy, duration, seed });
  if (!r.ok) {
    setText("attack-status", `FAILED: ${(r.err || r.error || "unknown error").trim()}`);
    console.error("attack failed:", r);
    return;
  }
  setText("attack-status", `running for ${duration}s -- watch the attacker card/charts`);
  await sleepMs(duration * 1000 + 300);
  const label = `Manual: attack (${sack ? "SACK" : "no-SACK"}${timestamps ? "" : ", no-TS"}${lazy ? ", lazy" : ""}, ${duration}s)`;
  Stepper.recordRun(label, "attacker", t0, Date.now());
  setText("attack-status", "done -- added to session report below");
});

document.getElementById("btn-reset-charts").addEventListener("click", () => {
  cwndChart.clear(); rttChart.clear(); thrChart.clear();
});

document.getElementById("btn-toggle-advanced").addEventListener("click", (ev) => {
  const box = document.getElementById("advanced-controls");
  box.hidden = !box.hidden;
  ev.target.textContent = box.hidden ? "Show advanced / manual controls" : "Hide advanced / manual controls";
});

// --- guided scenario -----------------------------------------------------
Stepper.init();
