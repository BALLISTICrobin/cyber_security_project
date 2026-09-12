// Guided scenario: a fixed sequence of steps that drive the real backend
// (same /api/* endpoints as the manual controls), then summarizes each
// step's measured results into a running report using the metrics history
// app.js is already recording for the charts.
const Stepper = (() => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // Throws on ok:false so a failed step (e.g. the testbed isn't up yet, so
  // `docker compose exec` has nothing to exec into) stops the scenario with
  // a clear error instead of silently continuing to the next step and
  // producing a report row with no real data behind it.
  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const json = await res.json();
    if (json.ok === false) {
      throw new Error(`${path} failed: ${(json.err || json.error || "unknown error").trim()}`);
    }
    return json;
  }

  const STEPS = [
    {
      id: "setup",
      title: "1. Setup",
      desc: "Bring the testbed up, start the server on CUBIC (defense off), and shape the link to 20ms delay / 2% loss -- a realistic, lossy bottleneck.",
      peer: null,
      async run() {
        await post("/api/testbed/up");
        await post("/api/server/start", { cc_algo: "cubic", defense: false });
        await sleep(1200);
        await post("/api/shape", { target: "server", delay_ms: 20, loss_pct: 2 });
        await sleep(500);
      },
    },
    {
      id: "baseline",
      title: "2. Honest baseline",
      desc: "A well-behaved client pulls data for 8 seconds. Watch the topology: a modest, steady trickle of data, with ACKs paced by the real ~20ms round trip.",
      peer: "observer",
      async run() {
        const start = Date.now();
        await post("/api/honest/start", { duration: 8 });
        await sleep(8500);
        return start;
      },
    },
    {
      id: "attack-sack",
      title: "3. Attack, with SACK",
      desc: "The attacker lies about received data, negotiating SACK like a real modern receiver. Watch the congestion window and data lane explode.",
      peer: "attacker",
      async run() {
        const start = Date.now();
        await post("/api/attack/start", { sack: true, timestamps: true, duration: 10 });
        await sleep(10500);
        return start;
      },
    },
    {
      id: "attack-nosack",
      title: "4. Attack, without SACK",
      desc: "The identical attack, but without negotiating SACK. Watch it (mostly) backfire -- this is the SACK-dependency finding from the project's M3 sweep.",
      peer: "attacker",
      async run() {
        const start = Date.now();
        await post("/api/attack/start", { sack: false, timestamps: true, duration: 10 });
        await sleep(10500);
        return start;
      },
    },
    {
      id: "defense",
      title: "5. Turn on the defense",
      desc: "Enable Sherwood's randomly-skipped-segment test and repeat the SACK attack. It should be detected on the very first skipped segment and reset.",
      peer: "attacker",
      async run() {
        await post("/api/server/start", { cc_algo: "cubic", defense: true });
        await sleep(1200);
        await post("/api/shape", { target: "server", delay_ms: 20, loss_pct: 2 });
        // Extra margin (vs. the other steps' 500ms) before launching the attack:
        // --force-recreate closes the dashboard's log-follow subprocess, which
        // needs a moment to reattach to the new container. The defense's first
        // detection can fire within ~1-1.5s of the attack starting, so without
        // this buffer the detection can be missed by the log stream even
        // though it genuinely happened (confirmed via `docker compose logs`).
        await sleep(2000);
        const start = Date.now();
        await post("/api/attack/start", { sack: true, timestamps: true, duration: 8 });
        await sleep(8500);
        return start;
      },
    },
    {
      id: "summary",
      title: "6. Summary",
      desc: "Session report -- everything measured above, in one table.",
      peer: null,
      async run() {},
    },
  ];

  let current = -1;
  let summaryShown = false;
  // Ordered report rows -- fed by BOTH the guided scenario (runStep, below)
  // and manual/advanced-control runs (Stepper.recordRun, called from
  // app.js), so a session mixing both shows up as one continuous table in
  // the order things actually happened.
  const rows = [];
  let lastBaselineThr = null; // most recent observer/honest run's mean Mbit/s

  function statsFor(peer, tStartMs, tEndMs) {
    if (!peer) return null;
    // Detections come from the server's log lines, not `ss -ti`, so they
    // must be computed independently of whether any ss samples exist. This
    // matters specifically for the defense step: server/defense_server.c
    // drives the connection entirely from a raw socket, so it has no kernel
    // TCB and never shows up in `ss -ti` at all -- ss-derived stats are
    // genuinely unavailable there, but detections are not.
    const detections = History.detectionsBetween(tStartMs, tEndMs);
    const samples = (History.get(peer) || []).filter(
      (s) => s.t * 1000 >= tStartMs && s.t * 1000 <= tEndMs
    );
    if (!samples.length) return { n: 0, detections };
    const cwnds = samples.map((s) => s.cwnd || 0);
    const minrtts = samples.map((s) => s.minrtt).filter((v) => v != null);
    const thrs = samples.map((s) => s.throughput_mbps || 0);
    return {
      n: samples.length,
      peakCwnd: Math.max(...cwnds),
      minRtt: minrtts.length ? Math.min(...minrtts) : null,
      meanThr: thrs.reduce((a, b) => a + b, 0) / thrs.length,
      detections,
    };
  }

  function renderProgress() {
    const box = document.getElementById("stepper-progress");
    box.innerHTML = "";
    STEPS.forEach((s, i) => {
      const span = document.createElement("span");
      span.className = "step-badge" + (i === current ? " active" : "") + (i < current ? " done" : "");
      span.textContent = s.title;
      box.appendChild(span);
    });
  }

  function renderCurrent() {
    document.getElementById("stepper-desc").textContent = STEPS[current]?.desc || "";
    const btn = document.getElementById("btn-step-run");
    btn.textContent = current >= STEPS.length - 1 ? "Show summary" : "Run this step";
    btn.disabled = current >= STEPS.length;
  }

  function fmt(v, d = 2) {
    return v == null || Number.isNaN(v) ? "—" : Number(v).toFixed(d);
  }

  function renderReport() {
    const tbody = document.querySelector("#report-table tbody");
    tbody.innerHTML = "";
    for (const r of rows) {
      const tr = document.createElement("tr");
      const ampl = r.baselineThr && r.meanThr != null ? r.meanThr / r.baselineThr : null;
      tr.innerHTML = `
        <td>${r.title}</td>
        <td>${r.peer}</td>
        <td>${r.peakCwnd ?? "—"}</td>
        <td>${fmt(r.minRtt, 3)}</td>
        <td>${fmt(r.meanThr)}</td>
        <td>${ampl != null ? fmt(ampl, 1) + "×" : "—"}</td>
        <td>${r.detections > 0 ? `⚠ ${r.detections}` : "0"}</td>
      `;
      tbody.appendChild(tr);
    }
    document.getElementById("report-section").hidden = rows.length === 0;
  }

  // Adds one row to the shared report and re-renders. `peer` "observer"
  // (re-)establishes the reference baseline that later rows' "vs. baseline"
  // column is computed against -- whether that observer run came from the
  // guided scenario or a manual "Run honest pull" click.
  function recordRun(title, peer, tStartMs, tEndMs) {
    if (!peer) return;
    const stats = statsFor(peer, tStartMs, tEndMs) || {};
    let baselineThr;
    if (peer === "observer") {
      if (stats.meanThr != null) lastBaselineThr = stats.meanThr;
      baselineThr = stats.meanThr; // compares to itself -> reads as 1.0x
    } else {
      baselineThr = lastBaselineThr;
    }
    rows.push({ title, peer, ...stats, baselineThr });
    renderReport();
  }

  async function runStep() {
    if (current >= STEPS.length - 1 && summaryShown) return;
    const previous = current;
    current = Math.min(current + 1, STEPS.length - 1);
    renderProgress();
    const step = STEPS[current];
    const btn = document.getElementById("btn-step-run");
    btn.disabled = true;
    btn.textContent = "running...";
    try {
      const t0 = Date.now();
      await step.run();
      const t1 = Date.now();
      if (step.peer) {
        recordRun(step.title, step.peer, t0, t1 + 200);
      }
      if (step.id === "summary") {
        summaryShown = true;
      }
    } catch (err) {
      // Roll back to the previous step so the button reads "retry" for the
      // SAME step rather than silently advancing past a step that didn't
      // actually run (e.g. the testbed wasn't up yet, so `docker compose
      // exec` had no container to exec into).
      current = previous;
      renderProgress();
      alert(
        `Step failed: ${err.message}\n\n` +
        `Common cause: the testbed isn't up yet -- click "Bring testbed up" ` +
        `under "Show advanced / manual controls" first, then retry this step.`
      );
      console.error(err);
    } finally {
      renderCurrent();
    }
  }

  function reset() {
    current = -1;
    summaryShown = false;
    lastBaselineThr = null;
    rows.length = 0;
    renderProgress();
    renderCurrent();
    renderReport();
  }

  function init() {
    renderProgress();
    renderCurrent();
    document.getElementById("btn-step-run").addEventListener("click", runStep);
    document.getElementById("btn-step-reset").addEventListener("click", reset);
  }

  return { init, recordRun };
})();
