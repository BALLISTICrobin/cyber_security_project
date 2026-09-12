// Guided scenario: a fixed sequence of steps that drive the real backend
// (same /api/* endpoints as the manual controls), then summarizes each
// step's measured results into a running report using the metrics history
// app.js is already recording for the charts.
const Stepper = (() => {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    return res.json();
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
  const report = {};

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
    const baselineThr = report["baseline"]?.meanThr;
    for (const step of STEPS) {
      const r = report[step.id];
      if (!r || step.peer === null) continue;
      const tr = document.createElement("tr");
      const ampl = baselineThr && r.meanThr != null ? r.meanThr / baselineThr : null;
      tr.innerHTML = `
        <td>${step.title}</td>
        <td>${step.peer}</td>
        <td>${r.peakCwnd ?? "—"}</td>
        <td>${fmt(r.minRtt, 3)}</td>
        <td>${fmt(r.meanThr)}</td>
        <td>${ampl != null ? fmt(ampl, 1) + "×" : "—"}</td>
        <td>${r.detections > 0 ? `⚠ ${r.detections}` : "0"}</td>
      `;
      tbody.appendChild(tr);
    }
    document.getElementById("report-section").hidden = Object.keys(report).length === 0;
  }

  async function runStep() {
    if (current >= STEPS.length - 1 && report["summary-shown"]) return;
    current = Math.min(current + 1, STEPS.length - 1);
    renderProgress();
    const step = STEPS[current];
    const btn = document.getElementById("btn-step-run");
    btn.disabled = true;
    btn.textContent = "running...";
    const t0 = Date.now();
    await step.run();
    const t1 = Date.now();
    if (step.peer) {
      report[step.id] = statsFor(step.peer, t0, t1 + 200);
      renderReport();
    }
    if (step.id === "summary") {
      report["summary-shown"] = true;
    }
    renderCurrent();
  }

  function reset() {
    current = -1;
    for (const k of Object.keys(report)) delete report[k];
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

  return { init };
})();
