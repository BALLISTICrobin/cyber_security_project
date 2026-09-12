// Animated network topology: Attacker <-> Server <-> Observer, with packets
// flowing along each link. This is an ILLUSTRATIVE animation, not a literal
// packet capture replay -- packet spawn rate and travel time are derived
// from the real live metrics (throughput, rtt) polled from `ss -ti`, so the
// visual behavior tracks reality (denser/faster flow under the real attack,
// a realistic trickle for the honest connection) without pretending to show
// individual real packets. Data-lane packets use a small icon (Twemoji
// "package", CC-BY 4.0, see index.html attribution); ACKs stay plain dots
// to keep the lower lane readable.
const TopoView = (() => {
  const NS = "http://www.w3.org/2000/svg";
  let svg;
  const X = { attacker: 90, server: 450, observer: 810 };
  const Y_DATA = 108;   // server -> peer lane (the bulk stream)
  const Y_ACK = 152;    // peer -> server lane (ACKs)
  const PACKET_ICON = "/static/images/packet.svg";
  const PACKET_SIZE = 18;

  let state = { attacker: null, observer: null };
  let lastSpawn = {};
  let packets = [];

  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

  function spawnDot(x0, x1, y, color, r, durMs) {
    const c = document.createElementNS(NS, "circle");
    c.setAttribute("r", r);
    c.setAttribute("fill", color);
    c.setAttribute("cx", x0);
    c.setAttribute("cy", y);
    c.setAttribute("opacity", "0.9");
    svg.appendChild(c);
    packets.push({ el: c, kind: "dot", x0, x1, y, start: performance.now(), dur: durMs });
  }

  function spawnIcon(x0, x1, y, durMs) {
    const img = document.createElementNS(NS, "image");
    img.setAttribute("href", PACKET_ICON);
    img.setAttribute("width", PACKET_SIZE);
    img.setAttribute("height", PACKET_SIZE);
    img.setAttribute("y", y - PACKET_SIZE / 2);
    img.setAttribute("x", x0 - PACKET_SIZE / 2);
    svg.appendChild(img);
    packets.push({ el: img, kind: "icon", x0, x1, y, start: performance.now(), dur: durMs });
  }

  function dataInterval(mbps) {
    // Denser stream as throughput rises; sqrt so honest (~5-10 Mbit/s) still
    // reads as a visible steady trickle instead of near-invisible. Floor
    // raised to 220ms (vs. the packets' own 1800ms travel time) so a
    // high-throughput attack still reads as "dense and fast" rather than a
    // solid, unreadable smear of overlapping icons.
    const thr = Math.max(mbps || 0.5, 0.5);
    return clamp(1400 / Math.sqrt(thr), 220, 900);
  }

  function tickPeer(peer, now) {
    const m = state[peer];
    if (!m) return;
    const xPeer = X[peer];
    const xServer = X.server;

    const dKey = peer + "Data", aKey = peer + "Ack";
    const dInterval = dataInterval(m.throughput_mbps);
    if (now - (lastSpawn[dKey] || 0) > dInterval) {
      lastSpawn[dKey] = now;
      spawnIcon(xServer, xPeer, Y_DATA, 1800); // slow, easy-to-follow travel time
    }

    // The signature visual: an honest ACK is paced by the real RTT and
    // travels back over roughly that real delay. An optimistic-ACK
    // attacker fires a near-constant stream of ACKs that arrive back
    // almost instantly, regardless of what was actually delivered --
    // that's the "near-zero RTT lie" the whole attack exploits.
    const aInterval = peer === "attacker" ? 85 : clamp((m.rtt || 40) * 3, 150, 900);
    const aDur = peer === "attacker" ? 180 : clamp((m.rtt || 40) * 8, 400, 1400);
    if (now - (lastSpawn[aKey] || 0) > aInterval) {
      lastSpawn[aKey] = now;
      spawnDot(xPeer, xServer, Y_ACK, "#e8871e", 3, aDur);
    }
  }

  function frame(now) {
    tickPeer("attacker", now);
    tickPeer("observer", now);
    packets = packets.filter((p) => {
      const t = (now - p.start) / p.dur;
      if (t >= 1) {
        p.el.remove();
        return false;
      }
      const x = p.x0 + (p.x1 - p.x0) * t;
      if (p.kind === "icon") {
        p.el.setAttribute("x", x - PACKET_SIZE / 2);
      } else {
        p.el.setAttribute("cx", x);
      }
      return true;
    });
    requestAnimationFrame(frame);
  }

  function init(svgEl) {
    svg = svgEl;
    requestAnimationFrame(frame);
  }

  function update(metrics) {
    state.attacker = metrics.attacker || null;
    state.observer = metrics.observer || null;
  }

  return { init, update };
})();
