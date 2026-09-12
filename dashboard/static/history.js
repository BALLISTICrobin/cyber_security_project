// Shared, bounded history of parsed `ss -ti` samples and detection events,
// fed by the SSE stream in app.js. Read by the charts (recent window) and by
// stepper.js (arbitrary time-range stats for the session report).
const History = (() => {
  const MAX_SAMPLES = 4000; // generous for a single demo session
  const data = { attacker: [], observer: [] };
  const detections = []; // array of epoch-ms timestamps
  const seenLines = new Set(); // dedup key: `${tsSeconds}|${text}`

  function record(peer, sample) {
    const arr = data[peer];
    if (!arr) return;
    arr.push(sample);
    if (arr.length > MAX_SAMPLES) arr.shift();
  }

  function get(peer) {
    return data[peer] || [];
  }

  // entries: array of [tsSeconds, text] pairs (the log line's true origin
  // time, from the backend -- NOT the SSE delivery time, which can lag or
  // repeat on an EventSource reconnect). Returns only the entries not
  // already seen, so a resent backlog (e.g. after a silent EventSource
  // reconnect) doesn't double-count detections or double-print log lines.
  function recordLogs(entries) {
    const fresh = [];
    for (const entry of entries) {
      const [tsSeconds, text] = entry;
      const key = `${tsSeconds}|${text}`;
      if (seenLines.has(key)) continue;
      seenLines.add(key);
      fresh.push(entry);
      if (text.includes("OPTIMISTIC ACK DETECTED")) detections.push(tsSeconds * 1000);
    }
    return fresh;
  }

  function detectionsBetween(tStartMs, tEndMs) {
    return detections.filter((t) => t >= tStartMs && t <= tEndMs).length;
  }

  return { record, get, recordLogs, detectionsBetween };
})();
