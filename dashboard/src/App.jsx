import { useCallback, useEffect, useMemo, useState } from "react";
import { createApi } from "./api.js";
import { flaggedFiles, flaggedSites, summarize, timelinePoints } from "./lib.js";
import IntegrityPanel from "./components/IntegrityPanel.jsx";
import Timeline from "./components/Timeline.jsx";
import TrackerChart from "./components/TrackerChart.jsx";
import { FlaggedFiles, FlaggedSites } from "./components/FlaggedTables.jsx";
import LogTable from "./components/LogTable.jsx";

export default function App({ api: injected }) {
  const api = useMemo(() => injected ?? createApi(), [injected]);
  const [data, setData] = useState({ status: "loading" });
  const [auto, setAuto] = useState(false);
  const [brokenId, setBrokenId] = useState(null);

  const load = useCallback(async () => {
    try {
      const [log, trackers] = await Promise.all([api.allEntries(), api.trackers()]);
      setData({ status: "ready", entries: log.items, total: log.total, truncated: log.truncated, trackers, at: new Date() });
    } catch (e) {
      setData({ status: "error", message: e.message });
    }
  }, [api]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!auto) return undefined;
    const id = setInterval(load, 10000);
    return () => clearInterval(id);
  }, [auto, load]);

  const entries = data.entries ?? [];
  const sum = useMemo(() => summarize(entries), [entries]);
  const caseIds = useMemo(() => [...new Set(entries.map((e) => e.case_id))].sort(), [entries]);

  return (
    <div className="page">
      <header>
        <div>
          <h1>Browser Security Analyzer</h1>
          <p className="muted">Forensic dashboard · API <span className="mono">{api.base}</span></p>
        </div>
        <div className="actions">
          <label><input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Auto-refresh (10 s)</label>
          <button className="secondary" onClick={load}>Refresh</button>
        </div>
      </header>

      {data.status === "loading" && <p className="status" role="status">Loading…</p>}
      {data.status === "error" && (
        <div className="result bad" role="alert">
          <strong>Can't load data from the backend</strong>
          <span>{data.message}</span>
          <span>Is it running at <span className="mono">{api.base}</span>? If the page loaded from another origin,
            add it to <span className="mono">BSA_DASHBOARD_ORIGINS</span> (CORS).</span>
        </div>
      )}

      {data.status === "ready" && (
        <>
          <section className="cards" aria-label="Summary">
            <div className="card stat"><b>{sum.urls}</b><span>flagged sites</span></div>
            <div className="card stat"><b>{sum.files}</b><span>flagged downloads</span></div>
            <div className="card stat"><b>{sum.trackerSessions}</b><span>high-tracking page loads</span></div>
            <div className="card stat"><b>{data.total}</b><span>log entries</span></div>
          </section>
          {data.truncated && <p className="muted">Showing the oldest {entries.length} of {data.total} log entries.</p>}

          <IntegrityPanel api={api} caseIds={caseIds} onVerified={(r) => setBrokenId(r && !r.valid ? r.first_broken_id : null)} />

          <section className="card"><h2>Risk timeline</h2>
            <Timeline points={timelinePoints(entries)} />
            <p className="muted">Only suspicious / phishing / malicious verdicts are written to the log, so benign pages do not appear here.</p>
          </section>

          <div className="two">
            <section className="card"><h2>Flagged sites</h2><FlaggedSites rows={flaggedSites(entries)} /></section>
            <section className="card"><h2>Flagged downloads</h2><FlaggedFiles rows={flaggedFiles(entries)} /></section>
          </div>

          <section className="card"><h2>Top trackers</h2><TrackerChart report={data.trackers} /></section>

          <section className="card"><h2>Forensic log</h2><LogTable entries={entries} brokenId={brokenId} /></section>
          <p className="muted foot">Loaded {data.at.toLocaleTimeString()}</p>
        </>
      )}
    </div>
  );
}
