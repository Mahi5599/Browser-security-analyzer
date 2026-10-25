import { useState } from "react";
import { buildEvidenceExport, caseReportFilename, downloadBlob, downloadText, shortHash } from "../lib.js";

// "Verify log integrity" + "Export evidence". The verify result is shown with
// both colour AND text/icon so it is readable without relying on colour.
export default function IntegrityPanel({ api, onVerified, caseIds = [] }) {
  const [state, setState] = useState({ status: "idle" });
  const [exp, setExp] = useState(null);
  const [exportErr, setExportErr] = useState(null);
  const [busy, setBusy] = useState(false);
  const [caseId, setCaseId] = useState("");
  const [examiner, setExaminer] = useState("");
  const [report, setReport] = useState(null);
  const [reportErr, setReportErr] = useState(null);
  const [reportBusy, setReportBusy] = useState(false);

  async function verify() {
    setState({ status: "running" });
    try {
      const result = await api.verify();
      setState({ status: "done", result, at: new Date() });
      onVerified?.(result);
    } catch (e) {
      setState({ status: "error", message: e.message });
      onVerified?.(null);
    }
  }

  async function exportEvidence() {
    setBusy(true);
    setExportErr(null);
    try {
      const { items } = await api.allEntries();
      // Re-verify at export time so the file records the chain state it was taken from.
      let result = null;
      try { result = await api.verify(); onVerified?.(result); } catch { /* exported as "not run" */ }
      const out = await buildEvidenceExport({ entries: items, verify: result, apiBase: api.base });
      // One download per click: browsers prompt before allowing several automatic
      // downloads, so the .sha256 sidecar is a separate button.
      downloadText(out.filename, out.json);
      setExp({ filename: out.filename, sha256: out.sha256, sha256File: out.sha256File, count: items.length });
    } catch (e) {
      setExportErr(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function generateReport() {
    setReportBusy(true);
    setReportErr(null);
    setReport(null);
    try {
      const c = caseId.trim();
      const { blob, sha256 } = await api.caseReport(c, examiner.trim());
      const filename = caseReportFilename(c);
      downloadBlob(filename, blob);
      setReport({ filename, sha256, caseId: c });
    } catch (e) {
      setReportErr(e.message);
    } finally {
      setReportBusy(false);
    }
  }

  const canReport = caseId.trim() !== "" && examiner.trim() !== "" && !reportBusy;
  const r = state.result;
  return (
    <section className="card integrity" aria-labelledby="integrity-h">
      <h2 id="integrity-h">Chain of custody</h2>
      <div className="actions">
        <button onClick={verify} disabled={state.status === "running"}>
          {state.status === "running" ? "Verifying…" : "Verify log integrity"}
        </button>
        <button onClick={exportEvidence} disabled={busy} className="secondary">
          {busy ? "Exporting…" : "Export evidence"}
        </button>
      </div>

      {state.status === "done" && r.valid && (
        <div className="result ok" role="status" data-testid="verify-result">
          <strong>✔ INTEGRITY VERIFIED</strong>
          <span>All {r.entries_checked} entries chain correctly and carry valid HMACs.</span>
          <span className="mono">head {shortHash(r.head_hash, 16)}</span>
        </div>
      )}
      {state.status === "done" && !r.valid && (
        <div className="result bad" role="alert" data-testid="verify-result">
          <strong>✖ TAMPERING DETECTED</strong>
          <span>
            {r.first_broken_id != null ? <>First broken entry: <b>#{r.first_broken_id}</b>. </> : null}
            {r.reason}
          </span>
          <span>{r.entries_checked} earlier {r.entries_checked === 1 ? "entry" : "entries"} verified intact before the break.</span>
        </div>
      )}
      {state.status === "error" && (
        <div className="result warn" role="alert">
          <strong>Could not verify</strong>
          <span>{state.message}</span>
        </div>
      )}
      {state.status === "done" && <p className="muted">Checked {state.at.toLocaleTimeString()}</p>}

      {exportErr && <div className="result warn" role="alert"><strong>Export failed</strong><span>{exportErr}</span></div>}
      {exp && (
        <div className="export" data-testid="export-result">
          <p>Exported <b>{exp.count}</b> entries to <span className="mono">{exp.filename}</span></p>
          <p>SHA-256 of the file:</p>
          <p className="mono hash" data-testid="export-hash">{exp.sha256}</p>
          <p className="muted">Check it later with <span className="mono">shasum -a 256 {exp.filename}</span>, or save the
            sidecar and run <span className="mono">shasum -a 256 -c</span>.</p>
          <button className="secondary" onClick={() => downloadText(`${exp.filename}.sha256`, exp.sha256File, "text/plain")}>
            Download .sha256 file
          </button>
        </div>
      )}

      <form className="report-form" onSubmit={(e) => { e.preventDefault(); if (canReport) generateReport(); }} aria-label="Case report">
        <h3>Case report (PDF)</h3>
        <div className="actions">
          <label>Case ID{" "}
            <input value={caseId} onChange={(e) => setCaseId(e.target.value)} list="case-ids" maxLength={128}
                   placeholder="e.g. DEMO-001" autoComplete="off" />
          </label>
          <datalist id="case-ids">{caseIds.map((c) => <option key={c} value={c} />)}</datalist>
          <label>Examiner{" "}
            <input value={examiner} onChange={(e) => setExaminer(e.target.value)} maxLength={128}
                   placeholder="Your name" autoComplete="name" />
          </label>
          <button type="submit" disabled={!canReport}>{reportBusy ? "Generating…" : "Generate case report"}</button>
        </div>
        {reportErr && <div className="result warn" role="alert"><strong>Report failed</strong><span>{reportErr}</span></div>}
        {report && (
          <div className="export" data-testid="report-result">
            <p>Downloaded <span className="mono">{report.filename}</span></p>
            <p>SHA-256 of the report's underlying data (also in every page footer):</p>
            <p className="mono hash" data-testid="report-hash">{report.sha256 ?? "(not exposed by server)"}</p>
            <p className="muted">Reproduce it with{" "}
              <span className="mono">curl '{api.base}/forensic-log/report?case_id={encodeURIComponent(report.caseId)}&amp;examiner=…&amp;format=json' | shasum -a 256</span>
              {" "}(same examiner text, log unchanged). A red <b>INTEGRITY FAILURE</b> banner means the log did not verify.</p>
          </div>
        )}
      </form>
    </section>
  );
}
