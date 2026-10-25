import { Fragment, useMemo, useState } from "react";
import { fmtTime, shortHash } from "../lib.js";

const PAGE_SIZE = 15;
const TYPES = ["all", "phishing_url", "malicious_file", "tracker_session"];

export default function LogTable({ entries, brokenId }) {
  const [type, setType] = useState("all");
  const [page, setPage] = useState(0);
  const [open, setOpen] = useState(null);

  const rows = useMemo(
    () => entries.filter((e) => type === "all" || e.event_type === type).slice().reverse(),
    [entries, type],
  );
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const cur = Math.min(page, pages - 1);
  const slice = rows.slice(cur * PAGE_SIZE, (cur + 1) * PAGE_SIZE);

  return (
    <>
      <div className="actions">
        <label>Event type{" "}
          <select value={type} onChange={(e) => { setType(e.target.value); setPage(0); }}>
            {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </label>
        <span className="muted">{rows.length} entr{rows.length === 1 ? "y" : "ies"}, newest first</span>
      </div>
      {!rows.length ? <p className="empty">The log is empty.</p> : (
        <div className="scroll">
          <table>
            <thead><tr><th>#</th><th>Time (UTC)</th><th>Type</th><th>Case</th><th>prev_hash</th><th>entry_hash</th><th>HMAC</th><th /></tr></thead>
            <tbody>
              {slice.map((e) => (
                <Fragment key={e.id}>
                  <tr className={e.id === brokenId ? "broken" : ""}>
                    <td className="mono">{e.id}{e.id === brokenId && " ✖"}</td>
                    <td>{fmtTime(e.timestamp_utc)}</td>
                    <td>{e.event_type}</td>
                    <td className="mono">{e.case_id}</td>
                    <td className="mono" title={e.prev_hash}>{shortHash(e.prev_hash)}</td>
                    <td className="mono" title={e.entry_hash}>{shortHash(e.entry_hash)}</td>
                    <td className="mono" title={e.hmac}>{shortHash(e.hmac)}</td>
                    <td><button className="link" onClick={() => setOpen(open === e.id ? null : e.id)}
                                aria-expanded={open === e.id}>{open === e.id ? "hide" : "details"}</button></td>
                  </tr>
                  {open === e.id && (
                    <tr className="detail"><td colSpan={8}><pre>{JSON.stringify(e.details, null, 2)}</pre></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="actions">
        <button className="secondary" disabled={cur === 0} onClick={() => setPage(cur - 1)}>‹ Newer</button>
        <span className="muted">Page {cur + 1} of {pages}</span>
        <button className="secondary" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>Older ›</button>
      </div>
    </>
  );
}
