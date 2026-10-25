import { fmtTime, pct, shortHash } from "../lib.js";

function Verdict({ v }) {
  return <span className={`badge badge-${v}`}>{v}</span>;
}

export function FlaggedSites({ rows }) {
  if (!rows.length) return <p className="empty">No suspicious or phishing sites logged yet.</p>;
  return (
    <div className="scroll">
      <table>
        <thead><tr><th>Time</th><th>URL</th><th>Verdict</th><th>Risk</th><th>Why</th><th>#</th></tr></thead>
        <tbody>
          {rows.slice(0, 25).map((r) => (
            <tr key={r.id}>
              <td>{fmtTime(r.time)}</td>
              <td className="mono wrap">{r.url}</td>
              <td><Verdict v={r.verdict} /></td>
              <td>{pct(r.score)}</td>
              <td>{r.reason}</td>
              <td className="mono">{r.id}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 25 && <p className="muted">Showing newest 25 of {rows.length}.</p>}
    </div>
  );
}

export function FlaggedFiles({ rows }) {
  if (!rows.length) return <p className="empty">No suspicious or malicious downloads logged yet.</p>;
  return (
    <div className="scroll">
      <table>
        <thead><tr><th>Time</th><th>File</th><th>Verdict</th><th>Risk</th><th>VirusTotal</th><th>SHA-256</th><th>Why</th><th>#</th></tr></thead>
        <tbody>
          {rows.slice(0, 25).map((r) => (
            <tr key={r.id}>
              <td>{fmtTime(r.time)}</td>
              <td className="mono wrap">{r.filename}</td>
              <td><Verdict v={r.verdict} /></td>
              <td>{pct(r.score)}</td>
              <td>{r.vt}</td>
              <td className="mono" title={r.sha256 ?? "metadata-only scan: file was not hashed"}>{r.sha256 ? shortHash(r.sha256) : "not hashed"}</td>
              <td>{r.reason}</td>
              <td className="mono">{r.id}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > 25 && <p className="muted">Showing newest 25 of {rows.length}.</p>}
    </div>
  );
}
