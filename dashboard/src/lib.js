// Pure data helpers (unit-tested in tests/lib.test.js).

export const FLAGGED_URL = "phishing_url";
export const FLAGGED_FILE = "malicious_file";
export const TRACKER_SESSION = "tracker_session";

export const shortHash = (h, n = 10) => (h ? `${h.slice(0, n)}…` : "–");
export const pct = (x) => `${Math.round((x ?? 0) * 100)}%`;
export const ts = (iso) => (iso ? new Date(iso) : null);
export const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : "–");

const newestFirst = (a, b) => (a.timestamp_utc < b.timestamp_utc ? 1 : a.timestamp_utc > b.timestamp_utc ? -1 : b.id - a.id);

export function flaggedSites(entries) {
  return entries
    .filter((e) => e.event_type === FLAGGED_URL)
    .sort(newestFirst)
    .map((e) => ({
      id: e.id, time: e.timestamp_utc, url: e.details.url, verdict: e.details.verdict,
      score: e.details.risk_score, reason: e.details.reasons?.[0] ?? "", case_id: e.case_id,
    }));
}

export function flaggedFiles(entries) {
  return entries
    .filter((e) => e.event_type === FLAGGED_FILE)
    .sort(newestFirst)
    .map((e) => ({
      id: e.id, time: e.timestamp_utc, filename: e.details.filename, sha256: e.details.sha256,
      verdict: e.details.verdict, score: e.details.risk_score, reason: e.details.reasons?.[0] ?? "",
      vt: e.details.virustotal?.status ?? "–", mode: e.details.analysis_mode, case_id: e.case_id,
    }));
}

// Risk timeline: every URL / file verdict that reached the log (benign verdicts
// are not logged, so the timeline shows flagged events only).
export function timelinePoints(entries) {
  return entries
    .filter((e) => e.event_type === FLAGGED_URL || e.event_type === FLAGGED_FILE)
    .map((e) => ({
      id: e.id,
      t: new Date(e.timestamp_utc).getTime(),
      score: e.details.risk_score,
      verdict: e.details.verdict,
      kind: e.event_type === FLAGGED_URL ? "URL" : "File",
      label: e.event_type === FLAGGED_URL ? e.details.url : e.details.filename,
    }))
    .sort((a, b) => a.t - b.t);
}

export function summarize(entries) {
  const count = (t) => entries.filter((e) => e.event_type === t).length;
  return {
    urls: count(FLAGGED_URL),
    files: count(FLAGGED_FILE),
    trackerSessions: count(TRACKER_SESSION),
    total: entries.length,
  };
}

// -------- evidence export --------------------------------------------------
export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// The JSON string returned here is exactly what gets downloaded and hashed.
export async function buildEvidenceExport({ entries, verify, apiBase, now = new Date() }) {
  const doc = {
    export_meta: {
      tool: "Browser Security Analyzer dashboard",
      exported_at: now.toISOString(),
      api_base: apiBase,
      entry_count: entries.length,
      head_hash: entries.length ? entries[entries.length - 1].entry_hash : null,
      integrity_check_at_export: verify
        ? { valid: verify.valid, entries_checked: verify.entries_checked,
            first_broken_id: verify.first_broken_id, reason: verify.reason }
        : "not run",
      note: "Entries are in chain order. Re-verify against the backend with GET /forensic-log/verify; "
          + "the HMAC key is held server-side and is not part of this export.",
    },
    entries,
  };
  const json = JSON.stringify(doc, null, 2);
  const sha256 = await sha256Hex(json);
  const stamp = now.toISOString().replace(/[:.]/g, "-");
  const filename = `bsa-evidence-${stamp}.json`;
  // `sha256sum -c` compatible (two spaces between hash and name)
  return { json, sha256, filename, sha256File: `${sha256}  ${filename}\n` };
}

export function downloadText(filename, text, mime = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
