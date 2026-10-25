export const mkEntry = (id, event_type, details, extra = {}) => ({
  id, event_type, case_id: "case-1",
  timestamp_utc: `2026-10-25T10:0${id}:00.000000Z`,
  prev_hash: "p".repeat(64), entry_hash: `${String(id).repeat(64)}`.slice(0, 64), hmac: "h".repeat(64),
  details, ...extra,
});

export const ENTRIES = [
  mkEntry(1, "phishing_url", { url: "http://paypaI-secure-login.tk/verify", verdict: "phishing", risk_score: 0.93,
    reasons: ["Looks like a typosquat of paypal.com"] }),
  mkEntry(2, "malicious_file", { filename: "eicar.com", sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    verdict: "malicious", risk_score: 0.98, reasons: ["Matches the EICAR anti-virus test file"],
    virustotal: { status: "malicious" }, analysis_mode: "hash+metadata" }),
  mkEntry(3, "tracker_session", { site: "news.example.org", tracker_domains: 12, reasons: ["high_tracker_count"] }),
  mkEntry(4, "phishing_url", { url: "http://amaz0n-account.top/login", verdict: "suspicious", risk_score: 0.58,
    reasons: ["Hostname uses an abused TLD"] }),
];

export const TRACKERS = {
  totals: { sessions: 2, sites: 1, pixels: 3, beacons: 1 },
  top_networks: [{ network: "doubleclick.net", requests: 9, sites: 1, sessions: 2 },
                 { network: "google-analytics.com", requests: 4, sites: 1, sessions: 2 }],
  fingerprinting: { sessions: 1, sites: ["news.example.org"], top_scripts: [] },
};

export const makeApi = (over = {}) => ({
  base: "http://api.test",
  allEntries: async () => ({ items: ENTRIES, total: ENTRIES.length, truncated: false }),
  trackers: async () => TRACKERS,
  caseReport: async () => ({ blob: new Blob(["%PDF-fake"], { type: "application/pdf" }), sha256: "f".repeat(64) }),
  verify: async () => ({ valid: true, entries_checked: 4, first_broken_id: null, reason: null, head_hash: "a".repeat(64) }),
  ...over,
});
