// Thin client for the backend. `fetchImpl` is injectable for tests.
export const DEFAULT_API_BASE = import.meta.env?.VITE_API_BASE ?? "http://127.0.0.1:8000";

const PAGE = 500;          // backend max page size
const MAX_ENTRIES = 10000; // dashboard cap; the UI says so when it truncates

export function createApi(base = DEFAULT_API_BASE, fetchImpl = (...a) => fetch(...a)) {
  async function getJson(path) {
    const res = await fetchImpl(`${base}${path}`);
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON error body */ }
    if (!res.ok) {
      const detail = body?.detail ? ` — ${typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)}` : "";
      throw new Error(`${path} returned ${res.status}${detail}`);
    }
    return body;
  }

  return {
    base,
    // Every log entry, oldest first (pages of 500, capped at MAX_ENTRIES).
    async allEntries() {
      const items = [];
      let total = 0;
      for (let offset = 0; offset < MAX_ENTRIES; offset += PAGE) {
        const page = await getJson(`/forensic-log?limit=${PAGE}&offset=${offset}`);
        total = page.total;
        items.push(...page.items);
        if (items.length >= total || page.items.length === 0) break;
      }
      return { items, total, truncated: total > items.length };
    },
    verify: () => getJson("/forensic-log/verify"),
    trackers: () => getJson("/tracker-report?top=10"),
    health: () => getJson("/health"),
  };
}
