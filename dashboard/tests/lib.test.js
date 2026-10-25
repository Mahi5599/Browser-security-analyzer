import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildEvidenceExport, flaggedFiles, flaggedSites, sha256Hex, summarize, timelinePoints } from "../src/lib.js";
import { ENTRIES } from "./fixtures.js";

describe("derived views", () => {
  it("flaggedSites: only URL events, newest first, with the top reason", () => {
    const rows = flaggedSites(ENTRIES);
    expect(rows.map((r) => r.id)).toEqual([4, 1]);
    expect(rows[1]).toMatchObject({ url: "http://paypaI-secure-login.tk/verify", verdict: "phishing", score: 0.93,
      reason: "Looks like a typosquat of paypal.com" });
  });

  it("flaggedFiles: file events with VirusTotal status and hash", () => {
    const rows = flaggedFiles(ENTRIES);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ filename: "eicar.com", vt: "malicious", mode: "hash+metadata" });
  });

  it("timelinePoints: URLs and files only, in time order", () => {
    const pts = timelinePoints(ENTRIES);
    expect(pts.map((p) => p.id)).toEqual([1, 2, 4]);
    expect(pts.map((p) => p.kind)).toEqual(["URL", "File", "URL"]);
    expect(pts[0].t).toBeLessThan(pts[2].t);
  });

  it("summarize counts by event type", () => {
    expect(summarize(ENTRIES)).toEqual({ urls: 2, files: 1, trackerSessions: 1, total: 4 });
  });

  it("handles an empty log", () => {
    expect(flaggedSites([])).toEqual([]);
    expect(timelinePoints([])).toEqual([]);
    expect(summarize([])).toEqual({ urls: 0, files: 0, trackerSessions: 0, total: 0 });
  });
});

describe("evidence export", () => {
  const verify = { valid: true, entries_checked: 4, first_broken_id: null, reason: null };
  const now = new Date("2026-10-25T12:00:00.000Z");

  it("sha256Hex matches Node's SHA-256 (incl. non-ASCII)", async () => {
    for (const s of ["", "abc", "héllo ✔ 日本"]) {
      expect(await sha256Hex(s)).toBe(createHash("sha256").update(s, "utf8").digest("hex"));
    }
  });

  it("hash covers exactly the exported JSON string", async () => {
    const out = await buildEvidenceExport({ entries: ENTRIES, verify, apiBase: "http://api.test", now });
    expect(out.sha256).toBe(createHash("sha256").update(out.json, "utf8").digest("hex"));
    expect(out.sha256File).toBe(`${out.sha256}  ${out.filename}\n`);
    expect(out.filename).toBe("bsa-evidence-2026-10-25T12-00-00-000Z.json");
  });

  it("contains every entry in order, the head hash and the integrity result", async () => {
    const out = await buildEvidenceExport({ entries: ENTRIES, verify, apiBase: "http://api.test", now });
    const doc = JSON.parse(out.json);
    expect(doc.entries.map((e) => e.id)).toEqual([1, 2, 3, 4]);
    expect(doc.export_meta).toMatchObject({ entry_count: 4, head_hash: ENTRIES[3].entry_hash, exported_at: now.toISOString() });
    expect(doc.export_meta.integrity_check_at_export).toMatchObject({ valid: true, entries_checked: 4 });
  });

  it("records 'not run' when no verify result is available, and any change alters the hash", async () => {
    const a = await buildEvidenceExport({ entries: ENTRIES, verify: null, apiBase: "x", now });
    expect(JSON.parse(a.json).export_meta.integrity_check_at_export).toBe("not run");
    const edited = ENTRIES.map((e, i) => (i === 1 ? { ...e, details: { ...e.details, verdict: "benign" } } : e));
    const b = await buildEvidenceExport({ entries: edited, verify: null, apiBase: "x", now });
    expect(b.sha256).not.toBe(a.sha256);
  });

  it("empty log exports cleanly", async () => {
    const out = await buildEvidenceExport({ entries: [], verify: null, apiBase: "x", now });
    expect(JSON.parse(out.json).export_meta.head_hash).toBeNull();
  });
});
