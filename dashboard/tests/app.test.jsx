import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

// Recharts needs real layout; swap the charts for stubs. They are covered by the build + screenshot check.
vi.mock("../src/components/Timeline.jsx", () => ({ default: ({ points }) => <div data-testid="timeline">{points.length} points</div> }));
vi.mock("../src/components/TrackerChart.jsx", () => ({ default: ({ report }) => <div data-testid="trackers">{report.top_networks.map((n) => n.network).join(",")}</div> }));

import App from "../src/App.jsx";
import { createApi } from "../src/api.js";
import { ENTRIES, makeApi } from "./fixtures.js";

afterEach(() => vi.restoreAllMocks());

describe("App", () => {
  it("renders summary, flagged sites/downloads, trackers and the log", async () => {
    render(<App api={makeApi()} />);
    await screen.findByText("flagged sites");
    expect(screen.getByTestId("timeline")).toHaveTextContent("3 points");
    expect(screen.getByTestId("trackers")).toHaveTextContent("doubleclick.net,google-analytics.com");
    expect(screen.getAllByText("http://paypaI-secure-login.tk/verify").length).toBeGreaterThan(0);
    expect(screen.getAllByText("eicar.com").length).toBeGreaterThan(0);
    const cards = screen.getByLabelText("Summary");
    expect(within(cards).getByText("flagged sites").previousSibling).toHaveTextContent("2");
    expect(within(cards).getByText("log entries").previousSibling).toHaveTextContent("4");
  });

  it("shows a helpful error when the backend is unreachable", async () => {
    render(<App api={makeApi({ allEntries: async () => { throw new Error("Failed to fetch"); } })} />);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Can't load data from the backend");
    expect(alert).toHaveTextContent("Failed to fetch");
    expect(alert).toHaveTextContent("BSA_DASHBOARD_ORIGINS");
  });

  it("log table: filter by type and expand details", async () => {
    render(<App api={makeApi()} />);
    await screen.findByText("flagged sites");
    const log = screen.getByRole("heading", { name: "Forensic log" }).closest("section");
    fireEvent.change(within(log).getByRole("combobox"), { target: { value: "tracker_session" } });
    expect(within(log).getByText(/1 entry/)).toBeInTheDocument();
    fireEvent.click(within(log).getByText("details"));
    expect(within(log).getByText(/"site": "news.example.org"/)).toBeInTheDocument();
  });
});

describe("Verify log integrity", () => {
  it("valid chain -> green 'INTEGRITY VERIFIED' with entry count", async () => {
    render(<App api={makeApi()} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Verify log integrity" }));
    const res = await screen.findByTestId("verify-result");
    expect(res).toHaveClass("ok");
    expect(res).toHaveTextContent("INTEGRITY VERIFIED");
    expect(res).toHaveTextContent("All 4 entries");
  });

  it("broken chain -> red 'TAMPERING DETECTED', names the entry and marks its row", async () => {
    const bad = { valid: false, entries_checked: 1, first_broken_id: 2, reason: "entry_hash does not match the row contents (row modified)", head_hash: null };
    render(<App api={makeApi({ verify: async () => bad })} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Verify log integrity" }));
    const res = await screen.findByTestId("verify-result");
    expect(res).toHaveClass("bad");
    expect(res).toHaveAttribute("role", "alert");
    expect(res).toHaveTextContent("TAMPERING DETECTED");
    expect(res).toHaveTextContent("#2");
    expect(res).toHaveTextContent("row modified");
    const log = screen.getByRole("heading", { name: "Forensic log" }).closest("section");
    const brokenRow = within(log).getByText("2 ✖").closest("tr");
    expect(brokenRow).toHaveClass("broken");
  });

  it("verify failing (e.g. 503 no key) is reported as an error, not as valid or tampered", async () => {
    render(<App api={makeApi({ verify: async () => { throw new Error("/forensic-log/verify returned 503 — FORENSIC_HMAC_KEY is not set"); } })} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Verify log integrity" }));
    const alert = await screen.findByText("Could not verify");
    expect(alert.closest(".result")).toHaveClass("warn");
    expect(screen.queryByText(/INTEGRITY VERIFIED/)).toBeNull();
    expect(screen.queryByText(/TAMPERING DETECTED/)).toBeNull();
  });
});

describe("Export evidence", () => {
  let blobs;
  beforeEach(() => {
    blobs = [];
    URL.createObjectURL = vi.fn((b) => { blobs.push(b); return `blob:${blobs.length}`; });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function () { this.dataset.clicked = this.download; });
  });

  const readBlob = (b) => new Promise((res) => { const r = new FileReader(); r.onload = () => res(r.result); r.readAsText(b); });

  it("downloads ONE file on export; the displayed hash is the SHA-256 of the downloaded bytes; .sha256 sidecar on request", async () => {
    render(<App api={makeApi()} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Export evidence" }));
    const shown = (await screen.findByTestId("export-hash")).textContent;

    await waitFor(() => expect(blobs).toHaveLength(1));   // no second automatic download
    const json = await readBlob(blobs[0]);
    fireEvent.click(screen.getByRole("button", { name: "Download .sha256 file" }));
    await waitFor(() => expect(blobs).toHaveLength(2));
    const sidecar = await readBlob(blobs[1]);
    expect(shown).toBe(createHash("sha256").update(json, "utf8").digest("hex"));
    expect(sidecar.startsWith(`${shown}  bsa-evidence-`)).toBe(true);
    const doc = JSON.parse(json);
    expect(doc.entries).toHaveLength(ENTRIES.length);
    expect(doc.export_meta.integrity_check_at_export.valid).toBe(true);
    expect(screen.getByTestId("export-result")).toHaveTextContent("Exported 4 entries");
  });

  it("still exports (marked 'not run') if the integrity check fails, and reports fetch failures", async () => {
    render(<App api={makeApi({ verify: async () => { throw new Error("503"); } })} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Export evidence" }));
    await screen.findByTestId("export-result");
    expect(JSON.parse(await readBlob(blobs[0])).export_meta.integrity_check_at_export).toBe("not run");
  });

  it("shows an error when the log cannot be fetched for export", async () => {
    let calls = 0;
    const api = makeApi({ allEntries: async () => { if (++calls > 1) throw new Error("boom"); return { items: ENTRIES, total: 4, truncated: false }; } });
    render(<App api={api} />);
    await screen.findByText("flagged sites");
    fireEvent.click(screen.getByRole("button", { name: "Export evidence" }));
    expect(await screen.findByText("Export failed")).toBeInTheDocument();
    expect(blobs).toHaveLength(0);
  });
});

describe("api client", () => {
  const fakeFetch = (pages) => vi.fn(async (url) => {
    const m = /offset=(\d+)/.exec(url);
    if (m) return { ok: true, json: async () => pages[Number(m[1]) / 500] };
    return { ok: true, json: async () => ({}) };
  });

  it("pages through the log until it has everything", async () => {
    const mk = (n, start) => Array.from({ length: n }, (_, i) => ({ id: start + i }));
    const f = fakeFetch([{ total: 620, items: mk(500, 1) }, { total: 620, items: mk(120, 501) }]);
    const out = await createApi("http://x", f).allEntries();
    expect(out.items).toHaveLength(620);
    expect(out.truncated).toBe(false);
    expect(f.mock.calls.map((c) => c[0])).toEqual([
      "http://x/forensic-log?limit=500&offset=0", "http://x/forensic-log?limit=500&offset=500"]);
  });

  it("includes the server's error detail in thrown errors", async () => {
    const f = vi.fn(async () => ({ ok: false, status: 503, json: async () => ({ detail: "FORENSIC_HMAC_KEY is not set" }) }));
    await expect(createApi("http://x", f).verify()).rejects.toThrow(/503.*FORENSIC_HMAC_KEY/);
  });
});

describe("Case report", () => {
  let blobs, anchors;
  beforeEach(() => {
    blobs = [];
    anchors = [];
    URL.createObjectURL = vi.fn((b) => { blobs.push(b); return `blob:${blobs.length}`; });
    URL.revokeObjectURL = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function () { anchors.push(this.download); });
  });
  const open = async (api) => {
    render(<App api={api} />);
    await screen.findByText("flagged sites");
    const form = screen.getByRole("form", { name: "Case report" });
    return {
      form,
      caseInput: within(form).getByPlaceholderText("e.g. DEMO-001"),
      examInput: within(form).getByPlaceholderText("Your name"),
      button: within(form).getByRole("button", { name: "Generate case report" }),
    };
  };

  it("button sits next to Export evidence and stays disabled until case ID and examiner are filled", async () => {
    const { caseInput, examInput, button } = await open(makeApi());
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeInTheDocument();
    expect(button).toBeDisabled();
    fireEvent.change(caseInput, { target: { value: "DEMO-001" } });
    expect(button).toBeDisabled();
    fireEvent.change(examInput, { target: { value: "   " } });
    expect(button).toBeDisabled();                      // whitespace-only examiner does not count
    fireEvent.change(examInput, { target: { value: "Dr. A. Examiner" } });
    expect(button).toBeEnabled();
  });

  it("offers the case IDs present in the log as suggestions", async () => {
    await open(makeApi());
    expect([...document.querySelectorAll("#case-ids option")].map((o) => o.value)).toEqual(["case-1"]);
  });

  it("sends trimmed values, downloads the PDF with a .pdf name and shows the report-data hash", async () => {
    const caseReport = vi.fn(async () => ({ blob: new Blob(["%PDF-1.4 fake"], { type: "application/pdf" }), sha256: "ab".repeat(32) }));
    const { caseInput, examInput, button } = await open(makeApi({ caseReport }));
    fireEvent.change(caseInput, { target: { value: "  DEMO 001/x  " } });
    fireEvent.change(examInput, { target: { value: " Dr. A. Examiner " } });
    fireEvent.click(button);
    const res = await screen.findByTestId("report-result");
    expect(caseReport).toHaveBeenCalledWith("DEMO 001/x", "Dr. A. Examiner");
    expect(blobs).toHaveLength(1);
    expect(blobs[0].type).toBe("application/pdf");
    expect(anchors[0]).toMatch(/^case-report_DEMO_001_x_\d{8}T\d{6}Z\.pdf$/);   // path characters can't leak into the filename
    expect(screen.getByTestId("report-hash")).toHaveTextContent("ab".repeat(32));
    expect(res).toHaveTextContent("INTEGRITY FAILURE");   // tells the reader what a red banner means
  });

  it("shows the server's error and downloads nothing when generation fails (e.g. 503 no HMAC key)", async () => {
    const caseReport = vi.fn(async () => { throw new Error("/forensic-log/report returned 503 — FORENSIC_HMAC_KEY is not set"); });
    const { caseInput, examInput, button } = await open(makeApi({ caseReport }));
    fireEvent.change(caseInput, { target: { value: "C1" } });
    fireEvent.change(examInput, { target: { value: "E" } });
    fireEvent.click(button);
    const alert = await screen.findByText("Report failed");
    expect(alert.closest(".result")).toHaveClass("warn");
    expect(alert.closest(".result")).toHaveTextContent("FORENSIC_HMAC_KEY");
    expect(blobs).toHaveLength(0);
    expect(screen.queryByTestId("report-result")).toBeNull();
  });

  it("pressing Enter in a field submits when valid", async () => {
    const caseReport = vi.fn(async () => ({ blob: new Blob(["x"]), sha256: null }));
    const { form, caseInput, examInput } = await open(makeApi({ caseReport }));
    fireEvent.change(caseInput, { target: { value: "C1" } });
    fireEvent.change(examInput, { target: { value: "E" } });
    fireEvent.submit(form);
    await screen.findByTestId("report-result");
    expect(caseReport).toHaveBeenCalledTimes(1);
    expect(screen.getByTestId("report-hash")).toHaveTextContent("not exposed");
  });
});

describe("api.caseReport", () => {
  it("URL-encodes parameters, asks for pdf, and returns the blob and hash header", async () => {
    const f = vi.fn(async () => ({ ok: true, blob: async () => new Blob(["%PDF"]), headers: { get: (h) => (h === "x-report-data-sha256" ? "cd".repeat(32) : null) } }));
    const out = await createApi("http://x", f).caseReport("A&B c", "Zoë <x>");
    const url = new URL(f.mock.calls[0][0]);
    expect(url.pathname).toBe("/forensic-log/report");
    expect(url.searchParams.get("case_id")).toBe("A&B c");
    expect(url.searchParams.get("examiner")).toBe("Zoë <x>");
    expect(url.searchParams.get("format")).toBe("pdf");
    expect(out.sha256).toBe("cd".repeat(32));
  });

  it("includes the server's error detail", async () => {
    const f = vi.fn(async () => ({ ok: false, status: 422, json: async () => ({ detail: "case_id and examiner must not be blank" }) }));
    await expect(createApi("http://x", f).caseReport("a", "b")).rejects.toThrow(/422.*must not be blank/);
  });
});
