// Run: node --test extension/tests
// EICAR is held in memory only and served from a throwaway localhost server.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { buildPayload, fetchAndHash, scanDownload, basename } from "../download-scan.js";

const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

function serve(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () =>
      resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() }));
  });
}

test("EICAR sample hashes to the published SHA-256", async () => {
  const s = await serve((req, res) => res.end(EICAR));
  try {
    const r = await fetchAndHash(`${s.url}/eicar.com`);
    assert.equal(r.sha256, EICAR_SHA);
    assert.equal(r.size, 68);
  } finally { s.close(); }
});

test("multi-chunk streamed body hashes identically", async () => {
  const s = await serve((req, res) => {
    res.write(EICAR.slice(0, 10));
    setTimeout(() => { res.write(EICAR.slice(10, 40)); setTimeout(() => res.end(EICAR.slice(40)), 20); }, 20);
  });
  try {
    assert.equal((await fetchAndHash(`${s.url}/x`)).sha256, EICAR_SHA);
  } finally { s.close(); }
});

test("HTTP 403 (auth-protected) falls back, no throw", async () => {
  const s = await serve((req, res) => { res.statusCode = 403; res.end("no"); });
  try {
    const r = await fetchAndHash(`${s.url}/x`);
    assert.equal(r.sha256, null);
    assert.match(r.reason, /403/);
  } finally { s.close(); }
});

test("declared Content-Length over the cap falls back", async () => {
  const s = await serve((req, res) => { res.setHeader("content-length", "1000"); res.end("a".repeat(1000)); });
  try {
    const r = await fetchAndHash(`${s.url}/big`, { maxBytes: 500 });
    assert.equal(r.sha256, null);
    assert.match(r.reason, /cap/);
  } finally { s.close(); }
});

test("chunked body without Content-Length is cut off at the cap", async () => {
  let aborted = false;
  const s = await serve((req, res) => {
    req.on("close", () => { aborted = true; });
    const t = setInterval(() => res.write("a".repeat(100)), 5);
    res.on("close", () => clearInterval(t));
  });
  try {
    const r = await fetchAndHash(`${s.url}/stream`, { maxBytes: 450 });
    assert.equal(r.sha256, null);
    assert.match(r.reason, /cap/);
  } finally { s.close(); }
});

test("network failure and non-http URLs fall back", async () => {
  assert.equal((await fetchAndHash("http://127.0.0.1:1/x")).sha256, null);
  for (const u of ["blob:https://a/1", "data:text/plain,hi", "file:///etc/passwd", undefined]) {
    const r = await fetchAndHash(u);
    assert.equal(r.sha256, null, u);
    assert.match(r.reason, /not http/);
  }
});

test("re-fetch omits credentials", async () => {
  let seen;
  const fetchImpl = async (url, opts) => { seen = opts; return new Response(EICAR); };
  await fetchAndHash("https://example.com/a", { fetchImpl });
  assert.equal(seen.credentials, "omit");
});

test("timeout aborts a hung download", async () => {
  const s = await serve(() => { /* never respond */ });
  try {
    const r = await fetchAndHash(`${s.url}/hang`, { timeoutMs: 100 });
    assert.equal(r.sha256, null);
    assert.match(r.reason, /timeout/);
  } finally { s.close(); }
});

test("basename strips local paths (Windows and POSIX)", () => {
  assert.equal(basename("C:\\Users\\bob\\Downloads\\a.exe"), "a.exe");
  assert.equal(basename("/Users/bob/Downloads/a.exe"), "a.exe");
});

test("scanDownload sends only hash + metadata, never file bytes or local path", async () => {
  const file = await serve((req, res) => res.end(EICAR));
  const sent = [];
  const fetchImpl = async (url, opts) => {
    if (String(url).startsWith("http://backend.test")) {
      sent.push({ url: String(url), body: opts.body });
      return new Response(JSON.stringify({ verdict: "malicious", risk_score: 0.95, reasons: ["EICAR"] }),
                          { status: 200 });
    }
    return fetch(url, opts);
  };
  try {
    const item = { filename: "/Users/bob/Downloads/eicar.com", url: `${file.url}/eicar.com`,
                   mime: "application/octet-stream", fileSize: 68 };
    const out = await scanDownload(item, { apiBase: "http://backend.test", fetchImpl });
    assert.equal(out.hashed, true);
    assert.equal(out.data.verdict, "malicious");
    assert.equal(sent.length, 1);
    assert.equal(sent[0].url, "http://backend.test/analyze-file");
    const body = JSON.parse(sent[0].body);
    assert.deepEqual(Object.keys(body).sort(),
                     ["filename", "mime_type", "sha256", "size_bytes", "source_url"]);
    assert.equal(body.sha256, EICAR_SHA);
    assert.equal(body.filename, "eicar.com");
    assert.ok(!sent[0].body.includes("EICAR-STANDARD"), "file contents must not be sent");
    assert.ok(!sent[0].body.includes("/Users/bob"), "local path must not be sent");
  } finally { file.close(); }
});

test("scanDownload falls back to metadata-only when re-fetch fails", async () => {
  const file = await serve((req, res) => { res.statusCode = 401; res.end(); });
  let body;
  const fetchImpl = async (url, opts) => {
    if (String(url).startsWith("http://backend.test")) {
      body = JSON.parse(opts.body);
      return new Response(JSON.stringify({ verdict: "malicious", risk_score: 0.9, reasons: [] }), { status: 200 });
    }
    return fetch(url, opts);
  };
  try {
    const item = { filename: "C:\\dl\\invoice.pdf.exe", finalUrl: `${file.url}/a`, url: "http://ignored", fileSize: 1234 };
    const out = await scanDownload(item, { apiBase: "http://backend.test", fetchImpl });
    assert.equal(out.hashed, false);
    assert.match(out.fallbackReason, /401/);
    assert.equal(body.sha256, null);
    assert.equal(body.filename, "invoice.pdf.exe");
    assert.equal(body.size_bytes, 1234);
    assert.ok(body.source_url.startsWith(file.url), "finalUrl preferred over url");
  } finally { file.close(); }
});

test("backend error is surfaced", async () => {
  const fetchImpl = async (url) => String(url).startsWith("http://backend.test")
    ? new Response("x", { status: 500 }) : new Response(EICAR);
  await assert.rejects(
    scanDownload({ filename: "a.bin", url: "https://example.com/a" }, { apiBase: "http://backend.test", fetchImpl }),
    /500/);
});

test("buildPayload tolerates missing fields", () => {
  const p = buildPayload({ filename: "a.txt" }, { sha256: null });
  assert.deepEqual(p, { filename: "a.txt", sha256: null, size_bytes: null, source_url: null, mime_type: null });
});
