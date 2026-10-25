#!/usr/bin/env node
// Real-browser end-to-end test: Chrome + the unpacked extension + the real backend.
//
//   (backend running on 127.0.0.1:8000 with FORENSIC_HMAC_KEY set, ideally a fresh DB)
//   node scripts/e2e_extension.mjs [path-to-chrome]
//
// Hermetic: every hostname resolves to 127.0.0.1 (--host-resolver-rules) and a
// local server plays the "tracker", "phishing" and "download" sites, so no
// real third-party site is contacted and only the EICAR test string is used.
// Needs Google Chrome >= 126 (uses Extensions.loadUnpacked over the debugging pipe).
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const API = process.env.API ?? "http://127.0.0.1:8000";
const CHROME = process.argv[2] ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const EXT_ID = "gknjaknibkcfffkjjceppndfodajfjil";
const EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failed = 0;
const check = (name, ok, detail = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  — " + detail : ""}`); if (!ok) failed++; };
const api = async (p) => (await fetch(API + p)).json();
const entries = async () => (await api("/forensic-log?limit=500")).items;

// ------------------------------------------------------------ fake internet
const TRACKERS = [
  "www.google-analytics.com/analytics.js", "stats.g.doubleclick.net/j/collect", "bat.bing.com/bat.js",
  "static.hotjar.com/c/hotjar-1.js", "sb.scorecardresearch.com/beacon.js", "pixel.quantserve.com/pixel",
  "www.facebook.com/tr/?id=1&ev=PageView", "px.ads.linkedin.com/collect", "cdn.taboola.com/libtrc/loader.js",
  "widgets.outbrain.com/outbrain.js", "connect.facebook.net/signals/config/1",
  "pagead2.googlesyndication.com/pagead/js/adsbygoogle.js",
];
const GIF = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64"); // 1x1 gif
// Chrome ships HSTS preloads for many real tracker domains (google-analytics.com, doubleclick.net,
// facebook.com ...) and upgrades these fake http:// requests to https://, which fail against this
// plain-HTTP server: the request is still seen (and classified) but no response/cookie arrives.
// The adnet-*.test hosts below respond normally so third-party cookie counting can be exercised.
let PORT;
const server = http.createServer((req, res) => {
  const host = (req.headers.host ?? "").split(":")[0];
  const url = new URL(req.url, "http://x");
  const headers = { "cache-control": "no-store" };
  if (host !== "shop.test") headers["set-cookie"] = "uid=1; Path=/"; // third-party cookie attempt
  if (host === "shop.test" && url.pathname === "/") {
    const tags = TRACKERS.map((t, i) => t.endsWith(".js") || t.includes(".js?")
      ? `<script src="http://${t}${t.includes("?") ? "&" : "?"}p=${PORT}" onerror="0"></script>`.replace(t.split("/")[0], `${t.split("/")[0]}:${PORT}`)
      : `<img src="http://${t.split("/")[0]}:${PORT}/${t.split("/").slice(1).join("/")}" width="${i === 5 ? 1 : 40}" height="${i === 5 ? 1 : 40}">`);
    res.writeHead(200, { ...headers, "content-type": "text/html" });
    return res.end(`<!doctype html><title>shop</title><h1>Shop</h1>${tags.join("\n")}
      ${[1, 2, 3, 4, 5, 6].map((n) => `<img src="http://adnet-${n}.test:${PORT}/x.gif" width="30" height="30">`).join("\n")}
      <script src="http://cdn.fp.test:${PORT}/fp.js"></script>
      <script>navigator.sendBeacon("http://bat.bing.com:${PORT}/collect", "x")</script>`);
  }
  if (url.pathname === "/fp.js") {
    res.writeHead(200, { ...headers, "content-type": "text/javascript" });
    return res.end(`const c=document.createElement("canvas");c.width=200;c.height=50;const x=c.getContext("2d");
      x.font="14px Arial";x.fillText("Cwm fjordbank glyphs vext quiz",2,15);c.toDataURL();`);
  }
  if (host === "dl.test") {
    res.writeHead(200, { ...headers, "content-type": "application/octet-stream",
      "content-disposition": 'attachment; filename="eicar.com"', "content-length": Buffer.byteLength(EICAR) });
    return res.end(EICAR);
  }
  if (url.pathname.endsWith(".js") || url.pathname.includes("signals") || url.pathname === "/pagead/js/adsbygoogle.js") {
    res.writeHead(200, { ...headers, "content-type": "text/javascript" }); return res.end("/*x*/");
  }
  if (url.pathname.includes("pixel") || url.pathname.startsWith("/tr") || url.pathname.endsWith(".gif")) {
    res.writeHead(200, { ...headers, "content-type": "image/gif" }); return res.end(GIF);
  }
  res.writeHead(200, { ...headers, "content-type": "text/html" });
  res.end("<!doctype html><title>page</title>hello");
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
PORT = server.address().port;

// ------------------------------------------------------------------ chrome
const profile = fs.mkdtempSync(path.join(os.tmpdir(), "bsa-e2e-profile-"));
const dlDir = fs.mkdtempSync(path.join(os.tmpdir(), "bsa-e2e-dl-"));
const chrome = spawn(CHROME, ["--headless=new", "--disable-gpu", "--remote-debugging-pipe",
  "--enable-unsafe-extension-debugging", "--user-data-dir=" + profile, "--no-first-run",
  "--host-resolver-rules=MAP * 127.0.0.1,EXCLUDE localhost", "about:blank"],
  { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
const [toChrome, fromChrome] = [chrome.stdio[3], chrome.stdio[4]];
let buf = "", seq = 0; const waiters = new Map();
fromChrome.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\0")) >= 0) { const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); waiters.get(m.id)?.(m); } });
const send = (method, params = {}, sessionId) => new Promise((r) => { const i = ++seq; waiters.set(i, r); toChrome.write(JSON.stringify({ id: i, method, params, ...(sessionId ? { sessionId } : {}) }) + "\0"); });
const exited = new Promise((r) => chrome.on("exit", r));
const cleanup = async () => {
  try { chrome.kill(); } catch {}
  await Promise.race([exited, sleep(5000)]);
  server.close();
  for (const d of [profile, dlDir]) { try { fs.rmSync(d, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch {} }
};

try {
  const loaded = await send("Extensions.loadUnpacked", { path: path.join(ROOT, "extension") });
  check("extension loads in Chrome with the pinned ID", loaded.result?.id === EXT_ID, loaded.result?.id ?? JSON.stringify(loaded.error));
  await send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath: dlDir });
  await sleep(1500);

  const targets = async () => (await send("Target.getTargets")).result.targetInfos;
  const sw = (await targets()).find((t) => t.type === "service_worker" && t.url.includes(EXT_ID));
  check("extension service worker is running", !!sw);
  const { sessionId } = (await send("Target.attachToTarget", { targetId: sw.targetId, flatten: true })).result;
  const inSW = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
    if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 300));
    return r.result?.result?.value;
  };
  const open = (url) => send("Target.createTarget", { url });
  const before = (await entries()).length;

  // 1. phishing-looking URL -> badge + forensic entry
  // NB: browsers lowercase hostnames, so the extension sees "paypai-…", not "paypaI-…".
  const phishUrl = `http://paypai-secure-login.test:${PORT}/verify/account`;
  await open(phishUrl);
  await sleep(3500);
  const badge = await inSW(`(async()=>{const t=(await chrome.tabs.query({})).find(t=>t.url&&t.url.includes("paypai"));return t?await chrome.action.getBadgeText({tabId:t.id}):null})()`);
  check("phishing-looking tab gets a warning badge from the extension", badge === "!" || badge === "!!", `badge=${JSON.stringify(badge)}`);

  // 2. tracker-heavy page
  await open(`http://shop.test:${PORT}/`);
  await sleep(9000); // page load + 3 s report debounce
  // 3. EICAR download
  await open(`http://dl.test:${PORT}/eicar.com`);
  let dl = null;
  for (let i = 0; i < 20 && !(dl?.status === "done"); i++) {
    await sleep(500);
    dl = (await inSW(`chrome.storage.local.get("downloadResults").then(r=>r.downloadResults||[])`))?.find((d) => d.filename === "eicar.com");
  }
  check("download completed and was scanned by the extension", dl?.status === "done", JSON.stringify(dl)?.slice(0, 200));
  check("extension re-fetched and hashed the file (not metadata-only)", dl?.hashed === true, `fallback=${dl?.fallbackReason ?? "none"}`);
  check("EICAR rated malicious", dl?.data?.verdict === "malicious", `${dl?.data?.verdict} ${dl?.data?.risk_score}`);
  check("file saved by Chrome is the 68-byte EICAR string", fs.existsSync(path.join(dlDir, "eicar.com")) && fs.statSync(path.join(dlDir, "eicar.com")).size === 68);

  // ---- backend evidence
  const all = await entries();
  const fresh = all.slice(before);
  const phish = fresh.find((e) => e.event_type === "phishing_url" && e.details.url.includes("paypai"));
  check("phishing URL reached the forensic log", !!phish, phish ? `${phish.details.verdict} ${phish.details.risk_score}` : "no entry");
  const file = fresh.find((e) => e.event_type === "malicious_file");
  check("EICAR logged with the right SHA-256 and mode", file?.details.sha256 === EICAR_SHA && file?.details.analysis_mode === "hash+metadata", file ? `${file.details.sha256?.slice(0, 12)} ${file.details.analysis_mode}` : "no entry");
  check("source URL of the download is not the local path", file && !String(file.details.filename).includes("/"), file?.details.filename);

  const trkEntries = fresh.filter((e) => e.event_type === "tracker_session");
  const trk = trkEntries[0];
  check("tracker-heavy page reached the forensic log", !!trk, trk ? JSON.stringify(trk.details.reasons) : "no entry");
  if (trk) {
    check("  ≥10 tracker domains detected from the bundled lists", trk.details.tracker_domains >= 10, `${trk.details.tracker_domains} of ${trk.details.third_party_domains} third-party domains`);
    check("  canvas fingerprinting flagged with the script host", trk.details.canvas_fingerprinting === true && trk.details.canvas_scripts.includes("cdn.fp.test"), JSON.stringify(trk.details.canvas_scripts));
    check("  pixel(s) and beacon seen", trk.details.pixels >= 1 && trk.details.beacons >= 1, `pixels=${trk.details.pixels} beacons=${trk.details.beacons}`);
    const last = (await api("/tracker-report?site=shop.test")).sites[0];
    check("  third-party Set-Cookie headers counted (final report)", last.third_party_cookies >= 10, `cookies=${last.third_party_cookies}`);
    check("  excessive-cookies threshold logged as its own forensic entry",
      trkEntries.some((e) => e.details.reasons.includes("excessive_third_party_cookies")), trkEntries.map((e) => e.details.reasons.join("+")).join(" | "));
    check("  list versions recorded", !!trk.details.list_versions?.easylist, JSON.stringify(trk.details.list_versions));
  }
  const rep = await api("/tracker-report?site=shop.test");
  check("GET /tracker-report aggregates the page load", rep.totals.sessions === 1 && rep.top_networks.length > 0, JSON.stringify(rep.totals));
  const v = await api("/forensic-log/verify");
  check("forensic chain verifies after real extension traffic", v.valid === true, `${v.entries_checked} entries`);
} catch (e) {
  check("script ran to completion", false, e.stack ?? String(e));
} finally {
  await cleanup();
}
console.log(failed ? `\n${failed} check(s) FAILED` : "\nall checks passed");
process.exit(failed ? 1 : 0);
