import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

import { parseFilterList, parseHeader, serializeCompiled } from "../../scripts/lib/parse-filters.mjs";
import { createMatcher, hostOf, isThirdParty, registrableDomain } from "../tracker-match.js";
import { TabSession, EXCESSIVE_COOKIES } from "../tracker-session.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, "..", "..");
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------- fixtures
const FIXTURE = `[Adblock Plus 2.0]
! Version: 111
! Title: Fixture
! Last modified: 01 Jan 2026 00:00 UTC
||tracker.example^$third-party
||ads.example.net^
||analytics.example/collect?
||pix.example/img/pixel.gif
@@||allowed.tracker.example^
||popup-only.example^$popup
||docs.example^$document
||restricted.example^$domain=a.com
||firstonly.example^$~third-party
||wild*.example^
||cdn.example/*/ad.js
##.ad-banner
example.com##.sponsor
/banner\\d+/
&ad_type=
||badopt.example^$csp=default-src
||Mixed.Case.Example^
`;

function fixtureMatcher() {
  const { compiled } = parseFilterList(FIXTURE);
  return createMatcher({ easylist: serializeCompiled(compiled) });
}

// ------------------------------------------------------------------ parser
test("parser keeps domain, path and exception rules and skips unsupported ones", () => {
  const { compiled, stats } = parseFilterList(FIXTURE);
  assert.deepEqual([...compiled.domains].sort(),
    ["ads.example.net", "mixed.case.example", "tracker.example"]);
  assert.deepEqual([...compiled.paths.keys()].sort(),
    ["analytics.example", "pix.example"]);
  assert.deepEqual([...compiled.exceptions], ["allowed.tracker.example"]);
  for (const why of ["popup-or-document", "domain-option", "first-party-only", "cosmetic",
                     "regex", "url-substring", "unsupported-option", "wildcard-path"]) {
    assert.ok(stats.skipped[why] > 0, `expected skip reason ${why}: ${JSON.stringify(stats.skipped)}`);
  }
});

test("header parsing", () => {
  assert.deepEqual(parseHeader(FIXTURE), { title: "Fixture", version: "111", last_modified: "01 Jan 2026 00:00 UTC" });
});

// ----------------------------------------------------------------- matcher
test("domain rule matches host and all subdomains but not lookalikes", () => {
  const m = fixtureMatcher();
  assert.equal(m.match("https://tracker.example/x.js")?.rule, "domain");
  assert.equal(m.match("https://sub.deep.tracker.example/x")?.domain, "tracker.example");
  assert.equal(m.match("https://nottracker.example/x"), null);
  assert.equal(m.match("https://tracker.example.evil.com/x"), null);
  assert.equal(m.match("https://example/x"), null);
});

test("exception beats a broader domain rule", () => {
  const m = fixtureMatcher();
  assert.equal(m.match("https://allowed.tracker.example/lib.js"), null);
  assert.ok(m.match("https://other.tracker.example/lib.js"));
});

test("path rules match only their prefix", () => {
  const m = fixtureMatcher();
  assert.equal(m.match("https://analytics.example/collect?v=1")?.rule, "path");
  assert.equal(m.match("https://analytics.example/home"), null);
  assert.ok(m.match("https://pix.example/img/pixel.gif?x=1"));
  assert.equal(m.match("https://pix.example/img/logo.png"), null);
});

test("unsupported / popup-only / domain=-restricted / first-party-only rules do not match", () => {
  const m = fixtureMatcher();
  for (const h of ["popup-only.example", "docs.example", "restricted.example", "firstonly.example", "badopt.example"]) {
    assert.equal(m.match(`https://${h}/`), null, h);
  }
});

test("case-insensitive; non-http schemes and garbage are ignored", () => {
  const m = fixtureMatcher();
  assert.ok(m.match("HTTPS://TRACKER.EXAMPLE./a"));
  assert.ok(m.match("https://mixed.case.example/"));
  for (const u of ["chrome://tracker.example/", "data:text/plain,hi", "not a url", ""]) {
    assert.equal(m.match(u), null, u);
  }
});

test("easyprivacy is reported in preference to easylist when both match", () => {
  const a = parseFilterList("||both.example^\n").compiled;
  const m = createMatcher({ easylist: serializeCompiled(a), easyprivacy: serializeCompiled(a) });
  assert.equal(m.match("https://both.example/").list, "easyprivacy");
});

// -------------------------------------------------------- third-party logic
test("registrable domain and third-party detection", () => {
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(registrableDomain("192.168.1.5"), "192.168.1.5");
  assert.equal(hostOf("ftp://x.com/"), null);
  assert.equal(isThirdParty("www.example.com", "cdn.example.com"), false);
  assert.equal(isThirdParty("example.com", "doubleclick.net"), true);
  assert.equal(isThirdParty("shop.bbc.co.uk", "static.bbc.co.uk"), false);
  assert.equal(isThirdParty("bbc.co.uk", "itv.co.uk"), true);
});

// --------------------------------------------- real bundled snapshot data
const real = JSON.parse(fs.readFileSync(path.join(ROOT, "extension", "data", "tracker-lists.json"), "utf8"));
const realMatcher = createMatcher(real);

test("real lists flag well-known tracker/ad hosts", () => {
  for (const url of [
    "https://www.google-analytics.com/analytics.js",
    "https://stats.g.doubleclick.net/collect",
    "https://www.facebook.com/tr/?id=123&ev=PageView",   // path rule: ||facebook.com/tr/
    "https://connect.facebook.net/signals/config/1",    // path rule
    "https://bat.bing.com/bat.js",
    "https://static.hotjar.com/c/hotjar-1.js",
  ]) {
    const hit = realMatcher.match(url);
    assert.ok(hit, `${url} should match`);
    assert.ok(["easylist", "easyprivacy"].includes(hit.list));
  }
});

test("real lists do not flag ordinary sites or CDNs", () => {
  for (const url of [
    "https://www.wikipedia.org/", "https://github.com/", "https://developer.mozilla.org/en-US/",
    "https://stackoverflow.com/questions", "https://fonts.gstatic.com/s/roboto.woff2",
  ]) {
    assert.equal(realMatcher.match(url), null, url);
  }
});

test("bundled manifest matches the snapshot files and the compiled data", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "data", "blocklists", "manifest.json"), "utf8"));
  assert.deepEqual(manifest.lists.map((l) => l.name).sort(), ["easylist", "easyprivacy"]);
  for (const l of manifest.lists) {
    const buf = fs.readFileSync(path.join(ROOT, "data", "blocklists", `${l.name}.txt`));
    assert.equal(createHash("sha256").update(buf).digest("hex"), l.sha256, `${l.name} snapshot was modified`);
    assert.equal(buf.length, l.bytes);
    assert.match(l.downloaded, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(l.list_version && l.source.startsWith("https://easylist.to/"));
    assert.equal(real.meta.lists.find((x) => x.name === l.name).sha256, l.sha256,
      "extension/data/tracker-lists.json is stale: run node scripts/build_tracker_lists.mjs");
  }
});

// ---------------------------------------------------------- tab sessions
function session(page = "https://news.example.org/story", m = realMatcher) {
  return new TabSession(page, m, "sess-00000001");
}

test("session counts third-party requests, trackers and unknown third parties", () => {
  const s = session();
  assert.deepEqual(s.recordRequest({ url: "https://news.example.org/app.js", type: "script" }), { thirdParty: false });
  assert.equal(s.recordRequest({ url: "https://www.google-analytics.com/collect", type: "xmlhttprequest" }).kind, "tracker");
  s.recordRequest({ url: "https://www.google-analytics.com/analytics.js", type: "script" });
  assert.equal(s.recordRequest({ url: "https://cdn.somewidget.example/w.js", type: "script" }).kind, "unknown_third_party");
  const snap = s.snapshot();
  assert.equal(snap.total_requests, 4);
  assert.equal(snap.third_party_requests, 3);
  assert.equal(snap.third_party_domains, 2);
  assert.equal(snap.tracker_domains, 1);
  assert.equal(snap.tracker_requests, 2);
  assert.equal(snap.unknown_third_party_domains, 1);
  assert.equal(snap.top_networks[0].network, "google-analytics.com");
  assert.ok(snap.list_versions.easylist && snap.list_versions.easyprivacy);
});

test("first-party and same-site subdomain requests are not third-party", () => {
  const s = session("https://www.bbc.co.uk/");
  s.recordRequest({ url: "https://static.bbc.co.uk/a.js", type: "script" });
  assert.equal(s.snapshot().third_party_requests, 0);
});

test("beacons: ping requests (sendBeacon / <a ping>) are flagged, even to unknown hosts", () => {
  const s = session();
  const r = s.recordRequest({ url: "https://collector.unknown-host.example/b", type: "ping" });
  assert.equal(r.beacon, true);
  assert.equal(r.kind, "unknown_third_party");
  assert.equal(s.snapshot().beacons, 1);
});

test("pixels: URL pattern, tiny content-length, and DOM-reported tiny images", () => {
  const s = session();
  assert.equal(s.recordRequest({ url: "https://t.unknown.example/pixel.gif?id=1", type: "image" }).pixel, true);
  assert.equal(s.recordRequest({ url: "https://cdn.unknown.example/photo.jpg", type: "image" }).pixel, false);

  s.recordCompleted({ url: "https://x.unknown.example/a.gif", type: "image", contentLength: 43 });
  s.recordCompleted({ url: "https://x.unknown.example/big.png", type: "image", contentLength: 40000 });
  s.recordCompleted({ url: "https://news.example.org/dot.gif", type: "image", contentLength: 43 }); // first-party

  s.recordTinyImages(["https://y.unknown.example/i?z=1", "https://news.example.org/spacer.png"]);
  assert.equal(s.snapshot().pixels, 3); // pixel.gif, a.gif, y.unknown (first-party ignored)

  // the request for an already-reported tiny image is still classified as a pixel,
  // but is not double counted
  assert.equal(s.recordRequest({ url: "https://y.unknown.example/i?z=1", type: "image" }).pixel, true);
  assert.equal(s.snapshot().pixels, 3);
  // while a normal photo from the same host is not
  assert.equal(s.recordRequest({ url: "https://y.unknown.example/photo.jpg", type: "image" }).pixel, false);
});

test("third-party cookies flagged as excessive at the threshold", () => {
  const s = session();
  for (let i = 0; i < EXCESSIVE_COOKIES - 1; i++) s.recordSetCookie(`https://t${i}.adnet.example/x`);
  s.recordSetCookie("https://news.example.org/first-party"); // ignored
  assert.equal(s.snapshot().excessive_third_party_cookies, false);
  s.recordSetCookie("https://last.adnet.example/x");
  const snap = s.snapshot();
  assert.equal(snap.third_party_cookies, EXCESSIVE_COOKIES);
  assert.equal(snap.excessive_third_party_cookies, true);
});

test("canvas events: only suspicious ones set the fingerprinting flag", () => {
  const s = session();
  s.recordCanvas({ api: "toDataURL", suspicious: false, scriptHost: "news.example.org" });
  assert.equal(s.snapshot().canvas_fingerprinting, false);
  s.recordCanvas({ api: "toDataURL", suspicious: true, scriptHost: "fp.tracker.example" });
  const snap = s.snapshot();
  assert.equal(snap.canvas_fingerprinting, true);
  assert.deepEqual(snap.canvas_scripts, ["fp.tracker.example"]);
  assert.equal(snap.canvas_events, 2);
});

test("session survives a service-worker restart (JSON round trip)", () => {
  const s = session();
  s.recordRequest({ url: "https://www.google-analytics.com/collect", type: "image" });
  s.recordRequest({ url: "https://stats.g.doubleclick.net/x", type: "ping" });
  s.recordSetCookie("https://stats.g.doubleclick.net/x");
  s.recordCanvas({ api: "getImageData", suspicious: true, scriptHost: "fp.example" });
  const restored = TabSession.fromJSON(JSON.parse(JSON.stringify(s.toJSON())), realMatcher);
  assert.deepEqual(restored.snapshot(), s.snapshot());
});

// ------------------------------------------------------------ canvas hook
const { install, scriptHostFromStack } = require("../canvas-hook.js");

function fakeWindow() {
  class HTMLCanvasElement {
    constructor(w, h) { this.width = w; this.height = h; }
    toDataURL() { return "data:image/png;base64,AAA"; }
    toBlob() { return "blob"; }
  }
  class CanvasRenderingContext2D {
    constructor(canvas) { this.canvas = canvas; }
    fillText() { return "filled"; }
    strokeText() {}
    getImageData() { return { data: [] }; }
  }
  return { HTMLCanvasElement, CanvasRenderingContext2D };
}

test("canvas hook flags text-then-read on a small canvas and preserves behaviour", () => {
  const win = fakeWindow();
  const events = [];
  assert.equal(install(win, (e) => events.push(e)), true);
  const canvas = new win.HTMLCanvasElement(240, 60);
  const ctx = new win.CanvasRenderingContext2D(canvas);
  assert.equal(ctx.fillText("Cwm fjordbank", 2, 15), "filled");     // return value preserved
  assert.equal(canvas.toDataURL(), "data:image/png;base64,AAA");     // return value preserved
  assert.equal(events.length, 1);
  assert.equal(events[0].api, "toDataURL");
  assert.equal(events[0].suspicious, true);
  assert.equal(events[0].text_drawn, true);
});

test("canvas hook: reads without text are recorded but not suspicious; getImageData and toBlob covered", () => {
  const win = fakeWindow();
  const events = [];
  install(win, (e) => events.push(e));
  const plain = new win.HTMLCanvasElement(300, 300);
  plain.toDataURL();
  const ctx2 = new win.CanvasRenderingContext2D(plain);
  ctx2.getImageData(0, 0, 1, 1);
  assert.ok(events.every((e) => e.suspicious === false));
  assert.deepEqual(events.map((e) => e.api).sort(), ["getImageData", "toDataURL"]);

  const fp = new win.HTMLCanvasElement(200, 50);
  new win.CanvasRenderingContext2D(fp).strokeText("x", 0, 0);
  fp.toBlob();
  assert.equal(events.at(-1).api, "toBlob");
  assert.equal(events.at(-1).suspicious, true);
});

test("canvas hook: huge canvases are not flagged, duplicates are throttled, hook errors never leak", () => {
  const win = fakeWindow();
  const events = [];
  install(win, (e) => { events.push(e); throw new Error("reporter blew up"); });
  const big = new win.HTMLCanvasElement(4000, 4000);
  new win.CanvasRenderingContext2D(big).fillText("t");
  assert.doesNotThrow(() => big.toDataURL());
  assert.equal(events[0].suspicious, false);
  big.toDataURL(); big.toDataURL();
  assert.equal(events.length, 1);
});

test("script host is parsed from a stack trace", () => {
  const stack = `Error\n    at onRead (chrome-extension://abc/canvas-hook.js:1:1)\n    at HTMLCanvasElement.toDataURL (https://cdn.fp.example/lib/fp.js:10:20)\n    at https://site.example/app.js:5:6`;
  assert.equal(scriptHostFromStack(stack), "cdn.fp.example");
  assert.equal(scriptHostFromStack("Error\n   at <anonymous>"), null);
});
