// Per-tab tracking session: classifies observed requests and aggregates the
// numbers shown in the popup and reported to /tracker-report. Pure logic (no
// chrome.*), so it is unit-tested in Node. Observe-only: nothing is blocked.
import { hostOf, isThirdParty, registrableDomain } from "./tracker-match.js";

export const EXCESSIVE_COOKIES = 10; // third-party Set-Cookie headers per page load
const PIXEL_URL = /(^|[\/_.-])(pixel|beacon|1x1|clear\.gif|spacer\.gif|blank\.gif|track(ing)?|collect|impression)([\/_.?&=-]|$)/i;
const PIXEL_MAX_BYTES = 128; // a 1x1 GIF is 35-43 bytes

export class TabSession {
  constructor(pageUrl, matcher, sessionId = crypto.randomUUID()) {
    this.sessionId = sessionId;
    this.pageUrl = pageUrl;
    this.pageHost = hostOf(pageUrl) ?? "";
    this.matcher = matcher;
    this.totalRequests = 0;
    this.thirdPartyRequests = 0;
    this.thirdParty = new Map(); // host -> { requests, tracker: match|null, pixels, beacons }
    this.pixelUrls = new Set();
    this.beaconCount = 0;
    this.cookieSets = 0;
    this.canvasEvents = 0;
    this.canvasFlagged = false;
    this.canvasScripts = new Set();
    this.tinyImageUrls = new Set();
    this.startedAt = Date.now();
  }

  _entry(host, url) {
    let e = this.thirdParty.get(host);
    if (!e) {
      e = { requests: 0, tracker: this.matcher.match(url), pixels: 0, beacons: 0 };
      this.thirdParty.set(host, e);
    } else if (!e.tracker) {
      e.tracker = this.matcher.match(url); // a later URL may hit a path rule
    }
    return e;
  }

  // details: { url, type, method? }  -> classification
  recordRequest({ url, type }) {
    this.totalRequests++;
    const host = hostOf(url);
    if (!host || !isThirdParty(this.pageHost, host)) return { thirdParty: false };

    this.thirdPartyRequests++;
    const e = this._entry(host, url);
    e.requests++;
    const kind = e.tracker ? "tracker" : "unknown_third_party";
    let pixel = false;
    let beacon = false;

    if (type === "ping") {
      beacon = true; // <a ping>, navigator.sendBeacon
      e.beacons++;
      this.beaconCount++;
    } else if (type === "image" && (PIXEL_URL.test(new URL(url).pathname) || this.tinyImageUrls.has(url))) {
      pixel = true;
      this._markPixel(url, host);
    }
    return { thirdParty: true, kind, pixel, beacon, list: e.tracker?.list ?? null };
  }

  _markPixel(url, host) {
    if (this.pixelUrls.has(url)) return;
    this.pixelUrls.add(url);
    const e = this.thirdParty.get(host);
    if (e) e.pixels++;
  }

  // onCompleted with a content-length: a tiny third-party image is a pixel.
  recordCompleted({ url, type, contentLength }) {
    const host = hostOf(url);
    if (type !== "image" || !host || !isThirdParty(this.pageHost, host)) return;
    if (Number.isFinite(contentLength) && contentLength > 0 && contentLength <= PIXEL_MAX_BYTES) {
      this._entry(host, url);
      this._markPixel(url, host);
    }
  }

  // content script saw rendered <img> elements of <= 2x2 px
  recordTinyImages(urls) {
    for (const url of urls ?? []) {
      this.tinyImageUrls.add(url);
      const host = hostOf(url);
      if (host && isThirdParty(this.pageHost, host)) {
        this._entry(host, url);
        this._markPixel(url, host);
      }
    }
  }

  recordSetCookie(url) {
    const host = hostOf(url);
    if (host && isThirdParty(this.pageHost, host)) this.cookieSets++;
  }

  recordCanvas(ev) {
    this.canvasEvents++;
    if (ev?.suspicious) {
      this.canvasFlagged = true;
      if (ev.scriptHost) this.canvasScripts.add(ev.scriptHost);
    }
  }

  snapshot() {
    const trackers = new Map(); // network (registrable domain) -> aggregate
    const trackerDomains = [];
    let trackerRequests = 0;
    let unknown = 0;
    for (const [host, e] of this.thirdParty) {
      if (e.tracker) {
        trackerDomains.push({ domain: host, network: registrableDomain(host), requests: e.requests,
                              list: e.tracker.list, pixels: e.pixels, beacons: e.beacons });
        trackerRequests += e.requests;
        const net = trackers.get(registrableDomain(host)) ?? { network: registrableDomain(host), requests: 0, domains: 0 };
        net.requests += e.requests;
        net.domains++;
        trackers.set(net.network, net);
      } else {
        unknown++;
      }
    }
    trackerDomains.sort((a, b) => b.requests - a.requests);
    return {
      session_id: this.sessionId,
      site: this.pageHost,
      total_requests: this.totalRequests,
      third_party_requests: this.thirdPartyRequests,
      third_party_domains: this.thirdParty.size,
      tracker_domains: trackerDomains.length,
      tracker_requests: trackerRequests,
      unknown_third_party_domains: unknown,
      trackers: trackerDomains.slice(0, 100),
      top_networks: [...trackers.values()].sort((a, b) => b.requests - a.requests).slice(0, 10),
      pixels: this.pixelUrls.size,
      beacons: this.beaconCount,
      third_party_cookies: this.cookieSets,
      excessive_third_party_cookies: this.cookieSets >= EXCESSIVE_COOKIES,
      canvas_fingerprinting: this.canvasFlagged,
      canvas_events: this.canvasEvents,
      canvas_scripts: [...this.canvasScripts].slice(0, 20),
      list_versions: Object.fromEntries((this.matcher.meta?.lists ?? []).map((l) => [l.name, l.list_version])),
    };
  }

  // chrome.storage.session persistence: the MV3 service worker can be killed mid-page.
  toJSON() {
    return {
      sessionId: this.sessionId, pageUrl: this.pageUrl, totalRequests: this.totalRequests,
      thirdPartyRequests: this.thirdPartyRequests,
      thirdParty: [...this.thirdParty].map(([h, e]) => [h, { requests: e.requests, pixels: e.pixels, beacons: e.beacons, tracker: e.tracker }]),
      pixelUrls: [...this.pixelUrls].slice(0, 500), beaconCount: this.beaconCount,
      cookieSets: this.cookieSets, canvasEvents: this.canvasEvents, canvasFlagged: this.canvasFlagged,
      canvasScripts: [...this.canvasScripts], tinyImageUrls: [...this.tinyImageUrls].slice(0, 500),
      startedAt: this.startedAt,
    };
  }

  static fromJSON(j, matcher) {
    const s = new TabSession(j.pageUrl, matcher, j.sessionId);
    s.totalRequests = j.totalRequests;
    s.thirdPartyRequests = j.thirdPartyRequests;
    for (const [h, e] of j.thirdParty) {
      s.thirdParty.set(h, { ...e });
    }
    s.pixelUrls = new Set(j.pixelUrls);
    s.beaconCount = j.beaconCount;
    s.cookieSets = j.cookieSets;
    s.canvasEvents = j.canvasEvents;
    s.canvasFlagged = j.canvasFlagged;
    s.canvasScripts = new Set(j.canvasScripts);
    s.tinyImageUrls = new Set(j.tinyImageUrls);
    s.startedAt = j.startedAt;
    return s;
  }
}
