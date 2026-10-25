// MV3 service worker: scores each navigated tab against the backend and
// reflects the verdict as a badge. State lives in memory only (Phase 5 will
// persist flagged events to the forensic log instead).
import { API_BASE_URL } from "./config.js";
import { scanDownload } from "./download-scan.js";
import { createMatcher } from "./tracker-match.js";
import { TabSession } from "./tracker-session.js";

const analysisByTab = new Map(); // tabId -> { status, url, data?, error? }
const pageSignalsByTab = new Map(); // tabId -> PageSignals
const scanTimers = new Map(); // tabId -> setTimeout handle

const BADGE_COLOR = {
  benign: "#16a34a",
  suspicious: "#f59e0b",
  phishing: "#dc2626",
  loading: "#9ca3af",
  error: "#6b7280",
};

const BADGE_TEXT = {
  benign: "",
  suspicious: "!",
  phishing: "!!",
};

function isScannable(url) {
  return typeof url === "string" && /^https?:\/\//.test(url);
}

function setBadge(tabId, kind, text) {
  chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE_COLOR[kind] ?? BADGE_COLOR.loading });
  chrome.action.setBadgeText({ tabId, text: text ?? "" });
}

async function analyzeTab(tabId, url, pageSignals) {
  if (!isScannable(url)) return;

  analysisByTab.set(tabId, { status: "loading", url });
  setBadge(tabId, "loading", "…");

  try {
    const res = await fetch(`${API_BASE_URL}/analyze-url`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        url,
        live_lookups: false,
        ...(pageSignals ? { page_signals: pageSignals } : {}),
      }),
    });

    if (!res.ok) throw new Error(`backend returned ${res.status}`);

    const data = await res.json();
    analysisByTab.set(tabId, { status: "done", url, data });
    setBadge(tabId, data.verdict, BADGE_TEXT[data.verdict] ?? "");
  } catch (err) {
    analysisByTab.set(tabId, { status: "error", url, error: String(err?.message ?? err) });
    setBadge(tabId, "error", "?");
  }

  return analysisByTab.get(tabId);
}

function scheduleScan(tabId, url, delayMs = 400) {
  clearTimeout(scanTimers.get(tabId));
  scanTimers.set(
    tabId,
    setTimeout(() => {
      scanTimers.delete(tabId);
      analyzeTab(tabId, url, pageSignalsByTab.get(tabId));
    }, delayMs)
  );
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && isScannable(tab.url)) {
    pageSignalsByTab.delete(tabId);
    scheduleScan(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (chrome.runtime.lastError || !tab) return;
    if (!analysisByTab.has(tabId) && isScannable(tab.url)) {
      scheduleScan(tabId, tab.url, 0);
    }
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  analysisByTab.delete(tabId);
  pageSignalsByTab.delete(tabId);
  clearTimeout(scanTimers.get(tabId));
  scanTimers.delete(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PAGE_SIGNALS" && sender.tab) {
    const tabId = sender.tab.id;
    pageSignalsByTab.set(tabId, message.signals);
    const cached = analysisByTab.get(tabId);
    // Content script signals arrive after the initial URL-only scan; re-score
    // once so the popup can show the DOM-aware verdict without a manual rescan.
    if (cached?.status === "done" && cached.url === sender.tab.url) {
      analyzeTab(tabId, sender.tab.url, message.signals);
    }
    return;
  }

  if (message?.type === "GET_ANALYSIS") {
    sendResponse(analysisByTab.get(message.tabId) ?? { status: "idle" });
    return;
  }

  if (message?.type === "RESCAN") {
    const { tabId, url } = message;
    clearTimeout(scanTimers.get(tabId));
    scanTimers.delete(tabId);
    analyzeTab(tabId, url, pageSignalsByTab.get(tabId)).then((result) => sendResponse(result));
    return true; // keep the message channel open for the async response
  }
});

// ---------------------------------------------------------------- downloads
// When a download finishes, re-fetch it (see download-scan.js for the caveats),
// hash it, and send only hash + metadata to /analyze-file. Results are kept in
// chrome.storage.local (last 20) so the popup can show them.
const MAX_DOWNLOAD_RESULTS = 20;

async function saveDownloadResult(entry) {
  const { downloadResults = [] } = await chrome.storage.local.get("downloadResults");
  const rest = downloadResults.filter((r) => r.id !== entry.id);
  await chrome.storage.local.set({
    downloadResults: [entry, ...rest].slice(0, MAX_DOWNLOAD_RESULTS),
  });
}

function notifyMalicious(entry) {
  chrome.notifications.create(`bsa-download-${entry.id}`, {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: "Malicious download detected",
    message: `${entry.filename}\n${entry.data.reasons?.[0] ?? "Flagged by Browser Security Analyzer"}`,
    priority: 2,
  });
}

async function handleCompletedDownload(downloadId) {
  const [item] = await chrome.downloads.search({ id: downloadId });
  if (!item) return;
  const filename = item.filename.split(/[\\/]/).pop();
  const base = { id: downloadId, filename, at: Date.now() };
  await saveDownloadResult({ ...base, status: "scanning" });
  try {
    const { data, hashed, fallbackReason } = await scanDownload(item, { apiBase: API_BASE_URL });
    const entry = { ...base, status: "done", data, hashed, fallbackReason };
    await saveDownloadResult(entry);
    if (data.verdict === "malicious") notifyMalicious(entry);
  } catch (err) {
    await saveDownloadResult({ ...base, status: "error", error: String(err?.message ?? err) });
  }
}

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === "complete") {
    handleCompletedDownload(delta.id).catch((e) => console.error("download scan failed", e));
  }
});

// ----------------------------------------------------------------- tracking
// Observe-only (no "blocking" option anywhere): classify every third-party
// request in a tab against the bundled EasyList/EasyPrivacy snapshot, then
// report the per-page-load totals to /tracker-report.
// The MV3 worker can be killed mid-page, so sessions are mirrored to
// chrome.storage.session and restored before any event is handled.
const trackerSessions = new Map(); // tabId -> TabSession
const persistTimers = { handle: null };
const reportTimers = new Map();
const lastReported = new Map(); // sessionId -> JSON of last snapshot sent
let matcher = null;

const trackingReady = (async () => {
  const res = await fetch(chrome.runtime.getURL("data/tracker-lists.json"));
  matcher = createMatcher(await res.json());
  const { tabSessions = {} } = await chrome.storage.session.get("tabSessions");
  for (const [tabId, json] of Object.entries(tabSessions)) {
    trackerSessions.set(Number(tabId), TabSession.fromJSON(json, matcher));
  }
})().catch((e) => console.error("tracker lists failed to load", e));

function persistSessions() {
  clearTimeout(persistTimers.handle);
  persistTimers.handle = setTimeout(() => {
    const tabSessions = {};
    for (const [tabId, sess] of trackerSessions) tabSessions[tabId] = sess.toJSON();
    chrome.storage.session.set({ tabSessions }).catch(() => {});
  }, 1000);
}

async function sendSessionReport(sess) {
  if (!sess) return;
  const snap = sess.snapshot();
  if (snap.third_party_requests === 0 && !snap.canvas_fingerprinting) return;
  const body = JSON.stringify(snap);
  if (lastReported.get(sess.sessionId) === body) return;
  lastReported.set(sess.sessionId, body);
  try {
    await fetch(`${API_BASE_URL}/tracker-report`, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
  } catch { /* backend offline: popup still works from local state */ }
}

const sendTrackerReport = (tabId) => sendSessionReport(trackerSessions.get(tabId));

function scheduleTrackerReport(tabId) {
  clearTimeout(reportTimers.get(tabId));
  reportTimers.set(tabId, setTimeout(() => { reportTimers.delete(tabId); sendTrackerReport(tabId); }, 3000));
}

async function sessionFor(tabId) {
  let sess = trackerSessions.get(tabId);
  if (!sess) {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (!isScannable(tab.url)) return null;
      sess = new TabSession(tab.url, matcher);
      trackerSessions.set(tabId, sess);
    } catch { return null; }
  }
  return sess;
}

const REQ_FILTER = { urls: ["http://*/*", "https://*/*"] };

chrome.webRequest.onBeforeRequest.addListener((d) => {
  if (d.tabId < 0) return;
  (async () => {
    await trackingReady;
    if (!matcher) return;
    if (d.type === "main_frame") {
      // Swap synchronously so the new page's first sub-requests land in the new
      // session, then flush the page we just left.
      const old = trackerSessions.get(d.tabId);
      trackerSessions.set(d.tabId, new TabSession(d.url, matcher));
      clearTimeout(reportTimers.get(d.tabId));
      if (old) sendSessionReport(old).finally(() => lastReported.delete(old.sessionId));
    } else {
      const sess = await sessionFor(d.tabId);
      if (!sess) return;
      sess.recordRequest({ url: d.url, type: d.type });
      scheduleTrackerReport(d.tabId);
    }
    persistSessions();
  })();
}, REQ_FILTER);

// Response headers: tiny third-party images (content-length) and third-party Set-Cookie.
chrome.webRequest.onResponseStarted.addListener((d) => {
  if (d.tabId < 0 || d.type === "main_frame") return;
  (async () => {
    await trackingReady;
    const sess = trackerSessions.get(d.tabId);
    if (!sess) return;
    for (const h of d.responseHeaders ?? []) {
      const name = h.name.toLowerCase();
      if (name === "set-cookie") sess.recordSetCookie(d.url);
      else if (name === "content-length") sess.recordCompleted({ url: d.url, type: d.type, contentLength: Number(h.value) });
    }
    // Cookie / pixel counts can change after the last request event, so the report
    // must be (re)scheduled here too, otherwise they can miss the debounced POST.
    scheduleTrackerReport(d.tabId);
    persistSessions();
  })();
}, REQ_FILTER, ["responseHeaders", "extraHeaders"]);

chrome.tabs.onRemoved.addListener((tabId) => {
  const sess = trackerSessions.get(tabId);
  sendSessionReport(sess).finally(() => {
    trackerSessions.delete(tabId);
    if (sess) lastReported.delete(sess.sessionId);
    clearTimeout(reportTimers.get(tabId));
    reportTimers.delete(tabId);
    persistSessions();
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "CANVAS_EVENT" && sender.tab) {
    trackingReady.then(async () => {
      const sess = await sessionFor(sender.tab.id);
      if (!sess) return;
      sess.recordCanvas(message.event);
      scheduleTrackerReport(sender.tab.id);
      persistSessions();
    });
    return;
  }
  if (message?.type === "TINY_IMAGES" && sender.tab) {
    trackingReady.then(async () => {
      const sess = await sessionFor(sender.tab.id);
      if (!sess) return;
      sess.recordTinyImages(message.urls);
      scheduleTrackerReport(sender.tab.id);
      persistSessions();
    });
    return;
  }
  if (message?.type === "GET_TRACKERS") {
    trackingReady.then(() => sendResponse(trackerSessions.get(message.tabId)?.snapshot() ?? null));
    return true;
  }
});
