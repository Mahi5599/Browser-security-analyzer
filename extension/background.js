// MV3 service worker: scores each navigated tab against the backend and
// reflects the verdict as a badge. State lives in memory only (Phase 5 will
// persist flagged events to the forensic log instead).
import { API_BASE_URL } from "./config.js";

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
