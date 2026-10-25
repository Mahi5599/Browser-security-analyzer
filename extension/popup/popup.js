import { API_BASE_URL } from "../config.js";

const contentEl = document.getElementById("content");
const hostEl = document.getElementById("host");
const rescanBtn = document.getElementById("rescan");

const VERDICT_LABEL = { benign: "Benign", suspicious: "Suspicious", phishing: "Phishing" };

let currentTab = null;

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function render(state) {
  if (!state || state.status === "idle" || state.status === "loading") {
    contentEl.innerHTML = `<p class="status">Scanning&hellip;</p>`;
    return;
  }

  if (state.status === "error") {
    contentEl.innerHTML = `
      <p class="status error">Couldn't reach the backend.</p>
      <p class="hint">Is it running at ${escapeHtml(API_BASE_URL)}?</p>
      <p class="hint">${escapeHtml(state.error ?? "")}</p>
    `;
    return;
  }

  const { verdict, risk_score, reasons, model_score, enrichment } = state.data;
  const pct = Math.round(risk_score * 100);
  const reasonsHtml = (reasons ?? []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");

  contentEl.innerHTML = `
    <div class="verdict verdict-${verdict}">
      <span class="verdict-label">${VERDICT_LABEL[verdict] ?? verdict}</span>
      <span class="verdict-score">${pct}% risk</span>
    </div>
    ${reasonsHtml ? `<ul class="reasons">${reasonsHtml}</ul>` : ""}
    <dl class="meta">
      <dt>Model score</dt><dd>${model_score ?? "–"}</dd>
      <dt>Reputation trusted</dt><dd>${enrichment?.reputation_trusted ? "yes" : "no"}</dd>
    </dl>
  `;
}

function loadTabAndAnalysis() {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) return;
    currentTab = tab;

    let host = "";
    try {
      host = new URL(tab.url).hostname;
    } catch {
      /* non-http(s) URL */
    }
    hostEl.textContent = host;

    if (!/^https?:\/\//.test(tab.url ?? "")) {
      contentEl.innerHTML = `<p class="status">Nothing to scan on this page.</p>`;
      rescanBtn.disabled = true;
      return;
    }

    rescanBtn.disabled = false;
    chrome.runtime.sendMessage({ type: "GET_ANALYSIS", tabId: tab.id }, render);
  });
}

rescanBtn.addEventListener("click", () => {
  if (!currentTab) return;
  render({ status: "loading" });
  chrome.runtime.sendMessage({ type: "RESCAN", tabId: currentTab.id, url: currentTab.url }, render);
});

const trackersEl = document.getElementById("trackers");

function renderTrackers(t) {
  if (!t || (t.third_party_requests === 0 && !t.canvas_fingerprinting)) {
    trackersEl.innerHTML = t ? `<h2>Tracking</h2><p class="hint">No third-party requests seen yet.</p>` : "";
    return;
  }
  const flags = [];
  if (t.canvas_fingerprinting) {
    flags.push(`<li class="flag">Canvas fingerprinting attempt${t.canvas_scripts?.length ? " from " + escapeHtml(t.canvas_scripts.join(", ")) : ""}</li>`);
  }
  if (t.excessive_third_party_cookies) {
    flags.push(`<li class="flag">${t.third_party_cookies} third-party cookies set</li>`);
  }
  const nets = (t.top_networks ?? []).slice(0, 3)
    .map((n) => `${escapeHtml(n.network)} (${n.requests})`).join(", ");
  trackersEl.innerHTML = `
    <h2>Tracking</h2>
    <p class="tracker-summary"><strong>${t.tracker_domains} trackers</strong> from
      <strong>${t.third_party_domains} third-party domains</strong></p>
    <p class="hint">${t.third_party_requests} third-party requests &middot; ${t.pixels} tracking pixels &middot; ${t.beacons} beacons</p>
    ${nets ? `<p class="hint">Top networks: ${nets}</p>` : ""}
    ${flags.length ? `<ul class="flags">${flags.join("")}</ul>` : ""}`;
}

function loadTrackers() {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab || !/^https?:\/\//.test(tab.url ?? "")) return;
    chrome.runtime.sendMessage({ type: "GET_TRACKERS", tabId: tab.id }, renderTrackers);
  });
}
loadTrackers();

const downloadsEl = document.getElementById("downloads");
const FILE_LABEL = { benign: "Benign", suspicious: "Suspicious", malicious: "Malicious" };

function renderDownloads(list) {
  if (!list?.length) {
    downloadsEl.innerHTML = "";
    return;
  }
  const rows = list.slice(0, 5).map((d) => {
    if (d.status === "scanning") {
      return `<li><span class="dl-name">${escapeHtml(d.filename)}</span><span class="dl-badge dl-pending">scanning&hellip;</span></li>`;
    }
    if (d.status === "error") {
      return `<li><span class="dl-name">${escapeHtml(d.filename)}</span><span class="dl-badge dl-pending">scan failed</span>
        <div class="hint">${escapeHtml(d.error ?? "")}</div></li>`;
    }
    const v = d.data.verdict;
    const note = d.hashed
      ? ""
      : `<div class="hint">Metadata-only: ${escapeHtml(d.fallbackReason ?? "file could not be re-downloaded")}</div>`;
    const reason = d.data.reasons?.[0] ? `<div class="hint">${escapeHtml(d.data.reasons[0])}</div>` : "";
    return `<li><span class="dl-name">${escapeHtml(d.filename)}</span>
      <span class="dl-badge dl-${v}">${FILE_LABEL[v] ?? v} ${Math.round(d.data.risk_score * 100)}%</span>${reason}${note}</li>`;
  });
  downloadsEl.innerHTML = `<h2>Recent downloads</h2><ul class="downloads">${rows.join("")}</ul>`;
}

chrome.storage.local.get("downloadResults", ({ downloadResults }) => renderDownloads(downloadResults));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.downloadResults) renderDownloads(changes.downloadResults.newValue);
});

loadTabAndAnalysis();
