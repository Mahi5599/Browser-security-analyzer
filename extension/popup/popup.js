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

loadTabAndAnalysis();
