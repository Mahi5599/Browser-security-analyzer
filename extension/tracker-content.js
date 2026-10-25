// Isolated-world content script (all frames, document_start):
//  1. relays canvas-fingerprinting events from canvas-hook.js (MAIN world)
//  2. reports tiny (<= 2x2 px) <img> elements, i.e. tracking pixels
// Third-party cookies are NOT collected here: a content script only sees the
// page's own cookies. background.js counts third-party Set-Cookie headers instead.

document.addEventListener("__bsa_canvas", (e) => {
  let d;
  try { d = JSON.parse(e.detail); } catch { return; }
  if (!d || typeof d !== "object") return;
  chrome.runtime.sendMessage({
    type: "CANVAS_EVENT",
    event: {
      api: String(d.api).slice(0, 20),
      width: Number(d.width) || 0,
      height: Number(d.height) || 0,
      text_drawn: !!d.text_drawn,
      suspicious: !!d.suspicious,
      scriptHost: typeof d.scriptHost === "string" ? d.scriptHost.slice(0, 253) : null,
    },
  }).catch(() => {});
});

const reported = new Set();
let timer = null;

function isTiny(img) {
  const w = img.naturalWidth || Number(img.getAttribute("width")) || img.width;
  const h = img.naturalHeight || Number(img.getAttribute("height")) || img.height;
  return w > 0 && h > 0 && w <= 2 && h <= 2;
}

function scan() {
  timer = null;
  const urls = [];
  for (const img of document.images) {
    const src = img.currentSrc || img.src;
    if (!/^https?:\/\//.test(src) || reported.has(src)) continue;
    if (img.complete && isTiny(img)) { reported.add(src); urls.push(src); }
  }
  if (urls.length) chrome.runtime.sendMessage({ type: "TINY_IMAGES", urls: urls.slice(0, 100) }).catch(() => {});
}

function schedule() {
  if (timer === null) timer = setTimeout(scan, 1500);
}

document.addEventListener("load", (e) => { if (e.target instanceof HTMLImageElement) schedule(); }, true);
new MutationObserver(schedule).observe(document, { childList: true, subtree: true });
window.addEventListener("load", schedule);
