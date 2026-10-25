// Canvas-fingerprinting detector. Injected into the PAGE's own JS world
// (manifest "world": "MAIN") at document_start so it sees the page's calls.
// Observe-only: every wrapped method still does exactly what it did before.
//
// Heuristic: a canvas that had text drawn on it (fillText/strokeText) and is
// then read back (toDataURL / toBlob / getImageData) while small (<= 250k px)
// is the classic fingerprinting recipe -> "suspicious". Reads of canvases with
// no text drawn (image editors, charts exported as PNG) are counted but not flagged.
// Events go to tracker-content.js (isolated world) as a JSON CustomEvent.
(function (root) {
  "use strict";
  const MAX_AREA = 250000;
  const MAX_EVENTS = 50;

  function scriptHostFromStack(stack) {
    for (const line of String(stack || "").split("\n")) {
      const m = /(https?:\/\/[^\s)]+?):\d+(?::\d+)?\)?\s*$/.exec(line.trim());
      if (m) {
        try { return new URL(m[1]).hostname; } catch (e) { /* keep looking */ }
      }
    }
    return null;
  }

  function install(win, report) {
    const Canvas = win.HTMLCanvasElement && win.HTMLCanvasElement.prototype;
    const Ctx = win.CanvasRenderingContext2D && win.CanvasRenderingContext2D.prototype;
    if (!Canvas || !Ctx) return false;

    const textDrawn = new WeakSet();
    const seen = new Set();
    let sent = 0;

    function wrap(proto, name, onCall) {
      const orig = proto[name];
      if (typeof orig !== "function") return;
      proto[name] = function () {
        try { onCall(this); } catch (e) { /* never break the page */ }
        return orig.apply(this, arguments);
      };
    }

    function onRead(api, canvas) {
      if (!canvas || sent >= MAX_EVENTS) return;
      const width = canvas.width | 0;
      const height = canvas.height | 0;
      const text = textDrawn.has(canvas);
      const scriptHost = scriptHostFromStack(new Error().stack);
      const key = api + "|" + scriptHost + "|" + text;
      if (seen.has(key)) return;
      seen.add(key);
      sent++;
      report({
        api, width, height, text_drawn: text, scriptHost,
        suspicious: text && width * height > 0 && width * height <= MAX_AREA,
      });
    }

    wrap(Ctx, "fillText", (ctx) => textDrawn.add(ctx.canvas));
    wrap(Ctx, "strokeText", (ctx) => textDrawn.add(ctx.canvas));
    wrap(Canvas, "toDataURL", (c) => onRead("toDataURL", c));
    wrap(Canvas, "toBlob", (c) => onRead("toBlob", c));
    wrap(Ctx, "getImageData", (ctx) => onRead("getImageData", ctx.canvas));
    return true;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { install, scriptHostFromStack };
  } else {
    install(root, (ev) => {
      try { root.document.dispatchEvent(new root.CustomEvent("__bsa_canvas", { detail: JSON.stringify(ev) })); } catch (e) { /* ignore */ }
    });
  }
})(typeof window !== "undefined" ? window : globalThis);
