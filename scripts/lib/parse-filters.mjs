// Adblock-Plus filter list -> the small subset of rules we can match reliably
// from a browser extension that only sees URLs.
//
// Compiled:
//   ||host^[$opts]           domain rule (host and all its subdomains)
//   ||host/literal/path[$o]  host + literal path-prefix rule
//   @@||host^                unconditional domain exception
// Skipped (counted, reported in the manifest): cosmetic/element-hiding filters,
// regex filters, plain URL-substring filters, rules with wildcards in the
// host or path, rules restricted with domain=, and rules that only affect
// pop-ups / top-level documents. Resource-type options are NOT enforced, so a
// "$script"-only rule matches every request type (slightly over-inclusive).

// Options that don't change what a subresource request to the host means.
const HARMLESS = new Set([
  "third-party", "3p", "script", "image", "xmlhttprequest", "xhr", "ping", "subdocument", "frame",
  "stylesheet", "css", "media", "object", "font", "other", "websocket", "important", "match-case",
]);

const HOST_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

export function emptyCompiled() {
  return { domains: new Set(), paths: new Map(), exceptions: new Set() };
}

function classifyOptions(optStr) {
  if (!optStr) return { ok: true, thirdPartyOnly: false };
  let thirdPartyOnly = false;
  for (const raw of optStr.split(",")) {
    const o = raw.trim().toLowerCase();
    if (!o) continue;
    if (o.startsWith("domain=")) return { ok: false, why: "domain-option" };
    if (o === "~third-party" || o === "~3p") return { ok: false, why: "first-party-only" };
    if (o === "third-party" || o === "3p") { thirdPartyOnly = true; continue; }
    const name = o.replace(/^~/, "");
    if (o === "popup" || o === "document" || o === "doc") return { ok: false, why: "popup-or-document" };
    if (!HARMLESS.has(name)) return { ok: false, why: "unsupported-option" };
  }
  return { ok: true, thirdPartyOnly };
}

export function parseFilterList(text) {
  const out = emptyCompiled();
  const skipped = {};
  const skip = (why) => { skipped[why] = (skipped[why] ?? 0) + 1; };
  let compiled = 0;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("!") || line.startsWith("[")) continue;
    if (/#[@?$%]?#/.test(line)) { skip("cosmetic"); continue; }

    let exception = false;
    let rule = line;
    if (rule.startsWith("@@")) { exception = true; rule = rule.slice(2); }

    if (!rule.startsWith("||")) {
      skip(rule.startsWith("/") && rule.lastIndexOf("/") > 0 ? "regex" : "url-substring");
      continue;
    }
    const dollar = rule.indexOf("$");
    const body = dollar === -1 ? rule.slice(2) : rule.slice(2, dollar);
    const opts = classifyOptions(dollar === -1 ? "" : rule.slice(dollar + 1));
    if (!opts.ok) { skip(opts.why); continue; }

    const m = /^([^/^?*|]+)(.*)$/.exec(body);
    if (!m) { skip("malformed"); continue; }
    const host = m[1].toLowerCase();
    let rest = m[2];
    if (!HOST_RE.test(host) || !host.includes(".")) { skip("host-wildcard-or-single-label"); continue; }

    if (rest === "" || rest === "^" || rest === "^|" || rest === "|") {
      if (exception) {
        // only a bare, unrestricted exception is safe to honour
        if (dollar !== -1) { skip("restricted-exception"); continue; }
        out.exceptions.add(host);
      } else {
        out.domains.add(host);
      }
      compiled++;
      continue;
    }

    // host + path
    if (exception) { skip("path-exception"); continue; }
    if (rest.includes("*")) { skip("wildcard-path"); continue; }
    rest = rest.replace(/[|^]+$/, "");
    if (rest.includes("^") || rest.includes("|")) { skip("separator-in-path"); continue; }
    if (!rest.startsWith("/") && !rest.startsWith("?")) { skip("odd-path"); continue; }
    if (rest === "/" || rest === "") { out.domains.add(host); compiled++; continue; }
    if (!out.paths.has(host)) out.paths.set(host, new Set());
    out.paths.get(host).add(rest);
    compiled++;
  }
  return { compiled: out, stats: { compiled, skipped } };
}

// Header comments: ! Version: 202610251011   ! Last modified: 25 Oct 2026 10:11 UTC
export function parseHeader(text) {
  const get = (k) => new RegExp(`^! ${k}:\\s*(.+)$`, "mi").exec(text)?.[1]?.trim() ?? null;
  return { title: get("Title"), version: get("Version"), last_modified: get("Last modified") };
}

export function serializeCompiled(c) {
  return {
    domains: [...c.domains].sort(),
    paths: [...c.paths].sort(([a], [b]) => (a < b ? -1 : 1)).map(([h, set]) => [h, [...set].sort()]),
    exceptions: [...c.exceptions].sort(),
  };
}
