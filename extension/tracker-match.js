// Runtime tracker matcher over the bundled EasyList/EasyPrivacy snapshot
// (data/tracker-lists.json, built by scripts/build_tracker_lists.mjs).
// Pure functions, no chrome.* -- unit-tested in Node.

// Common two-level public suffixes. We do not bundle the full Public Suffix
// List, so registrable-domain detection is a heuristic (see README).
const SECOND_LEVEL = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "co.jp", "or.jp", "ne.jp", "ac.jp", "co.kr", "or.kr", "co.in", "net.in", "org.in",
  "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my",
  "com.mx", "com.ar", "com.tr", "com.ua", "com.ru", "co.za", "co.il", "co.id", "co.th", "com.vn",
  "com.pl", "com.es", "com.pt", "com.gr", "com.eg", "com.sa", "com.ng", "co.ke",
]);

export function hostOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname.toLowerCase().replace(/\.$/, "") : null;
  } catch {
    return null;
  }
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function registrableDomain(host) {
  if (!host) return "";
  if (IPV4.test(host) || host.includes(":")) return host; // IPs are their own "site"
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join(".");
  return SECOND_LEVEL.has(last2) ? labels.slice(-3).join(".") : last2;
}

export function isThirdParty(pageHost, requestHost) {
  if (!pageHost || !requestHost) return false;
  return registrableDomain(pageHost) !== registrableDomain(requestHost);
}

const LIST_LABEL = { easylist: "advertising", easyprivacy: "tracking" };

export function createMatcher(data) {
  const lists = [];
  for (const name of ["easyprivacy", "easylist"]) { // privacy list wins when both match
    const l = data[name];
    if (!l) continue;
    lists.push({
      name,
      domains: new Set(l.domains),
      paths: new Map(l.paths.map(([h, ps]) => [h, ps])),
    });
  }
  const exceptions = new Set(Object.values(data).flatMap((l) => l?.exceptions ?? []));

  // all dotted suffixes of host: a.b.c.com -> a.b.c.com, b.c.com, c.com
  function suffixes(host) {
    const labels = host.split(".");
    const out = [];
    for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
    return out;
  }

  return {
    meta: data.meta ?? null,
    // -> null | { list, label, rule: "domain"|"path", domain }
    match(url) {
      let u;
      try { u = new URL(url); } catch { return null; }
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      const host = u.hostname.toLowerCase().replace(/\.$/, "");
      const sfx = IPV4.test(host) ? [host] : suffixes(host);
      if (sfx.some((s) => exceptions.has(s))) return null;
      const pathAndQuery = u.pathname + u.search;
      for (const l of lists) {
        for (const s of sfx) {
          if (l.domains.has(s)) return { list: l.name, label: LIST_LABEL[l.name], rule: "domain", domain: s };
        }
      }
      for (const l of lists) {
        for (const s of sfx) {
          const ps = l.paths.get(s);
          if (ps && ps.some((p) => pathAndQuery.startsWith(p))) {
            return { list: l.name, label: LIST_LABEL[l.name], rule: "path", domain: s };
          }
        }
      }
      return null;
    },
  };
}
