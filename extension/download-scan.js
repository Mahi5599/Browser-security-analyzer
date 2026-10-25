// Download scanning logic with no chrome.* dependency, so it can be unit-tested
// in Node. background.js wires it to chrome.downloads / notifications.

export const MAX_FILE_BYTES = 50 * 1024 * 1024; // 50 MB cap on re-fetch + hash
export const FETCH_TIMEOUT_MS = 60_000;

export function basename(path) {
  return String(path ?? "").split(/[\\/]/).pop();
}

export function isFetchable(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(bytes) {
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

// Re-download `url` and hash it. Never throws: returns
//   { sha256, size }                    on success, or
//   { sha256: null, reason }            when we must fall back to metadata-only.
//
// credentials are deliberately omitted: we don't replay the user's cookies at
// a server a second time. Cookie/auth-protected downloads therefore fail
// (401/403/redirect to login) and take the metadata-only path.
//
// SubtleCrypto has no incremental digest, so the body is streamed only to
// enforce the size cap while it arrives (the request is aborted the moment the
// cap is exceeded); the bytes are held in memory (<= maxBytes) and hashed once.
export async function fetchAndHash(url, { maxBytes = MAX_FILE_BYTES, fetchImpl = fetch,
                                          timeoutMs = FETCH_TIMEOUT_MS } = {}) {
  if (!isFetchable(url)) return { sha256: null, reason: "download URL is not http(s) (blob:/data:/file:)" };

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { credentials: "omit", redirect: "follow", signal: ctrl.signal });
    if (!res.ok) return { sha256: null, reason: `re-fetch failed with HTTP ${res.status} (auth/cookie-protected?)` };

    const declared = Number(res.headers.get("content-length"));
    if (declared > maxBytes) {
      ctrl.abort();
      return { sha256: null, reason: `file larger than ${Math.round(maxBytes / 1048576)} MB cap` };
    }
    if (!res.body) return { sha256: null, reason: "response has no body" };

    const chunks = [];
    let size = 0;
    const reader = res.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        ctrl.abort();
        return { sha256: null, reason: `file larger than ${Math.round(maxBytes / 1048576)} MB cap` };
      }
      chunks.push(value);
    }
    const all = new Uint8Array(size);
    let offset = 0;
    for (const c of chunks) { all.set(c, offset); offset += c.byteLength; }
    return { sha256: await sha256Hex(all), size };
  } catch (err) {
    return { sha256: null, reason: `re-fetch error: ${err?.name === "AbortError" ? "timeout/aborted" : err?.message ?? err}` };
  } finally {
    clearTimeout(timer);
  }
}

// Only the hash and metadata leave the browser -- never file contents, and
// only the file's basename (not the local path).
export function buildPayload(item, hashResult) {
  return {
    filename: basename(item.filename),
    sha256: hashResult.sha256 ?? null,
    size_bytes: hashResult.size ?? (item.fileSize > 0 ? item.fileSize : item.totalBytes > 0 ? item.totalBytes : null),
    source_url: item.finalUrl || item.url || null,
    mime_type: item.mime || null,
  };
}

// Full pipeline for one completed download item.
export async function scanDownload(item, { apiBase, fetchImpl = fetch, maxBytes = MAX_FILE_BYTES } = {}) {
  const hashResult = await fetchAndHash(item.finalUrl || item.url, { maxBytes, fetchImpl });
  const payload = buildPayload(item, hashResult);
  const res = await fetchImpl(`${apiBase}/analyze-file`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`backend returned ${res.status}`);
  const data = await res.json();
  return { data, hashed: hashResult.sha256 !== null, fallbackReason: hashResult.reason ?? null };
}
