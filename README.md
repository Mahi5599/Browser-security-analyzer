# Browser Security Analyzer

A browser extension + backend that detects **phishing sites**, scans **downloads**
for malicious files, and exposes **third-party tracking** — with a **hash-chained
forensic evidence log** for every flagged event.

> Cyber-forensics course project. Built in phases; see **Project status** below.

---

## Project status

| Phase | Scope | Status |
|------|-------|--------|
| **1** | Backend + phishing ML model + `/analyze-url` | ✅ **built** |
| **2** | Extension skeleton (MV3, service worker, popup) | ✅ **built** |
| **3** | Malicious download detection (`/analyze-file`, VirusTotal, extension download hook) | ✅ **built** — VirusTotal live calls untested (needs an API key) |
| **4** | Tracking detection (EasyList/EasyPrivacy snapshots, webRequest observer, canvas-fingerprint hook, `/tracker-report`) | ✅ **built** — exercised in real Chrome against a hermetic local test site, not against real websites |
| **5** | Forensic evidence log (HMAC'd hash chain, `/forensic-log`, `/forensic-log/verify`) | ✅ **built** |
| **6** | Dashboard (React + Vite), evidence export, CORS lock-down, demo script, docs | ✅ **built** — see [What was tested](#what-was-tested-and-what-was-not) for exactly what ran |
| + | **Case report** — PDF case report from the forensic log (`GET /forensic-log/report`) + dashboard button | ✅ **built** — see [Case report](#case-report-pdf) and [What was tested](#what-was-tested-and-what-was-not) |

Documentation map: [Architecture](#architecture) · [Quick start](#quick-start) ·
[Dashboard](#dashboard-phase-6) · [Download scanning](#download-scanning-phase-3) ·
[Tracking detection](#tracking-detection-phase-4) · [Chain of custody](#chain-of-custody-phase-5) ·
[Detects / misses](#what-it-detects--and-what-it-misses) · [Threat model](#threat-model) ·
[Model metrics](#model) · [Data and list versions](#data-and-list-versions) ·
[Demo script](docs/demo_script.md)

---

## Architecture

```
 ┌──────────────────────── browser (Chrome, MV3 extension) ────────────────────────┐
 │  content scripts                          service worker (background.js)         │
 │   • page_signals (login form, …)  ─────►   • tab URL scan ──► badge / popup       │
 │   • tiny-image scan, canvas events ────►   • downloads.onChanged: re-fetch ≤50 MB,│
 │   • canvas-hook.js (page JS world)         │    SHA-256 (crypto.subtle)           │
 │                                            • webRequest (observe-only):           │
 │                                            │    3rd-party / tracker / pixel /     │
 │                                            │    beacon / Set-Cookie per tab       │
 │                                            └ bundled EasyList + EasyPrivacy       │
 └──────────────┬──────────────────────────────────────────────────────────────────┘
                │ only URLs, hashes + metadata, tracker counts (never file contents)
                ▼
 ┌────────────────────────── backend (FastAPI + SQLite) ──────────────────────────────┐
 │  POST /analyze-url    features → RandomForest → rules → Tranco prior → verdict     │
 │  POST /analyze-file   VirusTotal hash lookup (cached, 4/min) + heuristics          │
 │                       + source-URL phishing score → verdict                        │
 │  POST/GET /tracker-report   per-page-load snapshots, per-site aggregation          │
 │                │ suspicious / phishing / malicious / high-tracking only            │
 │                ▼                                                                   │
 │  forensic_log   id, timestamp, event_type, case_id, details,                       │
 │                 prev_hash, entry_hash = SHA256(prev + canonical_json(…)),          │
 │                 hmac = HMAC-SHA256(FORENSIC_HMAC_KEY, entry_hash)  + signed head  │
 │  GET /forensic-log        paginated, filter by type / time                         │
 │  GET /forensic-log/verify recompute the chain → valid | first broken entry         │
 └──────────────┬─────────────────────────────────────────────────────────────────────┘
                │ CORS: dashboard origin + the extension's pinned ID only
                ▼
 ┌──────────────────── dashboard (React + Vite, localhost:5173) ──────────────────────┐
 │  risk timeline · flagged sites · flagged downloads · top trackers · log table      │
 │  [Verify log integrity] → green / red     [Export evidence] → JSON + SHA-256       │
 └────────────────────────────────────────────────────────────────────────────────────┘
```

Benign URL and file verdicts are **not** logged: the log is evidence of
something wrong, not a browsing history. The dashboard's timeline therefore only
shows flagged events.

### URL scoring pipeline

```
            POST /analyze-url { url, live_lookups, page_signals }
                                │
                                ▼
        ┌───────────────────────────────────────────────┐
        │  FastAPI  (backend/app)                        │
        │                                               │
        │  phishing_features.py   35 URL-lexical +       │
        │                         typosquat features    │
        │           │                                   │
        │           ▼                                   │
        │  phishing_model.pkl     RandomForest → P(phish)│
        │           │                                   │
        │           ▼                                   │
        │  phishing_predictor.py  + typosquat / keyword  │
        │                         rules                  │
        │                         + Tranco top-10k       │
        │                           reputation prior     │
        │                         + WHOIS age / SSL      │
        │                           (live, best-effort)  │
        │                         + DOM page_signals     │
        └───────────────────────────────────────────────┘
                                │
                                ▼
        { risk_score, verdict, reasons[], model_score, enrichment }
```

**Why a model *and* rules?** The ML model gives a calibrated base score from the
URL string alone. Typosquatting, raw-IP hosts, `@`-tricks and homographs are
strong human-verifiable signals that a lexical model under-weights, so they are
applied as explicit, explainable rules on top. A global top-10k reputation prior
(the way browser allow-lists work) suppresses false positives on well-known
domains — unless an active impersonation signal is present.

---

## Quick start

Requires Python 3.11+ and Node 18+ (the dashboard needs Node 18+; the extension tests use Node's built-in test runner).

```bash
# --- backend ---
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend
cp .env.example .env            # then set FORENSIC_HMAC_KEY (required) and optionally VIRUSTOTAL_API_KEY
python -c "import secrets; print(secrets.token_hex(32))"     # a good FORENSIC_HMAC_KEY

python -m ml.train_model        # downloads PhiUSIIL (~57 MB) once; falls back to a synthetic set if offline
python -m ml.evaluate           # -> ml/metrics_report.md
uvicorn app.main:app --reload --port 8000

# --- dashboard (second terminal) ---
cd dashboard && npm install && npm run dev          # http://localhost:5173

# --- extension ---
# chrome://extensions -> Developer mode -> Load unpacked -> extension/   (ID: gknjaknibkcfffkjjceppndfodajfjil)
```

Try it without the browser:

```bash
curl -s localhost:8000/analyze-url -H 'content-type: application/json' \
  -d '{"url":"http://paypaI-secure-login.tk/verify/account","live_lookups":false}' | python -m json.tool
python backend/scripts/demo_seed.py     # fills the dashboard with demo data (tracker report is SYNTHETIC)
python backend/scripts/tamper_demo.py   # viva demo: tamper with the log, watch /verify catch it
```

Tests:

```bash
cd backend && pytest -q                  # backend + runs the extension's Node tests + the dashboard's Vitest suite
cd extension && node --test tests        # extension logic only
cd dashboard && npm test                 # dashboard only
node scripts/e2e_extension.mjs           # real Chrome + extension + backend (backend must be running; see script header)
```

The **3-minute demo** is in [`docs/demo_script.md`](docs/demo_script.md).

---

## API

### `POST /analyze-url`

Request:

```json
{
  "url": "https://paypaI-secure-login.com",
  "live_lookups": true,
  "page_signals": {
    "has_login_form": true,
    "password_field_insecure": false,
    "form_action_cross_domain": true
  }
}
```

- `live_lookups` (default `true`) — run WHOIS + SSL enrichment. Network-dependent
  and best-effort; disable for fast/offline scoring.
- `page_signals` (optional) — DOM facts from the content script (Phase 2).

Response:

```json
{
  "url": "https://paypaI-secure-login.com",
  "risk_score": 0.93,
  "verdict": "phishing",
  "reasons": [
    "Looks like a typosquat of paypal.com (edit distance 1)",
    "Domain was registered only 3 day(s) ago",
    "SSL certificate is missing or failed validation"
  ],
  "model_score": 0.71,
  "enrichment": { "domain_age_days": 3, "ssl": {"valid": false}, "reputation_trusted": false }
}
```

`verdict`: `benign` (< 0.35) · `suspicious` (0.35–0.65) · `phishing` (≥ 0.65).

### `POST /analyze-file`

Request: `{ filename, sha256?, size_bytes?, source_url?, mime_type?, case_id? }`
(`sha256` omitted = metadata-only scan). Response: `{ filename, sha256,
risk_score, verdict, reasons[], virustotal{status,…}, analysis_mode, source_url_verdict,
forensic_log_id }`. `virustotal.status`: `malicious | suspicious | clean | unknown |
unavailable | rate_limited | error | not_checked`. Details in **Download scanning**.

### `GET /model-info`

Model type, training timestamp, dataset provenance, CV metrics.

### `GET /health`

Liveness probe.

---

## Extension (Phase 2)

MV3 skeleton: a service worker scores every tab you navigate to against the
backend, a content script reports DOM signals (login form, insecure password
field, cross-domain form action), and a popup shows the verdict.

```
extension/
  manifest.json          MV3 manifest
  config.js              API_BASE_URL (defaults to http://127.0.0.1:8000)
  background.js          service worker: calls /analyze-url, sets the badge
  content-script.js      collects page_signals from the DOM
  popup/                 popup.html / popup.js / popup.css
  icons/                 icon16.png, icon48.png, icon128.png
```

**Load it (Chrome/Edge):**

1. Start the backend (`uvicorn app.main:app --reload --port 8000`, see above).
2. Go to `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** → select the `extension/` folder.
4. Browse to any `http://`/`https://` page — the toolbar badge colors as
   green (benign), amber (suspicious), or red (phishing); click the icon for
   the full verdict, risk score and reasons.

The badge appears twice per page: once immediately from a URL-only scan, then
again a moment later once the content script's DOM signals arrive and refine
the verdict. `live_lookups` is left off (WHOIS/SSL enrichment is slow and
network-dependent) — the extension trades that for instant scoring.

---

## Dashboard (Phase 6)

`dashboard/` — React 18 + Vite + Recharts, reading the backend API (`VITE_API_BASE`,
default `http://127.0.0.1:8000`). No data is stored in the browser.

| Panel | Source |
|---|---|
| Summary cards (flagged sites / downloads, high-tracking page loads, log size) | `GET /forensic-log` |
| **Chain of custody**: *Verify log integrity* → green **INTEGRITY VERIFIED** or red **TAMPERING DETECTED** naming the first broken entry (that row is also highlighted in the log table) | `GET /forensic-log/verify` |
| **Export evidence** → downloads every log entry as one JSON file (with an `export_meta` header: time, entry count, head hash, integrity result at export) and shows the file's **SHA-256**; a *Download .sha256 file* button gives a `shasum -a 256 -c` sidecar | `GET /forensic-log` + `/verify` |
| **Generate case report** (next to Export evidence): *Case ID* (suggests IDs present in the log) + *Examiner* → downloads the PDF and shows its report-data SHA-256 | `GET /forensic-log/report` |
| Risk timeline (score vs time, URLs = circles, files = squares, threshold lines) | log entries |
| Flagged sites / flagged downloads | log entries (`phishing_url`, `malicious_file`) |
| Top trackers (bar chart) + fingerprinting summary | `GET /tracker-report` |
| Forensic log table (filter by type, paginate, expand details, hashes) | `GET /forensic-log` |

Behaviour worth knowing:

- The result of *Verify* is shown with an icon and text as well as colour. If the
  verify call itself fails (e.g. the HMAC key is missing → 503) the panel shows an
  amber **Could not verify** — never a false green.
- The dashboard displays what is in the database. After tampering, the tables show the
  *edited* value; only the verification result tells you not to trust it.
- The export's SHA-256 is computed in the browser over the exact bytes that are
  downloaded (checked against `shasum -a 256` of the real downloaded file). It proves the
  file wasn't changed *after* export; it is not a signature (no key is involved), and the
  `integrity_check_at_export` field is the server's answer at that moment.
- The dashboard loads at most 10,000 log entries (500 per request) and says so if truncated.
- **CORS:** the backend only allows `http://localhost:5173`, `http://127.0.0.1:5173` and
  `chrome-extension://gknjaknibkcfffkjjceppndfodajfjil` (the extension ID is pinned by the
  `key` field in `extension/manifest.json`). Override with `BSA_DASHBOARD_ORIGINS` /
  `BSA_EXTENSION_IDS`. CORS only restricts *browsers*: it is not authentication, and
  `curl` or any local process can still call the API (see Threat model).
- Production build: `npm run build` (static files in `dashboard/dist`); a deployed
  dashboard's origin must be added to `BSA_DASHBOARD_ORIGINS`.

---

## Dataset

**Primary:** [UCI PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)
(id 967) — 235,795 URLs (134,850 legitimate / 100,945 phishing). Downloaded once
to `backend/ml/dataset/phiusiil_raw.csv`, then cached. We use only the raw `URL`
string and the label; **all features are re-engineered by our own code** so the
same extractor runs at training and request time.

> PhiUSIIL labels `1 = legitimate`, `0 = phishing`. This project uses the
> opposite convention everywhere: **`1 = phishing`**.

**Fallback:** `backend/ml/dataset/build_sample_dataset.py` generates a synthetic
labelled set (benign top domains vs. the same brands under classic attack
patterns) when PhiUSIIL can't be downloaded (offline / CI). Metrics on the
fallback are optimistic — cite PhiUSIIL.

**Known dataset bias & our correction.** PhiUSIIL's benign URLs are ~100% HTTPS
*homepage* URLs of curated high-reputation sites, while its phishing URLs are
~50% HTTP and often carry deep paths. Trained raw, a model just learns
"HTTP or has-a-path → phishing" and scores `stackoverflow.com/questions/...` as
phishing. `ml/data_loader.py::_augment_benign` re-attaches realistic paths,
subdomains and schemes to the benign class before training. This is why our
held-out numbers (~0.96) are lower — and more trustworthy — than the ~0.999 you
get on raw PhiUSIIL. See `ml/metrics_report.md` for the full discussion.

**Reputation snapshot:** `backend/app/services/data/tranco_top10k.txt.gz` — the
[Tranco](https://tranco-list.eu/) top-10k domains, downloaded **2026-09-10**.
Bundled as a static snapshot, never fetched live. Refresh with
`python scripts/refresh_tranco.py`.

---

## Model

- **Algorithm:** Random Forest (`scikit-learn`), chosen for interpretability
  (feature importances explain every decision in a viva) and speed.
- **Features (35):** URL length / token counts / character ratios / entropy;
  `@` symbol; raw-IP host; HTTPS; port; punycode & non-ASCII host; TLD length &
  abused-TLD flag; URL-shortener flag; subdomain depth & length; credential
  keyword count; `//` in path; **edit distance to the nearest of ~55 curated
  brand domains** and typosquat / brand-in-subdomain flags.
- **Not model inputs** (applied as runtime rules instead, because they aren't
  available for every training row): WHOIS domain age, live SSL validity,
  DOM/page signals, reputation prior.

### Latest metrics (held-out test, threshold 0.50)

Model `RandomForestClassifier` (200 trees, max depth 24), trained **2026-10-25** on a
balanced 200,000-URL sample of PhiUSIIL plus the benign-path augmentation
(160,000 train / 40,000 test, random state 42).

| Metric | Value |
|---|---|
| Precision | 0.9626 |
| Recall | 0.9558 |
| F1 | 0.9592 |
| ROC-AUC | 0.9897 |
| PR-AUC | 0.9899 |

Confusion matrix (test, 40,000 URLs): 19,257 benign correct · **743 benign flagged**
(3.7 % of benign) · **884 phishing missed** (4.4 % of phishing) · 19,116 phishing caught.
Raising the threshold to 0.819 gives precision 0.98 at recall 0.869.

**How much to trust these numbers.** They come from the same distribution as the
training data (PhiUSIIL, with our augmentation), so real-world performance will be
lower. On a separate hand-labelled set of **30** modern URLs the *raw model alone* scored
**80.0 % accuracy / 77.3 % precision / 94.4 % recall**; the full pipeline (model + rules +
reputation prior) got 30/30 — but 30 hand-picked URLs is a smoke test, not a benchmark.
Full report (feature importances, sample mistakes):
[`backend/ml/metrics_report.md`](backend/ml/metrics_report.md), regenerated by
`python -m ml.train_model && python -m ml.evaluate`.

---

## What it detects — and what it misses

| Area | Detects | Misses |
|---|---|---|
| **Phishing URLs** | Lexical tells (raw-IP hosts, `@` tricks, punycode, abused TLDs, credential keywords, long/deep URLs); typosquats / brand-in-subdomain against ~55 curated brands; insecure password fields and cross-domain form actions (DOM signals); new domains and bad certificates when `live_lookups` is on | Phishing on a clean-looking fresh domain with no lexical tell; brands not in the curated list; anything behind a redirect chain (we score the URL we are given, not where it leads); pages that change after load; cloaked pages. The model sees only the URL string — never page content |
| **Downloads** | EICAR (local signature); files VirusTotal knows as malicious; double extensions, risky types, RTL-override names, MIME/extension mismatches; downloads from sources the URL model rates badly | Any new/unknown malware whose name and source look normal (VirusTotal says `unknown`; we never upload). **Download cloaking**: the hash is of a *re-download* made without cookies, so a server can hand the scanner a different file than the user got. Logged-in downloads, `blob:` URLs and files > 50 MB are metadata-only. No static or dynamic analysis of file contents |
| **Tracking** | Third-party requests to hosts in the bundled EasyList/EasyPrivacy snapshots; tracking pixels and beacons (by URL shape, tiny response, tiny rendered image, `ping` requests); text-then-read canvas fingerprinting; third-party `Set-Cookie` volume | Trackers only covered by list rules we skip (wildcards, regex, URL substrings); first-party / CNAME-cloaked tracking; fingerprinting via WebGL, audio, fonts or `OffscreenCanvas`; `fetch(keepalive)` beacons; anything newer than the list snapshot |
| **Evidence log** | Edited, deleted, reordered and tail-truncated entries; forged entries without the HMAC key | A key holder rewriting history; rollback to an older consistent copy unless the head hash was recorded elsewhere; entries that were never logged (benign verdicts are deliberately not recorded) |

### False-positive notes

- **Typosquat rules** fire on legitimately similar names (a real `paypa1.com` fan site,
  a small shop whose name is one edit from a big brand). Reasons are shown so a human can judge.
- **HTTP-only** government/university sites with deep paths looked phishing-like to the
  model (PhiUSIIL had no such benign examples). The Tranco top-10k prior and the
  augmentation reduce this; smaller HTTP-only sites can still be flagged.
- **URL shorteners** are reported as `suspicious` because the destination is hidden, even
  though the shortener itself is reputable.
- **Raw-IP hosts** (LAN servers, `127.0.0.1`, dev boxes) are scored as phishing-like — both
  as pages and as download sources — because that is what the URL model learned.
- **Risky-extension rules** mean installers (`.exe`, `.msi`) from unknown hashes score
  `suspicious`; a known-clean hash on VirusTotal (≥ 10 engines) caps the score at 0.30.
- **Tracker lists** are ad-blocker lists: `advertising` domains (EasyList) are reported as
  "trackers" too, and a listed host is flagged for every request type to it.
- **Canvas fingerprinting** is a heuristic: drawing text and reading it back also happens in
  legitimate captcha / text-measurement code.
- **Tracking pixels** by URL shape will flag some harmless third-party images (`/track/`, `/collect`).
- Browsers lowercase hostnames, so a homoglyph like `paypaI` (capital *I*) reaches the
  extension as `paypai`; it is still one edit from `paypal`, but real IDN homographs are
  handled only through punycode detection.

---

## Download scanning (Phase 3)

```
chrome.downloads.onChanged (state → complete)
   └─ service worker re-fetches the download URL (≤ 50 MB, no cookies)
        └─ SHA-256 via crypto.subtle
             └─ POST /analyze-file { filename, sha256, size_bytes, source_url, mime_type }
                    ├─ VirusTotal v3 hash lookup (cached, 4 req/min)
                    ├─ filename / MIME heuristics
                    └─ source_url scored by the phishing model
                         → { risk_score, verdict: benign|suspicious|malicious, reasons[], virustotal{} }
                           suspicious/malicious → forensic log (event_type "malicious_file")
```

**Privacy:** only the hash, the file's *base name* (not its local path) and
metadata leave the browser, and only to your own backend. File contents are
never sent to the backend, and the backend **never uploads a file to
VirusTotal** — a hash VirusTotal has not seen is reported as `unknown`.
The VirusTotal key (`VIRUSTOTAL_API_KEY` in `backend/.env`) is server-side only;
without it `/analyze-file` still works from heuristics and VirusTotal shows
`unavailable`.

**Scoring.** Signals are combined noisy-OR (several weak signals add up; the
result never exceeds 1). Thresholds: `benign` < 0.35 ≤ `suspicious` < 0.65 ≤ `malicious`.

| Signal | Weight |
|---|---|
| Double extension (`invoice.pdf.exe`) | 0.60 |
| Right-to-left-override filename trick | 0.55 |
| Risky extension (`.exe .scr .js .vbs .bat .msi .apk .jar .iso` + `.com .cmd .ps1 .hta .lnk .vbe .wsf .pif .dll`) | 0.15–0.40 |
| Server MIME says "program" but the name says otherwise | 0.45 |
| MIME / extension mismatch | 0.20 |
| Source URL rated phishing / suspicious by the model | 0.50 / 0.30 |
| VirusTotal ≥ 3 detections / 1–2 detections / suspicious only | 0.95 / 0.55 / 0.40 |
| Unknown to VirusTotal *and* a risky name | +0.10 |
| Known-clean on VirusTotal (≥ 10 engines) | score capped at 0.30 |
| Hash equals the EICAR test file | 0.95 (local signature) |

Reasons are returned strongest first. VirusTotal results are cached in SQLite
(24 h for known hashes, 1 h for unknown ones). The free-tier limit of 4 requests
per minute is enforced with a sliding window: a request waits up to 15 s for a
slot, otherwise VirusTotal shows `rate_limited` and the verdict uses heuristics
only; a 429 from VirusTotal triggers a one-minute back-off.

### Extension limitations (honest version)

- **The hash is of a *re-download*, not of the file on disk.** Chrome doesn't
  give extensions the saved file's bytes, so the service worker fetches the URL
  again. If the server returns different bytes the second time (one-time or
  expiring links, per-request watermarking, POST-initiated downloads, content
  that depends on headers) the hash won't match what the user saved.
- **Cookie/auth-protected downloads fall back to metadata-only.** The re-fetch
  deliberately sends **no cookies** (`credentials: "omit"`) — we don't replay
  the user's session at a server a second time. Logged-in downloads (intranets,
  Drive/SharePoint-style links, anything answering 401/403/redirect-to-login)
  therefore can't be hashed and are judged by filename/MIME/source-URL only.
  The popup marks these "Metadata-only". The same applies to `blob:`/`data:`/`file:` URLs.
- **50 MB cap.** Larger files (detected from `Content-Length`, or by cutting the
  stream off at the cap) are not hashed → metadata-only.
- `crypto.subtle` has no incremental digest, so the body is streamed only to
  enforce the cap and held in memory (≤ 50 MB) for one hash call.
- The re-download is a second request to the origin: it doubles the traffic and
  the origin sees it (without cookies, but with the user's IP).
- Metadata-only mode cannot see inside the file: a malicious file with an
  innocent name from a clean-looking source is not caught by it.
- A raw-IP source (e.g. a LAN or `127.0.0.1` server) scores as suspicious/
  phishing because that is what the URL model does with IP hosts.
- Only `malicious` verdicts raise a desktop notification; all results appear
  in the popup ("Recent downloads", last 20 kept in `chrome.storage.local`).
- **Testing uses only the EICAR test string** (68 harmless bytes, built in memory
  by the tests; never written to disk, never real malware).

---

## Tracking detection (Phase 4)

```
webRequest.onBeforeRequest (observe-only, never blocks)
   └─ per-tab TabSession: third-party? tracker (list match)? pixel? beacon?
webRequest.onResponseStarted ── third-party Set-Cookie headers, tiny Content-Length images
content script (all frames)  ── tiny <img> elements; relays canvas events
canvas-hook.js (page's own JS world) ── toDataURL / toBlob / getImageData
        └─ ~3 s after activity, and on navigation/tab close:
           POST /tracker-report  (one cumulative snapshot per page load)
                └─ stored in SQLite; high-tracking page loads → forensic log
```

**Popup:** "*N* trackers from *M* third-party domains" for the current tab (N =
distinct third-party domains matched by the lists, M = all distinct third-party
domains), plus request / pixel / beacon counts, top networks and any
fingerprinting or cookie flag.

### Bundled list versions

The lists are static snapshots committed under `data/blocklists/` and are **never
fetched at runtime**. `data/blocklists/manifest.json` records each snapshot's
source, download date, list version, SHA-256 and compile statistics; a test fails
if a snapshot is edited without rebuilding.

| List | Version | Last modified (upstream) | Downloaded | Source | SHA-256 | Rules compiled |
|---|---|---|---|---|---|---|
| easylist | `202610251011` | 25 Oct 2026 10:11 UTC | 2026-10-25 | https://easylist.to/easylist/easylist.txt | `afc22520a09013dc…` | 55,303 |
| easyprivacy | `202610251018` | 25 Oct 2026 10:18 UTC | 2026-10-25 | https://easylist.to/easylist/easyprivacy.txt | `df12d1813400347c…` | 51,417 |

Both lists are by the EasyList authors, dual-licensed GPLv3+ / CC BY-SA 3.0.
Reports sent to the backend carry `list_versions`, and forensic entries
record them, so a verdict can be tied to the exact list that produced it.

Refresh (the only code path that touches the network):

```bash
node scripts/build_tracker_lists.mjs --refresh   # download snapshots + recompile + update manifest
node scripts/build_tracker_lists.mjs             # offline: recompile the snapshots already in the repo
```

### What the matcher understands (and what it does not)

EasyList/EasyPrivacy are ad-blocker filter lists written for a full blocking
engine. We compile only the rules we can apply correctly from a URL:
`||domain^` (domain and all subdomains), `||host/literal/path` prefixes and
unconditional `@@||domain^` exceptions. **Skipped** (counts per reason are in the
manifest): cosmetic/element-hiding filters, regex filters, plain URL-substring
filters (about 900 + 2,300 rules), rules with wildcards in the host or path,
`$domain=`-restricted rules, `$popup`/`$document`-only rules, and path/restricted
exceptions. Resource-type options (e.g. `$script`) are not enforced, so a
type-restricted rule matches every request type to that host. So:

- **Misses:** trackers that only the skipped rule kinds cover are classed
  "unknown third party". E.g. the EasyPrivacy rule for
  `connect.facebook.net/*/fbevents.js` is a wildcard rule (and the list even has
  an exception for it), so it is not matched; `facebook.com/tr/` is.
- **Over-matching:** a listed host is "a tracker" for every request type,
  and the lists include advertising domains (label `advertising`, from EasyList)
  as well as tracking domains (label `tracking`, from EasyPrivacy).
- A tracker served from the site's own domain (first-party analytics, CNAME
  cloaking) is invisible: we only classify third-party requests.

### Detection details and honest limits

- **Third-party** = registrable domain differs from the top page's. There is no
  Public Suffix List bundled; `registrableDomain()` uses "last two labels, or three
  for ~50 common suffixes such as `co.uk`". Sites on private suffixes
  (`*.github.io`, `*.blogspot.com`) look first-party to each other.
- **Beacons:** request type `ping` (`navigator.sendBeacon`, `<a ping>`). Beacons
  sent via `fetch(keepalive)`/XHR are not recognised.
- **Pixels (no request-size API exists in `onBeforeRequest`):** an image is a pixel if
  the URL looks like one (`pixel`, `beacon`, `1x1`, `collect`, `track`…), the
  response `Content-Length` is ≤ 128 bytes, or a rendered `<img>` was ≤ 2×2 px.
  Images created with `new Image()` and never attached are caught only by the
  first two rules. Heuristics produce both false positives (a URL with `/track/`)
  and false negatives (chunked responses with no Content-Length).
- **Canvas fingerprinting** is a heuristic, not proof: text drawn onto a canvas
  (`fillText`/`strokeText`) and then read back (`toDataURL`/`toBlob`/`getImageData`)
  while the canvas is ≤ 250,000 px. Reads of canvases with no text are counted
  but not flagged. Legitimate uses (e.g. a captcha, a text-rendering test) can
  trip it; a fingerprinter that draws only shapes, or reads via `OffscreenCanvas`
  or WebGL, will not. The hook runs in the page's JS world (`"world": "MAIN"`,
  Chrome 111+) so a hostile page could also forge or suppress the events — it can
  only affect its own report.
- **Third-party cookies — deliberate deviation from the plan:** a content script
  cannot see cookies of other sites, so they are counted in the service worker
  from third-party `Set-Cookie` *response headers*. That counts cookies a server
  *tried* to set; Chrome may reject them under its third-party-cookie
  restrictions. "Excessive" = 10 or more per page load.
- **Service-worker lifetime:** MV3 workers get killed. Sessions are mirrored to
  `chrome.storage.session` (debounced 1 s) and restored on wake-up; events in
  the last second before a kill can be lost, so counts may be slightly low.
- **Privacy:** reports contain the site *hostname*, tracker domains and counts —
  not full page URLs, query strings or request URLs.
- **Not blocking:** this is observe-and-report. Nothing is blocked.

### `POST /tracker-report` / `GET /tracker-report`

`POST` takes one snapshot per page load (cumulative; re-posting the same
`session_id` replaces it) and returns `{stored, flags, forensic_log_ids}`.
`GET /tracker-report[?site=&since=&top=]` aggregates: `totals`, per-`sites`
(sessions, average/max tracker domains, pixels, beacons, cookies, fingerprinting
sessions), `top_networks` (a "network" is the registrable domain, e.g.
`doubleclick.net`; there is no company-ownership mapping), and
`fingerprinting` (sessions, sites, top scripts).

A page load is written to the forensic log (`event_type: tracker_session`) when it
first reaches **≥ 10 tracker domains**, **canvas fingerprinting**, or **≥ 10
third-party cookies** — one entry per newly crossed threshold, so a session that
later escalates is logged again but a long-lived page isn't logged repeatedly.
If the forensic log is unavailable the stats are still stored and a later update
retries the entry.

---

## Chain of custody (Phase 5)

Every `suspicious` / `phishing` verdict from `/analyze-url` is written
automatically to an append-only SQLite table `forensic_log`
(`id, timestamp_utc, event_type, case_id, details_json, prev_hash, entry_hash, hmac`).
`event_type` is `phishing_url | malicious_file | tracker_session`. A phishing
entry's `details` hold the URL, verdict, risk score, model score, reasons, model
version (type, training time, SHA-256 of the model file), Tranco snapshot date,
and the DOM signals.

```
entry_hash = SHA256( prev_hash + canonical_json({timestamp, event_type, case_id, details}) )
hmac       = HMAC-SHA256( FORENSIC_HMAC_KEY, entry_hash )
```

- `canonical_json` = sorted keys, `(",", ":")` separators, ASCII-escaped, so
  the hash is deterministic. The first entry chains to a fixed genesis hash
  (64 zeros). Timestamps use one fixed-width UTC format.
- **Hash chain:** edit, delete or reorder any row and `prev_hash`/`entry_hash`
  stop matching from that row on.
- **HMAC:** an attacker with only the DB file can recompute the SHA-256 chain,
  but not the HMACs, so `verify` still fails. The key lives in `backend/.env`
  (`FORENSIC_HMAC_KEY`, see `.env.example`; `.env` is gitignored). The log
  refuses to write without it.
- **Signed head:** a `chain_head` row (entry count + last hash, HMAC'd) is
  updated in the same transaction as each append, so deleting the *last* rows
  is detected too (a plain hash chain cannot see tail truncation).
- Appends use `BEGIN IMMEDIATE`, so concurrent writers cannot fork the chain.

| Endpoint | Purpose |
|---|---|
| `POST /forensic-log` `{event_type, case_id, details}` | append an entry |
| `GET /forensic-log?event_type=&since=&until=&limit=&offset=` | paginated, filterable (ISO-8601 times) |
| `GET /forensic-log/verify[?expected_head=<hash>]` | recompute the whole chain → `{valid, entries_checked, first_broken_id, reason, head_hash}` |
| `GET /forensic-log/report?case_id=&examiner=[&format=pdf\|json]` | read-only PDF case report (see [Case report](#case-report-pdf)) |

`/analyze-url` accepts an optional `case_id` (default `"default"`) and returns
`forensic_log_id` (null for benign verdicts, or if logging failed — a logging
failure is reported in the server log but never blocks the verdict).

**Viva demo:** `cd backend && python scripts/tamper_demo.py` appends entries to
a throwaway DB, edits one row directly in SQLite, shows `/verify` naming the
first broken entry, then repeats the attack with a recomputed hash to show the
HMAC still catches it.

### Case report (PDF)

`GET /forensic-log/report?case_id=<id>&examiner=<name>&format=pdf` returns a PDF (`format=json` returns the
data it is built from). Both parameters are required. The endpoint is **strictly read-only**: it never appends
to the log, and a test compares the SQLite file byte-for-byte before and after.

| Section | Contents |
|---|---|
| Header | title, case ID, examiner, generation time (UTC), tool version, model type / training time / file hash, EasyList + EasyPrivacy versions, Tranco snapshot date |
| Integrity banner | **green INTEGRITY VERIFIED**, **red INTEGRITY FAILURE** (also repeated in the footer of every page), or **grey LOG IS EMPTY**. A failed verification can never render green |
| 1. Executive summary | entries in the case, counts by event type and by verdict, fingerprinting sessions |
| 2. Chain of custody | the `/forensic-log/verify` result: valid / invalid, entries checked (entries intact before the break if invalid), first broken entry, reason, head hash |
| 3. Evidence | id, UTC timestamp, type, verdict, key details, shortened `entry_hash` — the first broken entry is shaded. At most 1,000 rows are printed (a notice says so; the data hash covers all entries) |
| 4. Limitations | symmetric HMAC (a key holder can forge), rollback, benign events not logged, verdicts can be wrong, host clock, the hash covers the data not the PDF, no digital signature |
| Footer | `Report data SHA-256: …` on every page |

**What the footer hash is, exactly.** It is the SHA-256 of the report's underlying data: the bytes returned by
`format=json` (`json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True)`, UTF-8). The generation time is
deliberately *not* in that data, so on an unchanged log the same `case_id` + `examiner` always give the same hash. Cross-check:

```bash
curl -s 'http://127.0.0.1:8000/forensic-log/report?case_id=DEMO-001&examiner=Dr.%20A.%20Examiner&format=json' | shasum -a 256
```

It also arrives in the `X-Report-Data-SHA256` response header. **It is not the same number as the dashboard's
*Export evidence* hash** — that file covers the whole log plus an export timestamp, this data covers one case plus
integrity and version metadata, so the hashes differ by design. What *can* be cross-checked is the content: each entry in the
report data is field-for-field identical to the entry returned by `/forensic-log` and written by Export evidence
(tested), including `entry_hash`, `hmac` and the chain `head_hash`. The hash proves the data wasn't changed after the report
was made; it is not a signature.

Behaviour worth knowing:

- Integrity covers **the whole log** (the hash chain is not per case), so tampering with *another* case's entry
  still fails every case report, with a note that the scope is the entire log.
- If `FORENSIC_HMAC_KEY` is missing the endpoint returns **503** instead of a report: without the key the
  chain cannot be verified, and a report with no verification result would mislead. A wrong key shows as INTEGRITY FAILURE.
- Entries and the verification result come from **one read transaction**, so a concurrent append cannot make them disagree.
- A tampered row that is no longer valid JSON still renders (shown as unparseable) — a damaged log gets a failure report, not a 500.
- **Log text is untrusted.** reportlab's `Paragraph` interprets XML-like markup (`<img src=…>` can make it fetch a URL or
  read a file), so every log-derived string is escaped, and non-ASCII characters are printed as visible `\uXXXX`
  escapes (also what an examiner wants for look-alike domains and RTL-override tricks).
- The PDF uses the built-in Helvetica/Courier fonts, hence the ASCII escaping rather than glyph rendering.
- Dependency: `reportlab` (pure Python) pulls in **Pillow**, which ships compiled wheels. Tests use `pypdf` to read the PDFs.

### Limits — what this does *not* protect against

- **Key holder can forge.** Anyone with `FORENSIC_HMAC_KEY` (e.g. a local
  operator or anyone who can read `.env`) can rewrite history and re-sign the
  whole chain. This is tamper-*evidence* against people without the key, not
  protection against the operator.
- **Whole-log rollback.** Restoring an older, internally-consistent copy of the
  DB (including its old signed head) verifies as valid. Defence: record the
  `head_hash` from `/verify` somewhere outside this machine (email, printout,
  notary) and check it later with `?expected_head=`.
- **Wrong key looks like tampering.** Rotating the key invalidates old entries.
- **No endpoint authentication.** `POST /forensic-log` is open to anything that
  can reach the API (CORS is `*` in dev), so a hostile page or local process
  could *add* junk entries. They are validly chained, so this is a
  log-pollution risk, not an integrity break of existing entries.
- **Evidence is only as good as the input.** The log proves a record was not
  altered after writing, not that the verdict was correct.
- SQLite triggers could block `UPDATE`/`DELETE` but anyone with file access can
  drop them, so none are used; detection, not prevention, is the design.

---

## Threat model

**What we protect:** the user from phishing pages, malicious downloads and invasive tracking
(detect and report — nothing is blocked), and the *integrity of the evidence* recorded about them.

| Actor / scenario | In scope? | What happens |
|---|---|---|
| Remote attacker hosting a phishing page or malware | ✅ detect | URL / hash / metadata scoring; see "detects / misses" for evasions |
| Third-party trackers on a page | ✅ detect | observed and reported, not blocked |
| Someone who can edit the SQLite file but **does not have the HMAC key** | ✅ detect | edits, deletions, reordering and tail truncation all fail `/forensic-log/verify` |
| **Operator holding `FORENSIC_HMAC_KEY`** (or anyone who can read `backend/.env`) | ❌ | can rewrite and re-sign the whole chain. Keep the key off the machine that stores the DB if that matters |
| Whole-DB rollback to an older consistent copy | ⚠️ partial | invisible to `/verify` alone; detectable if the head hash was recorded elsewhere (`?expected_head=`) |
| A malicious **web page** calling the backend | ✅ mitigated | CORS allow-list (dashboard + pinned extension ID) blocks it from reading responses, and JSON `POST`s need a preflight that is refused |
| A malicious **local process** / any non-browser client | ❌ | the API has no authentication: it can read the log and append junk (validly chained) entries |
| A hostile page faking canvas / tiny-image events | ⚠️ self-only | it can only distort the report about *itself* |
| Network attacker / MITM / TLS interception | ❌ out of scope | the extension talks to a local backend over plain HTTP on loopback |
| Malware sandboxing, dynamic analysis, zero-days, compromised browser or OS | ❌ out of scope | |

**Privacy by design.** File contents never leave the browser (only the SHA-256, the file's
base name and metadata go to *your own* backend), and the backend never uploads a file to
VirusTotal. Tracker reports store the site's *hostname*, not full page URLs. The VirusTotal
key is server-side only; no keys ship in the extension. `/analyze-url` does see the full URL
of every page you visit (it is sent to the local backend) — that is inherent to URL scoring,
and benign verdicts are not logged.

**Testing only ever uses the EICAR test string (68 harmless bytes) — never real malware.**
Blocklists are bundled snapshots, never fetched at runtime.

---

## Data and list versions

| Data | Version / date | Where | Notes |
|---|---|---|---|
| Phishing training set | UCI PhiUSIIL (id 967), 235,795 URLs; **200,000 used** (balanced 100k/100k) | `backend/ml/dataset/` (gitignored, downloaded on first train) | benign class augmented with paths/subdomains/schemes — see Dataset |
| Phishing model | RandomForest, **trained 2026-10-25** | `backend/app/models/phishing_model.pkl` (gitignored; the file's SHA-256 is recorded in every phishing forensic entry) | metrics above |
| Reputation prior | Tranco **top-10k, downloaded 2026-09-10** | `backend/app/services/data/tranco_top10k.txt.gz` | static snapshot |
| EasyList | version **202610251011** (25 Oct 2026 10:11 UTC), downloaded 2026-10-25 | `data/blocklists/easylist.txt` | 55,303 rules compiled |
| EasyPrivacy | version **202610251018** (25 Oct 2026 10:18 UTC), downloaded 2026-10-25 | `data/blocklists/easyprivacy.txt` | 51,417 rules compiled |
| VirusTotal | API v3, live hash lookups (not a snapshot) | server-side | needs `VIRUSTOTAL_API_KEY`; free tier 4 req/min; results cached 24 h (unknown: 1 h) |
| Extension ID | `gknjaknibkcfffkjjceppndfodajfjil` | `extension/manifest.json` `key` | pinned so CORS can be exact |

`data/blocklists/manifest.json` has the source URL, SHA-256 and per-reason skip counts for each list;
a test fails if a snapshot is edited without rebuilding.

---

## What was tested (and what was not)

**Automated, run and passing at the time of writing**

| Suite | Count | Covers |
|---|---|---|
| `pytest` (backend) | 115 | URL features/API, forensic chain (valid / modified / deleted / reordered / truncated / forged-without-key), `/analyze-file` heuristics + mocked VirusTotal (cache, 4/min limiter, 429 back-off, never uploads), `/tracker-report` aggregation and forensic logging, CORS allow/deny, manifest-key ↔ CORS-ID match, case report (populated / empty / tampered ×6 kinds / wrong key / missing key / read-only byte-compare / markup + non-ASCII escaping / hash cross-check / truncation / pagination); it also runs the two JS suites below |
| `node --test extension/tests` | 36 | download hashing/size cap/fallbacks/payload privacy, list parser + matcher against fixtures **and the real bundled lists**, snapshot manifest hashes, tab-session logic, canvas hook (fake canvas classes) |
| `npm test` in `dashboard/` | 28 | derived views, evidence-export hash, verify green/red/error rendering, export flow, API paging, and the case-report form (disabled until filled, trimmed inputs, download + hash display, error path); component tests use a mocked API and charts are stubbed |

**Run by hand against the real thing**

- `node scripts/e2e_extension.mjs` — **19 checks passed** in real Google Chrome 155 (macOS, headless) with the
  unpacked extension and the real backend: extension loads with the pinned ID; a phishing-looking tab gets the
  `!!` badge and a forensic entry; a downloaded EICAR file is re-fetched, hashed (`275a021b…fd0f`) and logged as
  malicious; a tracker-heavy page yields 12 tracker domains, canvas-fingerprinting (script host recorded), pixels,
  beacons, 13 third-party cookies and the matching forensic entries; the chain verifies afterwards. The "internet" was a
  local server (all hostnames mapped to 127.0.0.1) — **no real third-party site was contacted**.
- Dashboard built and rendered in headless Chrome against a live backend: data loads cross-origin under the
  tightened CORS; *Verify* showed green on a clean DB and red ("first broken entry #2") after editing a row
  with `sqlite3`; the exported file's displayed SHA-256 equals `shasum -a 256` of the file Chrome saved.
- Every command in `docs/demo_script.md` that has a curl/CLI fallback was run (steps 2, 3, 4, 5).
- **Case report in real Chrome:** the dashboard's *Generate case report* button was driven in headless Chrome against a live backend, on a clean and on a tampered log. The downloaded PDF has the expected banner; the hash displayed in the UI = the PDF footer text = `shasum -a 256` of `format=json`. The PDFs were also rendered to images and inspected (macOS `sips`).

**Not tested**

- **PDF rendering outside macOS**: the reports were viewed through macOS's renderer and text-extracted with `pypdf`, not in Acrobat, Chrome's PDF viewer, or on Windows/Linux. Reports of very large logs (beyond a few thousand entries) were not timed.
- The extension's **popup UI and desktop notifications** were never seen on a real screen (headless run;
  the popup's data path is covered, its rendering is not). Likewise the demo script's live-browser steps
  (1, 3-live, 4-live) were not performed on real websites.
- **Real-world accuracy**: no real phishing sites, real malware or real tracker-heavy sites were used; false-positive
  and false-negative rates on live traffic are unknown.
- **VirusTotal** live responses (no API key was available): parsing follows the documented v3 shape and is tested
  against mocks only.
- Other browsers (Firefox, Safari), Chrome versions other than 155, Windows/Linux, a deployed (non-localhost)
  setup, logs beyond a few hundred entries, concurrent multi-process writers, and key rotation.
- Security review: this is a course project; it has not been penetration-tested.

---

## Repo layout

```
backend/
  app/
    main.py                       FastAPI app, CORS allow-list
    routers/                      url_analysis, file_analysis, tracker_report, forensic
    services/
      phishing_features.py        feature engineering (train + serve)
      phishing_predictor.py       model + rules + reputation -> verdict
      whois_ssl.py, reputation.py, brands.py, data/tranco_top10k.txt.gz
      virustotal_client.py        VT v3 hash lookup, SQLite cache, 4/min limiter
      file_heuristics.py, file_analyzer.py   filename/MIME rules + verdict
      tracker_store.py            tracker sessions, aggregation, forensic hook
      forensic_log.py             hash chain + HMAC + signed head + verify
      case_report.py              PDF / JSON case report (read-only)
    version.py                    tool name + version printed on reports
    db/database.py                SQLite location
    models/phishing_model.pkl     trained bundle (gitignored)
  ml/                             data_loader, train_model, evaluate, metrics_report.md, ood_checkset.csv
  scripts/
    refresh_tranco.py             regenerate the reputation snapshot
    tamper_demo.py                viva demo: tamper with the log, watch /verify catch it
    demo_seed.py                  fill a running backend with demo data (tracker report is synthetic)
  tests/                          pytest (also runs the extension + dashboard suites)
extension/
  manifest.json                   MV3 manifest (pinned ID via "key")
  background.js                   service worker: URL scan, download hook, tracker observer
  download-scan.js                re-fetch, size cap, SHA-256, payload
  tracker-match.js / tracker-session.js   list matcher, per-tab classification
  tracker-content.js / canvas-hook.js     tiny-image scan; canvas detector (page JS world)
  content-script.js               DOM page_signals
  popup/, icons/, config.js
  data/tracker-lists.json         compiled lists (generated)
  tests/                          node --test
dashboard/                        React + Vite UI (src/, tests/)
data/blocklists/                  easylist.txt, easyprivacy.txt, manifest.json (static snapshots)
scripts/
  build_tracker_lists.mjs         compile (or --refresh) the list snapshots
  lib/parse-filters.mjs           ABP filter parser (subset)
  e2e_extension.mjs               real-Chrome end-to-end test
docs/demo_script.md               3-minute demo
```
