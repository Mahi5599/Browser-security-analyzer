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
| 3 | Malicious download detection (`/analyze-file`, VirusTotal) | ⛔ not started |
| 4 | Tracking detection (EasyList/EasyPrivacy, `/tracker-report`) | ⛔ not started |
| 5 | Forensic evidence log (append-only hash chain, `/forensic-log`) | ⛔ not started |
| 6 | Dashboard + demo + polish | ⛔ not started |

Everything below describes **Phase 1**, plus an **Extension (Phase 2)** section.

---

## Architecture (Phase 1)

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

## Quick start (Phase 1)

Requires Python 3.11+.

```bash
cd backend
python3.11 -m venv ../.venv && source ../.venv/bin/activate
pip install -r requirements.txt

# 1. Train the model (downloads the UCI PhiUSIIL dataset ~57 MB on first run,
#    then caches it; falls back to a bundled synthetic dataset if offline)
python -m ml.train_model

# 2. Evaluate → writes ml/metrics_report.md
python -m ml.evaluate

# 3. Run the API
uvicorn app.main:app --reload --port 8000

# 4. Try it
curl -s localhost:8000/analyze-url -H 'content-type: application/json' \
  -d '{"url":"http://paypaI-secure-login.tk/verify/account","live_lookups":false}' | python -m json.tool
```

Run the tests:

```bash
cd backend && pytest -q
```

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

| Metric | Value |
|---|---|
| Precision | 0.963 |
| Recall | 0.955 |
| F1 | 0.959 |
| ROC-AUC | 0.990 |
| PR-AUC | 0.990 |

Full report incl. confusion matrix, feature importances, sample
mis-classifications and an out-of-distribution sanity check:
[`backend/ml/metrics_report.md`](backend/ml/metrics_report.md).
*(Numbers regenerate on each `python -m ml.train_model && python -m ml.evaluate`.)*

---

## Known false-positive / false-negative cases

- **FP:** HTTP-only government / university sites with deep paths
  (PhiUSIIL had no such benign examples). Mitigated by the reputation prior and,
  in the real world, by these sites actually serving HTTPS.
- **FN:** phishing pages on clean-looking, freshly-registered domains with no
  lexical tell (PhiUSIIL labels these from *page content*, which the URL
  endpoint can't see). The `page_signals` path and WHOIS-age rule exist for this.
- URL shorteners are reported as suspicious (destination is hidden) even though
  the shortener domain itself is reputable.

---

## Forensic angle (Phase 5, planned)

Every flagged event will be written to an **append-only** SQLite table as
`{ timestamp, event_type, details, prev_hash, entry_hash }` where
`entry_hash = SHA256(prev_hash + json(details))`. Altering any row breaks every
hash after it — a tamper-evident chain of custody. The dashboard will expose a
client-side "verify log integrity" button that recomputes the chain.

The DB layer (`app/db/database.py`) is already scaffolded for this.

---

## Threat model (summary)

- **In scope:** credential-phishing URLs, lookalike/typosquat domains,
  malicious file downloads (hash reputation + static heuristics), third-party
  tracking exposure, tamper-evident logging of all of the above.
- **Out of scope:** malware sandboxing / dynamic analysis, MITM/TLS
  interception, zero-day exploit detection, protecting against a local attacker
  who controls the browser or the machine.
- **Testing only ever uses the EICAR test file — never real malware.**
  Blocklists are bundled snapshots, never fetched live. No API keys ship in the
  extension; VirusTotal calls are server-side only.

---

## Repo layout

```
backend/
  app/
    main.py                     FastAPI app
    routers/url_analysis.py     POST /analyze-url, GET /model-info
    services/
      phishing_features.py      feature engineering (train + serve)
      phishing_predictor.py     model + rules + reputation → verdict
      whois_ssl.py              best-effort WHOIS age / SSL check
      reputation.py             Tranco top-10k prior
      brands.py                 curated brand list for typosquat detection
      data/tranco_top10k.txt.gz bundled reputation snapshot (2026-09-10)
    db/database.py              SQLAlchemy / SQLite (for Phase 5)
    models/phishing_model.pkl   trained bundle (gitignored — run train_model)
  ml/
    data_loader.py              dataset download + benign augmentation
    train_model.py              → app/models/phishing_model.pkl
    evaluate.py                 → ml/metrics_report.md
    ood_checkset.csv            hand-labelled sanity-check URLs
    dataset/build_sample_dataset.py  offline synthetic fallback
  scripts/refresh_tranco.py     regenerate the reputation snapshot
  tests/                        pytest (features + API)
extension/
  manifest.json                MV3 manifest
  config.js                    API_BASE_URL
  background.js                service worker: scan + badge
  content-script.js            DOM page_signals collector
  popup/                       popup UI
  icons/                       toolbar icons
dashboard/                     later phases
```
