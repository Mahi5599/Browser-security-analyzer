# 3-minute demo script

**Story:** a browser extension scores what you visit and download, and every
flagged event goes into a tamper-evident log that a dashboard can verify.
Total ≈ 3:00. Steps 2 and 3 have a *fallback* (the same backend endpoint the
extension calls) because you should not browse to a live phishing site or rely
on Chrome letting an EICAR file finish downloading in front of an audience.

## Before you start (5 min, off-camera)

```bash
# one-time: venv + model + env
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
cd backend && python -m ml.train_model && cp .env.example .env
#   edit .env: set FORENSIC_HMAC_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
#   (VIRUSTOTAL_API_KEY is optional; without it VT shows "unavailable")
cd ../dashboard && npm install && cd ..
```

Start from an empty log so the dashboard tells a clean story:

```bash
cd backend
export BSA_DB_PATH=./demo.db && rm -f demo.db        # scratch DB for the demo only
uvicorn app.main:app --port 8000                      # terminal 1
cd ../dashboard && npm run dev                        # terminal 2 -> http://localhost:5173
```

Load the extension: `chrome://extensions` → Developer mode → **Load unpacked** →
`extension/`. Its ID must read **`gknjaknibkcfffkjjceppndfodajfjil`** (pinned by
the `key` in `manifest.json`; the backend's CORS list is built around it).
Open the dashboard in one window and keep a second window for browsing.

> **What was and wasn't verified:** the extension's detection flows (phishing badge, EICAR download,
> tracker/fingerprint capture, forensic logging) were run in real headless Chrome against a local
> test site (`node scripts/e2e_extension.mjs`), and every curl/CLI command below was run. What was
> **not** seen: the popup and desktop notification on a real screen, and the live steps against real
> websites (1, 3-live, 4-live). Rehearse those once before presenting.

## Script

| Time | Step | Do | Say |
|---|---|---|---|
| 0:00 | **0. Frame it** | Show the dashboard: empty log, "Verify log integrity" → green, *0 entries*. | "Three detectors — phishing URLs, malicious downloads, trackers — feed one evidence log. Verify is green on an empty chain." |
| 0:20 | **1. Benign site** | Visit `https://en.wikipedia.org`. Click the extension icon. | "Green: model score is low and it's in the Tranco top-10k, so the reputation prior caps it. Benign verdicts are **not** logged — only evidence of something wrong." |
| 0:50 | **2. Typosquat phishing** | *Don't visit it.* Run the curl below, then **Refresh** the dashboard. | "This is the exact request the extension makes for the tab URL. `paypaI` swaps the *l* of paypal for an *I* — edit distance 1 from paypal.com — on HTTP and the abused `.tk` TLD. (A browser lowercases hostnames, so a live tab would show `paypai…`, which is still one edit from paypal.) Each reason is rule-based, so it is explainable." |
| 1:20 | **3. EICAR download** | Download `https://secure.eicar.org/eicar.com.txt`. Extension hashes the re-fetched bytes → notification "Malicious download detected". If Chrome blocks/never completes it, run the fallback below. | "EICAR is the industry's harmless antivirus test string — we never touch real malware. Only the **SHA-256 and metadata** leave the browser; the file never goes to our server or VirusTotal." |
| 2:00 | **4. Tracker-heavy site** | Visit a large news/media site, wait ~5 s, open the popup ("N trackers from M third-party domains"). If it doesn't cross a threshold, run the synthetic fallback. | "Observe-only: matched against bundled EasyList/EasyPrivacy snapshots, plus pixels, beacons and canvas fingerprinting. Pages over 10 tracker domains or showing fingerprinting are logged." |
| 2:20 | **5. Tamper** | Dashboard → **Verify log integrity** (green). Then run the `sqlite3` line below and click Verify again → red. Then `python scripts/tamper_demo.py` for the "smarter attacker". | "I edit one row directly in SQLite — I downgrade a *phishing* verdict to *benign*. The hash chain catches it and names that exact entry. A smarter attacker recomputes the hashes — the HMAC, whose key is not in the database, still catches that." |
| 2:50 | **6. Export** | Click **Export evidence**, show the displayed SHA-256, run `shasum -a 256` on the file. | "Every export carries its own hash, so evidence handed to someone else can be checked later." |

### Commands

**Step 2 — typosquat (fallback = primary):**

```bash
curl -s localhost:8000/analyze-url -H 'content-type: application/json' \
  -d '{"url":"http://paypaI-secure-login.tk/verify/account","live_lookups":false,"case_id":"DEMO"}' | python -m json.tool
```

Expected: `verdict: "phishing"`, reasons include *typosquat of paypal.com*, a log entry is created (`forensic_log_id`).

**Step 3 — EICAR fallback** (hashes the 68-byte test string in the shell; nothing is written to disk):

```bash
HASH=$(printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | shasum -a 256 | cut -d' ' -f1)
echo $HASH      # 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
curl -s localhost:8000/analyze-file -H 'content-type: application/json' \
  -d "{\"filename\":\"eicar.com\",\"sha256\":\"$HASH\",\"size_bytes\":68,\"source_url\":\"https://secure.eicar.org/eicar.com\",\"mime_type\":\"application/octet-stream\",\"case_id\":\"DEMO\"}" | python -m json.tool
```

Expected: `verdict: "malicious"`, `virustotal.status: "malicious"` (this is the **local EICAR
signature**, not a VirusTotal lookup — say so if asked).

**Step 4 — tracker fallback.** This posts a **synthetic** report (clearly labelled
`SYNTHETIC` list versions); say so out loud if you use it.

```bash
python scripts/demo_seed.py --trackers-only
```

**Step 5 — tamper the live log, then re-verify in the dashboard:**

```bash
sqlite3 demo.db "UPDATE forensic_log SET details_json = replace(details_json,'\"verdict\":\"phishing\"','\"verdict\":\"benign\"') WHERE id = (SELECT MIN(id) FROM forensic_log WHERE event_type='phishing_url');"
# dashboard -> Verify log integrity -> red "TAMPERING DETECTED, first broken entry #<id of that row>"
python scripts/tamper_demo.py        # self-contained: uses its own throwaway DB
```

Note how the **Flagged sites** table now shows `benign` for that row — the
dashboard displays what is in the database; the *verification* is what tells
you not to trust it.

Reset between runs: stop the backend, `rm backend/demo.db`, restart.

### If something goes wrong

| Symptom | Cause / fix |
|---|---|
| Dashboard says *Can't load data* | Backend not running on :8000, or the dashboard isn't on `localhost:5173`/`127.0.0.1:5173` (CORS). |
| Verify shows amber "Could not verify … 503" | `FORENSIC_HMAC_KEY` not set in `backend/.env`. |
| `/analyze-url` returns 503 | Model not trained: `python -m ml.train_model`. |
| Extension badge shows `?` | Backend not reachable from the extension. |
| Extension ID differs from the pinned one | You loaded a different folder/copy; the manifest `key` must be intact. |
| EICAR download fails in Chrome | Chrome's own download protection may block or warn on it; use the step 3 fallback. |
| Popup shows 0 trackers | Reload the page after loading the extension (it observes requests made after it starts). |
