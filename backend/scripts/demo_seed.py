"""Fill a running backend with demo data by calling its real endpoints.

    python scripts/demo_seed.py [--api http://127.0.0.1:8000] [--trackers-only]

Use it to pre-populate the dashboard, or as a fallback if you can't drive the
browser extension live. The page-level analyses (URL, file) are the real
pipeline. The TRACKER report is SYNTHETIC: it mimics what the extension would
post for a tracker-heavy page; it was not observed from a real browser.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import uuid

import httpx

# EICAR anti-virus test string (harmless 68-byte test pattern), built in memory only.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".encode("ascii")

URLS = [
    ("benign", "https://www.wikipedia.org/wiki/Phishing", None),
    ("typosquat phishing", "http://paypaI-secure-login.tk/verify/account", None),
    ("IP-host phishing", "http://185.234.219.12/paypal/webscr?cmd=_login&verify=1", {"has_login_form": True, "password_field_insecure": True}),
]


def tracker_report() -> dict:
    nets = [("doubleclick.net", 14), ("google-analytics.com", 9), ("facebook.com", 6), ("hotjar.com", 4), ("criteo.com", 3)]
    return {
        "session_id": uuid.uuid4().hex, "site": "tracker-heavy.example", "total_requests": 142,
        "third_party_requests": sum(n for _, n in nets) + 8, "third_party_domains": 19,
        "tracker_domains": 12, "tracker_requests": sum(n for _, n in nets),
        "unknown_third_party_domains": 7,
        "trackers": [{"domain": f"x.{d}", "network": d, "requests": n, "list": "easyprivacy"} for d, n in nets],
        "top_networks": [{"network": d, "requests": n, "domains": 1} for d, n in nets],
        "pixels": 5, "beacons": 3, "third_party_cookies": 14, "excessive_third_party_cookies": True,
        "canvas_fingerprinting": True, "canvas_events": 2, "canvas_scripts": ["cdn.fp-vendor.example"],
        "list_versions": {"easylist": "SYNTHETIC", "easyprivacy": "SYNTHETIC"},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--case", default="DEMO-001")
    ap.add_argument("--trackers-only", action="store_true", help="post only the (synthetic) tracker report")
    args = ap.parse_args()
    c = httpx.Client(base_url=args.api, timeout=30)

    for label, url, signals in [] if args.trackers_only else URLS:
        body = {"url": url, "live_lookups": False, "case_id": args.case}
        if signals:
            body["page_signals"] = signals
        r = c.post("/analyze-url", json=body)
        r.raise_for_status()
        j = r.json()
        print(f"[url ] {label:<20} -> {j['verdict']:<10} {j['risk_score']:.2f}  log_id={j['forensic_log_id']}")

    files = [
        ("EICAR test file", {"filename": "eicar.com", "sha256": hashlib.sha256(EICAR).hexdigest(), "size_bytes": len(EICAR),
                             "source_url": "https://secure.eicar.org/eicar.com", "mime_type": "application/octet-stream"}),
        ("double extension", {"filename": "invoice.pdf.exe", "size_bytes": 48210, "mime_type": "application/pdf",
                              "source_url": "http://185.234.219.12/dl/invoice.pdf.exe"}),
    ]
    for label, body in [] if args.trackers_only else files:
        r = c.post("/analyze-file", json={**body, "case_id": args.case})
        r.raise_for_status()
        j = r.json()
        print(f"[file] {label:<20} -> {j['verdict']:<10} {j['risk_score']:.2f}  mode={j['analysis_mode']} log_id={j['forensic_log_id']}")

    r = c.post("/tracker-report", json={**tracker_report(), "case_id": args.case})
    r.raise_for_status()
    print(f"[trkr] synthetic tracker-heavy   -> flags={r.json()['flags']} log_ids={r.json()['forensic_log_ids']}")

    v = c.get("/forensic-log/verify").json()
    print(f"[chain] valid={v['valid']} entries={v['entries_checked']}")
    return 0 if v["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
