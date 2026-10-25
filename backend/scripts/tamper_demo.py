"""Viva demo: the forensic log catches tampering.

    cd backend && python scripts/tamper_demo.py

Uses a throwaway SQLite file (never your real bsa.db) and drives the real
FastAPI endpoints in-process:
  1. append evidence through POST /forensic-log
  2. GET /forensic-log/verify  -> valid
  3. edit one row directly in SQLite (what an attacker with file access does)
  4. GET /forensic-log/verify  -> invalid, names the first broken entry
  5. attacker "fixes" the chain by recomputing the hashes -> still caught by HMAC
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEMO_DB = os.path.join(tempfile.mkdtemp(prefix="bsa_tamper_demo_"), "demo.db")
os.environ["BSA_DB_PATH"] = DEMO_DB
# Real deployments set this in .env. Demo uses its own key unless one is given.
os.environ.setdefault("FORENSIC_HMAC_KEY", "demo-only-key-do-not-use")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.services.forensic_log import compute_entry_hash  # noqa: E402


def show(title: str, v: dict) -> None:
    status = "VALID  " if v["valid"] else "INVALID"
    print(f"   -> /forensic-log/verify: {status} entries_checked={v['entries_checked']}"
          f" first_broken_id={v['first_broken_id']}")
    if v["reason"]:
        print(f"      reason: {v['reason']}")


def main() -> None:
    print(f"Demo database: {DEMO_DB}\n")
    with TestClient(app) as client:
        print("1. Append 5 pieces of evidence")
        events = [
            ("phishing_url", {"url": "http://paypaI-secure-login.tk/verify", "verdict": "phishing",
                              "risk_score": 0.93}),
            ("phishing_url", {"url": "http://185.234.219.12/paypal/webscr", "verdict": "phishing",
                              "risk_score": 0.97}),
            ("malicious_file", {"filename": "eicar.com", "sha256": "275a021b...", "verdict": "malicious"}),
            ("tracker_session", {"site": "news.example", "trackers": 14}),
            ("phishing_url", {"url": "http://amaz0n-account.top/login", "verdict": "suspicious",
                              "risk_score": 0.58}),
        ]
        ids = []
        for etype, details in events:
            r = client.post("/forensic-log", json={"event_type": etype, "case_id": "VIVA-001",
                                                   "details": details})
            ids.append(r.json()["id"])
            print(f"   #{r.json()['id']} {etype:<16} entry_hash={r.json()['entry_hash'][:16]}...")

        print("\n2. Verify the untouched chain")
        show("clean", client.get("/forensic-log/verify").json())

        victim = ids[1]
        print(f"\n3. ATTACK: directly edit row #{victim} in SQLite "
              "(downgrade 'phishing' to 'benign' to hide it)")
        db = sqlite3.connect(DEMO_DB)
        row = db.execute("SELECT details_json FROM forensic_log WHERE id=?", (victim,)).fetchone()
        print(f"   before: {row[0][:90]}")
        db.execute("UPDATE forensic_log SET details_json = replace(details_json, "
                   "'\"verdict\":\"phishing\"', '\"verdict\":\"benign\"') WHERE id=?", (victim,))
        db.commit()
        row = db.execute("SELECT details_json FROM forensic_log WHERE id=?", (victim,)).fetchone()
        print(f"   after : {row[0][:90]}")

        print("\n4. Verify again")
        show("tampered", client.get("/forensic-log/verify").json())

        print(f"\n5. SMARTER ATTACK: also recompute row #{victim}'s entry_hash (no key available)")
        r = db.execute("SELECT * FROM forensic_log WHERE id=?", (victim,)).fetchone()
        cols = [d[0] for d in db.execute("SELECT * FROM forensic_log LIMIT 0").description]
        r = dict(zip(cols, r))
        import json
        new_hash = compute_entry_hash(r["prev_hash"], r["timestamp_utc"], r["event_type"],
                                      r["case_id"], json.loads(r["details_json"]))
        db.execute("UPDATE forensic_log SET entry_hash=? WHERE id=?", (new_hash, victim))
        db.commit()
        db.close()
        show("recomputed", client.get("/forensic-log/verify").json())
        print("\nThe hash chain alone is recomputable; the HMAC (secret key) is what stops "
              "the attacker.")


if __name__ == "__main__":
    main()
