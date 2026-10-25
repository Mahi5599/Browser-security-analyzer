"""Per-page-load tracking reports (Phase 4): storage, aggregation, flagging.

The extension POSTs a cumulative snapshot per page load (``session_id``);
each POST replaces the previous snapshot for that session. Only the site's
hostname is stored -- never the full page URL, which can carry tokens.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from .forensic_log import get_log

log = logging.getLogger(__name__)
_upsert_lock = threading.Lock()  # one writer at a time: avoids double-logging a session

# A page load is "high tracking" and goes to the forensic log when...
HIGH_TRACKER_DOMAINS = 10
EXCESSIVE_COOKIES = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tracker_sessions (
    session_id TEXT PRIMARY KEY,
    site TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    third_party_requests INTEGER NOT NULL,
    third_party_domains INTEGER NOT NULL,
    tracker_domains INTEGER NOT NULL,
    tracker_requests INTEGER NOT NULL,
    pixels INTEGER NOT NULL,
    beacons INTEGER NOT NULL,
    third_party_cookies INTEGER NOT NULL,
    canvas_fingerprinting INTEGER NOT NULL,
    trackers_json TEXT NOT NULL,
    networks_json TEXT NOT NULL,
    canvas_scripts_json TEXT NOT NULL,
    list_versions_json TEXT NOT NULL,
    logged_reasons TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS ix_tracker_sessions_site ON tracker_sessions(site);
CREATE INDEX IF NOT EXISTS ix_tracker_sessions_seen ON tracker_sessions(last_seen);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def flag_reasons(r: dict) -> list[str]:
    reasons = []
    if r["tracker_domains"] >= HIGH_TRACKER_DOMAINS:
        reasons.append("high_tracker_count")
    if r["canvas_fingerprinting"]:
        reasons.append("canvas_fingerprinting")
    if r["third_party_cookies"] >= EXCESSIVE_COOKIES:
        reasons.append("excessive_third_party_cookies")
    return reasons


class TrackerStore:
    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            from .forensic_log import _default_db_path
            db_path = _default_db_path()
        self.db_path = db_path
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def upsert(self, r: dict, case_id: str = "default") -> dict:
        with _upsert_lock:
            return self._upsert(r, case_id)

    def _upsert(self, r: dict, case_id: str) -> dict:
        now = _now()
        with self._conn() as c:
            row = c.execute("SELECT logged_reasons FROM tracker_sessions WHERE session_id=?",
                            (r["session_id"],)).fetchone()
        logged = json.loads(row["logged_reasons"]) if row else []
        reasons = flag_reasons(r)
        new_reasons = [x for x in reasons if x not in logged]

        log_ids = []
        if new_reasons:
            # One forensic entry per newly-crossed threshold, per page load. The
            # forensic log uses its own write transaction, so we hold none here.
            try:
                entry = get_log().append("tracker_session", case_id, {
                    "site": r["site"], "session_id": r["session_id"], "reasons": new_reasons,
                    "all_flags": reasons,
                    "tracker_domains": r["tracker_domains"],
                    "third_party_domains": r["third_party_domains"],
                    "third_party_requests": r["third_party_requests"],
                    "tracker_requests": r["tracker_requests"],
                    "pixels": r["pixels"], "beacons": r["beacons"],
                    "third_party_cookies": r["third_party_cookies"],
                    "canvas_fingerprinting": r["canvas_fingerprinting"],
                    "canvas_scripts": r["canvas_scripts"],
                    "top_networks": r["top_networks"][:5],
                    "list_versions": r["list_versions"],
                })
                log_ids.append(entry["id"])
                logged = logged + new_reasons
            except Exception:
                # Keep the stats; not marking the reasons as logged means the
                # next update of this session retries the forensic entry.
                log.exception("Forensic log append failed for tracker session %s", r["session_id"])

        with self._conn() as c:
            c.execute(
                "INSERT INTO tracker_sessions (session_id, site, first_seen, last_seen, "
                "third_party_requests, third_party_domains, tracker_domains, tracker_requests, "
                "pixels, beacons, third_party_cookies, canvas_fingerprinting, trackers_json, "
                "networks_json, canvas_scripts_json, list_versions_json, logged_reasons) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(session_id) DO UPDATE SET last_seen=excluded.last_seen, "
                "third_party_requests=excluded.third_party_requests, "
                "third_party_domains=excluded.third_party_domains, "
                "tracker_domains=excluded.tracker_domains, tracker_requests=excluded.tracker_requests, "
                "pixels=excluded.pixels, beacons=excluded.beacons, "
                "third_party_cookies=excluded.third_party_cookies, "
                "canvas_fingerprinting=excluded.canvas_fingerprinting, "
                "trackers_json=excluded.trackers_json, networks_json=excluded.networks_json, "
                "canvas_scripts_json=excluded.canvas_scripts_json, "
                "list_versions_json=excluded.list_versions_json, "
                "logged_reasons=excluded.logged_reasons",
                (r["session_id"], r["site"], now, now, r["third_party_requests"],
                 r["third_party_domains"], r["tracker_domains"], r["tracker_requests"],
                 r["pixels"], r["beacons"], r["third_party_cookies"],
                 int(r["canvas_fingerprinting"]), json.dumps(r["trackers"]),
                 json.dumps(r["top_networks"]), json.dumps(r["canvas_scripts"]),
                 json.dumps(r["list_versions"]), json.dumps(logged)),
            )
        return {"flags": reasons, "forensic_log_ids": log_ids,
                "forensic_logged": not new_reasons or bool(log_ids)}

    def report(self, site: Optional[str] = None, since: Optional[str] = None,
               top: int = 10) -> dict:
        where, args = [], []
        if site:
            where.append("site = ?")
            args.append(site.lower())
        if since:
            where.append("last_seen >= ?")
            args.append(since)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._conn() as c:
            rows = c.execute(f"SELECT * FROM tracker_sessions{clause}", args).fetchall()

        per_site: dict[str, dict] = defaultdict(lambda: {
            "sessions": 0, "tracker_domains_total": 0, "max_tracker_domains": 0,
            "tracker_requests": 0, "pixels": 0, "beacons": 0,
            "third_party_cookies": 0, "fingerprinting_sessions": 0})
        net_requests: Counter = Counter()
        net_sites: dict[str, set] = defaultdict(set)
        net_sessions: Counter = Counter()
        fp_sites: set = set()
        fp_scripts: Counter = Counter()
        totals = Counter()

        for r in rows:
            s = per_site[r["site"]]
            s["sessions"] += 1
            s["tracker_domains_total"] += r["tracker_domains"]
            s["max_tracker_domains"] = max(s["max_tracker_domains"], r["tracker_domains"])
            for k in ("tracker_requests", "pixels", "beacons", "third_party_cookies"):
                s[k] += r[k]
            s["fingerprinting_sessions"] += r["canvas_fingerprinting"]
            totals["sessions"] += 1
            for k in ("tracker_requests", "pixels", "beacons", "third_party_requests"):
                totals[k] += r[k]
            totals["fingerprinting_sessions"] += r["canvas_fingerprinting"]
            if r["canvas_fingerprinting"]:
                fp_sites.add(r["site"])
                fp_scripts.update(json.loads(r["canvas_scripts_json"]))
            for n in json.loads(r["networks_json"]):
                net_requests[n["network"]] += n["requests"]
                net_sites[n["network"]].add(r["site"])
                net_sessions[n["network"]] += 1

        sites = []
        for name, s in per_site.items():
            sites.append({"site": name, **{k: v for k, v in s.items() if k != "tracker_domains_total"},
                          "avg_tracker_domains": round(s["tracker_domains_total"] / s["sessions"], 2)})
        sites.sort(key=lambda x: (-x["avg_tracker_domains"], x["site"]))

        networks = [{"network": n, "requests": net_requests[n], "sites": len(net_sites[n]),
                     "sessions": net_sessions[n]}
                    for n, _ in net_requests.most_common(top)]
        return {
            "totals": {**totals, "sites": len(per_site)},
            "sites": sites[:top * 5],
            "top_networks": networks,
            "fingerprinting": {"sessions": totals["fingerprinting_sessions"],
                               "sites": sorted(fp_sites),
                               "top_scripts": [{"host": h, "sessions": n}
                                               for h, n in fp_scripts.most_common(top)]},
            "thresholds": {"high_tracker_domains": HIGH_TRACKER_DOMAINS,
                           "excessive_third_party_cookies": EXCESSIVE_COOKIES},
        }


_default: Optional[TrackerStore] = None


def get_store() -> TrackerStore:
    global _default
    from .forensic_log import _default_db_path
    if _default is None or _default.db_path != _default_db_path():
        _default = TrackerStore()
    return _default
