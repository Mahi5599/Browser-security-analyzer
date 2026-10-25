"""Tamper-evident forensic evidence log (Phase 5).

Every entry is chained to the previous one and authenticated with a keyed MAC:

    entry_hash = SHA256(prev_hash + canonical_json({timestamp, event_type, case_id, details}))
    hmac       = HMAC-SHA256(FORENSIC_HMAC_KEY, entry_hash)

* The hash chain makes edits, deletions and reordering *inside* the log
  detectable: changing any row breaks every hash after it.
* The HMAC stops someone who can only edit the DB file from simply recomputing
  the chain -- without the key they cannot produce valid MACs.
* ``chain_head`` is a second, HMAC-signed row holding the entry count and last
  hash, so truncating the *tail* of the log is also caught.

Limits (see README "Chain of custody"): anyone holding the key can forge
entries, and rolling the whole DB back to an older consistent copy is only
detectable if the head hash was recorded somewhere outside this database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from dotenv import load_dotenv

load_dotenv()  # picks up backend/.env (gitignored) when run from backend/

EVENT_TYPES = ("phishing_url", "malicious_file", "tracker_session")
GENESIS_HASH = "0" * 64
TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # fixed width => string order == time order

_SCHEMA = """
CREATE TABLE IF NOT EXISTS forensic_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    case_id       TEXT NOT NULL,
    details_json  TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL,
    hmac          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_forensic_log_type ON forensic_log(event_type);
CREATE INDEX IF NOT EXISTS ix_forensic_log_ts ON forensic_log(timestamp_utc);
CREATE TABLE IF NOT EXISTS chain_head (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    entry_count INTEGER NOT NULL,
    head_hash  TEXT NOT NULL,
    hmac       TEXT NOT NULL
);
"""


class ForensicKeyMissing(RuntimeError):
    """FORENSIC_HMAC_KEY is not configured; the log refuses to run unkeyed."""


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_entry_hash(prev_hash: str, timestamp: str, event_type: str,
                       case_id: str, details: Any) -> str:
    payload = canonical_json({
        "timestamp": timestamp,
        "event_type": event_type,
        "case_id": case_id,
        "details": details,
    })
    return hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()


def _get_key() -> bytes:
    key = os.getenv("FORENSIC_HMAC_KEY", "")
    if not key:
        raise ForensicKeyMissing(
            "FORENSIC_HMAC_KEY is not set. Add it to backend/.env (see .env.example)."
        )
    return key.encode("utf-8")


def compute_hmac(entry_hash: str, key: Optional[bytes] = None) -> str:
    return hmac.new(key or _get_key(), entry_hash.encode("ascii"), hashlib.sha256).hexdigest()


def _head_mac(count: int, head_hash: str, key: bytes) -> str:
    return hmac.new(key, f"head:{count}:{head_hash}".encode("ascii"), hashlib.sha256).hexdigest()


def _default_db_path() -> str:
    from ..db.database import engine  # reuse the app's configured SQLite file
    return engine.url.database


def normalize_ts(value: str | datetime) -> str:
    """Parse an ISO-8601 string/datetime into the log's fixed timestamp format."""
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(TS_FORMAT)


def _now() -> str:
    return datetime.now(timezone.utc).strftime(TS_FORMAT)


class ForensicLog:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _default_db_path()
        self._init()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    # ------------------------------------------------------------------ append
    def append(self, event_type: str, case_id: str, details: dict,
               timestamp: Optional[str] = None) -> dict:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"event_type must be one of {EVENT_TYPES}")
        if not case_id:
            raise ValueError("case_id is required")
        key = _get_key()
        ts = normalize_ts(timestamp) if timestamp else _now()
        # Round-trip through JSON so what is hashed is exactly what is stored.
        details = json.loads(canonical_json(details))

        with self._conn() as c:
            # IMMEDIATE takes the write lock before reading the tail, so two
            # concurrent appends cannot both chain to the same prev_hash.
            c.execute("BEGIN IMMEDIATE")
            try:
                last = c.execute(
                    "SELECT entry_hash FROM forensic_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = last["entry_hash"] if last else GENESIS_HASH
                entry_hash = compute_entry_hash(prev_hash, ts, event_type, case_id, details)
                mac = compute_hmac(entry_hash, key)
                cur = c.execute(
                    "INSERT INTO forensic_log (timestamp_utc, event_type, case_id, "
                    "details_json, prev_hash, entry_hash, hmac) VALUES (?,?,?,?,?,?,?)",
                    (ts, event_type, case_id, canonical_json(details), prev_hash, entry_hash, mac),
                )
                count = c.execute("SELECT COUNT(*) FROM forensic_log").fetchone()[0]
                c.execute(
                    "INSERT INTO chain_head (id, entry_count, head_hash, hmac) VALUES (1,?,?,?) "
                    "ON CONFLICT(id) DO UPDATE SET entry_count=excluded.entry_count, "
                    "head_hash=excluded.head_hash, hmac=excluded.hmac",
                    (count, entry_hash, _head_mac(count, entry_hash, key)),
                )
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise
            return self._row_to_dict(c.execute(
                "SELECT * FROM forensic_log WHERE id = ?", (cur.lastrowid,)
            ).fetchone())

    # -------------------------------------------------------------------- read
    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["details"] = json.loads(d.pop("details_json"))
        return d

    def query(self, *, event_type: Optional[str] = None, since: Optional[str] = None,
             until: Optional[str] = None, limit: int = 50, offset: int = 0) -> dict:
        where, args = [], []
        if event_type:
            where.append("event_type = ?")
            args.append(event_type)
        if since:
            where.append("timestamp_utc >= ?")
            args.append(normalize_ts(since))
        if until:
            where.append("timestamp_utc <= ?")
            args.append(normalize_ts(until))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._conn() as c:
            total = c.execute(f"SELECT COUNT(*) FROM forensic_log{clause}", args).fetchone()[0]
            rows = c.execute(
                f"SELECT * FROM forensic_log{clause} ORDER BY id ASC LIMIT ? OFFSET ?",
                [*args, limit, offset],
            ).fetchall()
        return {"total": total, "limit": limit, "offset": offset,
                "items": [self._row_to_dict(r) for r in rows]}

    # ------------------------------------------------------------------ verify
    def verify(self, expected_head: Optional[str] = None) -> dict:
        """Recompute the whole chain. Returns validity and the first broken id.

        ``expected_head``: optionally pin the head hash recorded out-of-band;
        a mismatch also catches rollback to an older consistent copy.
        """
        with self._conn() as c:
            rows = c.execute("SELECT * FROM forensic_log ORDER BY id ASC").fetchall()
            head = c.execute("SELECT * FROM chain_head WHERE id = 1").fetchone()
        return self._verify_rows(rows, head, expected_head)

    @staticmethod
    def _verify_rows(rows, head, expected_head: Optional[str] = None) -> dict:
        """Pure chain check over already-read rows (no database access)."""
        key = _get_key()

        def bad(entry_id, reason, n):
            return {"valid": False, "entries_checked": n, "first_broken_id": entry_id,
                    "reason": reason, "head_hash": None}

        prev = GENESIS_HASH
        for n, r in enumerate(rows):
            if r["prev_hash"] != prev:
                return bad(r["id"], "prev_hash does not match the preceding entry "
                           "(row deleted, inserted or reordered)", n)
            try:
                details = json.loads(r["details_json"])
            except ValueError:
                return bad(r["id"], "details_json is not valid JSON", n)
            expected = compute_entry_hash(r["prev_hash"], r["timestamp_utc"],
                                          r["event_type"], r["case_id"], details)
            if not hmac.compare_digest(expected, r["entry_hash"]):
                return bad(r["id"], "entry_hash does not match the row contents (row modified)", n)
            if not hmac.compare_digest(compute_hmac(r["entry_hash"], key), r["hmac"]):
                return bad(r["id"], "HMAC invalid (row forged or key mismatch)", n)
            prev = r["entry_hash"]

        # Tail truncation / head tampering: the head row is MAC'd separately.
        count = len(rows)
        if head is None:
            if count:
                return bad(rows[-1]["id"] + 1, "chain_head missing but entries exist", count)
        else:
            ok_mac = hmac.compare_digest(
                _head_mac(head["entry_count"], head["head_hash"], key), head["hmac"])
            if not ok_mac:
                return bad(None, "chain_head HMAC invalid", count)
            if head["entry_count"] != count or head["head_hash"] != prev:
                # First id that is no longer covered by the signed head.
                missing_after = rows[-1]["id"] if rows else 0
                return bad(missing_after + 1,
                           f"chain_head records {head['entry_count']} entries ending at "
                           f"{head['head_hash'][:12]}..., log has {count} (tail truncated or altered)",
                           count)
        if expected_head and expected_head != prev:
            return bad(None, "head hash differs from the pinned expected_head", count)

        return {"valid": True, "entries_checked": count, "first_broken_id": None,
                "reason": None, "head_hash": prev}


    def report_snapshot(self) -> tuple[list[dict], dict]:
        """Read-only: every entry plus the verification result of *that same read*.

        One deferred read transaction, so the entries and the verdict about them
        cannot disagree if another process appends meanwhile. Nothing is written.
        Rows that were tampered into something unparseable are returned with a
        placeholder ``details`` (the verification result flags them) instead of raising.
        """
        with self._conn() as c:
            c.execute("BEGIN")
            rows = c.execute("SELECT * FROM forensic_log ORDER BY id ASC").fetchall()
            head = c.execute("SELECT * FROM chain_head WHERE id = 1").fetchone()
            c.execute("COMMIT")
        verification = self._verify_rows(rows, head)
        entries = []
        for r in rows:
            d = dict(r)
            raw = d.pop("details_json")
            try:
                details = json.loads(raw)
            except ValueError:
                details = {"_unparseable_details_json": str(raw)[:300]}
            if not isinstance(details, dict):
                details = {"_non_object_details": details}
            d["details"] = details
            entries.append(d)
        return entries, verification


# ------------------------------------------------------------------ evidence
def _model_version() -> dict:
    """Identify exactly which model produced a verdict."""
    from . import phishing_predictor as pp
    meta = pp.model_metadata()
    digest = None
    try:
        with open(pp.MODEL_PATH, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        pass
    return {"model_type": meta.get("model_type"), "trained_at": meta.get("trained_at"),
            "dataset": meta.get("dataset"), "model_sha256": digest}


def build_phishing_evidence(result: dict, page_signals: Optional[dict]) -> dict:
    from .reputation import SNAPSHOT_DATE
    return {
        "url": result["url"],
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "model_score": result.get("model_score"),
        "reasons": result["reasons"],
        "model_version": _model_version(),
        "tranco_snapshot_date": SNAPSHOT_DATE,
        "dom_signals": page_signals,
        "enrichment": result.get("enrichment"),
    }


_default: Optional[ForensicLog] = None


def get_log() -> ForensicLog:
    global _default
    if _default is None or _default.db_path != _default_db_path():
        _default = ForensicLog()
    return _default
