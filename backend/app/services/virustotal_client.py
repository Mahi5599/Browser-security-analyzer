"""VirusTotal v3 hash-lookup client (server-side only).

* The API key comes from ``VIRUSTOTAL_API_KEY`` (backend/.env). It is never sent
  to the extension.
* Lookup only: ``GET /files/{sha256}``. If VirusTotal has never seen the hash we
  report ``unknown`` and DO NOT upload the file (privacy; uploads are public).
* Results are cached in SQLite so repeat downloads cost no quota.
* The free tier allows 4 requests/minute, enforced here with a sliding-window
  limiter. A caller waits up to ``max_wait`` seconds for a slot, otherwise the
  lookup returns ``rate_limited`` (the verdict then falls back to heuristics).

Result ``status`` values: malicious | suspicious | clean | unknown |
unavailable (no key) | rate_limited | error.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Callable, Optional

import httpx
from dotenv import load_dotenv

load_dotenv()

VT_BASE = "https://www.virustotal.com/api/v3"
FOUND_TTL = 24 * 3600      # a known verdict changes slowly
UNKNOWN_TTL = 3600         # an unseen hash may be analysed by someone soon

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vt_cache (
    sha256     TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    fetched_at REAL NOT NULL
);
"""


class RateLimiter:
    """Sliding window: at most ``max_calls`` per ``period`` seconds."""

    def __init__(self, max_calls: int = 4, period: float = 60.0,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.max_calls, self.period = max_calls, period
        self._clock, self._sleep = clock, sleep
        self._calls: list[float] = []
        self._lock = threading.Lock()

    def acquire(self, max_wait: float) -> bool:
        """Reserve a slot, waiting up to ``max_wait`` s. False if none in time."""
        deadline = self._clock() + max_wait
        while True:
            with self._lock:
                now = self._clock()
                self._calls = [t for t in self._calls if now - t < self.period]
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return True
                wait = self._calls[0] + self.period - now
            if self._clock() + wait > deadline:
                return False
            self._sleep(max(wait, 0.01))

    def penalize(self) -> None:
        """Server said 429: treat the whole window as used."""
        with self._lock:
            now = self._clock()
            self._calls = [now] * self.max_calls


class VirusTotalClient:
    def __init__(self, db_path: Optional[str] = None, api_key: Optional[str] = None,
                 http: Optional[httpx.Client] = None, limiter: Optional[RateLimiter] = None,
                 max_wait: float = 15.0, clock: Callable[[], float] = time.time):
        if db_path is None:
            from .forensic_log import _default_db_path
            db_path = _default_db_path()
        self.db_path = db_path
        self._api_key = api_key
        self._http = http
        self.limiter = limiter or RateLimiter()
        self.max_wait = max_wait
        self._now = clock
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @property
    def api_key(self) -> str:
        return self._api_key if self._api_key is not None else os.getenv("VIRUSTOTAL_API_KEY", "")

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ cache
    def _cache_get(self, sha256: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT result_json, fetched_at FROM vt_cache WHERE sha256=?",
                            (sha256,)).fetchone()
        if not row:
            return None
        result = json.loads(row[0])
        ttl = UNKNOWN_TTL if result["status"] == "unknown" else FOUND_TTL
        if self._now() - row[1] > ttl:
            return None
        return {**result, "cached": True}

    def _cache_put(self, sha256: str, result: dict) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO vt_cache VALUES (?,?,?)",
                      (sha256, json.dumps(result), self._now()))

    # ----------------------------------------------------------------- lookup
    def lookup(self, sha256: str) -> dict:
        sha256 = sha256.lower()
        cached = self._cache_get(sha256)
        if cached:
            return cached
        if not self.api_key:
            return {"status": "unavailable", "detail": "VIRUSTOTAL_API_KEY not configured",
                    "cached": False}
        if not self.limiter.acquire(self.max_wait):
            return {"status": "rate_limited", "detail": "free-tier limit (4/min) reached",
                    "cached": False}

        client = self._http or httpx.Client(timeout=10.0)
        try:
            resp = client.get(f"{VT_BASE}/files/{sha256}", headers={"x-apikey": self.api_key})
        except httpx.HTTPError as exc:
            return {"status": "error", "detail": f"VirusTotal unreachable: {exc.__class__.__name__}",
                    "cached": False}
        finally:
            if self._http is None:
                client.close()

        if resp.status_code == 404:
            result = {"status": "unknown", "detail": "hash not known to VirusTotal; file not uploaded",
                      "cached": False}
            self._cache_put(sha256, result)
            return result
        if resp.status_code == 429:
            self.limiter.penalize()
            return {"status": "rate_limited", "detail": "VirusTotal returned 429", "cached": False}
        if resp.status_code in (401, 403):
            return {"status": "error", "detail": "VirusTotal rejected the API key", "cached": False}
        if resp.status_code != 200:
            return {"status": "error", "detail": f"VirusTotal returned {resp.status_code}",
                    "cached": False}

        result = self._parse(resp.json())
        self._cache_put(sha256, result)
        return result

    @staticmethod
    def _parse(body: dict) -> dict:
        attrs = body.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        engines = sum(v for k, v in stats.items() if isinstance(v, int))
        if mal > 0:
            status = "malicious"
        elif sus > 0:
            status = "suspicious"
        else:
            status = "clean"
        threat = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        return {"status": status, "malicious": mal, "suspicious": sus, "engines": engines,
                "threat_label": threat, "type": attrs.get("type_description"),
                "cached": False}


_default: Optional[VirusTotalClient] = None


def get_client() -> VirusTotalClient:
    global _default
    from .forensic_log import _default_db_path
    if _default is None or _default.db_path != _default_db_path():
        _default = VirusTotalClient()
    return _default
