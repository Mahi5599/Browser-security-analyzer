"""Domain reputation prior.

A bundled snapshot of the Tranco top-10k domains (https://tranco-list.eu/,
list downloaded 2026-09-10). Browsers use large allow-lists the same way: a
registered domain that sits in the global top-10k and shows no active
impersonation signal is almost never phishing, so we cap its risk score.

This is a *snapshot* -- it is never fetched live. Refresh it by re-running
``scripts/refresh_tranco.py`` and committing the new file.
"""
from __future__ import annotations

import gzip
import os
from functools import lru_cache

_SNAPSHOT = os.path.join(os.path.dirname(__file__), "data", "tranco_top10k.txt.gz")
SNAPSHOT_DATE = "2026-09-10"
SNAPSHOT_SIZE = 10000


@lru_cache(maxsize=1)
def _top_domains() -> frozenset[str]:
    try:
        with gzip.open(_SNAPSHOT, "rt", encoding="utf-8") as fh:
            return frozenset(line.strip().lower() for line in fh if line.strip())
    except FileNotFoundError:
        return frozenset()


def reputation_rank(registered_domain: str) -> int | None:
    """1 if the domain is in the bundled top list, else None. (The snapshot is
    stored without ranks; presence alone is the signal.)"""
    if not registered_domain:
        return None
    return 1 if registered_domain.lower() in _top_domains() else None


def is_high_reputation(registered_domain: str) -> bool:
    return reputation_rank(registered_domain) is not None
