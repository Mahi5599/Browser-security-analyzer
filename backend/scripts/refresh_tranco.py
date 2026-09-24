"""Refresh the bundled Tranco top-domains snapshot used by the reputation prior.

Run manually (not at build/request time) and commit the result:

    python scripts/refresh_tranco.py --top 10000

Then bump ``SNAPSHOT_DATE`` in ``app/services/reputation.py``.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import io
import os
import urllib.request
import zipfile

OUT = os.path.join(
    os.path.dirname(__file__), "..", "app", "services", "data", "tranco_top10k.txt.gz"
)
TRANCO_ZIP = "https://tranco-list.eu/top-1m.csv.zip"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=10000)
    args = ap.parse_args()

    print(f"downloading {TRANCO_ZIP} ...")
    raw = urllib.request.urlopen(TRANCO_ZIP, timeout=120).read()
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = zf.namelist()[0]
        lines = zf.read(name).decode("utf-8").splitlines()

    domains = [ln.split(",", 1)[1].strip().lower() for ln in lines[: args.top] if "," in ln]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8") as fh:
        fh.write("\n".join(domains) + "\n")

    print(f"wrote {len(domains)} domains -> {os.path.relpath(OUT)}")
    print(f"now set SNAPSHOT_DATE = \"{dt.date.today().isoformat()}\" in app/services/reputation.py")


if __name__ == "__main__":
    main()
