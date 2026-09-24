"""Load a labelled URL dataset and turn it into a model-ready feature matrix.

Priority:
  1. UCI PhiUSIIL Phishing URL Dataset (id=967). The raw CSV is downloaded
     once from the UCI archive to ``dataset/phiusiil_raw.csv`` and a slim
     ``url,label`` parquet is cached next to it.
  2. Bundled synthetic fallback ``dataset/sample_urls.csv`` (offline / CI).

Label convention everywhere in this project: ``1 = phishing``, ``0 = benign``.
(PhiUSIIL ships the opposite: its ``label`` is 1 for legitimate, 0 for phishing.)
"""
from __future__ import annotations

import os
import random
import sys
import urllib.request

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.phishing_features import URL_FEATURE_NAMES, extract_url_features  # noqa: E402

HERE = os.path.dirname(__file__)
DATA_DIR = os.path.join(HERE, "dataset")
PHIUSIIL_RAW = os.path.join(DATA_DIR, "phiusiil_raw.csv")
PHIUSIIL_CACHE = os.path.join(DATA_DIR, "phiusiil_cache.csv.gz")
SAMPLE_CSV = os.path.join(DATA_DIR, "sample_urls.csv")

PHIUSIIL_URL = "https://archive.ics.uci.edu/static/public/967/data.csv"


def _download_phiusiil() -> bool:
    if os.path.exists(PHIUSIIL_RAW):
        return True
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"[data_loader] downloading PhiUSIIL (~57 MB) from {PHIUSIIL_URL} ...")
    try:
        tmp = PHIUSIIL_RAW + ".part"
        urllib.request.urlretrieve(PHIUSIIL_URL, tmp)
        os.replace(tmp, PHIUSIIL_RAW)
        return True
    except Exception as exc:
        print(f"[data_loader] PhiUSIIL download failed: {exc}")
        return False


def _load_phiusiil() -> pd.DataFrame | None:
    if os.path.exists(PHIUSIIL_CACHE):
        return pd.read_csv(PHIUSIIL_CACHE)
    if not _download_phiusiil():
        return None
    try:
        raw = pd.read_csv(PHIUSIIL_RAW, usecols=["URL", "label"])
    except Exception as exc:
        print(f"[data_loader] could not parse PhiUSIIL CSV: {exc}")
        return None

    df = pd.DataFrame(
        {
            "url": raw["URL"].astype(str),
            "label": (raw["label"].astype(int) == 0).astype(int),  # phishing == 0 -> 1
        }
    )
    df = df.dropna().drop_duplicates("url").reset_index(drop=True)
    df.to_csv(PHIUSIIL_CACHE, index=False, compression="gzip")
    print(f"[data_loader] cached -> {os.path.relpath(PHIUSIIL_CACHE)} ({len(df)} rows)")
    return df


_BENIGN_PATHS = [
    "/", "/about", "/contact", "/help", "/faq", "/search?q={q}", "/login",
    "/signin", "/account", "/account/settings", "/profile", "/dashboard",
    "/products/{n}", "/product/{q}-{n}", "/category/{q}", "/blog/{yr}/{mo}/{q}",
    "/news/{yr}/{mo}/{q}.html", "/wiki/{Q}", "/articles/{n}", "/p/{n}",
    "/watch?v={tok}", "/playlist/{tok}", "/user/{q}", "/u/{n}/inbox",
    "/checkout/cart", "/orders/{n}", "/{cc}/en/home", "/support/tickets/{n}",
    "/api/v2/status", "/docs/getting-started", "/pricing", "/#section-{n}",
    "/settings/security", "/{q}/{q2}", "/browse?page={n}&sort=new",
]
_WORDS = ["security", "update", "guide", "review", "python", "travel", "market",
          "health", "design", "history", "science", "finance", "recipe", "sport"]
_CC = ["us", "gb", "de", "fr", "in", "ca", "au", "jp"]
_BENIGN_SUBS = ["app", "login", "accounts", "account", "my", "secure", "portal",
                "api", "mail", "shop", "store", "blog", "support", "help", "m",
                "www", "docs", "dashboard", "auth", "id", "web", "cloud", "news"]


def _augment_benign(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """PhiUSIIL's benign URLs are 100% HTTPS bare domains, so a model trivially
    learns "has path or http -> phishing". Re-attach realistic paths/queries to
    most benign rows and downgrade a minority to http, matching how real benign
    traffic actually looks. Phishing rows are left untouched.
    """
    rng = random.Random(seed)
    benign = df[df.label == 0].copy()
    other = df[df.label != 0]

    new_urls = []
    for u in benign["url"]:
        u = str(u).rstrip("/")
        # ---- host shape (PhiUSIIL benign is ~100% "www.domain.tld") ----
        scheme, _, rest = u.partition("://")
        host, slash, tail = rest.partition("/")
        apex = host[4:] if host.startswith("www.") else host
        sr = rng.random()
        if sr < 0.34:            # bare apex domain (github.com)
            host = apex
        elif sr < 0.70:          # real service subdomain (accounts.google.com)
            sub = rng.choice(_BENIGN_SUBS)
            if rng.random() < 0.12:
                sub = rng.choice(_BENIGN_SUBS) + "." + sub
            host = f"{sub}.{apex}"
        # else: keep host as-is (www. or whatever it had)
        u = f"{scheme}://{host}" + (slash + tail if slash else "")
        r = rng.random()
        if r < 0.68:  # attach a realistic path
            tmpl = rng.choice(_BENIGN_PATHS)
            w = rng.choice(_WORDS)
            path = tmpl.format(
                q=w, q2=rng.choice(_WORDS), Q=w.capitalize(), n=rng.randint(1, 99999),
                yr=rng.randint(2018, 2026), mo=f"{rng.randint(1, 12):02d}",
                tok="".join(rng.choices("abcdefghijklmnop0123456789", k=11)),
                cc=rng.choice(_CC),
            )
            u = u + path
        if rng.random() < 0.15 and u.startswith("https://"):
            u = "http://" + u[len("https://"):]
        new_urls.append(u)

    benign["url"] = new_urls
    out = pd.concat([benign, other], ignore_index=True)
    return out.sample(frac=1, random_state=seed).reset_index(drop=True)


def _load_sample() -> pd.DataFrame:
    if not os.path.exists(SAMPLE_CSV):
        from ml.dataset.build_sample_dataset import main as build

        build()
    return pd.read_csv(SAMPLE_CSV)


def load_labelled_urls(prefer: str = "auto", max_rows: int | None = None,
                       augment: bool = True):
    """Return (DataFrame[url, label], source_name)."""
    df = None
    source = None
    is_phiusiil = False
    if prefer in {"auto", "phiusiil"}:
        df = _load_phiusiil()
        if df is not None:
            source = "UCI PhiUSIIL Phishing URL Dataset (id=967)"
            is_phiusiil = True
    if df is None:
        if prefer == "phiusiil":
            raise SystemExit("PhiUSIIL unavailable and --source phiusiil was requested.")
        df = _load_sample()
        source = "bundled synthetic sample (dataset/sample_urls.csv)"

    df = df.dropna(subset=["url", "label"]).copy()
    df["label"] = df["label"].astype(int)

    if is_phiusiil and augment:
        df = _augment_benign(df)
        source += " + benign path/scheme augmentation"

    if max_rows and len(df) > max_rows:
        per_class = max_rows // 2
        df = (
            df.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(min(len(g), per_class), random_state=42))
            .sample(frac=1, random_state=42)
            .reset_index(drop=True)
        )
    return df, source


def build_feature_frame(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for url in df["url"]:
        try:
            rows.append(extract_url_features(url))
        except Exception:
            rows.append({k: 0 for k in URL_FEATURE_NAMES})
    feat_df = pd.DataFrame(rows, columns=URL_FEATURE_NAMES)
    feat_df["label"] = df["label"].to_numpy()
    feat_df["url"] = df["url"].to_numpy()
    return feat_df
