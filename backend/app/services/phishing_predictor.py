"""Loads the trained phishing model and turns a URL into a verdict + reasons."""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import joblib
import numpy as np

from .brands import BRAND_DOMAIN_SET
from .reputation import SNAPSHOT_DATE, is_high_reputation
from .phishing_features import (
    URL_FEATURE_NAMES,
    extract_page_features,
    extract_url_features,
    nearest_brand,
    url_context,
)
from .whois_ssl import get_domain_age_days, get_ssl_info

MODEL_PATH = os.getenv(
    "PHISHING_MODEL_PATH",
    os.path.join(os.path.dirname(__file__), "..", "models", "phishing_model.pkl"),
)

# Score thresholds -> verdict label.
PHISHING_THRESHOLD = 0.65
SUSPICIOUS_THRESHOLD = 0.35


class ModelNotTrained(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _load_bundle():
    if not os.path.exists(MODEL_PATH):
        raise ModelNotTrained(
            f"No model at {MODEL_PATH}. Run: python -m ml.train_model"
        )
    return joblib.load(MODEL_PATH)


def model_metadata() -> dict:
    bundle = _load_bundle()
    return {
        "feature_names": bundle.get("feature_names", URL_FEATURE_NAMES),
        "trained_at": bundle.get("trained_at"),
        "dataset": bundle.get("dataset"),
        "model_type": bundle.get("model_type"),
        "cv_metrics": bundle.get("cv_metrics"),
    }


def _verdict(score: float) -> str:
    if score >= PHISHING_THRESHOLD:
        return "phishing"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "benign"


def _lexical_reasons(feats: dict, ctx: dict) -> list[str]:
    r = []
    if feats["has_at_symbol"]:
        r.append("URL contains an '@' symbol (browsers ignore text before it)")
    if feats["is_ip_host"]:
        r.append("Hostname is a raw IP address instead of a domain name")
    if not feats["has_https"]:
        r.append("Connection is not HTTPS")
    if feats["has_punycode"] or feats["has_non_ascii_host"]:
        r.append("Hostname uses punycode / non-ASCII characters (homograph risk)")
    if feats["num_subdomains"] >= 3:
        r.append(f"Unusually deep subdomain nesting ({feats['num_subdomains']} labels)")
    if feats["url_length"] >= 90:
        r.append(f"Very long URL ({feats['url_length']} characters)")
    if feats["suspicious_tld"]:
        r.append(f"Domain uses a frequently-abused TLD (.{ctx['tld'].split('.')[-1]})")
    if feats["is_shortener"]:
        r.append(f"URL shortener ({ctx['registered_domain']}) hides the true destination")
    if feats["num_suspicious_words"] >= 2:
        r.append("URL text contains multiple credential-related keywords")
    if feats["has_double_slash_in_path"]:
        r.append("Redundant '//' in the URL path (common redirect trick)")
    return r


def _typosquat_reason(feats: dict, ctx: dict) -> Optional[str]:
    if not feats["typosquat_flag"]:
        return None
    nb = nearest_brand(ctx["sld"])
    if nb:
        label, brand_domain, dist = nb
        if 0 < dist <= 2:
            return f"Looks like a typosquat of {brand_domain} (edit distance {dist})"
    if feats["brand_in_subdomain_or_path"]:
        return "A well-known brand name appears in the subdomain/path but is not the real domain"
    return "Domain closely resembles a known brand"


def analyze_url(url: str, *, live_lookups: bool = True,
                page_signals: Optional[dict] = None) -> dict:
    bundle = _load_bundle()
    model = bundle["model"]
    feature_names = bundle.get("feature_names", URL_FEATURE_NAMES)

    feats = extract_url_features(url)
    ctx = url_context(url)
    row = np.array([[feats[name] for name in feature_names]], dtype=float)

    proba = float(model.predict_proba(row)[0][1])

    reasons = _lexical_reasons(feats, ctx)
    score = proba

    tw = _typosquat_reason(feats, ctx)
    if tw:
        reasons.insert(0, tw)
        # Typosquatting / brand impersonation is a strong human-verifiable
        # signal that the lexical model under-weights, so lift the score.
        score = max(score, 0.6)
        if ctx["registered_domain"] not in BRAND_DOMAIN_SET:
            score = min(1.0, score + 0.2)

    if feats["num_suspicious_words"] >= 3 and not feats["has_https"]:
        score = min(1.0, score + 0.1)

    # ---- domain reputation prior -------------------------------------------
    # A global top-10k registered domain with no active impersonation signal
    # is treated as trusted (this is how browser allow-lists work). Typosquats,
    # '@' tricks, raw-IP hosts and homographs bypass the cap.
    bypass_reputation = bool(
        feats["typosquat_flag"] or feats["has_at_symbol"] or feats["is_ip_host"]
        or feats["has_punycode"] or feats["has_non_ascii_host"]
        or feats["is_shortener"]
    )
    reputation_trusted = (
        is_high_reputation(ctx["registered_domain"]) and not bypass_reputation
    )
    if reputation_trusted:
        if score > 0.15:
            score = 0.1
        reasons = [r for r in reasons
                   if not r.startswith(("URL text contains", "Very long URL",
                                        "Unusually deep subdomain"))]
        reasons.append(
            f"Registered domain is in the global top-10k (Tranco snapshot {SNAPSHOT_DATE})"
        )

    # ---- advisory runtime signals: nudge the score and add explanatory reasons ----
    enrichment = {"domain_age_days": None, "ssl": None,
                  "reputation_trusted": reputation_trusted}
    if live_lookups and not feats["is_ip_host"] and not reputation_trusted:
        age = get_domain_age_days(ctx["registered_domain"])
        enrichment["domain_age_days"] = age
        if age is not None and age <= 30:
            reasons.append(f"Domain was registered only {age} day(s) ago")
            score = min(1.0, score + 0.15)
        elif age is not None and age >= 730:
            score = max(0.0, score - 0.05)

        ssl_info = get_ssl_info(ctx["hostname"])
        enrichment["ssl"] = ssl_info
        if ssl_info is not None and ssl_info.get("valid") is False:
            reasons.append("SSL certificate is missing or failed validation")
            score = min(1.0, score + 0.1)

    if page_signals:
        pf = extract_page_features(page_signals)
        if pf["password_field_insecure"]:
            reasons.append("Password field submitted over a non-HTTPS connection")
            score = min(1.0, score + 0.2)
        if pf["form_action_cross_domain"]:
            reasons.append("Login form submits to a different domain than the page")
            score = min(1.0, score + 0.2)

    score = round(min(max(score, 0.0), 1.0), 4)
    if not reasons:
        reasons.append("No strong phishing indicators found")

    return {
        "url": url,
        "risk_score": score,
        "verdict": _verdict(score),
        "reasons": reasons,
        "model_score": round(proba, 4),
        "features": feats,
        "enrichment": enrichment,
    }
