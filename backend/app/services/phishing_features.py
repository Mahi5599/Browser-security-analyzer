"""URL / page feature engineering for the phishing classifier.

Two entry points:

- ``extract_url_features(url)``          -> dict of numeric features (model input)
- ``extract_page_features(page_signals)`` -> dict of DOM-derived features

Only the URL-lexical + typosquatting features are used to *train* the model,
because WHOIS / SSL / DOM signals are not available for every row of the
offline training set. They are computed at request time and fed to the
rule-based reason generator instead (see ``routers/url_analysis.py``).

The ordered feature list the model expects is ``URL_FEATURE_NAMES``.
"""
from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlparse

import tldextract
from rapidfuzz.distance import Levenshtein

from .brands import BRAND_DOMAIN_SET, BRAND_SLD, LEGIT_BRAND_ADJACENT

# Use the PSL snapshot bundled with tldextract -- never fetch it live.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "lnkd.in", "t.ly", "s.id",
}

# TLDs disproportionately abused for phishing / malware (Spamhaus, Interisle).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click",
    "link", "country", "kim", "science", "party", "gdn", "review", "loan",
    "rest", "fit", "cam", "surf", "cyou", "sbs", "cfd", "quest", "monster",
}

SUSPICIOUS_WORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure",
    "security", "account", "update", "confirm", "banking", "webscr", "ebayisapi",
    "wallet", "recover", "unlock", "suspend", "authenticate", "password",
    "credential", "billing", "invoice", "payment", "support", "helpdesk",
]

URL_FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_subdomains",
    "num_hyphens",
    "num_underscores",
    "num_slashes",
    "num_question_marks",
    "num_equals",
    "num_at",
    "num_ampersand",
    "num_percent",
    "num_digits",
    "digit_ratio",
    "letter_ratio",
    "non_alnum_ratio",
    "has_at_symbol",
    "has_https",
    "has_port",
    "is_ip_host",
    "has_punycode",
    "has_non_ascii_host",
    "tld_length",
    "suspicious_tld",
    "is_shortener",
    "subdomain_length",
    "sld_length",
    "num_suspicious_words",
    "has_double_slash_in_path",
    "host_entropy",
    "brand_min_edit_distance",
    "brand_in_subdomain_or_path",
    "typosquat_flag",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "http://" + url
    return url


def _brand_signals(registered_domain: str, subdomain: str, path: str, sld: str):
    """Return (min_edit_distance_to_a_brand, brand_in_sub_or_path, typosquat)."""
    reg = (registered_domain or "").lower()
    sld = (sld or "").lower()
    sub = (subdomain or "").lower()
    path = (path or "").lower()

    if reg in BRAND_DOMAIN_SET or reg in LEGIT_BRAND_ADJACENT:
        # Exact legit brand (or known brand-adjacent) domain -- not a typosquat.
        return 0, False, False

    if sld in BRAND_SLD:
        # Same second-level label as a brand but a different TLD
        # (amazon.co.uk, google.de, paypal.co.uk) -- brands run many ccTLDs.
        return 0, False, False

    # Closest brand to any hyphen/dot-separated token of the SLD
    # ("paypal-secure" -> tokens {paypal, secure}; "paypa1" -> {paypa1}).
    # Only compare comparable-length strings so short brands ("x", "citi")
    # don't match every random token.
    tokens = [t for t in re.split(r"[^a-z0-9]+", sld) if len(t) >= 4]
    min_dist = -1
    for tok in tokens or ([sld] if sld and len(sld) >= 4 else []):
        for brand_sld in BRAND_SLD:
            if len(brand_sld) < 5 or abs(len(tok) - len(brand_sld)) > 2:
                continue
            d = Levenshtein.distance(tok, brand_sld)
            if min_dist < 0 or d < min_dist:
                min_dist = d

    # A brand name embedded verbatim in the registered domain, subdomain, or
    # path while the real registered domain is NOT that brand.
    reg_no_tld = reg.split(".")[0] if reg else ""
    brand_substring_in_domain = any(
        len(b) >= 4 and b in reg_no_tld and reg not in BRAND_DOMAIN_SET
        for b in BRAND_SLD
    )
    brand_in_sub_or_path = any(
        len(b) >= 4 and (b in sub or f"/{b}" in path or f"{b}." in sub)
        for b in BRAND_SLD
    )

    typosquat = (
        0 < min_dist <= 2
        or brand_substring_in_domain
        or brand_in_sub_or_path
    )
    return min_dist, (brand_in_sub_or_path or brand_substring_in_domain), bool(typosquat)


def extract_url_features(url: str) -> dict:
    raw = _normalize_url(url)
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    ext = _extract(host)
    subdomain = ext.subdomain
    sld = ext.domain
    tld = ext.suffix
    registered_domain = ext.registered_domain or host

    text_for_words = raw.lower()
    letters = sum(ch.isalpha() for ch in raw)
    digits = sum(ch.isdigit() for ch in raw)
    non_alnum = sum((not ch.isalnum()) for ch in raw)
    n = max(len(raw), 1)

    is_ip = _is_ip(host)
    min_dist, brand_in_sp, typosquat = _brand_signals(
        registered_domain, subdomain, path, sld
    )

    feats = {
        "url_length": len(raw),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_subdomains": len([p for p in subdomain.split(".") if p]) if subdomain else 0,
        "num_hyphens": raw.count("-"),
        "num_underscores": raw.count("_"),
        "num_slashes": raw.count("/"),
        "num_question_marks": raw.count("?"),
        "num_equals": raw.count("="),
        "num_at": raw.count("@"),
        "num_ampersand": raw.count("&"),
        "num_percent": raw.count("%"),
        "num_digits": digits,
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "non_alnum_ratio": non_alnum / n,
        "has_at_symbol": int("@" in raw),
        "has_https": int(scheme == "https"),
        "has_port": int(parsed.port is not None),
        "is_ip_host": int(is_ip),
        "has_punycode": int("xn--" in host),
        "has_non_ascii_host": int(any(ord(ch) > 127 for ch in host)),
        "tld_length": len(tld),
        "suspicious_tld": int(tld.split(".")[-1] in SUSPICIOUS_TLDS if tld else 0),
        "is_shortener": int(registered_domain in SHORTENERS),
        "subdomain_length": len(subdomain),
        "sld_length": len(sld),
        "num_suspicious_words": sum(w in text_for_words for w in SUSPICIOUS_WORDS),
        "has_double_slash_in_path": int("//" in path),
        "host_entropy": round(_shannon_entropy(host), 4),
        "brand_min_edit_distance": min_dist,
        "brand_in_subdomain_or_path": int(brand_in_sp),
        "typosquat_flag": int(typosquat),
    }
    # Guarantee stable ordering / completeness.
    return {k: feats[k] for k in URL_FEATURE_NAMES}


def url_context(url: str) -> dict:
    """Non-numeric context used by the reason generator (not a model input)."""
    raw = _normalize_url(url)
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    ext = _extract(host)
    return {
        "normalized_url": raw,
        "scheme": (parsed.scheme or "").lower(),
        "hostname": host,
        "registered_domain": ext.registered_domain or host,
        "subdomain": ext.subdomain,
        "sld": ext.domain,
        "tld": ext.suffix,
    }


def nearest_brand(sld: str):
    """Return (brand_label, brand_domain, edit_distance) for the closest brand,
    comparing against each hyphen/dot-separated token of the SLD."""
    sld = (sld or "").lower()
    if not sld:
        return None
    tokens = [t for t in re.split(r"[^a-z0-9]+", sld) if len(t) >= 4] or [sld]
    best = None
    for tok in tokens:
        for brand_sld, label in BRAND_SLD.items():
            if len(brand_sld) < 5 or abs(len(tok) - len(brand_sld)) > 2:
                continue
            d = Levenshtein.distance(tok, brand_sld)
            if best is None or d < best[2]:
                best = (label, f"{brand_sld}.com", d)
    return best


# ---------------------------------------------------------------------------
# Page-content features (Phase 1 supports the schema; the content script that
# feeds these arrives in Phase 2).
# ---------------------------------------------------------------------------
PAGE_FEATURE_NAMES = [
    "has_login_form",
    "has_password_field",
    "password_field_insecure",
    "form_action_cross_domain",
    "num_external_form_actions",
    "num_hidden_iframes",
    "num_password_fields",
]


def extract_page_features(page_signals: dict | None) -> dict:
    page_signals = page_signals or {}
    return {
        "has_login_form": int(bool(page_signals.get("has_login_form"))),
        "has_password_field": int(bool(page_signals.get("has_password_field"))),
        "password_field_insecure": int(bool(page_signals.get("password_field_insecure"))),
        "form_action_cross_domain": int(bool(page_signals.get("form_action_cross_domain"))),
        "num_external_form_actions": int(page_signals.get("num_external_form_actions", 0) or 0),
        "num_hidden_iframes": int(page_signals.get("num_hidden_iframes", 0) or 0),
        "num_password_fields": int(page_signals.get("num_password_fields", 0) or 0),
    }
