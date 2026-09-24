from app.services.phishing_features import (
    URL_FEATURE_NAMES,
    extract_url_features,
    nearest_brand,
)


def _f(url):
    return extract_url_features(url)


def test_feature_vector_is_complete_and_ordered():
    feats = _f("https://example.com/path?a=1")
    assert list(feats.keys()) == URL_FEATURE_NAMES
    assert all(isinstance(v, (int, float)) for v in feats.values())


def test_at_symbol_and_ip_host():
    f = _f("http://paypal.com@203.0.113.9/login")
    assert f["has_at_symbol"] == 1
    assert f["is_ip_host"] == 1
    assert f["has_https"] == 0


def test_https_and_clean_domain():
    f = _f("https://www.wikipedia.org/wiki/Security")
    assert f["has_https"] == 1
    assert f["is_ip_host"] == 0
    assert f["typosquat_flag"] == 0


def test_punycode_flag():
    assert _f("http://xn--pypal-4ve.com/login")["has_punycode"] == 1


def test_typosquat_digit_homoglyph():
    f = _f("http://paypa1.com/webscr")
    assert f["typosquat_flag"] == 1
    assert 0 <= f["brand_min_edit_distance"] <= 2


def test_typosquat_hyphen_prefix():
    assert _f("http://secure-paypal-login.tk/verify")["typosquat_flag"] == 1


def test_brand_cctld_is_not_typosquat():
    assert _f("https://www.amazon.co.uk/gp/homepage.html")["typosquat_flag"] == 0
    assert _f("https://www.google.de/search?q=x")["typosquat_flag"] == 0


def test_suspicious_tld_and_keywords():
    f = _f("http://account-verify-update.xyz/confirm/login")
    assert f["suspicious_tld"] == 1
    assert f["num_suspicious_words"] >= 2


def test_nearest_brand_tokenized():
    label, domain, dist = nearest_brand("secure-paypal-login")
    assert domain == "paypal.com"
    assert dist == 0
