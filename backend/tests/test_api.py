import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def _analyze(url):
    r = client.post("/analyze-url", json={"url": url, "live_lookups": False})
    assert r.status_code == 200, r.text
    return r.json()


def test_benign_top_domain():
    body = _analyze("https://www.google.com/search?q=phishing")
    assert body["verdict"] == "benign"
    assert body["risk_score"] < 0.35


def test_obvious_phishing_ip_brand_path():
    body = _analyze("http://185.234.219.12/paypal/webscr?cmd=_login&verify=1")
    assert body["verdict"] == "phishing"
    assert body["risk_score"] >= 0.65
    assert any("IP address" in r for r in body["reasons"])


def test_typosquat_phishing():
    body = _analyze("http://paypaI-secure-login.tk/verify/account")
    assert body["verdict"] in {"phishing", "suspicious"}
    assert body["risk_score"] >= 0.5


def test_response_schema():
    body = _analyze("https://example.com")
    assert set(body) >= {"url", "risk_score", "verdict", "reasons", "model_score", "enrichment"}
    assert 0.0 <= body["risk_score"] <= 1.0


def test_page_signals_bump_score():
    base = client.post("/analyze-url", json={
        "url": "https://some-random-site-xyz123.com/login", "live_lookups": False,
    }).json()
    withsig = client.post("/analyze-url", json={
        "url": "https://some-random-site-xyz123.com/login", "live_lookups": False,
        "page_signals": {"password_field_insecure": True, "form_action_cross_domain": True},
    }).json()
    assert withsig["risk_score"] >= base["risk_score"]
