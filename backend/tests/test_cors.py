import json
import os

from fastapi.testclient import TestClient

from app.main import PINNED_EXTENSION_ID, allowed_origins, app

client = TestClient(app)
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def preflight(origin, method="POST", path="/analyze-url"):
    return client.options(path, headers={
        "Origin": origin, "Access-Control-Request-Method": method,
        "Access-Control-Request-Headers": "content-type"})


def test_dashboard_and_extension_origins_allowed():
    for origin in ("http://localhost:5173", "http://127.0.0.1:5173",
                   f"chrome-extension://{PINNED_EXTENSION_ID}"):
        r = preflight(origin)
        assert r.status_code == 200, origin
        assert r.headers["access-control-allow-origin"] == origin


def test_other_origins_rejected():
    for origin in ("https://evil.example", "http://localhost:3000", "http://localhost:5173.evil.com",
                   "chrome-extension://" + "a" * 32, "null"):
        r = preflight(origin)
        assert r.status_code == 400, origin
        assert "access-control-allow-origin" not in r.headers


def test_no_wildcard_and_foreign_simple_get_gets_no_cors_header():
    assert "*" not in allowed_origins()
    r = client.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers
    ok = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert ok.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_only_get_and_post_allowed():
    assert preflight("http://localhost:5173", "DELETE", "/forensic-log").status_code == 400


def test_env_overrides(monkeypatch):
    monkeypatch.setenv("BSA_DASHBOARD_ORIGINS", "https://dash.example/ ")
    monkeypatch.setenv("BSA_EXTENSION_IDS", "x" * 32 + ", " + "y" * 32)
    assert allowed_origins() == ["https://dash.example", "chrome-extension://" + "x" * 32,
                                 "chrome-extension://" + "y" * 32]


def test_pinned_id_matches_manifest_key():
    """The CORS allow-list entry must be the ID Chrome derives from manifest.json's key."""
    import base64
    import hashlib
    key = json.load(open(os.path.join(ROOT, "extension", "manifest.json")))["key"]
    digest = hashlib.sha256(base64.b64decode(key)).hexdigest()[:32]
    derived = "".join(chr(ord("a") + int(c, 16)) for c in digest)
    assert derived == PINNED_EXTENSION_ID
