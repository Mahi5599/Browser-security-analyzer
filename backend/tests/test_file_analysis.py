import hashlib
import json
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from app.services import file_analyzer, file_heuristics
from app.services import forensic_log as fl
from app.services import virustotal_client as vtc
from app.services.virustotal_client import RateLimiter, VirusTotalClient

# EICAR is built in memory only; it is never written to disk by these tests.
EICAR = file_analyzer.EICAR_STRING.encode("ascii")
EICAR_SHA = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
SHA_A = "a" * 64


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "test-key")


def test_eicar_constant_is_the_published_hash():
    assert hashlib.sha256(EICAR).hexdigest() == EICAR_SHA == file_analyzer.EICAR_SHA256
    assert len(EICAR) == 68  # EICAR spec: 68 bytes


# ------------------------------------------------------------------ heuristics
def _ev(name, mime=None):
    return file_heuristics.evaluate(name, mime)


def test_double_extension_flagged():
    f = _ev("invoice.pdf.exe")
    assert any("Double extension" in r for _, r in f)
    assert sum(w for w, _ in f) > 0.8


def test_plain_pdf_clean():
    assert _ev("report.pdf", "application/pdf") == []


@pytest.mark.parametrize("ext", ["exe", "scr", "js", "vbs", "bat", "msi", "apk", "jar", "iso"])
def test_each_required_risky_extension(ext):
    assert any("Risky file type" in r for _, r in _ev(f"setup.{ext}"))


def test_executable_masquerading_as_document_by_mime():
    f = _ev("resume.pdf", "application/x-msdownload")
    assert any("masquerading" in r for _, r in f)


def test_mime_extension_mismatch():
    f = _ev("photo.png", "application/pdf")
    assert any("does not match" in r for _, r in f)


def test_generic_octet_stream_is_not_a_mismatch():
    assert _ev("photo.png", "application/octet-stream") == []


def test_rtl_override_flagged():
    assert any("right-to-left" in r for _, r in _ev("invoice\u202efdp.exe"))


def test_path_stripped_from_filename():
    assert file_heuristics.basename("C:\\Users\\bob\\Downloads\\a.exe") == "a.exe"
    assert file_heuristics.basename("/home/bob/a.exe") == "a.exe"


# --------------------------------------------------------------- rate limiter
def test_rate_limiter_allows_four_then_blocks_then_recovers():
    t = [0.0]
    lim = RateLimiter(4, 60, clock=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s))
    assert all(lim.acquire(0) for _ in range(4))
    assert lim.acquire(0) is False               # 5th within the minute, no waiting allowed
    assert lim.acquire(100) is True              # allowed to wait: sleeps until a slot frees
    assert t[0] >= 60


def test_rate_limiter_gives_up_when_wait_too_long():
    t = [0.0]
    lim = RateLimiter(1, 60, clock=lambda: t[0], sleep=lambda s: None)
    assert lim.acquire(0)
    assert lim.acquire(5) is False


# ------------------------------------------------------------- VirusTotal client
def _client(tmp_path, handler, **kw):
    calls = []

    def wrapped(req):
        calls.append(req)
        return handler(req)

    http = httpx.Client(transport=httpx.MockTransport(wrapped))
    kw.setdefault("limiter", RateLimiter(4, 60, sleep=lambda s: None))
    kw.setdefault("max_wait", 0)
    return VirusTotalClient(str(tmp_path / "vt.db"), api_key="k", http=http, **kw), calls


def _vt_body(mal=0, sus=0, harmless=60, label=None):
    attrs = {"last_analysis_stats": {"malicious": mal, "suspicious": sus,
                                     "harmless": harmless, "undetected": 5}}
    if label:
        attrs["popular_threat_classification"] = {"suggested_threat_label": label}
    return {"data": {"attributes": attrs}}


def test_vt_malicious_parsed_and_key_sent_in_header(tmp_path):
    c, calls = _client(tmp_path, lambda r: httpx.Response(200, json=_vt_body(mal=40, label="trojan.x")))
    res = c.lookup(SHA_A)
    assert res["status"] == "malicious" and res["malicious"] == 40
    assert calls[0].headers["x-apikey"] == "k"
    assert calls[0].method == "GET" and calls[0].url.path.endswith(f"/files/{SHA_A}")


def test_vt_unknown_hash_is_unknown_and_never_uploads(tmp_path):
    c, calls = _client(tmp_path, lambda r: httpx.Response(404, json={"error": {}}))
    res = c.lookup(SHA_A)
    assert res["status"] == "unknown"
    assert all(r.method == "GET" and "/files/" in r.url.path and "upload" not in r.url.path
               for r in calls)


def test_vt_results_are_cached_in_sqlite(tmp_path):
    c, calls = _client(tmp_path, lambda r: httpx.Response(200, json=_vt_body()))
    c.lookup(SHA_A)
    second = c.lookup(SHA_A)
    assert len(calls) == 1 and second["cached"] is True
    # A fresh client object on the same DB file still hits the cache.
    c2 = VirusTotalClient(c.db_path, api_key="k", http=c._http, limiter=c.limiter, max_wait=0)
    assert c2.lookup(SHA_A)["cached"] is True and len(calls) == 1


def test_vt_cache_expires(tmp_path):
    now = [1000.0]
    c, calls = _client(tmp_path, lambda r: httpx.Response(404), clock=lambda: now[0])
    c.lookup(SHA_A)
    now[0] += vtc.UNKNOWN_TTL + 1
    c.lookup(SHA_A)
    assert len(calls) == 2


def test_vt_respects_four_per_minute(tmp_path):
    c, calls = _client(tmp_path, lambda r: httpx.Response(200, json=_vt_body()))
    results = [c.lookup(f"{i:064x}")["status"] for i in range(6)]
    assert results[:4] == ["clean"] * 4
    assert results[4:] == ["rate_limited"] * 2
    assert len(calls) == 4


def test_vt_429_backs_off(tmp_path):
    c, calls = _client(tmp_path, lambda r: httpx.Response(429))
    assert c.lookup(SHA_A)["status"] == "rate_limited"
    assert c.lookup("b" * 64)["status"] == "rate_limited"
    assert len(calls) == 1  # second lookup never left the building


def test_vt_without_key_is_unavailable_and_makes_no_request(tmp_path):
    http = httpx.Client(transport=httpx.MockTransport(lambda r: pytest.fail("request made")))
    c = VirusTotalClient(str(tmp_path / "v.db"), api_key="", http=http)
    assert c.lookup(SHA_A)["status"] == "unavailable"


def test_vt_network_error_is_reported_not_raised(tmp_path):
    def boom(req):
        raise httpx.ConnectError("down")
    c, _ = _client(tmp_path, boom)
    assert c.lookup(SHA_A)["status"] == "error"


# -------------------------------------------------------------------- analyzer
def _vt_stub(tmp_path, status_code=404, body=None):
    return _client(tmp_path, lambda r: httpx.Response(status_code, json=body or {}))[0]


def test_eicar_hash_is_malicious_without_calling_vt(tmp_path):
    vt = VirusTotalClient(str(tmp_path / "v.db"), api_key="k",
                          http=httpx.Client(transport=httpx.MockTransport(
                              lambda r: pytest.fail("VT should not be called"))))
    res = file_analyzer.analyze_file("eicar.com", EICAR_SHA, 68, None, "application/octet-stream", vt)
    assert res["verdict"] == "malicious" and res["risk_score"] >= 0.65
    assert any("EICAR" in r for r in res["reasons"])


def test_unknown_hash_benign_file_stays_benign(tmp_path):
    res = file_analyzer.analyze_file("notes.txt", SHA_A, 10, None, "text/plain",
                                     _vt_stub(tmp_path))
    assert res["verdict"] == "benign" and res["virustotal"]["status"] == "unknown"


def test_unknown_hash_double_extension_is_malicious_or_suspicious(tmp_path):
    res = file_analyzer.analyze_file("invoice.pdf.exe", SHA_A, 10, None, None, _vt_stub(tmp_path))
    assert res["verdict"] in ("suspicious", "malicious")
    assert res["virustotal"]["status"] == "unknown"


def test_vt_detections_drive_malicious(tmp_path):
    vt = _vt_stub(tmp_path, 200, _vt_body(mal=30))
    res = file_analyzer.analyze_file("setup.exe", SHA_A, 10, None, None, vt)
    assert res["verdict"] == "malicious"


def test_known_clean_hash_caps_heuristic_noise(tmp_path):
    vt = _vt_stub(tmp_path, 200, _vt_body())
    res = file_analyzer.analyze_file("setup.exe", SHA_A, 10, None, None, vt)
    assert res["verdict"] == "benign" and res["risk_score"] <= 0.30


def test_metadata_only_when_no_hash():
    res = file_analyzer.analyze_file("invoice.pdf.exe", None, None, None, None)
    assert res["analysis_mode"] == "metadata_only"
    assert res["virustotal"]["status"] == "not_checked"
    assert res["verdict"] == "malicious"


# ------------------------------------------------------------------------- API
@pytest.fixture
def client(tmp_path, monkeypatch):
    from app.main import app
    lg = fl.ForensicLog(str(tmp_path / "api.db"))
    monkeypatch.setattr(fl, "_default", lg)
    monkeypatch.setattr(fl, "_default_db_path", lambda: lg.db_path)
    vt = VirusTotalClient(lg.db_path, api_key="")  # no key: heuristics + local EICAR only
    monkeypatch.setattr(vtc, "_default", vt)
    return TestClient(app), lg


def test_api_eicar_is_logged_to_forensic_chain(client):
    c, _ = client
    r = c.post("/analyze-file", json={
        "filename": "eicar.com", "sha256": EICAR_SHA, "size_bytes": 68,
        "source_url": "https://www.eicar.org/download/eicar.com", "mime_type": "application/octet-stream",
        "case_id": "case-9"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "malicious" and body["forensic_log_id"]
    entry = c.get("/forensic-log").json()["items"][0]
    assert entry["event_type"] == "malicious_file" and entry["case_id"] == "case-9"
    assert entry["details"]["sha256"] == EICAR_SHA and entry["details"]["filename"] == "eicar.com"
    assert c.get("/forensic-log/verify").json()["valid"] is True


def test_api_benign_not_logged(client):
    c, _ = client
    body = c.post("/analyze-file", json={"filename": "notes.txt", "sha256": SHA_A,
                                         "mime_type": "text/plain"}).json()
    assert body["verdict"] == "benign" and body["forensic_log_id"] is None
    assert body["virustotal"]["status"] == "unavailable"
    assert c.get("/forensic-log").json()["total"] == 0


def test_api_validation(client):
    c, _ = client
    assert c.post("/analyze-file", json={"filename": "a.txt", "sha256": "xyz"}).status_code == 422
    assert c.post("/analyze-file", json={"sha256": SHA_A}).status_code == 422


def test_api_metadata_only_request(client):
    c, _ = client
    body = c.post("/analyze-file", json={"filename": "invoice.pdf.exe", "size_bytes": 9000}).json()
    assert body["analysis_mode"] == "metadata_only" and body["verdict"] == "malicious"


def test_api_scores_source_url_with_phishing_model(client):
    from app.services.phishing_predictor import MODEL_PATH
    if not os.path.exists(MODEL_PATH):
        pytest.skip("model not trained")
    c, _ = client
    body = c.post("/analyze-file", json={
        "filename": "update.exe", "sha256": SHA_A,
        "source_url": "http://185.234.219.12/paypal/webscr?cmd=_login&verify=1"}).json()
    assert body["source_url_verdict"] in ("suspicious", "phishing")
    assert any("Download source" in r for r in body["reasons"])


def test_strongest_reason_is_listed_first(tmp_path):
    vt = VirusTotalClient(str(tmp_path / "v.db"), api_key="")
    res = file_analyzer.analyze_file("eicar.com", EICAR_SHA, 68, None, None, vt)
    assert "EICAR" in res["reasons"][0]
