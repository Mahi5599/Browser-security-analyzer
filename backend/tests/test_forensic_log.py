import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.services import forensic_log as fl
from app.services.forensic_log import GENESIS_HASH, ForensicLog


@pytest.fixture(autouse=True)
def hmac_key(monkeypatch):
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "test-key-not-a-secret")


@pytest.fixture
def log(tmp_path):
    return ForensicLog(str(tmp_path / "log.db"))


def _fill(log, n=5):
    return [log.append("phishing_url", "case-1", {"url": f"http://evil{i}.tk", "n": i})
            for i in range(n)]


def _sql(log, stmt, *args):
    c = sqlite3.connect(log.db_path)
    c.execute(stmt, args)
    c.commit()
    c.close()


# ------------------------------------------------------------ chain mechanics
def test_empty_log_is_valid(log):
    r = log.verify()
    assert r["valid"] and r["entries_checked"] == 0


def test_first_entry_uses_genesis_and_chain_links(log):
    rows = _fill(log, 3)
    assert rows[0]["prev_hash"] == GENESIS_HASH
    assert rows[1]["prev_hash"] == rows[0]["entry_hash"]
    assert rows[2]["prev_hash"] == rows[1]["entry_hash"]


def test_hash_is_deterministic_and_key_order_independent():
    a = fl.compute_entry_hash("p", "t", "phishing_url", "c", {"a": 1, "b": [1, 2]})
    b = fl.compute_entry_hash("p", "t", "phishing_url", "c", {"b": [1, 2], "a": 1})
    assert a == b
    assert fl.canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_valid_chain_verifies(log):
    _fill(log, 6)
    r = log.verify()
    assert r["valid"] is True
    assert r["entries_checked"] == 6
    assert r["first_broken_id"] is None


# ------------------------------------------------------------------ tampering
def test_modified_row_detected(log):
    rows = _fill(log, 5)
    target = rows[2]["id"]
    _sql(log, "UPDATE forensic_log SET details_json = ? WHERE id = ?",
         '{"n":2,"url":"http://innocent.example"}', target)
    r = log.verify()
    assert r["valid"] is False
    assert r["first_broken_id"] == target


def test_modified_row_with_recomputed_hashes_but_no_key_detected(log):
    """Attacker rewrites the row AND recomputes entry_hash + downstream chain,
    but cannot compute valid HMACs without the key."""
    rows = _fill(log, 3)
    t = rows[1]
    new_details = {"url": "http://innocent.example"}
    new_hash = fl.compute_entry_hash(t["prev_hash"], t["timestamp_utc"], t["event_type"],
                                     t["case_id"], new_details)
    _sql(log, "UPDATE forensic_log SET details_json=?, entry_hash=? WHERE id=?",
         fl.canonical_json(new_details), new_hash, t["id"])
    r = log.verify()
    assert r["valid"] is False and r["first_broken_id"] == t["id"]
    assert "HMAC" in r["reason"]


def test_deleted_row_detected(log):
    rows = _fill(log, 5)
    _sql(log, "DELETE FROM forensic_log WHERE id = ?", rows[2]["id"])
    r = log.verify()
    assert r["valid"] is False
    assert r["first_broken_id"] == rows[3]["id"]  # first entry whose prev_hash dangles


def test_reordered_rows_detected(log):
    rows = _fill(log, 4)
    a, b = rows[1]["id"], rows[2]["id"]
    # Swap the two rows' positions by swapping their primary keys.
    _sql(log, "UPDATE forensic_log SET id = -1 WHERE id = ?", a)
    _sql(log, "UPDATE forensic_log SET id = ? WHERE id = ?", a, b)
    _sql(log, "UPDATE forensic_log SET id = ? WHERE id = -1", b)
    r = log.verify()
    assert r["valid"] is False
    assert r["first_broken_id"] == a


def test_truncated_tail_detected(log):
    rows = _fill(log, 4)
    _sql(log, "DELETE FROM forensic_log WHERE id = ?", rows[-1]["id"])
    r = log.verify()
    assert r["valid"] is False
    assert "truncated" in r["reason"]


def test_wrong_key_fails_verification(log, monkeypatch):
    _fill(log, 2)
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "a-different-key")
    assert log.verify()["valid"] is False


def test_pinned_head_detects_rollback(log):
    _fill(log, 2)
    old_head = log.verify()["head_hash"]
    _fill(log, 1)
    assert log.verify(expected_head=old_head)["valid"] is False


def test_append_requires_key(log, monkeypatch):
    monkeypatch.delenv("FORENSIC_HMAC_KEY")
    with pytest.raises(fl.ForensicKeyMissing):
        log.append("phishing_url", "c", {})


def test_rejects_bad_event_type(log):
    with pytest.raises(ValueError):
        log.append("nonsense", "c", {})


# ------------------------------------------------------------------------ API
@pytest.fixture
def client(tmp_path, monkeypatch):
    from app.main import app
    lg = ForensicLog(str(tmp_path / "api.db"))
    monkeypatch.setattr(fl, "_default", lg)
    monkeypatch.setattr(fl, "_default_db_path", lambda: lg.db_path)
    return TestClient(app), lg


def test_api_append_list_filter_verify(client):
    c, _ = client
    for t in ("phishing_url", "malicious_file", "phishing_url"):
        r = c.post("/forensic-log", json={"event_type": t, "case_id": "k", "details": {"x": 1}})
        assert r.status_code == 201, r.text
    assert c.post("/forensic-log", json={"event_type": "bogus", "case_id": "k",
                                         "details": {}}).status_code == 422

    body = c.get("/forensic-log").json()
    assert body["total"] == 3
    only = c.get("/forensic-log", params={"event_type": "malicious_file"}).json()
    assert only["total"] == 1 and only["items"][0]["details"] == {"x": 1}
    page = c.get("/forensic-log", params={"limit": 2, "offset": 2}).json()
    assert len(page["items"]) == 1 and page["total"] == 3
    future = c.get("/forensic-log", params={"since": "2999-01-01T00:00:00Z"}).json()
    assert future["total"] == 0
    assert c.get("/forensic-log", params={"since": "garbage"}).status_code == 422

    v = c.get("/forensic-log/verify").json()
    assert v["valid"] is True and v["entries_checked"] == 3


def test_api_verify_reports_first_broken(client):
    c, lg = client
    ids = [c.post("/forensic-log", json={"event_type": "tracker_session", "case_id": "k",
                                         "details": {"i": i}}).json()["id"] for i in range(3)]
    _sql(lg, "UPDATE forensic_log SET case_id='other' WHERE id=?", ids[1])
    v = c.get("/forensic-log/verify").json()
    assert v["valid"] is False and v["first_broken_id"] == ids[1]


# ------------------------------------------------- /analyze-url auto-logging
@pytest.fixture
def model_ready():
    from app.services.phishing_predictor import MODEL_PATH
    import os
    if not os.path.exists(MODEL_PATH):
        pytest.skip("phishing model not trained (python -m ml.train_model)")


def test_analyze_url_logs_phishing_with_evidence(client, model_ready):
    c, _ = client
    r = c.post("/analyze-url", json={
        "url": "http://185.234.219.12/paypal/webscr?cmd=_login&verify=1",
        "live_lookups": False, "case_id": "case-42",
        "page_signals": {"has_login_form": True, "password_field_insecure": True},
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] in ("suspicious", "phishing")
    assert body["forensic_log_id"] is not None

    entry = c.get("/forensic-log").json()["items"][0]
    assert entry["id"] == body["forensic_log_id"]
    assert entry["case_id"] == "case-42" and entry["event_type"] == "phishing_url"
    d = entry["details"]
    assert d["url"] == body["url"] and d["verdict"] == body["verdict"]
    assert d["risk_score"] == body["risk_score"] and d["reasons"] == body["reasons"]
    assert d["dom_signals"]["password_field_insecure"] is True
    assert d["tranco_snapshot_date"] and d["model_version"]["model_sha256"]
    assert c.get("/forensic-log/verify").json()["valid"] is True


def test_analyze_url_does_not_log_benign(client, model_ready):
    c, _ = client
    body = c.post("/analyze-url", json={"url": "https://www.google.com/",
                                        "live_lookups": False}).json()
    assert body["verdict"] == "benign" and body["forensic_log_id"] is None
    assert c.get("/forensic-log").json()["total"] == 0


def test_analyze_url_survives_missing_key(client, model_ready, monkeypatch):
    c, _ = client
    monkeypatch.delenv("FORENSIC_HMAC_KEY")
    r = c.post("/analyze-url", json={"url": "http://185.234.219.12/paypal/webscr?cmd=_login",
                                     "live_lookups": False})
    assert r.status_code == 200 and r.json()["forensic_log_id"] is None
