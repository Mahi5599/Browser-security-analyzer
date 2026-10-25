import hashlib
import json
import os

import pytest
from fastapi.testclient import TestClient

from app.services import forensic_log as fl
from app.services import tracker_store as ts

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "test-key")


@pytest.fixture
def client(tmp_path, monkeypatch):
    from app.main import app
    lg = fl.ForensicLog(str(tmp_path / "t.db"))
    monkeypatch.setattr(fl, "_default", lg)
    monkeypatch.setattr(fl, "_default_db_path", lambda: lg.db_path)
    monkeypatch.setattr(ts, "_default", ts.TrackerStore(lg.db_path))
    return TestClient(app)


def report(session_id="sess-0001", site="news.example.org", tracker_domains=3, **kw):
    r = {
        "session_id": session_id, "site": site, "total_requests": 80,
        "third_party_requests": 20, "third_party_domains": tracker_domains + 2,
        "tracker_domains": tracker_domains, "tracker_requests": tracker_domains * 3,
        "unknown_third_party_domains": 2,
        "trackers": [{"domain": "www.google-analytics.com", "network": "google-analytics.com",
                      "requests": 5, "list": "easyprivacy"}],
        "top_networks": [{"network": "google-analytics.com", "requests": 5, "domains": 1},
                         {"network": "doubleclick.net", "requests": 2, "domains": 1}],
        "pixels": 1, "beacons": 1, "third_party_cookies": 0,
        "canvas_fingerprinting": False, "canvas_events": 0, "canvas_scripts": [],
        "list_versions": {"easylist": "202610251011", "easyprivacy": "202610251018"},
    }
    r.update(kw)
    return r


def test_post_and_get_roundtrip(client):
    r = client.post("/tracker-report", json=report())
    assert r.status_code == 201, r.text
    assert r.json()["stored"] is True and r.json()["flags"] == []
    agg = client.get("/tracker-report").json()
    assert agg["totals"]["sessions"] == 1 and agg["totals"]["sites"] == 1
    assert agg["sites"][0]["site"] == "news.example.org"
    assert agg["sites"][0]["avg_tracker_domains"] == 3
    assert agg["top_networks"][0] == {"network": "google-analytics.com", "requests": 5,
                                      "sites": 1, "sessions": 1}


def test_repost_same_session_replaces_not_duplicates(client):
    client.post("/tracker-report", json=report(tracker_domains=2))
    client.post("/tracker-report", json=report(tracker_domains=4))
    agg = client.get("/tracker-report").json()
    assert agg["totals"]["sessions"] == 1
    assert agg["sites"][0]["max_tracker_domains"] == 4


def test_aggregation_across_sites_and_networks(client):
    client.post("/tracker-report", json=report("s-0000001", "a.example", 4))
    client.post("/tracker-report", json=report("s-0000002", "a.example", 8))
    client.post("/tracker-report", json=report("s-0000003", "b.example", 2,
                top_networks=[{"network": "doubleclick.net", "requests": 9, "domains": 1}]))
    agg = client.get("/tracker-report").json()
    by_site = {s["site"]: s for s in agg["sites"]}
    assert by_site["a.example"]["sessions"] == 2 and by_site["a.example"]["avg_tracker_domains"] == 6
    nets = {n["network"]: n for n in agg["top_networks"]}
    assert nets["google-analytics.com"] == {"network": "google-analytics.com", "requests": 10,
                                            "sites": 1, "sessions": 2}   # only site a, two sessions
    assert nets["doubleclick.net"] == {"network": "doubleclick.net", "requests": 2 + 2 + 9,
                                       "sites": 2, "sessions": 3}
    assert agg["top_networks"][0]["network"] == "doubleclick.net"  # sorted by requests

    only_b = client.get("/tracker-report", params={"site": "B.example"}).json()
    assert only_b["totals"]["sessions"] == 1


def test_fingerprinting_flags_aggregated(client):
    client.post("/tracker-report", json=report("s-0000001", "fp.example", canvas_fingerprinting=True,
                                               canvas_scripts=["cdn.fp.example"]))
    client.post("/tracker-report", json=report("s-0000002", "ok.example"))
    fp = client.get("/tracker-report").json()["fingerprinting"]
    assert fp["sessions"] == 1 and fp["sites"] == ["fp.example"]
    assert fp["top_scripts"] == [{"host": "cdn.fp.example", "sessions": 1}]


def test_since_filter(client):
    client.post("/tracker-report", json=report())
    assert client.get("/tracker-report", params={"since": "2999-01-01T00:00:00Z"}).json()["totals"].get("sessions", 0) == 0


def test_validation(client):
    bad = report()
    bad["tracker_domains"] = -1
    assert client.post("/tracker-report", json=bad).status_code == 422
    assert client.post("/tracker-report", json={"site": "x"}).status_code == 422


# ------------------------------------------------------- forensic-log coupling
def test_quiet_session_not_logged(client):
    r = client.post("/tracker-report", json=report(tracker_domains=ts.HIGH_TRACKER_DOMAINS - 1)).json()
    assert r["flags"] == [] and r["forensic_log_ids"] == []
    assert client.get("/forensic-log").json()["total"] == 0


def test_high_tracker_session_logged_once_with_evidence(client):
    n = ts.HIGH_TRACKER_DOMAINS
    first = client.post("/tracker-report", json=report(tracker_domains=n, case_id="c-7")).json()
    assert first["flags"] == ["high_tracker_count"] and len(first["forensic_log_ids"]) == 1
    # more updates of the same page load must not spam the log
    again = client.post("/tracker-report", json=report(tracker_domains=n + 5)).json()
    assert again["forensic_log_ids"] == []
    log = client.get("/forensic-log", params={"event_type": "tracker_session"}).json()
    assert log["total"] == 1
    e = log["items"][0]
    assert e["case_id"] == "c-7"
    d = e["details"]
    assert d["site"] == "news.example.org" and d["tracker_domains"] == n
    assert d["reasons"] == ["high_tracker_count"]
    assert d["list_versions"] == {"easylist": "202610251011", "easyprivacy": "202610251018"}
    assert d["top_networks"][0]["network"] == "google-analytics.com"
    assert client.get("/forensic-log/verify").json()["valid"] is True


def test_fingerprinting_logged_even_with_few_trackers_and_escalation_logged_separately(client):
    a = client.post("/tracker-report", json=report(tracker_domains=1, canvas_fingerprinting=True,
                                                   canvas_scripts=["fp.example"])).json()
    assert a["flags"] == ["canvas_fingerprinting"] and len(a["forensic_log_ids"]) == 1
    b = client.post("/tracker-report", json=report(tracker_domains=12, canvas_fingerprinting=True,
                                                   third_party_cookies=ts.EXCESSIVE_COOKIES)).json()
    assert len(b["forensic_log_ids"]) == 1
    assert client.get("/forensic-log").json()["items"][1]["details"]["reasons"] == [
        "high_tracker_count", "excessive_third_party_cookies"]
    assert client.get("/forensic-log").json()["total"] == 2


def test_forensic_failure_keeps_stats_and_retries_later(client, monkeypatch):
    monkeypatch.delenv("FORENSIC_HMAC_KEY")
    r = client.post("/tracker-report", json=report(tracker_domains=20))
    assert r.status_code == 201
    assert r.json()["forensic_logged"] is False and r.json()["forensic_log_ids"] == []
    assert client.get("/tracker-report").json()["totals"]["sessions"] == 1
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "test-key")
    retry = client.post("/tracker-report", json=report(tracker_domains=20)).json()
    assert len(retry["forensic_log_ids"]) == 1


# ----------------------------------------------------- bundled list snapshots
def test_blocklist_manifest_matches_files():
    d = os.path.join(ROOT, "data", "blocklists")
    manifest = json.load(open(os.path.join(d, "manifest.json")))
    assert {l["name"] for l in manifest["lists"]} == {"easylist", "easyprivacy"}
    for l in manifest["lists"]:
        data = open(os.path.join(d, l["name"] + ".txt"), "rb").read()
        assert hashlib.sha256(data).hexdigest() == l["sha256"]
        assert len(data) == l["bytes"]
        assert l["source"].startswith("https://easylist.to/") and l["downloaded"] and l["list_version"]
        assert l["rules_compiled"] > 10000
