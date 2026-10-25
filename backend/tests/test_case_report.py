import hashlib
import io
import json
import os
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.services import case_report as cr
from app.services import forensic_log as fl
from app.services.forensic_log import ForensicLog

CASE, EXAMINER = "CASE-2026-001", "Dr. A. Examiner"


@pytest.fixture(autouse=True)
def key(monkeypatch):
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "test-key")


@pytest.fixture
def env(tmp_path, monkeypatch):
    from app.main import app
    lg = ForensicLog(str(tmp_path / "r.db"))
    monkeypatch.setattr(fl, "_default", lg)
    monkeypatch.setattr(fl, "_default_db_path", lambda: lg.db_path)
    return TestClient(app), lg


def populate(lg, case=CASE):
    lg.append("phishing_url", case, {"url": "http://paypaI-secure-login.tk/verify", "verdict": "phishing",
                                     "risk_score": 0.93, "reasons": ["Looks like a typosquat of paypal.com"]})
    lg.append("phishing_url", case, {"url": "http://amaz0n-account.top/login", "verdict": "suspicious",
                                     "risk_score": 0.58, "reasons": ["Abused TLD"]})
    lg.append("malicious_file", case, {"filename": "eicar.com", "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                                       "verdict": "malicious", "risk_score": 0.97, "virustotal": {"status": "malicious"},
                                       "reasons": ["Matches the EICAR anti-virus test file"]})
    lg.append("tracker_session", case, {"site": "news.example", "reasons": ["high_tracker_count"],
                                        "tracker_domains": 12, "third_party_cookies": 14, "canvas_fingerprinting": True})
    lg.append("phishing_url", "OTHER-CASE", {"url": "http://other.example/", "verdict": "phishing", "risk_score": 0.9})


def report(client, fmt="pdf", case=CASE, examiner=EXAMINER):
    return client.get("/forensic-log/report", params={"case_id": case, "examiner": examiner, "format": fmt})


def text_of(content: bytes) -> str:
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(content)).pages)


def flat(s: str) -> str:
    return re.sub(r"\s+", "", s)


def sql(lg, stmt, *args):
    c = sqlite3.connect(lg.db_path)
    c.execute(stmt, args)
    c.commit()
    c.close()


# ------------------------------------------------------------ populated log
def test_populated_report_contents(env):
    c, lg = env
    populate(lg)
    r = report(c)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF")
    assert "attachment" in r.headers["content-disposition"] and ".pdf" in r.headers["content-disposition"]
    t = text_of(r.content)
    f = flat(t)
    for must in ["Forensic Case Report", CASE, EXAMINER, "Generated (UTC)", "Browser Security Analyzer v",
                 "Phishing model", "easylist", "easyprivacy", "Tranco", "INTEGRITY VERIFIED",
                 "All 5 log entries", "Executive summary", "phishing_url", "malicious_file", "tracker_session",
                 "phishing: 1", "suspicious: 1", "malicious: 1", "Chain of custody", "Entries checked",
                 "paypaI-secure-login.tk", "eicar.com", "275a021bbfb6489e", "news.example", "Limitations",
                 "symmetric", "FORENSIC_HMAC_KEY", "forge entries"]:
        assert flat(must) in f, must
    assert "INTEGRITYFAILURE" not in f
    assert "other.example" not in f            # other case's evidence is not in this report
    assert "of5inthewholelog" in f


def test_footer_hash_matches_json_and_header_and_is_stable(env):
    c, lg = env
    populate(lg)
    pdf = report(c)
    js = report(c, "json")
    assert js.headers["content-type"] == "application/json"
    sha = hashlib.sha256(js.content).hexdigest()
    assert pdf.headers["x-report-data-sha256"] == js.headers["x-report-data-sha256"] == sha
    # printed in the footer of every page
    reader = PdfReader(io.BytesIO(pdf.content))
    assert len(reader.pages) >= 1
    for page in reader.pages:
        assert sha in flat(page.extract_text())
    # same log + same parameters -> same hash (generation time is not part of the hashed data)
    assert report(c, "json").headers["x-report-data-sha256"] == sha
    # a different examiner is part of the report data, so it changes the hash
    assert report(c, "json", examiner="Someone Else").headers["x-report-data-sha256"] != sha
    data = json.loads(js.content)
    assert data["report"]["case_id"] == CASE and data["log"] == {"total_entries": 5, "case_entries": 4}
    assert [e["id"] for e in data["entries"]] == [1, 2, 3, 4]
    assert data["summary"]["by_type"]["phishing_url"] == 2
    assert data["summary"]["by_verdict"]["phishing_url"] == {"phishing": 1, "suspicious": 1}
    assert data["integrity"]["valid"] is True and data["integrity"]["entries_checked"] == 5
    assert "generated" not in json.dumps(data).lower()


def test_json_entries_match_forensic_log_entries(env):
    """Entries in the report data are identical to what /forensic-log (and Export evidence) return."""
    c, lg = env
    populate(lg)
    data = json.loads(report(c, "json").content)
    listed = {e["id"]: e for e in c.get("/forensic-log?limit=500").json()["items"]}
    for e in data["entries"]:
        assert e == listed[e["id"]]


# ---------------------------------------------------------------- empty log
def test_empty_log_report_says_so(env):
    c, lg = env
    r = report(c)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    f = flat(text_of(r.content))
    assert "LOGISEMPTY" in f
    assert "forensiclogisempty" in f.lower()
    assert "Noentriesforthiscase" in f
    assert "INTEGRITYFAILURE" not in f and "INTEGRITYVERIFIED" not in f
    data = json.loads(report(c, "json").content)
    assert data["log"] == {"total_entries": 0, "case_entries": 0} and data["entries"] == []


def test_unknown_case_in_nonempty_log(env):
    c, lg = env
    populate(lg)
    f = flat(text_of(report(c, case="NO-SUCH-CASE").content))
    assert "nonearefiledundercase" in f.lower()
    assert "INTEGRITYVERIFIED" in f      # the chain itself is fine


# ------------------------------------------------------------- tampered log
def _tamper_modify(lg):
    sql(lg, "UPDATE forensic_log SET details_json = ? WHERE id = 2", '{"verdict":"benign","url":"http://x"}')
    return 2


def _tamper_delete(lg):
    sql(lg, "DELETE FROM forensic_log WHERE id = 2")
    return 3


def _tamper_truncate(lg):
    sql(lg, "DELETE FROM forensic_log WHERE id = 5")
    return 5


def _tamper_garbage_json(lg):
    sql(lg, "UPDATE forensic_log SET details_json = ? WHERE id = 3", "{not json at all <img src=x>")
    return 3


def _tamper_nonobject_json(lg):
    sql(lg, "UPDATE forensic_log SET details_json = ? WHERE id = 1", '"just a string"')
    return 1


def _tamper_forged_hash_without_key(lg):
    row = sqlite3.connect(lg.db_path).execute("SELECT prev_hash, timestamp_utc, event_type, case_id FROM forensic_log WHERE id=2").fetchone()
    new = {"verdict": "benign"}
    h = fl.compute_entry_hash(row[0], row[1], row[2], row[3], new)
    sql(lg, "UPDATE forensic_log SET details_json=?, entry_hash=? WHERE id=2", fl.canonical_json(new), h)
    return 2


@pytest.mark.parametrize("tamper", [_tamper_modify, _tamper_delete, _tamper_truncate, _tamper_garbage_json,
                                    _tamper_nonobject_json, _tamper_forged_hash_without_key])
def test_tampered_log_shows_red_failure_banner_never_green(env, tamper):
    c, lg = env
    populate(lg)
    broken = tamper(lg)
    r = report(c)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")      # still renders, does not crash
    reader = PdfReader(io.BytesIO(r.content))
    f = flat("\n".join(p.extract_text() for p in reader.pages))
    assert "INTEGRITYFAILURE" in f
    assert "INTEGRITYVERIFIED" not in f
    assert "Donotrelyonthisevidence" in f
    assert f"Firstbrokenentry:#{broken}" in f
    assert "INVALID" in f
    for page in reader.pages:                                          # red warning in every page footer
        assert "do not rely on this report" in " ".join(page.extract_text().split())
    integ = json.loads(report(c, "json").content)["integrity"]
    assert integ["valid"] is False and integ["first_broken_id"] == broken


def test_banner_for_invalid_is_never_green_or_verified():
    for first, n in [(3, 5), (None, 5), (None, 0), (7, 0), (1, 1)]:
        b = cr.banner_for({"valid": False, "entries_checked": n, "first_broken_id": first, "reason": "x", "head_hash": None}, n)
        assert b["status"] == "failure" and b["color"] == cr.RED and "FAILURE" in b["text"]
        assert b["color"] != cr.GREEN
    ok = cr.banner_for({"valid": True, "entries_checked": 4, "first_broken_id": None, "reason": None, "head_hash": "a"}, 4)
    assert ok["status"] == "verified" and ok["color"] == cr.GREEN
    empty = cr.banner_for({"valid": True, "entries_checked": 0, "first_broken_id": None, "reason": None, "head_hash": None}, 0)
    assert empty["status"] == "empty" and empty["color"] not in (cr.GREEN, cr.RED)


def test_wrong_key_is_reported_as_failure_not_valid(env, monkeypatch):
    c, lg = env
    populate(lg)
    monkeypatch.setenv("FORENSIC_HMAC_KEY", "a-different-key")
    f = flat(text_of(report(c).content))
    assert "INTEGRITYFAILURE" in f and "INTEGRITYVERIFIED" not in f


def test_missing_key_refuses_to_produce_a_report(env, monkeypatch):
    c, lg = env
    populate(lg)
    monkeypatch.delenv("FORENSIC_HMAC_KEY")
    r = report(c)
    assert r.status_code == 503
    assert not r.content.startswith(b"%PDF")
    assert report(c, "json").status_code == 503


# ----------------------------------------------------------------- read-only
def _db_state(lg):
    d = os.path.dirname(lg.db_path)
    with open(lg.db_path, "rb") as fh:
        raw = hashlib.sha256(fh.read()).hexdigest()
    c = sqlite3.connect(lg.db_path)
    rows = c.execute("SELECT * FROM forensic_log ORDER BY id").fetchall()
    head = c.execute("SELECT * FROM chain_head").fetchall()
    c.close()
    return raw, rows, head, sorted(os.listdir(d))


def test_report_endpoint_does_not_modify_the_log(env):
    c, lg = env
    populate(lg)
    before = _db_state(lg)
    for fmt in ("pdf", "json", "pdf"):
        assert report(c, fmt).status_code == 200
    assert report(c, case="NO-SUCH-CASE").status_code == 200
    assert report(c, "pdf", case="x", examiner="y").status_code == 200
    after = _db_state(lg)
    assert after == before                       # byte-identical DB file, same rows, same head, no new files
    assert c.get("/forensic-log").json()["total"] == 5
    assert c.get("/forensic-log/verify").json()["valid"] is True


def test_report_on_tampered_log_does_not_modify_it_either(env):
    c, lg = env
    populate(lg)
    _tamper_modify(lg)
    before = _db_state(lg)
    assert report(c).status_code == 200
    assert _db_state(lg) == before


def test_report_snapshot_is_consistent_with_verify(env):
    c, lg = env
    populate(lg)
    entries, verification = lg.report_snapshot()
    assert verification == lg.verify()
    assert [e["id"] for e in entries] == [1, 2, 3, 4, 5]


# ------------------------------------------------------- hostile / odd input
def test_markup_in_log_data_is_rendered_literally(env):
    c, lg = env
    evil = '<img src="http://127.0.0.1:9/beacon.png"/> <b>bold</b> <para>x</para> & </font>'
    lg.append("phishing_url", CASE, {"url": f"http://x.example/{evil}", "verdict": "phishing", "risk_score": 1.0,
                                     "reasons": [evil]})
    lg.append("malicious_file", CASE, {"filename": 'a<font color="red">.exe', "verdict": "malicious", "risk_score": 1})
    r = report(c, examiner=evil)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    f = flat(text_of(r.content))
    assert flat('<img src="http://127.0.0.1:9/beacon.png"/>') in f      # shown as text, not interpreted
    assert flat("<b>bold</b>") in f


def test_non_ascii_is_shown_as_visible_escapes(env):
    c, lg = env
    lg.append("phishing_url", CASE, {"url": "http://аpple.com/‮", "verdict": "phishing", "risk_score": 1.0})
    f = flat(text_of(report(c, examiner="Zoë 日本").content))
    assert "\\u0430pple.com" in f            # Cyrillic 'a' is visible, not a look-alike glyph
    assert "\\u202e" in f                    # the RTL override is visible too
    assert "Zo\\xeb" in f


def test_filename_is_sanitised(env):
    c, lg = env
    r = report(c, case='../../etc/passwd"; evil\r\nX: y')
    disp = r.headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="case-report_[A-Za-z0-9._-]+_\d{8}T\d{6}Z\.pdf"', disp), disp


def test_parameter_validation(env):
    c, lg = env
    assert c.get("/forensic-log/report").status_code == 422
    assert c.get("/forensic-log/report", params={"case_id": CASE}).status_code == 422
    assert c.get("/forensic-log/report", params={"examiner": EXAMINER}).status_code == 422
    assert c.get("/forensic-log/report", params={"case_id": "  ", "examiner": EXAMINER}).status_code == 422
    assert c.get("/forensic-log/report", params={"case_id": CASE, "examiner": "   "}).status_code == 422
    assert report(c, "docx").status_code == 422
    assert report(c, case="x" * 129).status_code == 422


def test_table_truncation_notice(env, monkeypatch):
    c, lg = env
    populate(lg)
    monkeypatch.setattr(cr, "MAX_TABLE_ROWS", 2)
    f = flat(text_of(report(c).content))
    assert "Tabletruncated:showingthefirst2of4" in f
    assert len(json.loads(report(c, "json").content)["entries"]) == 4


def test_many_entries_paginate(env):
    c, lg = env
    for i in range(120):
        lg.append("phishing_url", CASE, {"url": f"http://evil{i}.tk/" + "a" * 150, "verdict": "phishing", "risk_score": 0.9})
    r = report(c)
    reader = PdfReader(io.BytesIO(r.content))
    assert r.status_code == 200 and len(reader.pages) > 2
    assert "evil119.tk" in flat("\n".join(p.extract_text() for p in reader.pages))


def test_cors_exposes_the_hash_header_to_the_dashboard(env):
    c, lg = env
    populate(lg)
    r = c.get("/forensic-log/report", params={"case_id": CASE, "examiner": EXAMINER},
              headers={"Origin": "http://localhost:5173"})
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "x-report-data-sha256" in r.headers["access-control-expose-headers"].lower()
