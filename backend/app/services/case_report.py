"""Case report (PDF) built from the forensic log. Strictly read-only.

``build_report_data`` produces the report's *underlying data* as a plain dict;
``data_json`` serialises it deterministically and its SHA-256 is printed in the
PDF footer, so anyone can fetch ``?format=json`` and re-hash it. The generation
time is deliberately NOT part of that data, so re-running the report on an
unchanged log yields the same hash.

Everything that comes from the log (URLs, filenames, reasons) is attacker
controlled. reportlab's Paragraph parses XML-like markup (``<img src=...>`` can
make it fetch a URL or read a local file), so all such text goes through
``pdf_text``: non-ASCII/control characters become visible ``\\uXXXX`` escapes
(also what an examiner wants for look-alike domains) and markup is escaped.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from ..version import APP_NAME, APP_VERSION
from .forensic_log import EVENT_TYPES, ForensicLog

MAX_TABLE_ROWS = 1000
RED, GREEN, GREY = "#b91c1c", "#166534", "#475569"

_MANIFEST = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "blocklists", "manifest.json")


# ----------------------------------------------------------------- text safety
def clip(value: Any, limit: int) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[: max(limit - 3, 0)] + "..."


def ascii_escape(s: str) -> str:
    """Printable ASCII only; everything else as a visible \\xNN / \\uNNNN escape."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\n\t":
            out.append(" ")
        elif 32 <= o < 127:
            out.append(ch)
        elif o < 256:
            out.append(f"\\x{o:02x}")
        elif o < 0x10000:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out)


def pdf_text(value: Any, limit: int = 300) -> str:
    """Safe for use inside a reportlab Paragraph."""
    return escape(ascii_escape(clip(value, limit)))


def safe_filename_part(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60].strip("._") or "case"


# ---------------------------------------------------------------- data (pure)
def _versions() -> dict:
    out: dict[str, Any] = {"tool": {"name": APP_NAME, "version": APP_VERSION}}
    try:
        from .forensic_log import _model_version
        out["model"] = _model_version()
    except Exception:  # model not trained / unreadable: say so rather than fail the report
        out["model"] = {"available": False}
    try:
        from .reputation import SNAPSHOT_DATE
        out["tranco_snapshot_date"] = SNAPSHOT_DATE
    except Exception:
        out["tranco_snapshot_date"] = None
    try:
        with open(_MANIFEST, encoding="utf-8") as fh:
            out["blocklists"] = [{k: l.get(k) for k in ("name", "list_version", "last_modified", "downloaded")}
                                 for l in json.load(fh)["lists"]]
    except Exception:
        out["blocklists"] = []
    return out


def verdict_of(entry: dict) -> str:
    d = entry.get("details") if isinstance(entry.get("details"), dict) else {}
    v = d.get("verdict")
    return v if isinstance(v, str) and v else ""


def summarize(entries: list[dict]) -> dict:
    by_type = {t: 0 for t in EVENT_TYPES}
    by_verdict: dict[str, dict[str, int]] = {}
    fingerprinting = 0
    for e in entries:
        t = e.get("event_type")
        by_type[t] = by_type.get(t, 0) + 1
        v = verdict_of(e)
        if v:
            by_verdict.setdefault(t, {})
            by_verdict[t][v] = by_verdict[t].get(v, 0) + 1
        if t == "tracker_session" and isinstance(e.get("details"), dict) \
                and e["details"].get("canvas_fingerprinting"):
            fingerprinting += 1
    return {"by_type": by_type, "by_verdict": by_verdict, "canvas_fingerprinting_sessions": fingerprinting}


def build_report_data(all_entries: list[dict], verification: dict, case_id: str, examiner: str) -> dict:
    case_entries = [e for e in all_entries if e.get("case_id") == case_id]
    return {
        "report": {"title": "Forensic Case Report", "case_id": case_id, "examiner": examiner,
                   **_versions()},
        "integrity": {
            "scope": "entire log (the hash chain is not per case)",
            "valid": bool(verification["valid"]),
            "entries_checked": verification["entries_checked"],
            "first_broken_id": verification["first_broken_id"],
            "reason": verification["reason"],
            "head_hash": verification["head_hash"],
        },
        "log": {"total_entries": len(all_entries), "case_entries": len(case_entries)},
        "summary": summarize(case_entries),
        "entries": case_entries,
    }


def data_json(data: dict) -> bytes:
    """The exact bytes whose SHA-256 appears in the PDF footer."""
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8")


def data_sha256(data: dict) -> str:
    return hashlib.sha256(data_json(data)).hexdigest()


def banner_for(integrity: dict, total_entries: int) -> dict:
    """status: failure (red) | empty (grey) | verified (green). Failure can never be green."""
    if not integrity["valid"]:
        where = (f" First broken entry: #{integrity['first_broken_id']}."
                 if integrity["first_broken_id"] is not None else "")
        return {"status": "failure", "color": RED, "text": "INTEGRITY FAILURE",
                "detail": f"The forensic log failed verification.{where} "
                          f"{integrity['reason'] or ''} Do not rely on this evidence."}
    if total_entries == 0:
        return {"status": "empty", "color": GREY, "text": "LOG IS EMPTY",
                "detail": "No evidence has been recorded, so there is nothing to verify."}
    return {"status": "verified", "color": GREEN, "text": "INTEGRITY VERIFIED",
            "detail": f"All {integrity['entries_checked']} log entries chain correctly and carry valid HMACs."}


def _short_hash(h: Any) -> str:
    h = "" if h is None else str(h)
    return h if len(h) <= 14 else h[:12] + "..."


def entry_row(e: dict) -> tuple[str, str]:
    """(verdict text, key-details text) for the evidence table; defensive about tampered rows."""
    d = e.get("details") if isinstance(e.get("details"), dict) else {}
    t = e.get("event_type")
    reasons = d.get("reasons") if isinstance(d.get("reasons"), list) else []
    first = clip(reasons[0], 110) if reasons else ""
    if t == "phishing_url":
        return (verdict_of(e) or "-",
                f"{clip(d.get('url'), 140)} | risk {d.get('risk_score')}" + (f" | {first}" if first else ""))
    if t == "malicious_file":
        vt = d.get("virustotal") if isinstance(d.get("virustotal"), dict) else {}
        sha = d.get("sha256") or "not hashed"
        sha = sha if len(str(sha)) <= 16 else str(sha)[:16] + "..."
        return (verdict_of(e) or "-",
                f"{clip(d.get('filename'), 80)} | sha256 {sha} | risk {d.get('risk_score')} | VT {vt.get('status', '-')}"
                + (f" | {first}" if first else ""))
    if t == "tracker_session":
        flags = d.get("reasons") if isinstance(d.get("reasons"), list) else []
        return ("flagged" if flags else "-",
                f"{clip(d.get('site'), 80)} | {clip(', '.join(map(str, flags)), 80)} | "
                f"{d.get('tracker_domains')} tracker domains | "
                f"{d.get('third_party_cookies')} 3rd-party cookies"
                + (" | canvas fingerprinting" if d.get("canvas_fingerprinting") else ""))
    return ("-", clip(json.dumps(d, sort_keys=True), 160))


# ----------------------------------------------------------------- PDF render
def _styles():
    ss = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=ss["Normal"], fontName="Helvetica", fontSize=9, leading=12)
    return {
        "base": base,
        "cell": ParagraphStyle("cell", parent=base, fontSize=7.5, leading=9.5, wordWrap="CJK"),
        "cellb": ParagraphStyle("cellb", parent=base, fontSize=7.5, leading=9.5, fontName="Helvetica-Bold"),
        "title": ParagraphStyle("title", parent=base, fontName="Helvetica-Bold", fontSize=20, leading=24, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=10, spaceAfter=4, keepWithNext=1),
        "small": ParagraphStyle("small", parent=base, fontSize=8, leading=10.5, textColor=colors.HexColor("#334155")),
        "mono": ParagraphStyle("mono", parent=base, fontName="Courier", fontSize=7.5, leading=9.5, wordWrap="CJK"),
        "banner": ParagraphStyle("banner", parent=base, fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=colors.white),
        "bannerd": ParagraphStyle("bannerd", parent=base, fontSize=9.5, leading=12.5, textColor=colors.white),
    }


def _kv_table(rows, st, widths):
    t = Table([[Paragraph(f"<b>{pdf_text(k)}</b>", st["cell"]), Paragraph(v, st["cell"])] for k, v in rows],
              colWidths=widths)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    return t


def render_pdf(data: dict, generated_at: datetime, report_sha256: str) -> bytes:
    st = _styles()
    rep, integ, summ = data["report"], data["integrity"], data["summary"]
    banner = banner_for(integ, data["log"]["total_entries"])
    failed = banner["status"] == "failure"
    gen = generated_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    W = landscape(A4)[0] - 30 * mm

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Courier", 6.8)
        canvas.setFillColor(colors.HexColor("#334155"))
        canvas.drawString(15 * mm, 9 * mm, f"Report data SHA-256: {report_sha256}")
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(landscape(A4)[0] - 15 * mm, 9 * mm,
                               f"Case {ascii_escape(clip(rep['case_id'], 40))}  |  page {doc.page}")
        if failed:
            canvas.setFillColor(colors.HexColor(RED))
            canvas.setFont("Helvetica-Bold", 8)
            canvas.drawString(15 * mm, 14 * mm, "INTEGRITY FAILURE - the forensic log did not verify; do not rely on this report")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=14 * mm, bottomMargin=20 * mm,
                            title=f"Forensic Case Report - {ascii_escape(clip(rep['case_id'], 60))}",
                            author=ascii_escape(clip(rep["examiner"], 60)), creator=APP_NAME)
    story: list = [Paragraph("Forensic Case Report", st["title"])]

    # --- header facts
    model = rep["model"]
    model_txt = (f"{pdf_text(model.get('model_type'))}, trained {pdf_text(model.get('trained_at'))}, "
                 f"file sha256 {pdf_text(clip(model.get('model_sha256'), 16))}"
                 if model.get("model_type") else "not available (model not loaded when the report was generated)")
    lists_txt = "; ".join(f"{pdf_text(l['name'])} {pdf_text(l['list_version'])} (downloaded {pdf_text(l['downloaded'])})"
                          for l in rep["blocklists"]) or "not available"
    story.append(_kv_table([
        ("Case ID", pdf_text(rep["case_id"], 128)),
        ("Examiner", pdf_text(rep["examiner"], 128)),
        ("Generated (UTC)", pdf_text(gen)),
        ("Tool", f"{pdf_text(rep['tool']['name'])} v{pdf_text(rep['tool']['version'])}"),
        ("Phishing model", model_txt),
        ("Tracker lists", lists_txt),
        ("Reputation snapshot", f"Tranco top-10k, {pdf_text(rep['tranco_snapshot_date'])}"),
    ], st, [40 * mm, W - 40 * mm]))
    story.append(Spacer(1, 6))

    # --- banner
    bt = Table([[Paragraph(banner["text"], st["banner"])], [Paragraph(pdf_text(banner["detail"], 500), st["bannerd"])]],
               colWidths=[W])
    bt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(banner["color"])),
                            ("LEFTPADDING", (0, 0), (-1, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 6),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story.append(bt)

    # --- executive summary
    story.append(Paragraph("1. Executive summary", st["h2"]))
    n_case, n_all = data["log"]["case_entries"], data["log"]["total_entries"]
    if n_all == 0:
        story.append(Paragraph("The forensic log is <b>empty</b>: no evidence has been recorded yet.", st["base"]))
    elif n_case == 0:
        story.append(Paragraph(f"The log holds {n_all} entries, but <b>none are filed under case "
                               f"{pdf_text(rep['case_id'], 128)}</b>. No evidence to report for this case.", st["base"]))
    else:
        story.append(Paragraph(f"Case <b>{pdf_text(rep['case_id'], 128)}</b> contains <b>{n_case}</b> evidence "
                               f"entr{'y' if n_case == 1 else 'ies'} (of {n_all} in the whole log).", st["base"]))
        rows = [["Event type", "Entries", "Verdict breakdown"]]
        for t in EVENT_TYPES:
            if summ["by_type"].get(t):
                vb = summ["by_verdict"].get(t)
                rows.append([t, str(summ["by_type"][t]),
                             ", ".join(f"{v}: {n}" for v, n in sorted(vb.items())) if vb else "(flag-based, no verdict)"])
        for t, n in summ["by_type"].items():       # types we do not know (tampered rows)
            if t not in EVENT_TYPES and n:
                rows.append([ascii_escape(clip(t, 40)), str(n), "unrecognised event type"])
        if summ["canvas_fingerprinting_sessions"]:
            rows.append(["", "", f"{summ['canvas_fingerprinting_sessions']} session(s) with canvas fingerprinting"])
        t = Table([[Paragraph(pdf_text(c), st["cellb"] if i == 0 else st["cell"]) for c in r] for i, r in enumerate(rows)],
                  colWidths=[55 * mm, 25 * mm, W - 80 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(Spacer(1, 4))
        story.append(t)

    # --- integrity
    story.append(Paragraph("2. Chain of custody - integrity verification", st["h2"]))
    story.append(_kv_table([
        ("Result", f"<b>{pdf_text('VALID' if integ['valid'] else 'INVALID')}</b>"),
        ("Entries checked" if integ["valid"] else "Entries intact before the first break", pdf_text(integ["entries_checked"])),
        ("First broken entry", pdf_text(f"#{integ['first_broken_id']}" if integ["first_broken_id"] is not None else "none")),
        ("Reason", pdf_text(integ["reason"] or "-", 400)),
        ("Chain head hash", f"<font face='Courier'>{pdf_text(integ['head_hash'] or '-', 80)}</font>"),
        ("Scope", pdf_text(integ["scope"])),
    ], st, [40 * mm, W - 40 * mm]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "Each entry is chained to the previous one (SHA-256) and authenticated with an HMAC; a signed head "
        "record detects deleted trailing entries. Verification covers the whole log, so a failure anywhere "
        "means no entry at or after the break can be vouched for." if integ["valid"] else
        "<b>Verification failed.</b> Entries at or after the first broken entry cannot be vouched for, and an "
        "attacker who altered one entry may have altered others.", st["small"]))

    # --- evidence
    story.append(Paragraph("3. Evidence", st["h2"]))
    if n_case == 0:
        story.append(Paragraph("No entries for this case.", st["base"]))
    else:
        shown = data["entries"][:MAX_TABLE_ROWS]
        hdr = ["ID", "Timestamp (UTC)", "Type", "Verdict", "Key details", "entry_hash"]
        widths = [12 * mm, 46 * mm, 28 * mm, 24 * mm, W - 12 * mm - 46 * mm - 28 * mm - 24 * mm - 36 * mm, 36 * mm]
        rows = [[Paragraph(h, st["cellb"]) for h in hdr]]
        style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                 ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]
        for i, e in enumerate(shown, start=1):
            verdict, details = entry_row(e)
            rows.append([Paragraph(pdf_text(e.get("id"), 12), st["cell"]), Paragraph(pdf_text(e.get("timestamp_utc"), 40), st["cell"]),
                         Paragraph(pdf_text(e.get("event_type"), 30), st["cell"]), Paragraph(pdf_text(verdict, 60), st["cell"]),
                         Paragraph(pdf_text(details, 420), st["cell"]),
                         Paragraph(pdf_text(_short_hash(e.get("entry_hash"))), st["mono"])])
            if failed and e.get("id") == integ["first_broken_id"]:
                style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fecaca")))
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle(style))
        story.append(t)
        if len(data["entries"]) > len(shown):
            story.append(Paragraph(f"Table truncated: showing the first {len(shown)} of {len(data['entries'])} entries. "
                                   "The report data (JSON) hashed in the footer contains all of them.", st["small"]))
        if failed and any(e.get("id") == integ["first_broken_id"] for e in shown):
            story.append(Paragraph("The shaded row is the first entry that failed verification.", st["small"]))

    # --- limitations
    story.append(KeepTogether([
        Paragraph("4. Limitations", st["h2"]),
        Paragraph("<br/>".join(f"&bull; {pdf_text(x, 600)}" for x in [
            "The HMAC is symmetric: anyone holding the server's FORENSIC_HMAC_KEY (for example a local operator or anyone who can "
            "read its .env file) could forge entries or re-sign a rewritten log. This log is tamper-evident against parties "
            "without the key, not against the key holder.",
            "Restoring an older, internally consistent copy of the whole database verifies as valid unless the head hash was "
            "recorded somewhere outside this machine.",
            "Only suspicious / phishing / malicious verdicts and high-tracking page loads are logged; benign activity is not, "
            "so this is evidence of flagged events, not a complete browsing record.",
            "Verdicts come from a statistical model, heuristics and list snapshots, and can be wrong; the log proves an "
            "entry was not altered after it was written, not that the verdict was correct.",
            "Timestamps come from the host's clock, not a trusted time source.",
            "The SHA-256 in the footer covers this report's underlying data (JSON), not the PDF file; the PDF is not "
            "digitally signed.",
        ]), st["small"]),
    ]))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


# ------------------------------------------------------------------ entrypoint
def generate_report(log: ForensicLog, case_id: str, examiner: str, fmt: str = "pdf",
                    now: Optional[datetime] = None) -> dict:
    """Read-only. Returns {"body": bytes, "media_type", "sha256", "data"}.

    ``sha256`` is the hash of the report's underlying data JSON for *both* formats,
    so it can be compared with ``format=json`` output.
    """
    entries, verification = log.report_snapshot()
    data = build_report_data(entries, verification, case_id, examiner)
    raw = data_json(data)
    sha = hashlib.sha256(raw).hexdigest()
    if fmt == "json":
        return {"body": raw, "media_type": "application/json", "sha256": sha, "data": data}
    pdf = render_pdf(data, now or datetime.now(timezone.utc), sha)
    return {"body": pdf, "media_type": "application/pdf", "sha256": sha, "data": data}
