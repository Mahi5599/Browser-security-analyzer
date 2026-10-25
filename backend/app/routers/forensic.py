"""/forensic-log -- append, browse and verify the tamper-evident evidence log."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, Field

from ..services.case_report import generate_report, safe_filename_part
from ..services.forensic_log import ForensicKeyMissing, get_log

router = APIRouter(tags=["forensic-log"])

EventType = Literal["phishing_url", "malicious_file", "tracker_session"]


class AppendRequest(BaseModel):
    event_type: EventType
    case_id: str = Field(..., min_length=1, max_length=128)
    details: dict[str, Any]


def _log():
    try:
        return get_log()
    except ForensicKeyMissing as exc:  # pragma: no cover - defensive
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/forensic-log", status_code=201)
def append_entry(req: AppendRequest):
    try:
        return _log().append(req.event_type, req.case_id, req.details)
    except ForensicKeyMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/forensic-log")
def list_entries(
    event_type: Optional[EventType] = None,
    since: Optional[str] = Query(None, description="ISO-8601, inclusive"),
    until: Optional[str] = Query(None, description="ISO-8601, inclusive"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    try:
        return _log().query(event_type=event_type, since=since, until=until,
                            limit=limit, offset=offset)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Bad timestamp: {exc}") from exc


@router.get("/forensic-log/verify")
def verify_chain(expected_head: Optional[str] = Query(
        None, description="Head hash recorded out-of-band; detects whole-log rollback")):
    try:
        return _log().verify(expected_head=expected_head)
    except ForensicKeyMissing as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/forensic-log/report")
def case_report(
    case_id: str = Query(..., min_length=1, max_length=128, description="Case to report on"),
    examiner: str = Query(..., min_length=1, max_length=128, description="Examiner's name, printed on the report"),
    format: Literal["pdf", "json"] = Query("pdf", description="json = the exact data whose SHA-256 is in the PDF footer"),
):
    """Case report. Strictly read-only: it never appends to the log."""
    case_id, examiner = case_id.strip(), examiner.strip()
    if not case_id or not examiner:
        raise HTTPException(status_code=422, detail="case_id and examiner must not be blank")
    try:
        out = generate_report(_log(), case_id, examiner, format)
    except ForensicKeyMissing as exc:
        # Without the key the chain cannot be verified, and a report without a
        # verification result would be misleading, so refuse.
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ext = "pdf" if format == "pdf" else "json"
    return Response(content=out["body"], media_type=out["media_type"], headers={
        "Content-Disposition": f'attachment; filename="case-report_{safe_filename_part(case_id)}_{stamp}.{ext}"',
        "X-Report-Data-SHA256": out["sha256"],
        "Cache-Control": "no-store",
    })
