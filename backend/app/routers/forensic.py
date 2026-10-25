"""/forensic-log -- append, browse and verify the tamper-evident evidence log."""
from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

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
