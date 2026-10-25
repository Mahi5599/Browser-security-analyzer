"""POST/GET /tracker-report -- per-page-load tracking snapshots and their aggregate."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from ..services.tracker_store import get_store

log = logging.getLogger(__name__)
router = APIRouter(tags=["tracker-report"])


class TrackerDomain(BaseModel):
    domain: str = Field(..., max_length=253)
    network: str = Field(..., max_length=253)
    requests: int = Field(..., ge=0)
    list: str = Field("", max_length=32)
    pixels: int = Field(0, ge=0)
    beacons: int = Field(0, ge=0)


class Network(BaseModel):
    network: str = Field(..., max_length=253)
    requests: int = Field(..., ge=0)
    domains: int = Field(0, ge=0)


class TrackerReport(BaseModel):
    session_id: str = Field(..., min_length=8, max_length=64)
    site: str = Field(..., min_length=1, max_length=253, description="hostname only")
    total_requests: int = Field(0, ge=0)
    third_party_requests: int = Field(..., ge=0)
    third_party_domains: int = Field(..., ge=0)
    tracker_domains: int = Field(..., ge=0)
    tracker_requests: int = Field(0, ge=0)
    unknown_third_party_domains: int = Field(0, ge=0)
    trackers: list[TrackerDomain] = Field(default_factory=list, max_length=100)
    top_networks: list[Network] = Field(default_factory=list, max_length=10)
    pixels: int = Field(0, ge=0)
    beacons: int = Field(0, ge=0)
    third_party_cookies: int = Field(0, ge=0)
    excessive_third_party_cookies: bool = False
    canvas_fingerprinting: bool = False
    canvas_events: int = Field(0, ge=0)
    canvas_scripts: list[str] = Field(default_factory=list, max_length=20)
    list_versions: dict[str, Optional[str]] = Field(default_factory=dict)
    case_id: str = Field("default", min_length=1, max_length=128)


@router.post("/tracker-report", status_code=201)
def post_report(req: TrackerReport):
    data = req.model_dump()
    data["site"] = data["site"].lower()
    case_id = data.pop("case_id")
    result = get_store().upsert(data, case_id)
    return {"session_id": req.session_id, "stored": True, **result}


@router.get("/tracker-report")
def get_report(site: Optional[str] = None,
               since: Optional[str] = Query(None, description="ISO-8601 UTC, e.g. 2026-10-01T00:00:00Z"),
               top: int = Query(10, ge=1, le=100)):
    return get_store().report(site=site, since=since, top=top)
