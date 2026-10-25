"""POST /analyze-file -- verdict for a completed download (hash + metadata only)."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ..services.file_analyzer import analyze_file
from ..services.forensic_log import get_log

log = logging.getLogger(__name__)
router = APIRouter(tags=["file-analysis"])


class AnalyzeFileRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=512)
    sha256: Optional[str] = Field(
        None, pattern=r"^[A-Fa-f0-9]{64}$",
        description="SHA-256 of the file; omit for a metadata-only scan")
    size_bytes: Optional[int] = Field(None, ge=0)
    source_url: Optional[str] = Field(None, max_length=2048)
    mime_type: Optional[str] = Field(None, max_length=255)
    case_id: str = Field("default", min_length=1, max_length=128)


class AnalyzeFileResponse(BaseModel):
    filename: str
    sha256: Optional[str]
    risk_score: float
    verdict: str
    reasons: list[str]
    virustotal: dict
    analysis_mode: str
    source_url_verdict: Optional[str] = None
    forensic_log_id: Optional[int] = None


@router.post("/analyze-file", response_model=AnalyzeFileResponse)
def analyze_file_endpoint(req: AnalyzeFileRequest) -> AnalyzeFileResponse:
    result = analyze_file(req.filename, req.sha256, req.size_bytes, req.source_url, req.mime_type)

    log_id = None
    if result["verdict"] in ("suspicious", "malicious"):
        try:
            entry = get_log().append("malicious_file", req.case_id, {
                "filename": result["filename"],
                "sha256": result["sha256"],
                "size_bytes": req.size_bytes,
                "source_url": req.source_url,
                "mime_type": req.mime_type,
                "verdict": result["verdict"],
                "risk_score": result["risk_score"],
                "reasons": result["reasons"],
                "virustotal": result["virustotal"],
                "analysis_mode": result["analysis_mode"],
                "source_url_verdict": result["source_url_verdict"],
            })
            log_id = entry["id"]
        except Exception:
            log.exception("Forensic log append failed for file %s", req.filename)

    return AnalyzeFileResponse(**result, forensic_log_id=log_id)
