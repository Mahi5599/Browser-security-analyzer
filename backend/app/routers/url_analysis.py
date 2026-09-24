"""POST /analyze-url -- phishing risk score for a URL (and optional page signals)."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..services.phishing_predictor import ModelNotTrained, analyze_url, model_metadata

router = APIRouter(tags=["url-analysis"])


class PageSignals(BaseModel):
    has_login_form: bool = False
    has_password_field: bool = False
    password_field_insecure: bool = False
    form_action_cross_domain: bool = False
    num_external_form_actions: int = 0
    num_hidden_iframes: int = 0
    num_password_fields: int = 0


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, examples=["https://paypaI-secure-login.com"])
    live_lookups: bool = Field(
        True, description="Run WHOIS + SSL enrichment (slower, network-dependent)"
    )
    page_signals: Optional[PageSignals] = None


class AnalyzeUrlResponse(BaseModel):
    url: str
    risk_score: float
    verdict: str
    reasons: list[str]
    model_score: float
    enrichment: dict


@router.post("/analyze-url", response_model=AnalyzeUrlResponse)
def analyze_url_endpoint(req: AnalyzeUrlRequest) -> AnalyzeUrlResponse:
    try:
        result = analyze_url(
            req.url,
            live_lookups=req.live_lookups,
            page_signals=req.page_signals.model_dump() if req.page_signals else None,
        )
    except ModelNotTrained as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return AnalyzeUrlResponse(**result)


@router.get("/model-info")
def model_info():
    try:
        return model_metadata()
    except ModelNotTrained as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
