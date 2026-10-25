"""Browser Security Analyzer -- FastAPI backend.

Phase 1: phishing URL analysis + trained ML model.
Later phases add /analyze-file, /tracker-report, /forensic-log.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db.database import init_db
from .routers import file_analysis, forensic, tracker_report, url_analysis


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Browser Security Analyzer",
    version="0.6.0",
    description="Phishing / malicious-download / tracker forensics backend.",
    lifespan=lifespan,
)

# CORS: only the dashboard and this project's extension may call the API from a
# browser. The extension ID is pinned by the "key" in extension/manifest.json.
# Override with BSA_DASHBOARD_ORIGINS / BSA_EXTENSION_IDS (comma-separated).
# CORS is not authentication: curl, scripts and other local processes are
# unaffected by it (see README, threat model).
PINNED_EXTENSION_ID = "gknjaknibkcfffkjjceppndfodajfjil"
DEFAULT_DASHBOARD_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


def allowed_origins() -> list[str]:
    def split(v: str) -> list[str]:
        return [x.strip().rstrip("/") for x in v.split(",") if x.strip()]

    dashboards = split(os.getenv("BSA_DASHBOARD_ORIGINS", DEFAULT_DASHBOARD_ORIGINS))
    ext_ids = split(os.getenv("BSA_EXTENSION_IDS", PINNED_EXTENSION_ID))
    return dashboards + [f"chrome-extension://{i}" for i in ext_ids]


app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins(),
    allow_methods=["GET", "POST"],
    allow_headers=["content-type"],
)

app.include_router(url_analysis.router)
app.include_router(file_analysis.router)
app.include_router(forensic.router)
app.include_router(tracker_report.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "browser-security-analyzer", "phase": 6, "phases_built": [1, 2, 3, 4, 5, 6]}
