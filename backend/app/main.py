"""Browser Security Analyzer -- FastAPI backend.

Phase 1: phishing URL analysis + trained ML model.
Later phases add /analyze-file, /tracker-report, /forensic-log.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .db.database import init_db
from .routers import url_analysis


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Browser Security Analyzer",
    version="0.1.0",
    description="Phishing / malicious-download / tracker forensics backend.",
    lifespan=lifespan,
)

# The extension calls this from arbitrary pages; lock down in production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(url_analysis.router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "browser-security-analyzer", "phase": 1}
