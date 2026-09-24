"""SQLite via SQLAlchemy.

Phase 1 only needs a working engine/session factory; the forensic evidence
log (Phase 5) and analytics tables build on top of this.
"""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = os.getenv(
    "BSA_DB_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "bsa.db"),
)
DATABASE_URL = os.getenv("BSA_DATABASE_URL", f"sqlite:///{os.path.abspath(DB_PATH)}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    # Import models here as they are added in later phases so their tables
    # are registered on Base.metadata before create_all().
    Base.metadata.create_all(bind=engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
