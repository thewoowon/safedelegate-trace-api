"""SQLAlchemy 2 engine, session factory, and declarative base.

SQLite is the zero-friction local default; deployment can switch to PostgreSQL by
changing DATABASE_URL only — the ORM models are dialect-neutral. The FastAPI
dependency ``get_db`` yields a request-scoped session.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

_settings = get_settings()
_db_url = _settings.sqlalchemy_url

# check_same_thread is a SQLite-only concern; harmless to compute unconditionally.
_connect_args = {"check_same_thread": False} if _db_url.startswith("sqlite") else {}

engine = create_engine(
    _db_url,
    connect_args=_connect_args,
    pool_pre_ping=True,  # recycle stale connections on managed Postgres
    future=True,
)


if _db_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fk(dbapi_connection: Any, _record: Any) -> None:
        """Enforce foreign keys on SQLite so local behavior matches PostgreSQL.

        SQLite ignores FK constraints unless this pragma is set per connection; enabling
        it means insert-ordering bugs surface in tests instead of only in deployment.
        """
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


class Base(DeclarativeBase):
    """Declarative base shared by every ORM model and by Alembic's metadata."""


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yield a session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables for local/demo use.

    Alembic remains the source of truth for schema evolution in deployment; for the
    SQLite demo this create_all keeps the one-command start frictionless.
    """
    # Import models for their side effect of registering on Base.metadata.
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
