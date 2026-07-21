"""Shared router dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db.base import get_db

DbDep = Annotated[Session, Depends(get_db)]


def request_id_of(request: Request) -> str:
    """Return the current request's id (set by middleware)."""
    return getattr(request.state, "request_id", "unknown")
