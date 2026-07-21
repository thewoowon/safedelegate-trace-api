"""System endpoints: health and deterministic demo bootstrap."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import __version__
from app.config import get_settings
from app.db.base import get_db
from app.demo.seed import seed_demo
from app.schemas.common import Envelope, HealthResponse

router = APIRouter()

DbDep = Annotated[Session, Depends(get_db)]


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health() -> HealthResponse:
    """Report process health and whether deterministic demo mode is active."""
    settings = get_settings()
    return HealthResponse(status="healthy", demo_mode=settings.demo_mode, version=__version__)


@router.get("/v1/demo/bootstrap", response_model=Envelope[dict[str, Any]], tags=["system"])
def bootstrap_demo(request: Request, db: DbDep) -> Envelope[dict[str, Any]]:
    """Seed the known synthetic demo state and return a count summary.

    Idempotent: repeated calls restore the same state, so the demo is reproducible.
    """
    counts = seed_demo(db)
    return Envelope(request_id=request.state.request_id, data={"seeded": counts})
