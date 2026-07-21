"""Evidence endpoints: traces and action receipts."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.db import models
from app.domain import trace
from app.routers.deps import DbDep, request_id_of
from app.schemas.common import Envelope
from app.schemas.receipt import ActionReceiptOut
from app.schemas.trace import TraceTimeline

router = APIRouter(prefix="/v1", tags=["evidence"])


@router.get("/traces/{trace_id}", response_model=Envelope[TraceTimeline])
def get_trace(trace_id: str, request: Request, db: DbDep) -> Envelope[TraceTimeline]:
    """Return the ordered, integrity-verified MSTS-Lite event timeline for a trace."""
    timeline = trace.get_timeline(db, trace_id)
    if not timeline.events:
        raise HTTPException(status_code=404, detail="Trace not found.")
    return Envelope(request_id=request_id_of(request), data=timeline)


def _load_receipt(db: DbDep, receipt_id: str) -> ActionReceiptOut:
    row = db.get(models.ActionReceipt, receipt_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Receipt not found.")
    return ActionReceiptOut.model_validate(row.payload)


@router.get("/receipts/{receipt_id}", response_model=Envelope[ActionReceiptOut])
def get_receipt(receipt_id: str, request: Request, db: DbDep) -> Envelope[ActionReceiptOut]:
    """Return a user-facing Action Receipt."""
    receipt = _load_receipt(db, receipt_id)
    return Envelope(request_id=request_id_of(request), data=receipt)


@router.get("/receipts/{receipt_id}/json", response_model=ActionReceiptOut)
def get_receipt_json(receipt_id: str, db: DbDep) -> ActionReceiptOut:
    """Return the raw receipt object (downloadable JSON), without the envelope."""
    return _load_receipt(db, receipt_id)
