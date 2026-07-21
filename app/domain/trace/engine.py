"""Append-only trace store with hash-chain integrity.

Every material step appends one event. Each event's hash is derived from the previous
event's hash, the event body, and the server secret, forming a per-trace chain. Events
are never updated or deleted; tampering with a stored body breaks the chain, which
``verify_chain`` detects.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import models
from app.domain.hashing import CANONICALIZATION_VERSION, GENESIS_HASH, chain_hash
from app.schemas.trace import TraceEventEnvelope, TraceTimeline


def _latest_event(db: Session, trace_id: str) -> models.TraceEvent | None:
    """Return the most recent event for a trace, or None if the chain is empty."""
    stmt = (
        select(models.TraceEvent)
        .where(models.TraceEvent.trace_id == trace_id)
        .order_by(models.TraceEvent.sequence.desc())
        .limit(1)
    )
    return db.execute(stmt).scalar_one_or_none()


def append_event(
    db: Session, trace_id: str, event_type: str, body: dict[str, Any]
) -> models.TraceEvent:
    """Append one MSTS-Lite event to a trace and return the stored row.

    The caller supplies the event ``body`` (the MSTS-Lite fields); this function owns
    sequencing and integrity metadata.
    """
    secret = get_settings().trace_hash_secret
    previous = _latest_event(db, trace_id)
    previous_hash = previous.event_hash if previous else GENESIS_HASH
    sequence = (previous.sequence + 1) if previous else 0

    event_hash = chain_hash(previous_hash, body, secret)
    event = models.TraceEvent(
        event_id=str(uuid.uuid4()),
        trace_id=trace_id,
        sequence=sequence,
        event_type=event_type,
        body=body,
        previous_event_hash=previous_hash,
        event_hash=event_hash,
        canonicalization_version=CANONICALIZATION_VERSION,
        created_at=datetime.now(UTC),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def verify_chain(events: list[models.TraceEvent]) -> bool:
    """Recompute the chain and confirm every stored hash matches (tamper detection)."""
    secret = get_settings().trace_hash_secret
    previous_hash = GENESIS_HASH
    for event in events:
        if event.previous_event_hash != previous_hash:
            return False
        expected = chain_hash(previous_hash, event.body, secret)
        if expected != event.event_hash:
            return False
        previous_hash = event.event_hash
    return True


def get_timeline(db: Session, trace_id: str) -> TraceTimeline:
    """Load the ordered event chain for a trace and report chain validity."""
    stmt = (
        select(models.TraceEvent)
        .where(models.TraceEvent.trace_id == trace_id)
        .order_by(models.TraceEvent.sequence.asc())
    )
    events = list(db.execute(stmt).scalars().all())
    envelopes = [
        TraceEventEnvelope(
            event_id=e.event_id,
            trace_id=e.trace_id,
            sequence=e.sequence,
            event_type=e.event_type,
            body=e.body,
            previous_event_hash=e.previous_event_hash,
            event_hash=e.event_hash,
            canonicalization_version=e.canonicalization_version,
        )
        for e in events
    ]
    return TraceTimeline(
        trace_id=trace_id,
        events=envelopes,
        chain_valid=verify_chain(events),
    )
