"""MSTS-Lite event boundary model (mirrors schemas/msts-lite.schema.json).

The 29 top-level business fields are the event body; integrity metadata
(previous/current hash, canonicalization version) lives in the trace envelope.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import AutonomyLevel, CriticalityLevel, Decision

SCHEMA_VERSION = "msts-lite-0.1"


class MstsLiteEvent(BaseModel):
    """A single MSTS-Lite event (the 29 core fields)."""

    schema_version: str = Field(default=SCHEMA_VERSION)
    event_id: str
    trace_id: str
    timestamp_utc: datetime
    jurisdiction: str = Field(min_length=2)
    institution_id: str
    principal_id: str
    agent_id: str
    agent_role: str
    autonomy_level: AutonomyLevel
    criticality_level: CriticalityLevel
    trigger_type: str
    user_intent: str
    delegated_scope: dict[str, Any]
    model_provider: str | None
    model_name: str | None
    model_version: str | None
    data_sources: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]
    recommended_action: dict[str, Any] | None
    executed_action: dict[str, Any] | None
    human_review_status: str
    policy_decision: Decision
    risk_flags: list[str]
    confidence_metadata: dict[str, Any]
    override_status: str
    post_action_outcome: dict[str, Any] | None
    retention_class: str
    supervisory_access_tier: str


class TraceEventEnvelope(BaseModel):
    """An MSTS-Lite event plus its append-only integrity fields."""

    model_config = ConfigDict(from_attributes=True)

    event_id: str
    trace_id: str
    sequence: int
    event_type: str
    body: dict[str, Any]
    previous_event_hash: str
    event_hash: str
    canonicalization_version: str


class TraceTimeline(BaseModel):
    """The full ordered event chain for a trace, as shown in the oversight console."""

    trace_id: str
    events: list[TraceEventEnvelope]
    chain_valid: bool
