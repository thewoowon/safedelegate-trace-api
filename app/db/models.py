"""ORM models for the SafeDelegate Trace domain (docs/08_DOMAIN_MODEL.md).

Design notes:
- Flexible, schema-validated structures (delegated scope, plan payloads, rule results,
  trace envelopes) are stored as JSON columns; their shape is enforced at the API
  boundary by Pydantic models and by JSON Schema in tests, not by the relational schema.
- Trace events are append-only (never updated or deleted) and carry hash-chain fields.
- Timestamps are timezone-aware UTC.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


class Principal(Base):
    """The human (or organization) that delegates authority. Demo identities only."""

    __tablename__ = "principals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    demo_identity_type: Mapped[str] = mapped_column(String, default="SYNTHETIC")
    notice: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base):
    """The AI system acting under delegated authority (agent registry record)."""

    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    owner_institution: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False)
    autonomy_level: Mapped[str] = mapped_column(String, nullable=False)  # L0..L4
    model: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="ACTIVE")  # ACTIVE|PAUSED|REVOKED
    kill_switch_owner: Mapped[str] = mapped_column(String, nullable=False)
    jurisdiction_tags: Mapped[list[str]] = mapped_column(JSON, default=list)


class DelegationPolicy(Base):
    """Versioned authorization contract binding a principal to an agent's bounded scope."""

    __tablename__ = "delegation_policies"

    policy_id: Mapped[str] = mapped_column(String, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_action_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_institutions: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_products: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_data_classes: Mapped[list[str]] = mapped_column(JSON, default=list)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, default=list)
    amount_limit: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    counterparty_rules: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    approval_rules: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String, default="ACTIVE")  # ACTIVE|EXPIRED|REVOKED
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionRequest(Base):
    """Original user intent + context and the lifecycle state machine cursor."""

    __tablename__ = "action_requests"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    principal_id: Mapped[str] = mapped_column(ForeignKey("principals.id"), nullable=False)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id"), nullable=False)
    policy_id: Mapped[str] = mapped_column(String, nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    user_request: Mapped[str] = mapped_column(Text, nullable=False)
    # Untrusted external content (e.g. a product document); treated as data, never instruction.
    untrusted_document: Mapped[str | None] = mapped_column(Text, nullable=True)
    trace_id: Mapped[str] = mapped_column(String, nullable=False)
    state: Mapped[str] = mapped_column(String, default="DRAFT")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    plan: Mapped[ActionPlan | None] = relationship(back_populates="request", uselist=False)


class ActionPlan(Base):
    """Typed proposed action produced by the orchestrator; identified by a content hash."""

    __tablename__ = "action_plans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    plan_hash: Mapped[str] = mapped_column(String, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    request: Mapped[ActionRequest] = relationship(back_populates="plan")


class PolicyEvaluation(Base):
    """Immutable rule-by-rule decision artifact bound to a policy + plan hash."""

    __tablename__ = "policy_evaluations"

    evaluation_id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    policy_id: Mapped[str] = mapped_column(String, nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String, nullable=False)
    decision: Mapped[str] = mapped_column(String, nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False)
    rule_results: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Approval(Base):
    """Human decision bound to the exact plan hash + policy version + expiry."""

    __tablename__ = "approvals"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)  # APPROVED|REJECTED|EXPIRED|PENDING
    approved_plan_hash: Mapped[str] = mapped_column(String, nullable=False)
    policy_version: Mapped[int] = mapped_column(Integer, nullable=False)
    approver_id: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolCall(Base):
    """Schema-validated tool attempt and its result; blocked calls are recorded too."""

    __tablename__ = "tool_calls"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String, nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String, nullable=False)  # STARTED|COMPLETED|BLOCKED|FAILED
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Execution(Base):
    """Simulated financial action outcome with reversibility metadata."""

    __tablename__ = "executions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String, nullable=True)
    # SUBMITTED | NO_EXECUTION | FAILED_SAFE
    status: Mapped[str] = mapped_column(String, nullable=False)
    outcome: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TraceEvent(Base):
    """Append-only MSTS-Lite event with hash-chain integrity fields (envelope)."""

    __tablename__ = "trace_events"

    event_id: Mapped[str] = mapped_column(String, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String, nullable=False)
    body: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # the 29-field MSTS-Lite event
    previous_event_hash: Mapped[str] = mapped_column(String, nullable=False)
    event_hash: Mapped[str] = mapped_column(String, nullable=False)
    canonicalization_version: Mapped[str] = mapped_column(String, default="jcs-0.1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionReceipt(Base):
    """User-facing evidence package derived from stored trace data."""

    __tablename__ = "action_receipts"

    receipt_id: Mapped[str] = mapped_column(String, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False)
    # Full action-receipt object (mirrors action-receipt.schema.json).
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    """Security or integrity issue requiring operator handling (quarantine linkage)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    trace_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    request_id: Mapped[str] = mapped_column(ForeignKey("action_requests.id"), nullable=False)
    classification: Mapped[str] = mapped_column(String, nullable=False)
    risk_flags: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String, default="OPEN")  # OPEN|CLOSED
    interventions: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class IdempotencyRecord(Base):
    """Stored key -> response so retried mutating requests do not double-execute."""

    __tablename__ = "idempotency_records"

    key: Mapped[str] = mapped_column(String, primary_key=True)
    endpoint: Mapped[str] = mapped_column(String, primary_key=True)
    response: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
