"""Action Receipt boundary model (mirrors schemas/action-receipt.schema.json).

Receipt facts are derived from stored evidence, never regenerated from model memory.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import ReceiptStatus

SCHEMA_VERSION = "action-receipt-0.1"


class ReceiptExplanation(BaseModel):
    summary: str
    reasons: list[str]


class ReceiptIntegrity(BaseModel):
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    canonicalization_version: str


class ActionReceiptOut(BaseModel):
    """User-facing evidence artifact."""

    model_config = ConfigDict(from_attributes=True)

    schema_version: str = Field(default=SCHEMA_VERSION)
    receipt_id: str
    trace_id: str
    status: ReceiptStatus
    headline: str
    user_request: str
    agent_plan: dict[str, Any]
    authorization: dict[str, Any]
    safety_decision: dict[str, Any]
    human_approval: dict[str, Any] | None
    actual_outcome: dict[str, Any] | None
    data_used: list[dict[str, Any]]
    tools_used: list[dict[str, Any]]
    explanation: ReceiptExplanation
    next_actions: list[dict[str, Any]]
    integrity: ReceiptIntegrity
