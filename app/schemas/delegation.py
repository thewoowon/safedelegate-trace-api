"""Delegation policy boundary models (mirrors schemas/delegation-policy.schema.json)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DelegationPolicyBase(BaseModel):
    """Fields shared by create/read; JSON-Schema-compatible field names."""

    policy_id: str
    version: int = Field(ge=1)
    principal_id: str
    agent_id: str
    purpose: str
    allowed_action_types: list[str]
    allowed_institutions: list[str]
    allowed_products: list[str] = Field(default_factory=list)
    allowed_data_classes: list[str]
    allowed_tools: list[str]
    amount_limit: dict[str, Any] | None = None
    counterparty_rules: dict[str, Any] = Field(default_factory=dict)
    approval_rules: dict[str, Any]
    valid_from: datetime
    valid_until: datetime
    status: str = "ACTIVE"


class DelegationPolicyCreate(DelegationPolicyBase):
    """Inbound policy creation payload."""


class DelegationPolicyOut(DelegationPolicyBase):
    """Outbound policy representation."""

    model_config = ConfigDict(from_attributes=True)
