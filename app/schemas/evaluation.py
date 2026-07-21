"""Policy evaluation boundary models (mirrors schemas/policy-evaluation.schema.json).

Each rule returns machine-readable evidence plus a plain-language message for both the
consumer and the operator, per docs/09_POLICY_ENGINE.md.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import Decision, RiskLevel, RuleStatus, Severity


class RuleResult(BaseModel):
    """One ordered policy rule's outcome."""

    rule_id: str
    status: RuleStatus
    severity: Severity
    evidence: dict[str, Any] = Field(default_factory=dict)
    user_message: str
    operator_message: str


class PolicyEvaluationOut(BaseModel):
    """Immutable evaluation artifact returned by the policy gate."""

    model_config = ConfigDict(from_attributes=True)

    evaluation_id: str
    policy_id: str
    policy_version: int
    rule_set_version: str
    plan_hash: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    rule_results: list[RuleResult]
    created_at: datetime
