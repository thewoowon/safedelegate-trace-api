"""Action plan and action-request boundary models.

The plan is the typed proposal the policy gate evaluates. It preserves the user's exact
purpose (e.g. does not silently broaden "prepare" into "submit") and lists the precise
data classes and tool calls it intends to use.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RequiredDatum(BaseModel):
    """A data class the plan needs, plus why it is needed (for the receipt/trace)."""

    data_class: str
    reason: str


class ProposedToolCall(BaseModel):
    """A tool the plan intends to call, with its concrete arguments."""

    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ActionPlan(BaseModel):
    """Typed proposed action produced by the orchestrator (never executed by it)."""

    action_type: str
    institution: str
    product: str | None = None
    goal: str
    assumptions: list[str] = Field(default_factory=list)
    required_data: list[RequiredDatum] = Field(default_factory=list)
    proposed_tool_calls: list[ProposedToolCall] = Field(default_factory=list)
    expected_output: str
    reversibility: str  # REVERSIBLE | PARTIALLY_REVERSIBLE | IRREVERSIBLE
    estimated_risk: str  # LOW | MEDIUM | HIGH | CRITICAL
    approval_reason: str | None = None
    # Structured financial parameters, present only when relevant to the action.
    amount: dict[str, Any] | None = None
    counterparty: dict[str, Any] | None = None


class ActionRequestCreate(BaseModel):
    """Inbound request: a natural-language task bound to a delegation policy."""

    principal_id: str
    agent_id: str
    policy_id: str
    policy_version: int
    user_request: str
    # Optional untrusted external content (e.g. a product document). Treated as data.
    untrusted_document: str | None = None


class PlanOut(BaseModel):
    """The plan plus the hash that binds approvals to it."""

    request_id: str
    plan_hash: str
    plan: ActionPlan


class ActionRequestOut(BaseModel):
    """Lifecycle view of an action request."""

    id: str
    principal_id: str
    agent_id: str
    policy_id: str
    policy_version: int
    user_request: str
    trace_id: str
    state: str
