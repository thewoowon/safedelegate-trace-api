"""Security-lab and operator boundary models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class ScenarioSummary(BaseModel):
    """A curated adversarial/benign scenario the lab can run."""

    scenario_id: str
    name: str
    description: str
    attack: bool
    expected_decision: str
    expected_outcome: str


class ScenarioResult(BaseModel):
    """Outcome of running a scenario end-to-end through the real control pipeline."""

    scenario_id: str
    name: str
    attack: bool
    expected_decision: str
    actual_decision: str
    decision_match: bool
    expected_outcome: str
    executed: bool
    no_execution: bool
    request_id: str
    trace_id: str
    receipt_id: str | None
    risk_flags: list[str]


class OperatorEvent(BaseModel):
    """A row in the operator trace queue: one action request with its latest decision."""

    request_id: str
    trace_id: str
    user_intent: str
    state: str
    decision: str | None
    risk_level: str | None
    has_incident: bool
    created_at: datetime


class Intervention(BaseModel):
    """An operator intervention applied to an incident."""

    type: str
    note: str | None = None


class IncidentOut(BaseModel):
    """Incident detail with its interventions and linked trace id."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    trace_id: str
    request_id: str
    classification: str
    risk_flags: list[str]
    status: str
    interventions: list[dict[str, Any]]
    created_at: datetime
