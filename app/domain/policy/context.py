"""Immutable inputs a policy evaluation runs against.

The context bundles the principal/agent/policy, the typed plan and its hash, security
signals from untrusted content, and (when re-evaluating at execution time) the human
approval and idempotency key. Rules read only from here — never from global state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.db import models
from app.schemas.plan import ActionPlan
from app.security import SecuritySignals


@dataclass
class EvaluationContext:
    """Everything the ordered rule pipeline needs to reach a decision."""

    principal: models.Principal | None
    agent: models.Agent | None
    policy: models.DelegationPolicy | None
    plan: ActionPlan
    plan_hash: str
    request: models.ActionRequest
    now: datetime
    security: SecuritySignals
    # Present only when re-evaluating at execution time.
    approval: models.Approval | None = None
    idempotency_key: str | None = None
    is_execution: bool = False
