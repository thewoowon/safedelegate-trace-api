"""Explanatory risk scoring (docs/09_POLICY_ENGINE.md).

The score is explanatory, not the sole authority mechanism: a hard policy violation
overrides it. Components are summed and clamped to 0-100, then bucketed into a level.
"""

from __future__ import annotations

from app.domain.policy.context import EvaluationContext
from app.schemas.common import RiskLevel

_CRITICALITY_BASE = {"LOW": 10, "MEDIUM": 15, "HIGH": 22, "CRITICAL": 30}


def compute_risk(ctx: EvaluationContext, approval_required: bool) -> tuple[int, RiskLevel]:
    """Return (score 0-100, level) for the evaluation context."""
    score = 0

    # base criticality (0-30) — proxied from the plan's estimated risk band.
    score += _CRITICALITY_BASE.get(ctx.plan.estimated_risk, 15)

    # financial exposure (0-20)
    if ctx.plan.amount is not None:
        amount = int(ctx.plan.amount.get("amount", 0))
        score += min(20, amount // 100000)  # 1 point per 100k KRW, capped

    # irreversibility (0-15)
    if ctx.plan.reversibility == "IRREVERSIBLE":
        score += 15
    elif ctx.plan.reversibility == "PARTIALLY_REVERSIBLE":
        score += 7

    # new counterparty / new product (0-10)
    if ctx.plan.counterparty and ctx.plan.counterparty.get("is_new"):
        score += 10

    # data sensitivity (0-10)
    score += min(10, 2 * len(ctx.plan.required_data))

    # external untrusted content (0-10)
    if ctx.request.untrusted_document:
        score += 5
    if ctx.security.injection_detected:
        score += 5

    # anomaly / integrity signal (0-20)
    if ctx.security.exfiltration_detected or ctx.security.attempted_unauthorized_tools:
        score += 20

    # human review mitigation (-0..15)
    if approval_required:
        score -= 10

    score = max(0, min(100, score))
    return score, _level(score)


def _level(score: int) -> RiskLevel:
    if score <= 24:
        return RiskLevel.LOW
    if score <= 49:
        return RiskLevel.MEDIUM
    if score <= 74:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL
