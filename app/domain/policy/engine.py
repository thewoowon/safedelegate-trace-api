"""Policy engine: run the ordered rule pipeline and derive the decision.

Precedence (docs/09_POLICY_ENGINE.md): QUARANTINE > DENY > REQUIRE_APPROVAL > ALLOW.
- Any failing SECURITY or INTEGRITY rule -> QUARANTINE.
- Any failing IDENTITY / SCOPE / IDEMPOTENCY rule -> DENY.
- Otherwise, a failing APPROVAL rule -> REQUIRE_APPROVAL.
- Otherwise -> ALLOW.

The engine returns a fully populated PolicyEvaluationOut with per-rule evidence and the
explanatory risk score. It never raises on rule failure — it fails closed into a decision.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.domain.policy.context import EvaluationContext
from app.domain.policy.risk import compute_risk
from app.domain.policy.rules import RULES, Category
from app.schemas.common import Decision, RuleStatus
from app.schemas.evaluation import PolicyEvaluationOut, RuleResult

RULE_SET_VERSION = "rules-0.1"


def _decide(results: list[RuleResult], categories: dict[str, Category]) -> Decision:
    """Map failing rules to a decision using category precedence."""
    failed = [r for r in results if r.status == RuleStatus.FAIL]
    failed_categories = {categories[r.rule_id] for r in failed}

    if Category.SECURITY in failed_categories or Category.INTEGRITY in failed_categories:
        return Decision.QUARANTINE
    if (
        Category.IDENTITY in failed_categories
        or Category.SCOPE in failed_categories
        or Category.IDEMPOTENCY in failed_categories
    ):
        return Decision.DENY
    if Category.APPROVAL in failed_categories:
        return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW


def evaluate(ctx: EvaluationContext) -> PolicyEvaluationOut:
    """Run all rules and return the immutable evaluation artifact."""
    categories: dict[str, Category] = {}
    results: list[RuleResult] = []
    for rule_fn, category in RULES:
        result = rule_fn(ctx)
        results.append(result)
        categories[result.rule_id] = category

    decision = _decide(results, categories)

    # Approval is "required" for risk mitigation purposes when the approval rule failed
    # (i.e. approval is needed and not yet present) or the decision is REQUIRE_APPROVAL.
    approval_rule = next(
        (r for r in results if r.rule_id == "human_approval_requirement"), None
    )
    approval_required = (
        decision == Decision.REQUIRE_APPROVAL
        or (approval_rule is not None and approval_rule.status == RuleStatus.FAIL)
    )
    risk_score, risk_level = compute_risk(ctx, approval_required)

    policy = ctx.policy
    return PolicyEvaluationOut(
        evaluation_id=str(uuid.uuid4()),
        policy_id=policy.policy_id if policy else "unknown",
        policy_version=policy.version if policy else 0,
        rule_set_version=RULE_SET_VERSION,
        plan_hash=ctx.plan_hash,
        decision=decision,
        risk_score=risk_score,
        risk_level=risk_level,
        rule_results=results,
        created_at=datetime.now(UTC),
    )
