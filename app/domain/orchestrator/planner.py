"""Deterministic mock planner.

Given a user request and its delegation policy, produce a typed ActionPlan. The plan is
derived from the *policy* and synthetic loan data — never from untrusted document content
— so an injected instruction cannot broaden the plan. Detection of such injections is the
policy gate's job (see app.security.detectors); the planner simply refuses to act on them.
"""

from __future__ import annotations

from app.db import models
from app.domain.adapters import get_adapter
from app.schemas.plan import ActionPlan, ProposedToolCall, RequiredDatum

# Human-readable reason strings for each data class used as eligibility basis.
_DATA_REASONS = {
    "CURRENT_RATE": "현재 적용 금리 확인 (인하 여력 산정)",
    "INCOME_CHANGE_FLAG": "소득 변동 여부 확인 (신청 자격 근거)",
    "LOAN_BALANCE": "대출 잔액 확인 (신청 서류 구성)",
    "CREDIT_SCORE_BAND": "신용점수 구간 확인 (신청 자격 근거)",
}


def _rate_reduction_plan(policy: models.DelegationPolicy) -> ActionPlan:
    """Build the hero rate-reduction plan from the policy and synthetic loan data."""
    institution = policy.allowed_institutions[0]
    product = policy.allowed_products[0] if policy.allowed_products else None

    # Read synthetic loan data through the adapter to ground the eligibility basis.
    read_profile = get_adapter("read_loan_profile")
    assert read_profile is not None  # registered tool
    profile = read_profile({"institution": institution, "product": product})
    basis = list(profile.get("eligibility", {}).get("reason_codes", []))

    # Only claim data classes the policy actually allows.
    used_classes = [
        c for c in ("CURRENT_RATE", "INCOME_CHANGE_FLAG") if c in policy.allowed_data_classes
    ]
    required_data = [
        RequiredDatum(data_class=c, reason=_DATA_REASONS.get(c, "신청 근거"))
        for c in used_classes
    ]

    submit_needs_human = bool(policy.approval_rules.get("submit_requires_human"))

    return ActionPlan(
        action_type="RATE_REDUCTION_REQUEST",
        institution=institution,
        product=product,
        goal="대출 금리인하요구 조건을 확인하고 신청을 준비하여, 승인 시 제출한다.",
        assumptions=[
            "소득 증가 등 금리인하 요구 자격 조건이 충족되었다고 가정",
            "실행은 시뮬레이션이며 실제 금융거래가 아님",
        ],
        required_data=required_data,
        proposed_tool_calls=[
            ProposedToolCall(
                tool="read_loan_profile",
                arguments={"institution": institution, "product": product},
            ),
            ProposedToolCall(
                tool="prepare_rate_reduction_request",
                arguments={"institution": institution, "product": product, "basis": basis},
            ),
            ProposedToolCall(
                tool="submit_rate_reduction_request",
                arguments={"institution": institution, "product": product},
            ),
        ],
        expected_output="금리인하요구 신청서가 준비되고, 승인 후 제출되어 접수번호가 발급됨.",
        reversibility="REVERSIBLE",
        estimated_risk="MEDIUM",
        approval_reason=(
            "제출은 위임 정책에 따라 제출 전 인간 승인이 필요합니다."
            if submit_needs_human
            else None
        ),
    )


def build_plan(request: models.ActionRequest, policy: models.DelegationPolicy) -> ActionPlan:
    """Return a typed ActionPlan for the request under its policy.

    The mock supports the hero action type. Other action types fall back to a minimal,
    tool-free analysis plan so the lifecycle still produces evidence rather than crashing.
    """
    action_type = policy.allowed_action_types[0] if policy.allowed_action_types else "UNKNOWN"

    if action_type == "RATE_REDUCTION_REQUEST":
        return _rate_reduction_plan(policy)

    # Generic fallback: analysis only, no tool calls.
    return ActionPlan(
        action_type=action_type,
        institution=policy.allowed_institutions[0] if policy.allowed_institutions else "UNKNOWN",
        goal=request.user_request,
        expected_output="분석 결과 요약.",
        reversibility="REVERSIBLE",
        estimated_risk="LOW",
    )
