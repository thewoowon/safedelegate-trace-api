"""The 20 ordered deterministic policy rules (docs/09_POLICY_ENGINE.md).

Each rule is a pure function of the EvaluationContext returning a RuleResult with
machine-readable evidence plus plain-language messages for consumer and operator. Rules
never mutate state and never consult an LLM. The engine maps failures to a decision using
each rule's category and the precedence QUARANTINE > DENY > REQUIRE_APPROVAL > ALLOW.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Any

from jsonschema import Draft202012Validator

from app.domain.adapters import TOOL_ARG_SCHEMAS
from app.domain.policy.context import EvaluationContext
from app.domain.timeutil import ensure_utc
from app.schemas.common import RuleStatus, Severity
from app.schemas.evaluation import RuleResult


class Category(StrEnum):
    """How a failing rule influences the final decision."""

    IDENTITY = "IDENTITY"  # -> DENY
    SCOPE = "SCOPE"  # -> DENY
    SECURITY = "SECURITY"  # -> QUARANTINE
    INTEGRITY = "INTEGRITY"  # -> QUARANTINE
    APPROVAL = "APPROVAL"  # -> REQUIRE_APPROVAL
    RISK = "RISK"  # informational / escalation
    IDEMPOTENCY = "IDEMPOTENCY"  # -> DENY at execution time


def _ok(
    rule_id: str, user: str, operator: str, evidence: dict[str, Any] | None = None
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        status=RuleStatus.PASS,
        severity=Severity.LOW,
        evidence=evidence or {},
        user_message=user,
        operator_message=operator,
    )


def _na(rule_id: str, operator: str) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        status=RuleStatus.NOT_APPLICABLE,
        severity=Severity.LOW,
        evidence={},
        user_message="",
        operator_message=operator,
    )


def _fail(
    rule_id: str,
    severity: Severity,
    user: str,
    operator: str,
    evidence: dict[str, Any] | None = None,
) -> RuleResult:
    return RuleResult(
        rule_id=rule_id,
        status=RuleStatus.FAIL,
        severity=severity,
        evidence=evidence or {},
        user_message=user,
        operator_message=operator,
    )


# --- 1. principal_identity_valid ------------------------------------------------------
def principal_identity_valid(ctx: EvaluationContext) -> RuleResult:
    if ctx.principal is None:
        return _fail(
            "principal_identity_valid",
            Severity.HIGH,
            "요청자 신원을 확인할 수 없습니다.",
            "Principal not found for request.",
        )
    return _ok(
        "principal_identity_valid",
        "요청자 신원이 확인되었습니다.",
        "Principal resolved.",
        {"principal_id": ctx.principal.id},
    )


# --- 2. agent_active_and_registered ---------------------------------------------------
def agent_active_and_registered(ctx: EvaluationContext) -> RuleResult:
    if ctx.agent is None:
        return _fail(
            "agent_active_and_registered",
            Severity.HIGH,
            "에이전트가 등록되어 있지 않습니다.",
            "Agent not found in registry.",
        )
    if ctx.agent.status != "ACTIVE":
        return _fail(
            "agent_active_and_registered",
            Severity.HIGH,
            "에이전트가 활성 상태가 아닙니다.",
            f"Agent status is {ctx.agent.status}.",
            {"status": ctx.agent.status},
        )
    return _ok(
        "agent_active_and_registered",
        "에이전트가 등록되어 있고 활성 상태입니다.",
        "Agent active and registered.",
        {"agent_id": ctx.agent.id},
    )


# --- 3. delegation_active -------------------------------------------------------------
def delegation_active(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    if policy is None:
        return _fail(
            "delegation_active",
            Severity.HIGH,
            "위임 정책을 찾을 수 없습니다.",
            "Delegation policy not found.",
        )
    if policy.status != "ACTIVE":
        return _fail(
            "delegation_active",
            Severity.HIGH,
            "위임이 활성 상태가 아닙니다.",
            f"Delegation status is {policy.status}.",
            {"status": policy.status},
        )
    if not (ensure_utc(policy.valid_from) <= ctx.now <= ensure_utc(policy.valid_until)):
        return _fail(
            "delegation_active",
            Severity.HIGH,
            "위임 유효기간이 아닙니다.",
            "Current time is outside the delegation validity window.",
            {
                "valid_from": policy.valid_from.isoformat(),
                "valid_until": policy.valid_until.isoformat(),
            },
        )
    return _ok(
        "delegation_active",
        "위임이 유효기간 내에서 활성 상태입니다.",
        "Delegation active and within validity window.",
    )


# --- 4. purpose_match -----------------------------------------------------------------
def purpose_match(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if policy.purpose and ctx.plan.action_type in policy.allowed_action_types:
        return _ok(
            "purpose_match",
            "요청 목적이 위임 목적과 일치합니다.",
            "Plan purpose aligns with delegation purpose.",
            {"purpose": policy.purpose},
        )
    return _fail(
        "purpose_match",
        Severity.HIGH,
        "요청 목적이 위임한 목적과 일치하지 않습니다.",
        "Plan purpose does not align with delegation purpose.",
    )


# --- 5. action_type_allowed -----------------------------------------------------------
def action_type_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if ctx.plan.action_type in policy.allowed_action_types:
        return _ok(
            "action_type_allowed",
            "허용된 행위 유형입니다.",
            "Action type is within allowed set.",
            {"action_type": ctx.plan.action_type},
        )
    return _fail(
        "action_type_allowed",
        Severity.HIGH,
        "위임 범위에 없는 행위 유형입니다.",
        "Action type is not in the delegation's allowed set.",
        {"action_type": ctx.plan.action_type, "allowed": policy.allowed_action_types},
    )


# --- 6. institution_allowed -----------------------------------------------------------
def institution_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if ctx.plan.institution in policy.allowed_institutions:
        return _ok(
            "institution_allowed",
            "허용된 금융기관입니다.",
            "Institution is allowed.",
            {"institution": ctx.plan.institution},
        )
    return _fail(
        "institution_allowed",
        Severity.HIGH,
        "허용되지 않은 금융기관입니다.",
        "Institution is not allowed.",
        {"institution": ctx.plan.institution, "allowed": policy.allowed_institutions},
    )


# --- 7. product_allowed ---------------------------------------------------------------
def product_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if not policy.allowed_products or ctx.plan.product is None:
        return _na("product_allowed", "No product restriction applies.")
    if ctx.plan.product in policy.allowed_products:
        return _ok(
            "product_allowed",
            "허용된 상품입니다.",
            "Product is allowed.",
            {"product": ctx.plan.product},
        )
    return _fail(
        "product_allowed",
        Severity.HIGH,
        "허용되지 않은 상품입니다.",
        "Product is not allowed.",
        {"product": ctx.plan.product, "allowed": policy.allowed_products},
    )


# --- 8. amount_within_limit -----------------------------------------------------------
def amount_within_limit(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if ctx.plan.amount is None or policy.amount_limit is None:
        return _na("amount_within_limit", "No amount limit applies to this action.")
    requested = int(ctx.plan.amount.get("amount", 0))
    limit = int(policy.amount_limit.get("amount", 0))
    if requested <= limit:
        return _ok(
            "amount_within_limit",
            "설정한 한도 이내입니다.",
            "Requested amount within limit.",
            {"requested": requested, "limit": limit},
        )
    return _fail(
        "amount_within_limit",
        Severity.HIGH,
        f"설정한 {limit:,}원 한도를 초과했습니다.",
        "Requested amount exceeds delegation policy limit.",
        {
            "requested": requested,
            "limit": limit,
            "currency": ctx.plan.amount.get("currency", "KRW"),
        },
    )


# --- 9. counterparty_allowed ----------------------------------------------------------
def counterparty_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    rules = policy.counterparty_rules or {}
    if rules.get("mode") in (None, "NOT_APPLICABLE"):
        return _na("counterparty_allowed", "Counterparty rules not applicable.")
    if ctx.plan.counterparty is None:
        return _ok(
            "counterparty_allowed",
            "수취인 정보가 없습니다.",
            "No counterparty in plan.",
        )
    if rules.get("mode") == "EXISTING_ONLY" and ctx.plan.counterparty.get("is_new"):
        return _fail(
            "counterparty_allowed",
            Severity.HIGH,
            "신규 수취인은 허용되지 않습니다.",
            "New counterparty is prohibited by policy.",
            {"mode": rules.get("mode")},
        )
    return _ok(
        "counterparty_allowed",
        "허용된 수취인입니다.",
        "Counterparty allowed.",
    )


# --- 10. data_access_allowed ----------------------------------------------------------
def data_access_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    used = [d.data_class for d in ctx.plan.required_data]
    disallowed = [c for c in used if c not in policy.allowed_data_classes]
    if disallowed:
        return _fail(
            "data_access_allowed",
            Severity.HIGH,
            "허용되지 않은 데이터에 접근하려 했습니다.",
            "Plan accesses data classes outside the allowlist.",
            {"disallowed": disallowed, "allowed": policy.allowed_data_classes},
        )
    return _ok(
        "data_access_allowed",
        "허용된 데이터만 사용합니다.",
        "All accessed data classes are allowed.",
        {"used": used},
    )


# --- 11. tool_allowed -----------------------------------------------------------------
def tool_allowed(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    tools = [c.tool for c in ctx.plan.proposed_tool_calls]
    disallowed = [t for t in tools if t not in policy.allowed_tools]
    if disallowed:
        return _fail(
            "tool_allowed",
            Severity.HIGH,
            "위임 범위에 없는 도구를 호출하려 했습니다.",
            "Plan proposes tools outside the allowlist.",
            {"disallowed": disallowed, "allowed": policy.allowed_tools},
        )
    return _ok(
        "tool_allowed",
        "허용된 도구만 사용합니다.",
        "All proposed tools are allowlisted.",
        {"tools": tools},
    )


# --- 12. tool_arguments_schema_valid --------------------------------------------------
def tool_arguments_schema_valid(ctx: EvaluationContext) -> RuleResult:
    errors: list[str] = []
    for call in ctx.plan.proposed_tool_calls:
        schema = TOOL_ARG_SCHEMAS.get(call.tool)
        if schema is None:
            errors.append(f"{call.tool}: no schema registered")
            continue
        validator = Draft202012Validator(schema)
        for err in validator.iter_errors(call.arguments):
            errors.append(f"{call.tool}: {err.message}")
    if errors:
        return _fail(
            "tool_arguments_schema_valid",
            Severity.HIGH,
            "도구 인자가 유효하지 않습니다.",
            "Tool arguments failed schema validation.",
            {"errors": errors},
        )
    return _ok(
        "tool_arguments_schema_valid",
        "도구 인자가 스키마를 통과했습니다.",
        "Tool arguments valid against schemas.",
    )


# --- 13. untrusted_instruction_boundary_intact ---------------------------------------
def untrusted_instruction_boundary_intact(ctx: EvaluationContext) -> RuleResult:
    if ctx.security.attempted_unauthorized_tools:
        return _fail(
            "untrusted_instruction_boundary_intact",
            Severity.CRITICAL,
            "외부 문서가 위임 범위 밖의 실행을 유도했습니다.",
            "Untrusted content attempted to invoke tools outside the delegated authority.",
            {"attempted_tools": ctx.security.attempted_unauthorized_tools},
        )
    return _ok(
        "untrusted_instruction_boundary_intact",
        "외부 콘텐츠는 데이터로만 처리되었습니다.",
        "Untrusted content treated as data; boundary intact.",
    )


# --- 14. prompt_injection_not_detected -----------------------------------------------
def prompt_injection_not_detected(ctx: EvaluationContext) -> RuleResult:
    if ctx.security.injection_detected:
        return _fail(
            "prompt_injection_not_detected",
            Severity.CRITICAL,
            "외부 데이터에서 비정상적인 실행 지시가 발견되었습니다.",
            "Prompt-injection indicators detected in untrusted content.",
            {"matches": ctx.security.injection_matches},
        )
    return _ok(
        "prompt_injection_not_detected",
        "프롬프트 인젝션 징후가 없습니다.",
        "No prompt-injection indicators.",
    )


# --- 15. sensitive_data_exfiltration_not_detected ------------------------------------
def sensitive_data_exfiltration_not_detected(ctx: EvaluationContext) -> RuleResult:
    if ctx.security.exfiltration_detected:
        return _fail(
            "sensitive_data_exfiltration_not_detected",
            Severity.CRITICAL,
            "민감정보를 외부로 전송하려는 시도가 발견되었습니다.",
            "Sensitive-data exfiltration attempt detected.",
            {"matches": ctx.security.exfiltration_matches},
        )
    return _ok(
        "sensitive_data_exfiltration_not_detected",
        "민감정보 유출 시도가 없습니다.",
        "No exfiltration indicators.",
    )


# --- 16. plan_matches_user_intent ----------------------------------------------------
def plan_matches_user_intent(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    tools = [c.tool for c in ctx.plan.proposed_tool_calls]
    broadened = [t for t in tools if t not in policy.allowed_tools]
    if broadened:
        return _fail(
            "plan_matches_user_intent",
            Severity.HIGH,
            "계획이 위임 범위를 벗어나 확장되었습니다.",
            "Plan broadened beyond delegated tools (possible excessive agency).",
            {"broadened_tools": broadened},
        )
    return _ok(
        "plan_matches_user_intent",
        "계획이 요청 의도와 위임 범위에 부합합니다.",
        "Plan consistent with user intent and delegated scope.",
    )


# --- 17. risk_threshold ---------------------------------------------------------------
def risk_threshold(ctx: EvaluationContext) -> RuleResult:
    # Security signals dominate; if any critical signal is present, risk is unacceptable.
    if ctx.security.any_critical:
        return _fail(
            "risk_threshold",
            Severity.CRITICAL,
            "위험도가 허용 임계값을 초과했습니다.",
            "Risk exceeds threshold due to critical security signals.",
        )
    return _ok(
        "risk_threshold",
        "위험도가 허용 범위 내에 있습니다.",
        "Risk within acceptable threshold.",
    )


# --- 18. human_approval_requirement --------------------------------------------------
def human_approval_requirement(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    requires = bool(policy.approval_rules.get("submit_requires_human"))
    submits = any(
        c.tool == "submit_rate_reduction_request" for c in ctx.plan.proposed_tool_calls
    )
    needs_approval = requires and submits
    if not needs_approval:
        return _ok(
            "human_approval_requirement",
            "별도의 인간 승인이 필요하지 않습니다.",
            "No human approval required for this plan.",
        )
    approved = (
        ctx.approval is not None
        and ctx.approval.status == "APPROVED"
        and ctx.approval.approved_plan_hash == ctx.plan_hash
        and ctx.approval.policy_version == policy.version
    )
    if approved:
        return _ok(
            "human_approval_requirement",
            "제출 전 인간 승인이 완료되었습니다.",
            "Required human approval present and binding.",
        )
    return _fail(
        "human_approval_requirement",
        Severity.MEDIUM,
        "제출 전 직접 승인이 필요합니다.",
        "Human approval is required before execution.",
    )


# --- 19. approval_binds_current_plan -------------------------------------------------
def approval_binds_current_plan(ctx: EvaluationContext) -> RuleResult:
    policy = ctx.policy
    assert policy is not None
    if ctx.approval is None:
        return _na("approval_binds_current_plan", "No approval to bind yet.")
    approval = ctx.approval
    if approval.approved_plan_hash != ctx.plan_hash or approval.policy_version != policy.version:
        return _fail(
            "approval_binds_current_plan",
            Severity.CRITICAL,
            "승인이 현재 계획과 일치하지 않습니다. 계획이 변경되었을 수 있습니다.",
            "Approval does not bind the current plan hash/policy version (possible replay).",
            {
                "approved_plan_hash": approval.approved_plan_hash,
                "current_plan_hash": ctx.plan_hash,
                "approval_policy_version": approval.policy_version,
                "current_policy_version": policy.version,
            },
        )
    if approval.expires_at is not None and ctx.now > ensure_utc(approval.expires_at):
        return _fail(
            "approval_binds_current_plan",
            Severity.HIGH,
            "승인이 만료되었습니다.",
            "Approval has expired.",
            {"expires_at": approval.expires_at.isoformat()},
        )
    return _ok(
        "approval_binds_current_plan",
        "승인이 현재 계획에 정확히 결합되어 있습니다.",
        "Approval binds current plan hash and policy version.",
    )


# --- 20. execution_idempotency_key_valid ---------------------------------------------
def execution_idempotency_key_valid(ctx: EvaluationContext) -> RuleResult:
    if not ctx.is_execution:
        return _na("execution_idempotency_key_valid", "Not an execution evaluation.")
    if not ctx.idempotency_key:
        return _fail(
            "execution_idempotency_key_valid",
            Severity.MEDIUM,
            "실행 요청에 멱등 키가 없습니다.",
            "Execution request is missing an idempotency key.",
        )
    return _ok(
        "execution_idempotency_key_valid",
        "실행 멱등 키가 유효합니다.",
        "Idempotency key present.",
    )


# Ordered pipeline with each rule's decision category.
RULES: list[tuple[Callable[[EvaluationContext], RuleResult], Category]] = [
    (principal_identity_valid, Category.IDENTITY),
    (agent_active_and_registered, Category.IDENTITY),
    (delegation_active, Category.IDENTITY),
    (purpose_match, Category.SCOPE),
    (action_type_allowed, Category.SCOPE),
    (institution_allowed, Category.SCOPE),
    (product_allowed, Category.SCOPE),
    (amount_within_limit, Category.SCOPE),
    (counterparty_allowed, Category.SCOPE),
    (data_access_allowed, Category.SCOPE),
    (tool_allowed, Category.SCOPE),
    (tool_arguments_schema_valid, Category.SCOPE),
    (untrusted_instruction_boundary_intact, Category.SECURITY),
    (prompt_injection_not_detected, Category.SECURITY),
    (sensitive_data_exfiltration_not_detected, Category.SECURITY),
    (plan_matches_user_intent, Category.SCOPE),
    (risk_threshold, Category.RISK),
    (human_approval_requirement, Category.APPROVAL),
    (approval_binds_current_plan, Category.INTEGRITY),
    (execution_idempotency_key_valid, Category.IDEMPOTENCY),
]
