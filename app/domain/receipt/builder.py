"""Build a user-facing Action Receipt from stored evidence.

Material facts (decision, approval, tools, outcome, integrity hash) are copied from the
stored trace/evaluation — never regenerated from model memory. Wording uses deterministic
templates. A blocked or quarantined action still receives a receipt that clearly states
no execution occurred (docs/11_ACTION_RECEIPT.md).
"""

from __future__ import annotations

import uuid

from app.db import models
from app.schemas.common import Decision, ReceiptStatus
from app.schemas.evaluation import PolicyEvaluationOut
from app.schemas.plan import ActionPlan
from app.schemas.receipt import (
    SCHEMA_VERSION,
    ActionReceiptOut,
    ReceiptExplanation,
    ReceiptIntegrity,
)


def _status_and_headline(
    decision: Decision, executed: models.Execution | None
) -> tuple[ReceiptStatus, str]:
    """Derive the receipt status and its ten-second headline from the decision/outcome."""
    if decision == Decision.QUARANTINE:
        return (
            ReceiptStatus.QUARANTINED,
            "실행이 차단되고 격리되었습니다. 계좌 정보는 전송되지 않았습니다.",
        )
    if decision == Decision.DENY:
        return ReceiptStatus.BLOCKED, "요청이 위임 범위를 벗어나 실행이 차단되었습니다."
    if executed is not None and executed.status == "FAILED_SAFE":
        return ReceiptStatus.FAILED_SAFE, "실행이 안전하게 중단되었습니다. 재시도되지 않았습니다."
    if executed is not None and executed.status == "SUBMITTED":
        return ReceiptStatus.COMPLETED, "금리인하요구 신청이 승인 후 제출되었습니다."
    return ReceiptStatus.APPROVAL_REQUIRED, "제출 전 직접 승인이 필요합니다."


def build_receipt(
    *,
    request: models.ActionRequest,
    plan: ActionPlan,
    plan_hash: str,
    evaluation: PolicyEvaluationOut,
    approval: models.Approval | None,
    execution: models.Execution | None,
    tool_calls: list[models.ToolCall],
    final_event_hash: str,
    canonicalization_version: str,
) -> ActionReceiptOut:
    """Assemble the receipt object from stored evidence."""
    status, headline = _status_and_headline(evaluation.decision, execution)

    failed_reasons = [
        r.user_message
        for r in evaluation.rule_results
        if r.status.value == "FAIL" and r.user_message
    ]
    passed_reasons = [
        "허용된 은행과 상품",
        "허용된 데이터만 사용",
    ]
    if approval is not None and approval.status == "APPROVED":
        passed_reasons.append("제출 전 인간 승인 완료")

    if evaluation.decision in (Decision.ALLOW, Decision.REQUIRE_APPROVAL):
        summary = "설정한 범위 안에서 신청이 처리되었고, 필요한 경우 직접 승인했습니다."
        reasons = passed_reasons
    else:
        summary = "위임 범위를 벗어나거나 안전하지 않은 실행이 감지되어 차단했습니다."
        reasons = failed_reasons or ["정책 위반 감지"]

    human_approval = None
    if approval is not None:
        human_approval = {
            "status": approval.status,
            "approved_plan_hash": approval.approved_plan_hash,
            "approver_id": approval.approver_id,
        }

    actual_outcome = None
    if execution is not None:
        actual_outcome = {"status": execution.status, **execution.outcome}

    security_flags = [
        r.rule_id
        for r in evaluation.rule_results
        if r.status.value == "FAIL" and r.severity.value == "CRITICAL"
    ]

    return ActionReceiptOut(
        schema_version=SCHEMA_VERSION,
        receipt_id=str(uuid.uuid4()),
        trace_id=request.trace_id,
        status=status,
        headline=headline,
        user_request=request.user_request,
        agent_plan={"action_type": plan.action_type, "institution": plan.institution},
        authorization={
            "policy_id": evaluation.policy_id,
            "policy_version": evaluation.policy_version,
            "matched": evaluation.decision in (Decision.ALLOW, Decision.REQUIRE_APPROVAL),
        },
        safety_decision={
            "decision": evaluation.decision.value,
            "risk_level": evaluation.risk_level.value,
            "flags": security_flags,
        },
        human_approval=human_approval,
        actual_outcome=actual_outcome,
        data_used=[{"class": d.data_class, "purpose": d.reason} for d in plan.required_data],
        tools_used=[{"name": tc.tool_name, "status": tc.status} for tc in tool_calls],
        explanation=ReceiptExplanation(summary=summary, reasons=reasons),
        next_actions=(
            [{"type": "VIEW_STATUS", "label": "신청 상태 확인"}]
            if status == ReceiptStatus.COMPLETED
            else [{"type": "REVIEW_INCIDENT", "label": "차단 사유 자세히 보기"}]
        ),
        integrity=ReceiptIntegrity(
            event_hash=final_event_hash,
            canonicalization_version=canonicalization_version,
        ),
    )
