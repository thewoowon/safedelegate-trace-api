"""Lifecycle service: the server-enforced state machine tying the boundaries together.

Flow (docs/07_ARCHITECTURE.md):
DRAFT -> PLAN_CREATED -> POLICY_EVALUATED
  -> DENIED | QUARANTINED -> RECEIPT_ISSUED
  -> APPROVAL_REQUIRED -> APPROVED | REJECTED
  -> ALLOWED -> EXECUTING -> EXECUTED | FAILED_SAFE -> RECEIPT_ISSUED

Illegal transitions are rejected. The deterministic policy gate — not the LLM — decides
authorization, and execution requires a current ALLOW plus (when applicable) a binding
approval. Every material step appends an MSTS-Lite trace event.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models
from app.domain import trace
from app.domain.gateway import execute_plan_tools
from app.domain.hashing import plan_hash as compute_plan_hash
from app.domain.orchestrator import build_plan
from app.domain.policy import RULE_SET_VERSION, EvaluationContext
from app.domain.policy import evaluate as run_policy
from app.domain.receipt import build_receipt
from app.schemas.common import Decision
from app.schemas.evaluation import PolicyEvaluationOut
from app.schemas.plan import ActionPlan, ActionRequestCreate, PlanOut
from app.schemas.receipt import ActionReceiptOut
from app.security import scan

APPROVAL_TTL = timedelta(hours=1)


class LifecycleError(Exception):
    """Raised on illegal transitions or missing prerequisites; mapped to a 4xx by routers."""

    def __init__(self, code: str, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# --------------------------------------------------------------------------------------
# Loading helpers
# --------------------------------------------------------------------------------------
def _get_request(db: Session, request_id: str) -> models.ActionRequest:
    req = db.get(models.ActionRequest, request_id)
    if req is None:
        raise LifecycleError("request_not_found", "Action request not found.", 404)
    return req


def _load_actors(
    db: Session, request: models.ActionRequest
) -> tuple[models.Principal | None, models.Agent | None, models.DelegationPolicy | None]:
    principal = db.get(models.Principal, request.principal_id)
    agent = db.get(models.Agent, request.agent_id)
    policy = db.get(
        models.DelegationPolicy, (request.policy_id, request.policy_version)
    )
    return principal, agent, policy


def _load_plan(db: Session, request_id: str) -> tuple[models.ActionPlan, ActionPlan]:
    row = db.execute(
        select(models.ActionPlan).where(models.ActionPlan.request_id == request_id)
    ).scalar_one_or_none()
    if row is None:
        raise LifecycleError("plan_not_found", "No plan exists for this request.", 409)
    return row, ActionPlan.model_validate(row.payload)


# --------------------------------------------------------------------------------------
# MSTS-Lite event body
# --------------------------------------------------------------------------------------
def _msts_body(
    request: models.ActionRequest,
    agent: models.Agent | None,
    policy: models.DelegationPolicy | None,
    plan: ActionPlan | None,
    *,
    policy_decision: str,
    human_review_status: str,
    risk_flags: list[str],
    tool_calls: list[dict[str, Any]] | None = None,
    executed_action: dict[str, Any] | None = None,
    post_action_outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct one MSTS-Lite event body (the 29 core fields) from current evidence."""
    model = agent.model if agent else {}
    institution_id = plan.institution if plan else (agent.owner_institution if agent else "UNKNOWN")
    delegated_scope = (
        {
            "allowed_action_types": policy.allowed_action_types,
            "allowed_institutions": policy.allowed_institutions,
            "allowed_products": policy.allowed_products,
            "allowed_data_classes": policy.allowed_data_classes,
            "allowed_tools": policy.allowed_tools,
            "valid_until": policy.valid_until.isoformat(),
        }
        if policy
        else {}
    )
    return {
        "schema_version": "msts-lite-0.1",
        "event_id": str(uuid.uuid4()),
        "trace_id": request.trace_id,
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "jurisdiction": "KR",
        "institution_id": institution_id,
        "principal_id": request.principal_id,
        "agent_id": request.agent_id,
        "agent_role": agent.role if agent else "UNKNOWN",
        "autonomy_level": agent.autonomy_level if agent else "L2",
        "criticality_level": "C2",
        "trigger_type": "USER_DELEGATED",
        "user_intent": request.user_request,
        "delegated_scope": delegated_scope,
        "model_provider": model.get("provider"),
        "model_name": model.get("name"),
        "model_version": model.get("version"),
        "data_sources": (
            [{"class": d.data_class, "purpose": d.reason} for d in plan.required_data]
            if plan
            else []
        ),
        "tool_calls": tool_calls or [],
        "recommended_action": (
            {"action_type": plan.action_type, "institution": plan.institution} if plan else None
        ),
        "executed_action": executed_action,
        "human_review_status": human_review_status,
        "policy_decision": policy_decision,
        "risk_flags": risk_flags,
        "confidence_metadata": {"planner": "deterministic-mock"},
        "override_status": "NONE",
        "post_action_outcome": post_action_outcome,
        "retention_class": "DEMO",
        "supervisory_access_tier": "T2",
    }


# --------------------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------------------
def create_request(db: Session, payload: ActionRequestCreate) -> models.ActionRequest:
    """Create a new action request and open its trace with a REQUEST_RECEIVED event."""
    policy = db.get(models.DelegationPolicy, (payload.policy_id, payload.policy_version))
    if policy is None:
        raise LifecycleError("policy_not_found", "Delegation policy not found.", 404)

    request = models.ActionRequest(
        id=str(uuid.uuid4()),
        principal_id=payload.principal_id,
        agent_id=payload.agent_id,
        policy_id=payload.policy_id,
        policy_version=payload.policy_version,
        user_request=payload.user_request,
        untrusted_document=payload.untrusted_document,
        trace_id=str(uuid.uuid4()),
        state="DRAFT",
    )
    db.add(request)
    db.commit()
    db.refresh(request)

    _, agent, _ = _load_actors(db, request)
    trace.append_event(
        db,
        request.trace_id,
        "REQUEST_RECEIVED",
        _msts_body(
            request, agent, policy, None,
            policy_decision="PENDING",
            human_review_status="NOT_REQUIRED",
            risk_flags=[],
        ),
    )
    return request


def _persist_plan(
    db: Session,
    request: models.ActionRequest,
    agent: models.Agent | None,
    policy: models.DelegationPolicy | None,
    plan: ActionPlan,
) -> str:
    """Store (or replace) the plan, move to PLAN_CREATED, and append a PLAN_CREATED event."""
    payload = plan.model_dump()
    ph = compute_plan_hash(payload)

    # Replace any prior plan (re-planning invalidates a previous approval by hash change).
    existing = db.execute(
        select(models.ActionPlan).where(models.ActionPlan.request_id == request.id)
    ).scalar_one_or_none()
    if existing is not None:
        existing.payload = payload
        existing.plan_hash = ph
    else:
        db.add(
            models.ActionPlan(
                id=str(uuid.uuid4()), request_id=request.id, plan_hash=ph, payload=payload
            )
        )
    request.state = "PLAN_CREATED"
    db.commit()

    trace.append_event(
        db, request.trace_id, "PLAN_CREATED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="PENDING",
            human_review_status="NOT_REQUIRED",
            risk_flags=[],
        ),
    )
    return ph


def create_plan(db: Session, request_id: str) -> PlanOut:
    """Run the orchestrator to produce a typed plan; append a PLAN_CREATED event."""
    request = _get_request(db, request_id)
    if request.state not in ("DRAFT", "PLAN_CREATED"):
        raise LifecycleError("illegal_transition", f"Cannot plan from state {request.state}.")
    _, agent, policy = _load_actors(db, request)
    if policy is None:
        raise LifecycleError("policy_not_found", "Delegation policy not found.", 404)

    plan = build_plan(request, policy)
    ph = _persist_plan(db, request, agent, policy, plan)
    return PlanOut(request_id=request.id, plan_hash=ph, plan=plan)


def store_custom_plan(db: Session, request_id: str, plan: ActionPlan) -> PlanOut:
    """Persist a caller-supplied plan (used by the security scenario runner).

    Represents an agent proposing a specific plan; the policy gate still decides.
    """
    request = _get_request(db, request_id)
    _, agent, policy = _load_actors(db, request)
    ph = _persist_plan(db, request, agent, policy, plan)
    return PlanOut(request_id=request.id, plan_hash=ph, plan=plan)


def evaluate(db: Session, request_id: str) -> PolicyEvaluationOut:
    """Evaluate the current plan; set state and, for blocked outcomes, issue a receipt."""
    request = _get_request(db, request_id)
    if request.state not in ("PLAN_CREATED", "POLICY_EVALUATED", "APPROVAL_REQUIRED"):
        raise LifecycleError("illegal_transition", f"Cannot evaluate from state {request.state}.")
    principal, agent, policy = _load_actors(db, request)
    plan_row, plan = _load_plan(db, request.id)

    signals = scan(request.untrusted_document, policy.allowed_tools if policy else [])
    ctx = EvaluationContext(
        principal=principal,
        agent=agent,
        policy=policy,
        plan=plan,
        plan_hash=plan_row.plan_hash,
        request=request,
        now=datetime.now(UTC),
        security=signals,
    )
    result = run_policy(ctx)
    _store_evaluation(db, request, result)

    trace.append_event(
        db, request.trace_id, "POLICY_EVALUATED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision=result.decision.value,
            human_review_status=(
                "PENDING" if result.decision == Decision.REQUIRE_APPROVAL else "NOT_REQUIRED"
            ),
            risk_flags=signals.risk_flags(),
        ),
    )

    if result.decision == Decision.QUARANTINE:
        request.state = "QUARANTINED"
        db.commit()
        _handle_blocked(db, request, agent, policy, plan, plan_row.plan_hash, result, signals)
    elif result.decision == Decision.DENY:
        request.state = "DENIED"
        db.commit()
        _handle_blocked(db, request, agent, policy, plan, plan_row.plan_hash, result, signals)
    elif result.decision == Decision.REQUIRE_APPROVAL:
        request.state = "APPROVAL_REQUIRED"
        db.commit()
        trace.append_event(
            db, request.trace_id, "APPROVAL_REQUESTED",
            _msts_body(
                request, agent, policy, plan,
                policy_decision=result.decision.value,
                human_review_status="PENDING",
                risk_flags=signals.risk_flags(),
            ),
        )
    else:  # ALLOW
        request.state = "ALLOWED"
        db.commit()
    return result


def approve(db: Session, request_id: str, approver_id: str) -> models.Approval:
    """Record a human approval bound to the exact current plan hash and policy version."""
    request = _get_request(db, request_id)
    if request.state != "APPROVAL_REQUIRED":
        raise LifecycleError("illegal_transition", f"Cannot approve from state {request.state}.")
    _, agent, policy = _load_actors(db, request)
    plan_row, plan = _load_plan(db, request.id)

    # The acting agent cannot approve its own high-risk request (no self-approval).
    if approver_id == request.agent_id:
        raise LifecycleError(
            "self_approval_forbidden", "An agent cannot approve its own request.", 403
        )

    approval = models.Approval(
        id=str(uuid.uuid4()),
        request_id=request.id,
        status="APPROVED",
        approved_plan_hash=plan_row.plan_hash,
        policy_version=request.policy_version,
        approver_id=approver_id,
        expires_at=datetime.now(UTC) + APPROVAL_TTL,
    )
    db.add(approval)
    request.state = "APPROVED"
    db.commit()
    db.refresh(approval)

    trace.append_event(
        db, request.trace_id, "APPROVAL_GRANTED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="REQUIRE_APPROVAL",
            human_review_status="APPROVED",
            risk_flags=[],
        ),
    )
    return approval


def reject(db: Session, request_id: str, approver_id: str) -> models.Approval:
    """Record a human rejection and close the request without execution."""
    request = _get_request(db, request_id)
    if request.state != "APPROVAL_REQUIRED":
        raise LifecycleError("illegal_transition", f"Cannot reject from state {request.state}.")
    _, agent, policy = _load_actors(db, request)
    plan_row, plan = _load_plan(db, request.id)

    approval = models.Approval(
        id=str(uuid.uuid4()),
        request_id=request.id,
        status="REJECTED",
        approved_plan_hash=plan_row.plan_hash,
        policy_version=request.policy_version,
        approver_id=approver_id,
    )
    db.add(approval)
    request.state = "REJECTED"
    db.commit()
    db.refresh(approval)

    trace.append_event(
        db, request.trace_id, "APPROVAL_REJECTED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="REQUIRE_APPROVAL",
            human_review_status="REJECTED",
            risk_flags=[],
        ),
    )
    return approval


def execute(db: Session, request_id: str, idempotency_key: str | None) -> ActionReceiptOut:
    """Re-evaluate with the approval bound, run the tool gateway, and issue a receipt.

    Fails closed: execution proceeds only if the re-evaluation is ALLOW. A repeated
    idempotency key returns the stored receipt rather than executing again.
    """
    request = _get_request(db, request_id)

    if idempotency_key:
        stored = db.get(models.IdempotencyRecord, (idempotency_key, f"execute:{request.id}"))
        if stored is not None:
            return ActionReceiptOut.model_validate(stored.response)

    if request.state not in ("ALLOWED", "APPROVED"):
        raise LifecycleError("illegal_transition", f"Cannot execute from state {request.state}.")
    principal, agent, policy = _load_actors(db, request)
    plan_row, plan = _load_plan(db, request.id)
    approval = db.execute(
        select(models.Approval)
        .where(models.Approval.request_id == request.id, models.Approval.status == "APPROVED")
        .order_by(models.Approval.created_at.desc())
    ).scalars().first()

    signals = scan(request.untrusted_document, policy.allowed_tools if policy else [])
    ctx = EvaluationContext(
        principal=principal,
        agent=agent,
        policy=policy,
        plan=plan,
        plan_hash=plan_row.plan_hash,
        request=request,
        now=datetime.now(UTC),
        security=signals,
        approval=approval,
        idempotency_key=idempotency_key,
        is_execution=True,
    )
    result = run_policy(ctx)
    _store_evaluation(db, request, result)

    if result.decision != Decision.ALLOW:
        # Fail closed: do not execute; reflect the blocking decision.
        request.state = "QUARANTINED" if result.decision == Decision.QUARANTINE else "DENIED"
        db.commit()
        return _handle_blocked(
            db, request, agent, policy, plan, plan_row.plan_hash, result, signals
        )

    # ALLOW -> execute through the gateway.
    request.state = "EXECUTING"
    db.commit()
    trace.append_event(
        db, request.trace_id, "TOOL_CALL_STARTED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="ALLOW",
            human_review_status="APPROVED" if approval else "NOT_REQUIRED",
            risk_flags=[],
        ),
    )

    tool_calls, outcome = execute_plan_tools(
        db, request, plan, policy.allowed_tools if policy else []
    )

    execution = models.Execution(
        id=str(uuid.uuid4()),
        request_id=request.id,
        idempotency_key=idempotency_key,
        status="SUBMITTED" if outcome else "FAILED_SAFE",
        outcome=outcome or {"status": "NO_EXECUTION"},
    )
    db.add(execution)
    request.state = "EXECUTED" if outcome else "FAILED_SAFE"
    db.commit()

    tool_call_bodies = [{"name": tc.tool_name, "status": tc.status} for tc in tool_calls]
    trace.append_event(
        db, request.trace_id, "TOOL_CALL_COMPLETED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="ALLOW",
            human_review_status="APPROVED" if approval else "NOT_REQUIRED",
            risk_flags=[],
            tool_calls=tool_call_bodies,
            executed_action=outcome,
            post_action_outcome=outcome,
        ),
    )
    final_event = trace.append_event(
        db, request.trace_id, "RECEIPT_ISSUED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision="ALLOW",
            human_review_status="APPROVED" if approval else "NOT_REQUIRED",
            risk_flags=[],
            tool_calls=tool_call_bodies,
            executed_action=outcome,
            post_action_outcome=outcome,
        ),
    )

    receipt = build_receipt(
        request=request,
        plan=plan,
        plan_hash=plan_row.plan_hash,
        evaluation=result,
        approval=approval,
        execution=execution,
        tool_calls=tool_calls,
        final_event_hash=final_event.event_hash,
        canonicalization_version=final_event.canonicalization_version,
    )
    _store_receipt(db, request, receipt)
    request.state = "RECEIPT_ISSUED"
    db.commit()

    if idempotency_key:
        db.add(
            models.IdempotencyRecord(
                key=idempotency_key,
                endpoint=f"execute:{request.id}",
                response=receipt.model_dump(mode="json"),
            )
        )
        db.commit()
    return receipt


# --------------------------------------------------------------------------------------
# Shared internals
# --------------------------------------------------------------------------------------
def _store_evaluation(
    db: Session, request: models.ActionRequest, result: PolicyEvaluationOut
) -> None:
    db.add(
        models.PolicyEvaluation(
            evaluation_id=result.evaluation_id,
            request_id=request.id,
            policy_id=result.policy_id,
            policy_version=result.policy_version,
            rule_set_version=RULE_SET_VERSION,
            plan_hash=result.plan_hash,
            decision=result.decision.value,
            risk_score=result.risk_score,
            risk_level=result.risk_level.value,
            rule_results=[r.model_dump() for r in result.rule_results],
        )
    )
    db.commit()


def _store_receipt(
    db: Session, request: models.ActionRequest, receipt: ActionReceiptOut
) -> None:
    db.add(
        models.ActionReceipt(
            receipt_id=receipt.receipt_id,
            trace_id=request.trace_id,
            request_id=request.id,
            status=receipt.status.value,
            payload=receipt.model_dump(mode="json"),
        )
    )
    db.commit()


def _handle_blocked(
    db: Session,
    request: models.ActionRequest,
    agent: models.Agent | None,
    policy: models.DelegationPolicy | None,
    plan: ActionPlan,
    plan_hash: str,
    result: PolicyEvaluationOut,
    signals: Any,
) -> ActionReceiptOut:
    """Record blocked tool calls, an incident (for quarantine), and a blocked receipt."""
    blocked_tool_calls: list[models.ToolCall] = []
    for tool in signals.attempted_unauthorized_tools:
        tc = models.ToolCall(
            id=str(uuid.uuid4()),
            request_id=request.id,
            tool_name=tool,
            arguments={},
            status="BLOCKED",
            result={"reason": "unauthorized_via_untrusted_content"},
        )
        db.add(tc)
        blocked_tool_calls.append(tc)
    db.commit()

    if blocked_tool_calls:
        trace.append_event(
            db, request.trace_id, "TOOL_CALL_BLOCKED",
            _msts_body(
                request, agent, policy, plan,
                policy_decision=result.decision.value,
                human_review_status="NOT_REQUIRED",
                risk_flags=signals.risk_flags(),
                tool_calls=[
                    {"name": tc.tool_name, "status": "BLOCKED"} for tc in blocked_tool_calls
                ],
            ),
        )

    if result.decision == Decision.QUARANTINE:
        incident = models.Incident(
            id=str(uuid.uuid4()),
            trace_id=request.trace_id,
            request_id=request.id,
            classification="INDIRECT_PROMPT_INJECTION",
            risk_flags=signals.risk_flags(),
        )
        db.add(incident)
        db.commit()
        trace.append_event(
            db, request.trace_id, "INCIDENT_QUARANTINED",
            _msts_body(
                request, agent, policy, plan,
                policy_decision=result.decision.value,
                human_review_status="NOT_REQUIRED",
                risk_flags=signals.risk_flags(),
            ),
        )

    final_event = trace.append_event(
        db, request.trace_id, "RECEIPT_ISSUED",
        _msts_body(
            request, agent, policy, plan,
            policy_decision=result.decision.value,
            human_review_status="NOT_REQUIRED",
            risk_flags=signals.risk_flags(),
            tool_calls=[{"name": tc.tool_name, "status": "BLOCKED"} for tc in blocked_tool_calls],
            post_action_outcome={"status": "NO_EXECUTION"},
        ),
    )

    execution = models.Execution(
        id=str(uuid.uuid4()),
        request_id=request.id,
        status="NO_EXECUTION",
        outcome={"status": "NO_EXECUTION"},
    )
    db.add(execution)
    db.commit()

    receipt = build_receipt(
        request=request,
        plan=plan,
        plan_hash=plan_hash,
        evaluation=result,
        approval=None,
        execution=None,
        tool_calls=blocked_tool_calls,
        final_event_hash=final_event.event_hash,
        canonicalization_version=final_event.canonicalization_version,
    )
    _store_receipt(db, request, receipt)
    request.state = "RECEIPT_ISSUED"
    db.commit()
    return receipt
