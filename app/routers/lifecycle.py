"""Action lifecycle endpoints: request -> plan -> evaluate -> approve/reject -> execute."""

from __future__ import annotations

from fastapi import APIRouter, Header, Request

from app.domain import lifecycle
from app.routers.deps import DbDep, request_id_of
from app.schemas.common import Envelope
from app.schemas.evaluation import PolicyEvaluationOut
from app.schemas.plan import ActionRequestCreate, ActionRequestOut, PlanOut
from app.schemas.receipt import ActionReceiptOut

router = APIRouter(prefix="/v1/action-requests", tags=["lifecycle"])


def _to_out(req) -> ActionRequestOut:  # type: ignore[no-untyped-def]
    return ActionRequestOut(
        id=req.id,
        principal_id=req.principal_id,
        agent_id=req.agent_id,
        policy_id=req.policy_id,
        policy_version=req.policy_version,
        user_request=req.user_request,
        trace_id=req.trace_id,
        state=req.state,
    )


@router.post("", response_model=Envelope[ActionRequestOut], status_code=201)
def create_action_request(
    payload: ActionRequestCreate, request: Request, db: DbDep
) -> Envelope[ActionRequestOut]:
    """Create a new action request and open its trace."""
    req = lifecycle.create_request(db, payload)
    return Envelope(request_id=request_id_of(request), data=_to_out(req))


@router.get("/{request_id}", response_model=Envelope[ActionRequestOut])
def get_action_request(
    request_id: str, request: Request, db: DbDep
) -> Envelope[ActionRequestOut]:
    """Return the current lifecycle view of an action request."""
    req = lifecycle._get_request(db, request_id)
    return Envelope(request_id=request_id_of(request), data=_to_out(req))


@router.post("/{request_id}/plan", response_model=Envelope[PlanOut])
def create_plan(request_id: str, request: Request, db: DbDep) -> Envelope[PlanOut]:
    """Produce the typed action plan for the request."""
    plan = lifecycle.create_plan(db, request_id)
    return Envelope(request_id=request_id_of(request), data=plan)


@router.post("/{request_id}/evaluate", response_model=Envelope[PolicyEvaluationOut])
def evaluate(request_id: str, request: Request, db: DbDep) -> Envelope[PolicyEvaluationOut]:
    """Run the deterministic policy gate over the current plan."""
    result = lifecycle.evaluate(db, request_id)
    return Envelope(request_id=request_id_of(request), data=result)


@router.post("/{request_id}/approve", response_model=Envelope[ActionRequestOut])
def approve(
    request_id: str,
    request: Request,
    db: DbDep,
    approver_id: str = "operator-demo",
) -> Envelope[ActionRequestOut]:
    """Capture explicit human approval bound to the current plan hash."""
    lifecycle.approve(db, request_id, approver_id)
    req = lifecycle._get_request(db, request_id)
    return Envelope(request_id=request_id_of(request), data=_to_out(req))


@router.post("/{request_id}/reject", response_model=Envelope[ActionRequestOut])
def reject(
    request_id: str,
    request: Request,
    db: DbDep,
    approver_id: str = "operator-demo",
) -> Envelope[ActionRequestOut]:
    """Reject the request; no execution occurs."""
    lifecycle.reject(db, request_id, approver_id)
    req = lifecycle._get_request(db, request_id)
    return Envelope(request_id=request_id_of(request), data=_to_out(req))


@router.post("/{request_id}/execute", response_model=Envelope[ActionReceiptOut])
def execute(
    request_id: str,
    request: Request,
    db: DbDep,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> Envelope[ActionReceiptOut]:
    """Execute the approved plan through the simulated tool gateway and issue a receipt."""
    receipt = lifecycle.execute(db, request_id, idempotency_key)
    return Envelope(request_id=request_id_of(request), data=receipt)
