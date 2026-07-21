"""Agent registry and delegation policy endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.db import models
from app.routers.deps import DbDep, request_id_of
from app.schemas.common import Envelope
from app.schemas.delegation import DelegationPolicyCreate, DelegationPolicyOut
from app.schemas.registry import AgentOut

router = APIRouter(prefix="/v1", tags=["delegation"])


@router.get("/agents", response_model=Envelope[list[AgentOut]])
def list_agents(request: Request, db: DbDep) -> Envelope[list[AgentOut]]:
    """List registered agents."""
    agents = db.execute(select(models.Agent)).scalars().all()
    return Envelope(
        request_id=request_id_of(request),
        data=[AgentOut.model_validate(a) for a in agents],
    )


@router.get("/delegations", response_model=Envelope[list[DelegationPolicyOut]])
def list_delegations(request: Request, db: DbDep) -> Envelope[list[DelegationPolicyOut]]:
    """List delegation policies (all versions)."""
    rows = db.execute(select(models.DelegationPolicy)).scalars().all()
    return Envelope(
        request_id=request_id_of(request),
        data=[DelegationPolicyOut.model_validate(r) for r in rows],
    )


@router.get("/delegations/{policy_id}", response_model=Envelope[DelegationPolicyOut])
def get_delegation(
    policy_id: str, request: Request, db: DbDep
) -> Envelope[DelegationPolicyOut]:
    """Return the latest version of a delegation policy."""
    row = db.execute(
        select(models.DelegationPolicy)
        .where(models.DelegationPolicy.policy_id == policy_id)
        .order_by(models.DelegationPolicy.version.desc())
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Delegation policy not found.")
    return Envelope(request_id=request_id_of(request), data=DelegationPolicyOut.model_validate(row))


@router.post("/delegations", response_model=Envelope[DelegationPolicyOut], status_code=201)
def create_delegation(
    payload: DelegationPolicyCreate, request: Request, db: DbDep
) -> Envelope[DelegationPolicyOut]:
    """Create a delegation policy version."""
    existing = db.get(models.DelegationPolicy, (payload.policy_id, payload.version))
    if existing is not None:
        raise HTTPException(status_code=409, detail="Policy version already exists.")
    row = models.DelegationPolicy(
        policy_id=payload.policy_id or f"policy-{uuid.uuid4().hex[:8]}",
        version=payload.version,
        principal_id=payload.principal_id,
        agent_id=payload.agent_id,
        purpose=payload.purpose,
        allowed_action_types=payload.allowed_action_types,
        allowed_institutions=payload.allowed_institutions,
        allowed_products=payload.allowed_products,
        allowed_data_classes=payload.allowed_data_classes,
        allowed_tools=payload.allowed_tools,
        amount_limit=payload.amount_limit,
        counterparty_rules=payload.counterparty_rules,
        approval_rules=payload.approval_rules,
        valid_from=payload.valid_from,
        valid_until=payload.valid_until,
        status=payload.status,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return Envelope(request_id=request_id_of(request), data=DelegationPolicyOut.model_validate(row))


@router.post("/delegations/{policy_id}/revoke", response_model=Envelope[DelegationPolicyOut])
def revoke_delegation(
    policy_id: str, request: Request, db: DbDep
) -> Envelope[DelegationPolicyOut]:
    """Revoke the latest version of a delegation policy (disables new authorizations)."""
    row = db.execute(
        select(models.DelegationPolicy)
        .where(models.DelegationPolicy.policy_id == policy_id)
        .order_by(models.DelegationPolicy.version.desc())
    ).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Delegation policy not found.")
    row.status = "REVOKED"
    db.commit()
    db.refresh(row)
    return Envelope(request_id=request_id_of(request), data=DelegationPolicyOut.model_validate(row))
