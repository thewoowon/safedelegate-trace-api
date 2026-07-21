"""Operator (oversight) endpoints: trace queue, incidents, and interventions."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from app.db import models
from app.domain import trace
from app.routers.deps import DbDep, request_id_of
from app.schemas.common import Envelope
from app.schemas.security import IncidentOut, Intervention, OperatorEvent

router = APIRouter(prefix="/v1/operator", tags=["operator"])


@router.get("/events", response_model=Envelope[list[OperatorEvent]])
def list_events(request: Request, db: DbDep) -> Envelope[list[OperatorEvent]]:
    """Return the recent action-request queue with each request's latest decision."""
    requests = db.execute(
        select(models.ActionRequest).order_by(models.ActionRequest.created_at.desc()).limit(50)
    ).scalars().all()

    events: list[OperatorEvent] = []
    for req in requests:
        evaluation = db.execute(
            select(models.PolicyEvaluation)
            .where(models.PolicyEvaluation.request_id == req.id)
            .order_by(models.PolicyEvaluation.created_at.desc())
        ).scalars().first()
        incident = db.execute(
            select(models.Incident).where(models.Incident.request_id == req.id)
        ).scalars().first()
        events.append(
            OperatorEvent(
                request_id=req.id,
                trace_id=req.trace_id,
                user_intent=req.user_request,
                state=req.state,
                decision=evaluation.decision if evaluation else None,
                risk_level=evaluation.risk_level if evaluation else None,
                has_incident=incident is not None,
                created_at=req.created_at,
            )
        )
    return Envelope(request_id=request_id_of(request), data=events)


@router.get("/incidents", response_model=Envelope[list[IncidentOut]])
def list_incidents(request: Request, db: DbDep) -> Envelope[list[IncidentOut]]:
    """List all recorded incidents (quarantine linkage)."""
    rows = db.execute(
        select(models.Incident).order_by(models.Incident.created_at.desc())
    ).scalars().all()
    return Envelope(
        request_id=request_id_of(request),
        data=[IncidentOut.model_validate(r) for r in rows],
    )


@router.get("/incidents/{incident_id}", response_model=Envelope[IncidentOut])
def get_incident(incident_id: str, request: Request, db: DbDep) -> Envelope[IncidentOut]:
    """Return incident detail with its interventions."""
    row = db.get(models.Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return Envelope(request_id=request_id_of(request), data=IncidentOut.model_validate(row))


@router.post("/incidents/{incident_id}/interventions", response_model=Envelope[IncidentOut])
def add_intervention(
    incident_id: str, payload: Intervention, request: Request, db: DbDep
) -> Envelope[IncidentOut]:
    """Apply an operator intervention (e.g. pause agent, revoke tool, close incident)."""
    row = db.get(models.Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found.")
    # Reassign the list so SQLAlchemy detects the JSON column change.
    row.interventions = [*row.interventions, payload.model_dump()]
    if payload.type == "CLOSE_INCIDENT":
        row.status = "CLOSED"
    db.commit()
    db.refresh(row)

    # Append an INTERVENTION_APPLIED event so the reconstruction stays complete.
    trace.append_event(
        db,
        row.trace_id,
        "INTERVENTION_APPLIED",
        {
            "event_type": "INTERVENTION_APPLIED",
            "incident_id": row.id,
            "intervention": payload.model_dump(),
            "override_status": "APPLIED",
        },
    )
    return Envelope(request_id=request_id_of(request), data=IncidentOut.model_validate(row))
