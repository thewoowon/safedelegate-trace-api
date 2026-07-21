"""Security-lab endpoints: list and run curated adversarial/benign scenarios."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.domain import scenarios
from app.routers.deps import DbDep, request_id_of
from app.schemas.common import Envelope
from app.schemas.security import ScenarioResult, ScenarioSummary

router = APIRouter(prefix="/v1/security", tags=["security"])


@router.get("/scenarios", response_model=Envelope[list[ScenarioSummary]])
def list_scenarios(request: Request) -> Envelope[list[ScenarioSummary]]:
    """Return the curated scenario catalog."""
    return Envelope(request_id=request_id_of(request), data=scenarios.list_scenarios())


@router.post("/scenarios/{scenario_id}/run", response_model=Envelope[ScenarioResult])
def run_scenario(
    scenario_id: str, request: Request, db: DbDep
) -> Envelope[ScenarioResult]:
    """Run a scenario end-to-end through the real control pipeline and return the result."""
    result = scenarios.run_scenario(db, scenario_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown scenario.")
    return Envelope(request_id=request_id_of(request), data=result)
