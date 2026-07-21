"""Phase 3 tests: security scenarios, operator console, and trace tamper detection."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models
from app.domain import trace


def _bootstrap(client: TestClient) -> None:
    assert client.get("/v1/demo/bootstrap").status_code == 200


def test_list_scenarios(client: TestClient) -> None:
    resp = client.get("/v1/security/scenarios")
    assert resp.status_code == 200
    ids = {s["scenario_id"] for s in resp.json()["data"]}
    assert {
        "rate-reduction-success",
        "indirect-prompt-injection",
        "scope-exceeded-transfer",
        "approval-replay",
    } <= ids


def test_scenario_outcomes_match_expectations(client: TestClient) -> None:
    _bootstrap(client)
    expectations = {
        "rate-reduction-success": ("REQUIRE_APPROVAL", True),
        "indirect-prompt-injection": ("QUARANTINE", False),
        "scope-exceeded-transfer": ("DENY", False),
        "approval-replay": ("QUARANTINE", False),
    }
    for scenario_id, (expected_decision, executed) in expectations.items():
        resp = client.post(f"/v1/security/scenarios/{scenario_id}/run")
        assert resp.status_code == 200, scenario_id
        data = resp.json()["data"]
        assert data["actual_decision"] == expected_decision, scenario_id
        assert data["decision_match"] is True, scenario_id
        assert data["executed"] is executed, scenario_id
        # Attacks and blocks must never produce a simulated execution.
        if not executed:
            assert data["no_execution"] is True, scenario_id


def test_injection_scenario_produces_incident_and_blocked_receipt(client: TestClient) -> None:
    _bootstrap(client)
    result = client.post("/v1/security/scenarios/indirect-prompt-injection/run").json()["data"]
    assert result["receipt_id"] is not None
    receipt = client.get(f"/v1/receipts/{result['receipt_id']}").json()["data"]
    assert receipt["status"] == "QUARANTINED"

    incidents = client.get("/v1/operator/incidents").json()["data"]
    assert any(i["request_id"] == result["request_id"] for i in incidents)


def test_operator_events_and_intervention(client: TestClient) -> None:
    _bootstrap(client)
    result = client.post("/v1/security/scenarios/indirect-prompt-injection/run").json()["data"]

    events = client.get("/v1/operator/events").json()["data"]
    assert any(e["request_id"] == result["request_id"] and e["has_incident"] for e in events)

    incidents = client.get("/v1/operator/incidents").json()["data"]
    incident_id = next(i["id"] for i in incidents if i["request_id"] == result["request_id"])

    resp = client.post(
        f"/v1/operator/incidents/{incident_id}/interventions",
        json={"type": "PAUSE_AGENT", "note": "조사 중"},
    )
    assert resp.status_code == 200
    updated = resp.json()["data"]
    assert len(updated["interventions"]) == 1

    close = client.post(
        f"/v1/operator/incidents/{incident_id}/interventions",
        json={"type": "CLOSE_INCIDENT"},
    ).json()["data"]
    assert close["status"] == "CLOSED"


def test_trace_tampering_is_detected(client: TestClient, db_session: Session) -> None:
    _bootstrap(client)
    result = client.post("/v1/security/scenarios/rate-reduction-success/run").json()["data"]
    trace_id = result["trace_id"]

    # Chain is valid immediately after a clean run.
    assert client.get(f"/v1/traces/{trace_id}").json()["data"]["chain_valid"] is True

    # Tamper with a stored event body; the hash chain must no longer verify.
    event = db_session.execute(
        select(models.TraceEvent).where(models.TraceEvent.trace_id == trace_id)
    ).scalars().first()
    assert event is not None
    tampered = dict(event.body)
    tampered["user_intent"] = "TAMPERED"
    event.body = tampered
    db_session.commit()

    assert client.get(f"/v1/traces/{trace_id}").json()["data"]["chain_valid"] is False
    # The verifier agrees when called directly, too.
    events = db_session.execute(
        select(models.TraceEvent)
        .where(models.TraceEvent.trace_id == trace_id)
        .order_by(models.TraceEvent.sequence)
    ).scalars().all()
    assert trace.verify_chain(list(events)) is False
