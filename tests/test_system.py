"""Integration tests for the system endpoints (health + demo bootstrap)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert "demo_mode" in body
    assert body["version"]
    # Every response is traceable.
    assert resp.headers.get("X-Request-Id")


def test_demo_bootstrap_seeds_and_is_idempotent(client: TestClient) -> None:
    first = client.get("/v1/demo/bootstrap")
    assert first.status_code == 200
    seeded = first.json()["data"]["seeded"]
    assert seeded == {"principals": 1, "agents": 1, "delegations": 1}
    assert first.json()["request_id"]

    # Re-seeding restores the same known state rather than duplicating rows.
    second = client.get("/v1/demo/bootstrap")
    assert second.status_code == 200
    assert second.json()["data"]["seeded"] == seeded
