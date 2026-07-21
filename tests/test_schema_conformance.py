"""Prove that every bundled fixture conforms to its canonical JSON Schema.

The JSON Schemas in ``schemas/`` are the single source of truth for the API contract.
These tests fail loudly if a fixture drifts from the schema it is supposed to satisfy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

BASE_DIR = Path(__file__).resolve().parent.parent
SCHEMAS = BASE_DIR / "schemas"
FIXTURES = BASE_DIR / "fixtures"


def _load(path: Path):
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(_load(SCHEMAS / schema_name))


@pytest.mark.parametrize("policy", _load(FIXTURES / "policies.json"))
def test_policies_conform(policy: dict) -> None:
    _validator("delegation-policy.schema.json").validate(policy)


@pytest.mark.parametrize("agent", _load(FIXTURES / "agents.json"))
def test_agents_conform(agent: dict) -> None:
    _validator("agent-registry.schema.json").validate(agent)


@pytest.mark.parametrize(
    "receipt_file",
    ["receipts/success.json", "receipts/quarantined.json"],
)
def test_receipts_conform(receipt_file: str) -> None:
    _validator("action-receipt.schema.json").validate(_load(FIXTURES / receipt_file))


def test_all_schemas_are_valid_metaschemas() -> None:
    """Every schema file must itself be a valid Draft 2020-12 schema."""
    for schema_path in SCHEMAS.glob("*.schema.json"):
        Draft202012Validator.check_schema(_load(schema_path))
