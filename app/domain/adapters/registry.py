"""Registry of simulated tools: their JSON-Schema argument contracts and implementations.

The Tool Gateway is the *only* caller of these functions, and only after validating the
tool name against the delegation allowlist and the arguments against the schema here.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.config import get_settings

# JSON Schemas (Draft 2020-12) for each tool's arguments. Anything not listed is unknown
# and rejected by the gateway (fail closed).
TOOL_ARG_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_loan_profile": {
        "type": "object",
        "additionalProperties": False,
        "required": ["institution", "product"],
        "properties": {
            "institution": {"type": "string"},
            "product": {"type": "string"},
        },
    },
    "prepare_rate_reduction_request": {
        "type": "object",
        "additionalProperties": False,
        "required": ["institution", "product", "basis"],
        "properties": {
            "institution": {"type": "string"},
            "product": {"type": "string"},
            "basis": {"type": "array", "items": {"type": "string"}},
        },
    },
    "submit_rate_reduction_request": {
        "type": "object",
        "additionalProperties": False,
        "required": ["institution", "product"],
        "properties": {
            "institution": {"type": "string"},
            "product": {"type": "string"},
        },
    },
}


def _load_loan_profiles() -> list[dict[str, Any]]:
    path: Path = get_settings().fixtures_dir / "loan_profiles.json"
    with path.open(encoding="utf-8") as fh:
        data: list[dict[str, Any]] = json.load(fh)
    return data


def _find_profile(institution: str, product: str) -> dict[str, Any] | None:
    for profile in _load_loan_profiles():
        if profile["institution"] == institution and profile["product"] == product:
            return profile
    return None


def read_loan_profile(args: dict[str, Any]) -> dict[str, Any]:
    """Return synthetic loan data for the requested institution/product."""
    profile = _find_profile(args["institution"], args["product"])
    if profile is None:
        return {"found": False}
    return {
        "found": True,
        "profile_id": profile["profile_id"],
        "data": profile["data"],
        "eligibility": profile["eligibility"],
        "reversible": True,
    }


def prepare_rate_reduction_request(args: dict[str, Any]) -> dict[str, Any]:
    """Simulate assembling (not submitting) a rate-reduction application."""
    return {
        "status": "PREPARED",
        "institution": args["institution"],
        "product": args["product"],
        "basis": args.get("basis", []),
        "reversible": True,
    }


def submit_rate_reduction_request(args: dict[str, Any]) -> dict[str, Any]:
    """Simulate submitting a rate-reduction application and return a demo reference."""
    return {
        "status": "SUBMITTED",
        "institution": args["institution"],
        "product": args["product"],
        "reference": "DEMO-RATE-2026-001",
        "reversible": True,
        "reversal_window_days": 7,
    }


# Tool name -> implementation. Only these are callable.
ADAPTERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "read_loan_profile": read_loan_profile,
    "prepare_rate_reduction_request": prepare_rate_reduction_request,
    "submit_rate_reduction_request": submit_rate_reduction_request,
}


def get_adapter(tool_name: str) -> Callable[[dict[str, Any]], dict[str, Any]] | None:
    """Return the adapter for ``tool_name`` or None if it is not registered."""
    return ADAPTERS.get(tool_name)
