"""Load synthetic fixtures into the database for a reproducible demo.

The seed is idempotent: running it repeatedly restores the known demo state (used by
``GET /v1/demo/bootstrap`` and by tests). All data is synthetic and clearly labeled.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import models


def _load_json(path: Path) -> Any:
    """Read and parse a JSON fixture file."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _parse_dt(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, accepting a trailing 'Z' for UTC."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def reset_demo_state(db: Session) -> None:
    """Remove all demo-scoped rows so the seed can be re-applied deterministically."""
    for model in (
        models.Incident,
        models.ActionReceipt,
        models.TraceEvent,
        models.Execution,
        models.ToolCall,
        models.Approval,
        models.PolicyEvaluation,
        models.ActionPlan,
        models.ActionRequest,
        models.IdempotencyRecord,
        models.DelegationPolicy,
        models.Agent,
        models.Principal,
    ):
        db.execute(delete(model))
    db.commit()


def seed_demo(db: Session) -> dict[str, int]:
    """Seed principals, agents, and delegation policies from fixtures.

    Returns a count summary for the bootstrap response.
    """
    fixtures = get_settings().fixtures_dir
    reset_demo_state(db)

    users = _load_json(fixtures / "users.json")
    for u in users:
        db.add(
            models.Principal(
                id=u["id"],
                display_name=u["display_name"],
                demo_identity_type=u.get("demo_identity_type", "SYNTHETIC"),
                notice=u.get("notice"),
            )
        )

    agents = _load_json(fixtures / "agents.json")
    for a in agents:
        db.add(
            models.Agent(
                id=a["agent_id"],
                name=a["name"],
                owner_institution=a["owner_institution"],
                role=a["role"],
                autonomy_level=a["autonomy_level"],
                model=a["model"],
                allowed_tools=a["allowed_tools"],
                status=a["status"],
                kill_switch_owner=a["kill_switch_owner"],
                jurisdiction_tags=a.get("jurisdiction_tags", []),
            )
        )

    # Flush parents (principals, agents) before children so the foreign keys on
    # delegation_policies resolve. Postgres enforces FKs; without this ordering the
    # single-commit flush can insert a policy before its principal/agent.
    db.flush()

    policies = _load_json(fixtures / "policies.json")
    for p in policies:
        db.add(
            models.DelegationPolicy(
                policy_id=p["policy_id"],
                version=p["version"],
                principal_id=p["principal_id"],
                agent_id=p["agent_id"],
                purpose=p["purpose"],
                allowed_action_types=p["allowed_action_types"],
                allowed_institutions=p["allowed_institutions"],
                allowed_products=p.get("allowed_products", []),
                allowed_data_classes=p["allowed_data_classes"],
                allowed_tools=p["allowed_tools"],
                amount_limit=p.get("amount_limit"),
                counterparty_rules=p.get("counterparty_rules", {}),
                approval_rules=p["approval_rules"],
                valid_from=_parse_dt(p["valid_from"]),
                valid_until=_parse_dt(p["valid_until"]),
                status=p["status"],
            )
        )

    db.commit()
    return {
        "principals": len(users),
        "agents": len(agents),
        "delegations": len(policies),
    }
