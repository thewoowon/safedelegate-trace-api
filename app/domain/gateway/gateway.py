"""Tool Gateway execution.

Runs the plan's proposed tool calls through allowlist + schema validation, then the
registered adapter. Every attempt is recorded as a ToolCall; a call that fails validation
is recorded as BLOCKED and does not reach an adapter (fail closed).
"""

from __future__ import annotations

import uuid
from typing import Any

from jsonschema import Draft202012Validator
from sqlalchemy.orm import Session

from app.db import models
from app.domain.adapters import TOOL_ARG_SCHEMAS, get_adapter
from app.schemas.plan import ActionPlan


def execute_plan_tools(
    db: Session,
    request: models.ActionRequest,
    plan: ActionPlan,
    allowed_tools: list[str],
) -> tuple[list[models.ToolCall], dict[str, Any] | None]:
    """Execute the plan's tool calls in order.

    Returns (recorded tool calls, final execution outcome). The final outcome is the
    result of the last submitting adapter, used to populate the Execution record.
    """
    recorded: list[models.ToolCall] = []
    final_outcome: dict[str, Any] | None = None

    for call in plan.proposed_tool_calls:
        blocked_reason: str | None = None
        if call.tool not in allowed_tools:
            blocked_reason = "tool_not_allowlisted"
        else:
            schema = TOOL_ARG_SCHEMAS.get(call.tool)
            adapter = get_adapter(call.tool)
            if schema is None or adapter is None:
                blocked_reason = "tool_not_registered"
            else:
                errors = list(Draft202012Validator(schema).iter_errors(call.arguments))
                if errors:
                    blocked_reason = "arguments_invalid"

        if blocked_reason is not None:
            tool_call = models.ToolCall(
                id=str(uuid.uuid4()),
                request_id=request.id,
                tool_name=call.tool,
                arguments=call.arguments,
                status="BLOCKED",
                result={"reason": blocked_reason},
            )
            db.add(tool_call)
            recorded.append(tool_call)
            continue

        adapter = get_adapter(call.tool)
        assert adapter is not None  # guarded above
        result = adapter(call.arguments)
        tool_call = models.ToolCall(
            id=str(uuid.uuid4()),
            request_id=request.id,
            tool_name=call.tool,
            arguments=call.arguments,
            status="COMPLETED",
            result=result,
        )
        db.add(tool_call)
        recorded.append(tool_call)
        if result.get("status") == "SUBMITTED":
            final_outcome = result

    db.commit()
    return recorded, final_outcome
