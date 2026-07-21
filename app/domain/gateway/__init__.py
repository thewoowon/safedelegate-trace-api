"""Tool Gateway: the only path to an execution adapter.

Validates each tool call against the delegation allowlist and its JSON-Schema argument
contract, records a ToolCall row for every attempt (including blocked ones), and invokes
only registered adapters.
"""

from app.domain.gateway.gateway import execute_plan_tools

__all__ = ["execute_plan_tools"]
