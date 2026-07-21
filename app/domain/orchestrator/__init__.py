"""Agent Orchestrator: converts a user request into a typed ActionPlan.

It may use an LLM or a deterministic fixture-driven mock; either way it CANNOT execute
tools and CANNOT approve its own plan. All retrieved/external text is treated as
untrusted data, never as higher-priority instructions.
"""

from app.domain.orchestrator.planner import build_plan

__all__ = ["build_plan"]
