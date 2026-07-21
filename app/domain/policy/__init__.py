"""Deterministic Policy Gate.

Runs an ordered rule pipeline over an immutable policy version and plan hash, returns a
decision + risk score + per-rule evidence, and fails closed. The LLM is never consulted
for authorization (docs/09_POLICY_ENGINE.md).
"""

from app.domain.policy.context import EvaluationContext
from app.domain.policy.engine import RULE_SET_VERSION, evaluate

__all__ = ["EvaluationContext", "RULE_SET_VERSION", "evaluate"]
