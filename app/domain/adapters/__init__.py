"""Simulated financial execution adapters.

Adapters simulate outcomes only: no real accounts, transfers, or PII. Each adapter is
idempotent and exposes reversibility metadata. Adapters never accept arbitrary shell,
URL, or database commands — only their declared, schema-validated arguments.
"""

from app.domain.adapters.registry import ADAPTERS, TOOL_ARG_SCHEMAS, get_adapter

__all__ = ["ADAPTERS", "TOOL_ARG_SCHEMAS", "get_adapter"]
