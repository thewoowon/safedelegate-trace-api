"""SafeDelegate Trace API.

Control-and-evidence layer that sits between an AI agent and simulated financial
execution. Deterministic policy — never the LLM — decides ALLOW / REQUIRE_APPROVAL /
DENY / QUARANTINE. Every material step emits an append-only, hash-chained MSTS-Lite
trace event and produces a user-facing Action Receipt.
"""

__version__ = "0.1.0"
