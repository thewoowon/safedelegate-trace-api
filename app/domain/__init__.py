"""Domain layer: orchestrator, policy gate, tool gateway, adapters, trace, receipt.

Each sub-package is a trust boundary from docs/07_ARCHITECTURE.md and must not be
bypassed for convenience. The deterministic policy gate — never the LLM — decides
authorization; the LLM/mock only plans and explains.
"""
