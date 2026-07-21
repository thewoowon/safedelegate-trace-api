"""Security detectors feeding the deterministic policy gate.

These are heuristic, deterministic scanners over *untrusted* content and proposed tool
calls. They do not make authorization decisions; they produce signals that the policy
rules turn into DENY/QUARANTINE outcomes. The MVP demonstrates control behavior against
curated scenarios and does not claim comprehensive protection.
"""

from app.security.detectors import SecuritySignals, scan

__all__ = ["SecuritySignals", "scan"]
