"""Deterministic detectors for prompt injection, unauthorized tools, and exfiltration.

Given untrusted document text and the set of allowed tools, produce structured signals:
- injection: the untrusted content tries to override instructions or issue commands,
- attempted_unauthorized_tools: tool names referenced by untrusted content that are not
  in the delegation allowlist,
- exfiltration: an attempt to send sensitive data (balance, account) to an external or
  "verification" destination.

These are curated heuristics, intentionally simple and explainable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Phrases that indicate an attempt to override the instruction hierarchy.
_INJECTION_PATTERNS = [
    r"system\s*override",
    r"ignore\s+(the\s+)?(previous|prior|above|user)",
    r"기존\s*지시\w*\s*무시",
    r"지시\w*\s*무시",
    r"무시하고",
    r"disregard\s+(the\s+)?(policy|instructions)",
    r"정책\w*\s*무시",
]

# Tool-call verbs referenced in free text (used to spot tool names the content wants run).
_TOOL_CALL_HINTS = [r"도구를?\s*호출", r"call\s+\w+", r"호출하여", r"호출하세요"]

# Known sensitive financial tool names that must never be reachable via untrusted content.
_SENSITIVE_TOOL_NAMES = ["transfer_funds", "wire_transfer", "send_money", "disclose_account"]

# Indicators that sensitive data is being routed to an external/verification destination.
_EXFIL_PATTERNS = [
    r"검증\s*계좌",
    r"verification\s+account",
    r"잔액을?\s*.*(전송|보내)",
    r"send\s+.*(balance|account)",
    r"계좌\s*정보를?\s*.*(전송|공유|보내)",
]


def _matches(text: str, patterns: list[str]) -> list[str]:
    """Return the patterns that match ``text`` (case-insensitive)."""
    found: list[str] = []
    for pat in patterns:
        if re.search(pat, text, flags=re.IGNORECASE):
            found.append(pat)
    return found


@dataclass
class SecuritySignals:
    """Structured output of a security scan over untrusted content."""

    injection_detected: bool = False
    injection_matches: list[str] = field(default_factory=list)
    attempted_unauthorized_tools: list[str] = field(default_factory=list)
    exfiltration_detected: bool = False
    exfiltration_matches: list[str] = field(default_factory=list)

    @property
    def any_critical(self) -> bool:
        """True if any signal warrants quarantine."""
        return (
            self.injection_detected
            or bool(self.attempted_unauthorized_tools)
            or self.exfiltration_detected
        )

    def risk_flags(self) -> list[str]:
        """Canonical risk-flag strings for the trace/receipt."""
        flags: list[str] = []
        if self.injection_detected:
            flags.append("INDIRECT_PROMPT_INJECTION")
        if self.attempted_unauthorized_tools:
            flags.append("UNAUTHORIZED_TOOL")
        if self.exfiltration_detected:
            flags.append("DATA_EXFILTRATION_ATTEMPT")
        return flags


def scan(untrusted_text: str | None, allowed_tools: list[str]) -> SecuritySignals:
    """Scan untrusted content and return security signals.

    A None/empty document produces empty signals (the common, safe case).
    """
    signals = SecuritySignals()
    if not untrusted_text:
        return signals

    text = untrusted_text

    injection_matches = _matches(text, _INJECTION_PATTERNS)
    if injection_matches:
        signals.injection_detected = True
        signals.injection_matches = injection_matches

    # A referenced sensitive tool that is not in the allowlist is an unauthorized-tool attempt.
    mentions_tool_call = bool(_matches(text, _TOOL_CALL_HINTS))
    for tool in _SENSITIVE_TOOL_NAMES:
        if re.search(re.escape(tool), text, flags=re.IGNORECASE) and tool not in allowed_tools:
            signals.attempted_unauthorized_tools.append(tool)
    # If the content clearly instructs a tool call but names no known-sensitive tool, and
    # injection is present, still treat the generic tool-call attempt as unauthorized.
    if (
        mentions_tool_call
        and signals.injection_detected
        and not signals.attempted_unauthorized_tools
    ):
        signals.attempted_unauthorized_tools.append("unknown_tool")

    exfil_matches = _matches(text, _EXFIL_PATTERNS)
    if exfil_matches:
        signals.exfiltration_detected = True
        signals.exfiltration_matches = exfil_matches

    return signals
