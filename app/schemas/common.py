"""Shared enums and response/error envelopes used across the API boundary.

Domain terminology follows docs/22_GLOSSARY.md and must not be renamed silently.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Decision(StrEnum):
    """Deterministic policy outcomes. Precedence: QUARANTINE > DENY > REQUIRE_APPROVAL > ALLOW."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    QUARANTINE = "QUARANTINE"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AutonomyLevel(StrEnum):
    """L0 analysis · L1 recommend · L2 bounded+approval · L3 bounded autonomous · L4 high."""

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


class CriticalityLevel(StrEnum):
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"


class RuleStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RequestState(StrEnum):
    """Server-enforced lifecycle state machine (docs/07_ARCHITECTURE.md)."""

    DRAFT = "DRAFT"
    PLAN_CREATED = "PLAN_CREATED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    DENIED = "DENIED"
    QUARANTINED = "QUARANTINED"
    ALLOWED = "ALLOWED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED_SAFE = "FAILED_SAFE"
    RECEIPT_ISSUED = "RECEIPT_ISSUED"


class ReceiptStatus(StrEnum):
    COMPLETED = "COMPLETED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BLOCKED = "BLOCKED"
    QUARANTINED = "QUARANTINED"
    FAILED_SAFE = "FAILED_SAFE"


class ErrorBody(BaseModel):
    """Typed, display-safe error body. Never leaks secrets, stack traces, or raw prompts."""

    code: str
    message: str
    details: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    request_id: str
    error: ErrorBody


class Envelope[T](BaseModel):
    """Standard success envelope; every response carries a request_id for traceability."""

    request_id: str
    data: T


class HealthResponse(BaseModel):
    status: str = Field(default="healthy")
    demo_mode: bool
    version: str
