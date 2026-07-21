"""Canonical JSON serialization and SHA-256 hashing / hash chaining.

Integrity is evidence-tamper-evidence, not a legal signature or blockchain (D-009).
We use a JCS-style canonical form (RFC 8785 principles): keys sorted lexicographically,
no insignificant whitespace, UTF-8, and a stable representation of scalars. Hashing the
canonical bytes makes an event's hash reproducible and any post-hoc mutation detectable.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

CANONICALIZATION_VERSION = "jcs-0.1"

# The all-zero hash is the conventional "genesis" predecessor for the first event
# in a trace chain.
GENESIS_HASH = "0" * 64


def canonicalize(value: Any) -> str:
    """Return the canonical JSON string for ``value``.

    Object keys are sorted; separators are compact; non-ASCII is preserved (ensure_ascii
    is False) so the same logical content always yields the same bytes regardless of how
    it was constructed.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(value: Any) -> str:
    """Canonicalize ``value`` and return the hex SHA-256 digest of its UTF-8 bytes."""
    canonical = canonicalize(value)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def plan_hash(plan_payload: dict[str, Any]) -> str:
    """Compute the content hash that binds an approval to an exact plan.

    A changed plan produces a different hash, which invalidates any prior approval
    (critical invariant, docs/08_DOMAIN_MODEL.md).
    """
    return sha256_hex(plan_payload)


def chain_hash(previous_event_hash: str, event_body: dict[str, Any], secret: str) -> str:
    """Compute an event's hash from its predecessor, its body, and a keyed secret.

    Including ``previous_event_hash`` links events into a tamper-evident chain; including
    a server-side ``secret`` (TRACE_HASH_SECRET) keys the chain so it cannot be silently
    reconstructed by a party without the secret.
    """
    material = {
        "previous_event_hash": previous_event_hash,
        "event_body": event_body,
    }
    canonical = canonicalize(material)
    return hashlib.sha256(f"{secret}\n{canonical}".encode()).hexdigest()
