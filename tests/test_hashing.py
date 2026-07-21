"""Unit tests for canonical JSON, plan hashing, and hash-chain tamper detection."""

from __future__ import annotations

from app.domain.hashing import (
    GENESIS_HASH,
    canonicalize,
    chain_hash,
    plan_hash,
    sha256_hex,
)


def test_canonicalize_is_key_order_independent() -> None:
    a = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    b = {"a": 2, "nested": {"x": 2, "y": 1}, "b": 1}
    assert canonicalize(a) == canonicalize(b)


def test_sha256_is_deterministic() -> None:
    payload = {"action_type": "RATE_REDUCTION_REQUEST", "amount": None}
    assert sha256_hex(payload) == sha256_hex(dict(reversed(list(payload.items()))))


def test_plan_hash_changes_when_plan_changes() -> None:
    base = {"action_type": "RATE_REDUCTION_REQUEST", "institution": "HANUL_BANK"}
    changed = {**base, "institution": "OTHER_BANK"}
    assert plan_hash(base) != plan_hash(changed)


def test_chain_hash_is_64_hex_and_secret_sensitive() -> None:
    body = {"event": "PLAN_CREATED"}
    h1 = chain_hash(GENESIS_HASH, body, secret="secret-a")
    h2 = chain_hash(GENESIS_HASH, body, secret="secret-b")
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)
    assert h1 != h2  # keyed chain: different secret -> different hash


def test_chain_links_depend_on_predecessor() -> None:
    body = {"event": "X"}
    first = chain_hash(GENESIS_HASH, body, secret="s")
    second_after_first = chain_hash(first, body, secret="s")
    second_after_genesis = chain_hash(GENESIS_HASH, body, secret="s")
    # Same body, different predecessor -> different hash (ordering is bound in).
    assert second_after_first != second_after_genesis
