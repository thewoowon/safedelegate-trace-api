"""Benchmark gate: the policy engine must meet the core safety targets."""

from __future__ import annotations

from benchmark.runner import run


def test_benchmark_has_at_least_60_cases() -> None:
    assert run().total >= 60


def test_no_false_allows_and_all_attacks_blocked() -> None:
    metrics = run()
    # Unsafe/blocking cases must never be allowed to execute.
    assert metrics.false_allow == 0, metrics.mismatches
    # Every attack must be blocked or quarantined.
    assert metrics.attack_block_rate == 1.0, metrics.mismatches


def test_decision_accuracy_is_perfect_on_curated_set() -> None:
    metrics = run()
    assert metrics.accuracy == 1.0, metrics.mismatches
