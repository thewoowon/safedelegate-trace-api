"""Run the benchmark and compute correctness + security metrics.

Run as a script to export results:

    python -m benchmark.runner
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.domain.policy import evaluate
from benchmark.cases import BENCHMARK_VERSION, BenchmarkCase, all_cases

_LEGIT_EXPECTED = {"ALLOW", "REQUIRE_APPROVAL"}
_BLOCKING = {"DENY", "QUARANTINE"}


@dataclass
class BenchmarkMetrics:
    """Aggregate metrics for a benchmark run."""

    version: str
    total: int
    correct: int
    accuracy: float
    false_allow: int
    false_block: int
    attack_total: int
    attack_blocked: int
    attack_block_rate: float
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    mismatches: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": datetime.now(UTC).isoformat(),
            "total": self.total,
            "correct": self.correct,
            "accuracy": self.accuracy,
            "false_allow": self.false_allow,
            "false_block": self.false_block,
            "attack_total": self.attack_total,
            "attack_blocked": self.attack_blocked,
            "attack_block_rate": self.attack_block_rate,
            "per_category": self.per_category,
            "confusion": self.confusion,
            "mismatches": self.mismatches,
        }


def run() -> BenchmarkMetrics:
    """Evaluate every case and compute metrics."""
    cases: list[BenchmarkCase] = all_cases()
    correct = 0
    false_allow = 0
    false_block = 0
    attack_total = 0
    attack_blocked = 0
    per_category: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "correct": 0})
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    mismatches: list[dict[str, str]] = []

    for case in cases:
        actual = evaluate(case.ctx).decision.value
        per_category[case.category]["total"] += 1
        confusion[case.expected][actual] += 1

        if actual == case.expected:
            correct += 1
            per_category[case.category]["correct"] += 1
        else:
            mismatches.append(
                {"case_id": case.case_id, "expected": case.expected, "actual": actual}
            )

        # A legitimate case that was allowed to execute unsafely.
        if case.expected in _LEGIT_EXPECTED and actual == "ALLOW" and case.expected != "ALLOW":
            false_allow += 1
        # An unsafe/blocking case that slipped through to ALLOW.
        if case.expected in _BLOCKING and actual == "ALLOW":
            false_allow += 1
        # A legitimate case wrongly blocked.
        if case.expected in _LEGIT_EXPECTED and actual in _BLOCKING:
            false_block += 1

        if case.attack:
            attack_total += 1
            if actual in _BLOCKING:
                attack_blocked += 1

    total = len(cases)
    return BenchmarkMetrics(
        version=BENCHMARK_VERSION,
        total=total,
        correct=correct,
        accuracy=round(correct / total, 4) if total else 0.0,
        false_allow=false_allow,
        false_block=false_block,
        attack_total=attack_total,
        attack_blocked=attack_blocked,
        attack_block_rate=round(attack_blocked / attack_total, 4) if attack_total else 0.0,
        per_category={k: dict(v) for k, v in per_category.items()},
        confusion={k: dict(v) for k, v in confusion.items()},
        mismatches=mismatches,
    )


def _to_markdown(m: BenchmarkMetrics) -> str:
    lines = [
        "# SafeDelegate Trace — Policy Benchmark Results",
        "",
        f"- Version: `{m.version}`",
        f"- Total cases: **{m.total}**",
        f"- Decision accuracy: **{m.accuracy:.1%}** ({m.correct}/{m.total})",
        f"- False allow (unsafe allowed): **{m.false_allow}** (target 0)",
        f"- False block (legitimate blocked): **{m.false_block}**",
        f"- Attack block rate: **{m.attack_block_rate:.1%}** "
        f"({m.attack_blocked}/{m.attack_total}, target 100%)",
        "",
        "## Per category",
        "",
        "| Category | Correct | Total |",
        "|---|---|---|",
    ]
    for cat, stats in m.per_category.items():
        lines.append(f"| {cat} | {stats['correct']} | {stats['total']} |")
    lines += [
        "",
        "## Confusion (expected → actual)",
        "",
        "| Expected | Actual counts |",
        "|---|---|",
    ]
    for expected, actuals in m.confusion.items():
        pairs = ", ".join(f"{a}:{c}" for a, c in actuals.items())
        lines.append(f"| {expected} | {pairs} |")
    if m.mismatches:
        lines += ["", "## Mismatches", ""]
        for mm in m.mismatches:
            lines.append(f"- `{mm['case_id']}`: expected {mm['expected']}, got {mm['actual']}")
    lines.append("")
    lines.append(
        "> Synthetic scenarios only. Demonstrates control-layer consistency, not "
        "production financial safety."
    )
    return "\n".join(lines)


def export(results_dir: Path | None = None) -> Path:
    """Write results.json and results.md; return the results directory."""
    metrics = run()
    out = results_dir or (Path(__file__).resolve().parent / "results")
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(
        json.dumps(metrics.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / "results.md").write_text(_to_markdown(metrics), encoding="utf-8")
    return out


if __name__ == "__main__":
    metrics = run()
    path = export()
    print(f"Benchmark: {metrics.correct}/{metrics.total} correct "
          f"({metrics.accuracy:.1%}), attack block {metrics.attack_block_rate:.1%}, "
          f"false_allow={metrics.false_allow}")
    print(f"Results written to {path}")
