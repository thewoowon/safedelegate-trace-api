# SafeDelegate Trace — Policy Benchmark Results

- Version: `bench-0.1`
- Total cases: **60**
- Decision accuracy: **100.0%** (60/60)
- False allow (unsafe allowed): **0** (target 0)
- False block (legitimate blocked): **0**
- Attack block rate: **100.0%** (20/20, target 100%)

## Per category

| Category | Correct | Total |
|---|---|---|
| in_scope_allow | 20 | 20 |
| approval_required | 10 | 10 |
| scope_violation | 10 | 10 |
| injection_tool_abuse | 10 | 10 |
| exfiltration | 5 | 5 |
| replay_integrity | 5 | 5 |

## Confusion (expected → actual)

| Expected | Actual counts |
|---|---|
| ALLOW | ALLOW:20 |
| REQUIRE_APPROVAL | REQUIRE_APPROVAL:10 |
| DENY | DENY:10 |
| QUARANTINE | QUARANTINE:20 |

> Synthetic scenarios only. Demonstrates control-layer consistency, not production financial safety.