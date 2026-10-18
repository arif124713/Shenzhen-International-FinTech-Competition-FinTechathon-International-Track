"""Task-completion scenario suite (testing.md §5) run against the real engine, registry, executor,
router and audit log. Offline and deterministic: no LLM, no network, no clock.

Each scenario scripts a seed state, a sequence of engine/executor steps, and an *expected final state*
(decision, ledger delta, audit events). Completion = the final state matches. Results feed the
`scenarios` block of `eval/reports/latest.json` (testing.md §10) and the evidence index.

Scope: the 48-hour priority subset — T01, T02, T06, T07, T08, R02, R05, R06, R07, P01 (testing.md §5).
A scenario that cannot run on the current system is reported as `skipped` with a reason, never as a pass.
"""
from __future__ import annotations
