# Mandate
> Simulated — no real money moves. Prototype for the 2026 Shenzhen International FinTech Competition, International Track, Topic C.

An AI agent handles cross-border student money tasks, **but authority comes from a user-signed policy and every
decision is made by deterministic code, not by an LLM.**

## Team eligibility
<!-- FILL WITH REAL, CONFIRMED FACTS BEFORE SUBMITTING (no placeholders):
All team members are full-time students at [University, Country]. [X] of [Y] members ([Z]%) are non-Chinese nationals. -->

## Status
Built and tested:
- `packages/policy_engine` — deterministic engine, signed decision tokens (purity enforced by a test).
- `services/rail_sim` — SIMULATED sandbox ledger.
- `apps/api` — FastAPI app: isolated reader (no tools), NL→Mandate compiler, planner, registry check,
  router, approvals, executor (single signed path), hash-chained audit log with signed checkpoints.
- `apps/web` — React + Vite + TypeScript + Tailwind UI (Dashboard, Mandate, Pay + Decision Trace,
  Guardian approval, Balances, Activity, Red-team report); en/bn.
- `eval/` — 100-case red-team benchmark (25 families), baselines B0/B1/B2, priority task-completion
  scenarios, report JSON/HTML, and the `docs/execution_evidence/` index + artifacts.
- `apps/web/e2e/` — Playwright flows (E2E-03/04/05/08/10/12) that boot the real API and UI.

Measured on this repo (`eval/reports/latest.json`, replay mode): attack success rate **B0 69.8% · B1 40.6% ·
Mandate 0%** (96 attack cases; 95% Wilson CI [0, 0.039]); false-block rate 0%. Task-completion priority
scenarios: **9/9 ran pass** (T06, duplicate detection, is an honest skip — see the evidence index). These are
static-benchmark, synthetic results — not a claim of general security.

## Quickstart (Linux/macOS; Windows via WSL or `py`)
    make setup && make test && make lint     # engine + API + UI tests
    make eval                                # regenerate the red-team report + task-completion scenarios
    make dev                                 # API on :8000
    cd apps/web && npm install && npm run dev  # UI on :5173 (proxies /api)
    make e2e                                 # Playwright UI flows (boots API + Vite)

The LLM is provider-agnostic: set `LLM_PROVIDER=openai_compat` with `LLM_BASE_URL`/`LLM_API_KEY` to use
DeepSeek v4 (defaults in `.env.example`); `replay` (default) runs fully offline on fixtures.

## Layout
    packages/policy_engine  pure engine (no LLM/network/clock/randomness; purity enforced by a test)
    apps/api                FastAPI: routes, services (executor, registry, router, approvals), agents
    apps/web                React app
    services/rail_sim       SIMULATED sandbox ledger
    data/                   registry, ratecards (SIMULATED), fixtures, demo keys (demo_* only)
    eval/                   attacks, baselines, scenarios, run_eval.py, evidence.py, reports/
    docs/                   specs + technical_documentation.md + security_self_assessment.md + execution_evidence/
    tests/                  integration tests; engine tests live in packages/policy_engine/tests

## Documentation
- `docs/technical_documentation.md` — architecture, core algorithms, security design (submission item 01).
- `docs/security_self_assessment.md` — tiers, trust boundaries, controls, known risks (item 05).
- `docs/execution_evidence/index.md` — scenario and attack results (item 06); audit export, ledger CSV,
  signed checkpoint and LLM config note in the same folder.

## Known limitations
See docs/bugs.md §5–6 and docs/security_self_assessment.md. Caps are single-currency per rule (a mismatched
currency is denied, not converted). The registry is team-enrolled demo data; a signature proves a record was
not altered, not that the institution is genuine.
