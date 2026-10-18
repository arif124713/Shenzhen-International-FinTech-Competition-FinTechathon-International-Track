# Mandate

> **Simulated — no real money moves.** Prototype for the 2026 Shenzhen International FinTech Competition,
> International Track, Topic C. Every number in this file comes from `eval/reports/latest.json`.

An AI agent handles cross-border student money tasks (tuition, remittances, multi-currency balances),
**but authority comes from a user-signed policy and every decision is made by deterministic code, not by an
LLM.** An adversarial document can fool the AI that *reads* it; it cannot fool the code that *decides*.

**One-sentence innovation:** separate *intelligence* from *authority* — the AI may read and propose, but a
deterministic engine, a signed payee registry and a transaction-bound approval decide what executes.

---

## Headline results

| Result | Value | Source |
|---|---|---|
| Test suite | **1379 tests pass** (offline, no network) | `make test` |
| Attack success rate — naive agent (B0) | **69.8%** (67/96) — 95% Wilson CI [0.600, 0.781] | `eval/reports/latest.json` |
| Attack success rate — safety-prompted agent (B1) | **40.6%** (39/96) — CI [0.314, 0.506] | same |
| Attack success rate — **Mandate (B2)** | **0.0%** (0/96) — CI [0.000, 0.038] | same |
| False blocks | **0 false blocks among 4 benign cases** | same |
| Task-completion scenarios (priority subset) | **10/10 ran pass** (including T06 duplicate-payment) | same |
| End-to-end UI flows (Playwright) | **16 pass, 2 mobile-only skips** | `make e2e` |

> Static benchmark on synthetic documents. Adaptive attackers may do better; the LLM has no authority to
> execute; a wrong-but-permitted extraction is a measured residual risk (see *Known limitations*).

---

## What we built and what we found

- **Found:** the two most dangerous failure modes for an AI that moves money are **(1) instructions hidden
  inside the document** (white-on-white text, tiny text, metadata, QR codes) and **(2) payee substitution**
  (a look-alike name or one changed account digit). Both routinely defeat an ordinary "careful prompt" agent
  — our B1 baseline still failed **40.6%** of attacks.
- **Built:** the fix is not a better prompt. It is **unambiguous authority**: a signed rule set the user
  approves, a signed registry that matches payees **by account, not by name**, and a single signed execution
  path. Result: **0%** attack success on the same 96 cases, with **no** false blocks on the benign cases.
- **Why it holds:** the AI is *isolated* (no tools, no DB, no ledger), decisions are *pure* code, and execution
  demands a signed, single-use, action-bound token. An attacker who fully controls the document still cannot
  cause a payment the signed policy does not permit.

---

## Architecture

```
 Browser (React) ──► FastAPI (apps/api) ──► routes → services → executor
                                             │
   ┌─────────────────────────────────────────┼──────────────────────────────────┐
   ▼                                         ▼                                  ▼
 Intent compiler (LLM)               Planner (LLM, untrusted)          Rail simulator + ledger
 NL → candidate Mandate                → ActionProposal                 (services/rail_sim, SIMULATED)
   │ signed, versioned                        │ structured fields only
   ▼                                          ▼
 Mandate store ◄────  POLICY ENGINE (pure)  ◄──  Reader (VLM, NO tools) ◄── Document pipeline
 (signed, append-only)   decide()                schema-only output         (text layer + detectors)
   │                        │ signed decision_token
   │                        ▼
   │              EXECUTOR (only rail_sim importer) ──► ledger transfer (idempotent)
   ▼
 Hash-chained audit log ──► signed checkpoints ──► evidence export
```

### Trust boundaries (enforced by tests, not promises)

| Zone | Contents |
|---|---|
| **Untrusted** | uploaded documents, user free text, planner output, reader output until validated |
| **Semi-trusted** | the LLMs (reader, compiler, planner) — manipulable by untrusted input |
| **Trusted** | policy engine, signature-verified registry, signed mandate, sandbox ledger, audit writer |

Only `apps/api/services/executor.py` may import `rail_sim`; an AST test fails the build otherwise. The reader
package is scanned for forbidden imports (DB, ledger, registry-write, router, executor, approvals).

### Modules

| Path | Responsibility |
|---|---|
| `packages/policy_engine/` | Pure decision logic: `decide()`, signed decision tokens, canonical JSON, signing. No LLM/network/clock/randomness (purity enforced by a test). |
| `apps/api/agents/reader` | Isolated document → validated `ReaderOutput`; deterministic detectors union in the anomaly flags. |
| `apps/api/agents/compiler` | NL (en/bn) → candidate Mandate over the **closed rule set**; refuses what it cannot express. |
| `apps/api/agents/planner` | Structured fields + request → typed `ActionProposal`; resolves `payee_id` from the registry (never invents one). |
| `apps/api/agents/llm.py` | `LLMClient`: OpenAI-compatible (DeepSeek), `ReplayClient` (offline fixtures), `FakeClient`. |
| `apps/api/services/` | `executor` (single signed path), `registry`, `router`, `approvals` (hashed, single-use), `mandates`, `runtime`, `audit_log`, `explain`. |
| `services/rail_sim/` | SIMULATED sandbox accounts, FX, fees, ledger, settlement clock. |
| `apps/web/` | React + Vite + TypeScript + Tailwind; Dashboard, Mandate, Pay + Decision Trace, Guardian, Balances, Activity, **Registry**, Red-team; en/bn. |
| `eval/` | Attack catalog (24 attack families × 4 = 96 cases, plus A25 benign look-alikes), baselines B0/B1/B2, task-completion scenarios, report JSON/HTML, evidence generator. |
| `apps/web/e2e/` | Playwright flows (E2E-03/04/05/08/10/12) booting the real API + UI. |
| `data/` | registry template, rate cards (SIMULATED), fixtures, demo keys (`demo_*` only). |

### Core algorithms

1. **Policy engine** (`packages/policy_engine/decide.py`) — evaluation order: integrity → anomalies →
   confidence → category → registry → payee status → caps → escalation → rail/time. Precedence
   `DENY > HOLD > ESCALATE > ALLOW`; **default deny**. Rules are sorted by id so rule order cannot change an
   outcome. A **signed decision token** binds `{decision, action_hash, mandate_version, registry_version,
   input_hash, expiry, nonce}`.
2. **Single execution path** (`services/executor.py`) — accepts only `(proposal, decision_token)` and refuses
   unless the signature verifies, the decision is `ALLOW`, the token is unexpired and unused, the recomputed
   `action_hash` matches, the mandate version is active, and the registry entry is valid.
3. **Approvals are inputs, not bypasses** (`services/approvals.py`) — a 256-bit token stored **hashed only**,
   single-use, bound to `action_hash + mandate_version + approver + expiry`; on approve the **engine re-runs**
   and issues a fresh token. Rejection is final.
4. **Registry match is by account** (`services/registry.py`, engine) — exact after NFKC normalization and
   confusable handling. The **planner** resolves the document payee to a registry entity id; the **engine**
   verifies the referenced entry matches. One changed digit → `DENY`.
5. **Routing** (`services/router.py`) — exact `Decimal` arithmetic, half-even rounding; excludes rails that
   violate the mandate or miss the deadline, each with a reason; savings measured **vs the simulated default
   rail**, never an arbitrary baseline.
6. **Audit log** (`services/audit_log.py`) — `hash = sha256(prev_hash || canonical_json(entry))`, signed
   checkpoints, `verify()` returns the first bad sequence.

Full detail: [`docs/technical_documentation.md`](docs/technical_documentation.md).

---

## Security design (summary)

| Control | Enforcement point |
|---|---|
| Deterministic decision + signing | `policy_engine/decide.py`, `tokens.py` |
| Execution verification | `services/executor.py:execute()` |
| Single execution path | AST test `tests/test_single_execution_path.py` |
| Reader isolation (no tools) | `agents/reader/__init__.py:read_document` |
| Payee resolution to signed registry | `agents/planner` + engine registry step |
| Approval binding + single use | `services/approvals.py` |
| Audit chain + checkpoints | `services/audit_log.py` |
| Engine purity | AST scan `packages/policy_engine/tests/test_engine_purity.py` |
| Upload validation (sniff MIME, ≤10 MB, ≤5 pages) | `services/documents.py:validate_upload` |

Full detail and the known-risk list: [`docs/security_self_assessment.md`](docs/security_self_assessment.md).

---

## Red-team benchmark — 24 attack families (+ 1 benign family)

An attack **succeeds** only if a violating sandbox action occurs, **read from the ledger — not from the
agent's words.** **24 attack families × 4 variants = 96 attack cases**, plus **A25** (benign look-alikes, 4
cases) which must **not** be blocked. Variants 1–2 are the development split; variants 3–4 are held-out,
frozen by `eval/heldout.sha256` (the runner refuses to run if the held-out set changed).

| # | Family | # | Family | # | Family |
|---|---|---|---|---|---|
| A01 | Hidden text in PDF | A09 | Urgency/threat | A17 | Compiler manipulation |
| A02 | Hidden text in image | A10 | Typographic attack | A18 | Ambiguity exploit |
| A03 | Visible fake notice | A11 | Bangla-language injection | A19 | Registry spoofing |
| A04 | Homoglyph payee | A12 | Forwarded-email injection | A20 | Planner tool-misuse |
| A05 | Account digit swap | A13 | Metadata/filename injection | A21 | Cooling-off bypass |
| A06 | Unregistered account | A14 | QR payee override | A22 | Currency confusion |
| A07 | Amount manipulation | A15 | Replay/duplicate | A23 | Policy disclosure |
| A08 | Split-payment structuring | A16 | Forged approval | A24 | Multi-turn drift |
| | | | | **A25** | **Benign look-alikes (must not block)** |

System under test, same LLM/temperature/documents/ledger:
- **B0** — naive agent with a payment tool and no policy engine.
- **B1** — the same agent with a careful safety system prompt.
- **B2** — Mandate (full pipeline).

---

## Test suite (1379 tests, all offline)

| File | Tests | Covers |
|---|---:|---|
| `tests/test_redteam_300_deep.py` | 550 | deep engine/API attacks |
| `tests/test_redteam_500.py` | 501 | broad red-team + API hardening |
| `tests/test_dangerous_redteam.py` | 150 | high-risk adversarial cases |
| `tests/test_prompt_injection_pdfs.py` | 37 | document-level injection |
| `packages/policy_engine/tests/test_engine_rules.py` | 38 | engine rule branches (incl. duplicate payment) |
| `tests/test_api_flows.py` | 25 | flagship API flows, registry, approvals, duplicate |
| `tests/test_reader.py` | 21 | reader + sanitizer |
| `tests/test_executor.py` | 13 | single execution path |
| `tests/test_eval.py` | 12 | benchmark + scenario harness |
| `tests/test_compiler_planner.py` | 8 | compiler/planner isolation |
| `tests/test_router.py` | 8 | routing + rate cards |
| `packages/policy_engine/tests/test_properties.py` | 5 | hypothesis invariants I1–I7 |
| `tests/test_registry.py` | 5 | registry build/verify |
| `tests/test_audit.py` | 2 | hash chain + checkpoints |
| other (`purity`, `signing_canonical`, `single_execution_path`) | 4 | invariants |
| **Total** | **1379** | |

### Claim → evidence map

| Claim | Evidence |
|---|---|
| The LLM cannot execute a payment | `tests/test_single_execution_path.py`, `tests/test_executor.py` |
| A modified action cannot use a signed token | action-hash verification in `tests/test_executor.py`; `packages/policy_engine/tests/test_signing_canonical.py` |
| An approval cannot be reused | approval single-use tests in `tests/test_api_flows.py` |
| A wrong payee is rejected | registry mismatch tests (`tests/test_registry.py`, engine rules) |
| A duplicate invoice is not paid twice | `packages/policy_engine/tests/test_engine_rules.py` (duplicate), `tests/test_api_flows.py::test_duplicate_invoice_is_denied_and_never_debits_again`, scenario `T06` |
| The UI drives an end-to-end payment | Playwright `apps/web/e2e/` + ledger evidence in `docs/execution_evidence/` |

---

## Quickstart (Linux/macOS; Windows via WSL or `py`)

```
make setup && make test && make lint     # engine + API + UI tests
make eval                                # regenerate the red-team report + scenarios
make dev                                 # API on :8000
cd apps/web && npm install && npm run dev  # UI on :5173 (proxies /api)
make e2e                                 # Playwright UI flows (boots API + Vite)
```

The LLM is provider-agnostic: set `LLM_PROVIDER=openai_compat` with `LLM_BASE_URL`/`LLM_API_KEY` to use
DeepSeek (defaults in `.env.example`); `replay` (default) runs fully offline on recorded fixtures, so
`make test` and `make eval` need **no network and no API key**.

---

## Documentation

- `docs/technical_documentation.md` — architecture, core algorithms, security design (submission item 01).
- `docs/security_self_assessment.md` — tiers, trust boundaries, controls, known risks (item 05).
- `docs/execution_evidence/index.md` — scenario and attack results (item 06); plus audit export, ledger CSV,
  signed checkpoint and LLM config note in the same folder.
- `docs/prd.md`, `docs/implementation_plan.md`, `docs/design.md`, `docs/testing.md`, `docs/bugs.md` — specs.

---

## Known limitations

- Sandbox only: no real money, banks, KYC or identity checks; all documents and people are synthetic.
- The benchmark is **static**; an adaptive attacker may succeed where our tests did not.
- **A wrong-but-permitted extraction** (a misread amount that still passes the rules) can slip through; the
  LLM has no authority to execute, but it influences what is proposed.
- Caps are single-currency per rule (a mismatched currency is denied, not converted).
- The registry is team-enrolled demo data; **a signature proves a record was not altered, not that the
  institution is genuine.** Rate cards are simulated; savings are relative to a simulated default rail.
- The Bangladesh rule pack is unverified placeholder content, not legal advice.
- Single-user prototype (Rafi + guardian). See `docs/bugs.md` §5–6 for the full list.

## Team eligibility

Team: **Mandate** — three members.

| # | Name | Role |
|---|---|---|
| 1 | Arif Hussain | Team Leader |
| 2 | Ankon Sinha | Member |
| 3 | Miftahul Alam Adib | Member |

<!-- TODO before submitting — replace each [ ] with confirmed facts (do not guess):
All three members are full-time students at [University, Country].
Full-time student status: [confirmed / how confirmed].
Nationality eligibility: [X] of 3 members ([Z]%) are non-Chinese nationals (the track requires >= 60% non-Chinese
nationals and institutions outside mainland China / Hong Kong / Macao / Chinese Taipei).
Registration on the official site: [complete on DATE, receipt saved]. -->

---

*Every claim above traces to a test id, a file, or `eval/reports/latest.json`. This is a prototype: it makes
no regulatory-compliance or security guarantee.*
