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
| Test suite | **1382 tests pass** (offline, no network) | `make test` |
| Engine-level attack success — naive baseline **B0** | **69.8%** (67/96) — 95% Wilson CI [0.600, 0.781] | `eval/reports/latest.json` |
| Engine-level attack success — heuristic "careful" baseline **B1** | **40.6%** (39/96) — CI [0.314, 0.506] | same |
| Engine-level attack success — **Mandate (B2)** | **0.0%** (0/96) — CI [0.000, 0.038] | same |
| False blocks | **0 false blocks among 4 benign cases** | same |
| Reader/detector layer (uploads → detectors → reader) | **anomalies caught 2/2; genuine docs clean 3/3; field agreement 9/9** | `reader_eval` block in `latest.json` |
| Task-completion scenarios (priority subset) | **10/10 ran pass** (including T06 duplicate-payment) | same |
| End-to-end UI flows (Playwright) | **16 pass, 2 mobile-only skips** | `make e2e` |

### How to read these numbers (methodology — read this before quoting the 0%)

- **B0 and B1 are structural baselines, not live LLM agents.** With `LLM_PROVIDER=replay` they are
  deterministic doubles (`eval/baselines/systems.py`): **B0** unconditionally trusts the document's fields;
  **B1** adds a keyword/anomaly heuristic but has no registry and no engine. They exist to show what a
  *no-policy* and a *prompt-only* design do **when handed the same structured fields** — they are not a
  measurement of any particular hosted model.
- **The benchmark is engine-level.** `eval/run_eval.py` builds a `ReaderOutput` directly from each case's
  labelled `fields` (and pre-labelled anomaly flags) and runs the deterministic engine + executor. So the
  **0% B2 rate proves: given the correct structured fields and anomaly flags, the engine never authorises a
  violating payment.** It does **not** measure document parsing, OCR, or hidden-text detection — that is the
  reader/detector layer, measured separately (see below and `docs/technical_documentation.md`).
- **All runs are `replay` (offline).** No live-LLM end-to-end benchmark run is included; that is an explicit
  limitation (see *Known limitations*), not a hidden step.
- **7 of 24 attack families are non-discriminative** on this setup (A08, A15, A17, A18, A22, A23, A24 score
  0/4 for B0 too) — they test engine properties where even the naive baseline does not act, so they do not
  separate the systems; they are retained for coverage, not for contrast.
- **No absolute-security claim.** A 0/96 result has a 95% upper bound of **3.9%**; a static benchmark with
  synthetic documents cannot show resistance to adaptive attackers.

> Simulated system, synthetic documents, static benchmark. The LLM has no authority to execute; a
> wrong-but-permitted extraction (a misread amount still under the cap) is a measured residual risk.

---

## What we built and what we found

- **Found:** the two most dangerous failure modes for an AI that moves money are **(1) instructions hidden
  inside the document** (white-on-white text, tiny text, metadata, QR codes) and **(2) payee substitution**
  (a look-alike name or one changed account digit). Both routinely defeat a *prompt-only* design — our
  heuristic "careful" baseline B1 still failed **40.6%** of engine-level attack cases.
- **Built:** the fix is not a better prompt. It is **unambiguous authority**: a signed rule set the user
  approves, a signed registry that matches payees **by account, not by name**, and a single signed execution
  path. Result: **0%** engine-level attack success on the same 96 cases, with **no** false blocks on the
  benign cases.
- **Why it holds:** the AI is *isolated* (no tools, no DB, no ledger), decisions are *pure* code, and execution
  demands a signed, single-use, action-bound token. An attacker who fully controls the document still cannot
  cause a payment the signed policy does not permit.
- **What this does *not* prove:** that the reader always extracts the right fields, or that hidden text is
  always detected — those are separate, weaker links measured by the reader/detector tests, not by the 0%.

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

A25 is **not** part of the 96-case attack set, so its ASR row is `0/0` in the evidence table; it is measured
only as the **false-block result** (0 of 4 benign cases blocked).

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

Systems under test (**structural baselines, not live LLM agents**; all three receive the same structured
`fields` and write to the same sandbox ledger, so "success" is measured identically from the ledger):
- **B0** — no-policy baseline: unconditionally trusts the document's payee, amount and rail. Shows what an
  agent with a payment tool and **no** policy engine does.
- **B1** — prompt-only baseline: a keyword/anomaly heuristic ("ignore", "urgent", "changed", …) that blocks
  obvious attacks but has **no** registry and **no** engine. Represents "just ask the model to be careful".
- **B2** — Mandate: the deterministic engine + signed registry + single signed execution path.

> With `LLM_PROVIDER=replay` (the default, and what the report uses) B0/B1 are deterministic doubles
> (`eval/baselines/systems.py`), and B2 is run engine-level from labelled fields. A live-LLM end-to-end
> benchmark is **not** included — see *Known limitations*.

**Detector / reader layer (the part the 0% does not cover).** Document-level hidden text, metadata payloads
and instruction phrasing are exercised end-to-end by `tests/test_prompt_injection_pdfs.py` (**37 tests
passing**): a synthetic PDF with hidden/obfuscated text is fed through the real upload → detector → engine
path and the expected anomaly flags must appear in the decision. This is a separate, weaker link than the
engine benchmark and is reported as such.

---

## Test suite (1382 tests, all offline)

| File | Tests | Covers |
|---|---:|---|
| `tests/test_redteam_300_deep.py` | 551 | deep engine/API attacks |
| `tests/test_redteam_500.py` | 501 | broad red-team + API hardening |
| `tests/test_dangerous_redteam.py` | 150 | high-risk adversarial cases |
| `tests/test_prompt_injection_pdfs.py` | 37 | document-level injection |
| `packages/policy_engine/tests/test_engine_rules.py` | 38 | engine rule branches (incl. duplicate payment) |
| `tests/test_api_flows.py` | 25 | flagship API flows, registry, approvals, duplicate |
| `tests/test_reader.py` | 21 | reader + sanitizer |
| `tests/test_executor.py` | 13 | single execution path |
| `tests/test_eval.py` | 14 | benchmark + scenario harness |
| `tests/test_compiler_planner.py` | 8 | compiler/planner isolation |
| `tests/test_router.py` | 8 | routing + rate cards |
| `packages/policy_engine/tests/test_properties.py` | 5 | hypothesis invariants I1–I7 |
| `tests/test_registry.py` | 5 | registry build/verify |
| `tests/test_audit.py` | 2 | hash chain + checkpoints |
| other (`purity`, `signing_canonical`, `single_execution_path`) | 4 | invariants |
| **Total** | **1382** | |

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
make setup && make test && make lint       # installs deps (incl. hypothesis), then runs the suite
make eval                                  # regenerate the red-team report + scenarios
make dev                                   # API on :8000
cd apps/web && npm install && npm run dev  # UI on :5173 (proxies /api)
make e2e                                   # Playwright UI flows (boots API + Vite)
```

**Reproduce the numbers.** `make setup` installs `-r requirements-dev.txt`, which includes **`hypothesis`**
(needed for the property tests) — run it before `make test`, or test collection will stop on the missing
package. Everything below runs **offline**: `LLM_PROVIDER=replay` (the default) uses recorded fixtures, so
`make test` and `make eval` need **no network and no API key**. To use a live provider, set
`LLM_PROVIDER=openai_compat` with `LLM_BASE_URL`/`LLM_API_KEY` (see `.env.example`; model IDs there are
unverified placeholders — confirm them first).

---

## Documentation

- `docs/technical_documentation.md` — architecture, core algorithms, security design (submission item 01).
- `docs/security_self_assessment.md` — tiers, trust boundaries, controls, known risks (item 05).
- `docs/execution_evidence/index.md` — scenario and attack results (item 06); plus audit export, ledger CSV,
  signed checkpoint and LLM config note in the same folder.
- `docs/prd.md`, `docs/implementation_plan.md`, `docs/design.md`, `docs/testing.md`, `docs/bugs.md` — specs.

## Submission assets

| Deliverable | Where |
|---|---|
| Source code + setup | this repository; `make setup && make test && make eval` |
| Technical documentation | `docs/technical_documentation.md` |
| Security self-assessment | `docs/security_self_assessment.md` |
| Red-team report (numbers) | `eval/reports/latest.json` · `latest.html` |
| Execution evidence | `docs/execution_evidence/` (index, audit export, ledger CSV, signed checkpoint, portability) |
| Demo video / deck | _pending_ — to be recorded and linked here before submission |

---

## Known limitations

- Sandbox only: no real money, banks, KYC or identity checks; all documents and people are synthetic.
- **Benchmark scope:** the 0% figure is **engine-level** (given correct structured fields and anomaly flags).
  It is **not** an end-to-end live-LLM evaluation, and it does not measure document parsing or OCR. B0/B1 are
  structural baselines (deterministic doubles in replay mode), not hosted-model measurements.
- **No live-LLM run is included.** Every reported number comes from `replay` mode. A live run with the
  configured model is a pre-submission to-do (`docs/bugs.md` R-012), not completed evidence.
- The benchmark is **static** with synthetic documents; a 0/96 result has a 95% upper bound of ~3.9%. An
  adaptive attacker may succeed where our tests did not.
- **7 of 24 families (A08, A15, A17, A18, A22, A23, A24) are non-discriminative** here (B0 also scores 0/4);
  they add coverage, not contrast.
- **A wrong-but-permitted extraction** (a misread amount that still passes the rules) can slip through; the
  LLM has no authority to execute, but it influences what is proposed. Hidden-text *detection* (reader layer)
  is weaker than the engine layer and measured separately.
- Caps are single-currency per rule (a mismatched currency is denied, not converted).
- The registry is team-enrolled demo data; **a signature proves a record was not altered, not that the
  institution is genuine.** Rate cards are simulated; savings are relative to a simulated default rail.
- The Bangladesh rule pack is unverified placeholder content, not legal advice.
- Model IDs in `.env.example` (e.g. `deepseek-v4.1-flash`) are **unverified placeholders** — confirm in the
  provider docs before any live run.
- Single-user prototype (Rafi + guardian). See `docs/bugs.md` §5–6 for the full list.

## Team eligibility

Team: **Mandate** — three full-time students at **Shahjalal University of Science and Technology (SUST)**,
Bangladesh — an institution **outside mainland China, Hong Kong, Macao and Chinese Taipei**.

| # | Name | Role | Department |
|---|---|---|---|
| 1 | Arif Hussain | Team Leader | Mathematics |
| 2 | Ankon Sinha | Member | Mathematics |
| 3 | Miftahul Alam Adib | Member | Statistics |

All three members are Bangladesh nationals (100% non-Chinese nationals, which satisfies the track's ≥ 60%
non-Chinese-national requirement). No member is affiliated with an institution in mainland China, Hong Kong,
Macao or Chinese Taipei.

<!-- TODO before submitting — fill only with confirmed facts:
Official-site registration: [complete on DATE; receipt saved in docs/execution_evidence/].
If any member holds a nationality other than Bangladeshi, state it here (the ≥ 60% rule is already satisfied). -->

---

*Every claim above traces to a test id, a file, or `eval/reports/latest.json`. This is a prototype: it makes
no regulatory-compliance or security guarantee.*
