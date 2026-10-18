# implementation_plan.md — Mandate: Technical Build Roadmap

> Pairs with `prd.md` (what/why) and `CLAUDE.md` (rules). This file is the *how* and *when*.
> Mark checklist items `[x]` as you finish them. Keep this file honest: if scope is cut, record it in §9.

---

## 0. Time model (read first)

Hard deadline: **20 Oct 2026, 23:59 Beijing time = 21:59 Bangladesh time**. Submit **at least 6 hours early** on Track B/C (12 hours on Track A); updates are allowed until the deadline, so an early submission is a safety net, not a commitment.

**Calendar confirmed (v1.1): today is 18 Oct 2026**, so at most about two days remain and the default is **Track B/C using the 48-hour sprint in §6A**. The six-day phases in §6 are kept only as a reference ordering. Compute `hours_left = deadline − now` at kickoff and pick a track:

| Hours left at kickoff | Track | What it means |
|---|---|---|
| ≥ 120 h | **Track A — Full (6 build days)** | All MVP features (PRD §4.2 A–G). |
| 48–119 h | **Track B — Compressed** | Cut H, F2, D3/D4 polish, Playwright suite; keep benchmark smaller (50 cases). |
| < 48 h | **Track C — Emergency** | See §9 scope-cut ladder: core engine + reader + registry + 12 scenarios + 40 attacks + docs + video. |

Everything in §3 (architecture), §4 (contracts) and §5 (engine semantics) is identical across tracks.

---

## 1. Architecture overview

```
                         ┌──────────────────────────┐
   Browser (React) ────► │  FastAPI  (apps/api)     │
   Rafi / Ammu           │  auth · routes · audit   │
                         └──────┬───────────────────┘
                                │
      ┌─────────────────────────┼───────────────────────────────┐
      ▼                         ▼                               ▼
┌───────────────┐      ┌─────────────────┐             ┌────────────────┐
│ Intent        │      │ Orchestrator    │             │ Rail simulator │
│ Compiler (LLM)│      │ (LangGraph)     │             │ + FX + ledger  │
│ NL → Mandate  │      │ UNTRUSTED       │             │ (sandbox)      │
│ + verifier    │      │ Planner (LLM)   │             └───────▲────────┘
└──────┬────────┘      └───┬─────────┬───┘                     │
       │ signed Mandate    │         │ ActionProposal          │ only on ALLOW
       ▼                   │         ▼                         │
┌───────────────┐   ┌──────┴───┐   ┌─────────────────────┐     │
│ Mandate store │   │ Reader   │   │ POLICY ENGINE       │─────┘
│ (versioned,   │   │ (VLM,    │   │ deterministic code  │
│  signed)      │   │ NO tools)│   │ NO LLM, NO network  │
└───────────────┘   │ schema-  │   └─────────▲───────────┘
                    │ only out │             │ reads
                    └────┬─────┘      ┌──────┴────────┐
                         │ ReaderOut  │ Signed payee  │
                         └───────────►│ registry      │
                                      └───────────────┘
   Everything above writes to ► hash-chained audit log ► red-team/eval harness reads it
```

### 1.1 Trust boundaries (the core security idea)

1. **Untrusted:** uploaded documents, user free text, planner output, reader output *until validated*.
2. **Semi-trusted:** the LLMs themselves (they can be manipulated by untrusted input).
3. **Trusted:** policy engine, registry (signature-verified), signed Mandate, rail simulator ledger, audit log writer.
4. **Rules of the boundary:**
   - The **reader** sees raw documents but has **no tools**: it is a function that receives the document and one injected `complete()` callable (the LLM call, egress allow-listed to the provider host) and nothing else — no DB session, ledger, registry-write, rail or executor handle. This is enforced by code structure (the reader package cannot import `services`, `db` or `rail_sim`; an AST test fails the build) plus a runtime test, never by the prompt. It may only return a JSON object conforming to `ReaderOutput`. Free-text from the document is never forwarded to the planner or engine as instructions; it is stored and displayed **escaped and labeled "untrusted"**.
   - The **planner** sees only validated structured data (`ReaderOutput` fields after sanitization), the user's request, and a *summary* of the Mandate; it emits a typed `ActionProposal`. It cannot call the rail simulator.
   - Only the **API's executor**, after `ALLOW` from the engine (or after a valid approval for `ESCALATE`), calls the rail simulator.
   - The **policy engine** is a pure function: `decide(mandate, proposal, context) -> Decision`. It must be importable and testable without any LLM or network package installed.

### 1.2 Tech stack (matches the team's strengths)

- **Backend:** Python 3.11, FastAPI, Pydantic v2, SQLAlchemy 2 + SQLite (file DB; Postgres optional), `cryptography` (Ed25519), `uvicorn`.
- **Agents:** LangGraph for the planner graph; direct provider SDK calls for the reader and compiler; MCP is optional (not required — do not add FastMCP unless time remains).
- **LLM access:** one `LLMClient` interface with implementations `AnthropicClient` (default), `OpenAICompatClient` (optional) and `ReplayClient` (fixtures, used in CI and benchmark). Model names come from env vars, never hard-coded.
- **Doc processing:** `pypdf`/`pdfplumber` for text-layer extraction used **only for anomaly detection** (e.g., hidden text), `pdf2image` + `Pillow` for rasterization, OpenCV for tamper heuristics (optional).
- **Frontend:** React 18 + Vite + TypeScript + Tailwind + react-i18next. No heavy UI kit; follow `design.md`.
- **Testing:** pytest, hypothesis (property tests), Playwright (e2e), ruff + mypy.
- **Ops:** Docker Compose (`api`, `web`), `Makefile` entry points, GitHub Actions CI (lint + unit + eval-smoke).

### 1.3 Repository layout

```
mandate/
├─ CLAUDE.md                 # AI-coder rules (copy to AGENTS.md)
├─ README.md                 # judge-facing: what, how to run, how to reproduce eval
├─ THIRD_PARTY.md            # licenses of all deps/data
├─ Makefile
├─ docker-compose.yml
├─ docs/
│  ├─ prd.md  implementation_plan.md  design.md  testing.md  bugs.md
│  ├─ technical_documentation.md      # submission item 01
│  ├─ security_self_assessment.md     # submission item 05
│  └─ execution_evidence/             # sandbox logs, screenshots (item 06)
├─ packages/
│  └─ policy_engine/                  # PURE PYTHON, zero LLM/network imports
│     ├─ models.py  decide.py  rules/  money.py  explain.py
│     └─ tests/
├─ apps/
│  ├─ api/
│  │  ├─ main.py  settings.py  deps.py  security.py
│  │  ├─ routes/ (auth, mandates, documents, proposals, approvals, rails, balances, attestations, audit, eval)
│  │  ├─ agents/
│  │  │   ├─ llm.py (LLMClient, ReplayClient)
│  │  │   ├─ compiler/ (prompt, schema, verifier, backtranslate, testgen)
│  │  │   ├─ reader/ (prompt, schema, sanitize, anomalies)
│  │  │   └─ planner/ (graph.py, nodes.py)
│  │  ├─ services/ (executor, router, registry, approvals, audit_log, attestation, alerts)
│  │  └─ db/ (models.py, migrations/, seed.py)
│  └─ web/
│     └─ src/ (pages, components, i18n, api, styles)
├─ services/
│  └─ rail_sim/                       # sandbox bank/FX/ledger (library, imported by api)
├─ data/
│  ├─ registry/registry.json + registry.sig + keys/ (demo keys only)
│  ├─ ratecards/ratecards.json        # SIMULATED, cited to public sources in comments
│  ├─ rulepacks/bd.json               # UNVERIFIED placeholders
│  ├─ fixtures/ (invoices/, nl_rules/, llm_replay/)
│  └─ seed/ (demo users, balances)
└─ eval/
   ├─ attacks/ (generator + catalog.yaml → 100 cases)
   ├─ scenarios/ (30 task scripts)
   ├─ run_eval.py  metrics.py  baselines/ (b0_naive.py, b1_prompted.py)
   └─ reports/ (generated HTML/JSON)
```

---

## 2. Environment and commands

`.env.example` (never commit real keys):

```
LLM_PROVIDER=anthropic            # anthropic | openai_compat | replay
LLM_API_KEY=
LLM_MODEL_READER=                 # vision-capable model id, from provider docs
LLM_MODEL_PLANNER=
LLM_MODEL_COMPILER=
LLM_TEMPERATURE=0
DATABASE_URL=sqlite:///./mandate.db
SIGNING_KEY_PATH=./data/registry/keys/demo_ed25519.pem   # demo keys only
SESSION_SECRET=
COOLING_OFF_HOURS_DEFAULT=24
SANDBOX_BANNER=Simulated — no real money moves
EVAL_SEED=1337
```

Make targets (all must work from a clean clone):

```
make setup      # venv, deps, web deps, seed DB, generate demo keys
make dev        # api on :8000, web on :5173
make test       # unit + property tests (engine must pass with no network)
make eval       # builds attack cases, runs B0/B1/Mandate, writes eval/reports
make e2e        # Playwright
make lint       # ruff, mypy, eslint, tsc
make demo-reset # reset DB + uploads to seeded state
```

### 2.1 Portability rules (a judge will clone and run this)

- Use `pathlib` and paths relative to `settings.REPO_ROOT`; **no absolute paths** anywhere, including `.env.example`.
- `.gitattributes` forces LF line endings; no Bash-only steps without a Python or `docker compose` alternative documented in the README (Windows users: WSL or `docker compose up`).
- **Docker Compose is the reference environment.** Before submission run `make setup && make test && make eval` inside a clean `python:3.11` Linux container and, if a Windows machine is available, once under WSL. Record both results in `docs/execution_evidence/portability.md`.
- Pin all dependency versions (lockfiles committed). No network access needed for `make test` or `make eval` in replay mode.

---

## 3. Data contracts (source of truth — implement as Pydantic models first)

### 3.1 `ReaderOutput` (the only thing the reader may emit)

```json
{
  "doc_type": "invoice | offer_letter | receipt | bank_notice | unknown",
  "payee_name": "string<=120",
  "account_identifier": "string<=64, ^[A-Za-z0-9 \\-]+$",
  "bank_identifier": "string<=34, ^[A-Za-z0-9]+$",
  "amount_minor": 0,
  "currency": "ISO-4217 3 letters, in allowed set",
  "due_date": "YYYY-MM-DD | null",
  "reference": "string<=64",
  "category_guess": "tuition | rent | insurance | family_support | other",
  "extraction_confidence": 0.0,
  "anomalies": ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE", "LOW_IMAGE_QUALITY", "AMOUNT_INCONSISTENT", "MULTI_PAYEE", "NONE"],
  "doc_sha256": "hex"
}
```

Rules: unknown keys rejected; strings pass a character allow-list; anomalies is an **enum list only** (no free text). `INSTRUCTION_LIKE_TEXT` is set by a **deterministic regex/heuristic detector over the PDF text layer and OCR text**, in addition to the reader's own flags (defense in depth — the engine trusts the union of flags).

### 3.2 `ActionProposal` (planner output)

```json
{
  "proposal_id": "uuid",
  "action": "pay | transfer | convert | schedule_recurring",
  "category": "tuition | rent | insurance | family_support | other",
  "payee_id": "registry id | user_payee id | null",
  "payee_ref": {"name": "...", "account_identifier": "...", "bank_identifier": "..."},
  "amount_minor": 0,
  "currency": "USD",
  "source_account": "acc_...",
  "rail_id": "rail_a_bank | rail_b_wallet | rail_c_card",
  "urgency": "normal | urgent",
  "doc_ref": "document_id | null",
  "created_by": "planner | user"
}
```

### 3.3 `Mandate` (policy DSL v1)

```json
{
  "mandate_id": "m_...",
  "version": 3,
  "owner_id": "u_rafi",
  "base_currency": "BDT",
  "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
  "rules": [
    {"id": "R1", "type": "category_allow", "categories": ["tuition","rent","insurance","family_support"]},
    {"id": "R2", "type": "payee_allowlist", "payee_ids": ["reg_northfield_univ", "usr_ammu_bkash"]},
    {"id": "R3", "type": "cap", "scope": "per_tx", "amount_minor": 500000, "currency": "USD", "categories": ["tuition"]},
    {"id": "R4", "type": "cap", "scope": "rolling_30d", "amount_minor": 800000, "currency": "USD", "categories": ["*"]},
    {"id": "R5", "type": "require_registry_match", "categories": ["tuition"]},
    {"id": "R6", "type": "new_payee", "action": "ESCALATE", "approvers": ["u_ammu"]},
    {"id": "R7", "type": "cooling_off", "applies_to": "new_payee", "hours": 24},
    {"id": "R8", "type": "escalate_above", "amount_minor": 200000, "currency": "USD", "approvers": ["u_ammu"]},
    {"id": "R9", "type": "min_confidence", "value": 0.90},
    {"id": "R10", "type": "block_anomalies", "anomalies": ["HIDDEN_TEXT","INSTRUCTION_LIKE_TEXT","PAYEE_CHANGE_NOTICE"], "action": "DENY"}
  ],
  "signature": "base64(ed25519 over canonical JSON)",
  "created_at": "ISO-8601"
}
```

Rule types in v1 (closed set — the compiler may only emit these): `category_allow`, `payee_allowlist`, `cap` (per_tx | rolling_7d | rolling_30d), `require_registry_match`, `new_payee`, `cooling_off`, `escalate_above`, `min_confidence`, `block_anomalies`, `time_window`, `rail_allow`, `conversion_rule` (target balance rule). Anything the user says that is not expressible is **refused with an explanation**, never approximated silently.

### 3.4 `Decision`

```json
{
  "decision": "ALLOW | HOLD | ESCALATE | DENY",
  "tier": "T0 | T1 | T2 | T3 | T4",
  "reason_codes": ["REGISTRY_MATCH", "WITHIN_CAP", "..."],
  "failed_rule_ids": [],
  "required_approvers": [],
  "hold_until": null,
  "trace": [{"step": "registry", "result": "pass", "detail": "..."}],
  "engine_version": "x.y.z",
  "input_hash": "sha256 of canonical inputs"
}
```

### 3.5 Signed decision and transaction binding (v1.1)

The engine does not just return a `Decision`; it returns a **signed `decision_token`**:

```
action_hash    = sha256(canonical({action, category, payee_id, payee_ref{name, account_identifier, bank_identifier},
                                   amount_minor, currency, source_account, rail_id}))
decision_token = Ed25519_sign(engine_key, canonical({decision, tier, action_hash, mandate_id, mandate_version,
                                                      registry_version, input_hash, issued_at, expires_at, nonce}))
```

The executor accepts **only** `(proposal, decision_token)` and refuses unless **all** hold: signature valid; `decision == ALLOW`; not expired; nonce unused; `action_hash` **recomputed from the proposal about to execute** equals the token's; the token's mandate version is still the active version; the registry entry used is still valid (not revoked or expired). Any failure → no execution and an `EXEC_REFUSED` audit entry with the reason.

**Approvals are inputs to the engine, not bypasses.** An approval token binds `action_hash + mandate_version + approver_id + expires_at + nonce` (hash stored, single use). On approval the engine is **re-run** with the approval in its context and issues a *new* `decision_token`. Changing payee, amount, currency, rail or action after approval changes `action_hash`, so the approval no longer matches.

**Single execution path:** `services/executor.execute()` is the only module that imports `rail_sim`. A CI test fails if any route, agent or script imports it. Idempotency key = `action_hash + nonce`; balance updates are atomic in one DB transaction.

---

## 4. Engine semantics (implement exactly; test with properties)

### 4.1 Precedence and defaults

`DENY` > `HOLD` > `ESCALATE` > `ALLOW`. The engine collects outcomes from **all** applicable rules; the strictest wins. **Default is DENY** when no rule explicitly permits.

### 4.2 Evaluation order (also the order shown in the decision trace)

1. **Integrity:** Mandate signature valid, version active, proposal schema valid → else `DENY` (`MANDATE_INVALID`/`PROPOSAL_INVALID`).
2. **Anomalies:** union of reader + detector flags; any in `block_anomalies` → `DENY`.
3. **Confidence:** `extraction_confidence < min_confidence` → `ESCALATE` (`LOW_CONFIDENCE`).
4. **Category:** not in `category_allow` → `DENY` (`CATEGORY_NOT_ALLOWED`).
5. **Registry check** (if `require_registry_match` for category): payee name + account + bank identifier must match a **signature-valid** registry entry exactly (after Unicode NFKC normalization and confusable detection). Mismatch → `DENY` (`REGISTRY_MISMATCH`); entry with bad signature → `DENY` (`REGISTRY_SIGNATURE_INVALID`).
6. **Payee status:** in `payee_allowlist` or verified registry entry referenced by Mandate → known; else *new payee* → apply `new_payee` action (`ESCALATE`) and `cooling_off` (`HOLD`). A listed approver's approval bound to the `action_hash` **releases a HOLD early** (engine re-run with the approval in context, new `decision_token`); it never overrides a DENY. If the invoice due date falls inside the hold window the decision carries `deadline_at_risk: true` so the UI can warn.
7. **Caps:** per-tx cap, then rolling-window caps computed from the **ledger** (not from the proposal). Over cap → `ESCALATE` if an `escalate_above` rule covers it, else `DENY`.
8. **Escalation thresholds:** `escalate_above` → `ESCALATE`.
9. **Rail and time-window rules** → `DENY` if violated.
10. **Currency sanity:** currency in allowed set; amount > 0; amount ≤ account balance (else `DENY`, `INSUFFICIENT_FUNDS`).
11. **Tier assignment:** `ALLOW` → T2; `ESCALATE` → T3; `HOLD` → T3 (pending); `DENY` → T4. (`T0/T1` are UI modes: read-only views and "proposal drafted, not executed".)

### 4.3 Invariants (must be property-tested with hypothesis)

- **I1 Monotonic safety:** adding a restrictive rule never turns a `DENY` into a less strict outcome.
- **I2 Determinism:** same canonical inputs → identical `Decision` and `input_hash`.
- **I3 No LLM influence:** the engine package has no import path to any LLM/network library (CI check: `pip install` the engine in a clean venv with only stdlib + pydantic).
- **I4 Registry strictness:** any single-character change in payee name, account or bank identifier → `DENY` for registry-required categories.
- **I5 Cap integrity:** the sum of executed amounts in any rolling window never exceeds the cap (checked against the ledger in simulation fuzzing, including split-payment attempts).
- **I6 Approval single-use:** a consumed approval token cannot authorize a second execution.
- **I7 Default deny:** a proposal with an unknown category/payee/rail is never `ALLOW`.

### 4.4 Execution rules

- `ALLOW` → executor calls rail simulator **inside a DB transaction** with an idempotency key = `proposal_id`.
- `ESCALATE` → create `Approval` (token = random 256-bit, stored hashed, expires in 24 h, bound to `input_hash`); on approve, **re-run the engine** with fresh context; only execute if still not `DENY`.
- `HOLD` → store `hold_until`; a scheduler re-evaluates at expiry.
- Every state change appends to the audit log.

### 4.5 Routing algorithm

For a proposal with source currency `S`, destination currency `D`, amount `A`:
1. Candidate rails = rails supporting the corridor and allowed by `rail_allow` rules.
2. `total_cost = fixed_fee + pct_fee·A + (mid_rate − offered_rate)/mid_rate·A` (all computed in `Decimal`, rounded half-even to minor units).
3. Filter by deadline feasibility (rail speed vs due date).
4. Sort: `urgent` → minimize time then cost; `normal` → minimize cost then time.
5. Return ranked list with **excluded rails and reasons**; savings = `cost(default_rail) − cost(chosen)`.
Rate cards live in `data/ratecards/ratecards.json`, **labeled SIMULATED**. Every card carries `source_url`, `source_date`, `assumptions` and `limitations`; none may be left blank. The router output includes `sender_total_cost`, `recipient_net_amount`, `eta`, and explicit intermediary and receiving-bank charge fields (a value of 0 must state the assumption). The **default route** used for savings is a transparent "standard bank wire" card with a cited fee, not an arbitrary expensive baseline. The flagship corridor is **BDT→USD only**; other corridors are configuration, not claims. Do not claim real provider quotes.

### 4.6 Abstention threshold (calibration)

- Build a validation set of reader outputs with ground truth (≥60 labeled docs incl. perturbed ones).
- Choose threshold τ via split-conformal-style calibration on the "extraction is fully correct" score so that, on exchangeable data, the share of **accepted-but-wrong** extractions ≤ α (default 0.05). Document the assumptions and **that this is a prototype guarantee on synthetic data only**.
- If calibration cannot be completed in time, set τ=0.90 and state that it is a heuristic.

### 4.7 Registry provenance and trust (v1.1)

A signature proves a record was not altered since a key signed it. It does **not** prove the institution is genuine. The UI and docs must say so plainly, and the data model must carry the evidence:

```json
{
  "entity_id": "reg_northfield_univ", "legal_name": "…", "account_identifier": "…", "bank_identifier": "…",
  "provenance": {"method": "enrolled by team from the institution's published payment page", "source_url": "…", "retrieved_on": "YYYY-MM-DD", "second_check": "none | callback | document"},
  "enrolled_by": "team", "valid_from": "…", "valid_to": "…", "revoked_at": null,
  "registry_version": "2026-10-18", "signer_key_id": "demo_registry_k1"
}
```

Engine checks: signature valid for a **non-retired** key id → entry within `valid_from/valid_to` → not revoked, else `DENY` (`REGISTRY_SIGNATURE_INVALID | REGISTRY_ENTRY_EXPIRED | REGISTRY_ENTRY_REVOKED`). Keys live in `registry_keys.json` with `active/retired` status to demonstrate rotation. Revocation = a new signed registry version listing `revoked_at`.

**Prototype vs production (state this in the security self-assessment):** prototype = team-enrolled demo entries from public pages, server-held keys; production would need institutional enrollment, out-of-band verification (e.g., callback), hardware-protected keys, and an independent operator.

### 4.8 Signing authority and audit-log threat model (v1.1)

- **Mandate signing:** prototype uses a server-held per-user demo key after the user confirms the compiled policy. State clearly that production would use a user-held device key with revocation and re-authentication. Superseded versions are never valid for new decisions.
- **Audit log:** the hash chain detects edits to individual entries but **not** a full rewrite by someone who can recompute every hash. Mitigation: periodically sign the head hash with a **separate checkpoint key** and export checkpoints (print the latest head hash in the README/video and store it in `docs/execution_evidence/`). A full rewrite is then detectable against the externally held checkpoint. Residual risk: if an attacker controls both the DB and the checkpoint key, the log can be forged.

---

## 5. API surface (FastAPI)

All routes under `/api/v1`, JSON, session cookie auth, CSRF-safe (SameSite=Lax + token on mutating routes).

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/login` | Seeded demo users (rafi, ammu) |
| POST | `/mandates/compile` | `{text, lang}` → candidate Mandate + back-translation + test cases (not active) |
| POST | `/mandates/{id}/confirm` | User confirms → sign + activate new version |
| GET | `/mandates/active` · `/mandates/{id}/versions` | Read |
| POST | `/documents` | Upload (PDF/PNG/JPG ≤ 10 MB, MIME sniffed) → reader → `ReaderOutput` |
| POST | `/proposals` | `{user_request, document_id?}` → planner → `ActionProposal` → engine → `Decision` (+ execution if ALLOW) |
| GET | `/proposals/{id}` | Proposal + decision + trace |
| GET | `/approvals/{token}` · POST `/approvals/{token}/decision` | Guardian page + approve/reject |
| POST | `/rails/quote` | Ranked rails for a corridor/amount |
| GET | `/balances` · POST `/conversions/rules` | Multi-currency |
| GET | `/alerts` | Low balance / due soon |
| POST | `/attestations` · GET `/attestations/{id}` · POST `/attestations/verify` | Credit-building prototype |
| GET | `/audit` · GET `/audit/verify` | Log view + chain verification |
| POST | `/eval/run` · GET `/eval/report` | Trigger/read benchmark report (admin only) |
| POST | `/admin/reset` | Demo reset (disabled unless `DEMO_MODE=1`) |

### 5.1 Database tables (SQLAlchemy)

`users(id, name, role, lang)` · `mandates(id, owner_id, version, json, signature, active, created_at)` · `payees(id, owner_id, name, account_identifier, bank_identifier, created_at, first_used_at)` · `documents(id, owner_id, sha256, mime, path, reader_json, anomalies_json, created_at)` · `proposals(id, owner_id, json, decision_json, status, created_at)` · `approvals(id, proposal_id, token_hash, approver_id, status, expires_at, consumed_at, input_hash)` · `accounts(id, owner_id, currency, balance_minor)` · `ledger(id, account_id, proposal_id, delta_minor, currency, fee_minor, rate, created_at)` · `audit_log(seq, ts, actor, event_type, payload_json, prev_hash, hash)` · `attestations(id, owner_id, payload_json, signature, created_at)` · `eval_runs(id, seed, started_at, report_json)`.

Audit hash: `hash = sha256(prev_hash || canonical_json(entry))`. `/audit/verify` recomputes the chain.

---

## 6. Phased build plan (Track A — 6 build days; adapt per §0)

Each phase ends with a **demoable milestone** and a commit tagged `phase-N`.

### Phase 0 — Kickoff (first 2–3 hours)
- [ ] Confirm team roster and nationality rule; confirm registration done on the official site.
- [ ] Create GitHub repo; add this spec set under `docs/`; copy `CLAUDE.md` to root (and `AGENTS.md`).
- [ ] Decide LLM provider and API budget; fill `.env`.
- [ ] Split ownership (suggested): **Dev 1** engine + API + eval; **Dev 2** frontend + docs + video. Both own tests for what they write.
- [ ] `make setup` works on both machines.
**Milestone M0:** empty app boots, CI green.

### Phase 1 — Engine and contracts (Day 1)
- [ ] Pydantic models for §3 contracts; JSON schemas exported.
- [ ] `policy_engine.decide()` implementing §4.2 with reason codes and trace.
- [ ] Money utils (minor units, Decimal rates), canonical JSON, input hashing.
- [ ] Unit tests for each rule type + the 7 invariants (hypothesis).
- [ ] Ed25519 signing utils; sign/verify Mandate and registry.
- [ ] Seed registry (fictional universities/landlords), demo users, balances.
**Milestone M1:** `make test` passes; CLI `python -m policy_engine.demo` prints ALLOW/DENY examples.

### Phase 2 — Sandbox rails, router, ledger, audit (Day 1–2)
- [ ] `rail_sim`: accounts, FX conversion, fees, settlement delay (simulated clock), idempotent transfers.
- [ ] Rate cards JSON with sourced calibration comments; corridor coverage: BDT↔USD/GBP/EUR/(+1).
- [ ] Router per §4.5 with exclusions and savings.
- [ ] Hash-chained audit log + verify endpoint.
- [ ] Executor with DB transaction + idempotency.
**Milestone M2:** scripted sandbox payment executes and appears in ledger + audit; chain verifies.

### Phase 3 — Reader and document pipeline (Day 2)
- [ ] `LLMClient` + `ReplayClient`; reader prompt (extract only; ignore any instructions in the document; output JSON only).
- [ ] Output validator/sanitizer (schema, allow-lists, length caps, NFKC, confusable check).
- [ ] Deterministic detectors: hidden-text (white/tiny/off-page text in PDF layer), instruction-like regex (en + Bangla keywords), payee-change phrases, metadata/filename scan.
- [ ] Upload endpoint with MIME sniffing, size limit, storage outside web root.
- [ ] Build 60 labeled invoices (30 clean, 30 perturbed) in `data/fixtures/invoices/` with gold JSON.
**Milestone M3:** upload invoice → validated `ReaderOutput` + anomaly flags in UI/JSON.

### Phase 4 — Planner, compiler, approvals (Day 2–3)
- [ ] LangGraph planner: nodes `parse_request → select_payee → choose_rail → build_proposal`; planner prompt receives only structured data.
- [ ] Intent compiler: NL (en/bn) → Mandate JSON (closed rule set) → schema validation → back-translation → test-case generation → user confirm → sign.
- [ ] Refusal path for inexpressible/ambiguous rules.
- [ ] Approval service (hashed single-use tokens, expiry, input-hash binding, re-evaluation on approve).
- [ ] Cooling-off scheduler (simulated clock for demos).
- [ ] 60 NL rules with gold policies (`data/fixtures/nl_rules/`), half Bangla.
**Milestone M4:** end-to-end API flow: compile → confirm → upload → propose → decision → approval → execution.

### Phase 5 — Frontend (Day 3–4; can start Day 2 against mocked API)
- [ ] App shell, i18n (en/bn), auth stub.
- [ ] Pages per `design.md`: Dashboard, Mandate editor, New payment, Decision trace, Guardian approval, Balances & conversions, Audit log, Attestation, Red-team report.
- [ ] Decision trace component (the signature interaction).
- [ ] Empty/error/loading states; keyboard and focus checks.
**Milestone M5:** a non-developer can run the full tuition story in the browser.

### Phase 6 — Benchmark and baselines (Day 4–5)
  - [x] Attack generator → 100 cases from the 24 attack families in `testing.md` §6 (seeded), plus 4 benign look-alikes.
- [ ] Baselines: **B0** naive single agent with payment tool and no policy; **B1** same agent with a careful system prompt; **B2** Mandate.
- [ ] Metrics: ASR, false-block rate, completion rate, per-family tables; report JSON + HTML page.
- [ ] 30 task scenarios scripted and runnable headless.
- [ ] Record LLM replay fixtures so `make eval` runs offline.
**Milestone M6:** `make eval` produces the report; numbers pasted into docs **as measured**.

### Phase 7 — Docs, evidence, video, submission (Day 5–6)
- [ ] `docs/technical_documentation.md`: architecture, core algorithms (engine semantics, routing, abstention), security design.
- [ ] `docs/security_self_assessment.md`: tier table, permission model, trust boundaries, threat model, test evidence, **known-risk list from `bugs.md`**.
- [ ] `docs/execution_evidence/`: exported sandbox logs (`/audit` export), ledger CSV, screenshots, eval report.
- [ ] README: quickstart, deployment, test commands, reproduce-eval instructions, license notes.
- [ ] Presentation deck ≤10 min (use the 8-slide skeleton in §8).
- [ ] Demo video ≤5 min (script in §8).
- [ ] `THIRD_PARTY.md` complete; no secrets in repo history.
- [ ] Final audit against `bugs.md` §4 checklist; tag `v1.0-submission`.
- [ ] **Submit ≥12 h before deadline**; re-submit only if a real defect is found.

---

## 6A. 48-hour sprint plan (DEFAULT — today is 18 Oct 2026)

Deadline is 20 Oct 23:59 Beijing = **21:59 Dhaka**. Assume ≤ 48 working hours and aim to submit **≥ 6 hours early**. Scope is the flagship only (PRD §0.1, tier P0). Two people split as: **Dev 1** = engine, executor, registry, API, eval; **Dev 2** = reader, UI, docs, video. If solo, follow the same order and cut from the bottom of §9.

| Block | Hours | Goal | Exit check |
|---|---|---|---|
| S0 | 0–2 | Repo from spec set, `make setup`, seed data (users, balances, mandate, registry v1, 4 invoices), CI | App boots; `make test` runs |
| S1 | 2–10 | Contracts (§3), policy engine + signed `decision_token`, executor with single path, ledger, audit log + checkpoint, tests U-ENG, U-EXEC, P-I1…I7 | Engine and execution-boundary tests green offline |
| S2 | 10–18 | Reader (injected `complete()`), sanitizer, deterministic detectors, registry check, router for **one corridor** with net amount and default route, rate card with source/date/assumptions | Genuine invoice → ALLOW → sandbox payment; substituted account → DENY |
| S3 | 18–26 | API routes for flagship, approval flow bound to `action_hash`, guardian page, minimal UI (Pay, Decision Trace, Mandate card, Activity), English compile with back-translation | Browser flow works end to end (§12 demo script in `testing.md`) |
| S4 | 26–34 | Attack catalog (50 dev + held-out set frozen before running), baselines B0/B1, run B0/B1/Mandate, stage-attributed failures, report page | `make eval` produces report JSON/HTML |
| S5 | 34–42 | `technical_documentation.md`, `security_self_assessment.md` (from `bugs.md` risks), README, evidence export, THIRD_PARTY.md | Docs match report numbers |
| S6 | 42–46 | Demo video (≤ 5 min) and deck (≤ 10 min), rehearsal with a timer | Both timed |
| S7 | 46–48 | Final audit (`bugs.md` §4), clean-clone test, submit | Submission receipt saved |

**Minimum viable submission if time collapses (never cut):** engine + executor boundary tests, registry cross-check, isolated reader, audit log, the 3 canonical demo cases, a reduced benchmark (≥ 25 held-out) with B0 vs Mandate, security self-assessment with known risks, README, sandbox logs, video.

---

## 7. Deliverables mapping (official checklist → files)

| Official item | Our artifact | Owner | Done |
|---|---|---|---|
| 01 Technical documentation | `docs/technical_documentation.md` | Dev 1 | [ ] |
| 02 Presentation ≤10 min | `docs/presentation.pdf` (+ source) | Dev 2 | [ ] |
| 03 Demo video ≤5 min | `docs/demo.mp4` or link | Dev 2 | [ ] |
| 04 Source code + README + GitHub + deploy + tests | repo root, `README.md`, `make test` | both | [ ] |
| 05 Security self-assessment | `docs/security_self_assessment.md` | Dev 1 | [ ] |
| 06 Execution evidence | `docs/execution_evidence/*`, including a generated `index.md` that maps every scenario and attack ID to its log | Dev 1 | [ ] |

### 7.1 Security self-assessment skeleton (fill from real results)

1. Scope and system description. 2. Permission tiers T0–T4 with exact enforcement points (file + function names). 3. Trust boundaries diagram. 4. Threat model (assets, adversaries, entry points) — reuse `testing.md` §6 families. 5. Controls mapped to threats (control → test id → measured result). 6. Residual risks and **known-risk list** (copy from `bugs.md` register, with status). 7. Limitations: sandbox only, synthetic data, unverified regulatory rule pack, prototype attestation. 8. Reproduction instructions.

**Enforcement-point table (name real files and functions; update after the build so every row is true):**

| Control | Enforcement point | Test |
|---|---|---|
| Decision computation and signing | `packages/policy_engine/decide.py:decide()` and `sign_decision()` | U-ENG-*, P-I2 |
| Execution verification (signature, ALLOW, expiry, nonce, `action_hash`, mandate and registry validity) | `apps/api/services/executor.py:execute()` | U-EXEC-01…04 |
| Single execution path | CI test `tests/test_single_execution_path.py` | U-EXEC-05 |
| Reader isolation | `apps/api/agents/reader/__init__.py:read_document(document, complete)` | U-EXEC-06 |
| Registry check | `packages/policy_engine/rules/registry.py:check_registry()` | U-ENG-05, U-REG-01 |
| Approval binding and single use | `apps/api/services/approvals.py:consume_approval()` | U-APPR, U-EXEC-03 |
| Audit chain and checkpoints | `apps/api/services/audit_log.py:append()` and `checkpoint()` | U-AUDIT, U-AUDIT-02 |
| Engine purity | `tests/test_engine_purity.py` | U-ENG-14, P-I3 |

---

### 7.2 README header template (fill with real facts; never submit with placeholders)

```
# Mandate
> Simulated — no real money moves. Prototype for the 2026 Shenzhen International FinTech Competition, International Track, Topic C.

## Team eligibility
All team members are full-time students at [University, Country]. [X] of [Y] members ([Z]%) are non-Chinese nationals, meeting the International Track rule.

## Quickstart  (Linux/macOS; Windows via WSL or `docker compose up`)
make setup && make dev        # app
make test                     # unit + property tests (offline)
make eval                     # regenerates the red-team report (replay mode)

## Reproduce the headline numbers
`make eval` writes eval/reports/latest.{json,html}; every number in the docs is copied from that file.

## Licences
Dependencies use permissive licences (listed in THIRD_PARTY.md and docs/licences_*.txt). Licence scan run on [date]: no AGPL/GPL components found.  <- only after the scan has actually been run

## Known limitations
See docs/bugs.md §5–6 and docs/security_self_assessment.md.
```

---

## 8. Presentation and video skeletons

**Deck (≤10 min, 8 slides):** (1) The problem: AI that moves money can be talked into wrong payments. (2) Mandate in one sentence + live trust boundary diagram. (3) Story: tuition invoice, tampered vs genuine. (4) How decisions are made (engine, registry, tiers). (5) Task completion results (priority scenarios) and routing savings, stated as "versus a simulated, publicly calibrated default route, not live market data". (6) Security results (attack cases, baselines, failures). State the limits on the slide: "Static benchmark of 24 attack families; adaptive attackers may do better. The LLM has no authority to execute; a wrong-but-permitted extraction is a measured residual risk." (7) Innovation: Bangla intent compiler, guardian co-sign, decision trace, attestation prototype. (8) Limits, honest risks, next steps.

**Video (≤5 min):** 0:00 hook (invoice with hidden instruction) → 0:30 write rule in Bangla → 1:15 genuine invoice paid → 2:00 tampered invoice blocked, trace shown → 2:45 guardian approves a large transfer on phone view → 3:30 cheapest-rail comparison + multi-currency → 4:15 red-team report numbers → 4:45 limits and close.

---

## 9. Scope-cut ladder (apply from the top when behind schedule)

Cut in this order; log each cut here with date/time.

1. H1 plan reminders (soft nudge). 2. F2 attestation verify UI (keep JSON + CLI verify). 3. D3 alerts. 4. Playwright e2e (keep manual checklist). 5. Postgres/Docker polish (SQLite + `make dev` only). 6. Rail count 3 → 2. 7. Benchmark 100 → 60 cases (keep all 24 attack families, fewer variants). 8. NL rules 60 → 30. 9. Bangla UI strings → keep Bangla *input* and guardian page only. 10. Planner LangGraph → plain function chain.

**Never cut:** policy engine + invariants tests, registry cross-check, isolated reader with schema output, audit log, decision trace, red-team report with baselines, security self-assessment, README with run instructions, sandbox logs, honest limitations section.

**Track C (Emergency, <48 h) minimum:** engine + registry + reader + sandbox ledger + 12 scenarios + 40 attacks (1–2 per family) + decision trace page + 5 docs + short video.

### Cut log
| When | Item cut | Reason |
|---|---|---|
| 2026-10-18 | F1–F2 attestation (generate + verify UI) | Two days left; flagship flow first |
| 2026-10-18 | D2–D4 multi-currency automation, alerts, fee audit | Out of flagship; keep D1 balance display only |
| 2026-10-18 | C3 recurring allowance; H1 reminders | Out of flagship |
| 2026-10-18 | Corridors other than BDT→USD | One corridor with documented rate card is more credible |

### Build status (updated 2026-10-18)
- **S0 done:** repo, make targets (cross-platform), seed data (users, balances, mandate rules, invoices),
  demo keys generated by `apps/api/db/keys.py`.
- **S1 done:** contracts (§3), engine + signed `decision_token`, executor (single path), ledger, audit log +
  checkpoint; unit/property tests green offline.
- **S2 done:** isolated reader (injected `complete()`), sanitizer, deterministic detectors, registry check,
  router with net amount + default route, rate card with source/date/assumptions.
- **S3 done:** API routes for the flagship, approval flow bound to `action_hash`, guardian page, UI (Pay,
  Decision Trace, Mandate, Dashboard, Balances, Activity, Red-team), English compile with back-translation.
- **S4 done:** attack catalog (24 families × 4 = 96 attacks + 4 benign), baselines B0/B1, runner + report
  JSON/HTML. Result: B0 69.8% · B1 40.6% · B2 0% ASR, 0% false-block.
- **S5 partial:** README, security self-assessment, THIRD_PARTY written; licence scans not yet run.
- **S6 (e2e/scenarios/docs):** priority task-completion scenarios (`eval/scenarios/run.py`, wired into the
  report + evidence index); Playwright e2e (E2E-03/04/05/08/10/12) with `make e2e`; `docs/technical_documentation.md`;
  `docs/execution_evidence/` (audit export, ledger CSV, signed checkpoint, LLM config, portability, index);
  `POST /admin/reset` demo route. Status: **9/9 scenario runs pass** (T06 honest skip), **16 e2e pass**.
- **Open:** licence scans; clean-container portability run; presentation/video; live-vs-replay comparison run.

---

## 10. Definition of done (per feature)

1. Code merged with tests; `make lint test` green.
2. Behavior matches PRD acceptance criteria.
3. Audit entries written for every state change.
4. Strings in en (and bn where specified); empty/error/loading states present.
5. No LLM output is trusted without validation; no raw document text reaches the planner/engine.
6. Entry added to `testing.md` coverage table; any issue logged in `bugs.md`.
