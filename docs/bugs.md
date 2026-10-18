# bugs.md — Mandate: Bug Log, Risk Register and Audit Log

> Living document. Log **everything** that breaks, surprises or drifts. This file feeds the **known-risk list** in the security self-assessment, so write entries as if a judge will read them.
> Update rule: new entries go at the top of their section; never delete — mark `Status: fixed/won't fix/accepted` with a commit link.

---

## 1. How to use this file

| Section | Purpose |
|---|---|
| §2 Bug and failure log | Errors, failing tests, console errors, successful attacks found |
| §3 Spec drift log | Places where code and docs disagree, or the spec is ambiguous |
| §4 Pre-submission audit checklist | Systematic check of the codebase against the plan; orphan-file detection |
| §5 Risk register (known risks) | Source for `security_self_assessment.md`; pre-populated |
| §6 Limitations to disclose | Plain-language list for README, deck and UI |
| §7 Console and log captures | Raw error output worth keeping |
| §8 Decisions log | Choices made under uncertainty |

### Severity scale
- **S0 Critical:** policy bypass, wrong payee executed, secret leak, audit-chain break, data loss.
- **S1 High:** wrong decision (false allow), crash in main flow, signature verification skipped.
- **S2 Medium:** false block, wrong explanation, i18n/a11y failure in main flow, flaky test.
- **S3 Low:** cosmetic, copy, minor perf, docs typo.

### Entry template (copy for each issue)

```
### BUG-### · <short title>
- Date/time (Beijing + Dhaka): 
- Reporter: 
- Severity: S0 | S1 | S2 | S3
- Area: engine | reader | compiler | planner | router | rail_sim | api | web | eval | docs
- Found by: unit | property | scenario <ID> | attack <ID> | e2e | manual | adaptive probe
- Environment: replay | live · commit <sha> · browser/OS if UI
- Steps to reproduce:
  1.
  2.
- Expected: 
- Actual: 
- Evidence: (log excerpt / screenshot path / case_id)
- Root cause: 
- Fix: (commit link) 
- Regression test added: (test id / catalog id)
- Status: open | in progress | fixed | won't fix | accepted risk
```

---

## 2. Bug and failure log

_(Newest first.)_

### NOTE-001 · Playwright: 2 tests report as "skipped" (by design, not a failure)
- Date: 2026-10-18 · Area: e2e
- What: the E2E suite reports **16 passed, 2 skipped**. The 2 skips are the `mobile-360` guardian-approval tests
  run under the **desktop** project: the spec contains
  `test.skip(({ viewport }) => (viewport?.width ?? 999) > 480, ...)` so the mobile-only flow is not run at a
  desktop viewport. The same tests **pass under the `mobile-360` project** (Pixel 5, 360 px), which is the
  correct place to verify the guardian page (design.md §6.10).
- Interpretation: the skip is a deliberate viewport guard, not a broken or environment-flaky test. All
  non-mobile flows run in both projects.
- Status: intentional

### BUG-011 · Duplicate payment was not prevented (T06 was an honest skip)
- Date: 2026-10-18 · Severity: S1 · Area: policy_engine / scenarios · Source: external review
- Finding: `docs/execution_evidence/index.md` showed scenario T06 (`Duplicate of an already-paid invoice`) as
  `Actual: ALLOW/executed=True` with `Result: SKIP` — i.e. the same invoice could be paid twice, a direct
  financial harm. Idempotency at the executor (token replay) and ledger (idempotency key) only stop the *same
  token/key*; neither catches a **new request** for an already-paid invoice.
- Fix: decision-layer idempotency. `Context.paid_action_hashes` is populated from the ledger's executed
  receipts; `decide()` denies with `DUPLICATE_PAYMENT` when the proposal's `action_hash` is already paid.
  `action_hash` excludes `proposal_id` (so a re-submitted invoice hashes identically) and binds payee + amount +
  currency + debit + rail. Strictly additive: a new DENY reason, so no other rule is relaxed and no security
  test was weakened.
- Scope (honest): catches a repeated request for the same canonical action; does **not** do fuzzy
  "same invoice with OCR/formatting variation" matching (documented limitation).
- Evidence: scenario T06 now `first=ALLOW/executed=True, second=DENY/executed=False` → PASS; scenarios 10/10.
- Regression tests: `packages/policy_engine/tests/test_engine_rules.py` (duplicate denied; keyed on action not
  proposal_id; a different amount is not a duplicate; empty set → ALLOW),
  `tests/test_api_flows.py::test_duplicate_invoice_is_denied_and_never_debits_again` (no second debit, one
  ledger row).
- Status: fixed

### BUG-012 · Documentation factual inconsistency: attack-family count and results wording
- Date: 2026-10-18 · Severity: S3 · Area: docs · Source: external review
- Finding: README and other docs said "25 families × 4" while the report has **96 attack cases** (24 attack
  families × 4), with **A25** being a benign look-alike family that must not be blocked; the false-block and
  task-completion summaries were terse and could be read as over-claiming.
- Fix: README now states "24 attack families × 4 = 96 cases + A25 benign look-alikes", gives CI bounds, phrases
  the false-block result as "0 false blocks among 4 benign cases", and reports scenarios as
  "10/10 ran pass". `docs/testing.md`, `docs/prd.md`, `docs/implementation_plan.md`, the ports evidence and the
  deck wording are aligned to the same numbers.
- Status: fixed

### BUG-010 · No UI to add a verified payee, and a new payee could never match the registry
- Date: 2026-10-18 · Severity: S1 · Area: registry / planner / web
- Found by: manual (the compiler says "add your university to the verified registry", but there is no way to do
  that in the UI; and paying a legitimately-added institution was denied)
- Expected: (a) a way to add/revoke a verified payee in the app; (b) once added, a payment to that institution's
  real account is matched by the registry and proceeds (allow, or a new-payee approval), not denied
- Actual: (a) no page or route existed to add a registry entry (only a team script); (b) the engine's
  `_check_registry` returned `REGISTRY_MISMATCH` whenever `proposal.payee_id is None`, and the planner never set
  a payee_id (the LLM cannot know registry ids), so a document-derived payee could never match the registry —
  `require_registry_match` was effectively unfulfillable for a new institution
- Root cause: (a) a missing surface; (b) the payee→registry resolution step had no owner. The engine correctly
  refuses to "trust" a proposal by its raw identifiers, but nothing resolved the document payee to a registry id
- Fix: (a) a Registry page (`apps/web/src/pages/RegistryPage.tsx`) + `GET/POST /api/v1/registry` and
  `POST /api/v1/registry/{id}/revoke` (team-enrolled, signed, audited, provenance captured, trust sentence shown);
  (b) the PLANNER now resolves `payee_id` by looking the document payee up in the read-only registry by its
  identifiers (`apps/api/agents/planner/_resolve_payee_id`), so the engine verifies a real referenced entry.
  The engine's strict rule is unchanged: `payee_id is None` ⇒ DENY (a fabricated payee_ref cannot claim an entry)
- Important: an initial fix attempt loosened `_check_registry` to match by identifiers and was REVERTED — it broke
  three security tests that assert `payee_id is None` ⇒ DENY. Per CLAUDE.md §6 the tests encode the safety
  property, so the fix moved to the planner instead of weakening the engine
- Evidence: engine trace now shows `registry: pass · payee matches a valid signed registry entry` for an
  in-app-added SUST entry; `835` security tests unchanged and green
- Regression tests added: tests/test_api_flows.py::test_registry_add_then_a_matching_payment_is_verified,
  ::test_registry_match_requires_a_resolved_payee_id_from_the_planner, ::test_registry_add_rejects_duplicate_with_typed_409,
  ::test_registry_revoke_blocks_a_previously_verified_payee; scratch registry seeded from the template so tests
  never depend on or pollute the committed registry
- Status: fixed

### BUG-009 · Edit pre-fill and offline compiler refused clear rules (named-institution wording)
- Date: 2026-10-18 · Severity: S2 · Area: compiler / web
- Found by: manual (a user typed "My university is Shahjala University of Science and Technology (SUST) ..."
  and got "I could not turn that into enforceable rules")
- Expected: a clear sentence with amounts/categories compiles; an institution name is handled via the signed
  registry, not refused with a generic message; editing a mandate round-trips (re-compiling the pre-filled text
  is not gibberish)
- Actual: (a) "Edit mandate" pre-filled the textarea with raw rule type names (`min_confidence`,
  `block_anomalies`, `per per_tx`) that the compiler cannot parse; (b) in offline/replay mode any sentence with
  no exact fixture fell through to a generic refusal, even when it clearly stated a cap/category; (c) the
  refusal message did not explain that institution identity lives in the registry
- Root cause: the editor mapped rules with the display formatter (which names internal types); the replay
  client is a fixed lookup with only a few seeded sentences; the default clarification was generic
- Fix: (a) a dedicated `ruleToEditableText` pre-fill that emits only compiler-friendly phrases and omits
  internal-only rules (`min_confidence`, `block_anomalies`) — round-trips cleanly; (b) a conservative
  deterministic `_local_extract` fallback in the compiler that compiles amount/category/new-payee/verified-payee
  rules when the model refuses but the text is expressible (still refuses genuinely vague input); (c) a
  situation-specific clarification (`_clarify`) that explains the registry for named institutions and asks
  for a number otherwise; and the prompt now states that a named institution is never a rule
- Regression tests added: tests/test_compiler_planner.py::test_local_extract_compiles_a_clear_sentence_when_the_model_refuses,
  ::test_local_extract_leaves_genuinely_vague_input_to_the_refusal_path; fixtures regenerated by
  `python -m eval.fixtures_gen` (keys match the updated compiler prompt)
- Status: fixed

### BUG-008 · Public approval endpoint returned HTTP 500 on a malformed proposal
- Date: 2026-10-18 · Severity: S1 · Area: api
- Found by: manual (browser session-goal run: POST /api/v1/approvals/decision with an empty proposal body)
- Expected: a typed 4xx problem response with a stable code (CLAUDE.md §5: never leak a stack trace / 500)
- Actual: `approval_decision` called `ActionProposal.model_validate(body.proposal)` unguarded, so an
  incomplete/invalid proposal raised a raw `pydantic ValidationError` → HTTP 500 and an ASGI traceback in
  the server log. The guardian endpoint is public and token-bound, so this is reachable by any client.
- Root cause: no validation guard and no typed error path on the public approval route
- Fix: the route now wraps `ActionProposal.model_validate` and returns `400 PROPOSAL_INVALID`, and rejects a
  missing token with `400 APPROVAL_TOKEN_INVALID` (apps/api/routes/proposals.py:approval_decision)
- Evidence: uvicorn traceback for `POST /api/v1/approvals/decision 500`; post-fix `400 {"code":"PROPOSAL_INVALID"}`
- Regression tests added: tests/test_api_flows.py::test_approval_endpoint_rejects_malformed_proposal_with_typed_400,
  ::test_approval_endpoint_requires_a_token
- Status: fixed

### BUG-007 · Offline compiler refused every input except the single seeded sentence
- Date: 2026-10-18 · Severity: S2 · Area: compiler
- Found by: manual (typing anything other than the exact example on the Mandate page)
- Expected: in the offline demo the compiler can turn several clear example rules into a candidate mandate
- Actual: only the one exact seeded sentence compiled; every other input hit `compiler_v1__default.json`
  (the BUG-006 default) and returned "I could not turn that into enforceable rules..."
- Root cause: `eval/fixtures_gen.py` wrote a single compiler fixture for one exact string; the offline
  replay client is a fixed lookup, so nothing else matched except the refusal default
- Fix: generated deterministic compiler fixtures for several clear inputs (tuition-only; "up to 2000 per
  payment"; "pay rent and tuition"; "send money to family only"), each a conservative candidate over the
  closed rule set. Genuinely ambiguous input (e.g. "send what's needed") is still refused — the compiler
  invariant "refuse what it cannot express" is preserved
- Note: this is offline demo plumbing only; the live path uses the real model and is unchanged
- Regression tests added: tests/test_redteam_300_deep.py::test_compiler_seeded_examples_compile_offline[*],
  ::test_compiler_ambiguous_input_still_refused_offline
- Status: fixed

### BUG-006 · Upload of any non-seeded document returned HTTP 500 (missing offline default fixtures)
- Date: 2026-10-18 · Severity: S1 · Area: api / reader
- Found by: manual (uploading an arbitrary invoice in the offline demo)
- Expected: `POST /api/v1/documents` returns a `ReaderOutput` for any accepted PDF/PNG/JPG, or a typed
  problem response; the offline replay mode handles documents it has no exact fixture for
- Actual: `ReplayClient.complete` raised `LLMError: no replay fixture for reader_v1__<hash>` for any
  document whose text did not byte-match one of the five seeded invoices; the route let it propagate as
  an unhandled ASGI exception → HTTP 500 and a raw traceback in the server log
- Root cause: `ReplayClient` documents a `<prompt_version>__default` fallback, but `eval/fixtures_gen.py`
  never wrote default fixtures — only exact-match ones for the seeded invoices/compiler/planner
- Fix: (a) `eval/fixtures_gen.py` now writes `reader_v1__default.json` (an honest, low-confidence
  "unknown document", category `other`, so the engine ESCALATEs and never fabricates a payee/amount — no
  invented facts, CLAUDE.md invariant 10) and `compiler_v1__default.json` (a safe refusal); (b)
  `routes/documents.py` catches `SanitizeError`/`LLMError` and returns a typed `422 READER_UNAVAILABLE`
  instead of crashing (CLAUDE.md §5: never leak a traceback)
- Evidence: server log `api.agents.llm.LLMError` traceback for `POST /api/v1/documents 500`
- Regression tests added: tests/test_redteam_300_deep.py::test_upload_unseeded_document_does_not_500,
  ::test_upload_reader_failure_returns_typed_problem_not_500, ::test_replay_default_reader_fixture_exists_and_is_honest,
  ::test_replay_default_reader_yields_escalation_not_allow, ::test_replay_default_compiler_fixture_refuses_safely,
  ::test_replay_client_still_raises_without_any_fixture
- Status: fixed

### BUG-005 · Payee-change detector missed passive/present-tense phrasings
- Date: 2026-10-18 · Severity: S2 · Area: reader
- Found by: unit (tests/test_redteam_300_deep.py, deep red-team pass)
- Expected: the deterministic detector flags a hostile document that redirects payment, e.g.
  "the payee was replaced" or "the beneficiary is now X", as `PAYEE_CHANGE_NOTICE`
- Actual: the regex matched only `has (been) changed|updated|replaced`; phrasings using `was`/`were`/
  `is now`/bare verbs were not flagged (INSTRUCTION_LIKE_TEXT was also absent for these)
- Root cause: `_PAYEE_CHANGE_PATTERNS` allowed only the `has (been)` auxiliary sequence
- Evidence: `detect_text_flags("the payee was replaced") == set()` before the fix
- Fix: pattern broadened to cover `has been|has|was|were|is|are|been|now` plus verbs
  `changed|updated|replaced|different|amended|redirected`, and an explicit `… is/are now` form
  (apps/api/agents/reader/anomalies.py)
- Regression tests added: tests/test_redteam_300_deep.py::test_detector_payee_change_tense_variants[*]
  (positive) and ::test_detector_payee_change_no_false_positive_on_benign_lines[*] (negative guard)
- Note: defense in depth only — registry match, proposal/reader consistency and the reader's own flags
  remain the load-bearing controls; this detector is not the sole barrier.
- Status: fixed

### BUG-004 · Runtime constructed the sandbox ledger outside the executor
- Date: 2026-10-18 · Severity: S1 · Area: api
- Found by: unit (test_single_execution_path)
- Expected: only `apps/api/services/executor.py` imports `rail_sim` (invariant 11)
- Actual: `runtime.py` imported `rail_sim.ledger.SandboxLedger` to build balances
- Root cause: the composition root created the ledger directly instead of through the executor
- Fix: ledger creation moved into `executor.make_ledger()`; runtime gets the ledger from the executor
- Regression test added: tests/test_single_execution_path.py
- Status: fixed

### BUG-003 · Engine did not treat a valid registry entry as a known payee
- Date: 2026-10-18 · Severity: S1 · Area: engine
- Found by: integration (test_api_flows)
- Expected: a payee matched against a signature-valid registry entry the mandate references is "known"
  (implementation_plan §4.2 step 6), so a genuine tuition invoice is ALLOWed
- Actual: a tuition invoice to the verified university was HOLD (treated as a new payee)
- Root cause: `known` only considered the payee allowlist and `known_payee_ids`, not the registry match
- Fix: `registry_entry_id is not None` now marks the payee known
- Regression test added: tests/test_api_flows.py::test_genuine_invoice_allowed_executes_once
- Status: fixed

### BUG-002 · ReplayClient fixture keys contained a colon (invalid on Windows)
- Date: 2026-10-18 · Severity: S2 · Area: agents
- Found by: unit (fixture generation)
- Expected: fixtures written as `<prompt_version>__<hash>.json`
- Actual: `reader_v1:<hash>.json` truncated on Windows, so no fixture loaded
- Fix: separator changed to `__` (filesystem-safe); fixtures regenerated
- Regression test added: tests/test_reader.py::test_replay_client_is_used_for_offline_reader_eval
- Status: fixed

### BUG-001 · Reader sanitizer accepted unknown keys and an ambiguous confidence scale
- Date: 2026-10-18 · Severity: S2 · Area: reader
- Found by: unit (tests/test_reader.py)
- Expected: unknown keys rejected; a value that is neither 0..1 nor 0..10000 basis points rejected
- Actual: extra keys were silently dropped by the schema; `2.0` was read as 2 basis points
- Fix: explicit unknown-key rejection + an "ambiguous scale" guard for values in (1, 100)
- Regression test added: tests/test_reader.py::test_sanitizer_rejects_unknown_keys_and_extra_fields
- Status: fixed

<!-- Example (delete when real entries exist):
### BUG-001 · Hidden-text variant A01-3 bypasses reader flag
- Severity: S1 · Area: reader · Found by: attack A01-3
- Expected: anomaly HIDDEN_TEXT flagged · Actual: not flagged by reader; deterministic detector caught it (decision still DENY)
- Status: fixed (commit abc123); regression: A01-3 stays in catalog
-->

---

## 3. Spec drift log

Record any mismatch between `prd.md`, `implementation_plan.md`, `design.md`, `testing.md`, `CLAUDE.md` and the code.

| # | Date | Doc/section | Code location | Mismatch or ambiguity | Safest reading used | Resolved? |
|---|---|---|---|---|---|---|
| D-001 | 2026-10-18 | implementation_plan §4.2 step 7 | `policy_engine/decide.py` caps | Spec: "Over cap -> ESCALATE if an escalate_above rule covers it, else DENY"; S1_NOTES §3 introduced `hard`/soft caps (hard -> DENY, soft -> ESCALATE) | Followed S1_NOTES (caps carry `hard: bool`, default true); kept the spec text as-is; documented here | Explained |
| D-002 | 2026-10-18 | implementation_plan §3.3 rule set | `policy_engine/models.py` | Spec lists `time_window` and `conversion_rule` rule types; S1_NOTES §10 defers them (P2) | Not implemented; the closed set omits them and the compiler refuses them | Accepted (P2 cut) |
| D-003 | 2026-10-18 | testing.md §6 / prd.md §6.1 | `eval/attacks/generate.py` | Spec says 100 attacks split 50/50 dev/held-out; A25 benign family is not an "attack" | 96 attack cases (24 families × 4) + 4 benign; splits remain 2 dev / 2 held-out per family | Explained |
| D-004 | 2026-10-18 | CLAUDE.md §2 (LangGraph planner) | `apps/api/agents/planner` | Spec names LangGraph; S1/48-hour sprint permits a plain function chain (§9 cut 10) | Implemented as a plain function chain with an injected `complete()` | Accepted (cut) |
| D-005 | 2026-10-18 | CLAUDE.md §1 invariant 3 (security floor) & decide.py §3 | `policy_engine/decide.py` confidence check | The anomaly floor (`BASELINE_BLOCKED`) cannot be weakened by a mandate, but `min_confidence` is NOT in that floor: `min_bp = max([MinConfidence rules]) or DEFAULT_MIN_CONFIDENCE_BP`, so any mandate supplying a `min_confidence` rule replaces the 9000 bp default entirely and can lower it (e.g. to 0), removing the `LOW_CONFIDENCE` ESCALATE guard. A manipulated compiler (family A17) could compile such a rule | Lower confidence still ESCALATEs (never ALLOWs) when the rule is absent; when a low rule is present the decision is governed by the rest of the policy. Pinned as current behavior in `tests/test_redteam_300_deep.py::test_confidence_rule_low_value_lowers_the_floor_FINDING`; not changed because a user mandate legitimately sets its own confidence floor and forcing a hard floor would alter documented policy semantics | Open (accepted risk, see R-001/R-002) |

Known open ambiguities from planning (resolve early):
1. **Demo video optional vs. required:** the official checklist marks it optional, but the execution-evidence row mentions a demo video. *Safest reading:* produce it.
2. **Registration channel:** the official site requires JavaScript and could not be opened during planning; confirm the registration flow in a browser. *Safest reading:* treat registration and submission as sharing the same deadline (as the PDF states).
3. **Calendar date — RESOLVED (v1.1):** today is 18 Oct 2026, so Track B/C applies and the 48-hour sprint in `implementation_plan.md` §6A is the default. (An earlier planning message assumed six days; that was wrong.)
4. **Hosted demo vs. repo + video:** the PDF requires a GitHub repo link and deployment instructions, not a hosted URL. *Safest reading:* repo + video + local-run instructions; hosted demo only if time remains.

---

## 4. Pre-submission audit checklist (run at M6 and again at G-8)

### 4.1 Plan-vs-code audit (find missing and orphaned files)

Run and record results:

```bash
# 1. Every route in the API table (implementation_plan §5) exists
grep -RhoE "@router\.(get|post|put|delete)\(\"[^\"]+\"" apps/api/routes | sort > /tmp/routes_found.txt

# 2. Every file in the repo layout (implementation_plan §1.3) exists
#    (maintain docs/expected_files.txt as a plain list, one path per line)
while read p; do [ -e "$p" ] || echo "MISSING: $p"; done < docs/expected_files.txt

# 3. Orphans: python modules never imported anywhere
python - <<'PY'
import ast, pathlib
root = pathlib.Path(".")
mods = {p.stem: p for p in root.rglob("*.py") if "tests" not in p.parts and "migrations" not in p.parts and p.name != "__init__.py"}
used = set()
for p in root.rglob("*.py"):
    try: tree = ast.parse(p.read_text())
    except Exception: continue
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module: used.update(n.module.split("."))
        if isinstance(n, ast.Import):
            for a in n.names: used.update(a.name.split("."))
for name, path in sorted(mods.items()):
    if name not in used and name not in {"main", "run_eval", "seed", "generate"}:
        print("POSSIBLY ORPHANED:", path)
PY

# 4. Frontend: unused exports/files and missing i18n keys
npx ts-prune || true
node scripts/check_i18n_keys.mjs   # every key in en.json exists in bn.json and vice versa

# 5. Secrets and licences
gitleaks detect --no-banner || true
pip-licenses --format=markdown > docs/licences_python.md
npx license-checker --summary > docs/licences_node.txt
```

### 4.2 Checklist

**Spec coverage**
- [ ] Every PRD §4.2 feature (A–G) is implemented or listed in the cut log with reason.
- [ ] Every user story US-01…US-10 has a passing test or a documented failure.
- [ ] All six docs updated to match final behavior (spec-drift table closed or explained).

**Security**
- [ ] Engine purity test passes; no LLM/network imports in `packages/policy_engine`.
- [ ] No code path calls the rail simulator except `services/executor.py`.
- [ ] Reader function has no access to tools, DB writes or registry writes.
- [ ] Planner input never contains raw document text (test double verified).
- [ ] Mandate, registry and attestation signatures verified at every decision-relevant read.
- [ ] Approval tokens hashed at rest, single-use, expiring, bound to `input_hash`.
- [ ] Uploads validated (MIME sniff, size, path handling).
- [ ] CSRF, CORS, CSP and security headers configured; error responses sanitized.
- [ ] Audit chain verifies on the final DB and the exported evidence.
- [ ] No secrets in git history; only `demo_*` keys committed.

**Evidence**
- [ ] `make eval` report regenerated from clean state; numbers in docs match report JSON.
- [ ] `docs/execution_evidence/` contains: audit export, ledger CSV, eval report (JSON+HTML), screenshots of key flows, scenario logs.
- [ ] Every attack failure is listed in §2 and in the known-risk list.

**Compliance wording**
- [ ] No claim of regulatory compliance anywhere.
- [ ] Rule pack `bd.json` marked UNVERIFIED in file, docs and UI.
- [ ] All results labeled simulated/synthetic.

**Submission**
- [ ] Links open from a logged-out browser (repo, video, docs).
- [ ] README reproduces: setup, run, test, eval.
- [ ] Presentation ≤ 10 min (timed); video ≤ 5 min (timed).
- [ ] Team roster/eligibility confirmed; registration confirmed; submission timestamp noted.
- [ ] README "Team eligibility" section contains real, confirmed facts (no placeholders); licence statement matches the scan.
- [ ] Clean-container run of `make setup && make test && make eval` recorded in `docs/execution_evidence/portability.md`.

---

## 5. Risk register (known-risk list for the security self-assessment)

Likelihood (L) and Impact (I): 1 low – 3 high. Status: open / mitigated / accepted. Update after the benchmark; **do not soften entries after seeing results.**

| ID | Risk | L | I | Mitigation in design | Residual risk / what we will report | Status |
|---|---|---|---|---|---|---|
| R-001 | **Policy compiler misreads intent** and produces a more permissive policy than the user meant | 2 | 3 | Closed rule set; back-translation; auto-generated allow/deny test cases; explicit user confirm; refusal on ambiguity; dangerous-error rate measured | Compiler accuracy and dangerous-error rate from §4.1 of testing.md; humans can still confirm a wrong policy | open |
| R-002 | **Reader extracts wrong fields** (amount/account) from low-quality documents | 3 | 3 | Confidence threshold + abstention; registry cross-check; amount sanity vs invoice totals; escalation | Measured extraction accuracy; threshold is a synthetic-data heuristic/prototype guarantee | open |
| R-003 | **Prompt injection via documents** manipulates the reader or planner | 3 | 3 | Reader has no tools; schema-constrained output; sanitizer; deterministic detectors; planner never sees raw text; engine decides | Static benchmark only; adaptive attacks may do better; published work shows many defenses fail adaptively | open |
| R-004 | **Registry compromise or stale registry** leads to accepting a wrong payee | 2 | 3 | Ed25519 signatures; versioned registry; signature check on every read; stale-version flag | In production, registry provenance and update process are unsolved in this prototype | accepted |
| R-005 | **Homoglyph/Unicode tricks** bypass matching | 2 | 3 | NFKC normalization; confusable detection; exact match; property test I4 | Unicode edge cases beyond tested families | open |
| R-006 | **Split-payment structuring** evades per-transaction caps | 2 | 2 | Rolling-window caps computed from ledger; property test I5 | Windows chosen by user may still allow slow-drip abuse within caps | open |
| R-007 | **Approval token theft/replay** | 1 | 3 | Hashed single-use tokens, expiry, input-hash binding, re-evaluation, rate limiting | Demo auth is simplified (seeded users); no real identity proofing | accepted |
| R-008 | **Social engineering of the guardian** (user pressured to approve) | 2 | 2 | Plain-language reasons; mandatory display of payee/amount; cooling-off for new payees | Cannot prevent a deceived human approving | accepted |
| R-009 | **Sandbox realism**: simulated rails and rate cards may not reflect real costs | 3 | 2 | Cards labeled SIMULATED; sources cited in file comments; savings reported only vs simulated default | No claim about real provider prices | accepted |
| R-010 | **Regulatory misstatement**: rule pack not verified against current Bangladesh Bank rules | 2 | 3 | Rule pack marked UNVERIFIED; no compliance claims | Needs verification by a qualified person before any real use | open |
| R-011 | **Synthetic-data validity**: results on synthetic documents/users may not generalize | 3 | 2 | Label everything synthetic; avoid behavior-change claims; diversify fixtures | No real-user evidence | accepted |
| R-012 | **LLM nondeterminism / model drift** changes results between runs | 2 | 2 | Temperature 0; replay fixtures; prompt versioning; live check before submission | Live runs may differ from replay | open |
| R-013 | **Audit log tampering by an insider with DB access** | 1 | 3 | Hash chain; verify endpoint; export | Hash chain detects but doesn't prevent; no external anchoring | accepted |
| R-014 | **Denial of service / cost abuse** via repeated uploads or LLM calls | 2 | 1 | Size limits, rate limiting, per-user quotas | Demo-grade controls | accepted |
| R-015 | **Privacy**: uploaded documents may contain personal data | 2 | 2 | Synthetic data only in repo/demo; delete on reset; no real passports in uploads | Real deployment would need retention policy | accepted |
| R-016 | **Over-trust / automation bias** in the UI (users approve everything) | 2 | 2 | Reason-first explanations; no pre-selected approve; show what changed | Not measured with real users | accepted |
| R-017 | **Time risk**: very short build window leads to incomplete security tests | 3 | 3 | Scope-cut ladder; never-cut list; track selection by hours-left | Reduced benchmark size if Track B/C | open |
| R-018 | **Over-claiming novelty** | 2 | 2 | Pitch says recombination vs. contribution explicitly; cites nearest prior work | Judges may still view as incremental | open |
| R-019 | **Dependency/licence issues** | 1 | 2 | THIRD_PARTY.md; licence scans | Missed transitive licence | open |
| R-020 | **Team eligibility/registration error** disqualifies entry | 2 | 3 | Confirm roster, nationality rule, registration receipt early | Dependent on organizer interpretation | open |
| R-021 | **Cryptographic integrity mistaken for real-world trust**: a signed registry record proves it was not altered, not that the institution is genuine | 2 | 3 | Provenance fields (method, source URL, retrieval date, second check), validity window, revocation, retired-key handling; UI states "a signature does not prove the institution is genuine" | Demo registry is team-enrolled from public pages with server-held keys; production needs institutional enrollment and out-of-band verification | open |
| R-022 | **Full audit-log rewrite** by someone who can recompute every hash | 1 | 3 | Separate checkpoint key signs head hash; checkpoints exported to evidence and printed in README/video | If DB and checkpoint key are both compromised the log can be forged | accepted |
| R-023 | **Reader isolation by convention only**: reader could be given tools by a later code change | 2 | 3 | Capability injection (document + `complete()` only); AST import test; runtime signature test | Reader still has LLM egress and can be manipulated into wrong extraction (see R-002, R-003) | open |
| R-024 | **Execution bypass or post-approval tampering** (changed beneficiary/amount, replayed approval, stale decision) | 2 | 3 | Signed `decision_token` bound to `action_hash`, mandate and registry versions; single executor path; nonce; U-EXEC tests | A bug in the executor or compromise of the engine key defeats it | open |
| R-025 | **Benchmark overfitting / validity**: tuning against the cases later reported | 3 | 2 | Dev/held-out split frozen by hash; held-out run once; raw counts and Wilson intervals; stage-attributed failures | Static, self-authored set; independent reproduction not yet done | open |
| R-026 | **Mandate signing authority**: signing key is server-held in the prototype | 2 | 2 | Documented; versions are append-only; superseded versions invalid | Production needs user-held device keys, re-authentication and revocation | accepted |
| R-027 | **Unvalidated user need**: no interviews with real students or guardians | 3 | 2 | Specific scenario written; no usage or behavior claims; ask 2–3 students/guardians to try the demo if time permits and record comments here | Cannot claim product-market fit | accepted |
| R-028 | **Cooling-off hold causes a missed tuition deadline** | 2 | 2 | Deadline-aware warning; co-signer can release a HOLD early (bound to `action_hash`); never overrides DENY | Guardian may be unreachable; hold is a deliberate trade-off between safety and speed | open |
| R-029 | **Over-broad or inaccurate claims** ("LLM can never cause a wrong payment", "all dependencies MIT", real savings) | 2 | 3 | Wording guardrails in `prd.md` §0.1; licence scan before any licence statement; savings stated vs simulated default route | A mis-extraction that satisfies mandate and registry can still pass (R-002) | open |

---

## 6. Limitations to disclose (plain language — copy into README, deck and UI "About")

1. Sandbox only: no real money, banks, or identity checks.
2. All documents, users and balances are synthetic; results may not hold on real data.
3. The benchmark is static; a determined adaptive attacker may succeed where our tests did not.
4. The policy compiler can still be wrong; the safety loop reduces but does not remove this risk.
5. The reader can misread documents; low-confidence cases are escalated, not guaranteed correct.
6. Rate cards are simulated; savings numbers are relative to a simulated default rail.
7. The Bangladesh rule pack is unverified placeholder content, not legal advice.
8. The credit-building feature is a signed-attestation prototype; no lender accepts it.
9. We make no claim that this system changes user behavior or saves real users money.
10. The registry's real-world governance (who verifies institutions, how updates are signed) is out of scope.
11. A wrong extraction that still satisfies the mandate and the registry (for example a wrong amount under the cap) can lead to a wrong-but-permitted payment; the LLM has no authority to execute, but it can influence what is proposed.

---

## 7. Console and log captures

Paste raw excerpts here (trim to the relevant lines; remove secrets).

```
<date> <component> <error>
```

---

## 8. Decisions log

Short record of choices made under uncertainty so judges and teammates can follow the reasoning.

| Date | Decision | Alternatives considered | Reason |
|---|---|---|---|
| (planning) | Topic C, not Topic F | Topic F on-chain wallet | Same scoring weights; on-chain adds legal and time risk; bonus is only 0–5 points |
| (planning) | Deterministic engine decides; LLM never approves | LLM "auditor" agent | Literature shows adaptive attacks defeat many LLM-based defenses; structural isolation is more defensible |
| (planning) | No FX prediction | FX timing feature | No credible evidence of timing gains for small senders; fee/spread choice is defensible |
| (planning) | Credit building = signed attestation prototype | Full credit-score feature | No evidence base; avoid over-claiming |
| (planning) | Registry-based payee verification | Trust document payee | Directly addresses invoice-redirection fraud class |
| (planning) | Repo + video + local-run, hosted demo optional | Mandatory hosted demo | Official checklist asks for repo/deploy instructions, not a URL |
| 2026-10-18 | Flagship = tuition invoice flow with one corridor (BDT→USD); defer recurring allowance, multi-currency automation, attestation | Keep all eight feature groups | About two days remain; a simulated judge panel and the scoring weights favor one reliable end-to-end task plus measured security evidence |
| 2026-10-18 | Executor accepts only a signed, action-bound decision token | Trust the policy engine's return value in-process | A tough reviewer will ask whether a modified proposal can reuse an earlier ALLOW or whether any path bypasses the engine |
| 2026-10-18 | Rejected two suggestions from a second simulated panel: (a) the line "structural isolation prevents the LLM from ever executing a payment, regardless of prompt success"; (b) a blanket "all dependencies are MIT/Apache-2.0" statement | Use both as written | (a) overclaims: a mis-extraction within caps can still pass, so we say the LLM lacks authority to execute and report the residual risk; (b) licences are mixed (MIT, BSD, PSF…), so claim only what the scan shows |
| 2026-10-18 | Accepted: co-signer release of HOLD bound to `action_hash`; README eligibility section; clean-container run; enforcement-point table with real file:function names | — | Addresses deadline risk, disqualification risk, reproduction failure, and judges' grep-for-enforcement habit |
| 2026-10-18 | Scenario suite added as `eval/scenarios/run.py`, wired into `eval/reports/latest.json` and `docs/execution_evidence/index.md` | A separate pytest-only harness | Keeps the 40% task-completion numbers in the same report as the red-team numbers, so every doc number traces to one file |
| 2026-10-18 | T06 (duplicate invoice) reported as an honest **skip** rather than a pass | Add a bespoke duplicate rule | The closed rule set has no duplicate-detection rule; claiming a pass would over-claim. Logged in the evidence index and here |
| 2026-10-18 | Held-out hash gate added to the runner (`_verify_heldout_hash`) | Trust the committed file | Enforces the frozen-set discipline (testing.md §6); the runner now refuses to run if the held-out set changed |
| 2026-10-18 | `POST /admin/reset` added (demo-mode only) for deterministic demo + e2e isolation | Rely on process restarts | Required by implementation_plan §5; makes the e2e suite order-independent |
| 2026-10-18 | Held-out hash file made committed (removed from `.gitignore`) and the gate now fails closed on a missing/empty file | Leave the ignored file in place with a silent early return | A review found the gate was a no-op on a clean clone (the ignored file is never committed, per testing.md §6 it must be). Fixed in `eval/run_eval.py:_verify_heldout_hash` + tests |
| 2026-10-18 | Demo mandate rules and the genuine-invoice fixture moved to `eval/fixtures_common.py` | Keep three verbatim copies | Review found drift risk across `eval/run_eval.py`, `eval/scenarios/run.py`, `tests/test_api_flows.py` and `eval/evidence.py`; a one-sided cap/threshold edit would silently diverge results |
| 2026-10-18 | Scenario `by_category` now counts every case (incl. skipped) in the denominator; T02/R02 strengthened to exercise decide()+execute(); E2E-08 asserts "Chain valid" (not "valid or broken") | Leave as-is | Review findings: `by_category` diverged from the testing.md §10 shape; T02/R02 were tautologies; E2E-08 accepted a broken chain |

---

## 9. Daily status snapshot (fill at end of each build day)

| Day / T-minus | Phase done | Tests passing | Open S0/S1 | Biggest risk now | Cuts made |
|---|---|---|---|---|---|
| | | | | | |
