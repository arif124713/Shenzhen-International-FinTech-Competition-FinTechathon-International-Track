# S1 build notes (deviations from the first draft of the specs — keep specs in sync)
1. `action_hash` also binds `source_debit_minor` (a changed fee/debit must not ride on an earlier ALLOW or approval).
2. Confidence is integer basis points (`extraction_confidence_bp`, `min_confidence.value_bp`) because canonical JSON forbids floats.
3. Caps have `hard: bool` (default true). Hard cap exceeded -> DENY; soft cap exceeded -> ESCALATE. (Spec §4.2 step 7 said "ESCALATE if an escalate_above rule covers it"; hard caps are safer and clearer.)
4. A `consistency` step compares the proposal with the reader output; a mismatch -> DENY `PROPOSAL_READER_MISMATCH` (planner cannot invent fields).
5. Security floor in the engine: HIDDEN_TEXT, INSTRUCTION_LIKE_TEXT, PAYEE_CHANGE_NOTICE are always DENY, even if the mandate omits `block_anomalies` (family A17).
6. Normalisation is NFKC + trim + whitespace collapse only (no case folding, no deleting characters). Identifier canonicalisation (e.g., removing spaces in IBAN groups) is the reader sanitiser's job (S2), applied to both reader output and registry data.
7. Invariant I1 covers restrictive rules only (cap, escalate_above, block_anomalies, min_confidence, require_registry_match). Permit-list rules (category_allow, payee_allowlist, rail_allow) and new_payee/cooling_off are additive by design; the compiler must emit "replace", not "append", when a user narrows a permit list.
8. Rules are sorted by id inside `decide()` so rule order cannot change outcomes.
9. Import roots: tests run with pythonpath = packages, services, apps. The API is imported as `api.services.*`, the simulator as `rail_sim`.
10. Not yet implemented in the engine: `time_window` and `conversion_rule` rule types (P2).
