"""The policy engine: decide(signed_mandate, proposal, ctx) -> Decision.

Pure and deterministic: no LLM, no network, no clock, no randomness. Strictest outcome wins:
DENY > HOLD > ESCALATE > ALLOW. Default is DENY. (implementation_plan §4)
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta

from pydantic import ValidationError

from .canonical import action_hash as compute_action_hash
from .canonical import canonical_json, sha256_hex
from .models import (
    ActionProposal,
    BlockAnomalies,
    Cap,
    CategoryAllow,
    Context,
    CoolingOff,
    Decision,
    EscalateAbove,
    Mandate,
    MinConfidence,
    NewPayee,
    PayeeAllowlist,
    RailAllow,
    RegistryEntry,
    RequireRegistryMatch,
    SignedMandate,
    TraceStep,
)
from .signing import verify

ENGINE_VERSION = "0.1.0"
# Security floor: a mandate (and therefore a manipulated compiler, family A17) can never weaken these.
BASELINE_BLOCKED = frozenset({"HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"})
DEFAULT_MIN_CONFIDENCE_BP = 9000
_WINDOW_DAYS = {"rolling_7d": 7, "rolling_30d": 30}


def norm(s: str) -> str:
    """NFKC + trim + collapse whitespace. No case folding and no deleting characters: one changed
    character in a payee, account or bank identifier must change the comparison (invariant I4)."""
    return " ".join(unicodedata.normalize("NFKC", s).split())


@dataclass
class _Item:
    level: str  # DENY | HOLD | ESCALATE
    code: str
    rule_id: str | None = None
    approvers: tuple[str, ...] = ()
    hold_until: datetime | None = None


@dataclass
class _Acc:
    items: list[_Item] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)
    passes: list[str] = field(default_factory=list)

    def step(self, name: str, items: list[_Item], ok_detail: str, ok_code: str | None = None) -> None:
        if not items:
            self.trace.append(TraceStep(step=name, result="pass", detail=ok_detail))
            if ok_code:
                self.passes.append(ok_code)
            return
        self.items.extend(items)
        worst = max(items, key=lambda i: {"ESCALATE": 1, "HOLD": 2, "DENY": 3}[i.level]).level
        self.trace.append(TraceStep(step=name, result=worst.lower(), detail="; ".join(i.code for i in items)))  # type: ignore[arg-type]


def _final(decision: str, tier: str, **kw) -> Decision:  # type: ignore[no-untyped-def]
    return Decision(decision=decision, tier=tier, engine_version=ENGINE_VERSION, **kw)  # type: ignore[arg-type]


def decide(signed: SignedMandate, proposal: ActionProposal, ctx: Context) -> Decision:
    ah = compute_action_hash(proposal)
    input_hash = sha256_hex({
        "mandate": signed.body, "signature": signed.signature, "signer": signed.signer_key_id,
        "proposal": proposal.model_dump(mode="json"), "ctx": ctx.model_dump(mode="json"),
    })

    def early_deny(code: str, detail: str, mandate: Mandate | None = None) -> Decision:
        return _final(
            "DENY", "T4", reason_codes=(code,), input_hash=input_hash, action_hash=ah,
            mandate_id=mandate.mandate_id if mandate else None,
            mandate_version=mandate.version if mandate else None,
            trace=(TraceStep(step="integrity", result="deny", detail=detail),),
        )

    # ---- 1. integrity: signature, schema, active version ----
    key = ctx.mandate_keys.get(signed.signer_key_id)
    if key is None or key.status != "active":
        return early_deny("MANDATE_INVALID", "unknown or retired mandate signing key")
    if not verify(key.public_key_b64, canonical_json(signed.body), signed.signature):
        return early_deny("MANDATE_INVALID", "mandate signature invalid")
    try:
        mandate = Mandate.model_validate(signed.body)
    except ValidationError:
        return early_deny("MANDATE_INVALID", "mandate does not match the closed rule set")
    if mandate.version != ctx.active_mandate_version:
        return early_deny("MANDATE_SUPERSEDED", f"v{mandate.version} is not the active version", mandate)

    # ---- 1b. duplicate payment (idempotency at the decision layer) ----
    # The action_hash binds payee + amount + currency + debit + rail and excludes proposal_id, so a re-submitted
    # invoice yields the same hash. If that exact action already executed, deny it: no second debit, no second
    # payment. This is strictly additive (a new DENY) and never relaxes another rule. (review finding: T06)
    if ah in set(ctx.paid_action_hashes):
        return _final(
            "DENY", "T4", reason_codes=("DUPLICATE_PAYMENT",), input_hash=input_hash, action_hash=ah,
            mandate_id=mandate.mandate_id, mandate_version=mandate.version,
            trace=(TraceStep(step="integrity", result="pass", detail=f"mandate v{mandate.version} signature valid"),
                   TraceStep(step="duplicate", result="deny",
                             detail="this exact payment already executed (same payee, amount and debit)")),
        )

    rules = sorted(mandate.rules, key=lambda r: r.id)  # rule order must not influence the outcome (I2)
    cosigners = tuple(sorted(c.id for c in mandate.co_signers))
    acc = _Acc()
    acc.trace.append(TraceStep(step="integrity", result="pass", detail=f"mandate v{mandate.version} signature valid"))
    reader = ctx.reader

    if proposal.action not in ("pay", "transfer"):
        acc.items.append(_Item("DENY", "ACTION_NOT_SUPPORTED"))
        acc.trace.append(TraceStep(step="action", result="deny", detail=f"{proposal.action} is not supported"))

    # ---- 2. anomalies (baseline floor + mandate rules) ----
    flags = (set(ctx.detector_flags) | (set(reader.anomalies) if reader else set())) - {"NONE"}
    its: list[_Item] = []
    if flags & BASELINE_BLOCKED:
        its.append(_Item("DENY", "ANOMALY_BLOCKED", "baseline"))
    for r in rules:
        if isinstance(r, BlockAnomalies) and flags & set(r.anomalies):
            its.append(_Item("DENY", "ANOMALY_BLOCKED", r.id))
    acc.step("anomalies", its, "no blocking anomalies")

    # ---- 2b. proposal must agree with the document the reader parsed (planner cannot invent fields) ----
    its = []
    if reader is not None and proposal.doc_ref is not None:
        same_money = reader.amount_minor == proposal.amount_minor and reader.currency == proposal.currency
        ref = proposal.payee_ref
        same_payee = ref is not None and (
            norm(ref.name) == norm(reader.payee_name)
            and norm(ref.account_identifier) == norm(reader.account_identifier)
            and norm(ref.bank_identifier) == norm(reader.bank_identifier)
        )
        if not (same_money and same_payee):
            its.append(_Item("DENY", "PROPOSAL_READER_MISMATCH"))
    acc.step("consistency", its, "proposal matches the document")

    # ---- 3. confidence ----
    its = []
    min_bp = max([r.value_bp for r in rules if isinstance(r, MinConfidence)] or [DEFAULT_MIN_CONFIDENCE_BP])
    if proposal.doc_ref is not None and reader is None:
        its.append(_Item("ESCALATE", "READER_OUTPUT_MISSING", approvers=cosigners))
    elif reader is not None and reader.extraction_confidence_bp < min_bp:
        ids = [r.id for r in rules if isinstance(r, MinConfidence)]
        its.append(_Item("ESCALATE", "LOW_CONFIDENCE", ids[0] if ids else None, cosigners))
    acc.step("confidence", its, f"confidence meets {min_bp} bp")

    # ---- 4. category (default deny: something must explicitly permit it) ----
    allowed_cats = {c for r in rules if isinstance(r, CategoryAllow) for c in r.categories}
    its = [] if proposal.category in allowed_cats else [_Item("DENY", "CATEGORY_NOT_ALLOWED")]
    acc.step("category", its, f"{proposal.category} is permitted", "CATEGORY_ALLOWED")

    # ---- 5. registry ----
    registry_version: str | None = None
    registry_entry_id: str | None = None
    needs_registry = any(
        isinstance(r, RequireRegistryMatch) and ("*" in r.categories or proposal.category in r.categories)
        for r in rules
    )
    its = []
    if needs_registry:
        code, entry = _check_registry(proposal, ctx)
        if code:
            its.append(_Item("DENY", code))
        elif entry is not None:
            registry_version, registry_entry_id = entry.registry_version, entry.entity_id
        acc.step("registry", its, "payee matches a valid signed registry entry", "REGISTRY_MATCH")
    else:
        acc.trace.append(TraceStep(step="registry", result="skipped", detail="not required for this category"))

    # ---- 6. payee status, new-payee escalation, cooling-off ----
    allowlist = {p for r in rules if isinstance(r, PayeeAllowlist) for p in r.payee_ids}
    registry_known = registry_entry_id is not None  # a valid registry entry referenced by the mandate is known
    known = registry_known or (proposal.payee_id is not None
                               and (proposal.payee_id in allowlist or proposal.payee_id in ctx.known_payee_ids))
    its = []
    hold_until: datetime | None = None
    if not known:
        np_rules = [r for r in rules if isinstance(r, NewPayee)]
        if not np_rules:
            its.append(_Item("DENY", "PAYEE_NOT_ALLOWED"))
        else:
            appr = tuple(sorted({a for r in np_rules for a in r.approvers})) or cosigners
            its.append(_Item("ESCALATE", "NEW_PAYEE", np_rules[0].id, appr))
            for r in rules:
                if isinstance(r, CoolingOff):
                    start = ctx.hold_started_at or ctx.now
                    until = start + timedelta(hours=r.hours)
                    if ctx.now < until:
                        its.append(_Item("HOLD", "COOLING_OFF", r.id, appr, until))
                        hold_until = max(hold_until, until) if hold_until else until
    acc.step("payee", its, "payee is known", "KNOWN_PAYEE")

    # ---- 7. caps (computed from the ledger, never from the proposal) ----
    its = []
    for r in rules:
        if not isinstance(r, Cap) or not ("*" in r.categories or proposal.category in r.categories):
            continue
        if r.currency != proposal.currency:
            its.append(_Item("DENY", "CAP_CURRENCY_UNSUPPORTED", r.id))
            continue
        if r.scope == "per_tx":
            used = 0
        else:
            since = ctx.now - timedelta(days=_WINDOW_DAYS[r.scope])
            used = sum(e.amount_minor for e in ctx.ledger
                       if e.currency == r.currency and e.ts > since and ("*" in r.categories or e.category in r.categories))
        if used + proposal.amount_minor > r.amount_minor:
            its.append(_Item("DENY" if r.hard else "ESCALATE", "OVER_CAP" if r.hard else "OVER_SOFT_CAP", r.id,
                             () if r.hard else cosigners))
    acc.step("caps", its, "within all caps", "WITHIN_CAP")

    # ---- 8. escalation thresholds ----
    its = []
    for r in rules:
        if isinstance(r, EscalateAbove):
            if r.currency != proposal.currency:
                its.append(_Item("DENY", "CAP_CURRENCY_UNSUPPORTED", r.id))
            elif proposal.amount_minor > r.amount_minor:
                its.append(_Item("ESCALATE", "ESCALATE_ABOVE", r.id, r.approvers or cosigners))
    acc.step("escalation", its, "below escalation threshold")

    # ---- 9. rail ----
    rail_rules = [r for r in rules if isinstance(r, RailAllow)]
    its = []
    if rail_rules and proposal.rail_id not in {x for r in rail_rules for x in r.rail_ids}:
        its.append(_Item("DENY", "RAIL_NOT_ALLOWED", rail_rules[0].id))
    acc.step("rail", its, "rail permitted")

    # ---- 10. funds ----
    bal = ctx.balances.get(proposal.source_account)
    its = []
    if bal is None:
        its.append(_Item("DENY", "UNKNOWN_ACCOUNT"))
    elif proposal.source_debit_minor > bal:
        its.append(_Item("DENY", "INSUFFICIENT_FUNDS"))
    acc.step("funds", its, "sufficient funds")

    # ---- approvals are inputs, never bypasses; they cannot override DENY ----
    same_action = [a for a in ctx.approvals if a.action_hash == ah and a.mandate_version == mandate.version]
    if any(a.status == "rejected" for a in same_action):
        acc.items.append(_Item("DENY", "APPROVAL_REJECTED"))
        acc.trace.append(TraceStep(step="approval", result="deny", detail="an approver rejected this exact action"))
    valid = [a for a in same_action if a.status == "approved" and a.expires_at > ctx.now]

    def resolved(item: _Item) -> bool:
        who = set(item.approvers or cosigners)
        return any(a.approver_id in who for a in valid)

    denies = [i for i in acc.items if i.level == "DENY"]
    pending = [i for i in acc.items if i.level in ("HOLD", "ESCALATE") and not resolved(i)]
    if any(i.level in ("HOLD", "ESCALATE") and resolved(i) for i in acc.items) and not denies:
        acc.trace.append(TraceStep(step="approval", result="pass", detail="valid approval bound to this exact action"))

    common = dict(input_hash=input_hash, action_hash=ah, mandate_id=mandate.mandate_id, mandate_version=mandate.version,
                  registry_version=registry_version, registry_entry_id=registry_entry_id)
    due_risk = False
    if reader is not None and reader.due_date and hold_until is not None:
        try:
            due_risk = hold_until.date() >= date.fromisoformat(reader.due_date)
        except ValueError:
            due_risk = False

    if denies:
        return _final("DENY", "T4", reason_codes=tuple(sorted({i.code for i in denies})),
                      failed_rule_ids=tuple(sorted({i.rule_id for i in denies if i.rule_id})),
                      trace=tuple(acc.trace), **common)
    holds = [i for i in pending if i.level == "HOLD"]
    if holds:
        return _final("HOLD", "T3", reason_codes=tuple(sorted({i.code for i in pending})),
                      failed_rule_ids=tuple(sorted({i.rule_id for i in pending if i.rule_id})),
                      required_approvers=tuple(sorted({a for i in pending for a in (i.approvers or cosigners)})),
                      hold_until=max(i.hold_until for i in holds if i.hold_until), deadline_at_risk=due_risk,
                      trace=tuple(acc.trace), **common)
    if pending:
        return _final("ESCALATE", "T3", reason_codes=tuple(sorted({i.code for i in pending})),
                      failed_rule_ids=tuple(sorted({i.rule_id for i in pending if i.rule_id})),
                      required_approvers=tuple(sorted({a for i in pending for a in (i.approvers or cosigners)})),
                      trace=tuple(acc.trace), **common)
    codes = sorted(set(acc.passes) | ({"APPROVED"} if valid and acc.items else set()))
    return _final("ALLOW", "T2", reason_codes=tuple(codes), trace=tuple(acc.trace), **common)


def _check_registry(proposal: ActionProposal, ctx: Context) -> tuple[str | None, RegistryEntry | None]:
    """Returns (deny_code, entry). Exact match after NFKC; signature, key status, validity window, revocation.

    The proposal MUST carry a payee_id: the planner is the only component that resolves a document payee to a
    registry entity id, and the engine verifies that the referenced entry's identifiers match the proposal's.
    A missing payee_id is a DENY — a proposal cannot become "known" merely by supplying matching identifiers
    (that would let a fabricated payee_ref claim a registry entry without the registry lookup the planner owes).
    """
    ref = proposal.payee_ref
    if ref is None or proposal.payee_id is None:
        return "REGISTRY_MISMATCH", None
    signed = next((s for s in ctx.registry if s.body.get("entity_id") == proposal.payee_id), None)
    if signed is None:
        return "REGISTRY_MISMATCH", None
    try:
        entry = RegistryEntry.model_validate(signed.body)
    except ValidationError:
        return "REGISTRY_SIGNATURE_INVALID", None
    key = ctx.registry_keys.get(entry.signer_key_id)
    if key is None or key.status != "active":
        return "REGISTRY_SIGNATURE_INVALID", None
    if not verify(key.public_key_b64, canonical_json(signed.body), signed.signature):
        return "REGISTRY_SIGNATURE_INVALID", None
    if entry.revoked_at is not None and entry.revoked_at <= ctx.now:
        return "REGISTRY_ENTRY_REVOKED", None
    if not (entry.valid_from <= ctx.now <= entry.valid_to):
        return "REGISTRY_ENTRY_EXPIRED", None
    if not (norm(ref.name) == norm(entry.legal_name)
            and norm(ref.account_identifier) == norm(entry.account_identifier)
            and norm(ref.bank_identifier) == norm(entry.bank_identifier)):
        return "REGISTRY_MISMATCH", None
    return None, entry
