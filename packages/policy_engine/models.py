"""Contracts (implementation_plan §3). All models are frozen and reject unknown fields."""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Currency = Annotated[str, Field(pattern=r"^[A-Z]{3}$")]
Category = Literal["tuition", "rent", "insurance", "family_support", "other"]
Anomaly = Literal[
    "HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE", "LOW_IMAGE_QUALITY",
    "AMOUNT_INCONSISTENT", "MULTI_PAYEE", "NONE",
]
DecisionName = Literal["ALLOW", "HOLD", "ESCALATE", "DENY"]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_aware(v: datetime | None) -> datetime | None:
    if v is not None and (v.tzinfo is None or v.tzinfo.utcoffset(v) is None):
        raise ValueError("datetime must be timezone-aware")
    return v


# ---------- inputs ----------
class PayeeRef(Strict):
    name: str = Field(max_length=120)
    account_identifier: str = Field(max_length=64)
    bank_identifier: str = Field(max_length=34)


class ReaderOutput(Strict):
    doc_type: Literal["invoice", "offer_letter", "receipt", "bank_notice", "unknown"]
    payee_name: str = Field(max_length=120)
    account_identifier: str = Field(max_length=64)
    bank_identifier: str = Field(max_length=34)
    amount_minor: int = Field(gt=0)
    currency: Currency
    due_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    reference: str = Field(default="", max_length=64)
    category_guess: Category
    extraction_confidence_bp: int = Field(ge=0, le=10000)  # basis points: 9000 = 0.90 (no floats in canonical JSON)
    anomalies: tuple[Anomaly, ...] = ()
    doc_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActionProposal(Strict):
    proposal_id: str
    action: Literal["pay", "transfer", "convert", "schedule_recurring"]
    category: Category
    payee_id: str | None = None
    payee_ref: PayeeRef | None = None
    amount_minor: int = Field(gt=0)
    currency: Currency
    source_account: str
    source_debit_minor: int = Field(gt=0)
    rail_id: str
    urgency: Literal["normal", "urgent"] = "normal"
    doc_ref: str | None = None
    created_by: Literal["planner", "user"] = "planner"


# ---------- mandate (policy DSL v1: closed rule set) ----------
class CoSigner(Strict):
    id: str
    name: str
    lang: Literal["en", "bn"] = "en"


class _Rule(Strict):
    id: str


class CategoryAllow(_Rule):
    type: Literal["category_allow"]
    categories: tuple[Category, ...]


class PayeeAllowlist(_Rule):
    type: Literal["payee_allowlist"]
    payee_ids: tuple[str, ...]


class Cap(_Rule):
    type: Literal["cap"]
    scope: Literal["per_tx", "rolling_7d", "rolling_30d"]
    amount_minor: int = Field(gt=0)
    currency: Currency
    categories: tuple[str, ...] = ("*",)
    hard: bool = True  # hard cap -> DENY when exceeded; soft cap -> ESCALATE


class RequireRegistryMatch(_Rule):
    type: Literal["require_registry_match"]
    categories: tuple[str, ...]


class NewPayee(_Rule):
    type: Literal["new_payee"]
    action: Literal["ESCALATE"] = "ESCALATE"
    approvers: tuple[str, ...] = ()


class CoolingOff(_Rule):
    type: Literal["cooling_off"]
    applies_to: Literal["new_payee"] = "new_payee"
    hours: int = Field(ge=0)


class EscalateAbove(_Rule):
    type: Literal["escalate_above"]
    amount_minor: int = Field(gt=0)
    currency: Currency
    approvers: tuple[str, ...] = ()


class MinConfidence(_Rule):
    type: Literal["min_confidence"]
    value_bp: int = Field(ge=0, le=10000)


class BlockAnomalies(_Rule):
    type: Literal["block_anomalies"]
    anomalies: tuple[Anomaly, ...]


class RailAllow(_Rule):
    type: Literal["rail_allow"]
    rail_ids: tuple[str, ...]


Rule = Annotated[
    CategoryAllow | PayeeAllowlist | Cap | RequireRegistryMatch | NewPayee | CoolingOff | EscalateAbove | MinConfidence | BlockAnomalies | RailAllow,
    Field(discriminator="type"),
]


class Mandate(Strict):
    mandate_id: str
    version: int = Field(ge=1)
    owner_id: str
    base_currency: Currency
    co_signers: tuple[CoSigner, ...] = ()
    rules: tuple[Rule, ...]
    created_at: datetime

    _aw = field_validator("created_at")(_require_aware)


class SignedMandate(Strict):
    """Raw body is kept as a dict so a mandate with an unknown rule type fails closed (DENY), not with a crash."""
    body: dict[str, Any]
    signature: str
    signer_key_id: str


# ---------- registry ----------
class RegistryEntry(Strict):
    entity_id: str
    legal_name: str
    account_identifier: str
    bank_identifier: str
    provenance: dict[str, str]
    enrolled_by: str
    valid_from: datetime
    valid_to: datetime
    revoked_at: datetime | None = None
    registry_version: str
    signer_key_id: str

    _aw = field_validator("valid_from", "valid_to", "revoked_at")(_require_aware)


class SignedRegistryEntry(Strict):
    body: dict[str, Any]
    signature: str


class KeyInfo(Strict):
    public_key_b64: str
    status: Literal["active", "retired"] = "active"


# ---------- context (everything time/state related arrives here; decide() stays pure) ----------
class LedgerEntry(Strict):
    ts: datetime
    amount_minor: int
    currency: Currency
    category: str
    payee_id: str | None = None

    _aw = field_validator("ts")(_require_aware)


class Approval(Strict):
    approval_id: str
    approver_id: str
    action_hash: str
    mandate_version: int
    expires_at: datetime
    status: Literal["approved", "rejected"]

    _aw = field_validator("expires_at")(_require_aware)


class Context(Strict):
    now: datetime
    mandate_keys: dict[str, KeyInfo]
    registry_keys: dict[str, KeyInfo]
    active_mandate_version: int
    ledger: tuple[LedgerEntry, ...] = ()
    balances: dict[str, int] = Field(default_factory=dict)
    known_payee_ids: tuple[str, ...] = ()
    registry: tuple[SignedRegistryEntry, ...] = ()
    reader: ReaderOutput | None = None
    detector_flags: tuple[Anomaly, ...] = ()
    approvals: tuple[Approval, ...] = ()
    hold_started_at: datetime | None = None

    _aw = field_validator("now", "hold_started_at")(_require_aware)


# ---------- output ----------
class TraceStep(Strict):
    step: str
    result: Literal["pass", "hold", "escalate", "deny", "skipped"]
    detail: str


class Decision(Strict):
    decision: DecisionName
    tier: Literal["T2", "T3", "T4"]
    reason_codes: tuple[str, ...]
    failed_rule_ids: tuple[str, ...] = ()
    required_approvers: tuple[str, ...] = ()
    hold_until: datetime | None = None
    deadline_at_risk: bool = False
    trace: tuple[TraceStep, ...]
    engine_version: str
    input_hash: str
    action_hash: str
    mandate_id: str | None = None
    mandate_version: int | None = None
    registry_version: str | None = None
    registry_entry_id: str | None = None
