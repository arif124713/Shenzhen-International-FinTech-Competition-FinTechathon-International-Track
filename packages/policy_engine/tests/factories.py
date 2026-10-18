"""Shared test builders (demo keys only; every value is synthetic)."""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from policy_engine import (
    ActionProposal,
    Context,
    KeyInfo,
    ReaderOutput,
    SignedMandate,
    SignedRegistryEntry,
    canonical_json,
    generate_keypair,
    sign,
)

NOW = datetime(2026, 10, 19, 9, 0, tzinfo=timezone.utc)
UNI_NAME, UNI_ACCT, UNI_BANK = "Northfield University", "NF0012345678", "NFLDGB2L"


@dataclass
class Env:
    m_priv: str; m_pub: str
    r_priv: str; r_pub: str
    e_priv: str; e_pub: str

    def mandate_keys(self): return {"mk1": KeyInfo(public_key_b64=self.m_pub)}
    def registry_keys(self): return {"rk1": KeyInfo(public_key_b64=self.r_pub)}
    def engine_keys(self): return {"ek1": KeyInfo(public_key_b64=self.e_pub)}


def make_env() -> Env:
    (a, b), (c, d), (e, f) = generate_keypair(), generate_keypair(), generate_keypair()
    return Env(a, b, c, d, e, f)


def default_rules() -> list[dict[str, Any]]:
    return [
        {"id": "R01", "type": "category_allow", "categories": ["tuition", "rent", "family_support"]},
        {"id": "R02", "type": "payee_allowlist", "payee_ids": ["reg_northfield_univ", "usr_ammu"]},
        {"id": "R03", "type": "cap", "scope": "per_tx", "amount_minor": 200000, "currency": "USD", "categories": ["*"]},
        {"id": "R04", "type": "cap", "scope": "rolling_30d", "amount_minor": 500000, "currency": "USD", "categories": ["*"]},
        {"id": "R05", "type": "require_registry_match", "categories": ["tuition"]},
        {"id": "R06", "type": "new_payee", "action": "ESCALATE", "approvers": ["u_ammu"]},
        {"id": "R07", "type": "cooling_off", "applies_to": "new_payee", "hours": 24},
        {"id": "R08", "type": "escalate_above", "amount_minor": 120000, "currency": "USD", "approvers": ["u_ammu"]},
        {"id": "R09", "type": "min_confidence", "value_bp": 9000},
        {"id": "R10", "type": "block_anomalies", "anomalies": ["HIDDEN_TEXT", "INSTRUCTION_LIKE_TEXT", "PAYEE_CHANGE_NOTICE"]},
        {"id": "R11", "type": "rail_allow", "rail_ids": ["rail_a_bank", "rail_b_wallet"]},
    ]


def mandate_body(rules=None, version=1) -> dict[str, Any]:
    return {"mandate_id": "m_rafi", "version": version, "owner_id": "u_rafi", "base_currency": "BDT",
            "co_signers": [{"id": "u_ammu", "name": "Ammu", "lang": "bn"}],
            "rules": default_rules() if rules is None else rules, "created_at": NOW.isoformat()}


def sign_mandate(env: Env, body: dict[str, Any], key_id="mk1") -> SignedMandate:
    return SignedMandate(body=body, signature=sign(env.m_priv, canonical_json(body)), signer_key_id=key_id)


def registry_entry(env: Env, **over) -> SignedRegistryEntry:
    body = {"entity_id": "reg_northfield_univ", "legal_name": UNI_NAME, "account_identifier": UNI_ACCT,
            "bank_identifier": UNI_BANK,
            "provenance": {"method": "demo: team-enrolled from a fictional public page", "retrieved_on": "2026-10-18"},
            "enrolled_by": "team", "valid_from": (NOW - timedelta(days=30)).isoformat(),
            "valid_to": (NOW + timedelta(days=300)).isoformat(), "revoked_at": None,
            "registry_version": "2026-10-18", "signer_key_id": "rk1"}
    body.update(over)
    return SignedRegistryEntry(body=body, signature=sign(env.r_priv, canonical_json(body)))


def reader(**over) -> ReaderOutput:
    d = dict(doc_type="invoice", payee_name=UNI_NAME, account_identifier=UNI_ACCT, bank_identifier=UNI_BANK,
             amount_minor=90000, currency="USD", due_date="2026-11-05", reference="INV-1", category_guess="tuition",
             extraction_confidence_bp=9600, anomalies=(), doc_sha256="a" * 64)
    d.update(over)
    return ReaderOutput(**d)


def proposal(**over) -> ActionProposal:
    d = dict(proposal_id="p1", action="pay", category="tuition", payee_id="reg_northfield_univ",
             payee_ref={"name": UNI_NAME, "account_identifier": UNI_ACCT, "bank_identifier": UNI_BANK},
             amount_minor=90000, currency="USD", source_account="acc_rafi", source_debit_minor=11_000_000,
             rail_id="rail_a_bank", doc_ref="doc1")
    d.update(over)
    return ActionProposal(**d)


def context(env: Env, **over) -> Context:
    d = dict(now=NOW, mandate_keys=env.mandate_keys(), registry_keys=env.registry_keys(), active_mandate_version=1,
             balances={"acc_rafi": 50_000_000}, registry=(registry_entry(env),), reader=reader())
    d.update(over)
    return Context(**d)


def tamper(body: dict[str, Any], **over) -> dict[str, Any]:
    b = copy.deepcopy(body); b.update(over); return b
