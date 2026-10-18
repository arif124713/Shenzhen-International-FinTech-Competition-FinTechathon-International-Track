"""Canonical JSON, hashing and the transaction-binding action_hash (implementation_plan §3.5)."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any


def _normalise(obj: Any) -> Any:
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, dict):
        return {unicodedata.normalize("NFC", str(k)): _normalise(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_normalise(v) for v in obj]
    if isinstance(obj, float):
        raise TypeError("floats are not allowed in canonical JSON (money is integer minor units)")
    return obj


def canonical_json(obj: Any) -> bytes:
    """Sorted keys, no whitespace, UTF-8, NFC strings. One helper for hashing and signing everywhere."""
    return json.dumps(_normalise(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj)).hexdigest()


def action_hash(proposal: Any) -> str:
    """Hash of every field that decides where money goes and how much leaves the account.

    Includes source_debit_minor (deviation from the first draft of the spec) so a changed fee/debit
    cannot ride on an earlier ALLOW or approval. Excludes proposal_id, urgency and created_by.
    """
    d = proposal.model_dump(mode="json")
    bound = {k: d[k] for k in (
        "action", "category", "payee_id", "payee_ref", "amount_minor", "currency",
        "source_account", "source_debit_minor", "rail_id",
    )}
    return sha256_hex(bound)
