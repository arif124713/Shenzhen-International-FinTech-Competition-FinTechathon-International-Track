"""Registry loading and verification for the API layer (implementation_plan §4.7).

The engine does its own signature/validity check; this service loads the signed registry file, exposes
validity helpers to the executor and reports provenance for the UI badge.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from policy_engine import KeyInfo, RegistryEntry, SignedRegistryEntry
from policy_engine.canonical import canonical_json
from policy_engine.signing import verify


@dataclass(frozen=True)
class RegistryView:
    version: str
    entries: tuple[SignedRegistryEntry, ...]
    keys: dict[str, str]  # key_id -> public b64


class Registry:
    def __init__(self, version: str, entries: tuple[SignedRegistryEntry, ...], keys: dict[str, str]):
        self.version = version
        self.entries = entries
        self.keys = keys  # key_id -> public b64 (used by entry_valid)

    @property
    def key_infos(self) -> dict[str, KeyInfo]:
        """KeyInfo mapping for the engine's `Context` (engine-facing view)."""
        return {k: KeyInfo(public_key_b64=v) for k, v in self.keys.items()}

    @classmethod
    def load(cls, path: Path) -> Registry:
        data = json.loads(path.read_text(encoding="utf-8"))
        version = data["registry_version"]
        keys = {k: v["public_key_b64"] for k, v in data.get("keys", {}).items()
                if v.get("status", "active") == "active"}
        entries = tuple(SignedRegistryEntry(body=e["body"], signature=e["signature"]) for e in data["entries"])
        return cls(version, entries, keys)

    def find(self, entity_id: str) -> SignedRegistryEntry | None:
        return next((e for e in self.entries if e.body.get("entity_id") == entity_id), None)

    def entry_valid(self, entity_id: str, version: str | None, now: datetime) -> bool:
        """Used by the executor to re-check the registry entry between ALLOW and execution."""
        signed = self.find(entity_id)
        if signed is None:
            return False
        try:
            entry = RegistryEntry.model_validate(signed.body)
        except Exception:  # noqa: BLE001
            return False
        pub = self.keys.get(entry.signer_key_id)
        if pub is None or not verify(pub, canonical_json(signed.body), signed.signature):
            return False
        if entry.revoked_at is not None and entry.revoked_at <= now:
            return False
        return entry.valid_from <= now <= entry.valid_to

    def provenance(self, entity_id: str) -> dict[str, str] | None:
        signed = self.find(entity_id)
        if signed is None:
            return None
        entry = RegistryEntry.model_validate(signed.body)
        return {"legal_name": entry.legal_name, "registry_version": entry.registry_version,
                **{f"provenance_{k}": v for k, v in entry.provenance.items()}}

    def list_entries(self) -> list[dict]:
        """Return every entry body (public fields) for a read-only UI view."""
        out = []
        for e in self.entries:
            entry = RegistryEntry.model_validate(e.body)
            out.append({**entry.model_dump(mode="json"), "signature_present": bool(e.signature)})
        return out


def sign_entry_body(entry_body: dict, keys: dict[str, dict[str, str]]) -> str:
    """Sign one registry entry body with the active registry key (demo key; never a real trust anchor)."""
    from policy_engine.signing import sign

    return sign(keys["registry"]["private_b64"], canonical_json(entry_body))


def add_entry(registry_path: Path, keys: dict[str, dict[str, str]], entry_body: dict) -> dict:
    """Add a new signed entry to the registry file and return the written entry.

    A signature proves the record was not altered; it does NOT prove the institution is genuine — the caller
    must supply provenance fields (method, source_url, retrieved_on).
    """
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    body = dict(entry_body)
    body.setdefault("registry_version", data.get("registry_version", "2026-10-18"))
    body.setdefault("signer_key_id", "demo_registry_k1")
    body.setdefault("revoked_at", None)
    RegistryEntry.model_validate(body)  # closed shape; rejects unknown/invalid fields
    if any(e["body"].get("entity_id") == body["entity_id"] for e in data["entries"]):
        raise ValueError("ENTITY_EXISTS")
    data["entries"].append({"body": body, "signature": sign_entry_body(body, keys)})
    registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return body


def revoke_entry(registry_path: Path, keys: dict[str, dict[str, str]], entity_id: str, now: datetime) -> dict:
    """Mark an entry revoked and re-sign it. Revocation is a new signed version (implementation_plan §4.7)."""
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    for e in data["entries"]:
        if e["body"].get("entity_id") == entity_id:
            e["body"]["revoked_at"] = now.isoformat()
            e["signature"] = sign_entry_body(e["body"], keys)
            registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return e["body"]
    raise KeyError(entity_id)
