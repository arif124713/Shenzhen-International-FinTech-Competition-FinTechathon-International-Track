"""Hash-chained audit log with signed checkpoints (implementation_plan §4.8).

The chain detects edits to individual entries. It cannot, by itself, detect a full rewrite by someone who
can recompute every hash; a checkpoint signed with a separate key and stored elsewhere closes that gap.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Any

from policy_engine.canonical import canonical_json
from policy_engine.signing import sign, verify

GENESIS = "0" * 64


def _hash(prev: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode() + canonical_json(entry)).hexdigest()


class AuditLog:
    def __init__(self, clock: Callable[[], datetime]):
        self._clock = clock
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, actor: str, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            body = {"seq": len(self.entries), "ts": self._clock().isoformat(), "actor": actor,
                    "event_type": event_type, "payload": payload, "prev_hash": prev}
            entry = {**body, "hash": _hash(prev, body)}
            self.entries.append(entry)
            return entry

    def verify(self) -> tuple[bool, int | None]:
        """(valid, first_bad_seq)."""
        prev = GENESIS
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev_hash"] != prev or _hash(prev, body) != e["hash"]:
                return False, e["seq"]
            prev = e["hash"]
        return True, None

    def checkpoint(self, private_b64: str, key_id: str) -> dict[str, Any]:
        head = self.entries[-1] if self.entries else None
        cp = {"seq": head["seq"] if head else -1, "head_hash": head["hash"] if head else GENESIS,
              "ts": self._clock().isoformat(), "key_id": key_id}
        return {**cp, "signature": sign(private_b64, canonical_json(cp))}

    @staticmethod
    def verify_checkpoint_signature(cp: dict[str, Any], public_b64: str) -> bool:
        body = {k: v for k, v in cp.items() if k != "signature"}
        return verify(public_b64, canonical_json(body), cp["signature"])

    def matches_checkpoint(self, cp: dict[str, Any]) -> bool:
        """True if this log still contains the entry the (externally stored) checkpoint committed to."""
        if cp["seq"] == -1:
            return True
        return cp["seq"] < len(self.entries) and self.entries[cp["seq"]]["hash"] == cp["head_hash"]
