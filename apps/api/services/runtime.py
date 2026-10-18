"""Per-process runtime wiring: DB, sandbox ledger, audit log, registry, executor (composition root).

Kept out of route modules so routes stay thin and every security-relevant object is created once.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from policy_engine import KeyInfo

from ..agents.llm import build_client
from ..settings import settings
from .audit_log import AuditLog
from .executor import Executor, make_ledger
from .registry import Registry
from .router import load_ratecards


class SimClock:
    """Simulated clock: demo holds and settlement delays advance without waiting on real time."""

    def __init__(self, start: datetime | None = None):
        self._now = start or datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, hours: float) -> datetime:
        from datetime import timedelta

        self._now = self._now + timedelta(hours=hours)
        return self._now


class Runtime:
    def __init__(self) -> None:
        self.clock = SimClock()
        keys_path = settings.registry_dir / "keys.json"
        if not keys_path.exists():
            from ..db.keys import ensure_keys, sign_registry

            keys = ensure_keys()
            sign_registry(keys)
        self.keys = json.loads(keys_path.read_text(encoding="utf-8"))

        self.registry = Registry.load(settings.registry_dir / "registry.json")
        self.ratecards, self.default_rail_id = load_ratecards(settings.ratecards_path)

        self.balances = {"acc_rafi_bdt": 50_000_000, "acc_rafi_usd": 300_000, "acc_rafi_gbp": 64_000,
                         "acc_rafi_eur": 70_000}
        self.ledger = make_ledger(self.balances)
        self.audit = AuditLog(self.clock)

        self.engine_keys = {"demo_engine_k1": KeyInfo(public_key_b64=self.keys["engine"]["public_b64"])}
        self.mandate_keys = {"demo_mandate_k1": KeyInfo(public_key_b64=self.keys["mandate"]["public_b64"])}

        self.executor = Executor(
            engine_keys=self.engine_keys, ledger=self.ledger, audit=self.audit, clock=self.clock,
            active_mandate_version=lambda mid: self._active_version(mid),
            registry_entry_valid=lambda eid, ver, now: self.registry.entry_valid(eid, ver, now),
        )
        self._active_versions: dict[str, int] = {}
        self._mandates: dict[str, dict] = {}
        self._hold_started: dict[str, datetime] = {}
        self._approvals: dict[str, dict] = {}

        self.compiler_client = build_client(role="compiler")
        self.reader_client = build_client(role="reader")
        self.planner_client = build_client(role="planner")

    def set_clients(self, *, reader=None, planner=None, compiler=None) -> None:  # type: ignore[no-untyped-def]
        """Override the LLM clients (used by tests and the eval harness to inject deterministic doubles)."""
        if reader is not None:
            self.reader_client = reader
        if planner is not None:
            self.planner_client = planner
        if compiler is not None:
            self.compiler_client = compiler

    # -- tiny in-memory mandate store (SQLite rows are authoritative for persisted state) --
    def set_active_mandate(self, mandate_id: str, version: int, signed_body: dict, signature: str,
                           back_translation: str = "") -> None:
        self._mandates[mandate_id] = {"body": signed_body, "signature": signature, "version": version,
                                      "back_translation": back_translation}
        self._active_versions[mandate_id] = version

    def active_mandate(self, mandate_id: str = "m_rafi") -> dict | None:
        if mandate_id in self._mandates:
            return self._mandates[mandate_id]
        # fall back to the most recently activated mandate (the compiler may pick its own id)
        if not self._mandates:
            return None
        last_id = max(self._mandates, key=lambda k: self._mandates[k]["version"])
        return self._mandates[last_id]

    def clear_active_mandate(self) -> None:
        """Drop all stored mandates so no mandate is active. Superseded versions are never valid for new
        decisions; with none active the engine defaults to DENY (default-deny, CLAUDE.md invariant 3)."""
        self._mandates.clear()
        self._active_versions.clear()

    # -- issued approval summaries, keyed by token HASH (only a hash is stored; the raw token is never kept) --
    def store_approval(self, token: str, summary: dict, proposal: dict) -> None:
        from .approvals import hash_token

        self._approvals[hash_token(token)] = {"summary": summary, "proposal": proposal}

    def get_approval(self, token: str) -> dict | None:
        from .approvals import hash_token

        return self._approvals.get(hash_token(token))

    # -- cooling-off hold bookkeeping: a hold's start time must survive clock advances --
    def mark_hold(self, proposal_id: str) -> None:
        self._hold_started.setdefault(proposal_id, self.clock())

    def hold_started_at(self, proposal_id: str | None):  # type: ignore[no-untyped-def]
        if proposal_id is None:
            return None
        return self._hold_started.get(proposal_id)

    def _active_version(self, mandate_id: str | None) -> int:
        if mandate_id is None:
            return 1
        return self._active_versions.get(mandate_id, 1)


_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    global _runtime
    if _runtime is None:
        _runtime = Runtime()
    return _runtime


def reset_runtime() -> Runtime:
    global _runtime
    _runtime = Runtime()
    _runtime.balances = {"acc_rafi_bdt": 50_000_000, "acc_rafi_usd": 300_000, "acc_rafi_gbp": 64_000,
                         "acc_rafi_eur": 70_000}
    _runtime.ledger = make_ledger(_runtime.balances)
    _runtime.audit = AuditLog(_runtime.clock)
    _runtime.executor = Executor(
        engine_keys=_runtime.engine_keys, ledger=_runtime.ledger, audit=_runtime.audit, clock=_runtime.clock,
        active_mandate_version=lambda mid: _runtime._active_version(mid),
        registry_entry_valid=lambda eid, ver, now: _runtime.registry.entry_valid(eid, ver, now),
    )
    return _runtime
