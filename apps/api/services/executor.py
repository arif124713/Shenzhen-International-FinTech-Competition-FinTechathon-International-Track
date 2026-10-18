"""The ONLY execution path to the sandbox rail (CLAUDE.md invariant 11).

execute(proposal, decision_token) refuses unless the engine's signed token is valid, ALLOW, unexpired, unused,
bound to the exact proposal being executed, and the mandate and registry entry it relied on are still valid.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime

from policy_engine import ActionProposal, DecisionToken, KeyInfo, action_hash, verify_decision_token

from .audit_log import AuditLog


class ExecRefused(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def make_ledger(balances: dict[str, int]):  # type: ignore[no-untyped-def]
    """Create the sandbox ledger. Kept here so this module remains the only rail_sim importer (invariant 11)."""
    from rail_sim.ledger import SandboxLedger

    return SandboxLedger(balances)


class Executor:
    def __init__(self, *, engine_keys: dict[str, KeyInfo], ledger, audit: AuditLog,  # type: ignore[no-untyped-def]
                 clock: Callable[[], datetime], active_mandate_version: Callable[[str], int],
                 registry_entry_valid: Callable[[str, str | None, datetime], bool]):
        self._keys = engine_keys
        self._ledger = ledger
        self._audit = audit
        self._clock = clock
        self._active_version = active_mandate_version
        self._registry_valid = registry_entry_valid
        self._used_nonces: set[str] = set()
        self._lock = threading.Lock()

    @property
    def ledger(self):  # type: ignore[no-untyped-def]
        return self._ledger

    def _refuse(self, code: str, proposal: ActionProposal | None) -> ExecRefused:
        self._audit.append("executor", "EXEC_REFUSED", {"code": code, "proposal_id": proposal.proposal_id if proposal else None})
        return ExecRefused(code)

    def execute(self, proposal: ActionProposal, token: DecisionToken | None):  # type: ignore[no-untyped-def]
        from rail_sim.ledger import InsufficientFunds

        if not isinstance(token, DecisionToken):
            raise self._refuse("NO_TOKEN", proposal)
        key = self._keys.get(token.key_id)
        if key is None or key.status != "active" or not verify_decision_token(token, key.public_key_b64):
            raise self._refuse("BAD_TOKEN_SIGNATURE", proposal)
        p = token.payload
        if p.get("decision") != "ALLOW":
            raise self._refuse("NOT_ALLOW", proposal)
        now = self._clock()
        if datetime.fromisoformat(p["expires_at"]) <= now:
            raise self._refuse("TOKEN_EXPIRED", proposal)
        if p["action_hash"] != action_hash(proposal):
            raise self._refuse("ACTION_MISMATCH", proposal)
        if self._active_version(p["mandate_id"]) != p["mandate_version"]:
            raise self._refuse("MANDATE_CHANGED", proposal)
        if p.get("registry_entry_id") is not None and not self._registry_valid(
                p["registry_entry_id"], p.get("registry_version"), now):
            raise self._refuse("REGISTRY_CHANGED", proposal)
        with self._lock:  # nonce check, ledger write and nonce burn are one critical section
            if p["nonce"] in self._used_nonces:
                raise self._refuse("TOKEN_REPLAY", proposal)
            try:
                receipt = self._ledger.transfer(
                    idempotency_key=f"{p['action_hash']}:{p['nonce']}", proposal_id=proposal.proposal_id,
                    payee_id=proposal.payee_id, amount_minor=proposal.amount_minor, currency=proposal.currency,
                    category=proposal.category, source_account=proposal.source_account,
                    debit_minor=proposal.source_debit_minor, rail_id=proposal.rail_id, executed_at=now)
            except InsufficientFunds:
                raise self._refuse("INSUFFICIENT_FUNDS", proposal) from None
            self._used_nonces.add(p["nonce"])
        self._audit.append("executor", "EXEC_OK", {
            "proposal_id": proposal.proposal_id, "action_hash": p["action_hash"], "nonce": p["nonce"],
            "receipt_id": receipt.receipt_id, "simulated": True})
        return receipt
