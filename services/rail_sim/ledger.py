"""SIMULATED sandbox ledger. No real money, banks or identity checks. (PRD §4.3)

Only apps/api/services/executor.py may import this package (CLAUDE.md invariant 11; enforced by a CI test).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime


class InsufficientFunds(Exception):
    pass


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    idempotency_key: str
    proposal_id: str
    payee_id: str | None
    amount_minor: int
    currency: str
    source_account: str
    debit_minor: int
    rail_id: str
    executed_at: str
    action_hash: str = ""
    simulated: bool = True


class SandboxLedger:
    def __init__(self, balances: dict[str, int]):
        self._balances = dict(balances)
        self._receipts: dict[str, Receipt] = {}
        self.rows: list[dict] = []
        self._lock = threading.Lock()

    def balance(self, account: str) -> int:
        return self._balances[account]

    def balances(self) -> dict[str, int]:
        with self._lock:
            return dict(self._balances)

    def executed_action_hashes(self) -> tuple[str, ...]:
        """Every action_hash that has already executed. Used by the ContextBuilder so the engine can deny a
        duplicate (a re-submitted invoice) at the decision layer — distinct from the executor's token-replay
        guard, which only stops the *same token* being reused."""
        with self._lock:
            return tuple(r.action_hash for r in self._receipts.values() if r.action_hash)

    def transfer(self, *, idempotency_key: str, proposal_id: str, payee_id: str | None, amount_minor: int,
                 currency: str, category: str, source_account: str, debit_minor: int, rail_id: str,
                 executed_at: datetime, action_hash: str = "") -> Receipt:
        """Atomic and idempotent: the same key never debits twice."""
        with self._lock:
            if idempotency_key in self._receipts:
                return self._receipts[idempotency_key]
            bal = self._balances.get(source_account)
            if bal is None or bal < debit_minor:
                raise InsufficientFunds(source_account)
            receipt = Receipt(
                receipt_id=f"rcpt_{len(self._receipts) + 1:06d}", idempotency_key=idempotency_key,
                proposal_id=proposal_id, payee_id=payee_id, amount_minor=amount_minor, currency=currency,
                source_account=source_account, debit_minor=debit_minor, rail_id=rail_id, action_hash=action_hash,
                executed_at=executed_at.isoformat(),
            )
            self._balances[source_account] = bal - debit_minor
            self._receipts[idempotency_key] = receipt
            self.rows.append({"ts": executed_at.isoformat(), "amount_minor": amount_minor, "currency": currency,
                              "category": category, "payee_id": payee_id, "receipt_id": receipt.receipt_id})
            return receipt
