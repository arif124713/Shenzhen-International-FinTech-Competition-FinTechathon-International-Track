"""Wires a full simulated system for integration tests."""
from __future__ import annotations

import itertools
from datetime import timedelta

from api.services.audit_log import AuditLog
from api.services.executor import Executor
from policy_engine import decide, issue_decision_token
from policy_engine.tests.factories import NOW, context, make_env, mandate_body, sign_mandate
from rail_sim.ledger import SandboxLedger


class System:
    def __init__(self, rules=None, balances=None):
        self.env = make_env()
        self.now = NOW
        self.active_version = 1
        self.registry_ok = True
        self.ledger = SandboxLedger(balances or {"acc_rafi": 50_000_000})
        self.audit = AuditLog(lambda: self.now)
        self.signed = sign_mandate(self.env, mandate_body(rules))
        self._n = itertools.count(1)
        self.executor = Executor(
            engine_keys=self.env.engine_keys(), ledger=self.ledger, audit=self.audit, clock=lambda: self.now,
            active_mandate_version=lambda mid: self.active_version,
            registry_entry_valid=lambda eid, ver, now: self.registry_ok)

    def ctx(self, **over):
        return context(self.env, now=self.now, balances=self.ledger.balances(), **over)

    def authorize(self, proposal, **ctx_over):
        d = decide(self.signed, proposal, self.ctx(**ctx_over))
        tok = issue_decision_token(self.env.e_priv, "ek1", d, nonce=f"n{next(self._n)}", issued_at=self.now,
                                   expires_at=self.now + timedelta(minutes=10))
        return d, tok
