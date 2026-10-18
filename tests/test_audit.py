"""U-AUDIT / U-AUDIT-02: chain verification, tamper detection and signed checkpoints."""
import copy
from datetime import datetime, timezone

from api.services.audit_log import AuditLog
from policy_engine import generate_keypair

T = datetime(2026, 10, 19, tzinfo=timezone.utc)


def log_with(n=5):
    a = AuditLog(lambda: T)
    for i in range(n):
        a.append("test", "EVENT", {"i": i})
    return a


def test_chain_verifies_and_detects_edit_at_exact_entry():
    a = log_with()
    assert a.verify() == (True, None)
    a.entries[2]["payload"]["i"] = 99
    assert a.verify() == (False, 2)


def test_full_rewrite_is_caught_only_by_an_external_signed_checkpoint():
    a = log_with(); priv, pub = generate_keypair()
    cp = a.checkpoint(priv, "audit_k1")
    assert AuditLog.verify_checkpoint_signature(cp, pub) and a.matches_checkpoint(cp)
    forged = AuditLog(lambda: T)  # attacker rewrites history and recomputes every hash
    for i in range(5):
        forged.append("test", "EVENT", {"i": i + 100})
    assert forged.verify() == (True, None)           # the chain alone cannot tell
    assert not forged.matches_checkpoint(cp)         # the exported checkpoint can
    cp2 = copy.deepcopy(cp); cp2["head_hash"] = "0" * 64
    assert not AuditLog.verify_checkpoint_signature(cp2, pub)
