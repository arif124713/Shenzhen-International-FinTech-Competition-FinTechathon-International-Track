"""Approvals: single-use, expiring, action-bound tokens stored hashed (CLAUDE.md §5, testing.md U-APPR).

An approval is an INPUT to the engine, never a bypass: after approval the engine is re-run and may issue
a fresh decision token. Never overrides a DENY.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta


def new_token() -> str:
    return secrets.token_urlsafe(32)  # ~256 bits


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class ApprovalToken:
    token: str
    token_hash: str
    expires_at: datetime
    action_hash: str
    approver_id: str


def create_approval(*, action_hash: str, approver_id: str, now: datetime, hours: int = 24) -> ApprovalToken:
    token = new_token()
    return ApprovalToken(token=token, token_hash=hash_token(token), expires_at=now + timedelta(hours=hours),
                         action_hash=action_hash, approver_id=approver_id)


def constant_time_match(stored_hash: str, presented_token: str) -> bool:
    return hmac.compare_digest(stored_hash, hash_token(presented_token))
