"""Ed25519 helpers (the only crypto dependency allowed inside the engine package)."""
from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def generate_keypair() -> tuple[str, str]:
    """Returns (private_b64, public_b64) raw 32-byte keys. Demo keys only in the repo."""
    priv = Ed25519PrivateKey.generate()
    raw_priv = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    raw_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(raw_priv), _b64(raw_pub)


def sign(private_b64: str, data: bytes) -> str:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return _b64(key.sign(data))


def verify(public_b64: str, data: bytes, signature_b64: str) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64))
        key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
