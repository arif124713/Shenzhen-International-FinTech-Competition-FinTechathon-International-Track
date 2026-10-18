"""Reader output sanitizer: turns raw model JSON into a validated `ReaderOutput`, rejecting anything unsafe
(implementation_plan §3.1, testing.md U-SANIT). Closed schema, character allow-lists, length caps, NFKC.
"""
from __future__ import annotations

import unicodedata
from typing import Any

from policy_engine import ReaderOutput

ALLOWED_CURRENCIES = {"USD", "BDT", "GBP", "EUR", "SGD"}
_ACCOUNT_RE = None  # compiled lazily to keep import cheap


def _account_ok(value: str) -> bool:
    import re

    return re.fullmatch(r"[A-Za-z0-9 \-]{1,64}", value) is not None


def _bank_ok(value: str) -> bool:
    import re

    return re.fullmatch(r"[A-Za-z0-9]{1,34}", value) is not None


class SanitizeError(ValueError):
    pass


def sanitize_reader_output(raw: dict[str, Any], *, doc_sha256: str) -> ReaderOutput:
    """Validate and normalise a raw reader payload. Extra keys, bad enums and bad chars are rejected."""
    allowed = {"doc_type", "payee_name", "account_identifier", "bank_identifier", "amount_minor", "currency",
               "due_date", "reference", "category_guess", "extraction_confidence", "extraction_confidence_bp",
               "anomalies"}
    unknown = set(raw) - allowed
    if unknown:
        raise SanitizeError(f"unknown keys rejected: {sorted(unknown)}")
    data = dict(raw)

    # confidence: accept either 0..1 float or integer basis points 0..10000 and normalise to basis points.
    conf_raw = data.pop("extraction_confidence", data.pop("extraction_confidence_bp", None))
    if conf_raw is None:
        raise SanitizeError("missing confidence")
    conf = float(conf_raw)
    if 1.0 < conf < 100:
        raise SanitizeError("ambiguous confidence scale (expected a 0..1 fraction or 0..10000 basis points)")
    conf_bp = round(conf * 10000) if conf <= 1.0 else round(conf)
    if not 0 <= conf_bp <= 10000:
        raise SanitizeError("confidence out of range")

    anomalies = data.pop("anomalies", ()) or ()
    if isinstance(anomalies, str):
        anomalies = (anomalies,)

    normalized_payee = _nfkc(data.get("payee_name", ""))
    normalized_account = _nfkc(data.get("account_identifier", ""))
    normalized_bank = _nfkc(data.get("bank_identifier", ""))

    if not _account_ok(normalized_account):
        raise SanitizeError("account_identifier has disallowed characters")
    if not _bank_ok(normalized_bank):
        raise SanitizeError("bank_identifier has disallowed characters")

    currency = str(data.get("currency", "")).upper()
    if currency not in ALLOWED_CURRENCIES:
        raise SanitizeError(f"currency {currency!r} not in allowed set")

    payload = {
        "doc_type": data.get("doc_type", "unknown"),
        "payee_name": normalized_payee,
        "account_identifier": normalized_account,
        "bank_identifier": normalized_bank,
        "amount_minor": int(data.get("amount_minor", 0)),
        "currency": currency,
        "due_date": data.get("due_date"),
        "reference": _nfkc(str(data.get("reference", "")))[:64],
        "category_guess": data.get("category_guess", "other"),
        "extraction_confidence_bp": conf_bp,
        "anomalies": tuple(dict.fromkeys(anomalies)),  # de-dup, keep order
        "doc_sha256": doc_sha256,
    }
    try:
        return ReaderOutput.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - convert any pydantic failure into one typed error
        raise SanitizeError(str(exc)) from exc


def _nfkc(s: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(s)).split())
