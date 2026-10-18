"""Deterministic anomaly detection over the document text layer (implementation_plan §3.1, testing.md U-DET).

These run in addition to the reader's own flags; the engine trusts the UNION of both (defense in depth).
Pure functions: text in, flags out. No LLM, no network.
"""
from __future__ import annotations

import re

# Instruction-like phrases (English + Bangla + transliterated "Banglish"). Kept deliberately broad.
_INSTRUCTION_PATTERNS = [
    r"ignore (all |any |the |your )?(previous|prior|above|earlier|system)?\s*(rules|instructions|prompts|policy)",
    r"disregard (the |your |all )?(rules|instructions|policy|mandate)",
    r"\bpay (the )?(new|updated|different) account\b",
    r"\buse (this|the following|the new) account\b",
    r"\bnew account\b",
    r"\bupdated account\b",
    r"(payment|bank|remittance) (details|instructions|information) (have been|were|are)? ?(updated|changed|revised)",
    r"override (the )?(cap|limit|rule|policy)",
    r"do not (tell|inform|notify) (the )?(user|guardian|owner)",
    r"without (asking|approval|confirmation)",
    r"urgent(ly)?[,:]? (pay|send|transfer)",
    # Bangla
    "নিয়ম উপেক্ষা",
    "নির্দেশ মানুন",
    "নতুন অ্যাকাউন্টে",
    "একাউন্ট পরিবর্তন",
    "লুকানো",
    "বেনামে",
    # transliterated Bangla
    r"\bniyom upekkha\b",
    r"\bnothun account\b",
]

_PAYEE_CHANGE_PATTERNS = [
    # BUG-005: cover passive and present tense ("was replaced", "is now X") and bare verbs, not just
    # "has been changed"; a hostile document redirecting payment commonly uses these phrasings.
    r"(beneficiary|payee|recipient|account holder)\b.{0,12}?"
    r"(has been|has|was|were|is|are|been|now)?\s?(changed|updated|replaced|different|amended|redirected)",
    r"(beneficiary|payee|recipient|account holder)\s+(is|are)\s+now\b",
    r"new beneficiary",
    r"নতুন প্রাপক",
]

_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.IGNORECASE)
_PAYEE_CHANGE_RE = re.compile("|".join(_PAYEE_CHANGE_PATTERNS), re.IGNORECASE)

# Hidden-text detection thresholds.
MIN_VISIBLE_FONT_SIZE = 4.0  # pt: text below this is effectively invisible and is treated as hidden
_SUSPICIOUS_METADATA_KEY_RE = re.compile(
    r"(instruction|ignore|pay|account|beneficiary|transfer|redirect)", re.IGNORECASE
)


def detect_text_flags(text: str) -> set[str]:
    """Flags derivable from the document's text layer alone."""
    flags: set[str] = set()
    if not text:
        return flags
    if _INSTRUCTION_RE.search(text):
        flags.add("INSTRUCTION_LIKE_TEXT")
    if _PAYEE_CHANGE_RE.search(text):
        flags.add("PAYEE_CHANGE_NOTICE")
    return flags


def detect_metadata_flags(metadata: dict[str, str] | None, filename: str | None = None) -> set[str]:
    """Payloads smuggled in PDF metadata or the filename (attack family A13)."""
    import re as _re

    flags: set[str] = set()
    blobs = list((metadata or {}).values())
    if filename:
        blobs.append(filename)
    for blob in blobs:
        if not isinstance(blob, str):
            continue
        # filenames use hyphens/underscores as separators; normalise so phrase regexes still match
        normalized = _re.sub(r"[-_.]+", " ", blob)
        if _INSTRUCTION_RE.search(normalized) or _PAYEE_CHANGE_RE.search(normalized):
            flags.add("INSTRUCTION_LIKE_TEXT")
        if _SUSPICIOUS_METADATA_KEY_RE.search(normalized) and _INSTRUCTION_RE.search(normalized):
            flags.add("HIDDEN_TEXT")
    return flags


def detect_spans(spans: list[dict[str, float]]) -> set[str]:
    """Flags from positioned text spans.

    Each span is {"size": pt, "x": .., "y": .., "page_w": .., "page_h": .., "color": 0xRRGGBB}. We flag
    white-on-white, tiny fonts and text placed outside the page box (attack families A01/A02).
    """
    flags: set[str] = set()
    for s in spans:
        size = s.get("size", 10.0)
        color = int(s.get("color", 0x000000))
        x, y = s.get("x", 0.0), s.get("y", 0.0)
        pw, ph = s.get("page_w", 0.0), s.get("page_h", 0.0)
        if size < MIN_VISIBLE_FONT_SIZE:
            flags.add("HIDDEN_TEXT")
        if color == 0xFFFFFF:  # white text (white-on-white)
            flags.add("HIDDEN_TEXT")
        if pw and ph and (x < 0 or y < 0 or x > pw or y > ph):
            flags.add("HIDDEN_TEXT")
    return flags
