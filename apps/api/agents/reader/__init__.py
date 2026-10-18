"""Isolated reader (CLAUDE.md invariants 4, 5; testing.md U-EXEC-06).

`read_document(document, complete)` is a pure function of (document text, injected LLM callable). It has
NO tools: it must not import or receive db, ledger, registry-write, rail or executor handles. An AST test
enforces the import boundary; a runtime test enforces the two-argument signature.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from policy_engine import ReaderOutput

from .anomalies import detect_metadata_flags, detect_spans, detect_text_flags
from .prompt import PROMPT_VERSION, READER_SYSTEM, build_user_prompt
from .schema import SanitizeError, sanitize_reader_output

Complete = Callable[..., Any]  # complete(*, system, user, prompt_version, images=None) -> LLMResponse


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{") :]
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no JSON object in reader output")
    return json.loads(text[start : end + 1])


def read_document(
    document: dict[str, Any],
    complete: Complete,
    *,
    detector_spans: list[dict[str, float]] | None = None,
) -> tuple[ReaderOutput, tuple[str, ...]]:
    """Returns (validated ReaderOutput, union of deterministic detector flags).

    `document` is a plain dict: {text, doc_sha256, metadata?, filename?}. Raw text is only ever used to
    build the prompt and to run detectors; it is never returned to the planner/engine as instructions.
    """
    text = str(document.get("text", ""))
    doc_sha256 = str(document.get("doc_sha256", "0" * 64))

    flags: set[str] = set()
    flags |= detect_text_flags(text)
    flags |= detect_metadata_flags(document.get("metadata"), document.get("filename"))
    flags |= detect_spans(detector_spans or [])

    user = build_user_prompt(text)
    last_error: Exception | None = None
    for _ in range(2):  # retry once, then fail closed (CLAUDE.md §5)
        resp = complete(system=READER_SYSTEM, user=user, prompt_version=PROMPT_VERSION)
        try:
            raw = _parse_json(resp.text)
            reader = sanitize_reader_output(raw, doc_sha256=doc_sha256)
            merged = tuple(sorted(flags | set(reader.anomalies) - {"NONE"}))
            return reader, merged
        except (ValueError, SanitizeError, KeyError) as exc:
            last_error = exc
    raise SanitizeError(f"reader output invalid after retry: {last_error}")
