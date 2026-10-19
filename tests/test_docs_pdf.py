"""Tests for the submission PDF generators (make pdf).

The Chromium render step is environment-heavy, so these cover the deterministic parts: markdown -> styled HTML,
the cover page, the evidence assembly, and the committed PDFs themselves (valid header, reasonable size).
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("markdown", reason="pdf docs build needs `markdown` (make setup installs it)")

from scripts import md_to_pdf  # noqa: E402
from scripts.md_to_pdf import DOCS, ROOT  # noqa: E402


def test_builders_are_registered():
    assert set(DOCS) == {"technical", "security", "evidence"}


def test_all_committed_pdfs_are_valid():
    for name in ("technical_documentation", "security_self_assessment", "execution_evidence"):
        pdf = ROOT / "docs" / f"{name}.pdf"
        assert pdf.exists(), f"missing docs/{name}.pdf"
        assert pdf.stat().st_size > 20_000
        assert pdf.read_bytes()[:5] == b"%PDF-"


def test_security_pdf_html_has_cover_and_scope():
    md = (ROOT / "docs" / "security_self_assessment.md").read_text(encoding="utf-8")
    html = md_to_pdf._full_html(md_to_pdf._cover("b", "Security Self-Assessment", "s"), md_to_pdf._render(md), "t")
    assert 'class="cover"' in html and "SIMULATED — NO REAL MONEY MOVES" in html
    assert "Threat model" in html and "T0" in html  # the tiers table is present


def test_evidence_markdown_is_built_from_the_report_not_hand_typed():
    report = json.loads((ROOT / "eval" / "reports" / "latest.json").read_text(encoding="utf-8"))
    md = md_to_pdf._evidence_markdown()
    # the numbers must match the report JSON, not be typed in
    asr = report["attacks"]["systems"]["B2"]["asr"]
    assert f"{asr:.1%}" in md
    assert str(report["attacks"]["total"]) in md


def test_evidence_html_embeds_screenshots_when_present():
    html = md_to_pdf._screenshots_html()
    assert "<figure" in html and "<img" in html
    assert "live-03-allowed.png" in html or "pay.png" in html
