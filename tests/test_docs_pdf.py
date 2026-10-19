"""Tests for the technical-documentation PDF generator (make pdf).

The Chromium render step is environment-heavy, so these tests cover the deterministic part: the markdown ->
styled HTML conversion, the cover page, and that the source/documentation contract holds (no stray H1, a
SIMULATED marker, the team and repo present). The committed PDF itself is checked for a valid header/size.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("markdown", reason="pdf docs build needs `markdown` (make setup installs it)")

from scripts.md_to_pdf import ROOT, build_html  # noqa: E402


def test_html_build_produces_a_cover_and_body():
    md = (ROOT / "docs" / "technical_documentation.md").read_text(encoding="utf-8")
    html = build_html(md)
    assert html.startswith("<!doctype html>")
    assert 'class="cover"' in html                       # a cover page is rendered
    assert "SIMULATED — NO REAL MONEY MOVES" in html
    assert "Arif Hussain" in html and "SUST" in html


def test_source_h1_is_not_repeated_after_the_cover():
    md = (ROOT / "docs" / "technical_documentation.md").read_text(encoding="utf-8")
    html = build_html(md)
    # the markdown's own leading "# technical_documentation.md ..." title must be stripped (the cover titles it)
    assert "technical_documentation.md — Mandate" not in html


def test_committed_pdf_is_a_valid_pdf():
    pdf = ROOT / "docs" / "technical_documentation.pdf"
    assert pdf.exists() and pdf.stat().st_size > 20_000
    assert pdf.read_bytes()[:5] == b"%PDF-"


def test_pdf_generator_importable_without_side_effects():
    # importing the module must not build anything or require a browser
    import importlib

    import scripts.md_to_pdf as mod

    importlib.reload(mod)
    assert Path(mod.__file__).name == "md_to_pdf.py"
