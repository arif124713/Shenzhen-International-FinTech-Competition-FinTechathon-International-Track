"""Generate a well-formatted PDF of the technical documentation.

Pipeline: docs/technical_documentation.md -> styled HTML (python-markdown + Pygments for code) -> PDF via
headless Chromium (the Playwright Chromium already installed for the e2e suite). Produces:
  docs/technical_documentation.pdf

The output uses real fonts, a cover page, page numbers, and a footer marking the document SIMULATED.

Run: python -m scripts.md_to_pdf            (or: python scripts/md_to_pdf.py)
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

try:
    import markdown
except ImportError:  # pragma: no cover
    raise SystemExit("Missing dependency: run `pip install markdown pygments` first.") from None


CSS = """
@page { size: A4; margin: 20mm 16mm 18mm 16mm; }
* { box-sizing: border-box; }
:root { --ink:#14212b; --muted:#4a5b68; --line:#c5cfd6; --seal:#0b6e6e; --code-bg:#f3f6f8; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  color: var(--ink); font-size: 10.5pt; line-height: 1.55; margin: 0; padding-bottom: 14mm; }
h1, h2, h3 { line-height: 1.25; color: var(--ink); }
h1 { font-size: 20pt; border-bottom: 2px solid var(--seal); padding-bottom: 6px; margin: 0 0 14px; }
h2 { font-size: 14.5pt; margin: 22px 0 8px; padding-top: 6px; border-top: 1px solid var(--line); }
h3 { font-size: 12pt; margin: 16px 0 6px; color: var(--seal); }
p, li { orphans: 3; widows: 3; }
a { color: var(--seal); text-decoration: none; }
code { font-family: "Cascadia Mono", "Cascadia Code", Consolas, "DejaVu Sans Mono", "Courier New", ui-monospace, monospace; font-size: 9pt;
  background: var(--code-bg); padding: 1px 4px; border-radius: 3px; }
pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px;
  overflow: auto; break-inside: avoid; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8.6pt; line-height: 1.5; white-space: pre;
  font-family: "Cascadia Mono", "Cascadia Code", Consolas, "DejaVu Sans Mono", "Courier New", ui-monospace, monospace; }
table { border-collapse: collapse; width: 100%; margin: 10px 0 14px; font-size: 9.5pt; break-inside: avoid; }
th, td { border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: var(--code-bg); font-weight: 600; }
blockquote { margin: 10px 0; padding: 8px 12px; border-left: 3px solid var(--seal);
  background: #f7fafa; color: var(--muted); }
hr { border: none; border-top: 1px solid var(--line); margin: 20px 0; }
ul, ol { padding-left: 20px; }
.cover { height: 247mm; display: flex; flex-direction: column; justify-content: space-between;
  page-break-after: always; }
.cover .brand { color: var(--seal); font-weight: 700; letter-spacing: 0.14em; font-size: 11pt;
  text-transform: uppercase; }
.cover h1 { font-size: 34pt; border: none; margin: 10px 0; }
.cover .sub { font-size: 13pt; color: var(--muted); }
.cover .sim { display: inline-block; margin-top: 18px; padding: 6px 12px; border: 2px solid #b3261e;
  color: #b3261e; border-radius: 6px; font-weight: 700; letter-spacing: 0.05em; }
.cover .meta { font-size: 10pt; color: var(--muted); line-height: 1.7; }
.cover .meta strong { color: var(--ink); }
footer.run { position: fixed; bottom: 6mm; left: 16mm; right: 16mm; font-size: 8pt; color: var(--muted);
  border-top: 1px solid var(--line); padding-top: 4px; display: flex; justify-content: space-between; }
"""

FOOTER_HTML = (
    '<footer class="run"><span>Mandate — Technical Documentation · <b>SIMULATED</b> '
    '(no real money moves)</span><span>Page <span class="pageNumber"></span> of '
    '<span class="totalPages"></span></span></footer>'
)


def build_html(md_text: str) -> str:
    # Drop the leading markdown H1 ("# technical_documentation.md — Mandate ..."): the cover already titles
    # the document, so repeating it after the cover looks like a stray heading.
    lines = md_text.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    md_body = "\n".join(lines).lstrip("\n")

    body = markdown.markdown(
        md_body,
        extensions=["tables", "fenced_code", "codehilite", "toc", "sane_lists", "attr_list"],
        extension_configs={"codehilite": {"noclasses": True, "pygments_style": "default"}},
    )
    cover = f"""
    <section class="cover">
      <div>
        <div class="brand">Mandate — Simulated Prototype</div>
        <h1>Technical Documentation</h1>
        <div class="sub">A payment-intent firewall for student cross-border payments</div>
        <div class="sub" style="margin-top:6px">Submission item 01 · 2026 Shenzhen International FinTech
        Competition, International Track, Topic C</div>
        <div class="sim">SIMULATED — NO REAL MONEY MOVES</div>
      </div>
      <div class="meta">
        <div><strong>Team:</strong> Mandate — Arif Hussain (Team Leader), Ankon Sinha, Miftahul Alam Adib</div>
        <div><strong>Institution:</strong> Shahjalal University of Science and Technology (SUST), Bangladesh</div>
        <div><strong>Repository:</strong> github.com/arif124713/Shenzhen-International-FinTech-Competition-FinTechathon-International-Track</div>
        <div><strong>Live demo:</strong> mandate-nu-ten.vercel.app</div>
        <div><strong>Generated:</strong> {date.today().isoformat()}</div>
        <div style="margin-top:10px;color:#4a5b68">Every control named here is a real <code>file:function</code>
        in the repository. Benchmark numbers come from <code>eval/reports/latest.json</code> (replay mode).</div>
      </div>
    </section>
    """
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Mandate — Technical Documentation</title><style>{CSS}</style></head>
<body>{cover}{body}{FOOTER_HTML}</body></html>"""


def main() -> None:
    src = ROOT / "docs" / "technical_documentation.md"
    html_path = ROOT / "docs" / "technical_documentation.html"
    pdf_path = ROOT / "docs" / "technical_documentation.pdf"
    html = build_html(src.read_text(encoding="utf-8"))
    html_path.write_text(html, encoding="utf-8")

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.as_uri(), wait_until="networkidle")
        page.pdf(path=str(pdf_path), format="A4", print_background=True,
                 display_header_footer=False, margin={"top": "20mm", "bottom": "18mm",
                                                      "left": "16mm", "right": "16mm"})
        browser.close()
    size_kb = pdf_path.stat().st_size // 1024
    print(f"wrote {pdf_path.relative_to(ROOT)} ({size_kb} KB)")


if __name__ == "__main__":
    sys.exit(main())
