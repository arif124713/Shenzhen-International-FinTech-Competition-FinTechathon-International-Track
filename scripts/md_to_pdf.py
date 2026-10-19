"""Generate well-formatted PDFs for the submission documents.

Pipeline: <source>.md -> styled HTML (python-markdown + Pygments) -> PDF via headless Chromium (the Playwright
Chromium already installed for the e2e suite). Produces the PDF next to its source.

Supported documents (see DOCS): the technical documentation, the security self-assessment, and a generated
execution-evidence report that gathers the real numbers, the evidence index and the screenshots.

Run:  python -m scripts.md_to_pdf              # build all
      python -m scripts.md_to_pdf technical    # build one by key
      python -m scripts.md_to_pdf --all
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

MONO = '"Cascadia Mono", "Cascadia Code", Consolas, "DejaVu Sans Mono", "Courier New", ui-monospace, monospace'

CSS = f"""
@page {{ size: A4; margin: 20mm 16mm 18mm 16mm; }}
* {{ box-sizing: border-box; }}
:root {{ --ink:#14212b; --muted:#4a5b68; --line:#c5cfd6; --seal:#0b6e6e; --code-bg:#f3f6f8; }}
html {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
body {{ font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  color: var(--ink); font-size: 10.5pt; line-height: 1.55; margin: 0; padding-bottom: 14mm; }}
h1, h2, h3 {{ line-height: 1.25; color: var(--ink); }}
h1 {{ font-size: 20pt; border-bottom: 2px solid var(--seal); padding-bottom: 6px; margin: 0 0 14px; }}
h2 {{ font-size: 14.5pt; margin: 22px 0 8px; padding-top: 6px; border-top: 1px solid var(--line); }}
h3 {{ font-size: 12pt; margin: 16px 0 6px; color: var(--seal); }}
p, li {{ orphans: 3; widows: 3; }}
a {{ color: var(--seal); text-decoration: none; }}
code {{ font-family: {MONO}; font-size: 9pt; background: var(--code-bg); padding: 1px 4px; border-radius: 3px; }}
pre {{ background: var(--code-bg); border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px;
  overflow: auto; break-inside: avoid; page-break-inside: avoid; }}
pre code {{ background: none; padding: 0; font-size: 8.6pt; line-height: 1.5; white-space: pre; font-family: {MONO}; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0 14px; font-size: 9.5pt; break-inside: avoid; }}
th, td {{ border: 1px solid var(--line); padding: 6px 8px; text-align: left; vertical-align: top; }}
th {{ background: var(--code-bg); font-weight: 600; }}
blockquote {{ margin: 10px 0; padding: 8px 12px; border-left: 3px solid var(--seal);
  background: #f7fafa; color: var(--muted); }}
hr {{ border: none; border-top: 1px solid var(--line); margin: 20px 0; }}
ul, ol {{ padding-left: 20px; }}
img {{ max-width: 100%; border: 1px solid var(--line); border-radius: 6px; margin: 6px 0; break-inside: avoid; }}
.shot {{ margin: 10px 0 16px; break-inside: avoid; }}
.shot figcaption {{ font-size: 8.5pt; color: var(--muted); margin-top: 3px; }}
.grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }}
.cover {{ min-height: 247mm; display: flex; flex-direction: column; justify-content: space-between;
  page-break-after: always; }}
.cover .brand {{ color: var(--seal); font-weight: 700; letter-spacing: 0.14em; font-size: 11pt;
  text-transform: uppercase; }}
.cover h1 {{ font-size: 32pt; border: none; margin: 10px 0; }}
.cover .sub {{ font-size: 13pt; color: var(--muted); }}
.cover .sim {{ display: inline-block; margin-top: 18px; padding: 6px 12px; border: 2px solid #b3261e;
  color: #b3261e; border-radius: 6px; font-weight: 700; letter-spacing: 0.05em; }}
.cover .meta {{ font-size: 10pt; color: var(--muted); line-height: 1.7; }}
.cover .meta strong {{ color: var(--ink); }}
footer.run {{ position: fixed; bottom: 6mm; left: 16mm; right: 16mm; font-size: 8pt; color: var(--muted);
  border-top: 1px solid var(--line); padding-top: 4px; display: flex; justify-content: space-between; }}
"""


def _footer(title: str) -> str:
    return (f'<footer class="run"><span>{title} · <b>SIMULATED</b> (no real money moves)</span>'
            '<span>Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></footer>')


def _cover(brand: str, title: str, sub: str, extra_meta: str = "") -> str:
    return f"""
    <section class="cover">
      <div>
        <div class="brand">{brand}</div>
        <h1>{title}</h1>
        <div class="sub">{sub}</div>
        <div class="sub" style="margin-top:6px">Submission · 2026 Shenzhen International FinTech Competition,
        International Track, Topic C</div>
        <div class="sim">SIMULATED — NO REAL MONEY MOVES</div>
      </div>
      <div class="meta">
        <div><strong>Team:</strong> Mandate — Arif Hussain (Team Leader), Ankon Sinha, Miftahul Alam Adib</div>
        <div><strong>Institution:</strong> Shahjalal University of Science and Technology (SUST), Bangladesh</div>
        <div><strong>Repository:</strong> github.com/arif124713/Shenzhen-International-FinTech-Competition-FinTechathon-International-Track</div>
        <div><strong>Live demo:</strong> mandate-nu-ten.vercel.app</div>
        <div><strong>Generated:</strong> {date.today().isoformat()}</div>
        {extra_meta}
      </div>
    </section>
    """


def _render(md_body: str) -> str:
    return markdown.markdown(
        md_body,
        extensions=["tables", "fenced_code", "codehilite", "toc", "sane_lists", "attr_list"],
        extension_configs={"codehilite": {"noclasses": True, "pygments_style": "default"}},
    )


def _strip_title(md_text: str) -> str:
    lines = md_text.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).lstrip("\n")


def _full_html(cover_html: str, body_html: str, footer_title: str) -> str:
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            f"<title>{footer_title}</title><style>{CSS}</style></head>"
            f"<body>{cover_html}{body_html}{_footer(footer_title)}</body></html>")


def _to_pdf(html: str, pdf_path: Path) -> None:
    html_path = pdf_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(html_path.as_uri(), wait_until="networkidle")
        page.pdf(path=str(pdf_path), format="A4", print_background=True, display_header_footer=False,
                 margin={"top": "20mm", "bottom": "18mm", "left": "16mm", "right": "16mm"})
        browser.close()
    print(f"wrote {pdf_path.relative_to(ROOT)} ({pdf_path.stat().st_size // 1024} KB)")


# --- document builders ------------------------------------------------------------------------------

def build_technical() -> None:
    md = (ROOT / "docs" / "technical_documentation.md").read_text(encoding="utf-8")
    cover = _cover("Mandate — Simulated Prototype", "Technical Documentation",
                   "A payment-intent firewall for student cross-border payments")
    _to_pdf(_full_html(cover, _render(_strip_title(md)), "Mandate — Technical Documentation"),
            ROOT / "docs" / "technical_documentation.pdf")


def build_security() -> None:
    md = (ROOT / "docs" / "security_self_assessment.md").read_text(encoding="utf-8")
    cover = _cover("Mandate — Simulated Prototype", "Security Self-Assessment",
                   "Threat model, safeguards, measured results, and known risks")
    _to_pdf(_full_html(cover, _render(_strip_title(md)), "Mandate — Security Self-Assessment"),
            ROOT / "docs" / "security_self_assessment.pdf")


def _evidence_markdown() -> str:
    """Assemble the execution-evidence report from the real committed artifacts (never hand-typed)."""
    import json

    parts = [
        "> Submission item 06. Assembled from the committed artifacts in `docs/execution_evidence/`,",
        "> `eval/reports/latest.json`, and a live end-to-end pass against the deployed link.",
        "> Nothing here is typed by hand.",
        "",
        "## 1. Evaluation report (from eval/reports/latest.json)",
        "",
    ]
    report_path = ROOT / "eval" / "reports" / "latest.json"
    if report_path.exists():
        r = json.loads(report_path.read_text(encoding="utf-8"))
        atk = r["attacks"]
        s = atk["systems"]
        fb = r["false_blocks"]
        sc = r.get("scenarios", {})
        rv = r.get("reader_eval", {})
        parts += [
            f"- Run id: `{r['run_id']}` · seed `{r['seed']}` · mode `{r['mode']}` · engine `{r['engine_version']}`",
            f"- Generated: {r['generated_at']}",
            f"- Held-out set SHA-256: `{r.get('heldout_sha256', '')}`",
            "",
            "### Red-team benchmark (engine-level, replay)",
            "",
            "| System | Attack success | Violations | 95% Wilson CI |",
            "|---|---|---|---|",
            f"| B0 no-policy baseline | {s['B0']['asr']:.1%} | {s['B0']['violations']}/{s['B0']['total']} | "
            f"[{s['B0']['ci95'][0]:.3f}, {s['B0']['ci95'][1]:.3f}] |",
            f"| B1 prompt-only baseline | {s['B1']['asr']:.1%} | {s['B1']['violations']}/{s['B1']['total']} | "
            f"[{s['B1']['ci95'][0]:.3f}, {s['B1']['ci95'][1]:.3f}] |",
            f"| B2 Mandate | {s['B2']['asr']:.1%} | {s['B2']['violations']}/{s['B2']['total']} | "
            f"[{s['B2']['ci95'][0]:.3f}, {s['B2']['ci95'][1]:.3f}] |",
            "",
            f"- Attack cases: **{atk['total']}** (24 families × 4). False blocks: **{fb['blocked']}/{fb['benign_total']}**.",
            f"- Task-completion scenarios: **{sc.get('passed', 0)}/{sc.get('ran', 0)} ran and passed** "
            f"({len(sc.get('skipped', []))} skipped of {sc.get('total', 0)}).",
        ]
        if rv:
            rec, fp = rv["detector_recall"], rv["detector_false_positives"]
            parts.append(f"- Reader/detector layer: anomalies caught **{rec['caught']}/{rec['total']}**, "
                         f"genuine documents clean **{fp['clean']}/{fp['total']}**.")
        parts += ["", "> Scope: engine-level, static, synthetic, replay mode. B0/B1 are structural baselines.",
                  "", "## 2. Task-completion scenarios", ""]
        parts += ["| ID | Scenario | Expected | Actual | Result |", "|---|---|---|---|---|"]
        for row in sc.get("results", []):
            verdict = "PASS" if row["passed"] else ("SKIP" if row["status"] == "skipped" else "FAIL")
            parts.append(f"| {row['id']} | {row['name']} | {row['expected']} | {row['actual']} | {verdict} |")
    parts += ["", "## 3. Live end-to-end verification (deployed link)", ""]
    live = ROOT / "docs" / "execution_evidence" / "live_verification.md"
    if live.exists():
        parts.append(_strip_title(live.read_text(encoding="utf-8")))
    return "\n".join(parts)


def _screenshots_html() -> str:
    shot_dir = ROOT / "docs" / "execution_evidence" / "screenshots"
    labels = {
        "dashboard.png": "Dashboard — active mandate, balances",
        "mandate.png": "Mandate editor — compiled rules, back-translation, test cases",
        "pay.png": "Pay — upload, extraction, untrusted-text block",
        "registry.png": "Registry — verified payees with the trust sentence",
        "guardian-360.png": "Guardian approval page at 360 px (mobile)",
        "activity.png": "Activity — hash-chained audit log, chain verification",
        "redteam.png": "Red-team report — live numbers from the report JSON",
        "live-03-allowed.png": "LIVE — genuine invoice: Allowed with Decision Trace",
        "live-04-blocked.png": "LIVE — substituted account: Blocked (registry mismatch)",
        "live-05-hidden-blocked.png": "LIVE — hidden-text invoice: Blocked (anomaly)",
        "live-06-needs-approval.png": "LIVE — large amount: Needs approval (guardian link)",
        "live-07-guardian-360.png": "LIVE — guardian page at 360 px",
        "live-09-activity.png": "LIVE — audit chain valid",
        "live-10-redteam.png": "LIVE — red-team report on the hosted link",
    }
    figs = []
    for name, label in labels.items():
        p = shot_dir / name
        if p.exists():
            figs.append(f'<figure class="shot"><img src="{p.as_uri()}">'
                        f'<figcaption>{label} — <code>{name}</code></figcaption></figure>')
    return "<h2>4. Screenshots (flagship screens and live run)</h2>" + "".join(figs)


def build_evidence() -> None:
    cover = _cover("Mandate — Simulated Prototype", "Execution Evidence",
                   "Screenshots, test results, evaluation report, and reproducible evidence")
    body = _render(_evidence_markdown()) + _screenshots_html()
    _to_pdf(_full_html(cover, body, "Mandate — Execution Evidence"),
            ROOT / "docs" / "execution_evidence.pdf")


DOCS = {"technical": build_technical, "security": build_security, "evidence": build_evidence}


def main(argv: list[str]) -> None:
    args = [a for a in argv[1:] if not a.startswith("-")]
    keys = [k for k in args if k in DOCS] or list(DOCS)
    for key in keys:
        DOCS[key]()


if __name__ == "__main__":
    main(sys.argv)
