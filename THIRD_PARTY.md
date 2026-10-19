# THIRD_PARTY.md — third-party components and licences

> Permissive licences only (MIT, BSD, Apache-2.0, ISC, PSF, MPL-2.0, CC-BY-4.0). No AGPL/GPL component is
> used. This file records the result of an actual licence scan; the scan commands are in §4.

## 1. Python (backend) — `pip-licenses`, 2026-10-19

Direct dependencies (all permissive):

| Package | Purpose | Licence |
|---|---|---|
| pydantic / pydantic_core | contracts / validation | MIT |
| cryptography | Ed25519 sign/verify | Apache-2.0 OR BSD-3-Clause |
| fastapi | HTTP API | MIT |
| starlette | ASGI framework | BSD-3-Clause |
| uvicorn | ASGI server | BSD-3-Clause |
| sqlalchemy | ORM (SQLite default) | MIT |
| httpx / httpcore | test client / smoke | BSD-3-Clause |
| anyio, sniffio, h11, idna, certifi | transitive (HTTP/SSL) | MIT / BSD-3-Clause / MPL-2.0 |
| pypdf | PDF text-layer extraction | BSD-3-Clause |
| python-multipart | multipart uploads | Apache-2.0 |
| typing_extensions | typing backports | PSF-2.0 |
| pytest / pluggy / iniconfig / packaging | tests | MIT / Apache-2.0 |
| hypothesis / sortedcontainers | property tests | MPL-2.0 / Apache-2.0 |
| ruff | linter | MIT |
| mypy / mypy_extensions / pathspec / typing-inspection | type checker | MIT / MPL-2.0 |
| Pygments, colorama, click | CLI transitive | BSD-2-Clause / BSD / BSD-3-Clause |

**No GPL/AGPL.** `PyMuPDF`/`fitz` (AGPL) is deliberately **not** used; `pypdf` (BSD) does text extraction.

## 2. JavaScript (frontend) — `npx license-checker`, 2026-10-19

Summary of the install tree: **MIT 126 · ISC 9 · Apache-2.0 7 · BSD-3-Clause 1 · CC-BY-4.0 1 · UNLICENSED 1**.

| Group | Licence |
|---|---|
| react, react-dom, react-router-dom | MIT |
| react-i18next, i18next | MIT |
| vite, @vitejs/plugin-react, rollup, esbuild, postcss, autoprefixer, tailwindcss | MIT |
| typescript | Apache-2.0 |
| @playwright/test | Apache-2.0 |
| caniuse-lite (browser data) | CC-BY-4.0 (attribution-only data) |
| `mandate-web` (this project) | UNLICENSED — the local package itself; covered by the repository `LICENSE` |

No copyleft (GPL/AGPL) package is present.

## 3. Fonts, data and assets

- **Fonts** are referenced by name only (`"Schibsted Grotesk"`, `"Hind Siliguri"`, `"IBM Plex Mono"`) with a
  `system-ui, sans-serif` fallback. **No font file is bundled or fetched at runtime** (no Google Fonts/CDN
  link), so no font licence file is redistributed. To self-host later, add the font's OFL file and record it
  here.
- `data/ratecards/ratecards.json`, `data/registry/*`, `data/fixtures/**`, `data/rulepacks/bd.json` — **SIMULATED**
  content authored for this prototype; no third-party data. `bd.json` is an unverified placeholder, not legal
  advice.
- Invoices under `data/fixtures/invoices/` are synthetic documents generated for this project.

## 4. How to reproduce the scan

```
python -m pip install pip-licenses
pip-licenses --format=csv --with-urls          # backend
cd apps/web && npx license-checker              # frontend
```

## 5. Licence statement (verified)

The Mandate source is released under the **MIT** licence (see `LICENSE`). The dependency scan above found
**only permissive licences** (plus CC-BY-4.0 attribution-only data and this project's own package), so the
MIT statement is supported by the scan.
