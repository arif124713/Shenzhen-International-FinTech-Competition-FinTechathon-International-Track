# THIRD_PARTY.md — third-party components and licences

> Record every dependency and asset. Permissive licences only (MIT, BSD, Apache-2.0, ISC, PSF).
> A licence scan must be run before any blanket licence claim is made in the README or deck.

## Python (backend)
| Package | Purpose | Licence |
|---|---|---|
| pydantic | contracts / validation | MIT |
| cryptography | Ed25519 sign/verify | Apache-2.0 OR BSD-3-Clause |
| fastapi | HTTP API | MIT |
| uvicorn | ASGI server | BSD-3-Clause |
| sqlalchemy | ORM (SQLite default) | MIT |
| httpx | test client / smoke | BSD-3-Clause |
| pypdf | PDF text-layer extraction | BSD-3-Clause |
| python-multipart | multipart uploads | Apache-2.0 |
| pytest | tests | MIT |
| hypothesis | property tests | MPL-2.0 |
| ruff | linter | MIT |
| mypy | type checker | MIT |

Note: PyMuPDF/fitz (AGPL) is deliberately **not** used; `pypdf` (BSD) is used for text extraction only.

## JavaScript (frontend)
| Package | Purpose | Licence |
|---|---|---|
| react, react-dom | UI | MIT |
| react-router-dom | routing | MIT |
| react-i18next, i18next | i18n (en/bn) | MIT |
| vite, @vitejs/plugin-react | build | MIT |
| typescript | types | Apache-2.0 |
| tailwindcss, postcss, autoprefixer | styling | MIT |

## Fonts & data
- Schibsted Grotesk, Hind Siliguri, IBM Plex Mono — open-licence families (verify and record the exact
  licence files when self-hosting before submission).
- `data/ratecards/ratecards.json`, `data/registry/*`, all fixtures — **SIMULATED** content authored for this
  prototype; no third-party data.
- `data/rulepacks/bd.json` — UNVERIFIED placeholder; not legal advice.

## Scan status
- Run `pip-licenses` (Python) and `npx license-checker` (Node) and paste the summaries here before any
  blanket licence statement is added to the README. **Not yet run in this environment.**
