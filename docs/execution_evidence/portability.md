# portability.md — clean-environment run evidence (testing.md G-1)

> Honesty rule: this file records only runs that were actually performed on this machine. A container/WSL
> run that has not been executed is marked **not yet run**, never faked.

## 1. Local Windows run (performed)

Environment: Windows, Python 3.11+ from `.venv`, Node 22, PowerShell.

| Command | Result |
|---|---|
| `python -m pytest` | **1358 passed** in ~4 s (offline; no network) |
| `python -m ruff check packages apps services tests eval` | **all checks passed** |
| `python -m eval.attacks.generate` | wrote 100 cases (`eval/attacks/cases.json`) |
| `python -m eval.run_eval` | wrote `eval/reports/latest.{json,html}` and `docs/execution_evidence/index.md` |
| `python -m eval.evidence` | wrote audit export, ledger CSV, signed checkpoint, LLM config note |
| `npx playwright test` (apps/web) | **16 passed, 2 skipped** (guardian flow is mobile-only by design) |

Notes:
- `make test` and `make eval` run **fully offline** in replay mode; no API key or network is required.
- The Playwright run boots the real FastAPI app (replay LLM) and the Vite dev server automatically.

## 2. Clean-container run (to perform before submission)

Reference environment: a clean `python:3.11` Linux container. Command:

```
make setup && make test && make eval
```

Status: **not yet run** on this machine (no Docker/WSL available in the build window). The repository is
written for portability: `pathlib` + repo-relative paths, no absolute paths committed, LF line endings via
`.gitattributes`, and every step exposed as a `make` target. Record the container output here before submitting.
