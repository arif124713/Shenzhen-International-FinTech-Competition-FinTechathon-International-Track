"""Seed a dummy mandate for manual testing (SIMULATED; no real money or policy).

Usage (from the repo root):

    # list the available dummy mandates
    python -m scripts.seed_mandate --list

    # activate one in-platform (server-side runtime) and print the result
    python -m scripts.seed_mandate tuition_strict

    # print the JSON body to POST to /api/v1/mandates/confirm
    python -m scripts.seed_mandate student_allowance --print-json

Notes:
- The demo mandate signing key is server-held (data/registry/keys.json); this script uses the same
  service the API uses (`api.services.mandates.sign_and_activate`) so behavior matches the web flow.
- This only makes the mandate the ACTIVE in-process version. A real running uvicorn server has its own
  process state; to seed a live server, POST the `--print-json` body to /api/v1/mandates/confirm.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)


def load_dummies() -> dict:
    path = _ROOT / "data" / "seed" / "mandates.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    # strip the comment / helper keys; allow the caller to inspect them separately
    return {k: v for k, v in data.items() if k != "mandates"}, data["mandates"]


def main(argv: list[str]) -> int:
    meta, mandates = load_dummies()
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}

    if "--list" in flags or not args:
        print("Available dummy mandates:")
        for name, body in mandates.items():
            types = ", ".join(r["type"] for r in body["rules"])
            print(f"  {name:20s} {body['mandate_id']:18s} rules: {types}")
        return 0

    name = args[0]
    if name not in mandates:
        print(f"unknown mandate {name!r}; use --list", file=sys.stderr)
        return 2
    body = mandates[name]

    if "--print-json" in flags:
        print(json.dumps({"body": body, "back_translation": f"[dummy] {name}"}, indent=2))
        return 0

    from api.services.mandates import sign_and_activate
    from api.services.runtime import reset_runtime

    rt = reset_runtime()
    signed = sign_and_activate(rt, body, back_translation=f"[dummy] {name}")
    print(f"activated {name}: mandate_id={signed.body['mandate_id']} version={signed.body['version']}")
    print(f"signature={signed.signature[:24]}…")
    print(f"rules={len(signed.body['rules'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
