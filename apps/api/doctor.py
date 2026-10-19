"""`make doctor` — environment and provider capability check (remaining_work_spec §3, §2.3).

Checks, printing a clear pass/fail for each and NEVER printing the API key:
  1. provider / base URL / model IDs are set;
  2. API key presence (boolean only);
  3. a one-call text reachability test against the configured model (verifies the MODEL ID actually resolves);
  4. an image-capability probe (one tiny image): if the provider rejects images, the reader must run in
     `text` mode — printed as the effective READER_MODE.

In `replay` mode (the default) there is no network: this reports the configured values and skips the live
calls, so `make doctor` is safe offline. Run: python -m api.doctor
"""
from __future__ import annotations

import sys
from pathlib import Path as _Path

_ROOT = _Path(__file__).resolve().parents[2]
for _sub in ("packages", "services", "apps", "."):
    _p = str((_ROOT / _sub).resolve())
    if _p not in sys.path:
        sys.path.insert(0, _p)

from api.settings import settings  # noqa: E402

# A 1x1 transparent PNG, base64 (tiny image for the capability probe).
_TINY_PNG = ("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGA"
             "WjR9awAAAABJRU5ErkJggg==")


def _check(name: str, ok: bool, detail: str = "") -> bool:
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail else ""))
    return ok


def run() -> int:
    provider = settings.llm_provider
    print("Mandate doctor — simulated system, no real money moves")
    _check("provider configured", bool(provider), f"LLM_PROVIDER={provider}")
    _check("base URL set", bool(settings.llm_base_url), settings.llm_base_url)
    _check("model id (reader) set", bool(settings.llm_model_reader), settings.llm_model_reader)
    key_present = bool(settings.llm_api_key)
    if provider == "replay":
        # In replay mode no key is needed, so report it as informational, not a failure.
        print(f"[INFO] API key {'present' if key_present else 'not set'} (not required for replay)")
    else:
        _check("API key present", key_present, "present (value not printed)" if key_present else "missing")

    if provider == "replay":
        print("[SKIP] live model reachability — LLM_PROVIDER=replay (offline)")
        print("[SKIP] image capability probe — replay mode")
        print("READER_MODE=text (offline replay uses recorded fixtures)")
        return 0

    if not key_present:
        _check("live model reachable", False, "no API key set; cannot test")
        return 1

    from api.agents.llm import build_client

    client = build_client(role="reader")
    # 3. one-call text reachability: does the configured MODEL ID resolve?
    try:
        resp = client.complete(system="Reply with the single word: ok", user="ping", prompt_version="doctor_v1")
        _check("live model reachable (model id resolves)", True,
               f"model={settings.llm_model_reader}, response_len={len(resp.text)}")
    except Exception as exc:  # noqa: BLE001 - a failed probe must report, not crash
        _check("live model reachable (model id resolves)", False, f"{type(exc).__name__}: {exc}")
        return 1

    # 4. image capability probe: one tiny image.
    data_uri = "data:image/png;base64," + _TINY_PNG
    try:
        client.complete(system="You are a capability probe. Reply 'ok'.", user="What colour is this image?",
                        prompt_version="doctor_v1", images=[data_uri])
        _check("image capability", True, "model accepted an image → READER_MODE=vision")
        print("READER_MODE=vision")
    except Exception as exc:  # noqa: BLE001 - image rejection is expected for text-only models
        _check("image capability", False, f"{type(exc).__name__}: model rejected image input")
        print("READER_MODE=text (model rejects images; reader will use the text layer)")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
