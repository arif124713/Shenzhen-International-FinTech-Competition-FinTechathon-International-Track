"""Demo keys and registry signing. `make setup` runs this once; keys are demo-only and clearly named."""
from __future__ import annotations

import json
from pathlib import Path

from policy_engine import canonical_json, generate_keypair, sign
from policy_engine.signing import verify

from ..settings import settings


def ensure_keys(keys_path: Path | None = None) -> dict[str, dict[str, str]]:
    """Create data/registry/keys.json (mandate/registry/engine demo keys) if missing. Returns the mapping."""
    keys_path = keys_path or (settings.registry_dir / "keys.json")
    if keys_path.exists():
        return json.loads(keys_path.read_text(encoding="utf-8"))
    keys: dict[str, dict[str, str]] = {}
    for name in ("mandate", "registry", "engine", "audit"):
        priv, pub = generate_keypair()
        keys[name] = {"private_b64": priv, "public_b64": pub}
    keys_path.parent.mkdir(parents=True, exist_ok=True)
    keys_path.write_text(json.dumps(keys, indent=2), encoding="utf-8")
    return keys


def sign_registry(keys: dict[str, dict[str, str]], *, template_path: Path | None = None,
                  out_path: Path | None = None) -> Path:
    """Write data/registry/registry.json with every entry signed by the registry key."""
    template_path = template_path or (settings.registry_dir / "registry.template.json")
    out_path = out_path or (settings.registry_dir / "registry.json")
    data = json.loads(template_path.read_text(encoding="utf-8"))
    reg_pub = keys["registry"]["public_b64"]
    reg_priv = keys["registry"]["private_b64"]
    data["keys"]["demo_registry_k1"]["public_key_b64"] = reg_pub
    for entry in data["entries"]:
        entry["signature"] = sign(reg_priv, canonical_json(entry["body"]))
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    assert verify(reg_pub, canonical_json(data["entries"][0]["body"]), data["entries"][0]["signature"])
    return out_path


def main() -> None:  # pragma: no cover - setup entry point
    keys = ensure_keys()
    path = sign_registry(keys)
    print(f"wrote {path}")


if __name__ == "__main__":  # pragma: no cover
    main()
