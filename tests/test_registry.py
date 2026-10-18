"""U-REG-01: registry trust, provenance and validity windows (testing.md §3, implementation_plan §4.7)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from api.services.registry import Registry
from api.settings import settings

NOW = datetime(2026, 10, 20, tzinfo=timezone.utc)


def reg() -> Registry:
    return Registry.load(settings.registry_dir / "registry.json")


def test_registry_entry_is_valid_and_has_provenance():
    r = reg()
    assert r.entry_valid("reg_northfield_univ", r.version, NOW)
    prov = r.provenance("reg_northfield_univ")
    assert prov["legal_name"] == "Northfield University"
    assert prov["provenance_method"]  # provenance must be present, never a bare "verified institution"


def test_registry_rejects_unknown_entry():
    assert not reg().entry_valid("reg_does_not_exist", None, NOW)


def test_registry_rejects_entry_outside_validity_window():
    r = reg()
    far_future = NOW + timedelta(days=1000)
    assert not r.entry_valid("reg_northfield_univ", r.version, far_future)


def test_registry_rejects_retired_key(tmp_path):
    import json

    data = json.loads((settings.registry_dir / "registry.json").read_text(encoding="utf-8"))
    data["keys"]["demo_registry_k1"]["status"] = "retired"
    p = tmp_path / "r.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    r = Registry.load(p)
    assert not r.entry_valid("reg_northfield_univ", r.version, NOW)  # retired key is not accepted


def test_registry_rejects_tampered_signature(tmp_path):
    import json

    data = json.loads((settings.registry_dir / "registry.json").read_text(encoding="utf-8"))
    sig = data["entries"][0]["signature"]
    data["entries"][0]["signature"] = ("AAAA" + sig[4:])
    p = tmp_path / "r.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    r = Registry.load(p)
    assert not r.entry_valid("reg_northfield_univ", r.version, NOW)
