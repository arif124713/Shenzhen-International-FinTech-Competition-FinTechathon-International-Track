"""Red-team harness tests: the runner runs offline, generates 100 cases and beats the baselines.

Also covers the scenario suite, its `by_category` shape, and the frozen held-out hash gate (testing.md §6)."""
from __future__ import annotations

from eval.attacks.generate import FAMILIES, generate, heldout_sha256
from eval.run_eval import run, wilson


def test_generator_produces_100_cases_across_25_families():
    cases = generate()
    assert len(cases) == 100
    assert len({c["family"] for c in cases}) == 25
    assert sum(c["split"] == "heldout" for c in cases) == 50


def test_heldout_hash_is_stable_for_a_fixed_seed():
    assert heldout_sha256(generate()) == heldout_sha256(generate())


def test_heldout_hash_file_is_committed_and_non_empty():
    """The gate is only meaningful if the recorded hash is a committed, non-empty file (testing.md §6)."""
    from api.settings import settings

    path = settings.repo_root / "eval" / "heldout.sha256"
    assert path.exists(), "eval/heldout.sha256 must be committed, not gitignored/generated in place"
    assert path.read_text(encoding="utf-8").strip(), "eval/heldout.sha256 must not be empty"
    assert path.read_text(encoding="utf-8").strip() == heldout_sha256(generate())


def test_runner_refuses_when_the_recorded_heldout_hash_is_wrong(tmp_path, monkeypatch):
    from api.settings import settings

    from eval import run_eval

    # Preserve the real settings, then point repo_root at a scratch dir holding a wrong hash.
    real_root = settings.repo_root
    bogus = tmp_path / "eval" / "heldout.sha256"
    bogus.parent.mkdir(parents=True)
    bogus.write_text("0" * 64, encoding="utf-8")
    monkeypatch.setattr(type(settings), "repo_root", property(lambda self: tmp_path))
    try:
        run_eval._verify_heldout_hash()
        raise AssertionError("expected the runner to refuse a mismatched held-out hash")
    except SystemExit as exc:
        assert "HELD-OUT SET CHANGED" in str(exc)
    finally:
        monkeypatch.setattr(type(settings), "repo_root", property(lambda self: real_root))


def test_runner_refuses_when_the_heldout_hash_file_is_missing(tmp_path, monkeypatch):
    from api.settings import settings

    from eval import run_eval

    real_root = settings.repo_root
    monkeypatch.setattr(type(settings), "repo_root", property(lambda self: tmp_path))  # empty tree: no hash
    try:
        run_eval._verify_heldout_hash()
        raise AssertionError("expected the runner to refuse a missing held-out hash file")
    except SystemExit as exc:
        assert "HELD-OUT HASH MISSING" in str(exc)
    finally:
        monkeypatch.setattr(type(settings), "repo_root", property(lambda self: real_root))


def test_scenario_by_category_counts_every_case_including_skipped():
    from eval.scenarios.run import run as run_scenarios

    block = run_scenarios()
    total_from_categories = sum(v[1] for v in block["by_category"].values())
    assert total_from_categories == block["total"]


def test_wilson_interval_is_bounded_and_order_independent():
    lo, hi = wilson(0, 50)
    assert 0.0 <= lo <= hi <= 1.0
    lo2, hi2 = wilson(50, 50)
    assert lo2 >= 0.9


def test_full_run_is_offline_and_mandate_beats_baselines():
    report = run()
    systems = report["attacks"]["systems"]
    assert report["attacks"]["total"] == 96  # 24 attack families x 4 (A25 is the benign family)
    assert systems["B2"]["asr"] <= systems["B1"]["asr"] <= systems["B0"]["asr"]
    assert systems["B2"]["asr"] == 0.0  # all simulated attacks blocked by the deterministic engine
    assert report["false_blocks"]["rate"] == 0.0


def test_every_family_is_represented_in_the_case_set():
    families = {c["family"] for c in generate()}
    assert families == {f[0] for f in FAMILIES}


def test_scenarios_priority_subset_runs_and_passes():
    from eval.scenarios.run import run as run_scenarios

    block = run_scenarios()
    assert block["ran"] == block["total"] == 10  # every priority scenario now runs (T06 included)
    assert block["passed"] == block["ran"], block["failures"]
    assert set(block["by_category"]) <= {"T", "R", "M", "C", "P"}


def test_scenarios_report_is_wired_into_the_eval_report():
    report = run()
    assert report["scenarios"]["ran"] >= 8
    assert report["scenarios"]["passed"] == report["scenarios"]["ran"]
    assert any(r["id"] == "T01" for r in report["scenarios"]["results"])


def test_scenarios_never_silently_pass_a_skip():
    from eval.scenarios.run import run as run_scenarios

    block = run_scenarios()
    for r in block["results"]:
        if r["status"] == "skipped":
            assert r["passed"] is False
