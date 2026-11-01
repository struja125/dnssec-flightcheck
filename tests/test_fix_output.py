"""What ``flightcheck fix`` saves and says: the model is kept, and an unsafe plan is never written."""

import pytest

from flightcheck import cli
from flightcheck.cli import EXIT_ERROR, EXIT_MODEL_LIMITED, EXIT_SAFE, EXIT_UNSAFE, main
from flightcheck.fixer import LIMIT_LABEL, fix_plan
from flightcheck.plan import MODELS, load_plan
from flightcheck.simulator import simulate

from .conftest import SCENARIOS

UNFIXABLE = """\
name: Signs with a key that is never published
keys: {K1: {role: ksk}, Z1: {role: zsk}, Z2: {role: zsk}}
initial:
  ds: {keys: [K1], ttl: 1h}
  dnskey: {keys: [K1, Z1], signed_by: [K1], ttl: 1h}
  data: {www: {signed_by: [Z1], ttl: 1h}}
steps:
  - {name: Sign with Z2, at: 0, data: {www: {signed_by: [Z2]}}}
"""


def fix(*arguments) -> int:
    return main(["--no-color", "fix", *map(str, arguments)])


def check(*arguments) -> int:
    return main(["--no-color", "check", *map(str, arguments)])


@pytest.fixture
def unfixable(tmp_path):
    path = tmp_path / "unfixable.yaml"
    path.write_text(UNFIXABLE, encoding="utf-8")
    return path


def no_leftovers(folder) -> bool:
    return not list(folder.glob(".*.tmp"))


# ---- the model (F3)


def test_saved_plan_keeps_the_selected_model(tmp_path, capsys):
    # This plan used to be saved without a model, so `check` read it as conservative and called it unsafe.
    saved = tmp_path / "fixed.yaml"
    assert fix(SCENARIOS / "zsk-prepublish-bad.yaml", "--model", "fetch", "--write", saved) == EXIT_MODEL_LIMITED
    assert load_plan(saved).model == "fetch"
    capsys.readouterr()
    assert check(saved) == EXIT_SAFE
    assert "SAFE under the fetch model only" in capsys.readouterr().out
    assert check(saved, "--model", "conservative") == EXIT_UNSAFE


def test_fetch_safe_plan_is_not_presented_as_universally_safe(tmp_path, capsys):
    saved = tmp_path / "fixed.yaml"
    assert fix(SCENARIOS / "zsk-prepublish-bad.yaml", "--model", "fetch", "--write", saved) == EXIT_MODEL_LIMITED
    captured = capsys.readouterr()
    assert "safe under the fetch model only" in captured.out
    assert "safe under both" not in captured.out + captured.err
    assert "model-limited" in captured.err and "NOT safe under the conservative model" in captured.err
    assert "T+" in captured.err  # the intervals that remain
    plan = load_plan(saved)
    assert LIMIT_LABEL in plan.description and "NOT safe under: conservative" in plan.description
    assert not simulate(plan, "conservative").ok


def test_both_models_are_verified():
    result = fix_plan(load_plan(SCENARIOS / "zsk-prepublish-bad.yaml"), "fetch")
    assert set(result.verified) == set(MODELS)
    assert result.safe_models == ["fetch"] and result.unsafe_models == ["conservative"]
    assert result.model_limited and not result.fully_safe
    result = fix_plan(load_plan(SCENARIOS / "zsk-prepublish-bad.yaml"), "conservative")
    assert result.fully_safe and not result.model_limited


# ---- unsafe results are not written (F4)


def test_unsafe_result_is_not_written(tmp_path, unfixable, capsys):
    saved = tmp_path / "fixed.yaml"
    assert fix(unfixable, "--write", saved) == EXIT_UNSAFE
    assert not saved.exists() and no_leftovers(tmp_path)
    captured = capsys.readouterr()
    assert "no safe plan" in captured.err and "was not written" in captured.err
    assert "T+0 -> never" in captured.err and "signed only by {Z2}" in captured.err
    assert "still unsafe" in captured.out and "safe under both" not in captured.out


def test_failed_replace_keeps_the_old_file_and_removes_the_temporary_one(tmp_path, monkeypatch):
    saved = tmp_path / "fixed.yaml"
    saved.write_text("the previous plan\n", encoding="utf-8")

    def refuse(*_):
        raise PermissionError("in use")

    monkeypatch.setattr(cli.os, "replace", refuse)
    assert fix(SCENARIOS / "ksk-double-ds-bad.yaml", "--write", saved) == EXIT_ERROR
    assert saved.read_text(encoding="utf-8") == "the previous plan\n"
    assert no_leftovers(tmp_path)


# ---- the input and successful runs


def test_output_cannot_be_the_input(tmp_path, capsys):
    path = tmp_path / "plan.yaml"
    original = (SCENARIOS / "ksk-double-ds-bad.yaml").read_bytes()
    path.write_bytes(original)
    assert fix(path, "--write", path) == EXIT_ERROR
    assert path.read_bytes() == original
    assert "must not name the input" in capsys.readouterr().err


def test_exit_codes_tell_the_outcomes_apart():
    assert len({EXIT_SAFE, EXIT_UNSAFE, EXIT_ERROR, EXIT_MODEL_LIMITED}) == 4
