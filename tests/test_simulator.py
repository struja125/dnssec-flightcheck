import json

from flightcheck.cli import main
from flightcheck.plan import MODELS
from flightcheck.simulator import simulate

from .conftest import SCENARIOS, scenario_names

H = 3600


def test_good_plans_are_safe(scenario):
    for name in scenario_names("good"):
        for model in MODELS:
            assert simulate(scenario(name), model).ok, (name, model)


def test_bad_plans_are_unsafe(scenario):
    for name in scenario_names("bad"):
        assert not simulate(scenario(name), "conservative").ok, name


def test_ksk_swap_breaks_until_old_ds_expires(scenario):
    result = simulate(scenario("ksk-double-ds-bad"))
    assert [(f.rrset, f.intervals) for f in result.failures] == [("dnskey", [[2 * H, 25 * H]])]
    failure = result.failures[0]
    assert failure.reference.rrset == "ds" and failure.reference.index == 0
    assert "KSK1" in failure.reason


def test_zsk_failures_differ_between_models(scenario):
    plan = scenario("zsk-prepublish-bad")
    fetch = simulate(plan, "fetch")
    conservative = simulate(plan, "conservative")
    # Signing with the new ZSK at once breaks both models for one DNSKEY TTL + propagation.
    assert {(f.rrset, tuple(map(tuple, f.intervals))) for f in fetch.failures} == {
        ("data:www", ((0, H + 300),)),
        ("data:mail", ((0, H + 300),)),
    }
    # Removing ZSK1 while the 1-day mail signatures are cached only hurts validators behind caches.
    mail = [f for f in conservative.failures if f.rrset == "data:mail" and f.start == 2 * H]
    assert mail and mail[0].end == 86400 + 300


def test_cli_exit_codes_and_json(capsys, tmp_path):
    assert main(["--no-color", "check", str(SCENARIOS / "ksk-double-ds-good.yaml")]) == 0
    assert main(["--no-color", "check", str(SCENARIOS / "ksk-double-ds-bad.yaml")]) == 1
    capsys.readouterr()
    assert main(["check", str(SCENARIOS / "ksk-double-ds-bad.yaml"), "--json", "-"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False and data["failures"][0]["rrset"] == "dnskey"
    report = tmp_path / "report.html"
    main(["check", str(SCENARIOS / "zsk-prepublish-bad.yaml"), "--html", str(report), "--both-models"])
    assert "What breaks" in report.read_text(encoding="utf-8")
    assert main(["check", str(tmp_path / "missing.yaml")]) == 2
