"""Signature validity periods, and authenticated answers that say a name or type does not exist."""

import pytest
import yaml

from flightcheck.cli import EXIT_UNSAFE, main
from flightcheck.fixer import fix_plan
from flightcheck.lab.experiment import build_network
from flightcheck.lab.resolver import Resolver, wall_clock_for
from flightcheck.lab.zones import ROOT_IP, LabWorld
from flightcheck.plan import load_plan, plan_from_dict
from flightcheck.simulator import simulate

from .conftest import SCENARIOS

H = 3600
DAY = 86400
WWW = "www.bank.test."


# Without it the plan would end at once, and any later expiry would be the signer's routine.
LATER = {"name": "a later change", "at": "5d", "dnskey": {"ttl": "30m"}}


def plan(www_rrsig=None, dnskey_rrsig=None, signed_by=("Z1",), steps=(LATER,)):
    data = {
        "keys": {"K": {"role": "ksk"}, "Z1": {"role": "zsk"}, "Z2": {"role": "zsk"}},
        "initial": {
            "ds": {"keys": ["K"], "ttl": "1h"},
            "dnskey": {"keys": ["K", "Z1", "Z2"], "signed_by": ["K"], "ttl": "1h"},
            "data": {"www": {"signed_by": list(signed_by), "ttl": "1d"}},
        },
        "steps": list(steps),
    }
    if www_rrsig:
        data["initial"]["data"]["www"]["rrsig"] = www_rrsig
    if dnskey_rrsig:
        data["initial"]["dnskey"]["rrsig"] = dnskey_rrsig
    return plan_from_dict(data)


def resolver_for(parsed, **options):
    wall = wall_clock_for(parsed.start)
    world = LabWorld(parsed, wall)
    return Resolver("r", build_network(world, parsed), [ROOT_IP], world.trust_anchor(), wall, **options)


def windows(parsed, model):
    return simulate(parsed, model).failure_windows()


# ---- predictions


@pytest.mark.parametrize("model", ["conservative"])
def test_data_signature_expiry_is_a_failure_even_with_the_right_key(model):
    result = simulate(plan({"Z1": {"expires": "2d"}}), model)
    assert result.failures[0].intervals == [[2 * DAY, float("inf")]]
    assert "expired at T+2d" in result.failures[0].reason


@pytest.mark.parametrize("model", ["conservative"])
def test_dnskey_signature_expiry_is_a_failure(model):
    result = simulate(plan(dnskey_rrsig={"K": {"expires": "2d"}}), model)
    assert result.failures[0].kind == "dnskey" and result.failures[0].start == 2 * DAY


@pytest.mark.parametrize("model", ["conservative"])
def test_another_valid_signature_is_enough(model):
    both = plan({"Z1": {"expires": "2d"}, "Z2": {"expires": "4d"}}, signed_by=("Z1", "Z2"))
    assert windows(both, model)[0][0] == 4 * DAY


@pytest.mark.parametrize("model", ["conservative"])
def test_expiry_after_the_plan_is_a_warning_but_moving_a_step_past_it_is_a_failure(model):
    routine = simulate(plan({"Z1": {"expires": "9d"}}), model)
    assert routine.safe and any("signer has to keep running" in lint.message for lint in routine.lints)
    late = [{**LATER, "at": "10d"}]
    assert not simulate(plan({"Z1": {"expires": "9d"}}, steps=late), model).ok


def resign_at(at):
    return [{"name": "re-sign", "at": at, "data": {"www": {"rrsig": {"Z1": {"expires": "30d"}}}}}, LATER]


@pytest.mark.parametrize("model", ["conservative"])
def test_resigning_early_enough_is_safe(model):
    assert simulate(plan({"Z1": {"expires": "2d"}}, steps=resign_at("12h")), model).safe


# ---- the fixer


@pytest.mark.parametrize("model", ["conservative"])
def test_fixer_does_not_call_an_expired_signature_repaired(model, tmp_path, capsys):
    parsed = plan({"Z1": {"expires": "2d"}})
    assert not fix_plan(parsed, model).fixed_result.ok
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(parsed.source), encoding="utf-8")
    saved = tmp_path / "fixed.yaml"
    assert main(["--no-color", "fix", str(path), "--model", model, "--write", str(saved)]) == EXIT_UNSAFE
    assert not saved.exists() and "needs new signatures" in capsys.readouterr().err


# ---- real signatures in the lab


def test_lab_dnskey_signature_expires():
    parsed = plan(dnskey_rrsig={"K": {"expires": "2d"}})
    assert resolver_for(parsed).resolve(WWW, "A", 2 * DAY + 1).status == "bogus"


# ---- negative answers


def signed_resolver(**options):
    return resolver_for(load_plan(SCENARIOS / "ksk-double-ds-good.yaml"), **options)


def test_authenticated_nxdomain():
    outcome = signed_resolver().resolve("nope.bank.test.", "A", -H)
    assert (outcome.status, outcome.rcode) == ("secure", "NXDOMAIN")


def test_authenticated_nodata():
    outcome = signed_resolver().resolve(WWW, "AAAA", -H)
    assert (outcome.status, outcome.rcode, outcome.rrset) == ("secure", "NOERROR", None)
