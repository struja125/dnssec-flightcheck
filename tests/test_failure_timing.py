"""How long a failure can outlive the zone's problem, on every clock. Times are chosen by hand, so each
resolver below reaches the exact state a test is about, and no random lookups are involved."""

from dataclasses import replace

import pytest

from flightcheck.lab.experiment import build_network
from flightcheck.lab.network import LabConfig, Sample, _named_conf, _unbound_conf, lab_memory, probe_report_text, resolver_windows, software_of, summarise
from flightcheck.lab.resolver import Resolver, wall_clock_for
from flightcheck.lab.zones import ROOT_IP, LabWorld
from flightcheck.plan import load_plan
from flightcheck.simulator import simulate

from .conftest import SCENARIOS

H = 3600
NAME = "www.bank.test."
KSK_END = 25 * H  # ksk-double-ds-bad: registry 1h + DS TTL 1d


def ksk_plan():
    return load_plan(SCENARIOS / "ksk-double-ds-bad.yaml")


def resolver_for(plan, key_failure, answer):
    wall = wall_clock_for(plan.start)
    world = LabWorld(plan, wall)
    return Resolver(
        "r", build_network(world, plan), [ROOT_IP], world.trust_anchor(), wall, key_failure_ttl=key_failure, bogus_ttl=answer
    )


def with_timers(plan, key_failure, answer):
    return replace(plan, key_failure_ttl=key_failure, bogus_ttl=answer)


# ---- the timers add up only after a failed chain of trust (F5)


@pytest.mark.parametrize("key_failure, answer", [(60, 60)])
def test_chained_bound_is_reached_and_not_exceeded(key_failure, answer):
    plan = with_timers(ksk_plan(), key_failure, answer)
    assert simulate(plan, "fetch").failure_windows()[-1][1] == KSK_END + key_failure + answer
    resolver = resolver_for(plan, key_failure, answer)
    resolver.resolve(NAME, "A", 3599)
    resolver.touch(plan.zone, KSK_END - 2)  # DS v0, fetched at 3599, is cached until KSK_END - 1
    last_chance = KSK_END + key_failure - 3  # the chain still fails 1 s before its timer ends
    assert resolver.resolve(NAME, "A", last_chance).status == "bogus"
    if answer:
        assert resolver.resolve(NAME, "A", last_chance + answer - 1).status == "bogus"
    assert resolver.resolve(NAME, "A", KSK_END + key_failure + answer).status == "secure"


# ---- the clock of the probe (F6)


def config(scale):
    return LabConfig(start_wall=0, scale=scale, t_begin=-24 * H, t_end=60 * H)


def failure_at(t, resolver):
    return Sample(t, resolver, NAME, "bogus", "SERVFAIL", [])


def answer_at(t, resolver):
    return Sample(t, resolver, NAME, "secure", "NOERROR", [])


def probe_inside(scale, t, label="unbound", model="fetch"):
    samples = [answer_at(-H, label), failure_at(t, label)]
    return summarise(ksk_plan(), config(scale), {label: "ip"}, samples, 0.25)["per_resolver"][label]["inside"][model]


@pytest.mark.parametrize("scale", [600])
@pytest.mark.parametrize("label, software", [("unbound", "unbound"), ("bind", "bind"), ("emulated", None)])
@pytest.mark.parametrize("model", ["fetch"])
def test_window_is_scaled_exactly_once(scale, label, software, model):
    assert software_of(label) == software
    key_failure, answer = lab_memory(software, scale)
    window = resolver_windows(ksk_plan(), label, scale, model)
    assert window[-1][1] == KSK_END + (key_failure + answer) * scale
    tolerance = scale * 2.25
    end = window[-1][1] + tolerance
    assert probe_inside(scale, end - 1, label, model) == 1
    assert probe_inside(scale, end + 1, label, model) == 0


# ---- what was observed


def test_report_separates_prediction_from_observation():
    plan = ksk_plan()
    summary = summarise(plan, config(600), {"unbound": "ip"}, [failure_at(10 * H, "unbound"), answer_at(11 * H, "unbound")], 0.25)
    data = summary["per_resolver"]["unbound"]
    assert data["comparison"]["fetch"]["series"][0]["recovered_at"] == 11 * H
    assert data["predicted_end"]["fetch"] == KSK_END + 61 * 600
    text = probe_report_text(summary, plan)
    assert "latest possible failure" in text and "recovered between T+10h and T+11h" in text
    summary = summarise(plan, config(600), {"unbound": "ip"}, [failure_at(10 * H, "unbound")], 0.25)
    assert "recovery_not_observed" in probe_report_text(summary, plan)


# ---- the Docker configuration (F7)


def test_docker_timers_match_what_the_prediction_assumes():
    fast, slow = config(600), config(1)
    assert "val-bogus-ttl: 1\n" in _unbound_conf(None, fast)
    assert "val-bogus-ttl: 1\n" not in _unbound_conf(None, slow)

    class Ds:
        digest, key_tag, algorithm, digest_type = b"\x01", 1, 13, 2

    assert "servfail-ttl 0;" in _named_conf(Ds, fast)
    assert "servfail-ttl 0;" not in _named_conf(Ds, slow)
