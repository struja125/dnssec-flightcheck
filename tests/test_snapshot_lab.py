"""Plans from snapshots in the existing lab, with synthetic keys. No Internet and no Docker."""

import base64
import copy
import json
from pathlib import Path

import dns.dnssec
import dns.message
import dns.name
import dns.rdatatype
import pytest
import yaml

from flightcheck.cli import EXIT_MODEL_LIMITED, main
from flightcheck.fixer import fix_plan
from flightcheck.lab.experiment import build_network, run_experiment
from flightcheck.lab.report import lab_report
from flightcheck.lab.resolver import Resolver, _ds_matches, wall_clock_for
from flightcheck.lab.zones import ROOT_IP, LabWorld
from flightcheck.plan import plan_from_dict

from .test_planbuilder import built, snapshot

WWW = "www.bank.test."
ROOT = Path(__file__).resolve().parent.parent


def lab(parsed, trust_cache=False):
    wall = wall_clock_for(parsed.start)
    world = LabWorld(parsed, wall)
    resolver = Resolver("r", build_network(world, parsed), [ROOT_IP], world.trust_anchor(), wall, trust_cache=trust_cache)
    return world, resolver


def rushed(parsed):
    source = copy.deepcopy(parsed.source)
    for step in source["steps"]:
        step["at"] = 0
    return plan_from_dict(source)


def servfails(parsed, population="behind-cache"):
    return run_experiment(parsed, resolvers=2, probe_interval=1800, seed=1).stats[population].bogus


@pytest.mark.parametrize("rollover", ["zsk", "ksk"])
def test_generated_schedule_runs_in_the_lab_without_failures(rollover):
    experiment = run_experiment(built(rollover), resolvers=2, probe_interval=1800, seed=1)
    assert all(stats.bogus == 0 and stats.lookups for stats in experiment.stats.values())


def test_ds_and_signatures_are_synthetic_and_verify():
    snap = snapshot()
    parsed = built("ksk", snap)
    world, _ = lab(parsed)
    real_digests = {record["digest"] for record in snap["ds"]["records"]}
    real_keys = {key["public_key"] for key in snap["dnskey"]["keys"]}
    ds_rrset = world.tld_at(0).get(world.zone, dns.rdatatype.DS)
    dnskey = world.zone_at(0).get(world.zone, dns.rdatatype.DNSKEY)
    assert not real_digests & {ds.digest.hex() for ds in ds_rrset}
    assert not real_keys & {base64.b64encode(key.key).decode() for key in dnskey}
    assert any(_ds_matches(world.zone, ds, key) for ds in ds_rrset for key in dnskey)
    www = dns.name.from_text(WWW)
    keys = {world.zone: dnskey.to_rdataset()}
    now = wall_clock_for(parsed.start)
    dns.dnssec.validate(world.zone_at(0).get(www, dns.rdatatype.A), world.zone_at(0).sig(www, dns.rdatatype.A), keys, now=now)


@pytest.mark.parametrize("rollover", ["zsk", "ksk"])
def test_unsafe_schedule_fails_and_the_corrected_one_does_not(rollover):
    unsafe = rushed(built(rollover))
    assert servfails(unsafe) > 0
    fixed = fix_plan(unsafe, "conservative")
    assert fixed.fixed_result.ok and servfails(fixed.fixed_plan) == 0


# ---- provenance


def test_reports_keep_the_evidence_and_the_run_does_not_widen_it(tmp_path):
    parsed = built("zsk")
    experiment = run_experiment(parsed, resolvers=2, probe_interval=1800, seed=1)
    text = experiment.summary_text()
    for phrase in ("coverage sampled", "2027-01-15T08:00:00Z", "zone_ttl_bound", "synthetic keys", "not how the production zone", "does not make the plan safe"):
        assert phrase in text
    data = experiment.to_dict()
    json.dumps(data)
    assert data["coverage"] == "sampled" and data["key_mapping"]
    assert "coverage sampled" in lab_report(experiment)
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(parsed.source), encoding="utf-8")
    assert main(["--no-color", "lab", str(path), "--resolvers", "1", "--probe-interval", "3600"]) == 0
    assert main(["--no-color", "check", str(path)]) == EXIT_MODEL_LIMITED
