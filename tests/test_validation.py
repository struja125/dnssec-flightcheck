"""A malformed plan is rejected before anything is predicted: it must never reach a SAFE verdict."""

import copy

import pytest
import yaml

from flightcheck.cli import main
from flightcheck.plan import PlanError, load_plan, plan_from_dict
from flightcheck.simulator import simulate

from .conftest import SCENARIOS

ROOT = SCENARIOS.parent
ALL_PLANS = sorted([*SCENARIOS.rglob("*.yaml"), *(ROOT / "examples").glob("*.yaml")])

# The KSK is swapped one hour after the DS, while the old DS is cached for a day: this plan is unsafe,
# so each mistake below that went unnoticed would be able to turn it into a SAFE verdict.
UNSAFE = {
    "keys": {"K1": {"role": "ksk"}, "K2": {"role": "ksk"}, "Z": {"role": "zsk"}},
    "initial": {
        "ds": {"keys": ["K1"], "ttl": "1d"},
        "dnskey": {"keys": ["K1", "Z"], "signed_by": ["K1"], "ttl": "1h"},
        "data": {"www": {"signed_by": ["Z"], "ttl": "1h"}},
    },
    "steps": [
        {"name": "ds", "at": 0, "ds": {"keys": ["K1", "K2"]}},
        {"name": "swap", "at": "1h", "dnskey": {"keys": ["K2", "Z"], "signed_by": ["K2"]}},
    ],
}


def plan_with(change) -> dict:
    data = copy.deepcopy(UNSAFE)
    change(data)
    return data


def initial(section: str, **fields):
    return lambda d: d["initial"].__setitem__(section, {**d["initial"][section], **fields})


def replace_section(section: str, value):
    return lambda d: d["initial"].__setitem__(section, value)


def top(**fields):
    return lambda d: d.update(fields)


def without(*path):
    def change(d):
        for part in path[:-1]:
            d = d[part]
        del d[path[-1]]

    return change


# (mistake, the field the message must name)
INVALID = {
    # F1: unknown and missing fields
    "unknown top-level field": (top(margn="1h"), "margn"),
    "misspelled delay": (top(delays={"propogation": "6h"}), "propogation"),
    "unknown resolver field": (top(resolver={"max_ttl": "1h"}), "max_ttl"),
    "initial.ds with key instead of keys": (replace_section("ds", {"key": ["K1"], "ttl": "1d"}), "key"),
    "initial.ds without keys": (replace_section("ds", {"ttl": "1d"}), "keys"),
    "initial without ds": (without("initial", "ds"), "ds"),
    "initial without dnskey": (without("initial", "dnskey"), "dnskey"),
    "initial without data": (without("initial", "data"), "data"),
    "initial.dnskey without signed_by": (replace_section("dnskey", {"keys": ["K1", "Z"]}), "signed_by"),
    "unknown initial section": (lambda d: d["initial"].update(soa={}), "soa"),
    "unknown initial.dnskey field": (initial("dnskey", signers=["K1"]), "signers"),
    "data without signed_by": (lambda d: d["initial"]["data"].update(www={"ttl": "1h"}), "signed_by"),
    "empty data entry": (lambda d: d["initial"]["data"].update(www=None), "www"),
    "unknown key field": (lambda d: d["keys"]["K1"].update(alg=13), "alg"),
    "key without role": (lambda d: d["keys"].update(K1={"algorithm": 13}), "role"),
    "plan without keys": (without("keys"), "keys"),
    "plan without initial": (without("initial"), "initial"),
    "plan without steps": (without("steps"), "steps"),
    "unknown step field": (lambda d: d["steps"][0].update(when="1h"), "when"),
    "empty change in a step": (lambda d: d["steps"][0].update(ds={}), "ds"),
    "keys set to nothing": (initial("ds", keys=None), "initial.ds.keys"),
    # F2: negative values
    "negative DS TTL": (initial("ds", ttl="-1d"), "initial.ds.ttl"),
    "negative DNSKEY TTL": (initial("dnskey", ttl="-1h"), "initial.dnskey.ttl"),
    "negative data TTL": (lambda d: d["initial"]["data"]["www"].update(ttl=-60), "initial.data.www.ttl"),
    "negative TTL in a step": (lambda d: d["steps"][0]["ds"].update(ttl="-1h"), "ds.ttl"),
    "negative max_cache_ttl": (top(resolver={"max_cache_ttl": "-5d"}), "resolver.max_cache_ttl"),
    "negative bogus_ttl": (top(resolver={"bogus_ttl": -1}), "resolver.bogus_ttl"),
    "negative key_failure_ttl": (top(resolver={"key_failure_ttl": "-1m"}), "resolver.key_failure_ttl"),
    "negative registry": (top(delays={"registry": "-2d"}), "delays.registry"),
    "negative propagation": (top(delays={"propagation": "-5h"}), "delays.propagation"),
    "negative parent_propagation": (top(delays={"parent_propagation": "-1h"}), "delays.parent_propagation"),
    "negative margin": (top(margin="-1h"), "margin"),
    # F14: malformed structures
    "key is a number": (lambda d: d["keys"].update(K1=5), "keys.K1"),
    "initial.ds is a number": (replace_section("ds", 5), "initial.ds"),
    "initial is a list": (top(initial=[1]), "initial"),
    "resolver is text": (top(resolver="x"), "resolver"),
    "delays is a list": (top(delays=[1]), "delays"),
    "steps is a number": (top(steps=5), "steps"),
    "steps is a mapping": (top(steps={"at": 0}), "steps"),
    "steps is empty": (top(steps=None), "steps"),
    "step is a number": (top(steps=[5]), "step 1"),
    "keys of a DS is a number": (initial("ds", keys=5), "initial.ds.keys"),
    "keys in a step is a number": (lambda d: d["steps"][0]["ds"].update(keys=5), "ds.keys"),
    "TTL is a list": (initial("ds", ttl=[1]), "initial.ds.ttl"),
    "TTL is infinite": (initial("ds", ttl=float("inf")), "initial.ds.ttl"),
    "TTL is not a number": (initial("ds", ttl=float("nan")), "initial.ds.ttl"),
    "TTL is absurdly long": (initial("ds", ttl="999999999d"), "initial.ds.ttl"),
    "step time is empty": (lambda d: d["steps"][0].update(at=None), "at"),
    "algorithm is a list": (lambda d: d["keys"]["K1"].update(algorithm=[13]), "algorithm"),
    "unknown algorithm number": (lambda d: d["keys"]["K1"].update(algorithm=99), "algorithm"),
    "strict_algorithms is text": (top(resolver={"strict_algorithms": "false"}), "strict_algorithms"),
    "zone is a number": (top(zone=5), "zone"),
    "start is not a time": (top(start="tomorrow"), "start"),
}


def test_the_base_plan_is_valid_and_unsafe():
    assert not simulate(plan_from_dict(UNSAFE)).ok


def test_invalid_plan_is_rejected_and_names_the_field():
    for change, field in INVALID.values():
        with pytest.raises(PlanError) as error:
            plan_from_dict(plan_with(change))
        assert field in str(error.value)


@pytest.mark.parametrize("mistake", list(INVALID)[:1])
def test_check_rejects_invalid_plan_without_a_verdict(mistake, tmp_path, capsys):
    change, _ = INVALID[mistake]
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(plan_with(change)), encoding="utf-8")
    report = tmp_path / "report.html"
    assert main(["--no-color", "check", str(path), "--html", str(report)]) == 2
    out, err = capsys.readouterr()
    assert "SAFE" not in out and "error:" in err
    assert not report.exists()


def test_error_suggests_the_field_that_was_meant():
    with pytest.raises(PlanError, match="did you mean 'propagation'"):
        plan_from_dict(plan_with(top(delays={"propogation": "6h"})))


def test_every_plan_in_the_repository_still_loads():
    for path in ALL_PLANS:
        assert load_plan(path).steps, path
