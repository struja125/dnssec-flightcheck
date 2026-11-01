"""From a snapshot of the lab's zone, through a candidate plan, to check and fix."""

import json

import dns.name
import dns.rdatatype
import pytest
import yaml

from flightcheck.cli import EXIT_MODEL_LIMITED, main
from flightcheck.plan import PlanError, apply_change, plan_from_dict
from flightcheck.planbuilder import UNOBSERVED, build_plan, key_id, plan_text

from .test_snapshot import collect, plan as zone


WWW = (dns.name.from_text("www.bank.test."), dns.rdatatype.A)


def snapshot(parsed=None):
    return collect(parsed or zone(dnskey=("K1", "Z")), children=["192.0.2.1"], queries=[WWW])


def key_with(snap, flags):
    return next(key_id(k) for k in snap["dnskey"]["keys"] if k["flags"] == flags)


def inputs(snap, rollover, **changes):
    values = {
        "replace": key_with(snap, 257 if rollover == "ksk" else 256),
        "new_key": {"algorithm": 13},
        "start": "2027-02-01T00:00:00Z",
        "delays": {"propagation": "5m", "registry": "1h", "parent_propagation": "5m"},
        "margin": "1h",
        "resolver": {"max_cache_ttl": "1d"},
        "zone_ttl_bound": "1d",
    }
    values.update(changes)
    return {name: value for name, value in values.items() if value is not None}


def built(rollover="zsk", snap=None, **changes):
    snap = snap or snapshot()
    return plan_from_dict(yaml.safe_load(plan_text(build_plan(snap, rollover, inputs(snap, rollover, **changes)))))


def final_state(parsed):
    state = dict(parsed.initial)
    for step in parsed.ordered_steps():
        for rrset, change in step.changes.items():
            state[rrset] = apply_change(state[rrset], change)
    return state


# ---- generation


def test_zsk_rollover_steps_and_final_state():
    snap = snapshot()
    parsed = built("zsk", snap)
    old = key_with(snap, 256)
    new = "new-zsk-placeholder"
    steps = parsed.ordered_steps()
    assert [list(s.changes) for s in steps][0] == ["dnskey"] and "data:www" in steps[1].changes and list(steps[2].changes) == ["dnskey"]
    assert steps[0].at < steps[1].at < steps[2].at
    state = final_state(parsed)
    assert state["dnskey"].keys == {key_with(snap, 257), new}
    assert state["data:www"].signed_by == {new} and state[f"data:{UNOBSERVED}"].signed_by == {new}
    assert old not in state["dnskey"].keys


def test_ksk_rollover_steps_and_final_state():
    snap = snapshot()
    parsed = built("ksk", snap)
    new = "new-ksk-placeholder"
    assert [list(s.changes) for s in parsed.ordered_steps()] == [["ds"], ["dnskey"], ["ds"]]
    assert parsed.ordered_steps()[0].changes["ds"]["keys"] == {key_with(snap, 257), new}
    state = final_state(parsed)
    assert state["ds"].keys == {new} and state["dnskey"].signed_by == {new}
    assert state["data:www"].signed_by == {key_with(snap, 256)}


def test_unclear_role_needs_the_operator():
    # One key that signs everything: it could be a CSK, so nothing is assumed.
    snap = snapshot(zone(dnskey=("K1", "Z"), signed_by=("Z",), ds=("Z",)))
    with pytest.raises(PlanError, match="confirm it under 'roles'"):
        build_plan(snap, "zsk", inputs(snap, "zsk"))
    zsk = key_with(snap, 256)
    ksk = key_with(snap, 257)
    parsed = built("zsk", snap, roles={zsk: "zsk", ksk: "ksk"})
    assert parsed.source["provenance"]["keys"][zsk]["role_from"] == "confirmed by the operator"


def test_private_material_is_never_in_the_plan():
    snap = snapshot()
    text = plan_text(build_plan(snap, "zsk", inputs(snap, "zsk")))
    assert "PRIVATE" not in text and "private" not in text


# ---- what is refused


@pytest.mark.parametrize("status", ["unknown", "absent_unproven"])
def test_uncertain_ds_is_never_turned_into_an_insecure_zone(status):
    snap = snapshot()
    snap["ds"] = {"status": status, "ttl": None, "records": []}
    with pytest.raises(PlanError, match="cannot be assumed"):
        build_plan(snap, "zsk", inputs(snap, "zsk"))


# ---- evidence and the verdicts


def test_partial_snapshot_gives_a_sampled_plan_with_the_unobserved_bound():
    parsed = built()
    assert parsed.coverage == "sampled"
    assert parsed.initial[f"data:{UNOBSERVED}"].ttl == 86400
    provenance = parsed.source["provenance"]
    assert {"name": "www.bank.test.", "type": "A", "ttl": 300} in provenance["observed"]
    assert UNOBSERVED in provenance["unobserved"]
    assert provenance["assumptions"]["zone_ttl_bound"] == "1d"


def write(tmp_path, parsed):
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(parsed.source), encoding="utf-8")
    return str(path)


def test_check_never_gives_a_plain_safe_for_a_sampled_plan(tmp_path, capsys):
    path = write(tmp_path, built())
    assert main(["--no-color", "check", path]) == EXIT_MODEL_LIMITED
    out = capsys.readouterr().out
    assert "SAFE for the sampled records only" in out and "Verdict: SAFE -" not in out
    assert main(["check", path, "--json", "-"]) == EXIT_MODEL_LIMITED
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False and data["coverage"] == "sampled" and data["no_bogus_answers"] is True
    report = tmp_path / "report.html"
    main(["check", path, "--html", str(report)])
    assert "sampled records only" in report.read_text(encoding="utf-8")
