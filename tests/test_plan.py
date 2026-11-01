import pytest

from flightcheck.durations import parse_duration
from flightcheck.plan import PlanError, plan_from_dict


def test_parse_duration():
    assert parse_duration("1d2h") == 93600
    assert parse_duration("90m") == 5400
    assert parse_duration("-30m") == -1800
    assert parse_duration(45) == 45
    assert parse_duration("0") == 0
    with pytest.raises(ValueError):
        parse_duration("2 days")


def minimal(**overrides):
    data = {
        "keys": {"KSK": {"role": "ksk"}, "ZSK": {"role": "zsk"}},
        "initial": {
            "ds": {"keys": ["KSK"]},
            "dnskey": {"keys": ["KSK", "ZSK"], "signed_by": ["KSK"]},
            "data": {"www": {"signed_by": ["ZSK"]}},
        },
        "steps": [{"at": "1h", "dnskey": {"ttl": "5m"}}],
    }
    data.update(overrides)
    return data


def test_minimal_plan_loads():
    plan = plan_from_dict(minimal())
    assert plan.zone == "bank.test."
    assert plan.data_names == ["www"]
    assert plan.steps[0].at == 3600


def test_unknown_key_is_rejected():
    data = minimal(steps=[{"at": "1h", "dnskey": {"keys": ["NOPE"]}}])
    with pytest.raises(PlanError, match="unknown key"):
        plan_from_dict(data)
