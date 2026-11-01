"""Real-resolver lab: configurations and analysis. The resolvers themselves are optional."""

import pytest

from flightcheck.lab.network import LabConfig, Sample
from flightcheck.lab.real import analyse
from flightcheck.plan import load_plan

from .conftest import SCENARIOS

H = 3600


def config() -> LabConfig:
    return LabConfig(start_wall=0, scale=600, t_begin=-24 * H, t_end=31 * H)


def sample(t, status="secure", rcode="NOERROR", resolver="unbound-0"):
    return Sample(t, resolver, "www.bank.test.", status, rcode, [])


def result_for(name, samples):
    plan = load_plan(SCENARIOS / f"{name}.yaml")
    return analyse(plan, config(), ("unbound",), 1, samples, 0.25)["results"]["unbound"]


def test_failure_inside_the_window_is_counted_inside():
    result = result_for("ksk-double-ds-bad", [sample(-H), sample(10 * H, "bogus", "SERVFAIL")])
    assert result.validated and result.failures == 1
    assert result.consistent("fetch") and result.consistent("conservative")


def test_no_ad_flag_on_a_secure_zone_invalidates_the_run():
    assert not result_for("ksk-double-ds-good", [sample(-H, "insecure")]).validated


@pytest.fixture
def lab(tmp_path):
    (tmp_path / "root.ds").write_text(". IN DS 60806 13 2 403AA89C\n", encoding="utf-8")
    (tmp_path / "root.hints").write_text(".  3600000 NS a.root-lab.\na.root-lab. 3600000 A 127.0.0.10\n", encoding="utf-8")
    return tmp_path
