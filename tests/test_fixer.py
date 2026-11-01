
from flightcheck.fixer import fix_plan
from flightcheck.plan import MODELS

from .conftest import scenario_names

H = 3600


def test_every_bad_plan_gets_a_safe_schedule(scenario):
    for name in scenario_names("bad"):
        for model in MODELS:
            fix = fix_plan(scenario(name), model)
            assert fix.fixable and fix.fixed_result.ok, (name, model)


def test_ksk_swap_earliest_time_is_exact(scenario):
    fix = fix_plan(scenario("ksk-double-ds-bad"), "conservative")
    swap = fix.advice[1]
    assert swap.earliest == 25 * H  # registry delay 1h + DS TTL 1d
    assert swap.recommended == 26 * H  # + 1h margin
    remove_ds = fix.advice[2]
    # the old DNSKEY RRset (TTL 1h, 5m propagation) must expire before the new DS appears (1h registry delay)
    assert remove_ds.earliest == 26 * H + 300


def test_conflicting_step_is_split(scenario):
    fix = fix_plan(scenario("go-insecure-bad"), "conservative")
    assert fix.splits and "DNSKEY" in fix.splits[0]
    names = [step.name for step in fix.fixed_plan.ordered_steps()]
    assert names == ["Remove the DS and unsign the zone", "Remove the DS and unsign the zone (part 2)"]
    second = fix.fixed_plan.ordered_steps()[1]
    assert second.at == 26 * H  # registry 1h + DS TTL 1d + margin 1h
