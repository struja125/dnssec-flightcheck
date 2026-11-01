"""Resolvers keep a validation failure for a while after the data has become valid."""

from flightcheck.simulator import STATUS_BOGUS, STATUS_RECOVERING, simulate

H = 3600
DAY = 86400


def statuses(result):
    return [(s.start, s.end, s.status) for s in result.segments if s.status in (STATUS_BOGUS, STATUS_RECOVERING)]


def test_failed_chain_of_trust_is_remembered(scenario):
    result = simulate(scenario("ksk-double-ds-bad"))
    assert statuses(result) == [(2 * H, 25 * H, STATUS_BOGUS), (25 * H, 25 * H + 120, STATUS_RECOVERING)]
    assert result.broken_time == 23 * H
    assert result.outage_time == 23 * H + 120
    assert result.failure_windows() == [(2 * H, 25 * H + 120)]


def test_memory_cannot_make_a_safe_plan_unsafe(scenario):
    result = simulate(scenario("ksk-double-ds-good"))
    assert result.ok and result.outage_time == 0 and not statuses(result)
