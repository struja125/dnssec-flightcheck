"""Reports and exit codes tell prediction, observation and recovery apart. All samples are written by hand."""


from flightcheck.lab.comparison import AGREEMENT, EXIT_INCONCLUSIVE, EXIT_INVALID_RUN, EXIT_OPERATIONAL, EXIT_UNDERPREDICTION, INCONCLUSIVE, OVERPREDICTION, UNDERPREDICTION, compare, run_outcome
from flightcheck.lab.network import LabConfig, Sample, summarise
from flightcheck.plan import load_plan

from .conftest import SCENARIOS

H = 3600
WWW, MAIL = "www.bank.test.", "mail.bank.test."
RAW, BOUND = [(100.0, 200.0)], [(100.0, 300.0)]


def ok(t, resolver="r-0", name=WWW):
    return Sample(t, resolver, name, "secure", "NOERROR", [])


def bad(t, resolver="r-0", name=WWW):
    return Sample(t, resolver, name, "bogus", "SERVFAIL", [])


def always(sample):
    return sample.status == "secure"


def small(samples, raw=RAW, bound=BOUND, **options):
    return compare(samples, raw, bound, always, **{"max_gap": 10, **options})


def steady(low, high, make=ok):
    return [make(t) for t in range(low, high, 5)]


def ksk():
    return load_plan(SCENARIOS / "ksk-double-ds-bad.yaml")


def config(scale=600):
    return LabConfig(start_wall=0, scale=scale, t_begin=-24 * H, t_end=60 * H)


def measured_run(label):
    """Failures through most of the KSK mismatch (T+2h to T+1d 1h), then answers."""
    return (
        [ok(t, label) for t in range(-H, 3 * H, 600)]
        + [bad(t, label) for t in range(3 * H, 25 * H, 600)]
        + [ok(t, label) for t in range(25 * H, 50 * H, 600)]
    )


def probe_code(samples, label="unbound"):
    data = summarise(ksk(), config(), {label: "ip"}, samples, 0.25)["per_resolver"][label]
    return run_outcome({label: data["comparison"][data["model"]]})[0]


# ---- F10: categories


def test_failures_inside_the_window_agree():
    assert small(steady(0, 120) + steady(120, 200, bad) + steady(200, 400))["classification"] == AGREEMENT


def test_well_observed_risk_without_failures_is_overprediction():
    assert small(steady(0, 400))["classification"] == OVERPREDICTION


def test_failure_outside_the_window_is_underprediction():
    assert small(steady(0, 90) + [bad(90)] + steady(95, 400))["classification"] == UNDERPREDICTION


def test_truncated_recording_is_inconclusive():
    result = small(steady(0, 150))
    assert result["classification"] == INCONCLUSIVE and result["recording_ended_inside_a_window"]


# ---- F9: exit codes


def test_servfail_outside_the_window_fails_the_probe():
    assert probe_code([ok(0, "unbound"), bad(55 * H, "unbound"), ok(56 * H, "unbound")]) == EXIT_UNDERPREDICTION


def test_no_answers_at_all_is_an_operational_failure():
    assert probe_code([Sample(0, "unbound", WWW, "error", "TIMEOUT", [])]) == EXIT_OPERATIONAL


def test_nxdomain_means_the_run_does_not_count():
    assert probe_code([ok(-H, "unbound"), Sample(0, "unbound", WWW, "error", "NXDOMAIN", [])]) == EXIT_INVALID_RUN


def test_recovery_not_seen_is_inconclusive():
    samples = [s for s in measured_run("unbound") if s.t < 25 * H]
    assert probe_code(samples) == EXIT_INCONCLUSIVE
