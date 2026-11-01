"""Compare what resolvers answered with what was predicted. Works on recorded samples and given windows only.

Times are plan seconds relative to T+0, on every clock. One real second is ``scale`` plan seconds.

A predicted window says a failure *can* happen, so a window without a failure is not a model error. Only a
validation failure outside every window contradicts the prediction. The thresholds below describe one
recording, and they are not statistics: samples are few, and those of one resolver depend on each other.
"""

from __future__ import annotations

import math

from ..durations import format_offset
from ..timeline import build_timelines
from .resolver import BOGUS, INSECURE, SECURE

AGREEMENT = "observed_agreement"  # failures inside the windows, and none outside
OVERPREDICTION = "overprediction"  # well observed, but no failure, or failures over a much shorter period
UNDERPREDICTION = "underprediction"  # validation failures outside the windows
INCONCLUSIVE = "inconclusive"  # the recording does not say
NO_FAILURES = "no_failures_expected_or_observed"

RECOVERED = "recovered"
RECOVERY_NOT_OBSERVED = "recovery_not_observed"
NOTHING_TO_RECOVER = "no_failures"

MIN_COVERAGE = 0.9  # share of the raw mismatch that has to be recorded to call a window observed
WIDE_RATIO = 0.5  # failures over less than this share of the raw mismatch: the window was much wider

# Exit codes of probe and real-lab. These are not the codes of check and fix, which judge a plan:
# here an unsafe plan whose failures were predicted is a good result.
EXIT_OK, EXIT_UNDERPREDICTION, EXIT_OPERATIONAL, EXIT_INVALID_RUN, EXIT_INCONCLUSIVE = 0, 1, 2, 3, 4

EXPLANATIONS = {
    AGREEMENT: "failures occurred inside the predicted windows, and none outside",
    OVERPREDICTION: "the windows were observed, but failures were absent or much shorter; a window is a risk, not a promise",
    UNDERPREDICTION: "validation failures occurred outside every predicted window",
    INCONCLUSIVE: "the recording does not cover enough of the predicted windows to say",
    NO_FAILURES: "no failure was predicted and none was seen",
}


def _finite(value):
    return None if value is None or math.isinf(value) else value


def _pair(window) -> list:
    return [_finite(window[0]), _finite(window[1])]


def _is_failure(sample) -> bool:
    return sample.status == BOGUS or getattr(sample, "rcode", "") == "TIMEOUT"


def _is_timeout(sample) -> bool:
    return getattr(sample, "rcode", "") == "TIMEOUT"


def validated_answer_rule(plan, tolerance: float = 0):
    """Which answers prove a resolver works: a validated one, or an unvalidated one only while it can be right.

    A resolver can answer without validation while a copy of "no DS" is cached, and for one data TTL after that."""
    timelines = build_timelines(plan)
    data_ttl = max(v.ttl for rrset, versions in timelines.items() if rrset != "ds" and rrset != "dnskey" for v in versions)
    no_ds = [v for v in timelines["ds"] if not v.state.keys]

    def qualifies(sample) -> bool:
        if sample.status == SECURE:
            return True
        if sample.status != INSECURE:
            return False
        return any(v.publish <= sample.t < v.cache_end + data_ttl + tolerance for v in no_ds)

    return qualifies


def series_recovery(samples, qualifies) -> dict:
    """One resolver and one name. The recovery is sustained: the first qualifying answer after the *last* failure.

    The real moment lies between the last failure and that answer, so both are reported. Earlier recoveries
    of an intermittent failure only count as ``episodes``."""
    items = sorted(samples, key=lambda s: s.t)
    failed = [s.t for s in items if _is_failure(s)]
    episodes = 0
    failing = False
    for sample in items:
        if _is_failure(sample):
            failing = True
        elif failing and qualifies(sample):
            failing = False
            episodes += 1
    if not failed:
        return {"status": NOTHING_TO_RECOVER, "last_failure": None, "recovered_at": None, "episodes": 0}
    answered = [s.t for s in items if s.t > failed[-1] and qualifies(s)]
    return {
        "status": RECOVERED if answered else RECOVERY_NOT_OBSERVED,
        "last_failure": failed[-1],
        "recovered_at": answered[0] if answered else None,
        "episodes": episodes,
    }


def _covered(samples, max_gap: float) -> list[tuple[float, float]]:
    """The time a resolver and name were really being watched: between lookups that are not too far apart."""
    spans = []
    for current, following in zip(samples, samples[1:]):
        if following.t - current.t <= max_gap:
            spans.append((current.t, following.t))
    return spans


def _union(spans: list[tuple[float, float]]) -> list[tuple[float, float]]:
    merged: list[list[float]] = []
    for low, high in sorted(spans):
        if merged and low <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return [(low, high) for low, high in merged]


def _overlap(first, second) -> float:
    total = 0.0
    for a1, b1 in first:
        for a2, b2 in second:
            total += max(0.0, min(b1, b2) - max(a1, a2))
    return total


def _classify(samples, inside, outside, timeouts_outside, raw_windows, bound_windows, coverage) -> str:
    if not samples:
        return INCONCLUSIVE
    if outside:
        return UNDERPREDICTION
    if timeouts_outside:
        return INCONCLUSIVE  # a lookup without an answer is not a validation failure
    if not bound_windows:
        return NO_FAILURES
    well_seen = coverage is not None and coverage >= MIN_COVERAGE
    if inside:
        raw_length = sum(b - a for a, b in raw_windows)
        failing_for = inside[-1].t - inside[0].t
        much_wider = not math.isinf(raw_length) and raw_length > 0 and failing_for < WIDE_RATIO * raw_length
        return OVERPREDICTION if well_seen and much_wider else AGREEMENT
    # Coverage only counts the recorded part, so a recording that stopped early cannot call a window quiet.
    stopped_early = any(b > samples[-1].t for _, b in raw_windows if not math.isinf(b))
    return OVERPREDICTION if well_seen and not stopped_early else INCONCLUSIVE


def compare(samples, raw_windows, bound_windows, qualifies, tolerance: float = 0, max_gap: float = math.inf) -> dict:
    """``raw_windows``: when the records can really mismatch. ``bound_windows``: the same with the resolver's
    timers, the latest it can still fail. ``tolerance``: sampling and clock granularity, in plan seconds."""
    samples = sorted(samples, key=lambda s: s.t)
    series: dict[tuple, list] = {}
    for sample in samples:
        series.setdefault((str(sample.resolver), sample.name), []).append(sample)
    start = samples[0].t if samples else None
    end = samples[-1].t if samples else None

    def in_bound(t) -> bool:
        return any(a <= t <= b + tolerance for a, b in bound_windows)

    rows = []
    covered = []
    for (resolver, name), items in series.items():
        failed = [s for s in items if _is_failure(s)]
        rows.append(
            {
                "resolver": resolver,
                "name": name,
                "queries": len(items),
                "servfail": sum(1 for s in failed if not _is_timeout(s)),
                "timeouts": sum(1 for s in failed if _is_timeout(s)),
                "inside": sum(1 for s in failed if in_bound(s.t)),
                "outside": sum(1 for s in failed if not in_bound(s.t)),
                "first_failure": failed[0].t if failed else None,
                **series_recovery(items, qualifies),
            }
        )
        covered += _covered(items, max_gap)
    covered = _union(covered)

    failures = [s for s in samples if _is_failure(s)]
    outside = [s for s in failures if s.status == BOGUS and not in_bound(s.t)]
    timeouts_outside = [s for s in failures if _is_timeout(s) and not in_bound(s.t)]
    inside = [s for s in failures if in_bound(s.t)]

    windows = []
    relevant_total = relevant_covered = 0.0
    for a, b in bound_windows:
        spans = []
        for low, high in raw_windows:
            if samples and max(low, a) < min(high, b):
                spans.append((max(low, a, start), min(high, b, end)))
        spans = [(low, high) for low, high in spans if low < high]
        length = sum(high - low for low, high in spans)
        seen = _overlap(spans, covered)
        relevant_total += length
        relevant_covered += seen
        windows.append(
            {
                "bound": _pair((a, b)),
                "failures": sum(1 for s in failures if a <= s.t <= b + tolerance),
                "coverage": seen / length if length else 0.0,
            }
        )
    coverage = relevant_covered / relevant_total if relevant_total else None
    answered = sum(1 for s in samples if s.status in (SECURE, INSECURE))
    open_ended = any(math.isinf(b) for _, b in bound_windows)
    truncated = bool(samples) and any(b > end for _, b in bound_windows)

    classification = _classify(samples, inside, outside, timeouts_outside, raw_windows, bound_windows, coverage)

    failing = [row for row in rows if row["status"] != NOTHING_TO_RECOVER]
    recovered = [row["recovered_at"] for row in failing if row["status"] == RECOVERED]
    if not failing:
        recovery = NOTHING_TO_RECOVER
    elif len(recovered) == len(failing):
        recovery = RECOVERED
    else:
        recovery = RECOVERY_NOT_OBSERVED

    return {
        "classification": classification,
        "explanation": EXPLANATIONS[classification],
        "timeline": {
            "units": "plan seconds relative to T+0",
            "observation_start": start,
            "observation_end": end,
            "first_possible_mismatch": _finite(raw_windows[0][0]) if raw_windows else None,
            "first_failure": failures[0].t if failures else None,
            "last_failure": failures[-1].t if failures else None,
            "first_recovery": min(recovered) if recovered else None,
            "last_recovery": max(recovered) if recovered else None,
        },
        "raw_windows": [_pair(w) for w in raw_windows],
        "bound_windows": [_pair(w) for w in bound_windows],
        "queries": len(samples),
        "answered": answered,
        "servfail": sum(1 for s in failures if not _is_timeout(s)),
        "timeouts": sum(1 for s in failures if _is_timeout(s)),
        "inside": len(inside),
        "outside": len(outside),
        "timeouts_outside": len(timeouts_outside),
        "windows": windows,
        "windows_with_failures": sum(1 for w in windows if w["failures"]),
        "windows_without_failures": sum(1 for w in windows if not w["failures"]),
        "coverage": coverage,
        "open_ended": open_ended,
        "recording_ended_inside_a_window": truncated,
        "unexpected_insecure": sum(1 for s in samples if s.status == INSECURE and not qualifies(s)),
        "other_answers": sum(1 for s in samples if s.status not in (SECURE, INSECURE, BOGUS) and not _is_timeout(s)),
        "recovery": recovery,
        "series": rows,
    }


def run_outcome(comparisons: dict[str, dict]) -> tuple[int, str]:
    """The exit code and the reason for a whole run, given the comparison of each resolver."""
    if not comparisons or all(not c["answered"] and not c["servfail"] for c in comparisons.values()):
        return EXIT_OPERATIONAL, "no resolver answered: the run itself did not work"
    invalid = [n for n, c in comparisons.items() if c["unexpected_insecure"] or c["other_answers"] or not c["answered"]]
    if invalid:
        return EXIT_INVALID_RUN, f"the run does not count: {', '.join(invalid)} did not validate as the lab requires"
    under = [n for n, c in comparisons.items() if c["classification"] == UNDERPREDICTION]
    if under:
        return EXIT_UNDERPREDICTION, f"unexpected SERVFAIL outside the predicted windows: {', '.join(under)}"
    open_questions = [n for n, c in comparisons.items() if c["classification"] == INCONCLUSIVE]
    if open_questions:
        return EXIT_INCONCLUSIVE, f"the recording does not settle the comparison: {', '.join(open_questions)}"
    not_seen = [n for n, c in comparisons.items() if c["recovery"] == RECOVERY_NOT_OBSERVED and not c["open_ended"]]
    if not_seen:
        return EXIT_INCONCLUSIVE, f"recovery was expected but not observed: {', '.join(not_seen)}"
    return EXIT_OK, "the resolvers do not contradict the prediction"


def provenance_lines(plan) -> list[str]:
    """What a run of a plan from a snapshot does and does not show. Passing here never widens the plan's coverage."""
    if plan.coverage is None:
        return []
    provenance = plan.source["provenance"]
    snapshot = provenance.get("snapshot", {})
    lines = [
        f"Evidence: coverage {plan.coverage}; snapshot of {snapshot.get('collected_at', 'unknown time')} "
        f"({(snapshot.get('completeness') or {}).get('status', 'unknown')}); operator's assumptions: {provenance.get('assumptions', 'none')}",
        "This lab uses synthetic keys and signatures. Observed RRsets are reproduced by name and TTL as A records; "
        "planned keys are placeholders. It shows how validators treat this schedule, not how the production zone will behave.",
    ]
    if plan.coverage == "sampled":
        lines.append(f"Not reproduced: {provenance.get('unobserved', 'the rest of the zone')}. This does not make the plan safe for the whole zone.")
    return lines


def provenance_row(plan) -> list[tuple]:
    """The same for the summary of an HTML report."""
    lines = provenance_lines(plan)
    return [("evidence", plan.coverage, " ".join(lines))] if lines else []


def _windows_text(windows) -> str:
    if not windows:
        return "none"
    return ", ".join(f"{format_offset(a if a is not None else -math.inf)} -> {format_offset(b if b is not None else math.inf)}" for a, b in windows)


def comparison_lines(comparison: dict, indent: str = "  ") -> list[str]:
    timeline = comparison["timeline"]
    coverage = "no raw window" if comparison["coverage"] is None else f"{comparison['coverage']:.0%} of the raw windows"
    lines = [
        f"comparison: {comparison['classification']}: {comparison['explanation']}",
        f"predicted mismatch (raw): {_windows_text(comparison['raw_windows'])}",
        f"latest possible failure (upper bound with resolver timers, not a predicted duration): {_windows_text(comparison['bound_windows'])}",
        (
            f"observed: {comparison['queries']} queries, {comparison['servfail']} SERVFAIL, {comparison['timeouts']} timeouts, "
            f"{comparison['inside']} inside and {comparison['outside']} SERVFAIL outside the bound"
        ),
        (
            f"windows with failures {comparison['windows_with_failures']}, without {comparison['windows_without_failures']}; "
            f"recorded {coverage}"
        ),
    ]
    if comparison["recording_ended_inside_a_window"]:
        lines.append("the recording ended before the upper bound")
    if timeline["first_failure"] is not None:
        lines.append(f"first failure {format_offset(timeline['first_failure'])}, last {format_offset(timeline['last_failure'])}")
    for row in comparison["series"]:
        if row["status"] == NOTHING_TO_RECOVER:
            continue
        where = f"{row['resolver']} {row['name']}"
        if row["status"] == RECOVERED:
            lines.append(
                f"{where}: recovered between {format_offset(row['last_failure'])} and {format_offset(row['recovered_at'])} "
                f"(sustained; {row['episodes']} recoveries in total)"
            )
        else:
            lines.append(f"{where}: {RECOVERY_NOT_OBSERVED} after the last failure at {format_offset(row['last_failure'])}")
    return [indent + line for line in lines]
