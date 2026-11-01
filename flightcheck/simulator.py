"""Worst-case simulation of what validating resolvers see while a plan is executed.

Two resolver models are supported:

``conservative`` (default, the RFC 7583 assumption)
    Any combination of versions that can be cached at the same moment may be validated together.
    This covers validators behind a non-validating cache (forwarders, CPEs, stub validators) and
    resolvers that re-validate cached data.

``fetch``
    A single validating resolver that validates an RRset when it fetches it and then trusts the
    cached result. The RRset being fetched has to be served at that moment; what it is validated
    against (DS, DNSKEY) can be any version still in the cache.

Time is cut at every moment where the set of possible versions changes, so the result is exact
rather than sampled.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .durations import format_duration, format_offset, format_time
from .plan import DATA_PREFIX, DNSKEY, DS, Plan
from .timeline import Version, build_timelines, plan_end, rrset_label
from .validate import BOGUS, INSECURE, SECURE, check_data, check_dnskey

STATUS_SECURE = "secure"
STATUS_PARTLY_INSECURE = "partly-insecure"
STATUS_INSECURE = "insecure"
STATUS_BOGUS = "bogus"
STATUS_RECOVERING = "recovering"  # the zone validates again, but resolvers still remember the failure


@dataclass
class Failure:
    kind: str  # "dnskey" or "data"
    rrset: str  # the RRset that fails to validate
    reference: Version  # what it is validated against (a DS or DNSKEY version)
    target: Version  # the version that fails to validate
    reason: str
    intervals: list[list[float]] = field(default_factory=list)
    memory: float = 0  # how long resolvers keep this failure, in plan seconds

    @property
    def versions(self) -> tuple[Version, Version]:
        return (self.reference, self.target)

    @property
    def start(self) -> float:
        return self.intervals[0][0]

    @property
    def end(self) -> float:
        return self.intervals[-1][1]

    @property
    def impact_end(self) -> float:
        """End of the outage including the time resolvers keep the bogus result cached."""
        return self.end + self.memory

    @property
    def duration(self) -> float:
        return sum(end - start for start, end in self.intervals)

    @property
    def newer(self) -> Version:
        return max(self.versions, key=lambda v: v.publish)

    @property
    def older(self) -> Version:
        return min(self.versions, key=lambda v: v.publish)

    def explain(self, plan: Plan) -> str:
        fmt = lambda t: format_time(t, plan.start)  # noqa: E731
        reference, target = self.reference, self.target
        what = rrset_label(self.rrset)
        if target is reference:
            return f"{what} ({target.label}) becomes bogus: {self.reason}."
        if target.publish == reference.publish:
            story = (
                f"From {fmt(target.publish)} the zone serves {target.label} together with "
                f"{reference.label} (step \"{target.step}\")"
            )
        elif target.publish > reference.publish:
            story = (
                f"From {fmt(target.publish)} the zone serves {target.label} (step \"{target.step}\"), "
                f"but resolvers may still hold {reference.label} in their cache until "
                f"{fmt(reference.cache_end)}"
            )
        else:
            story = (
                f"Resolvers may still hold {target.label} in their cache until {fmt(target.cache_end)}, "
                f"but from {fmt(reference.publish)} they validate it against {reference.label} "
                f"(step \"{reference.step}\")"
            )
        text = f"{story}. {what} becomes bogus: {self.reason}."
        if self.memory:
            text += f" Resolvers can keep answering SERVFAIL for up to {format_duration(self.memory)} after that."
        return text


@dataclass
class Segment:
    start: float
    end: float
    status: str
    failure_ids: tuple[int, ...] = ()


@dataclass
class Lint:
    step: str
    severity: str  # "warning" or "info"
    message: str


@dataclass(frozen=True)
class Finding:
    """Something wrong with the state a plan ends in, which no change of timing can repair."""

    code: str
    message: str
    missing: str  # the operation the plan would need


@dataclass
class Result:
    plan: Plan
    model: str
    timelines: dict[str, list[Version]]
    segments: list[Segment]
    failures: list[Failure]
    lints: list[Lint]
    label: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """No moment of the plan can give a bogus answer. This says nothing about where the plan ends: see ``safe``."""
        return not self.failures

    @property
    def safe(self) -> bool:
        return self.ok and not self.findings

    @property
    def safe_for_whole_zone(self) -> bool:
        return self.safe and self.plan.coverage != "sampled"

    @property
    def final_status(self) -> str:
        return self.segments[-1].status if self.segments else STATUS_SECURE

    @property
    def outage_time(self) -> float:
        """Total time during which at least one resolver can answer SERVFAIL."""
        return sum(end - start for start, end in self.failure_windows())

    @property
    def broken_time(self) -> float:
        """Total time during which the data itself cannot be validated, without failure memory."""
        return sum(s.end - s.start for s in self.segments if s.status == STATUS_BOGUS)

    def failure_windows(self) -> list[tuple[float, float]]:
        """Merged periods in which at least one resolver can answer SERVFAIL."""
        windows: list[tuple[float, float]] = []
        for segment in self.segments:
            if segment.status not in (STATUS_BOGUS, STATUS_RECOVERING):
                continue
            if windows and windows[-1][1] == segment.start:
                windows[-1] = (windows[-1][0], segment.end)
            else:
                windows.append((segment.start, segment.end))
        return windows

    def view_range(self) -> tuple[float, float]:
        """A sensible time window for showing this result."""
        finite = [
            t
            for versions in self.timelines.values()
            for v in versions
            for t in (v.publish, v.withdraw, v.cache_end)
            if not math.isinf(t)
        ]
        finite += [end for _, end in self.failure_windows() if not math.isinf(end)]
        steps = [step.at for step in self.plan.steps]
        if not finite and not steps:
            return (0.0, 3600.0)
        low = min(steps + finite)
        high = max(steps + finite)
        span = max(high - low, 3600)
        return (low - 0.06 * span, high + 0.08 * span)


def simulate(plan: Plan, model: str | None = None, memory_scale: float = 1) -> Result:
    """Simulate a plan. ``memory_scale`` multiplies the resolvers' failure memory: their timers run in
    real seconds, so on a clock compressed N times they last N times longer in plan time."""
    model = model or plan.model
    timelines = build_timelines(plan)
    signature_times = {
        t for versions in timelines.values() for v in versions for times in v.state.rrsig.values() for t in times if t is not None
    }
    boundaries = sorted(
        signature_times
        | {
            t
            for versions in timelines.values()
            for v in versions
            for t in (v.publish, v.withdraw, v.cache_end)
            if not math.isinf(t)
        }
    )

    if boundaries:
        points = [(-math.inf, boundaries[0])] + [
            (boundaries[i], boundaries[i + 1] if i + 1 < len(boundaries) else math.inf)
            for i in range(len(boundaries))
        ]
    else:
        points = [(-math.inf, math.inf)]

    failures: dict[tuple, Failure] = {}
    raw_segments: list[Segment] = []
    for start, end in points:
        if math.isinf(start):
            probe = end - 1 if not math.isinf(end) else 0.0
        else:
            probe = start
        status, failure_keys = _evaluate(plan, timelines, probe, model, failures)
        ids = tuple(sorted(failure_keys))
        if raw_segments and raw_segments[-1].status == status and raw_segments[-1].failure_ids == ids:
            raw_segments[-1].end = end
        else:
            raw_segments.append(Segment(start, end, status, ids))
        for key in failure_keys:
            intervals = failures[key].intervals
            if intervals and intervals[-1][1] == start:
                intervals[-1][1] = end
            else:
                intervals.append([start, end])

    ordered = sorted(failures.values(), key=lambda f: (f.start, f.rrset))
    index_of = {id(f): i for i, f in enumerate(ordered)}
    key_index = {key: index_of[id(f)] for key, f in failures.items()}
    for segment in raw_segments:
        segment.failure_ids = tuple(sorted(key_index[k] for k in segment.failure_ids))
    for failure in ordered:
        # A failed answer is kept for the answer timer. A failed chain of trust is kept for the key timer,
        # and an answer that fails against it at the last moment is then kept for the answer timer. A failed
        # answer never starts a key timer, so the two only add up in this order. This is an upper bound.
        seconds = plan.bogus_ttl + (plan.key_failure_ttl if failure.kind == "dnskey" else 0)
        failure.memory = seconds * memory_scale

    return Result(plan, model, timelines, _with_memory(raw_segments, ordered), ordered, lint(plan), findings=final_findings(plan))


def _with_memory(segments: list[Segment], failures: list[Failure]) -> list[Segment]:
    """Mark the time after each failure during which resolvers still remember it."""
    tails = [
        (end, end + failure.memory, index)
        for index, failure in enumerate(failures)
        for _, end in failure.intervals
        if failure.memory and not math.isinf(end)
    ]
    if not tails:
        return segments
    cuts = sorted({s.start for s in segments} | {s.end for s in segments} | {t for a, b, _ in tails for t in (a, b)})
    result: list[Segment] = []
    for start, end in zip(cuts, cuts[1:]):
        base = next(s for s in segments if s.start <= start < s.end)
        status, ids = base.status, base.failure_ids
        if status != STATUS_BOGUS:
            remembered = tuple(sorted(index for a, b, index in tails if a <= start < b))
            if remembered:
                status, ids = STATUS_RECOVERING, remembered
        if result and result[-1].status == status and result[-1].failure_ids == ids:
            result[-1].end = end
        else:
            result.append(Segment(start, end, status, ids))
    return result


def _evaluate(plan: Plan, timelines, t: float, model: str, failures: dict) -> tuple[str, set]:
    keys = plan.keys
    strict = plan.strict_algorithms
    ds_versions = timelines[DS]
    dnskey_versions = timelines[DNSKEY]
    data_rrsets = [r for r in timelines if r.startswith(DATA_PREFIX)]

    cached_ds = [v for v in ds_versions if v.cacheable_at(t)]
    cached_dnskey = [v for v in dnskey_versions if v.cacheable_at(t)]
    fetched_dnskey = [v for v in dnskey_versions if v.served_at(t)]

    found: set = set()
    seen = set()

    def record(kind, rrset, reference, target, reason):
        key = (kind, rrset, (reference.rrset, reference.index), target.index, reason)
        if key not in failures:
            failures[key] = Failure(kind, rrset, reference, target, reason)
        found.add(key)

    # DS -> DNSKEY
    dnskey_candidates = cached_dnskey if model == "conservative" else fetched_dnskey
    for ds in cached_ds:
        for dnskey in dnskey_candidates:
            verdict = check_dnskey(ds.state, dnskey.state, keys, strict, t)
            seen.add(verdict.status)
            if verdict.status == BOGUS:
                # An expired signature is the RRset's own problem, not caused by the DS version it met.
                record("dnskey", DNSKEY, dnskey if verdict.signature_time else ds, dnskey, verdict.reason)

    # DNSKEY -> data
    for rrset in data_rrsets:
        versions = timelines[rrset]
        if model == "conservative":
            data_candidates = [v for v in versions if v.cacheable_at(t)]
        else:
            data_candidates = [v for v in versions if v.served_at(t)]
        for ds in cached_ds:
            for dnskey in cached_dnskey:
                if model == "conservative":
                    if check_dnskey(ds.state, dnskey.state, keys, strict, t).status != SECURE:
                        continue
                elif not _trustable(dnskey, ds_versions, t, keys, strict):
                    continue
                for data in data_candidates:
                    verdict = check_data(ds.state, dnskey.state, data.state, keys, strict, t)
                    seen.add(verdict.status)
                    if verdict.status == BOGUS:
                        reference = ds if verdict.against == "ds" else dnskey
                        record("data", rrset, data if verdict.signature_time else reference, data, verdict.reason)
            if not ds.state.keys:
                seen.add(INSECURE)

    if found:
        return STATUS_BOGUS, found
    if INSECURE in seen and SECURE in seen:
        return STATUS_PARTLY_INSECURE, found
    if INSECURE in seen and SECURE not in seen:
        return STATUS_INSECURE, found
    return STATUS_SECURE, found


def _trustable(dnskey: Version, ds_versions: list[Version], t: float, keys, strict) -> bool:
    """Fetch model: could this DNSKEY version have been fetched, validated and still be cached at t?"""
    for ds in ds_versions:
        # Resolvers do not keep a validated RRset past the end of its signatures, so it must be valid now.
        if check_dnskey(ds.state, dnskey.state, keys, strict, t).status != SECURE:
            continue
        low = max(ds.publish, dnskey.publish, t - dnskey.ttl)
        high = min(ds.cache_end, dnskey.withdraw)
        if low >= high or low > t:
            continue
        # It must also have been valid when it was fetched, at the latest moment that was possible.
        fetched_at = t if t < high else high - 1
        if check_dnskey(ds.state, dnskey.state, keys, strict, fetched_at).status == SECURE:
            return True
    return False


# ---------------------------------------------------------------------------
# The state the plan ends in
#
# Validation only needs one working path, so a plan can never produce a bogus answer and still end in
# a state nobody would choose: a DS for a key that was never published, a key that was never put to
# use. Every intermediate state of a rollover looks like that for a while, which is why these checks
# look at the final state only.


def final_findings(plan: Plan) -> list[Finding]:
    from .plan import apply_change

    state = dict(plan.initial)
    for step in plan.ordered_steps():
        for rrset, change in step.changes.items():
            state[rrset] = apply_change(state[rrset], change)

    keys = plan.keys
    ds, dnskey = state[DS], state[DNSKEY]
    data = {rrset: value for rrset, value in state.items() if rrset.startswith(DATA_PREFIX)}
    signers = dnskey.signed_by.union(*(value.signed_by for value in data.values()))
    initial_signers = plan.initial[DNSKEY].signed_by.union(
        *(value.signed_by for rrset, value in plan.initial.items() if rrset.startswith(DATA_PREFIX))
    )
    found: list[Finding] = []

    def add(code, message, missing):
        found.append(Finding(code, message, missing))

    for name in sorted(ds.keys - dnskey.keys):
        if not keys[name].standby:
            add(
                "ds-without-dnskey",
                f"the plan ends with a DS for {name}, which is not in the DNSKEY RRset",
                f"publish {name} in the DNSKEY RRset and sign it, or remove its DS",
            )
    for name in sorted((ds.keys & dnskey.keys) - dnskey.signed_by):
        if not keys[name].standby:
            add(
                "ds-key-not-signing",
                f"the plan ends with a DS for {name}, but {name} does not sign the DNSKEY RRset",
                f"sign the DNSKEY RRset with {name}, or remove its DS",
            )
    for name in sorted(dnskey.signed_by - dnskey.keys):
        add(
            "signature-without-key",
            f"the DNSKEY RRset ends with an RRSIG by {name}, which is not published",
            f"publish {name}, or stop signing the DNSKEY RRset with it",
        )
    for rrset, value in data.items():
        for name in sorted(value.signed_by - dnskey.keys):
            add(
                "signature-without-key",
                f"{rrset_label(rrset)} ends with an RRSIG by {name}, which is not published",
                f"publish {name}, or stop signing {rrset_label(rrset)} with it",
            )
    for name in sorted(dnskey.keys - signers):
        if keys[name].standby:
            continue
        if name not in plan.initial[DNSKEY].keys:
            add(
                "key-never-used",
                f"{name} is published by the plan but signs nothing when it ends",
                f"sign with {name}, remove it, or mark it 'standby: true' if it is kept ready on purpose",
            )
        elif name in initial_signers:
            add(
                "key-not-removed",
                f"{name} no longer signs anything when the plan ends, but it stays published",
                f"remove {name} from the DNSKEY RRset, or mark it 'standby: true' if it is kept ready on purpose",
            )

    # RFC 4035 section 2.2 binds the signer. Validators need not enforce it (RFC 6840 section 5.11), so
    # during a change it stays a warning, see lint(). A zone must not end up violating it.
    algorithms = {keys[name].algorithm for name in dnskey.keys}
    dnskey_algorithms = {keys[name].algorithm for name in dnskey.signed_by & dnskey.keys}
    for algorithm in sorted({keys[name].algorithm for name in ds.keys} - dnskey_algorithms):
        add(
            "algorithm-rule",
            f"the DS RRset has algorithm {algorithm}, but the final DNSKEY RRset has no signature of that "
            "algorithm (RFC 4035 section 2.2)",
            f"sign the DNSKEY RRset with an algorithm {algorithm} key, or remove the DS",
        )
    for algorithm in sorted(algorithms - dnskey_algorithms):
        add(
            "algorithm-rule",
            f"the final DNSKEY RRset has algorithm {algorithm} keys but no signature of that algorithm "
            "(RFC 4035 section 2.2)",
            f"sign the DNSKEY RRset with an algorithm {algorithm} key, or remove those keys",
        )
    for rrset, value in data.items():
        for algorithm in sorted(algorithms - {keys[name].algorithm for name in value.signed_by}):
            add(
                "algorithm-rule",
                f"{rrset_label(rrset)} ends without a signature of algorithm {algorithm}, although the DNSKEY "
                "RRset has keys of that algorithm (RFC 4035 section 2.2)",
                f"sign {rrset_label(rrset)} with an algorithm {algorithm} key, or remove those keys",
            )

    # A zone can stay signed without a DS, but a plan that goes there has stopped half way.
    if not ds.keys and dnskey.keys and state != plan.initial:
        add(
            "signed-without-ds",
            "the plan ends with a signed zone and no DS, so validators treat it as insecure",
            "submit the DS to finish going secure, or remove the keys and signatures to finish going insecure",
        )
    return found


# ---------------------------------------------------------------------------
# Static checks on each state the plan passes through


def lint(plan: Plan) -> list[Lint]:
    from .plan import apply_change

    lints: list[Lint] = []
    state = dict(plan.initial)
    stages = [("initial state", dict(state))]
    for step in plan.ordered_steps():
        for rrset, change in step.changes.items():
            state[rrset] = apply_change(state[rrset], change)
        stages.append((step.name, dict(state)))

    reported = set()

    def add(stage, severity, message):
        if message not in reported:
            reported.add(message)
            lints.append(Lint(stage, severity, message))

    for stage, current in stages:
        ds, dnskey = current[DS], current[DNSKEY]
        for name in sorted(ds.keys):
            if plan.keys[name].role == "zsk":
                add(stage, "warning", f"the DS RRset points to {name}, which is a ZSK")
        for name in sorted(dnskey.signed_by - dnskey.keys):
            add(
                stage,
                "info",
                f"the DNSKEY RRset carries an RRSIG by {name}, which is not published yet "
                "(normal while pre-signing for an algorithm rollover)",
            )
        algorithms = {plan.keys[name].algorithm for name in dnskey.keys}
        dnskey_algs = {plan.keys[name].algorithm for name in dnskey.signed_by & dnskey.keys}
        for algorithm in sorted(algorithms - dnskey_algs):
            add(
                stage,
                "warning",
                f"the DNSKEY RRset contains algorithm {algorithm} keys but no signature of that "
                "algorithm (RFC 4035 section 2.2)",
            )
        for rrset, data in current.items():
            if not rrset.startswith(DATA_PREFIX):
                continue
            label = rrset_label(rrset)
            data_algs = {plan.keys[name].algorithm for name in data.signed_by}
            for algorithm in sorted(algorithms - data_algs):
                add(
                    stage,
                    "warning",
                    f"{label} is not signed with algorithm {algorithm}, although the DNSKEY RRset "
                    "has keys of that algorithm (RFC 4035 section 2.2)",
                )
            if ds.keys and dnskey.keys and data.signed_by and not data.signed_by & dnskey.keys:
                add(stage, "warning", f"{label} is signed only by keys that are not published")
    end = plan_end(build_timelines(plan))
    for rrset, value in state.items():
        for signer, (_, expires) in value.rrsig.items():
            if expires is not None and expires >= end:
                add(
                    "plan",
                    "warning",
                    f"the signature of {rrset_label(rrset)} by {signer} expires at {format_offset(expires)}, after this "
                    "plan: the signer has to keep running",
                )
    if plan.margin < 0:
        lints.append(Lint("plan", "warning", "the safety margin is negative"))
    if plan.registry_delay and plan.registry_delay > 0:
        lints.append(
            Lint(
                "plan",
                "info",
                f"DS changes take effect {format_duration(plan.registry_delay)} after submission "
                "(registry delay)",
            )
        )
    return lints
