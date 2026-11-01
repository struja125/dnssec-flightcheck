"""Run a plan in the lab and compare what emulated resolvers see with the simulator's prediction.

Two resolver populations are run:

* ``validating``   - validating resolvers that trust what they validated when fetching
                     (compared with the ``fetch`` model);
* ``behind-cache`` - validators behind a non-validating cache (compared with the ``conservative``
                     model, the RFC 7583 assumption).

Resolvers start at staggered moments during the longest TTL before the first step, so at the
moment of each change their caches hold data of every age, as in a real resolver population.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field, replace

from ..durations import format_duration, format_offset
from ..plan import MODELS, Plan
from ..simulator import STATUS_BOGUS, Result, simulate
from .authserver import AuthServer
from .comparison import compare, provenance_lines, validated_answer_rule
from .resolver import BOGUS, INSECURE, SECURE, Network, Resolver, Verifier, wall_clock_for
from .zones import PRIMARY_IP, ROOT_IP, SECONDARY_IP, TLD_IP, LabWorld, key_mapping

POPULATIONS = {
    "validating": {"model": "fetch", "trust_cache": True, "label": "validating resolvers"},
    "behind-cache": {"model": "conservative", "trust_cache": False, "label": "validators behind a cache"},
}


@dataclass
class Probe:
    t: float
    resolver: int
    population: str
    name: str
    status: str
    reason: str


@dataclass
class PopulationStats:
    population: str
    model: str
    label: str
    lookups: int = 0
    bogus: int = 0
    bogus_inside: int = 0
    first_bogus: float | None = None
    last_bogus: float | None = None
    predicted_seconds: float = 0.0
    observed_seconds: float = 0.0
    segments: list = field(default_factory=list)
    reasons: dict = field(default_factory=dict)
    comparison: dict = field(default_factory=dict)  # see comparison.py

    @property
    def bogus_outside(self) -> int:
        return self.bogus - self.bogus_inside

    @property
    def consistent(self) -> bool:
        return self.bogus_outside == 0

    @property
    def coverage(self) -> float | None:
        if self.predicted_seconds <= 0:
            return None
        return min(self.observed_seconds / self.predicted_seconds, 1.0)


@dataclass
class Experiment:
    plan: Plan
    predictions: dict[str, Result]
    stats: dict[str, PopulationStats]
    probes: list[Probe]
    resolvers: int
    probe_interval: int
    queries: int
    elapsed: float
    window: tuple[float, float]
    key_mapping: list = field(default_factory=list)

    @property
    def consistent(self) -> bool:
        return all(s.consistent for s in self.stats.values())

    def summary_text(self) -> str:
        plan = self.plan
        lines = [
            f"FlightCheck lab - {plan.name}",
            (
                f"{len(self.stats)} resolver populations x {self.resolvers} resolvers, a lookup every "
                f"{format_duration(self.probe_interval)} per resolver, {sum(s.lookups for s in self.stats.values()):,} "
                f"lookups, {self.queries:,} DNS queries with real signatures, {self.elapsed:.1f}s"
            ),
            f"Simulated period: {format_offset(self.window[0])} -> {format_offset(self.window[1])}",
            *provenance_lines(plan),
            "",
        ]
        for stats in self.stats.values():
            predicted = self.predictions[stats.model]
            lines.append(f"{stats.label} (compared with the {stats.model} model)")
            if predicted.ok:
                lines.append("  predicted: no failures")
            else:
                windows = ", ".join(
                    f"{format_offset(s.start)} -> {format_offset(s.end)}"
                    for s in predicted.segments
                    if s.status == STATUS_BOGUS
                )
                lines.append(f"  predicted bogus: {windows}")
            if stats.bogus:
                lines.append(
                    f"  measured: {stats.bogus:,} of {stats.lookups:,} lookups SERVFAIL, "
                    f"first {format_offset(stats.first_bogus)}, last {format_offset(stats.last_bogus)}"
                )
            else:
                lines.append(f"  measured: no SERVFAIL in {stats.lookups:,} lookups")
            mark = "yes" if stats.consistent else "NO"
            lines.append(f"  every SERVFAIL inside a predicted window: {mark} ({stats.bogus_inside}/{stats.bogus})")
            if stats.coverage is not None:
                lines.append(
                    f"  failures observed during {format_duration(stats.observed_seconds)} of the "
                    f"{format_duration(stats.predicted_seconds)} predicted ({stats.coverage:.0%})"
                )
            for reason, count in sorted(stats.reasons.items(), key=lambda item: -item[1])[:3]:
                lines.append(f"    {count:>6,} x {reason}")
            lines.append(f"  comparison: {stats.comparison['classification']}: {stats.comparison['explanation']}")
            lines.append(f"  recovery: {stats.comparison['recovery']}")
            lines.append("")
        verdict = (
            "No failure happened outside the predicted windows. A window is a risk: see the comparison above."
            if self.consistent
            else "MISMATCH: some failures happened outside the predicted windows."
        )
        lines.append(verdict)
        return "\n".join(lines) + "\n"

    def to_dict(self) -> dict:
        return {
            "plan": self.plan.name,
            "coverage": self.plan.coverage,
            "key_mapping": self.key_mapping,
            "consistent": self.consistent,
            "resolvers": self.resolvers,
            "probe_interval": self.probe_interval,
            "queries": self.queries,
            "populations": {
                name: {
                    "model": s.model,
                    "lookups": s.lookups,
                    "servfail": s.bogus,
                    "servfail_inside_prediction": s.bogus_inside,
                    "first_servfail": s.first_bogus,
                    "last_servfail": s.last_bogus,
                    "predicted_bogus_seconds": s.predicted_seconds,
                    "observed_bogus_seconds": s.observed_seconds,
                    "segments": [[a, b, st] for a, b, st in s.segments],
                    "reasons": s.reasons,
                    "comparison": s.comparison,
                }
                for name, s in self.stats.items()
            },
        }


def build_network(world: LabWorld, plan: Plan) -> Network:
    network = Network()
    network.servers[ROOT_IP] = AuthServer("root", lambda t: [world.root])
    # The parent's last server: it shows a new DS last, and keeps the old one for the whole parent_propagation.
    network.servers[TLD_IP] = AuthServer("tld", lambda t: [world.tld_at(t, plan.parent_propagation)])
    network.servers[PRIMARY_IP] = AuthServer("ns1", lambda t: [world.zone_at(t, 0)])
    network.servers[SECONDARY_IP] = AuthServer("ns2", lambda t: [world.zone_at(t, plan.propagation)])
    return network


def run_experiment(plan: Plan, resolvers: int = 24, probe_interval: int = 300, seed: int = 1) -> Experiment:
    started = time.perf_counter()
    predictions = {model: simulate(plan, model) for model in MODELS}
    wall = wall_clock_for(plan.start)
    world = LabWorld(plan, wall)
    network = build_network(world, plan)
    verifier = Verifier()
    rng = random.Random(seed)

    longest_ttl = max(
        (v.ttl for versions in predictions["conservative"].timelines.values() for v in versions), default=3600
    )
    first_step = min((s.at for s in plan.steps), default=0)
    low, high = predictions["conservative"].view_range()
    warmup_start = first_step - longest_ttl
    t_end = high
    window = (min(low, warmup_start), t_end)

    names = [f"{name}.{plan.zone}" for name in plan.data_names]
    background = None  # marks other clients' lookups: they refresh DS/DNSKEY at independent moments
    probes: list[Probe] = []
    stats: dict[str, PopulationStats] = {}

    for population, config in POPULATIONS.items():
        model = config["model"]
        stat = PopulationStats(population, model, config["label"])
        holds: list[tuple[float, float, str]] = []
        predicted = predictions[model]
        windows = predicted.failure_windows()
        for index in range(resolvers):
            resolver = Resolver(
                f"{population}-{index}",
                network,
                [ROOT_IP],
                world.trust_anchor(),
                wall,
                max_cache_ttl=plan.max_cache_ttl,
                bogus_ttl=plan.bogus_ttl,
                key_failure_ttl=plan.key_failure_ttl,
                trust_cache=config["trust_cache"],
                seed=rng.randrange(1 << 30),
                verifier=verifier,
            )
            # Lookups arrive at random (Poisson) moments, independently per name, starting at a
            # staggered moment so that caches of different resolvers have different ages.
            start = warmup_start + (index + rng.random()) * longest_ttl / resolvers
            events = []
            for name in names + [background]:
                t = start + rng.expovariate(1 / probe_interval)
                while t < t_end:
                    events.append((t, name))
                    t += rng.expovariate(1 / probe_interval)
            events.sort(key=lambda event: event[0])
            last_seen: dict[str, tuple[float, str]] = {}
            for t, name in events:
                if name is background:
                    resolver.touch(plan.zone, t)
                    continue
                outcome = resolver.resolve(name, "A", t)
                stat.lookups += 1
                probes.append(Probe(t, index, population, name, outcome.status, outcome.reason))
                if name in last_seen:
                    previous_t, previous_status = last_seen[name]
                    holds.append((previous_t, t, previous_status))
                last_seen[name] = (t, outcome.status)
                if outcome.status == BOGUS:
                    stat.bogus += 1
                    stat.reasons[outcome.reason] = stat.reasons.get(outcome.reason, 0) + 1
                    stat.first_bogus = t if stat.first_bogus is None else min(stat.first_bogus, t)
                    stat.last_bogus = t if stat.last_bogus is None else max(stat.last_bogus, t)
                    if any(a <= t < b for a, b in windows):
                        stat.bogus_inside += 1
            for previous_t, previous_status in last_seen.values():
                holds.append((previous_t, min(previous_t + probe_interval, t_end), previous_status))
        stat.segments = _merge_holds(holds)
        stat.predicted_seconds = predicted.outage_time if not math.isinf(predicted.outage_time) else 0.0
        stat.observed_seconds = _overlap(
            [(a, b) for a, b, s in stat.segments if s == BOGUS],
            windows,
        )
        raw = simulate(replace(plan, key_failure_ttl=0, bogus_ttl=0), model).failure_windows()
        stat.comparison = compare(
            [probe for probe in probes if probe.population == population],
            raw,
            windows,
            validated_answer_rule(plan),
            max_gap=4 * probe_interval,
        )
        stats[population] = stat

    return Experiment(
        plan=plan,
        predictions=predictions,
        stats=stats,
        probes=probes,
        resolvers=resolvers,
        probe_interval=probe_interval,
        queries=network.queries,
        elapsed=time.perf_counter() - started,
        window=window,
        key_mapping=key_mapping(plan, world.keys),
    )


def _merge_holds(holds: list[tuple[float, float, str]]) -> list[tuple[float, float, str]]:
    """Combine per-resolver status intervals: bogus if any resolver failed, then insecure mixes."""
    points = sorted({a for a, _, _ in holds} | {b for _, b, _ in holds})
    if not points:
        return []
    starts = sorted(holds)
    segments: list[tuple[float, float, str]] = []
    active: list[tuple[float, float, str]] = []
    cursor = 0
    for left, right in zip(points, points[1:]):
        while cursor < len(starts) and starts[cursor][0] <= left:
            active.append(starts[cursor])
            cursor += 1
        active = [h for h in active if h[1] > left]
        statuses = {h[2] for h in active}
        if not statuses:
            continue
        if BOGUS in statuses:
            status = "bogus"
        elif INSECURE in statuses and SECURE in statuses:
            status = "partly-insecure"
        elif INSECURE in statuses:
            status = "insecure"
        else:
            status = "secure"
        if segments and segments[-1][2] == status and segments[-1][1] == left:
            segments[-1] = (segments[-1][0], right, status)
        else:
            segments.append((left, right, status))
    return segments


def _overlap(first: list[tuple[float, float]], second: list[tuple[float, float]]) -> float:
    total = 0.0
    for a1, b1 in first:
        for a2, b2 in second:
            low, high = max(a1, a2), min(b1, b2)
            if high > low:
                total += high - low
    return total
