"""Find the earliest safe moment for every step and build a corrected plan.

Steps are handled in time order. For step ``i`` the plan is cut after that step (the state it
creates is assumed to stay) and the step is moved later until no failure is caused by a version
the step introduces. Earlier steps keep the times already chosen for them; later steps are never
moved earlier than planned and never before the step that precedes them.

Some steps cannot be fixed by waiting because they change two RRsets that must change at
different times (for example: remove the DS and unsign the zone at once). Such a step is split:
the changes that have to wait are moved into a new step placed after the conflicting old version
has expired from every cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from .durations import format_duration
from .plan import MODELS, Plan, Step
from .simulator import Failure, Result, simulate
from .timeline import rrset_label

SEARCH_LIMIT = 60 * 86400  # give up if a step is still unsafe 60 days later
MAX_SPLITS = 10
LIMIT_LABEL = "Model-limited:"  # starts the line of the description that says what was not established


@dataclass
class StepAdvice:
    index: int
    name: str
    planned: int
    earliest: int | None  # None: no waiting time makes this step safe
    recommended: int
    blocking: list[Failure] = field(default_factory=list)

    @property
    def moved(self) -> bool:
        return self.recommended != self.planned

    @property
    def possible(self) -> bool:
        return self.earliest is not None


@dataclass
class FixResult:
    plan: Plan
    advice: list[StepAdvice]
    fixed_plan: Plan
    fixed_result: Result
    splits: list[str] = field(default_factory=list)
    verified: dict[str, Result] = field(default_factory=dict)  # the corrected plan under every model

    @property
    def fixable(self) -> bool:
        return all(a.possible for a in self.advice)

    @property
    def safe_models(self) -> list[str]:
        return [model for model, result in self.verified.items() if result.ok]

    @property
    def unsafe_models(self) -> list[str]:
        return [model for model, result in self.verified.items() if not result.ok]

    @property
    def fully_safe(self) -> bool:
        return not self.unsafe_models

    @property
    def incomplete(self) -> bool:
        """No bogus answers, but the plan does not reach a valid final state. Timing cannot change that."""
        return self.fixed_result.ok and bool(self.fixed_result.findings)

    @property
    def model_limited(self) -> bool:
        """Safe under the model it was corrected for, but not under another one."""
        return self.fixed_result.ok and not self.fully_safe

    def output_plan(self) -> Plan:
        """The corrected plan as it is saved: a model-limited plan says so in its description."""
        kept = [line for line in self.fixed_plan.description.splitlines() if not line.startswith(LIMIT_LABEL)]
        if self.model_limited:
            kept.append(
                f"{LIMIT_LABEL} flightcheck fix verified this plan as safe under the {self.fixed_result.model} model "
                f"only. It is NOT safe under: {', '.join(self.unsafe_models)}."
            )
        return replace(self.fixed_plan, description="\n".join(kept))


def fix_plan(plan: Plan, model: str | None = None) -> FixResult:
    model = model or plan.model
    splits: list[str] = []
    current = plan
    for _ in range(MAX_SPLITS + 1):
        advice, times = _schedule(current, model)
        impossible = next((a for a in advice if not a.possible), None)
        if impossible is None:
            break
        split = _split_step(current, impossible, times, model)
        if split is None:
            break
        current, message = split
        splits.append(message)
    fixed = replace(current.with_step_times({a.index: a.recommended for a in advice}), model=model)
    original = {s.index: s.at for s in plan.steps}
    for item in advice:
        item.planned = original.get(item.index, item.planned)
    verified = {name: simulate(fixed, name) for name in MODELS}
    return FixResult(plan, advice, fixed, verified[model], splits, verified)


def _caused_by(result: Result, step_index: int) -> list[Failure]:
    return [
        f
        for f in result.failures
        if f.reference.step_index == step_index or f.target.step_index == step_index
    ]


def _schedule(plan: Plan, model: str) -> tuple[list[StepAdvice], dict[int, int]]:
    ordered = plan.ordered_steps()
    times: dict[int, int] = {}
    advice: list[StepAdvice] = []
    previous = None

    for position, step in enumerate(ordered):
        lower = step.at if previous is None else max(step.at, previous)
        kept = [s.index for s in ordered[: position + 1]]

        def run(moment: int) -> Result:
            return simulate(plan.with_step_times({**times, step.index: moment}).only_steps(kept), model)

        def safe(moment: int) -> bool:
            return not _caused_by(run(moment), step.index)

        if safe(lower):
            earliest = recommended = lower
        else:
            earliest = _search(safe, lower)
            if earliest is None:
                blocking = _caused_by(run(lower), step.index)
                advice.append(StepAdvice(step.index, step.name, step.at, None, lower, blocking))
                times[step.index] = previous = lower
                continue
            recommended = earliest + max(plan.margin, 0)
        times[step.index] = previous = recommended
        advice.append(StepAdvice(step.index, step.name, step.at, earliest, recommended))
    return advice, times


def _search(safe, lower: int) -> int | None:
    """Smallest moment >= lower for which ``safe`` holds, assuming waiting longer never hurts."""
    step = 60
    unsafe = lower
    candidate = lower + step
    while not safe(candidate):
        unsafe = candidate
        step *= 2
        candidate = lower + step
        if candidate - lower > SEARCH_LIMIT:
            return None
    good = candidate
    while good - unsafe > 1:
        middle = (good + unsafe) // 2
        if safe(middle):
            good = middle
        else:
            unsafe = middle
    return good


def _split_step(plan: Plan, advice: StepAdvice, times: dict[int, int], model: str):
    """Split a step whose changes conflict with each other. Returns (new plan, message) or None."""
    step = next(s for s in plan.steps if s.index == advice.index)
    at = times[step.index]
    result = simulate(plan.with_step_times(times), model)
    delays: dict[str, float] = {}
    for failure in _caused_by(result, step.index):
        pair = _internal_conflict(result, failure, step.index)
        if pair is None:
            continue
        old, new = pair
        wait = old.cache_end - new.publish
        if wait > 0:
            delays[new.rrset] = max(delays.get(new.rrset, 0), wait)
    if not delays or set(delays) == set(step.changes):
        return None

    later = {rrset: change for rrset, change in step.changes.items() if rrset in delays}
    keep = {rrset: change for rrset, change in step.changes.items() if rrset not in delays}
    wait = int(max(delays.values())) + max(plan.margin, 0)
    new_at = at + wait

    # The new step goes right after the one it was split from; steps that came after it in the
    # plan stay after it.
    timed = [replace(s, at=times.get(s.index, s.at)) for s in plan.steps]
    position = (at, step.order)
    following = [s.order for s in timed if (s.at, s.order) > position]
    next_order = min(following) if following else step.order + 1
    second = Step(
        name=f"{step.name} (part 2)",
        at=new_at,
        changes=later,
        index=max(s.index for s in plan.steps) + 1,
        order=(step.order + next_order) / 2,
    )
    steps = []
    for s in timed:
        if s.index == step.index:
            steps.append(replace(s, changes=keep))
        elif (s.at, s.order) > position and s.at < new_at:
            steps.append(replace(s, at=new_at))
        else:
            steps.append(s)
    steps.append(second)
    moved = ", ".join(sorted(rrset_label(r) for r in later))
    message = (
        f'Split "{step.name}": the change to {moved} must wait until the old data has expired '
        f"from caches, so it moves to a new step {format_duration(wait)} later"
    )
    return replace(plan, steps=steps), message


def _internal_conflict(result: Result, failure: Failure, step_index: int):
    """(old, new) if the step both replaces ``old`` and introduces the conflicting ``new``."""
    timelines = result.timelines
    for old, new in ((failure.reference, failure.target), (failure.target, failure.reference)):
        if new.step_index != step_index:
            continue
        versions = timelines[old.rrset]
        successor = versions[old.index + 1] if old.index + 1 < len(versions) else None
        if successor is not None and successor.step_index == step_index:
            return old, new
    return None
