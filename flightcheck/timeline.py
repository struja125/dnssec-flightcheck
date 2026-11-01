"""Version timelines: when each version of each RRset is served and how long it can stay cached.

For a version ``v`` of an RRset:

* it is *served* (a resolver can fetch it) from ``publish`` until ``withdraw``. ``withdraw`` is the
  moment the next version reaches the last authoritative server: the next publish time plus the
  propagation delay to the secondaries (or the parent's own propagation delay for DS);
* it can be *cached* from ``publish`` until ``withdraw + TTL``. A resolver that fetched it at the
  last possible moment keeps it for a full TTL (capped by the resolver's maximum cache TTL).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, replace

from .plan import DATA_PREFIX, DNSKEY, DS, Plan, RRsetState, apply_change


@dataclass(frozen=True)
class Version:
    rrset: str
    index: int
    state: RRsetState
    publish: float
    withdraw: float
    ttl: int
    step: str
    step_index: int | None

    @property
    def cache_end(self) -> float:
        return self.withdraw + self.ttl

    def served_at(self, t: float) -> bool:
        return self.publish <= t < self.withdraw

    def cacheable_at(self, t: float) -> bool:
        return self.publish <= t < self.cache_end

    @property
    def label(self) -> str:
        return f"{rrset_label(self.rrset)} v{self.index}"


def rrset_label(rrset: str) -> str:
    if rrset == DS:
        return "DS"
    if rrset == DNSKEY:
        return "DNSKEY"
    return rrset[len(DATA_PREFIX):]


def _cached_ttl(plan: Plan, rrset: str, state: RRsetState) -> int:
    """An RRset that does not exist is cached as a negative answer, for the TTL of the denying zone (RFC 2308)."""
    negative = None
    if rrset == DS and not state.keys:
        negative = plan.parent_negative_ttl
    elif rrset == DNSKEY and not state.keys:
        negative = plan.zone_negative_ttl
    return state.ttl if negative is None else negative


def build_timelines(plan: Plan) -> dict[str, list[Version]]:
    """Return, per RRset id, the ordered list of its versions."""
    raw: dict[str, list[list]] = {
        rrset: [[plan.initial[rrset], -math.inf, "initial state", None]] for rrset in plan.rrset_ids
    }
    current = dict(plan.initial)

    for step in plan.ordered_steps():
        for rrset, change in step.changes.items():
            new_state = apply_change(current[rrset], change)
            if new_state == current[rrset]:
                continue
            current[rrset] = new_state
            publish = step.at + (plan.registry_delay if rrset == DS else 0)
            history = raw[rrset]
            if history[-1][1] == publish:
                # Two changes at the same moment: the later one replaces the earlier one.
                history[-1][0] = new_state
                history[-1][2] = step.name
                history[-1][3] = step.index
            else:
                history.append([new_state, publish, step.name, step.index])

    timelines = {}
    for rrset, history in raw.items():
        lag = plan.parent_propagation if rrset == DS else plan.propagation
        versions = []
        for index, (state, publish, step_name, step_index) in enumerate(history):
            withdraw = history[index + 1][1] + lag if index + 1 < len(history) else math.inf
            ttl = min(_cached_ttl(plan, rrset, state), plan.max_cache_ttl)
            versions.append(Version(rrset, index, state, publish, withdraw, ttl, step_name, step_index))
        timelines[rrset] = versions
    end = plan_end(timelines)
    return {rrset: [_signature_times_of_this_plan(v, end) for v in versions] for rrset, versions in timelines.items()}


def plan_end(timelines: dict[str, list[Version]]) -> float:
    """When everything the plan replaced has left the caches."""
    return max([0.0] + [v.cache_end for versions in timelines.values() for v in versions if not math.isinf(v.cache_end)])


def _signature_times_of_this_plan(version: Version, end: float) -> Version:
    """Every signature expires one day. After the plan, renewing it is the signer's routine, which lint() points out.
    A signature that started before T+0 says nothing about the plan: an older one was in use before it."""
    rrsig = {
        signer: (
            None if inception is not None and inception <= 0 else inception,
            None if expires is not None and expires >= end else expires,
        )
        for signer, (inception, expires) in version.state.rrsig.items()
    }
    return replace(version, state=replace(version.state, rrsig=rrsig))


def served_version_index(versions: list[Version], t: float, lag: float = 0) -> int:
    """Index of the version an authoritative server lagging ``lag`` seconds behind serves at ``t``."""
    moment = t - lag
    chosen = 0
    for version in versions:
        if version.publish <= moment:
            chosen = version.index
    return chosen
