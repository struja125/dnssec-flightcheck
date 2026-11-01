"""Machine-readable result (for CI pipelines and for comparing with lab measurements)."""

from __future__ import annotations

import math

from .fixer import FixResult
from .simulator import Result
from .timeline import Version


def _t(value: float):
    if math.isinf(value):
        return None if value > 0 else "-inf"
    return value


def _version(version: Version) -> dict:
    return {
        "label": version.label,
        "rrset": version.rrset,
        "keys": sorted(version.state.keys),
        "signed_by": sorted(version.state.signed_by),
        "ttl": version.ttl,
        "rrsig": {name: list(times) for name, times in version.state.rrsig.items()},
        "publish": _t(version.publish),
        "withdraw": _t(version.withdraw),
        "cache_end": _t(version.cache_end),
        "step": version.step,
    }


def to_dict(result: Result, fix: FixResult | None = None) -> dict:
    plan = result.plan
    data = {
        "plan": plan.name,
        "zone": plan.zone,
        "model": result.model,
        "ok": result.safe_for_whole_zone,
        "coverage": plan.coverage,
        "no_bogus_answers": result.ok,
        "findings": [{"code": f.code, "message": f.message, "missing": f.missing} for f in result.findings],
        "final_status": result.final_status,
        "outage_seconds": result.outage_time,
        "broken_seconds": result.broken_time,
        "resolver_profile": plan.profile,
        "start": plan.start.isoformat() if plan.start else None,
        "segments": [
            {"start": _t(s.start), "end": _t(s.end), "status": s.status, "failures": list(s.failure_ids)}
            for s in result.segments
        ],
        "failures": [
            {
                "kind": f.kind,
                "rrset": f.rrset,
                "intervals": [[_t(a), _t(b)] for a, b in f.intervals],
                "memory_seconds": f.memory,
                "impact_end": _t(f.impact_end),
                "reason": f.reason,
                "explanation": f.explain(plan),
                "reference": _version(f.reference),
                "target": _version(f.target),
            }
            for f in result.failures
        ],
        "versions": {rrset: [_version(v) for v in versions] for rrset, versions in result.timelines.items()},
        "lints": [{"step": l.step, "severity": l.severity, "message": l.message} for l in result.lints],
    }
    if fix is not None:
        data["fix"] = {
            "fixable": fix.fixable,
            "fixed_plan_ok": fix.fixed_result.safe,
            "fixed_plan_incomplete": fix.incomplete,
            "fixed_plan_model": fix.fixed_result.model,
            "fixed_plan_safe_under": fix.safe_models,
            "splits": fix.splits,
            "steps": [
                {
                    "name": a.name,
                    "planned": a.planned,
                    "earliest": a.earliest,
                    "recommended": a.recommended,
                    "possible": a.possible,
                }
                for a in fix.advice
            ],
        }
    return data
