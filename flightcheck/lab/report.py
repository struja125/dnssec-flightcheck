"""HTML report for a lab run: predictions and measurements on one timeline."""

from __future__ import annotations

from ..durations import format_duration
from ..fixer import fix_plan
from ..report_html import render_html
from .comparison import provenance_row
from .experiment import Experiment


def lab_report(experiment: Experiment) -> str:
    conservative = experiment.predictions["conservative"]
    fetch = experiment.predictions["fetch"]
    measured = [
        (f"Lab: behind cache ({experiment.resolvers})", experiment.stats["behind-cache"].segments),
        (f"Lab: validating ({experiment.resolvers})", experiment.stats["validating"].segments),
    ]
    summary = [
        (
            "lookups with real signatures",
            f"{sum(s.lookups for s in experiment.stats.values()):,}",
            f"{experiment.queries:,} DNS queries, {experiment.elapsed:.1f}s",
        )
    ]
    for stats in experiment.stats.values():
        inside = f"{stats.bogus_inside:,}/{stats.bogus:,}" if stats.bogus else "0 failures"
        coverage = f"{stats.coverage:.0%} of the predicted window observed" if stats.coverage is not None else ""
        summary.append(
            (
                f"{stats.comparison['classification']} · {stats.label}",
                inside,
                coverage or f"{stats.model} model predicts no failure",
            )
        )
    summary.append(
        (
            "verdict",
            "nothing outside the windows" if experiment.consistent else "MISMATCH",
            f"lookup every {format_duration(experiment.probe_interval)} per resolver",
        )
    )
    summary += provenance_row(experiment.plan)
    return render_html(
        conservative,
        fix=fix_plan(experiment.plan, "conservative"),
        extra=[fetch],
        measured=measured,
        lab_summary=summary,
    )
