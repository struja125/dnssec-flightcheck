"""Plain-text report for the terminal and CI logs."""

from __future__ import annotations

from .durations import format_duration, format_offset, format_time
from .fixer import FixResult
from .simulator import Result

MODEL_TEXT = {
    "conservative": "conservative (RFC 7583: any cached versions may meet, e.g. validators behind caches)",
    "fetch": "fetch (validating resolver that trusts what it validated when fetching)",
}


def _color(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def render(result: Result, fix: FixResult | None = None, color: bool = False) -> str:
    plan = result.plan
    out: list[str] = []
    fmt = lambda t: format_time(t, plan.start)  # noqa: E731
    red = lambda s: _color(s, "1;31", color)  # noqa: E731
    green = lambda s: _color(s, "1;32", color)  # noqa: E731
    bold = lambda s: _color(s, "1", color)  # noqa: E731

    out.append(bold(f"DNSSEC FlightCheck - {plan.name}"))
    meta = f"Zone {plan.zone}   Model: {MODEL_TEXT.get(result.model, result.model)}"
    out.append(meta)
    out.append(
        "Delays: propagation {p}, registry {r}   Resolver max cache TTL {m}   Safety margin {g}".format(
            p=format_duration(plan.propagation),
            r=format_duration(plan.registry_delay),
            m=format_duration(plan.max_cache_ttl),
            g=format_duration(plan.margin),
        )
    )
    if plan.start:
        out.append(f"Plan start: {plan.start.strftime('%Y-%m-%d %H:%M UTC')}")
    out.append("")

    out.append(bold("Steps"))
    for step in plan.ordered_steps():
        out.append(f"  {format_offset(step.at):>14}  {step.name}")
    out.append("")

    if result.ok and result.findings:
        out.append(
            red("Verdict: INCOMPLETE")
            + f" - the {result.model} model predicts no bogus answers, but the plan does not reach a valid final state."
        )
    elif result.ok and plan.coverage == "sampled":
        out.append(
            green("Verdict: SAFE for the sampled records only")
            + f" ({result.model} model) - built from part of the zone and the operator's assumptions, not all of its data."
        )
    elif result.ok and result.model == "fetch":
        out.append(
            green("Verdict: SAFE under the fetch model only")
            + " - validators behind a cache are not covered; use --model conservative to check them."
        )
    elif result.ok:
        out.append(green("Verdict: SAFE") + " - no resolver can see a bogus answer at any moment of this plan.")
    else:
        windows = result.failure_windows()
        first, last = windows[0][0], windows[-1][1]
        span = "until the end of the plan" if last == float("inf") else f"until {fmt(last)}"
        out.append(
            red("Verdict: UNSAFE")
            + f" - resolvers can answer SERVFAIL for {format_duration(result.outage_time)} in total, "
            f"from {fmt(first)} {span}."
        )
        out.append(
            f"The zone itself cannot be validated for {format_duration(result.broken_time)}; the rest is "
            f"resolvers remembering the failure ({plan.profile} profile: chain of trust "
            f"{format_duration(plan.key_failure_ttl)}, answers {format_duration(plan.bogus_ttl)}, "
            "added up after a failed chain of trust; an upper bound)."
        )
    if result.final_status not in ("secure",):
        out.append(f"The zone ends up {result.final_status}.")
    out.append("")

    for number, failure in enumerate(result.failures, 1):
        windows = ", ".join(f"{format_offset(a)} -> {format_offset(b)}" for a, b in failure.intervals)
        out.append(red(f"  [{number}] {windows}  ({format_duration(failure.duration)})"))
        out.append(_wrap(failure.explain(plan), "      "))
        out.append("")

    if result.findings:
        out.append(bold("Final state"))
        for finding in result.findings:
            out.append(_wrap(f"- {finding.message}. Missing: {finding.missing}.", "  "))
        out.append("")

    if fix is not None and (not result.ok or any(a.moved for a in fix.advice)):
        out.append(bold("Safe schedule") + f" (worst case + {format_duration(plan.margin)} margin)")
        for message in fix.splits:
            out.append(_wrap("* " + message, "  "))
        for item in fix.advice:
            if not item.possible:
                change = red("cannot be made safe by waiting")
            elif item.moved:
                change = f"move to {format_offset(item.recommended)} (earliest {format_offset(item.earliest)})"
            else:
                change = "ok"
            out.append(f"  {format_offset(item.planned):>14}  {item.name}: {change}")
        if fix.incomplete:
            out.append(red("  Timing alone cannot complete this plan: it still needs the operations listed under Final state."))
        elif fix.model_limited:
            out.append(
                f"  The corrected plan is safe under the {fix.fixed_result.model} model only, "
                f"NOT under: {', '.join(fix.unsafe_models)}."
            )
        elif fix.fixed_result.ok and plan.coverage == "sampled":
            out.append(green("  The corrected plan is safe under both models, for the sampled records only."))
        elif fix.fixed_result.ok:
            out.append(green("  The corrected plan is safe under both models.") + " Use 'flightcheck fix --write' to save it.")
        else:
            out.append(red(f"  The corrected plan is still unsafe under the {fix.fixed_result.model} model."))
        out.append("")

    notes = [lint for lint in result.lints if lint.severity == "warning"]
    if notes:
        out.append(bold("Warnings"))
        for lint in notes:
            out.append(_wrap(f"- {lint.step}: {lint.message}", "  "))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def _wrap(text: str, indent: str, width: int = 100) -> str:
    words = text.split()
    lines, line = [], indent
    for word in words:
        if len(line) + len(word) + 1 > width and line.strip():
            lines.append(line.rstrip())
            line = indent + "  " if lines else indent
        line += word + " "
    if line.strip():
        lines.append(line.rstrip())
    return "\n".join(lines)
