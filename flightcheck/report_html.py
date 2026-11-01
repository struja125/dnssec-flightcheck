"""Self-contained HTML report with a timeline of versions, cache lifetimes and validation status."""

from __future__ import annotations

import html
import math
from datetime import timedelta

from .durations import format_duration, format_offset, format_time
from .fixer import FixResult
from .plan import DATA_PREFIX, DNSKEY, DS
from .simulator import (
    STATUS_BOGUS,
    STATUS_INSECURE,
    STATUS_PARTLY_INSECURE,
    STATUS_RECOVERING,
    STATUS_SECURE,
    Result,
)
from .timeline import Version

STATUS_CLASS = {
    STATUS_SECURE: "ok",
    STATUS_BOGUS: "bad",
    STATUS_RECOVERING: "recovering",
    STATUS_INSECURE: "insecure",
    STATUS_PARTLY_INSECURE: "insecure",
}
MODEL_NAMES = {"conservative": "conservative model", "fetch": "fetch model"}

TICK_STEPS = [300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 2 * 86400, 7 * 86400]

W, LABEL_W, PAD_R = 1100, 196, 16
CHART_W = W - LABEL_W - PAD_R


def esc(value) -> str:
    return html.escape(str(value), quote=True)


class _Scale:
    def __init__(self, low: float, high: float):
        self.low, self.high = low, high

    def x(self, t: float) -> float:
        t = min(max(t, self.low), self.high)
        return LABEL_W + (t - self.low) / (self.high - self.low) * CHART_W


def _rrset_title(rrset: str) -> str:
    if rrset == DS:
        return "DS (parent)"
    if rrset == DNSKEY:
        return "DNSKEY"
    return rrset[len(DATA_PREFIX):]


def _version_text(version: Version) -> str:
    state = version.state
    if version.rrset == DS:
        return " + ".join(sorted(state.keys)) if state.keys else "no DS (insecure)"
    if version.rrset == DNSKEY:
        if not state.keys:
            return "no keys (unsigned)"
        return f"{' '.join(sorted(state.keys))}  ·  sig {' '.join(sorted(state.signed_by)) or '-'}"
    return f"sig {' '.join(sorted(state.signed_by))}" if state.signed_by else "unsigned"


def _timeline_svg(result: Result, measured: list, extra: list[Result]) -> str:
    plan = result.plan
    low, high = result.view_range()
    for other in extra:
        lo2, hi2 = other.view_range()
        low, high = min(low, lo2), max(high, hi2)
    for _, segments in measured:
        high = max([high] + [end for _, end, _ in segments if not math.isinf(end)])
    scale = _Scale(low, high)
    parts: list[str] = []
    y = 44

    # bogus background bands
    bands = []
    for segment in result.segments:
        if segment.status == STATUS_BOGUS:
            x1, x2 = scale.x(segment.start), scale.x(segment.end)
            bands.append(f'<rect class="band" x="{x1:.1f}" y="30" width="{max(x2 - x1, 1):.1f}" height="__H__"/>')

    # step markers
    steps = plan.ordered_steps()
    for number, step in enumerate(steps, 1):
        x = scale.x(step.at)
        parts.append(f'<line class="step-line" x1="{x:.1f}" y1="30" x2="{x:.1f}" y2="__H__"/>')
        parts.append(
            f'<g class="step-dot"><title>{esc(step.name)} at {esc(format_offset(step.at))}</title>'
            f'<circle cx="{x:.1f}" cy="16" r="10"/><text x="{x:.1f}" y="20" text-anchor="middle">{number}</text></g>'
        )

    # RRset rows
    for rrset, versions in result.timelines.items():
        kind = "ds" if rrset == DS else "dnskey" if rrset == DNSKEY else "data"
        parts.append(f'<text class="row-label" x="{LABEL_W - 12}" y="{y + 22}" text-anchor="end">{esc(_rrset_title(rrset))}</text>')
        for version in versions:
            lane_y = y + (0 if version.index % 2 == 0 else 20)
            x1 = scale.x(version.publish)
            x2 = scale.x(version.withdraw)
            x3 = scale.x(version.cache_end)
            tip = (
                f"{version.label}: {_version_text(version)}\n"
                f"served {format_offset(version.publish)} -> {format_offset(version.withdraw)}\n"
                f"can stay cached until {format_offset(version.cache_end)} (TTL {format_duration(version.ttl)})\n"
                f"introduced by: {version.step}"
            )
            parts.append(f"<g><title>{esc(tip)}</title>")
            if x3 > x2:
                parts.append(
                    f'<rect class="tail" fill="url(#hatch-{kind})" x="{x2:.1f}" y="{lane_y}" width="{x3 - x2:.1f}" height="16" rx="2"/>'
                )
            if x2 > x1:
                parts.append(
                    f'<rect class="bar {kind}" x="{x1:.1f}" y="{lane_y}" width="{x2 - x1:.1f}" height="16" rx="2"/>'
                )
            text = f"v{version.index}  {_version_text(version)}"
            room = (x3 if x3 > x2 else x2) - x1
            if room > 7 * len(text) * 0.62:
                parts.append(f'<text class="bar-text" x="{x1 + 5:.1f}" y="{lane_y + 12}">{esc(text)}</text>')
            elif room > 30:
                parts.append(f'<text class="bar-text" x="{x1 + 5:.1f}" y="{lane_y + 12}">v{version.index}</text>')
            parts.append("</g>")
        y += 50

    # status rows
    y += 4
    rows = [(result.label or f"Predicted: {result.model}", result.segments)]
    for other in extra:
        rows.append((other.label or f"Predicted: {other.model}", other.segments))
    for label, segments in rows:
        parts.append(f'<text class="row-label" x="{LABEL_W - 12}" y="{y + 13}" text-anchor="end">{esc(label)}</text>')
        for segment in segments:
            x1, x2 = scale.x(segment.start), scale.x(segment.end)
            if x2 - x1 <= 0:
                continue
            cls = STATUS_CLASS.get(segment.status, "ok")
            tip = f"{segment.status}: {format_offset(segment.start)} -> {format_offset(segment.end)}"
            parts.append(
                f'<rect class="status {cls}" x="{x1:.1f}" y="{y}" width="{x2 - x1:.1f}" height="18"><title>{esc(tip)}</title></rect>'
            )
        y += 26
    for label, segments in measured:
        parts.append(f'<text class="row-label" x="{LABEL_W - 12}" y="{y + 13}" text-anchor="end">{esc(label)}</text>')
        parts.append(f'<rect class="status measured-bg" x="{LABEL_W}" y="{y}" width="{CHART_W}" height="18"/>')
        for start, end, status in segments:
            x1, x2 = scale.x(start), scale.x(end)
            if x2 - x1 <= 0:
                continue
            cls = STATUS_CLASS.get(status, "ok")
            tip = f"measured {status}: {format_offset(start)} -> {format_offset(end)}"
            parts.append(
                f'<rect class="status {cls}" x="{x1:.1f}" y="{y}" width="{max(x2 - x1, 1.5):.1f}" height="18"><title>{esc(tip)}</title></rect>'
            )
        y += 26

    # time axis
    span = high - low
    tick = next((s for s in TICK_STEPS if span / s <= 12), TICK_STEPS[-1])
    first_tick = math.ceil(low / tick) * tick
    parts.append(f'<line class="axis" x1="{LABEL_W}" y1="{y + 2}" x2="{LABEL_W + CHART_W}" y2="{y + 2}"/>')
    t = first_tick
    while t <= high:
        x = scale.x(t)
        parts.append(f'<line class="tick" x1="{x:.1f}" y1="{y}" x2="{x:.1f}" y2="{y + 6}"/>')
        parts.append(f'<text class="tick-text" x="{x:.1f}" y="{y + 19}" text-anchor="middle">{esc(format_offset(t))}</text>')
        if plan.start is not None:
            label = (plan.start + timedelta(seconds=t)).strftime("%d %b %H:%M")
            parts.append(f'<text class="tick-sub" x="{x:.1f}" y="{y + 32}" text-anchor="middle">{esc(label)}</text>')
        t += tick
    height = y + (40 if plan.start is not None else 28)
    body = "".join(bands + parts).replace("__H__", str(y - 30))
    return (
        f'<svg class="timeline" viewBox="0 0 {W} {height}" role="img" '
        f'aria-label="Timeline of RRset versions and validation status">'
        "<defs>"
        + "".join(
            f'<pattern id="hatch-{kind}" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
            f'<rect class="hatch-{kind}" width="3" height="6"/></pattern>'
            for kind in ("ds", "dnskey", "data")
        )
        + "</defs>"
        f"{body}</svg>"
    )


CSS = """
:root {
  --bg: #f6f7f9; --card: #ffffff; --ink: #18202b; --muted: #5d6877; --line: #dde2e8;
  --accent: #0b6e8a; --ok: #2f9e6e; --bad: #d64545; --warn: #d99a20;
  --ds: #7a5cc4; --dnskey: #2f6fd1; --data: #138a8a; --band: rgba(214, 69, 69, 0.08);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #12161c; --card: #1a2028; --ink: #e8edf3; --muted: #9aa6b4; --line: #2c3540;
    --accent: #4fb3cf; --ok: #3fbf85; --bad: #ef6464; --warn: #e8b04a;
    --ds: #a58bea; --dnskey: #6a9cf0; --data: #3fbcbc; --band: rgba(239, 100, 100, 0.12);
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.5 system-ui, "Segoe UI", Roboto, Arial, sans-serif; }
main { max-width: 1160px; margin: 0 auto; padding: 28px 20px 48px; }
header { display: flex; flex-wrap: wrap; gap: 12px 24px; align-items: flex-end; justify-content: space-between; }
.brand { font-size: 13px; letter-spacing: .08em; text-transform: uppercase; color: var(--accent); font-weight: 700; }
h1 { margin: 2px 0 0; font-size: 26px; line-height: 1.2; }
.meta { color: var(--muted); font-size: 13.5px; margin-top: 6px; }
.verdict { padding: 10px 16px; border-radius: 10px; font-weight: 700; font-size: 17px; color: #fff; }
.verdict small { display: block; font-weight: 500; font-size: 13px; opacity: .92; }
.verdict.ok { background: var(--ok); } .verdict.bad { background: var(--bad); }
section { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; margin-top: 18px; }
h2 { font-size: 16px; margin: 0 0 12px; }
p.desc { margin: 10px 0 0; color: var(--muted); max-width: 900px; }
.timeline { width: 100%; height: auto; display: block; color: var(--ink); }
.timeline .row-label { font-size: 12.5px; fill: var(--ink); font-weight: 600; }
.timeline .bar.ds { fill: var(--ds); } .timeline .bar.dnskey { fill: var(--dnskey); } .timeline .bar.data { fill: var(--data); }
.timeline .tail { opacity: .55; }
.timeline .hatch-ds { fill: var(--ds); } .timeline .hatch-dnskey { fill: var(--dnskey); } .timeline .hatch-data { fill: var(--data); }
.timeline .bar-text { font-size: 11px; fill: #fff; font-weight: 600; pointer-events: none; paint-order: stroke; stroke: rgba(0,0,0,.25); stroke-width: 2px; }
.timeline .status.ok { fill: var(--ok); } .timeline .status.bad { fill: var(--bad); } .timeline .status.insecure { fill: var(--warn); } .timeline .status.recovering { fill: var(--bad); opacity: .5; }
.timeline .status.measured-bg { fill: var(--line); }
.timeline .band { fill: var(--band); }
.timeline .step-line { stroke: var(--muted); stroke-dasharray: 3 4; stroke-width: 1; }
.timeline .step-dot circle { fill: var(--accent); } .timeline .step-dot text { fill: #fff; font-size: 11px; font-weight: 700; }
.timeline .axis, .timeline .tick { stroke: var(--muted); }
.timeline .tick-text { font-size: 11px; fill: var(--muted); } .timeline .tick-sub { font-size: 10px; fill: var(--muted); opacity: .8; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 12.5px; color: var(--muted); margin-top: 10px; }
.legend i { display: inline-block; width: 22px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: middle; }
.steps { margin: 12px 0 0; padding-left: 0; list-style: none; display: grid; gap: 4px; }
.steps li { display: grid; grid-template-columns: 26px 120px 1fr; gap: 8px; align-items: baseline; font-size: 14px; }
.steps .n { background: var(--accent); color: #fff; border-radius: 50%; width: 20px; height: 20px; font-size: 11px;
  display: inline-flex; align-items: center; justify-content: center; font-weight: 700; }
.steps .t { color: var(--muted); font-variant-numeric: tabular-nums; }
.failure { border-left: 4px solid var(--bad); padding: 8px 12px; margin: 10px 0; background: var(--band); border-radius: 0 8px 8px 0; }
.failure .when { font-weight: 700; color: var(--bad); }
.failure .why { margin-top: 4px; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12.5px; text-transform: uppercase; letter-spacing: .04em; }
td.num { font-variant-numeric: tabular-nums; white-space: nowrap; }
.tag { display: inline-block; padding: 1px 8px; border-radius: 99px; font-size: 12px; font-weight: 600; }
.tag.ok { background: color-mix(in srgb, var(--ok) 18%, transparent); color: var(--ok); }
.tag.move { background: color-mix(in srgb, var(--warn) 22%, transparent); color: var(--warn); }
.tag.bad { background: color-mix(in srgb, var(--bad) 18%, transparent); color: var(--bad); }
.note { color: var(--muted); font-size: 13.5px; }
ul.lints { margin: 0; padding-left: 18px; } ul.lints li { margin: 4px 0; }
details { margin-top: 12px; } summary { cursor: pointer; color: var(--accent); font-weight: 600; }
pre { background: var(--bg); border: 1px solid var(--line); border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12.5px; }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; margin-top: 4px; }
.metric { border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; }
.metric b { display: block; font-size: 20px; } .metric span { color: var(--muted); font-size: 12.5px; }
footer { color: var(--muted); font-size: 12.5px; margin-top: 22px; }
@media (max-width: 700px) {
  main { padding: 18px 12px 36px; } h1 { font-size: 21px; }
  .steps li { grid-template-columns: 26px 1fr; } .steps .t { grid-column: 2; }
}
"""


def render_html(
    result: Result,
    fix: FixResult | None = None,
    extra: list[Result] | None = None,
    measured: list | None = None,
    lab_summary: list[tuple[str, str, str]] | None = None,
) -> str:
    """Render a report. ``measured`` is a list of (label, [(start, end, status), ...]) rows."""
    plan = result.plan
    extra = extra or []
    measured = measured or []
    fmt = lambda t: format_time(t, plan.start)  # noqa: E731

    if result.ok and result.findings:
        verdict = '<div class="verdict bad">INCOMPLETE<small>no bogus answers, but no valid final state</small></div>'
    elif result.ok and plan.coverage == "sampled":
        verdict = '<div class="verdict bad">SAFE for the sampled records only<small>not all of the zone was seen</small></div>'
    elif result.ok and result.model == "fetch":
        verdict ='<div class="verdict ok">SAFE under the fetch model only<small>validators behind a cache are not covered</small></div>'
    elif result.ok:
        verdict = '<div class="verdict ok">SAFE<small>no bogus answers at any moment</small></div>'
    else:
        verdict = (
            '<div class="verdict bad">UNSAFE'
            f"<small>SERVFAIL for up to {esc(format_duration(result.outage_time))}</small></div>"
        )

    meta = (
        f"Zone <b>{esc(plan.zone)}</b> · {esc(MODEL_NAMES.get(result.model, result.model))} · "
        f"propagation {esc(format_duration(plan.propagation))} · registry delay {esc(format_duration(plan.registry_delay))} · "
        f"max cache TTL {esc(format_duration(plan.max_cache_ttl))}"
    )
    if plan.start:
        meta += f" · start {esc(plan.start.strftime('%Y-%m-%d %H:%M UTC'))}"

    out = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>FlightCheck: {esc(plan.name)}</title><style>{CSS}</style></head><body><main>",
        "<header><div><div class='brand'>DNSSEC FlightCheck</div>",
        f"<h1>{esc(plan.name)}</h1><div class='meta'>{meta}</div></div>{verdict}</header>",
    ]
    if plan.description:
        out.append(f"<p class='desc'>{esc(plan.description)}</p>")
    if result.findings:
        items = "".join(f"<li>{esc(f.message)}. Missing: {esc(f.missing)}.</li>" for f in result.findings)
        out.append(f"<section><h2>Final state</h2><ul class='lints'>{items}</ul></section>")

    # timeline
    out.append("<section><h2>Timeline</h2>")
    out.append(_timeline_svg(result, measured, extra))
    out.append(
        "<div class='legend'>"
        "<span><i style='background:var(--dnskey)'></i>served by the authoritative servers</span>"
        "<span><i style='background:repeating-linear-gradient(135deg,var(--dnskey) 0 3px,transparent 3px 6px)'></i>can still be in resolver caches</span>"
        "<span><i style='background:var(--ok)'></i>validates</span>"
        "<span><i style='background:var(--bad)'></i>bogus (SERVFAIL)</span>"
        "<span><i style='background:var(--bad);opacity:.5'></i>valid again, resolvers still remember the failure</span>"
        "<span><i style='background:var(--warn)'></i>insecure for some or all resolvers</span>"
        "</div>"
    )
    out.append("<ol class='steps'>")
    for number, step in enumerate(plan.ordered_steps(), 1):
        out.append(
            f"<li><span class='n'>{number}</span><span class='t'>{esc(format_offset(step.at))}</span>"
            f"<span>{esc(step.name)}</span></li>"
        )
    out.append("</ol></section>")

    if lab_summary:
        out.append("<section><h2>Lab measurement</h2><div class='metrics'>")
        for title, value, note in lab_summary:
            out.append(f"<div class='metric'><b>{esc(value)}</b>{esc(title)}<br><span>{esc(note)}</span></div>")
        out.append("</div></section>")

    # failures
    if result.failures:
        out.append("<section><h2>What breaks</h2>")
        for failure in result.failures:
            windows = ", ".join(f"{fmt(a)} → {fmt(b)}" for a, b in failure.intervals)
            out.append(
                f"<div class='failure'><div class='when'>{esc(windows)} · {esc(format_duration(failure.duration))}</div>"
                f"<div class='why'>{esc(failure.explain(plan))}</div></div>"
            )
        out.append(
            f"<p class='note'>Resolver profile: {esc(plan.profile)}. A failed chain of trust is remembered for "
            f"{esc(format_duration(plan.key_failure_ttl))} and a failed answer for {esc(format_duration(plan.bogus_ttl))}. "
            f"The zone itself cannot be validated for {esc(format_duration(result.broken_time))}.</p></section>"
        )

    # schedule
    if fix is not None:
        out.append("<section><h2>Safe schedule</h2>")
        if fix.splits:
            out.append("<ul class='lints'>" + "".join(f"<li>{esc(s)}</li>" for s in fix.splits) + "</ul>")
        out.append(
            "<table><thead><tr><th>Step</th><th>Planned</th><th>Earliest safe</th><th>Recommended</th><th></th></tr></thead><tbody>"
        )
        for item in fix.advice:
            if not item.possible:
                tag, earliest = "<span class='tag bad'>cannot be fixed by waiting</span>", "-"
            elif item.moved:
                tag, earliest = "<span class='tag move'>move</span>", format_offset(item.earliest)
            else:
                tag, earliest = "<span class='tag ok'>ok</span>", format_offset(item.earliest)
            out.append(
                f"<tr><td>{esc(item.name)}</td><td class='num'>{esc(format_offset(item.planned))}</td>"
                f"<td class='num'>{esc(earliest)}</td><td class='num'>{esc(format_offset(item.recommended))}</td><td>{tag}</td></tr>"
            )
        out.append("</tbody></table>")
        state = "incomplete" if fix.incomplete else "safe" if fix.fixed_result.ok else "still unsafe"
        out.append(
            f"<p class='note'>Recommended = earliest safe moment + {esc(format_duration(plan.margin))} safety margin. "
            f"The corrected plan is <b>{state}</b> in the {esc(MODEL_NAMES.get(fix.fixed_result.model, ''))}."
            + (f" It is <b>not safe</b> under: {esc(', '.join(fix.unsafe_models))}." if fix.model_limited else "")
            + "</p>"
        )
        out.append(f"<details><summary>Corrected plan (YAML)</summary><pre>{esc(fix.fixed_plan.to_yaml())}</pre></details>")
        out.append("</section>")

    if result.lints:
        out.append("<section><h2>Notes</h2><ul class='lints'>")
        for lint in result.lints:
            out.append(f"<li><b>{esc(lint.severity)}</b> · {esc(lint.step)}: {esc(lint.message)}</li>")
        out.append("</ul></section>")

    out.append(
        "<footer>Worst-case analysis: a version can stay in a resolver's cache for a full TTL after the last "
        "authoritative server stopped serving it. Conservative model = RFC 7583 assumptions (any cached versions "
        "may be combined, as for validators behind caches); fetch model = a validating resolver that validates on "
        "fetch and trusts its cache.</footer></main></body></html>"
    )
    return "".join(out)
