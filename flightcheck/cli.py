"""Command line interface.

    flightcheck check PLAN [--model M] [--html FILE] [--json FILE|-]   exit 0 = safe, 1 = unsafe
    flightcheck fix   PLAN [--model M] [--write FILE] [--html FILE]    exit 0 = safe under both models,
                                                                       1 = no safe plan (nothing written),
                                                                       3 = safe only under the selected model,
                                                                       4 = no bogus answers, but the plan does not
                                                                           reach a valid final state (nothing written)
    flightcheck lab   PLAN [--resolvers N] [--html FILE] [--json FILE]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

import yaml

from .durations import format_offset
from .fixer import FixResult, fix_plan
from .plan import MODELS, RESOLVER_PROFILES, PlanError, load_plan, plan_from_dict
from .report_html import render_html
from .report_json import to_dict
from .report_text import render
from .simulator import Result, simulate

EXIT_SAFE, EXIT_UNSAFE, EXIT_ERROR, EXIT_MODEL_LIMITED, EXIT_INCOMPLETE = 0, 1, 2, 3, 4


def _write(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    Path(path).write_text(text, encoding="utf-8")
    print(f"wrote {path}", file=sys.stderr)


def _write_atomic(path: str, text: str) -> None:
    """Replace ``path`` in one move, so a failure leaves whatever was there before."""
    target = Path(path)
    try:
        handle, temporary = tempfile.mkstemp(dir=target.resolve().parent, prefix=f".{target.name}.", suffix=".tmp")
    except OSError as exc:
        raise PlanError(f"{path}: cannot write the corrected plan: {exc}") from exc
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.chmod(temporary, target.stat().st_mode if target.exists() else 0o644)
        os.replace(temporary, target)
    except OSError as exc:
        Path(temporary).unlink(missing_ok=True)
        raise PlanError(f"{path}: cannot write the corrected plan: {exc}") from exc
    print(f"wrote {path}", file=sys.stderr)


def _same_file(first: str, second: str) -> bool:
    if Path(first).resolve() == Path(second).resolve():
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _failure_lines(result: Result) -> list[str]:
    lines = []
    for failure in result.failures:
        spans = ", ".join(f"{format_offset(a)} -> {format_offset(b)}" for a, b in failure.intervals)
        lines.append(f"  {spans}: {failure.rrset}: {failure.reason}")
    return lines


def _verified_yaml(fix: FixResult) -> str:
    """The text to save, after reading it back the way ``check`` will."""
    plan = fix.output_plan()
    text = plan.to_yaml()
    saved = plan_from_dict(yaml.safe_load(text), origin="the corrected plan")
    same = (
        saved.model == plan.model
        and sorted(s.at for s in saved.steps) == sorted(s.at for s in plan.steps)
        and simulate(saved).safe
    )
    if not same:
        raise PlanError("the corrected plan does not give the same result when read back; nothing was written")
    return text


def _load(args):
    plan = load_plan(args.plan)
    return plan.with_profile(args.resolver_profile) if args.resolver_profile else plan


def cmd_check(args) -> int:
    plan = _load(args)
    result = simulate(plan, args.model)
    fix = fix_plan(plan, args.model)
    if args.json != "-":
        sys.stdout.write(render(result, fix, color=_color(args)))
    if args.html:
        extra = [simulate(plan, m) for m in MODELS if m != result.model] if args.both_models else []
        _write(args.html, render_html(result, fix, extra=extra))
    if args.json:
        _write(args.json, json.dumps(to_dict(result, fix), indent=2) + "\n")
    if not result.ok:
        return EXIT_UNSAFE
    if result.findings:
        return EXIT_INCOMPLETE
    return EXIT_SAFE if result.safe_for_whole_zone else EXIT_MODEL_LIMITED


def cmd_fix(args) -> int:
    if args.write and args.write != "-" and _same_file(args.write, args.plan):
        raise PlanError(f"{args.write}: --write must not name the input plan; choose another file")
    plan = _load(args)
    result = simulate(plan, args.model)
    fix = fix_plan(plan, args.model)
    sys.stdout.write(render(result, fix, color=_color(args)))
    if args.html:
        fixed_result = fix.fixed_result
        _write(args.html, render_html(fixed_result, fix_plan(fix.fixed_plan, args.model)))

    model = fix.fixed_result.model
    if not fix.fixed_result.ok:
        target = f"; {args.write} was not written" if args.write else ""
        print(f"error: no safe plan: the corrected plan is still unsafe under the {model} model{target}", file=sys.stderr)
        print("\n".join(_failure_lines(fix.fixed_result)), file=sys.stderr)
        return EXIT_UNSAFE
    if fix.incomplete:
        target = f"; {args.write} was not written" if args.write else ""
        print(f"error: incomplete plan: changing the timing cannot give it a valid final state{target}", file=sys.stderr)
        for finding in fix.fixed_result.findings:
            print(f"  {finding.message}. Missing: {finding.missing}.", file=sys.stderr)
        return EXIT_INCOMPLETE

    if args.write:
        text = _verified_yaml(fix)
        if args.write == "-":
            sys.stdout.write(text)
        else:
            _write_atomic(args.write, text)
    if fix.model_limited:
        print(f"warning: model-limited: the corrected plan is safe under the {model} model only", file=sys.stderr)
        for other in fix.unsafe_models:
            print(f"it is NOT safe under the {other} model:", file=sys.stderr)
            print("\n".join(_failure_lines(fix.verified[other])), file=sys.stderr)
        return EXIT_MODEL_LIMITED
    if plan.coverage == "sampled":
        print("warning: the corrected plan is safe for the sampled records only, not for the whole zone", file=sys.stderr)
        return EXIT_MODEL_LIMITED
    print("the corrected plan is safe under both models", file=sys.stderr)
    return EXIT_SAFE


def _snapshot_axfr(args, zone) -> int:
    from . import axfr, snapshot

    if args.query:
        raise PlanError("--axfr transfers the whole zone, so --query cannot be used with it")
    if not args.server:
        raise PlanError("--axfr needs --server: name the authoritative server that allows you the transfer")
    children = [snapshot.parse_server(text) for text in args.server]
    parents = [snapshot.parse_server(text) for text in args.parent_server or []]
    tsig = axfr.load_tsig(args.tsig_file) if args.tsig_file else None
    print("mode: axfr (zone transfer over TCP)")
    return _finish_snapshot(args, zone, axfr.collect_axfr_snapshot(zone, children[: snapshot.MAX_SERVERS], parents[: snapshot.MAX_SERVERS], tsig))


def _finish_snapshot(args, zone, result: dict) -> int:
    from . import snapshot

    status = result["completeness"]["status"]
    print(f"{zone}: {status}: {result['completeness']['meaning']}")
    for line in result["warnings"]:
        print(f"warning: {line}")
    for line in result["errors"]:
        print(f"error: {line}", file=sys.stderr)
    if status == "failed":
        print(f"error: no snapshot was written: {result['completeness']['meaning']}", file=sys.stderr)
        return EXIT_ERROR
    _write_atomic(args.output, snapshot.to_yaml(result))
    return EXIT_UNSAFE if status == "inconsistent" else EXIT_SAFE


def cmd_snapshot(args) -> int:
    from . import snapshot

    zone = snapshot.parse_zone(args.zone)
    if args.axfr:
        return _snapshot_axfr(args, zone)
    if args.tsig_file:
        raise PlanError("--tsig-file only applies to --axfr")
    print("mode: dns-query (individual queries)", file=sys.stderr)
    queries =[snapshot.parse_query(text, zone) for text in args.query or []]
    if len(queries) > snapshot.MAX_QUERIES:
        raise PlanError(f"at most {snapshot.MAX_QUERIES} --query options")
    children = [snapshot.parse_server(text) for text in args.server or []]
    parents = [snapshot.parse_server(text) for text in args.parent_server or []]
    source = "given by the operator"
    if not children or not parents:
        source = "found with the system resolver; the records still come from these servers"
    if not children:
        children = snapshot.discover_servers(zone)
    if not parents:
        parent_zone = snapshot.parent_zone_of(zone)
        parents = snapshot.discover_servers(parent_zone) if parent_zone else []
    if not children:
        raise PlanError(f"{zone}: no name servers found; give them with --server")

    result = snapshot.collect_snapshot(zone, children[: snapshot.MAX_SERVERS], parents[: snapshot.MAX_SERVERS], queries, server_source=source)
    return _finish_snapshot(args, zone, result)


def cmd_plan(args) -> int:
    from .planbuilder import build_plan, load_yaml, plan_text

    for other in (args.snapshot, args.inputs):
        if _same_file(args.output, other):
            raise PlanError(f"{args.output}: --output must not name an input file; choose another file")
    text = plan_text(build_plan(load_yaml(args.snapshot), args.rollover, load_yaml(args.inputs)))
    plan = plan_from_dict(yaml.safe_load(text), origin=args.output)
    _write_atomic(args.output, text)
    print("This is a candidate, not an approved schedule, and nothing has been changed in DNS.")
    for model in MODELS:
        result = simulate(plan, model)
        verdict = "no bogus answers in the model" if result.ok else "unsafe as scheduled; 'flightcheck fix' can look for a safe schedule"
        print(f"  {model}: {verdict}")
    if plan.coverage == "sampled":
        print("  evidence: sampled records and the operator's assumptions, so this can never be SAFE for the whole zone")
    return EXIT_SAFE


def cmd_lab(args) -> int:
    from .lab.experiment import run_experiment
    from .lab.report import lab_report

    plan = load_plan(args.plan)
    experiment = run_experiment(plan, resolvers=args.resolvers, probe_interval=args.probe_interval, seed=args.seed)
    sys.stdout.write(experiment.summary_text())
    if args.html:
        _write(args.html, lab_report(experiment))
    if args.json:
        _write(args.json, json.dumps(experiment.to_dict(), indent=2) + "\n")
    return EXIT_SAFE if experiment.consistent else EXIT_UNSAFE


def _pairs(values: list[str]) -> dict[str, str]:
    pairs = {}
    for value in values or []:
        for item in value.split(","):
            if item:
                key, _, val = item.partition("=")
                pairs[key.strip()] = val.strip()
    return pairs


def cmd_lab_init(args) -> int:
    from .lab.network import lab_init

    config = lab_init(
        args.plan,
        args.out,
        scale=args.scale,
        start_delay=args.start_in,
        port=args.port,
        addresses=_pairs(args.address),
    )
    duration = config.end_wall - config.start_wall
    print(
        f"lab written to {args.out}: clock x{config.scale:g}, starts in {args.start_in:g}s, "
        f"runs {duration:.0f}s (plan {config.t_begin / 3600:+.1f}h -> {config.t_end / 3600:+.1f}h)"
    )
    for role, ip in config.addresses.items():
        print(f"  {role:4s} {ip}:{config.port}")
    return EXIT_SAFE


def cmd_lab_bootstrap(args) -> int:
    from .lab.network import lab_bootstrap

    config = lab_bootstrap(args.plan, args.out, port=args.port, addresses=_pairs(args.address))
    print(f"stable lab written to {args.out}: real-time clock, no planned changes")
    for role, ip in config.addresses.items():
        print(f"  {role:4s} {ip}:{config.port}")
    return EXIT_SAFE


def cmd_serve(args) -> int:
    from .lab.network import ROLES, serve

    roles = list(ROLES) if args.role == ["all"] else args.role
    serve(args.lab, roles, forever=args.forever, axfr_allow=args.axfr_allow)
    return EXIT_SAFE


def cmd_emu_resolver(args) -> int:
    from .lab.network import serve_resolver

    serve_resolver(args.lab, args.listen, args.port, trust_cache=not args.behind_cache, forever=args.forever)
    return EXIT_SAFE


def cmd_probe(args) -> int:
    from .lab.comparison import run_outcome
    from .lab.network import probe, probe_report_html, probe_report_text

    result = probe(args.lab, _pairs(args.resolver), interval=args.interval, port=args.port)
    plan = load_plan(Path(args.lab) / "plan.yaml")
    sys.stdout.write(probe_report_text(result, plan))
    if args.json:
        _write(args.json, json.dumps(result, indent=2) + "\n")
    if args.html:
        _write(args.html, probe_report_html(result, plan))
    code, reason = run_outcome({label: data["comparison"][data["model"]] for label, data in result["per_resolver"].items()})
    print(reason, file=sys.stderr)
    return code


def cmd_real_lab(args) -> int:
    from .lab.real import report_html, report_text, run_real_lab, run_status, to_json

    try:
        run = run_real_lab(
            args.plan,
            args.out,
            software=tuple(args.software),
            instances=args.instances,
            scale=args.scale,
            subnet=args.subnet,
        )
    except (RuntimeError, OSError) as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        print(f"error: the run did not work: {exc}", file=sys.stderr)
        return EXIT_ERROR
    sys.stdout.write(report_text(run))
    plan = load_plan(args.plan)
    _write(args.html or str(Path(args.out) / "report.html"), report_html(run, plan))
    _write(args.json or str(Path(args.out) / "result.json"), to_json(run) + "\n")
    code, reason = run_status(run)
    print(reason, file=sys.stderr)
    return code


def _color(args) -> bool:
    return not args.no_color and sys.stdout.isatty()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flightcheck",
        description="Pre-flight simulator for DNSSEC key rollovers and DS changes.",
    )
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="simulate a plan and report every moment validation can fail")
    check.add_argument("plan")
    check.add_argument("--model", choices=MODELS, help="resolver model (default: the plan's, else conservative)")
    check.add_argument("--resolver-profile", choices=RESOLVER_PROFILES, help="how long resolvers remember a failure")
    check.add_argument("--html", metavar="FILE", help="write an HTML report")
    check.add_argument("--json", metavar="FILE", help="write the result as JSON ('-' for stdout)")
    check.add_argument("--both-models", action="store_true", help="show both resolver models in the HTML report")
    check.set_defaults(func=cmd_check)

    fix = sub.add_parser("fix", help="compute the earliest safe time for every step and a corrected plan")
    fix.add_argument("plan")
    fix.add_argument("--model", choices=MODELS)
    fix.add_argument("--resolver-profile", choices=RESOLVER_PROFILES)
    fix.add_argument("--write", metavar="FILE", help="write the corrected plan as YAML")
    fix.add_argument("--html", metavar="FILE", help="write an HTML report of the corrected plan")
    fix.set_defaults(func=cmd_fix)

    snap = sub.add_parser("snapshot", help="record what a zone publishes now, read-only, from its authoritative servers")
    snap.add_argument("zone")
    snap.add_argument("--output", required=True, help="YAML file; not written if collection fails")
    snap.add_argument("--server", action="append", metavar="IP", help="the zone's authoritative server (repeatable)")
    snap.add_argument("--parent-server", action="append", metavar="IP", help="the parent's authoritative server (repeatable)")
    snap.add_argument("--query", action="append", metavar="NAME/TYPE", help="also collect this RRset (repeatable)")
    snap.add_argument("--axfr", action="store_true", help="transfer the whole zone from each --server instead of asking record by record")
    snap.add_argument("--tsig-file", metavar="FILE", help="with --axfr: YAML with the TSIG key's name, secret and optionally algorithm")
    snap.set_defaults(func=cmd_snapshot)

    planner = sub.add_parser("plan", help="write a candidate rollover plan from a snapshot and the operator's inputs")
    planner.add_argument("snapshot")
    planner.add_argument("--rollover", required=True, choices=("ksk", "zsk"))
    planner.add_argument("--inputs", required=True, help="YAML file with the key to replace, the new key, and the assumptions")
    planner.add_argument("--output", required=True, help="the candidate plan; not written on failure")
    planner.set_defaults(func=cmd_plan)

    lab = sub.add_parser("lab", help="execute the plan in the built-in lab (real DNSSEC signatures) and compare")
    lab.add_argument("plan")
    lab.add_argument("--resolvers", type=int, default=12, help="emulated resolvers per resolver type")
    lab.add_argument("--probe-interval", type=int, default=300, help="seconds between probes of one resolver")
    lab.add_argument("--seed", type=int, default=1)
    lab.add_argument("--html", metavar="FILE")
    lab.add_argument("--json", metavar="FILE")
    lab.set_defaults(func=cmd_lab)

    init = sub.add_parser("lab-init", help="prepare a network lab run (keys, clock, resolver configs)")
    init.add_argument("plan")
    init.add_argument("--out", required=True, help="lab directory shared by all lab processes")
    init.add_argument("--scale", type=float, default=600, help="plan seconds per real second (default 600)")
    init.add_argument("--start-in", type=float, default=30, help="seconds until the plan clock starts")
    init.add_argument("--port", type=int, default=53)
    init.add_argument("--address", action="append", metavar="ROLE=IP", help="e.g. root=127.0.0.10 (repeatable)")
    init.set_defaults(func=cmd_lab_init)

    bootstrap = sub.add_parser("lab-bootstrap", help="prepare a stable lab for 'snapshot': no steps, real-time clock")
    bootstrap.add_argument("plan", help="the zone as it is now: a plan with 'steps: []'")
    bootstrap.add_argument("--out", required=True, help="lab directory shared by all lab processes")
    bootstrap.add_argument("--port", type=int, default=53)
    bootstrap.add_argument("--address", action="append", metavar="ROLE=IP", help="e.g. root=127.0.0.10 (repeatable)")
    bootstrap.set_defaults(func=cmd_lab_bootstrap)

    srv = sub.add_parser("serve", help="run lab authoritative servers on UDP/TCP")
    srv.add_argument("--lab", required=True)
    srv.add_argument("--role", nargs="+", default=["all"], choices=["all", "root", "tld", "ns1", "ns2"])
    srv.add_argument("--forever", action="store_true", help="keep serving after the plan ends")
    srv.add_argument("--axfr-allow", action="append", metavar="IP", help="stable lab only: allow this client a zone transfer from ns1 and ns2 (repeatable)")
    srv.set_defaults(func=cmd_serve)

    emu = sub.add_parser("emu-resolver", help="run the emulated validating resolver as a network service")
    emu.add_argument("--lab", required=True)
    emu.add_argument("--listen", required=True)
    emu.add_argument("--port", type=int, default=53)
    emu.add_argument("--behind-cache", action="store_true", help="validate every answer again (validator behind a cache)")
    emu.add_argument("--forever", action="store_true")
    emu.set_defaults(func=cmd_emu_resolver)

    prb = sub.add_parser("probe", help="query resolvers during a network lab run and compare with the prediction")
    prb.add_argument("--lab", required=True)
    prb.add_argument("--resolver", action="append", required=True, metavar="NAME=IP", help="repeatable")
    prb.add_argument("--interval", type=float, default=0.25, help="real seconds between rounds of lookups")
    prb.add_argument("--port", type=int, default=53)
    prb.add_argument("--html", metavar="FILE")
    prb.add_argument("--json", metavar="FILE")
    prb.set_defaults(func=cmd_probe)

    real = sub.add_parser("real-lab", help="measure real Unbound and BIND against the prediction (loopback, no Docker)")
    real.add_argument("plan")
    real.add_argument("--out", required=True, help="directory for this run")
    real.add_argument("--software", nargs="+", default=["unbound", "bind"], choices=["unbound", "bind"])
    real.add_argument("--instances", type=int, default=3, help="instances of each resolver")
    real.add_argument("--scale", type=float, default=600, help="plan seconds per real second")
    real.add_argument("--subnet", default="127.0.0", help="loopback prefix; use a different one for parallel runs")
    real.add_argument("--html", metavar="FILE")
    real.add_argument("--json", metavar="FILE")
    real.set_defaults(func=cmd_real_lab)
    return parser


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except PlanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
