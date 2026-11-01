"""Run every scenario against real Unbound and BIND and write results/summary.md.

    .venv\\Scripts\\python scripts\\run_all.py [--scale 600] [--parallel 4]

Each run gets its own loopback prefix, so runs can overlap.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
RUNS = ROOT / "netlab-all"
RESULTS = ROOT / "results"
INSTANCES = 3
TITLES = {"unbound": "Unbound 1.26.2", "bind": "BIND 9.16.50"}


def run_one(name: str, subnets: Queue, scale: float) -> dict:
    subnet = subnets.get()
    out = RUNS / name
    shutil.rmtree(out, ignore_errors=True)
    command = [
        sys.executable, "-m", "flightcheck", "real-lab", str(SCENARIOS / f"{name}.yaml"),
        "--out", str(out), "--scale", str(scale), "--subnet", subnet, "--instances", str(INSTANCES),
    ]
    try:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        subnets.put(subnet)
    (RESULTS / f"{name}.txt").write_text(done.stdout + done.stderr, encoding="utf-8")
    report = out / "report.html"
    if report.exists():
        shutil.copyfile(report, RESULTS / f"{name}.html")
    result_file = out / "result.json"
    if not result_file.exists():
        print(f"{name}: FAILED\n{done.stdout}\n{done.stderr}", flush=True)
        return {"scenario": name, "error": True}
    data = json.loads(result_file.read_text(encoding="utf-8"))
    data.pop("samples", None)
    print(f"{name}: done, exit {done.returncode}", flush=True)
    return {"scenario": name, "scale": scale, "exit": done.returncode, **data}


def _cell(result: dict, model: str, field: str = "inside") -> str:
    failures = result["servfail"] + result["timeouts"]
    return f"{result[field][model]:,}/{failures:,}" if failures else "0"


def _hours(seconds: float) -> str:
    return f"{seconds / 3600:.1f}h" if seconds else "0"


def write_summary(runs: list[dict], scale: float) -> None:
    lines = [
        "# Real resolvers against the prediction",
        "",
        f"Clock x{scale:g}, {INSTANCES} instances of each resolver, loopback only. *Inside* counts failed lookups",
        "(SERVFAIL and timeouts) that fell inside the fetch model's predicted window, and *without timers*",
        "the same when the simulator ignores how long resolvers remember a failure. *Recovery* is how many",
        "real seconds after the zone became valid again the last failure was seen.",
        "",
        "| Scenario | Resolver | Validating | Predicted (conservative / fetch) | Observed in fetch window | Lookups | Failures | Inside conservative | Inside fetch | Inside fetch, without timers | Recovery | EDE |",
        "|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    for run in sorted(runs, key=lambda r: r["scenario"]):
        if run.get("error"):
            lines.append(f"| {run['scenario']} | run failed | | | | | | | | | | |")
            continue
        for name, result in run["results"].items():
            predicted = f"{_hours(result['predicted_seconds']['conservative'])} / {_hours(result['predicted_seconds']['fetch'])}"
            observed = _hours(result["observed_seconds"]["fetch"])
            recovery = result["recovery_real"].get("fetch")
            recovery_text = f"{recovery:.0f} s" if recovery is not None else "-"
            lines.append(
                f"| {run['scenario']} | {TITLES[name]} | {'yes' if result['validated'] else 'NO'} | {predicted} | {observed} "
                f"| {result['lookups']:,} | {result['servfail'] + result['timeouts']:,} | {_cell(result, 'conservative')} "
                f"| {_cell(result, 'fetch')} | {_cell(result, 'fetch', 'inside_without_memory')} "
                f"| {recovery_text} | {result['ede'] or '-'} |"
            )
    (RESULTS / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (RESULTS / "summary.json").write_text(json.dumps(runs, indent=1), encoding="utf-8")


def reanalyse_all(scale: float) -> None:
    """Recompute reports and the summary from the samples of the last run, without measuring again."""
    from flightcheck.lab.real import reanalyse, report_html, report_text, to_json
    from flightcheck.plan import load_plan

    runs = []
    for result_file in sorted(RUNS.glob("*/result.json")):
        name = result_file.parent.name
        run = reanalyse(str(result_file.parent))
        plan = load_plan(result_file.parent / "plan.yaml")
        (RESULTS / f"{name}.txt").write_text(report_text(run), encoding="utf-8")
        (RESULTS / f"{name}.html").write_text(report_html(run, plan), encoding="utf-8")
        data = json.loads(to_json(run))
        data.pop("samples")
        runs.append({"scenario": name, "scale": scale, **data})
    write_summary(runs, scale)


def main() -> int:
    global SCENARIOS, RUNS, RESULTS, INSTANCES
    parser = argparse.ArgumentParser()
    parser.add_argument("--scale", type=float, default=600)
    parser.add_argument("--parallel", type=int, default=4)
    parser.add_argument("--only", nargs="+", help="rerun these scenarios and keep the other results")
    parser.add_argument("--dir", default="scenarios", help="folder with the plans")
    parser.add_argument("--name", default="", help="suffix for the run and result folders, e.g. realtime")
    parser.add_argument("--instances", type=int, default=3)
    parser.add_argument("--reanalyse", action="store_true", help="recompute reports from the stored samples")
    args = parser.parse_args()
    SCENARIOS = ROOT / args.dir
    INSTANCES = args.instances
    if args.name:
        RUNS = ROOT / f"netlab-{args.name}"
        RESULTS = ROOT / "results" / args.name
    RESULTS.mkdir(parents=True, exist_ok=True)
    RUNS.mkdir(exist_ok=True)
    if args.reanalyse:
        reanalyse_all(args.scale)
        print((RESULTS / "summary.md").read_text(encoding="utf-8"))
        return 0
    names = args.only or sorted(path.stem for path in SCENARIOS.glob("*.yaml"))
    subnets: Queue = Queue()
    for index in range(args.parallel):
        subnets.put(f"127.{index + 10}.0")
    with ThreadPoolExecutor(args.parallel) as pool:
        runs = list(pool.map(lambda name: run_one(name, subnets, args.scale), names))
    if args.only:
        fresh = {run["scenario"] for run in runs}
        previous = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
        runs += [run for run in previous if run["scenario"] not in fresh]
    write_summary(runs, args.scale)
    print((RESULTS / "summary.md").read_text(encoding="utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
