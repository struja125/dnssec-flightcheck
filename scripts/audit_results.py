"""Audit a full run: failures against the raw predicted windows, with no timer or clock tolerance.

    .venv\\Scripts\\python scripts\\audit_results.py
"""

from __future__ import annotations

import json
from pathlib import Path

from flightcheck.plan import load_plan
from flightcheck.simulator import simulate

ROOT = Path(__file__).resolve().parent.parent


def hours(seconds: float) -> float:
    return round(seconds / 3600, 2)


def windows(plan, model: str) -> list[tuple[float, float]]:
    return [(s.start, s.end) for s in simulate(plan, model).segments if s.status == "bogus"]


def main() -> None:
    totals = {"lookups": 0, "failures": 0, "strict": 0, "before": 0, "after": 0, "good_plan_failures": 0}
    for path in sorted((ROOT / "netlab-all").glob("*/result.json")):
        name = path.parent.name
        data = json.loads(path.read_text(encoding="utf-8"))
        plan = load_plan(ROOT / "scenarios" / f"{name}.yaml")
        fetch = windows(plan, "fetch")
        for software in ("unbound", "bind"):
            samples = [s for s in data["samples"] if s["resolver"].startswith(software)]
            failures = [s for s in samples if s["status"] == "bogus" or s["rcode"] == "TIMEOUT"]
            strict = sum(any(a <= s["t"] < b for a, b in fetch) for s in failures)
            before = sum(1 for s in failures if fetch and s["t"] < fetch[0][0])
            totals["lookups"] += len(samples)
            totals["failures"] += len(failures)
            totals["strict"] += strict
            totals["before"] += before
            totals["after"] += len(failures) - strict - before
            if name.endswith("good"):
                totals["good_plan_failures"] += len(failures)
            if failures:
                spans = {}
                for sample in failures:
                    low, high, count = spans.get(sample["resolver"], (sample["t"], sample["t"], 0))
                    spans[sample["resolver"]] = (min(low, sample["t"]), max(high, sample["t"]), count + 1)
                print(f"{name} {software}: {len(failures)} failures, {strict} inside the raw fetch window, {before} before it")
                print(f"  fetch window {[(hours(a), hours(b)) for a, b in fetch]}")
                for resolver, (low, high, count) in sorted(spans.items()):
                    print(f"  {resolver}: {hours(low)}h -> {hours(high)}h, {count}")
    print(totals)

    data = json.loads((ROOT / "netlab-all/go-secure-good/result.json").read_text(encoding="utf-8"))
    plan = load_plan(ROOT / "scenarios/go-secure-good.yaml")
    print("go-secure-good model:", [(hours(s.start), hours(s.end), s.status) for s in simulate(plan, "fetch").segments])
    last = {}
    for sample in data["samples"]:
        if sample["status"] == "insecure":
            last[sample["resolver"]] = max(last.get(sample["resolver"], float("-inf")), sample["t"])
    print("go-secure-good last insecure answer:", {k: hours(v) for k, v in sorted(last.items())})


if __name__ == "__main__":
    main()
