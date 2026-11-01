"""Real-time runs: where each resolver's failures ended, compared with the prediction.

    .venv\\Scripts\\python scripts\\audit_realtime.py
"""

from __future__ import annotations

import json
from pathlib import Path

from flightcheck.lab.real import _tuned
from flightcheck.plan import load_plan
from flightcheck.simulator import simulate

ROOT = Path(__file__).resolve().parent.parent
TOLERANCE = 2.25  # one lookup interval plus the lookup timeout, in seconds


def inside(t: float, windows) -> bool:
    return any(a <= t <= b + TOLERANCE for a, b in windows)


def main() -> None:
    totals = {"lookups": 0, "failures": 0, "inside_without_timers": 0, "inside_with_timers": 0}
    for path in sorted(ROOT.glob("netlab-realtime*/*/result.json")):
        name = path.parent.name
        data = json.loads(path.read_text(encoding="utf-8"))
        plan = load_plan(ROOT / "scenarios" / "realtime" / f"{name}.yaml")
        print(f"{path.parent.parent.name} {name}")
        for software in ("unbound", "bind"):
            with_timers = simulate(_tuned(plan, software, 1), "fetch").failure_windows()
            without = simulate(_tuned(plan, software, 1, memory=False), "fetch").failure_windows()
            samples = [s for s in data["samples"] if s["resolver"].startswith(software)]
            failures = [s for s in samples if s["status"] == "bogus" or s["rcode"] == "TIMEOUT"]
            spans: dict[str, list[float]] = {}
            for sample in failures:
                spans.setdefault(sample["resolver"], []).append(sample["t"])
            good_without = sum(inside(s["t"], without) for s in failures)
            good_with = sum(inside(s["t"], with_timers) for s in failures)
            totals["lookups"] += len(samples)
            totals["failures"] += len(failures)
            totals["inside_without_timers"] += good_without
            totals["inside_with_timers"] += good_with
            timeouts = sum(1 for s in samples if s["rcode"] == "TIMEOUT")
            print(f"  {software}: window without timers {without}, with timers {with_timers}")
            print(f"    {len(samples)} lookups, {len(failures)} failures ({timeouts} timeouts), "
                  f"inside without timers {good_without}, with timers {good_with}")
            print("    per instance (first, last, count):",
                  {k: (round(min(v)), round(max(v)), len(v)) for k, v in sorted(spans.items())})
    print(totals)


if __name__ == "__main__":
    main()
