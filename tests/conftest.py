from pathlib import Path

import pytest

from flightcheck.plan import load_plan

SCENARIOS = Path(__file__).resolve().parent.parent / "scenarios"


@pytest.fixture
def scenario():
    def load(name: str):
        return load_plan(SCENARIOS / f"{name}.yaml")

    return load


def scenario_names(suffix: str) -> list[str]:
    return sorted(path.stem for path in SCENARIOS.glob(f"*-{suffix}.yaml"))
