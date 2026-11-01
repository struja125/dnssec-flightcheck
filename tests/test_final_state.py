"""Where a plan ends is checked separately from whether any moment of it gives a bogus answer."""

import pytest
import yaml

from flightcheck.cli import EXIT_INCOMPLETE, EXIT_UNSAFE, main
from flightcheck.plan import MODELS, plan_from_dict
from flightcheck.simulator import simulate


H = 3600
DAY = 86400
KEYS = {
    "K1": {"role": "ksk"},
    "K2": {"role": "ksk"},
    "Z1": {"role": "zsk"},
    "Z2": {"role": "zsk"},
    "R": {"role": "zsk", "algorithm": "RSASHA256"},
}


def plan(*steps, keys=None, **initial):
    state = {
        "ds": {"keys": ["K1"], "ttl": "1h"},
        "dnskey": {"keys": ["K1", "Z1"], "signed_by": ["K1"], "ttl": "1h"},
        "data": {"www": {"signed_by": ["Z1"], "ttl": "1h"}},
        **initial,
    }
    named = [{"name": f"step {i}", "at": at, **change} for i, (at, change) in enumerate(steps)]
    return {"zone": "bank.test.", "keys": keys or KEYS, "initial": state, "steps": named}


def codes(data, model=None) -> set:
    return {f.code for f in simulate(plan_from_dict(data), model).findings}


# (plan, finding, does any moment of it give a bogus answer?)
INCOMPLETE = {
    "DS for a key that is never published": (
        plan((0, {"ds": {"keys": ["K1", "K2"]}})),
        "ds-without-dnskey",
    ),
    "KSK rollover: old DS never removed": (
        plan(
            (0, {"ds": {"keys": ["K1", "K2"]}}),
            (DAY, {"dnskey": {"keys": ["K2", "Z1"], "signed_by": ["K2"]}}),
        ),
        "ds-without-dnskey",
    ),
    "KSK rollover: new key published but never signs": (
        plan(
            (0, {"ds": {"keys": ["K1", "K2"]}}),
            (DAY, {"dnskey": {"keys": ["K1", "K2", "Z1"]}}),
        ),
        "ds-key-not-signing",
    ),
    "DNSKEY RRset keeps a signature by a removed key": (
        plan((0, {"dnskey": {"keys": ["K1", "Z1"], "signed_by": ["K1", "K2"]}})),
        "signature-without-key",
    ),
    "data keeps a second signature by an unpublished key": (
        plan((0, {"data": {"www": {"signed_by": ["Z1", "Z2"]}}})),
        "signature-without-key",
    ),
    "ZSK rollover: new key published, never used": (
        plan((0, {"dnskey": {"keys": ["K1", "Z1", "Z2"]}})),
        "key-never-used",
    ),
    "ZSK rollover: old key never removed": (
        plan(
            (0, {"dnskey": {"keys": ["K1", "Z1", "Z2"]}}),
            (2 * H, {"data": {"*": {"signed_by": ["Z2"]}}}),
        ),
        "key-not-removed",
    ),
    "algorithm added without its signatures": (
        plan((0, {"dnskey": {"keys": ["K1", "Z1", "R"]}})),
        "algorithm-rule",
    ),
    "going secure without submitting the DS": (
        plan(
            (0, {"dnskey": {"keys": ["K1", "Z1"], "signed_by": ["K1"]}, "data": {"*": {"signed_by": ["Z1"]}}}),
            ds={"keys": [], "ttl": "1h"},
            dnskey={"keys": [], "signed_by": [], "ttl": "1h"},
            data={"www": {"signed_by": [], "ttl": "1h"}},
        ),
        "signed-without-ds",
    ),
    "going insecure without unsigning": (
        plan((0, {"ds": {"keys": []}})),
        "signed-without-ds",
    ),
}

# Plans that never give a bogus answer once they reach their end, but cannot get there by waiting.
BROKEN = {
    "DS only for a key that is never published": (plan((0, {"ds": {"keys": ["K2"]}})), "ds-without-dnskey"),
    "DNSKEY RRset signed by nothing that can be verified": (
        plan((0, {"dnskey": {"keys": ["K1", "Z1"], "signed_by": []}})),
        "ds-key-not-signing",
    ),
    "data signed by an unavailable ZSK": (
        plan((0, {"data": {"*": {"signed_by": ["Z2"]}}})),
        "signature-without-key",
    ),
    "KSK swapped, DS never updated": (
        plan((0, {"dnskey": {"keys": ["K2", "Z1"], "signed_by": ["K2"]}})),
        "ds-without-dnskey",
    ),
}


def test_incomplete_plan_has_no_bogus_answers_but_is_not_safe():
    for data, code in INCOMPLETE.values():
        for model in MODELS:
            result = simulate(plan_from_dict(data), model)
            assert result.ok and not result.safe and code in {f.code for f in result.findings}


def test_broken_plan_is_unsafe_and_says_what_is_missing():
    for data, code in BROKEN.values():
        for model in MODELS:
            result = simulate(plan_from_dict(data), model)
            assert not result.ok and code in {f.code for f in result.findings}


# ---- what stays valid


VALID_DOUBLE_DS = plan(
    (0, {"ds": {"keys": ["K1", "K2"]}}),
    (2 * H, {"dnskey": {"keys": ["K2", "Z1"], "signed_by": ["K2"]}}),
    (4 * H, {"ds": {"keys": ["K2"]}}),
)
VALID_PRE_PUBLISH = plan(
    (0, {"dnskey": {"keys": ["K1", "Z1", "Z2"]}}),
    (2 * H, {"data": {"*": {"signed_by": ["Z2"]}}}),
    (4 * H, {"dnskey": {"keys": ["K1", "Z2"]}}),
)


def test_intermediate_states_are_not_findings_but_the_same_state_at_the_end_is():
    # A DS for an unpublished key is the normal first step of a double-DS rollover.
    assert not codes(VALID_DOUBLE_DS)
    assert codes(plan((0, {"ds": {"keys": ["K1", "K2"]}}))) == {"ds-without-dnskey"}
    # The same holds for a published ZSK that is not used yet.
    assert not codes(VALID_PRE_PUBLISH)
    assert codes(plan((0, {"dnskey": {"keys": ["K1", "Z1", "Z2"]}}))) == {"key-never-used"}


def test_standby_key_may_stay_unused():
    keys = {**KEYS, "K2": {"role": "ksk", "standby": True}, "Z2": {"role": "zsk", "standby": True}}
    assert not codes(plan((0, {"ds": {"keys": ["K1", "K2"]}}), keys=keys))
    assert not codes(plan((0, {"dnskey": {"keys": ["K1", "Z1", "Z2"]}}), keys=keys))
    assert not codes(plan((0, {"dnskey": {"keys": ["K1", "K2", "Z1"]}}), (0, {"ds": {"keys": ["K1", "K2"]}}), keys=keys))


# ---- the fixer and the command line


def write(tmp_path, data):
    path = tmp_path / "plan.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("name", list(INCOMPLETE)[:1])
@pytest.mark.parametrize("model", ["conservative"])
def test_incomplete_plan_gets_its_own_exit_code_and_no_output(name, model, tmp_path, capsys):
    path = write(tmp_path, INCOMPLETE[name][0])
    saved = tmp_path / "fixed.yaml"
    saved.write_text("the previous plan\n", encoding="utf-8")
    assert main(["--no-color", "check", path, "--model", model]) == EXIT_INCOMPLETE
    out = capsys.readouterr().out
    assert "Verdict: INCOMPLETE" in out and "Missing:" in out and "Verdict: SAFE" not in out
    assert main(["--no-color", "fix", path, "--model", model, "--write", str(saved)]) == EXIT_INCOMPLETE
    captured = capsys.readouterr()
    assert "incomplete plan" in captured.err and "Missing:" in captured.err and "was not written" in captured.err
    assert "safe under both" not in captured.out + captured.err
    assert saved.read_text(encoding="utf-8") == "the previous plan\n"


def test_timing_problem_comes_before_the_final_state(tmp_path):
    # Swapped too early, and the old DS is never removed: unsafe is the more urgent answer.
    data = plan(
        (0, {"ds": {"keys": ["K1", "K2"]}}),
        (60, {"dnskey": {"keys": ["K2", "Z1"], "signed_by": ["K2"]}}),
    )
    assert main(["--no-color", "check", write(tmp_path, data)]) == EXIT_UNSAFE
