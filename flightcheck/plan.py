"""The change plan: keys, the initial state of the zone and the timed steps that change it.

A plan describes three kinds of RRsets:

* ``ds``      - the DS RRset at the parent (which keys it points to)
* ``dnskey``  - the DNSKEY RRset of the zone (which keys are published, which keys sign it)
* ``data:X``  - ordinary signed RRsets in the zone (which keys sign them)

Each step changes some of them at a moment relative to the start of the plan.
"""

from __future__ import annotations

import copy
import difflib
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

import yaml

from .durations import parse_duration, parse_start

ALGORITHMS = {
    "RSASHA1": 5,
    "RSASHA1-NSEC3-SHA1": 7,
    "RSASHA256": 8,
    "RSASHA512": 10,
    "ECDSAP256SHA256": 13,
    "ECDSAP384SHA384": 14,
    "ED25519": 15,
    "ED448": 16,
}
ALGORITHM_NAMES = {number: name for name, number in ALGORITHMS.items()}
ROLES = ("ksk", "zsk", "csk")
MODELS = ("conservative", "fetch")

# How long a resolver keeps a validation failure after the data has become valid, in seconds:
# (failed chain of trust, failed answer). Taken from the sources of the versions we measured.
# Unbound 1.26: BOGUS_KEY_TTL and val-bogus-ttl. BIND 9.16: DNS_RESOLVER_BADCACHETTL and servfail-ttl.
RESOLVER_PROFILES = {"worst": (60, 60), "unbound": (60, 60), "bind": (30, 1)}

DS = "ds"
DNSKEY = "dnskey"
DATA_PREFIX = "data:"

PLAN_FIELDS = (
    "name", "description", "zone", "start", "model", "delays", "resolver", "margin", "negative_ttl", "provenance",
    "keys", "initial", "steps",
)
PROVENANCE_FIELDS = ("coverage", "status", "snapshot", "observed", "unobserved", "assumptions", "keys")
COVERAGES = ("sampled", "complete")
DELAY_FIELDS = ("propagation", "registry", "parent_propagation")
RESOLVER_FIELDS = ("profile", "max_cache_ttl", "bogus_ttl", "key_failure_ttl", "strict_algorithms")
KEY_FIELDS = ("role", "algorithm", "standby")
STEP_FIELDS = ("name", "at", "ds", "dnskey", "data", "note")
MAX_DURATION = 100 * 365 * 86400  # beyond this a value is a typing error, and absolute times can overflow


class PlanError(ValueError):
    """The plan file is malformed."""


@dataclass(frozen=True)
class Key:
    name: str
    role: str
    algorithm: int
    standby: bool = False  # kept ready on purpose: its DNSKEY or DS may stay in place without being used

    @property
    def algorithm_name(self) -> str:
        return ALGORITHM_NAMES.get(self.algorithm, str(self.algorithm))


@dataclass(frozen=True)
class RRsetState:
    """What one version of an RRset contains.

    For ``ds`` only ``keys`` matters (the keys the DS records point to).
    For ``dnskey`` ``keys`` are the published keys and ``signed_by`` the keys whose RRSIGs cover the set.
    For data RRsets only ``signed_by`` matters.
    ``rrsig`` gives the (inception, expires) of a signer's RRSIG in plan seconds, either may be None.
    A signer without an entry is valid during the whole plan.
    """

    keys: frozenset[str] = frozenset()
    signed_by: frozenset[str] = frozenset()
    ttl: int = 3600
    rrsig: dict = field(default_factory=dict, hash=False)


@dataclass(frozen=True)
class Step:
    name: str
    at: int
    changes: dict  # rrset id -> dict of changed fields ("keys", "signed_by", "ttl")
    index: int = 0
    order: float = 0.0  # tie-breaker for steps at the same moment (the position in the plan)


@dataclass
class Plan:
    name: str
    zone: str
    keys: dict[str, Key]
    initial: dict[str, RRsetState]
    steps: list[Step]
    description: str = ""
    start: datetime | None = None
    model: str = "conservative"
    propagation: int = 0
    registry_delay: int = 0
    parent_propagation: int = 0
    max_cache_ttl: int = 7 * 86400
    bogus_ttl: int = 60  # how long a failed answer is kept
    key_failure_ttl: int = 60  # how long a failed chain of trust is kept
    profile: str = "worst"
    strict_algorithms: bool = False
    margin: int = 3600
    zone_negative_ttl: int | None = None  # min(SOA TTL, SOA MINIMUM) of the zone; None: same as the RRset's TTL
    parent_negative_ttl: int | None = None  # the same for the parent zone, which denies the DS
    coverage: str | None = None  # "sampled": built from part of a zone, so it can never be called safe for all of it
    source: dict = field(default_factory=dict, repr=False)

    @property
    def data_names(self) -> list[str]:
        return [rrset[len(DATA_PREFIX):] for rrset in self.initial if rrset.startswith(DATA_PREFIX)]

    @property
    def rrset_ids(self) -> list[str]:
        return [DS, DNSKEY] + [DATA_PREFIX + name for name in self.data_names]

    def with_profile(self, profile: str) -> "Plan":
        key_failure_ttl, bogus_ttl = RESOLVER_PROFILES[profile]
        return replace(self, profile=profile, key_failure_ttl=key_failure_ttl, bogus_ttl=bogus_ttl)

    def ordered_steps(self) -> list[Step]:
        return sorted(self.steps, key=lambda step: (step.at, step.order))

    def with_step_times(self, times: dict[int, int]) -> "Plan":
        """Copy of the plan with some steps (by index) moved to new times."""
        steps = [replace(step, at=times.get(step.index, step.at)) for step in self.steps]
        return replace(self, steps=steps)

    def only_steps(self, indices) -> "Plan":
        """Copy of the plan that keeps only the steps with the given indices."""
        keep = set(indices)
        return replace(self, steps=[step for step in self.steps if step.index in keep])

    def to_yaml(self) -> str:
        """Serialise the plan back to YAML (used to write a corrected plan)."""
        data = copy.deepcopy(self.source) if self.source else {}
        data["model"] = self.model
        if self.description:
            data["description"] = self.description
        data["steps"] = []
        for step in self.ordered_steps():
            entry = {"name": step.name, "at": _duration_text(step.at)}
            for rrset, change in step.changes.items():
                rendered = {}
                if "keys" in change:
                    rendered["keys"] = sorted(change["keys"])
                if "signed_by" in change:
                    rendered["signed_by"] = sorted(change["signed_by"])
                if "ttl" in change:
                    rendered["ttl"] = _duration_text(change["ttl"])
                if "rrsig" in change:
                    rendered["rrsig"] = {name: _rrsig_text(times) for name, times in change["rrsig"].items()}
                if rrset.startswith(DATA_PREFIX):
                    entry.setdefault("data", {})[rrset[len(DATA_PREFIX):]] = rendered
                else:
                    entry[rrset] = rendered
            data["steps"].append(entry)
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)


def _rrsig_text(times: tuple) -> dict:
    inception, expires = times
    text = {}
    if inception is not None:
        text["inception"] = _duration_text(inception)
    if expires is not None:
        text["expires"] = _duration_text(expires)
    return text


def _duration_text(seconds: int) -> str:
    if seconds == 0:
        return "0s"
    sign = "-" if seconds < 0 else ""
    rest = abs(int(seconds))
    out = ""
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        amount, rest = divmod(rest, size)
        if amount:
            out += f"{amount}{unit}"
    return sign + out


# ---------------------------------------------------------------------------
# Loading


def load_plan(path: str | Path) -> Plan:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise PlanError(f"{path}: cannot read the plan: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PlanError(f"{path}: invalid YAML: {exc}") from exc
    return plan_from_dict(data, origin=str(path))


def _mapping(value, where: str, optional: bool = False) -> dict:
    """``value`` as a mapping. With ``optional``, an empty section counts as an empty mapping."""
    if value is None and optional:
        return {}
    if not isinstance(value, dict):
        raise PlanError(f"{where}: must be a mapping, not {_shown(value)}")
    return value


def _shown(value) -> str:
    return "nothing" if value is None else repr(value)


def _check_fields(spec: dict, allowed, where: str, required=()) -> None:
    """Reject fields the plan format does not have, and require the ones it cannot do without."""
    for field_name in spec:
        if field_name not in allowed:
            close = difflib.get_close_matches(str(field_name), allowed, n=1)
            hint = f"did you mean '{close[0]}'? " if close else ""
            raise PlanError(f"{where}: unexpected field '{field_name}' ({hint}allowed: {', '.join(allowed)})")
    for field_name in required:
        if field_name not in spec:
            raise PlanError(f"{where}: missing required field '{field_name}'")


def _moment(value, where: str) -> int:
    """A signed duration, such as a time relative to T+0."""
    try:
        seconds = parse_duration(value)
    except ValueError as exc:
        raise PlanError(f"{where}: {exc}") from exc
    if abs(seconds) > MAX_DURATION:
        raise PlanError(f"{where}: {value!r} is out of range (at most 100 years)")
    return seconds


def _length(value, where: str) -> int:
    """A duration that cannot be negative, such as a TTL or a delay."""
    seconds = _moment(value, where)
    if seconds < 0:
        raise PlanError(f"{where}: must not be negative, got {value!r}")
    return seconds


def _optional_length(spec: dict, name: str, where: str) -> int | None:
    return _length(spec[name], where) if name in spec else None


def _parse_rrsig(raw, keys, where: str) -> dict:
    """{signer: (inception, expires)}. Times may be before T+0: a signature usually predates the plan."""
    rrsig = {}
    for name, spec in _mapping(raw, where).items():
        place = f"{where}.{name}"
        if str(name) not in keys:
            raise PlanError(f"{place}: unknown key {name}")
        _mapping(spec, place)
        _check_fields(spec, ("inception", "expires"), place)
        if not spec:
            raise PlanError(f"{place}: give 'inception', 'expires' or both")
        inception = _moment(spec["inception"], f"{place}.inception") if "inception" in spec else None
        expires = _moment(spec["expires"], f"{place}.expires") if "expires" in spec else None
        if inception is not None and expires is not None and inception >= expires:
            raise PlanError(f"{place}: the signature expires before it starts: {spec['inception']} -> {spec['expires']}")
        rrsig[str(name)] = (inception, expires)
    return rrsig


def _check_rrsig_signers(initial: dict, steps: list, origin: str) -> None:
    """A validity period for a key that does not sign this RRset would be silently ignored."""
    state = dict(initial)
    for rrset, value in initial.items():
        for name in value.rrsig:
            if name not in value.signed_by:
                raise PlanError(f"{origin}: initial: rrsig of {rrset} names {name}, which is not in its signed_by")
    for step in sorted(steps, key=lambda s: (s.at, s.index)):
        for rrset, change in step.changes.items():
            state[rrset] = apply_change(state[rrset], change)
            for name in change.get("rrsig", {}):
                if name not in state[rrset].signed_by:
                    raise PlanError(f"{origin}: step {step.index + 1}: rrsig of {rrset} names {name}, which is not in its signed_by")


def plan_from_dict(data, origin: str = "plan") -> Plan:
    if not isinstance(data, dict):
        raise PlanError(f"{origin}: the plan must be a mapping")
    _check_fields(data, PLAN_FIELDS, origin, required=("keys", "initial", "steps"))

    keys = _parse_keys(data.get("keys"), origin)
    initial = _parse_initial(data.get("initial"), keys, origin)
    resolver = _mapping(data.get("resolver"), f"{origin}: resolver", optional=True)
    delays = _mapping(data.get("delays"), f"{origin}: delays", optional=True)
    _check_fields(resolver, RESOLVER_FIELDS, f"{origin}: resolver")
    _check_fields(delays, DELAY_FIELDS, f"{origin}: delays")

    model = str(data.get("model", "conservative"))
    if model not in MODELS:
        raise PlanError(f"{origin}: model must be one of {', '.join(MODELS)}")

    raw_steps = data["steps"]
    if not isinstance(raw_steps, list):
        raise PlanError(f"{origin}: steps: must be a list of steps, not {_shown(raw_steps)}")
    data_names = [rrset[len(DATA_PREFIX):] for rrset in initial if rrset.startswith(DATA_PREFIX)]
    steps = []
    for index, raw in enumerate(raw_steps):
        steps.append(_parse_step(raw, index, keys, data_names, origin))
    _check_rrsig_signers(initial, steps, origin)

    negative_ttl = _mapping(data.get("negative_ttl"), f"{origin}: negative_ttl", optional=True)
    _check_fields(negative_ttl, ("zone", "parent"), f"{origin}: negative_ttl")

    coverage = None
    if "provenance" in data:
        provenance = _mapping(data["provenance"], f"{origin}: provenance")
        _check_fields(provenance, PROVENANCE_FIELDS, f"{origin}: provenance", required=("coverage",))
        coverage = provenance["coverage"]
        if coverage not in COVERAGES:
            raise PlanError(f"{origin}: provenance.coverage must be one of {', '.join(COVERAGES)}")

    profile = str(resolver.get("profile", "worst"))
    if profile not in RESOLVER_PROFILES:
        raise PlanError(f"{origin}: resolver.profile must be one of {', '.join(RESOLVER_PROFILES)}")
    default_key_ttl, default_bogus_ttl = RESOLVER_PROFILES[profile]

    strict_algorithms = resolver.get("strict_algorithms", False)
    if not isinstance(strict_algorithms, bool):
        raise PlanError(f"{origin}: resolver.strict_algorithms: must be true or false, not {_shown(strict_algorithms)}")

    zone = data.get("zone", "bank.test.")
    if not isinstance(zone, str) or not zone.strip("."):
        raise PlanError(f"{origin}: zone: must be a domain name, not {_shown(zone)}")
    if not zone.endswith("."):
        zone += "."

    try:
        start = parse_start(data.get("start"))
    except (ValueError, OverflowError) as exc:
        raise PlanError(f"{origin}: start: {exc}") from exc

    return Plan(
        name=str(data.get("name", Path(origin).stem)),
        description=str(data.get("description", "")).strip(),
        zone=zone,
        keys=keys,
        initial=initial,
        steps=steps,
        start=start,
        model=model,
        propagation=_length(delays.get("propagation", 0), f"{origin}: delays.propagation"),
        registry_delay=_length(delays.get("registry", 0), f"{origin}: delays.registry"),
        parent_propagation=_length(delays.get("parent_propagation", 0), f"{origin}: delays.parent_propagation"),
        max_cache_ttl=_length(resolver.get("max_cache_ttl", "7d"), f"{origin}: resolver.max_cache_ttl"),
        bogus_ttl=_length(resolver.get("bogus_ttl", default_bogus_ttl), f"{origin}: resolver.bogus_ttl"),
        key_failure_ttl=_length(resolver.get("key_failure_ttl", default_key_ttl), f"{origin}: resolver.key_failure_ttl"),
        profile=profile,
        strict_algorithms=strict_algorithms,
        margin=_length(data.get("margin", "1h"), f"{origin}: margin"),
        zone_negative_ttl=_optional_length(negative_ttl, "zone", f"{origin}: negative_ttl.zone"),
        parent_negative_ttl=_optional_length(negative_ttl, "parent", f"{origin}: negative_ttl.parent"),
        coverage=coverage,
        source=data,
    )


def _parse_algorithm(value, where: str) -> int:
    if isinstance(value, str) and not value.isdigit():
        if value.upper() not in ALGORITHMS:
            raise PlanError(f"{where}: unknown algorithm {value} (known: {', '.join(ALGORITHMS)})")
        return ALGORITHMS[value.upper()]
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise PlanError(f"{where}: must be an algorithm name or number, not {_shown(value)}")
    number = int(value)
    if number not in ALGORITHM_NAMES:
        raise PlanError(f"{where}: unknown algorithm {number} (known: {', '.join(map(str, sorted(ALGORITHM_NAMES)))})")
    return number


def _parse_keys(raw, origin) -> dict[str, Key]:
    if not isinstance(raw, dict) or not raw:
        raise PlanError(f"{origin}: 'keys' must list at least one key")
    keys = {}
    for name, spec in raw.items():
        where = f"{origin}: keys.{name}"
        _mapping(spec, where)
        _check_fields(spec, KEY_FIELDS, where, required=("role",))
        role = str(spec["role"]).lower()
        if role not in ROLES:
            raise PlanError(f"{origin}: key {name}: role must be one of {', '.join(ROLES)}")
        standby = spec.get("standby", False)
        if not isinstance(standby, bool):
            raise PlanError(f"{where}.standby: must be true or false, not {_shown(standby)}")
        keys[str(name)] = Key(str(name), role, _parse_algorithm(spec.get("algorithm", 13), f"{where}.algorithm"), standby)
    return keys


def _key_set(value, keys, where) -> frozenset[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise PlanError(f"{where}: must be a list of key names, not {_shown(value)}")
    names = frozenset(str(item) for item in value)
    unknown = names - set(keys)
    if unknown:
        raise PlanError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    return names


def _parse_initial(raw, keys, origin) -> dict[str, RRsetState]:
    where = f"{origin}: initial"
    _mapping(raw, where)
    _check_fields(raw, ("ds", "dnskey", "data"), where, required=("ds", "dnskey", "data"))
    ds = _mapping(raw["ds"], f"{where}.ds")
    dnskey = _mapping(raw["dnskey"], f"{where}.dnskey")
    # An unsigned zone says so with empty lists: a missing list is more likely a mistake.
    _check_fields(ds, ("keys", "ttl"), f"{where}.ds", required=("keys",))
    _check_fields(dnskey, ("keys", "signed_by", "ttl", "rrsig"), f"{where}.dnskey", required=("keys", "signed_by"))
    initial = {
        DS: RRsetState(
            keys=_key_set(ds["keys"], keys, f"{where}.ds.keys"),
            ttl=_length(ds.get("ttl", "1d"), f"{where}.ds.ttl"),
        ),
        DNSKEY: RRsetState(
            keys=_key_set(dnskey["keys"], keys, f"{where}.dnskey.keys"),
            signed_by=_key_set(dnskey["signed_by"], keys, f"{where}.dnskey.signed_by"),
            ttl=_length(dnskey.get("ttl", "1h"), f"{where}.dnskey.ttl"),
            rrsig=_parse_rrsig(dnskey.get("rrsig", {}), keys, f"{where}.dnskey.rrsig"),
        ),
    }
    data = raw["data"]
    if not isinstance(data, dict) or not data:
        raise PlanError(f"{origin}: initial.data must name at least one RRset (e.g. www)")
    for name, spec in data.items():
        if name == "*":
            raise PlanError(f"{origin}: '*' is only allowed in steps")
        place = f"{where}.data.{name}"
        _mapping(spec, place)
        _check_fields(spec, ("signed_by", "ttl", "rrsig"), place, required=("signed_by",))
        initial[DATA_PREFIX + str(name)] = RRsetState(
            signed_by=_key_set(spec["signed_by"], keys, f"{place}.signed_by"),
            ttl=_length(spec.get("ttl", "1h"), f"{place}.ttl"),
            rrsig=_parse_rrsig(spec.get("rrsig", {}), keys, f"{place}.rrsig"),
        )
    return initial


def _parse_change(spec, keys, where, allowed) -> dict:
    if not isinstance(spec, dict):
        raise PlanError(f"{where}: must be a mapping")
    _check_fields(spec, allowed, where)
    if not spec:
        raise PlanError(f"{where}: changes nothing (use: {', '.join(allowed)})")
    change = {}
    for field_name, value in spec.items():
        if field_name == "ttl":
            change["ttl"] = _length(value, f"{where}.ttl")
        elif field_name == "rrsig":
            change["rrsig"] = _parse_rrsig(value, keys, f"{where}.rrsig")
        else:
            change[field_name] = _key_set(value, keys, f"{where}.{field_name}")
    return change


def _parse_step(raw, index, keys, data_names, origin) -> Step:
    if not isinstance(raw, dict):
        raise PlanError(f"{origin}: step {index + 1} must be a mapping")
    where = f"{origin}: step {index + 1}"
    _check_fields(raw, STEP_FIELDS, where)
    if "at" not in raw:
        raise PlanError(f"{where}: missing 'at'")
    at = _moment(raw["at"], f"{where}.at")  # a step may come before T+0

    changes = {}
    if "ds" in raw:
        changes[DS] = _parse_change(raw["ds"], keys, f"{where}.ds", ("keys", "ttl"))
    if "dnskey" in raw:
        changes[DNSKEY] = _parse_change(raw["dnskey"], keys, f"{where}.dnskey", ("keys", "signed_by", "ttl", "rrsig"))
    if "data" in raw:
        data = raw["data"]
        if not isinstance(data, dict):
            raise PlanError(f"{where}.data: must map RRset names to changes")
        for name, spec in data.items():
            change = _parse_change(spec, keys, f"{where}.data.{name}", ("signed_by", "ttl", "rrsig"))
            targets = data_names if name == "*" else [str(name)]
            for target in targets:
                if target not in data_names:
                    raise PlanError(f"{where}.data: unknown RRset '{target}' (not in initial.data)")
                changes.setdefault(DATA_PREFIX + target, {}).update(change)
    if not changes:
        raise PlanError(f"{where}: the step changes nothing")
    return Step(
        name=str(raw.get("name", f"Step {index + 1}")), at=at, changes=changes, index=index, order=index
    )


def apply_change(state: RRsetState, change: dict) -> RRsetState:
    signed_by = change.get("signed_by", state.signed_by)
    # A key that stops signing takes its period with it, and one that starts signing has a new signature.
    rrsig = {name: times for name, times in {**state.rrsig, **change.get("rrsig", {})}.items() if name in signed_by}
    return RRsetState(
        keys=change.get("keys", state.keys),
        signed_by=signed_by,
        ttl=change.get("ttl", state.ttl),
        rrsig=rrsig,
    )
