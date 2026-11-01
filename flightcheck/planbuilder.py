"""Turn a snapshot and the operator's intention into a candidate plan for ``check`` and ``fix``.

Four kinds of information end up in a plan, and ``provenance`` keeps them apart:

* observed: DS, DNSKEY, signatures and TTLs from the snapshot;
* assumed: delays, cache limits and the bound on the TTLs nobody looked at, from the operator;
* planned: the new key and the steps, which do not exist in DNS yet;
* missing: the rest of the zone, represented by one RRset with the operator's bound.

The builder refuses what it cannot state truthfully. It does not predict anything itself.
"""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import yaml

from .durations import parse_start
from .lab.zones import SERVER_1, SERVER_2
from .plan import ROLES, PlanError, _check_fields, _length, _mapping, _parse_algorithm

INPUT_FIELDS = ("replace", "new_key", "start", "delays", "margin", "resolver", "zone_ttl_bound", "roles")
REQUIRED_INPUTS = ("replace", "new_key", "start", "delays", "margin", "resolver")
DELAYS = ("propagation", "registry", "parent_propagation")
UNOBSERVED = "unobserved-records"
SEP_FLAG = 0x0001


def load_yaml(path: str) -> dict:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise PlanError(f"{path}: cannot read it: {exc}") from exc
    return _mapping(data, str(path))


def plan_text(plan: dict) -> str:
    return yaml.safe_dump(plan, sort_keys=False, allow_unicode=True)


def key_id(key: dict) -> str:
    """A name that follows from the key itself: key tags are only 16 bits, so two keys can share one."""
    digest = hashlib.sha256(f"{key['algorithm']}:{key['public_key']}".encode()).hexdigest()[:10]
    return f"key-{key['key_tag']}-{digest}"


# ---------------------------------------------------------------------------
# what the snapshot can be used for


def _check_snapshot(snapshot: dict, rollover: str) -> None:
    if snapshot.get("schema_version") != 1 or "completeness" not in snapshot:
        raise PlanError("this file is not a snapshot of a known version")
    status = snapshot["completeness"].get("status")
    if status not in ("partial", "complete"):
        raise PlanError(f"the snapshot is {status}: collect a consistent one before planning a change")
    if not snapshot.get("dnskey") or not snapshot.get("soa"):
        raise PlanError("the snapshot has no DNSKEY RRset or SOA: there is no signed zone to plan for")
    ds_status = (snapshot.get("ds") or {}).get("status")
    if ds_status in ("unknown", "absent_unproven"):
        # Treating this as an insecure zone would make every timing problem disappear from the prediction.
        raise PlanError(f"the DS state is {ds_status}: it cannot be assumed that the zone has no DS")
    if ds_status != "present":
        raise PlanError(f"a {rollover.upper()} rollover needs a DS, and this zone has none (DS state: {ds_status})")


def _check_inputs(inputs: dict) -> None:
    _check_fields(inputs, INPUT_FIELDS, "inputs")
    missing = [name for name in REQUIRED_INPUTS if name not in inputs]
    if missing:
        raise PlanError(f"inputs: missing required: {', '.join(missing)}")
    delays = _mapping(inputs["delays"], "inputs: delays")
    _check_fields(delays, DELAYS, "inputs: delays")
    missing = [name for name in DELAYS if name not in delays]
    if missing:
        raise PlanError(f"inputs: delays: missing required: {', '.join(missing)}")
    resolver = _mapping(inputs["resolver"], "inputs: resolver")
    if "max_cache_ttl" not in resolver and "profile" not in resolver:
        raise PlanError("inputs: resolver: give max_cache_ttl or profile")
    new_key = _mapping(inputs["new_key"], "inputs: new_key")
    _check_fields(new_key, ("algorithm", "public_key"), "inputs: new_key", required=("algorithm",))


# ---------------------------------------------------------------------------
# keys and signatures


def _signatures(rrsigs: list, published: list, start, where: str) -> dict:
    """{key id: {inception, expires}} in seconds from the plan's start. If one key signed twice, the longer one counts."""
    found: dict[str, dict] = {}
    for sig in rrsigs:
        signers = [k for k in published if k["key_tag"] == sig["key_tag"] and k["algorithm"] == sig["algorithm"]]
        if not signers:
            raise PlanError(f"{where}: signed by key tag {sig['key_tag']}, which is not in the DNSKEY RRset: finish that change first")
        if len(signers) > 1:
            raise PlanError(f"{where}: key tag {sig['key_tag']} belongs to {len(signers)} keys, so the signer cannot be told from the snapshot")
        times = {
            "inception": int((parse_start(sig["inception"]) - start).total_seconds()),
            "expires": int((parse_start(sig["expiration"]) - start).total_seconds()),
        }
        name = key_id(signers[0])
        if name not in found or times["expires"] > found[name]["expires"]:
            found[name] = times
    return found


def _role(key: dict, signs_dnskey: bool, signs_data: bool, confirmed: dict) -> tuple[str, str]:
    """The operator decides. Without that, only cases that flags and signatures leave no doubt about are accepted."""
    name = key_id(key)
    if name in confirmed:
        role = str(confirmed[name]).lower()
        if role not in ROLES:
            raise PlanError(f"inputs: roles: {name}: must be one of {', '.join(ROLES)}")
        return role, "confirmed by the operator"
    sep = bool(key["flags"] & SEP_FLAG)
    if sep and signs_dnskey and not signs_data:
        return "ksk", "SEP flag, signs only the DNSKEY RRset among the records observed"
    if not sep and not signs_dnskey:
        return "zsk", "no SEP flag, does not sign the DNSKEY RRset"
    raise PlanError(
        f"the role of {name} is not clear (flags {key['flags']}, signs DNSKEY: {signs_dnskey}, signs observed data: {signs_data}): "
        "confirm it under 'roles' in the inputs"
    )


def _observed_rrsets(snapshot: dict) -> list[dict]:
    """The signed RRsets seen at the zone's apex and the requested names, once each."""
    zone = snapshot["zone"]
    soa = {"name": zone, "type": "SOA", "ttl": snapshot["soa"]["ttl"], "rrsig": snapshot["soa"]["rrsig"]}
    candidates = [soa] + ([snapshot["ns"]] if snapshot.get("ns") else []) + list(snapshot.get("rrsets") or [])
    seen = {}
    for rrset in candidates:
        seen.setdefault((rrset["name"], rrset["type"]), rrset)
    return list(seen.values())


def _label(name: str, rdtype: str, zone: str) -> str:
    relative = "apex" if name == zone else name[: -len(zone) - 1].replace("*", "wildcard")
    # A transfer from the lab also sees the lab's own server names, and a data RRset must not replace their addresses.
    if relative in (SERVER_1, SERVER_2):
        return f"{relative}-{rdtype}"
    return relative if rdtype == "A" and name != zone else f"{relative}-{rdtype}"


# ---------------------------------------------------------------------------
# the plan


def _initial_state(snapshot: dict, inputs: dict, start) -> tuple[dict, dict, dict, list]:
    published = snapshot["dnskey"]["keys"]
    names = {key["public_key"]: key_id(key) for key in published}
    if len(set(names.values())) != len(published):
        raise PlanError("the DNSKEY RRset has the same key twice")
    ds_keys = []
    for record in snapshot["ds"]["records"]:
        matches = record["matches_public_keys"]
        if not matches:
            raise PlanError(f"a DS (key tag {record['key_tag']}) points to no published key: finish that change first")
        ds_keys.append(names[matches[0]])

    dnskey_rrsig = _signatures(snapshot["dnskey"]["rrsig"], published, start, "DNSKEY RRset")
    data = {}
    observed = []
    for rrset in _observed_rrsets(snapshot):
        where = f"{rrset['name']} {rrset['type']}"
        rrsig = _signatures(rrset["rrsig"], published, start, where)
        data[_label(rrset["name"], rrset["type"], snapshot["zone"])] = {"signed_by": sorted(rrsig), "ttl": rrset["ttl"], "rrsig": rrsig}
        observed.append({"name": rrset["name"], "type": rrset["type"], "ttl": rrset["ttl"]})

    if snapshot["completeness"]["status"] == "partial":
        if "zone_ttl_bound" not in inputs:
            raise PlanError(
                "inputs: missing required: zone_ttl_bound. The snapshot saw only some RRsets, so give the longest TTL any "
                "other RRset of the zone can have"
            )
        bound = _length(inputs["zone_ttl_bound"], "inputs: zone_ttl_bound")
        longest = max(entry["ttl"] for entry in data.values())
        if bound < longest:
            raise PlanError(f"inputs: zone_ttl_bound is {bound} s, but an observed RRset has a TTL of {longest} s")
        signers = sorted({name for entry in data.values() for name in entry["signed_by"]})
        data[UNOBSERVED] = {"signed_by": signers, "ttl": bound}

    initial = {
        "ds": {"keys": sorted(ds_keys), "ttl": snapshot["ds"]["ttl"]},
        "dnskey": {
            "keys": sorted(names.values()),
            "signed_by": sorted(dnskey_rrsig),
            "ttl": snapshot["dnskey"]["ttl"],
            "rrsig": dnskey_rrsig,
        },
        "data": data,
    }
    signing_data = {name for entry in data.values() for name in entry["signed_by"]}
    confirmed = inputs.get("roles") or {}
    for name in confirmed:
        if name not in names.values():
            raise PlanError(f"inputs: roles: {name} is not a key of this zone (keys: {', '.join(sorted(names.values()))})")
    keys, key_sources = {}, {}
    for key in published:
        name = key_id(key)
        role, why = _role(key, name in dnskey_rrsig, name in signing_data, confirmed)
        keys[name] = {"role": role, "algorithm": key["algorithm"]}
        key_sources[name] = {
            "source": "published, from the snapshot",
            "key_tag": key["key_tag"],
            "flags": key["flags"],
            "algorithm": key["algorithm"],
            "public_key": key["public_key"],
            "role_from": why,
        }
    return keys, initial, key_sources, observed


def _new_key(inputs: dict, role: str) -> tuple[str, dict, dict]:
    spec = inputs["new_key"]
    algorithm = _parse_algorithm(spec["algorithm"], "inputs: new_key.algorithm")
    if "public_key" in spec:
        name = key_id({"key_tag": "new", "algorithm": algorithm, "public_key": str(spec["public_key"])})
        source = {"source": "planned, public key given by the operator; not published yet", "public_key": str(spec["public_key"])}
    else:
        name = f"new-{role}-placeholder"
        source = {"source": "planned placeholder; there is no real key yet, and it is not published"}
    return name, {"role": role, "algorithm": algorithm}, {**source, "algorithm": algorithm, "role_from": "the operator's intention"}


def _replaceable(inputs: dict, keys: dict, role: str, new_algorithm: int) -> str:
    replaced = str(inputs["replace"])
    if replaced not in keys:
        listed = ", ".join(f"{name} ({keys[name]['role']})" for name in sorted(keys))
        raise PlanError(f"inputs: replace: {replaced} is not a key of this zone (keys: {listed})")
    if keys[replaced]["role"] != role:
        raise PlanError(f"inputs: replace: {replaced} is a {keys[replaced]['role'].upper()}, not a {role.upper()}")
    if keys[replaced]["algorithm"] != new_algorithm:
        raise PlanError("inputs: new_key: another algorithm is an algorithm rollover, which this builder does not generate")
    return replaced


def _swap(names: list, old: str, new: str) -> list:
    return sorted((set(names) - {old}) | {new})


def _ksk_steps(initial: dict, old: str, new: str, seconds: dict) -> list:
    """Double-DS (RFC 7583): both DS records first, then the new key, and the old DS last."""
    ds, dnskey = initial["ds"], initial["dnskey"]
    if old not in ds["keys"] or old not in dnskey["signed_by"]:
        raise PlanError(f"inputs: replace: {old} is not in the DS RRset or does not sign the DNSKEY RRset")
    swap_at = seconds["registry"] + seconds["parent_propagation"] + ds["ttl"] + seconds["margin"]
    remove_at = swap_at + dnskey["ttl"] + seconds["propagation"] + seconds["registry"] + seconds["margin"]
    return [
        {"name": f"Submit the DS for {new}", "at": 0, "ds": {"keys": sorted(ds["keys"] + [new])}},
        {
            "name": f"Replace {old} with {new} in the DNSKEY RRset",
            "at": swap_at,
            "dnskey": {"keys": _swap(dnskey["keys"], old, new), "signed_by": _swap(dnskey["signed_by"], old, new)},
        },
        {"name": f"Remove the DS for {old}", "at": remove_at, "ds": {"keys": sorted(set(ds["keys"]) - {old} | {new})}},
    ]


def _zsk_steps(initial: dict, old: str, new: str, seconds: dict) -> list:
    """Pre-publish (RFC 7583): publish the new key, sign with it once it is known, and remove the old key last."""
    dnskey = initial["dnskey"]
    signed = {name: spec for name, spec in initial["data"].items() if old in spec["signed_by"]}
    if not signed:
        raise PlanError(f"inputs: replace: {old} signs none of the observed records")
    sign_at = dnskey["ttl"] + seconds["propagation"] + seconds["margin"]
    remove_at = sign_at + max(spec["ttl"] for spec in signed.values()) + seconds["propagation"] + seconds["margin"]
    return [
        {"name": f"Publish {new}", "at": 0, "dnskey": {"keys": sorted(dnskey["keys"] + [new])}},
        {
            "name": f"Sign with {new} instead of {old}",
            "at": sign_at,
            "data": {name: {"signed_by": _swap(spec["signed_by"], old, new)} for name, spec in signed.items()},
        },
        {"name": f"Remove {old}", "at": remove_at, "dnskey": {"keys": _swap(dnskey["keys"] + [new], old, new)}},
    ]


def build_plan(snapshot: dict, rollover: str, inputs: dict) -> dict:
    """The plan as data, ready for the same parser that reads every other plan."""
    _check_snapshot(snapshot, rollover)
    _check_inputs(inputs)
    try:
        start = parse_start(inputs["start"])
        collected = parse_start(snapshot["collected_at"])
    except (ValueError, OverflowError, KeyError) as exc:
        raise PlanError(f"inputs: start: {exc}") from exc
    if start < collected:
        raise PlanError("inputs: start is before the snapshot was taken, so the snapshot does not describe that moment")

    keys, initial, key_sources, observed = _initial_state(snapshot, inputs, start)
    new_name, new_spec, new_source = _new_key(inputs, rollover)
    if new_name in keys:
        raise PlanError(f"inputs: new_key: {new_name} is already in the zone")
    old = _replaceable(inputs, keys, rollover, new_spec["algorithm"])
    keys[new_name] = new_spec
    key_sources[new_name] = new_source

    seconds = {name: _length(inputs["delays"][name], f"inputs: delays.{name}") for name in DELAYS}
    seconds["margin"] = _length(inputs["margin"], "inputs: margin")
    steps = (_ksk_steps if rollover == "ksk" else _zsk_steps)(initial, old, new_name, seconds)

    partial = snapshot["completeness"]["status"] == "partial"
    plan = {
        "name": f"{rollover.upper()} rollover of {snapshot['zone']} (candidate)",
        "description": "Generated from a snapshot. A candidate for 'check' and 'fix', not an approved schedule.",
        "zone": snapshot["zone"],
        "start": inputs["start"],
        "delays": inputs["delays"],
        "resolver": inputs["resolver"],
        "margin": inputs["margin"],
        "negative_ttl": {"zone": snapshot["soa"]["negative_ttl"]},
        "provenance": {
            "coverage": "sampled" if partial else "complete",
            "status": "candidate: not approved, and nothing here has been done in DNS",
            "snapshot": {
                "collected_at": snapshot["collected_at"],
                "method": snapshot.get("method"),
                "completeness": snapshot["completeness"],
                "sources": snapshot.get("sources"),
            },
            "observed": observed,
            "unobserved": f"every other RRset, represented by {UNOBSERVED} with the operator's TTL bound" if partial else "none",
            # A copy: the same object twice would appear in the YAML as an anchor and an alias.
            "assumptions": copy.deepcopy({name: inputs[name] for name in ("delays", "margin", "resolver", "zone_ttl_bound") if name in inputs}),
            "keys": key_sources,
        },
        "keys": keys,
        "initial": initial,
        "steps": steps,
    }
    return plan
