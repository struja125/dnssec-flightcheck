"""Snapshot by zone transfer, only when the operator asks for it with ``snapshot --axfr``.

Ordinary snapshots stay in snapshot.py. This one gives the same YAML sections, so the plan builder reads both.
A transfer only asks servers the operator named, and a failed one is reported: it never turns into ordinary
queries. The DS is not in the child zone, so it is still asked from the parent.

``completeness.status`` is ``complete`` only if every part of the evidence is there:

    failed        no server finished a transfer
    inconsistent  servers transferred different zones
    partial       a transfer finished, but a server failed or was not asked, the DS state is not known,
                  or a record that should be signed has no signature
    complete      as many matching transfers as the zone has NS records, a known DS state, and signatures present

``transfer`` says what is known about each part. Signatures are kept, but not checked cryptographically.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.tsigkeyring
import dns.xfr
import dns.zone
import yaml

from .plan import PlanError
from .snapshot import SCHEMA_VERSION, _ask, _ds_section, _key_data, _rrset_data, _soa_section, query_server

TIMEOUT = 10.0  # seconds without any data from the server
LIFETIME = 120.0  # seconds for one whole transfer, which also limits how much a server can send
APEX = (dns.rdatatype.SOA, dns.rdatatype.NS, dns.rdatatype.DNSKEY)  # these have their own sections
DENIAL = (dns.rdatatype.NSEC, dns.rdatatype.NSEC3)
USABLE_DS = ("present", "absent_signed_denial")


def load_tsig(path: str) -> dict:
    """The key from a YAML file: name, secret, and optionally algorithm. The secret stays out of errors and output."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        name, secret = data["name"], data["secret"]
        algorithm = dns.name.from_text(data.get("algorithm", "hmac-sha256"))
        return {"keyring": dns.tsigkeyring.from_text({name: (algorithm, secret)}), "keyname": name, "algorithm": algorithm}
    except OSError as exc:
        raise PlanError(f"{path}: cannot read the TSIG file: {type(exc).__name__}") from None
    except (yaml.YAMLError, UnicodeDecodeError, KeyError, TypeError, AttributeError, ValueError, dns.exception.DNSException):
        raise PlanError(f"{path}: the TSIG file needs a valid name and a base64 secret, and optionally algorithm") from None


def transfer_zone(server: str, zone: dns.name.Name, tsig: dict | None = None, port: int = 53, timeout: float = TIMEOUT, lifetime: float = LIFETIME) -> dns.zone.Zone:
    """One whole AXFR over TCP. dnspython reads every message, and raises if the end is not a matching SOA."""
    keys = {"keyring": tsig["keyring"], "keyname": tsig["keyname"], "keyalgorithm": tsig["algorithm"]} if tsig else {}
    messages = dns.query.xfr(server, zone, port=port, timeout=timeout, lifetime=lifetime, relativize=False, **keys)
    return dns.zone.from_xfr(_only_this_zone(messages, zone), relativize=False, check_origin=False)


def _only_this_zone(messages, zone: dns.name.Name):
    """dnspython rejects records from outside the zone or silently drops them, depending on its version. Reject them always."""
    for message in messages:
        for rrset in message.answer:
            if not rrset.name.is_subdomain(zone):
                raise dns.exception.FormError(f"{rrset.name} is outside the zone")
        yield message


def _attempt(transfer, server: str, zone: dns.name.Name, tsig: dict | None) -> dict:
    """What came of one transfer. Only a finished, usable one has a ``zone``."""
    result = {"server": server, "status": "ok", "detail": "", "zone": None}
    try:
        transferred = transfer(server, zone, tsig)
    except dns.xfr.TransferError as exc:
        refused = exc.rcode in (dns.rcode.REFUSED, dns.rcode.NOTAUTH)
        return {**result, "status": "refused" if refused else "error", "detail": dns.rcode.to_text(exc.rcode)}
    except dns.exception.Timeout:
        return {**result, "status": "timeout"}
    except EOFError:
        return {**result, "status": "incomplete", "detail": "the connection ended before the final SOA"}
    except (dns.exception.DNSException, KeyError, ValueError) as exc:
        return {**result, "status": "malformed", "detail": type(exc).__name__}
    except OSError as exc:
        return {**result, "status": "unreachable", "detail": type(exc).__name__}
    if transferred.get_rdataset(zone, dns.rdatatype.SOA) is None or transferred.get_rdataset(zone, dns.rdatatype.NS) is None:
        return {**result, "status": "malformed", "detail": "no SOA or NS at the zone's apex"}
    return {**result, "zone": transferred}


def _sorted_rrsets(transferred: dns.zone.Zone) -> tuple[dict, dict]:
    """({(name, type): RRset}, {(name, covered type): RRSIG RRset}), so each signature stays with what it covers."""
    rrsets, sigs = {}, {}
    for name, rdataset in sorted(transferred.iterate_rdatasets(), key=lambda item: (item[0], item[1].rdtype, item[1].covers)):
        rrset = dns.rrset.from_rdata_list(name, rdataset.ttl, list(rdataset))
        if rdataset.rdtype == dns.rdatatype.RRSIG:
            sigs[(name, rdataset.covers)] = rrset
        else:
            rrsets[(name, rdataset.rdtype)] = rrset
    return rrsets, sigs


def _fingerprint(transferred: dns.zone.Zone) -> tuple[dict, dict]:
    """What servers must agree on, and the signature times, which servers that sign for themselves may not share."""
    rrsets, sigs = _sorted_rrsets(transferred)
    same = {}
    for key, rrset in rrsets.items():
        signers = sorted((sig.signer.to_text(), sig.key_tag, int(sig.algorithm)) for sig in sigs.get(key, ()))
        same[key] = (rrset.ttl, sorted(rdata.to_text() for rdata in rrset), signers)
    times = {key: sorted((sig.key_tag, sig.inception, sig.expiration) for sig in rrsig) for key, rrsig in sigs.items()}
    return same, times


def _label(key: tuple) -> str:
    return f"{key[0].to_text()} {dns.rdatatype.to_text(key[1])}"


def _compare(transfers: list[dict]) -> tuple[list[str], list[str]]:
    """(disagreements, warnings) of every finished transfer against the first. A matching serial proves nothing by itself."""
    disagreements, warnings = [], []
    first = transfers[0]
    same, times = _fingerprint(first["zone"])
    for other in transfers[1:]:
        between = f"{first['server']} and {other['server']}"
        other_same, other_times = _fingerprint(other["zone"])
        differing = [key for key in sorted(set(same) | set(other_same)) if same.get(key) != other_same.get(key)]
        if differing:
            names = ", ".join(_label(key) for key in differing[:10])
            more = f" and {len(differing) - 10} more" if len(differing) > 10 else ""
            disagreements.append(f"{between} transferred different records: {names}{more}")
        if times != other_times:
            warnings.append(f"{between} hold different signature times")
    return disagreements, warnings


def _below_cut(name: dns.name.Name, cuts: set) -> bool:
    return any(name.is_subdomain(cut) for cut in cuts)


def _sections(transfer: dict, zone: dns.name.Name) -> dict:
    """The records of one transfer, in the snapshot's sections. Nothing is dropped: each RRset ends up in one of them."""
    rrsets, sigs = _sorted_rrsets(transfer["zone"])
    cuts = {name for name, rdtype in rrsets if rdtype == dns.rdatatype.NS and name != zone}
    sections = {"rrsets": [], "denial_rrsets": [], "unsigned_rrsets": [], "unsigned_in_zone": []}
    for key, rrset in rrsets.items():
        name, rdtype = key
        if name == zone and rdtype in APEX:
            continue
        data = _rrset_data({"server": transfer["server"], "rrset": rrset, "sigs": sigs.get(key)})
        if rdtype in DENIAL:
            sections["denial_rrsets"].append(data)
        elif key in sigs:
            sections["rrsets"].append(data)
        else:
            sections["unsigned_rrsets"].append(data)
            # A delegation and its glue are unsigned by design. Anything else is missing evidence.
            if not _below_cut(name, cuts):
                sections["unsigned_in_zone"].append(_label(key))
    sections["orphan_signatures"] = [_label(key) for key in sigs if key not in rrsets]
    sections["answer"] = lambda rdtype: {"status": "ok", "server": transfer["server"], "rrset": rrsets.get((zone, rdtype)), "sigs": sigs.get((zone, rdtype))}
    return sections


def _transfer_row(transfer: dict) -> dict:
    row = {"server": transfer["server"], "status": transfer["status"]}
    if transfer["detail"]:
        row["detail"] = transfer["detail"]
    if transfer["zone"] is not None:
        rrsets, sigs = _sorted_rrsets(transfer["zone"])
        row.update(
            serial=transfer["zone"].get_rdataset(transfer["zone"].origin, dns.rdatatype.SOA)[0].serial,
            rrsets=len(rrsets) + len(sigs),
            records=sum(len(r) for r in [*rrsets.values(), *sigs.values()]),
        )
    return row


def _failed_result(zone, child_servers, parent_servers, now, rows, errors) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "zone": zone.to_text(),
        "collected_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "axfr",
        "sources": {"child": list(child_servers), "parent": list(parent_servers), "server_list": "given by the operator"},
        "completeness": {"status": "failed", "meaning": "no server finished a zone transfer", "scope": "nothing was collected"},
        "transfer": {"zone": zone.to_text(), "status": "failed", "servers": rows},
        "warnings": [],
        "errors": errors,
    }


def collect_axfr_snapshot(
    zone: dns.name.Name,
    child_servers: list[str],
    parent_servers: list[str],
    tsig: dict | None = None,
    transfer=None,
    ask=None,
    now: datetime | None = None,
) -> dict:
    """Transfer from every named server, and describe the first finished transfer. ``transfer`` and ``ask`` are replaceable for tests."""
    transfer = transfer or transfer_zone
    ask = ask or query_server
    now = now or datetime.now(timezone.utc)
    attempts = [_attempt(transfer, server, zone, tsig) for server in child_servers]
    finished = [a for a in attempts if a["zone"] is not None]
    rows = [_transfer_row(a) for a in attempts]
    errors = [
        f"{zone.to_text()} AXFR at {a['server']}: {a['status']}" + (f" ({a['detail']})" if a["detail"] else "")
        for a in attempts
        if a["zone"] is None
    ]
    if not finished:
        return _failed_result(zone, child_servers, parent_servers, now, rows, errors)

    disagreements, warnings = _compare(finished)
    sections = _sections(finished[0], zone)
    answer = sections["answer"]
    # One answer per finished server, so the SOA section can list every serial.
    soa_answers = []
    for attempt in finished:
        rrsets, sigs = _sorted_rrsets(attempt["zone"])
        soa_answers.append({"status": "ok", "server": attempt["server"], "rrset": rrsets[(zone, dns.rdatatype.SOA)], "sigs": sigs.get((zone, dns.rdatatype.SOA))})
    dnskey = answer(dns.rdatatype.DNSKEY)
    if dnskey["rrset"] is None:
        warnings.append("the transferred zone has no DNSKEY RRset: the zone may be unsigned")
        dnskey = None
    if not parent_servers:
        warnings.append("no parent server was asked, so nothing is known about the DS")
    parent = [_ask(ask, server, zone, dns.rdatatype.DS) for server in parent_servers]
    errors += [f"{a['name']} {a['type']} at {a['server']}: {a['status']}" for a in parent if a["status"] not in ("ok", "nodata", "nxdomain")]
    ds = _ds_section(ask, parent, zone, dnskey, now.timestamp(), warnings)

    unsigned = sections["unsigned_in_zone"]
    if dnskey and unsigned:
        warnings.append("signed zone, but these RRsets have no signature: " + ", ".join(unsigned))
    if sections["orphan_signatures"]:
        warnings.append("signatures for RRsets that were not transferred: " + ", ".join(sections["orphan_signatures"]))
    evidence_ok = bool(dnskey) and not unsigned and not sections["orphan_signatures"]

    ns = answer(dns.rdatatype.NS)
    enough_servers = len(finished) == len(attempts) and len(finished) >= len(ns["rrset"])
    cross_server = "inconsistent" if disagreements else "consistent" if enough_servers else "unverified"
    if cross_server == "unverified":
        warnings.append(f"only {len(finished)} of the zone's {len(ns['rrset'])} name servers gave a transfer that could be compared")

    if disagreements:
        status, meaning = "inconsistent", "authoritative servers transferred different zones"
    elif cross_server == "consistent" and ds["status"] in USABLE_DS and evidence_ok:
        status, meaning = "complete", "every RRset was transferred, matching servers agree, and the DS state is known"
    else:
        status, meaning = "partial", "the transfer finished, but other evidence is missing: see 'transfer'"

    return {
        "schema_version": SCHEMA_VERSION,
        "zone": zone.to_text(),
        "collected_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "axfr",
        "sources": {"child": list(child_servers), "parent": list(parent_servers), "server_list": "given by the operator"},
        "completeness": {
            "status": status,
            "meaning": meaning,
            "scope": f"the whole zone as {finished[0]['server']} transferred it, and the DS from the parent",
        },
        "transfer": {
            "zone": zone.to_text(),
            "status": "complete",
            "source": finished[0]["server"],
            "servers": rows,
            "parent_ds_collected": ds["status"] in USABLE_DS,
            "cross_server": cross_server,
            "dnssec_validation": "not performed: signatures are recorded, not verified",
        },
        "soa": _soa_section(soa_answers),
        "ns": _rrset_data(ns),
        "dnskey": (
            {
                "ttl": dnskey["rrset"].ttl,
                "keys": [_key_data(rdata) for rdata in dnskey["rrset"]],
                "rrsig": _rrset_data(dnskey)["rrsig"],
                "server": dnskey["server"],
            }
            if dnskey
            else None
        ),
        "ds": ds,
        "rrsets": sections["rrsets"],
        "denial_rrsets": sections["denial_rrsets"],
        "unsigned_rrsets": sections["unsigned_rrsets"],
        "answers": [{"server": a["server"], "name": zone.to_text(), "type": "AXFR", "status": a["status"]} for a in attempts]
        + [{"server": a["server"], "name": a["name"], "type": a["type"], "status": a["status"]} for a in parent],
        "warnings": warnings + disagreements,
        "errors": errors,
    }
