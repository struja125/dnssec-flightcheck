"""Read-only snapshot of what a zone publishes now, asked directly from its authoritative servers.

A snapshot is a record of observations, not a plan: it has no steps, and nothing here decides what a
key is for. It only sends ordinary queries, so it never transfers or changes a zone. Answers are
untrusted: they are stored as text after being parsed, and nothing in them is acted upon.

A snapshot from queries sees only the names it asked for, so it is never ``complete``. See COMPLETENESS.
"""

from __future__ import annotations

import base64
import ipaddress
from datetime import datetime, timezone

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import yaml

from .lab.resolver import INSECURE, Verifier, _ds_matches, _find
from .plan import PlanError

SCHEMA_VERSION = 1
TIMEOUT = 3.0  # seconds per query; there are no retries, so a dead server costs little
MAX_SERVERS = 4
MAX_QUERIES = 100
# Zone transfers are never asked for, and the others are not records a zone publishes.
NOT_COLLECTED = (dns.rdatatype.AXFR, dns.rdatatype.IXFR, dns.rdatatype.ANY, dns.rdatatype.OPT, dns.rdatatype.TSIG, dns.rdatatype.TKEY)

COMPLETENESS = {
    # Reserved for a source that sees a whole zone, such as a zone file. Queries can never establish it.
    "complete": "every RRset of the zone was seen",
    "partial": "only the apex, the DS and the requested names were asked, or some answers are missing",
    "inconsistent": "authoritative servers gave different answers",
    "failed": "no authoritative server gave the zone's SOA",
}
ANSWERS = ("ok", "nodata", "nxdomain")  # a server said something about the zone; other statuses are collection errors


# ---------------------------------------------------------------------------
# what the user asks for


def parse_zone(text: str) -> dns.name.Name:
    try:
        zone = dns.name.from_text(text)
    except dns.exception.DNSException as exc:
        raise PlanError(f"{text}: not a valid zone name: {exc}") from exc
    if zone == dns.name.root:
        raise PlanError("the root zone has no parent to ask for a DS")
    return zone


def parse_server(text: str) -> str:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise PlanError(f"{text}: give the server's IP address") from None


def parse_query(text: str, zone: dns.name.Name) -> tuple[dns.name.Name, int]:
    """NAME/TYPE, or NAME for its A records. Only names inside the zone: those are the servers we were told to ask."""
    name_text, _, type_text = text.partition("/")
    try:
        name = dns.name.from_text(name_text)
        rdtype = dns.rdatatype.from_text(type_text or "A")
    except (dns.exception.DNSException, dns.rdatatype.UnknownRdatatype) as exc:
        raise PlanError(f"{text}: expected NAME/TYPE: {exc}") from exc
    if not name.is_subdomain(zone):
        raise PlanError(f"{text}: this name is not in {zone}")
    if rdtype in NOT_COLLECTED:
        raise PlanError(f"{text}: {dns.rdatatype.to_text(rdtype)} is not a record type that can be collected")
    return name, rdtype


# ---------------------------------------------------------------------------
# asking one server


def query_server(server: str, name, rdtype, port: int = 53, timeout: float = TIMEOUT) -> dns.message.Message:
    """One non-recursive query with DNSSEC records; a truncated answer is asked again over TCP."""
    query = dns.message.make_query(name, rdtype, want_dnssec=True, use_edns=0, payload=1232)
    query.flags &= ~dns.flags.RD
    response, _ = dns.query.udp_with_fallback(query, server, timeout=timeout, port=port)
    return response


def _ask(ask, server: str, name, rdtype) -> dict:
    answer = {"server": server, "name": name.to_text(), "type": dns.rdatatype.to_text(rdtype), "status": "", "detail": ""}
    answer.update(response=None, rrset=None, sigs=None)
    try:
        response = ask(server, name, rdtype)
    except dns.exception.Timeout:
        return {**answer, "status": "timeout"}
    except (dns.exception.DNSException, ValueError) as exc:
        return {**answer, "status": "malformed", "detail": type(exc).__name__}
    except OSError as exc:
        return {**answer, "status": "unreachable", "detail": type(exc).__name__}

    answer["response"] = response
    rcode = response.rcode()
    if rcode == dns.rcode.REFUSED:
        return {**answer, "status": "refused"}
    if rcode == dns.rcode.SERVFAIL:
        return {**answer, "status": "servfail"}
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return {**answer, "status": "error", "detail": dns.rcode.to_text(rcode)}
    if not response.flags & dns.flags.AA:
        # This may be a cached answer, or a referral: either way it is not what the zone publishes.
        return {**answer, "status": "not_authoritative"}
    if rcode == dns.rcode.NXDOMAIN:
        return {**answer, "status": "nxdomain"}
    rrset = _find(response.answer, name, rdtype)
    if rrset is None:
        if response.answer:
            return {**answer, "status": "malformed", "detail": "the answer does not contain the requested RRset"}
        return {**answer, "status": "nodata"}
    sigs = _find(response.answer, name, dns.rdatatype.RRSIG, covers=rdtype)
    return {**answer, "status": "ok", "rrset": rrset, "sigs": sigs}


# ---------------------------------------------------------------------------
# records as plain data


def _time(seconds: int) -> str:
    return datetime.fromtimestamp(seconds, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rrsig_data(sigs) -> list[dict]:
    return [
        {
            "covers": dns.rdatatype.to_text(sig.type_covered),
            "signer": sig.signer.to_text(),
            "key_tag": sig.key_tag,
            "algorithm": int(sig.algorithm),
            "labels": sig.labels,
            "original_ttl": sig.original_ttl,
            "inception": _time(sig.inception),
            "expiration": _time(sig.expiration),
            "signature": base64.b64encode(sig.signature).decode(),
        }
        for sig in sigs or []
    ]


def _rrset_data(answer: dict) -> dict:
    rrset = answer["rrset"]
    return {
        "name": rrset.name.to_text(),
        "type": dns.rdatatype.to_text(rrset.rdtype),
        "ttl": rrset.ttl,
        "rdata": sorted(rdata.to_text() for rdata in rrset),
        "rrsig": _rrsig_data(answer["sigs"]),
        "server": answer["server"],
    }


def _key_data(rdata) -> dict:
    # Flags and signatures are kept instead of a role: two keys can share a tag, and SEP is only a hint.
    return {
        "key_tag": dns.dnssec.key_id(rdata),
        "flags": int(rdata.flags),
        "protocol": int(rdata.protocol),
        "algorithm": int(rdata.algorithm),
        "public_key": base64.b64encode(rdata.key).decode(),
    }


def _ds_data(zone, rdata, dnskey_rrset) -> dict:
    return {
        "key_tag": rdata.key_tag,
        "algorithm": int(rdata.algorithm),
        "digest_type": int(rdata.digest_type),
        "digest": rdata.digest.hex(),
        "matches_public_keys": [
            base64.b64encode(key.key).decode() for key in dnskey_rrset or [] if _ds_matches(zone, rdata, key)
        ],
    }


# ---------------------------------------------------------------------------
# the DS, or proof that there is none


def _denial_records(response) -> list[tuple]:
    records = []
    for rrset in response.authority:
        if rrset.rdtype in (dns.rdatatype.NSEC, dns.rdatatype.NSEC3):
            records.append((rrset, _find(response.authority, rrset.name, dns.rdatatype.RRSIG, covers=rrset.rdtype)))
    return records


def _no_ds_is_proven(ask, answer, zone, now: float) -> bool:
    """A missing DS counts as proven only with an NSEC signed by the parent's DNSKEY. NSEC3 is kept, but not checked."""
    proof = [(rrset, sigs) for rrset, sigs in _denial_records(answer["response"]) if rrset.rdtype == dns.rdatatype.NSEC]
    parent_keys = _ask(ask, answer["server"], zone.parent(), dns.rdatatype.DNSKEY)
    if parent_keys["status"] != "ok":
        return False
    status, _ = Verifier().verify_no_ds(zone, proof, parent_keys["rrset"].to_rdataset(), now)
    return status == INSECURE


def _ds_section(ask, answers: list[dict], zone, dnskey_answer, now: float, warnings: list[str]) -> dict:
    usable = next((a for a in answers if a["status"] == "ok"), None)
    if usable:
        dnskey_rrset = dnskey_answer["rrset"] if dnskey_answer else None
        return {
            "status": "present",
            "ttl": usable["rrset"].ttl,
            "records": [_ds_data(zone, rdata, dnskey_rrset) for rdata in usable["rrset"]],
            "rrsig": _rrsig_data(usable["sigs"]),
            "server": usable["server"],
        }
    negative = next((a for a in answers if a["status"] in ("nodata", "nxdomain")), None)
    if negative is None:
        warnings.append("no parent server answered for the DS, so whether it exists is unknown")
        return {"status": "unknown", "ttl": None, "records": [], "rrsig": [], "server": None}
    proven = negative["status"] == "nodata" and _no_ds_is_proven(ask, negative, zone, now)
    if not proven:
        warnings.append("the parent gave no DS, but no signed NSEC proves that: the delegation may still be secure")
    # Checked against the DNSKEY the parent serves, not up to a trust anchor.
    denial = [{"name": r.name.to_text(), "type": dns.rdatatype.to_text(r.rdtype), "ttl": r.ttl,
               "rdata": sorted(x.to_text() for x in r), "rrsig": _rrsig_data(s)} for r, s in _denial_records(negative["response"])]
    return {
        "status": "absent_signed_denial" if proven else "absent_unproven",
        "ttl": None,
        "records": [],
        "rrsig": [],
        "denial": denial,
        "server": negative["server"],
    }


# ---------------------------------------------------------------------------
# one snapshot


def _fingerprint(answer: dict):
    if answer["status"] != "ok":
        return answer["status"]
    return answer["rrset"].ttl, tuple(sorted(rdata.to_text() for rdata in answer["rrset"]))


def _disagreements(answers: list[dict]) -> list[str]:
    """Signatures are not compared: servers may legitimately hold different ones for the same data."""
    groups: dict[tuple, dict] = {}
    for answer in answers:
        if answer["status"] in ANSWERS:
            groups.setdefault((answer["name"], answer["type"]), {}).setdefault(_fingerprint(answer), []).append(answer["server"])
    return [
        f"{name} {rdtype}: servers disagree: " + "; ".join(sorted(", ".join(servers) for servers in seen.values()))
        for (name, rdtype), seen in groups.items()
        if len(seen) > 1
    ]


def _soa_section(answers: list[dict]) -> dict | None:
    usable = [a for a in answers if a["status"] == "ok"]
    if not usable:
        return None
    rrset = usable[0]["rrset"]
    return {
        "ttl": rrset.ttl,
        "minimum": rrset[0].minimum,
        "negative_ttl": min(rrset.ttl, rrset[0].minimum),  # RFC 2308
        "serials": {a["server"]: a["rrset"][0].serial for a in usable},
        "rrsig": _rrsig_data(usable[0]["sigs"]),
    }


def collect_snapshot(
    zone: dns.name.Name,
    child_servers: list[str],
    parent_servers: list[str],
    queries: list[tuple] = (),
    ask=None,
    now: datetime | None = None,
    server_source: str = "given by the operator",
) -> dict:
    """Ask every server the same questions, and report what they said. ``ask`` is replaceable for tests."""
    ask = ask or query_server
    now = now or datetime.now(timezone.utc)
    apex = [(zone, dns.rdatatype.SOA), (zone, dns.rdatatype.NS), (zone, dns.rdatatype.DNSKEY)]
    child = [_ask(ask, server, name, rdtype) for server in child_servers for name, rdtype in [*apex, *queries]]
    parent = [_ask(ask, server, zone, dns.rdatatype.DS) for server in parent_servers]
    everything = child + parent

    def about(rdtype: int) -> list[dict]:
        return [a for a in child if a["name"] == zone.to_text() and a["type"] == dns.rdatatype.to_text(rdtype)]

    warnings: list[str] = []
    errors = [
        f"{a['name']} {a['type']} at {a['server']}: {a['status']}" + (f" ({a['detail']})" if a["detail"] else "")
        for a in everything
        if a["status"] not in ANSWERS
    ]
    if not parent_servers:
        warnings.append("no parent server was asked, so nothing is known about the DS")
    disagreements = _disagreements(everything)
    soa = _soa_section(about(dns.rdatatype.SOA))
    dnskey = next((a for a in about(dns.rdatatype.DNSKEY) if a["status"] == "ok"), None)
    ns = next((a for a in about(dns.rdatatype.NS) if a["status"] == "ok"), None)
    if soa and dnskey is None:
        warnings.append("no server gave a DNSKEY RRset: the zone may be unsigned")

    status = "failed" if soa is None else "inconsistent" if disagreements else "partial"
    requested = {(n.to_text(), dns.rdatatype.to_text(t)) for n, t in queries}
    return {
        "schema_version": SCHEMA_VERSION,
        "zone": zone.to_text(),
        "collected_at": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "dns-query",
        "sources": {"child": list(child_servers), "parent": list(parent_servers), "server_list": server_source},
        "completeness": {
            "status": status,
            "meaning": COMPLETENESS[status],
            "scope": "the zone apex, its DS and the requested names; not the whole zone",
        },
        "soa": soa,
        "ns": _rrset_data(ns) if ns else None,
        "dnskey": (
            {
                "ttl": dnskey["rrset"].ttl,
                "keys": [_key_data(rdata) for rdata in dnskey["rrset"]],
                "rrsig": _rrsig_data(dnskey["sigs"]),
                "server": dnskey["server"],
            }
            if dnskey
            else None
        ),
        "ds": _ds_section(ask, parent, zone, dnskey, now.timestamp(), warnings),
        "rrsets": [_rrset_data(a) for a in child if a["status"] == "ok" and (a["name"], a["type"]) in requested],
        "answers": [{"server": a["server"], "name": a["name"], "type": a["type"], "status": a["status"]} for a in everything],
        "warnings": warnings + disagreements,
        "errors": errors,
    }


def to_yaml(snapshot: dict) -> str:
    return yaml.safe_dump(snapshot, sort_keys=False, allow_unicode=True)


def discover_servers(name: dns.name.Name) -> list[str]:
    """Addresses of a zone's name servers, from the system resolver. This only says whom to ask: every record
    in the snapshot still comes from those servers themselves."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    addresses = []
    try:
        hosts = [rdata.target for rdata in resolver.resolve(name, "NS")]
    except dns.exception.DNSException:
        return []
    for host in hosts:
        for rdtype in ("A", "AAAA"):
            try:
                addresses += [rdata.address for rdata in resolver.resolve(host, rdtype)]
            except dns.exception.DNSException:
                continue
    return addresses[:MAX_SERVERS]


def parent_zone_of(zone: dns.name.Name) -> dns.name.Name | None:
    try:
        return dns.resolver.zone_for_name(zone.parent())
    except dns.exception.DNSException:
        return None
