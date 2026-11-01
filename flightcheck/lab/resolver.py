"""An emulated iterative, validating resolver with a TTL cache.

``trust_cache=True``  (a validating resolver such as Unbound or BIND)
    RRsets are validated when they are fetched; the result is cached with them and trusted until
    the TTL expires. Bogus results are kept for ``bogus_ttl``.

``trust_cache=False`` (a validator behind a non-validating cache, e.g. a forwarder or CPE)
    The cache only stores raw RRsets. Every lookup is validated again against whatever DS and
    DNSKEY RRsets the cache holds at that moment.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.rrset

SECURE, INSECURE, BOGUS = "secure", "insecure", "bogus"
ROOT = dns.name.root


class Network:
    """Delivers wire-format queries to the lab's authoritative servers."""

    def __init__(self):
        self.servers = {}
        self.queries = 0

    def query(self, ip: str, qname, rdtype, t: float) -> dns.message.Message:
        query = dns.message.make_query(qname, rdtype, want_dnssec=True, use_edns=0, payload=1232)
        query.flags &= ~dns.flags.RD
        self.queries += 1
        return dns.message.from_wire(self.servers[ip].handle(query.to_wire(), t))


@dataclass
class Entry:
    rrset: dns.rrset.RRset | None
    sigs: dns.rrset.RRset | None
    expires: float
    negative: bool = False
    proof: list = field(default_factory=list)  # [(rrset, sigs)] for negative answers
    soa: tuple | None = None  # (rrset, sigs) of a negative answer
    rcode: str = "NOERROR"
    zone: dns.name.Name | None = None
    status: str | None = None
    reason: str = ""


@dataclass
class Cut:
    ips: list[str]
    parent: dns.name.Name | None


@dataclass
class Outcome:
    status: str
    reason: str = ""
    rrset: dns.rrset.RRset | None = None
    response: str = "NOERROR"  # NXDOMAIN for a name that does not exist; NOERROR without rrset is NODATA

    @property
    def rcode(self) -> str:
        return "SERVFAIL" if self.status == BOGUS else self.response


class Resolver:
    def __init__(
        self,
        name: str,
        network: Network,
        root_ips: list[str],
        trust_anchor: dns.rrset.RRset,
        wall_base: float,
        max_cache_ttl: int = 7 * 86400,
        bogus_ttl: int = 60,
        key_failure_ttl: int = 60,
        trust_cache: bool = True,
        seed: int = 0,
        verifier: "Verifier | None" = None,
    ):
        self.name = name
        self.network = network
        self.trust_anchor = trust_anchor
        self.wall_base = wall_base
        self.max_cache_ttl = max_cache_ttl
        self.bogus_ttl = bogus_ttl
        self.key_failure_ttl = key_failure_ttl
        self.trust_cache = trust_cache
        self.rng = random.Random(seed)
        self.verifier = verifier or Verifier()
        self.cache: dict[tuple, Entry] = {}
        self.cuts: dict[dns.name.Name, Cut] = {ROOT: Cut(list(root_ips), None)}

    # ------------------------------------------------------------------ public

    def resolve(self, qname, rdtype, t: float) -> Outcome:
        qname = dns.name.from_text(qname) if isinstance(qname, str) else qname
        rdtype = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else dns.rdatatype.RdataType(rdtype)
        entry = self._fresh((qname, rdtype), t)
        if entry is None:
            entry = self._iterate(qname, rdtype, t)
        if self.trust_cache and entry.status is not None:
            # A validating resolver keeps the security status it gave the answer when it was fetched.
            return Outcome(entry.status, entry.reason, entry.rrset, entry.rcode)
        status, keys, reason = self._zone_keys(entry.zone, t)
        if status != SECURE:
            result = (status, reason)
        elif entry.negative:
            result = self.verifier.verify_denial(qname, rdtype, entry, keys, self.now(t))
        else:
            result = self.verifier.verify(entry.rrset, entry.sigs, entry.zone, keys, self.now(t))
        if self.trust_cache:
            entry.status, entry.reason = result
            if result[0] == BOGUS:
                entry.expires = min(entry.expires, t + self.bogus_ttl)
        return Outcome(result[0], result[1], entry.rrset, entry.rcode)

    def touch(self, zone, t: float) -> None:
        """Emulate other clients' cache misses in ``zone``: refresh its DS/DNSKEY if they expired."""
        zone = dns.name.from_text(zone) if isinstance(zone, str) else zone
        if zone in self.cuts:
            self._zone_keys(zone, t)

    def now(self, t: float) -> float:
        return self.wall_base + t

    # ------------------------------------------------------------------ cache

    def _fresh(self, key, t: float) -> Entry | None:
        entry = self.cache.get(key)
        if entry is not None and entry.expires > t:
            return entry
        return None

    def _store(self, response: dns.message.Message, qname, rdtype, t: float, zone) -> Entry:
        rrset = _find(response.answer, qname, rdtype)
        if rrset is not None:
            sigs = _find(response.answer, qname, dns.rdatatype.RRSIG, covers=rdtype)
            ttl = min(rrset.ttl, self.max_cache_ttl)
            if self.trust_cache and sigs is not None:
                # A validating resolver does not keep an RRset past the end of its signatures.
                ttl = min(ttl, max(0, max(sig.expiration for sig in sigs) - self.now(t)))
            entry = Entry(rrset, sigs, t + ttl, zone=zone)
        else:
            soa = next((r for r in response.authority if r.rdtype == dns.rdatatype.SOA), None)
            proof = []
            for nsec in (r for r in response.authority if r.rdtype == dns.rdatatype.NSEC):
                sigs = _find(response.authority, nsec.name, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC)
                proof.append((nsec, sigs))
            # RFC 2308 and RFC 9077: the smallest of the SOA TTL, the SOA MINIMUM and the NSEC TTLs.
            limits = [soa.ttl, soa[0].minimum] if soa is not None else [60]
            ttl = min(limits + [nsec.ttl for nsec, _ in proof] + [self.max_cache_ttl])
            soa_proof = None
            if soa is not None:
                soa_proof = (soa, _find(response.authority, soa.name, dns.rdatatype.RRSIG, covers=dns.rdatatype.SOA))
            rcode = dns.rcode.to_text(response.rcode())
            entry = Entry(None, None, t + ttl, negative=True, proof=proof, soa=soa_proof, rcode=rcode, zone=zone)
        self.cache[(qname, rdtype)] = entry
        return entry

    def _get(self, qname, rdtype, t: float, zone, ips: list[str]) -> Entry:
        entry = self._fresh((qname, rdtype), t)
        if entry is None:
            response = self.network.query(self.rng.choice(ips), qname, rdtype, t)
            entry = self._store(response, qname, rdtype, t, zone)
        return entry

    # ------------------------------------------------------------------ iteration

    def _iterate(self, qname, rdtype, t: float) -> Entry:
        zone = max((cut for cut in self.cuts if qname.is_subdomain(cut)), key=len)
        for _ in range(16):
            response = self.network.query(self.rng.choice(self.cuts[zone].ips), qname, rdtype, t)
            if response.flags & dns.flags.AA or response.answer:
                return self._store(response, qname, rdtype, t, zone)
            ns = next(
                (r for r in response.authority if r.rdtype == dns.rdatatype.NS and r.name.is_subdomain(zone) and r.name != zone),
                None,
            )
            if ns is None:
                return self._store(response, qname, rdtype, t, zone)
            ips = [
                rdata.address
                for rrset in response.additional
                if rrset.rdtype == dns.rdatatype.A and any(rrset.name == n.target for n in ns)
                for rdata in rrset
            ]
            self.cuts[ns.name] = Cut(ips, zone)
            zone = ns.name
        raise RuntimeError(f"too many referrals for {qname}")

    # ------------------------------------------------------------------ chain of trust

    def _zone_keys(self, zone, t: float):
        """(status, trusted DNSKEY rdataset or None, reason) for a zone."""
        cut = self.cuts[zone]
        if cut.parent is None:
            ds_rrset = self.trust_anchor
        else:
            parent_status, parent_keys, parent_reason = self._zone_keys(cut.parent, t)
            if parent_status != SECURE:
                return parent_status, None, parent_reason
            ds_entry = self._get(zone, dns.rdatatype.DS, t, cut.parent, self.cuts[cut.parent].ips)
            status, reason = self._ds_status(ds_entry, zone, parent_keys, t)
            if status != SECURE:
                return status, None, reason
            ds_rrset = ds_entry.rrset

        dnskey_entry = self._get(zone, dns.rdatatype.DNSKEY, t, zone, cut.ips)
        if self.trust_cache and dnskey_entry.status is not None:
            status, reason = dnskey_entry.status, dnskey_entry.reason
        else:
            status, reason = self.verifier.verify_dnskey(zone, dnskey_entry, ds_rrset, self.now(t))
            if self.trust_cache:
                dnskey_entry.status, dnskey_entry.reason = status, reason
                if status == BOGUS:
                    dnskey_entry.expires = min(dnskey_entry.expires, t + self.key_failure_ttl)
        if status != SECURE:
            return status, None, f"DNSKEY {zone}: {reason}"
        return SECURE, dnskey_entry.rrset.to_rdataset(), ""

    def _ds_status(self, entry: Entry, zone, parent_keys, t: float):
        if self.trust_cache and entry.status is not None:
            return entry.status, entry.reason
        parent = self.cuts[zone].parent  # the zone that delegates, which need not be one label up
        if not entry.negative:
            status, reason = self.verifier.verify(entry.rrset, entry.sigs, parent, parent_keys, self.now(t))
            if status == BOGUS:
                reason = f"DS {zone}: {reason}"
        else:
            status, reason = self.verifier.verify_no_ds(zone, entry.proof, parent_keys, self.now(t), parent)
        if self.trust_cache:
            entry.status, entry.reason = status, reason
            if status == BOGUS:
                entry.expires = min(entry.expires, t + self.key_failure_ttl)
        return status, reason


class Verifier:
    """Signature checks, memoised (the same RRsets are verified many times in one experiment)."""

    def __init__(self):
        self._memo: dict = {}

    def verify(self, rrset, sigs, signer, keys, now: float):
        if rrset is None:
            return BOGUS, "no data"
        if sigs is None:
            return BOGUS, f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)} has no RRSIG"
        # The result depends on the clock only through which signatures are inside their period.
        in_period = tuple(sig.inception <= now <= sig.expiration for sig in sigs)
        memo_key = ("v", rrset.to_text(), sigs.to_text(), keys.to_text(), str(signer), in_period)
        if memo_key not in self._memo:
            try:
                dns.dnssec.validate(rrset, sigs, {signer: keys}, now=now)
                self._memo[memo_key] = (SECURE, "")
            except dns.dnssec.ValidationFailure as exc:
                what = f"{rrset.name} {dns.rdatatype.to_text(rrset.rdtype)}"
                self._memo[memo_key] = (BOGUS, f"{what}: no valid signature from a trusted key ({exc})")
        return self._memo[memo_key]

    def verify_dnskey(self, zone, entry: Entry, ds_rrset, now: float):
        if entry.negative or entry.rrset is None:
            return BOGUS, "the zone has a DS but publishes no DNSKEY RRset"
        matched = [key for key in entry.rrset if any(_ds_matches(zone, ds, key) for ds in ds_rrset)]
        if not matched:
            return BOGUS, "no DNSKEY matches the cached DS RRset"
        keys = dns.rdataset.from_rdata_list(entry.rrset.ttl, matched)
        status, reason = self.verify(entry.rrset, entry.sigs, zone, keys, now)
        if status == BOGUS:
            reason = "the DNSKEY RRset is not signed by a key that matches the cached DS RRset"
        return status, reason

    def verify_no_ds(self, zone, proof, parent_keys, now: float, parent=None):
        for nsec, sigs in proof:
            if nsec.name != zone:
                continue
            status, reason = self.verify(nsec, sigs, parent or zone.parent(), parent_keys, now)
            if status != SECURE:
                return BOGUS, f"invalid proof that {zone} has no DS: {reason}"
            types = _nsec_types(nsec)
            if "DS" not in types and "NS" in types and "SOA" not in types:
                return INSECURE, "no DS at the parent: insecure delegation"
            return BOGUS, f"NSEC for {zone} does not prove an insecure delegation"
        return BOGUS, f"no proof that {zone} has no DS"

    def verify_denial(self, qname, rdtype, entry: Entry, keys, now: float):
        """A negative answer in a secure zone needs signed records that prove it (RFC 4035 section 5.4).

        Only NSEC is supported: NSEC3 is not, and neither are wildcard answers."""
        if entry.soa is None:
            return BOGUS, f"{qname}: a negative answer without a SOA"
        status, reason = self.verify(entry.soa[0], entry.soa[1], entry.zone, keys, now)
        if status != SECURE:
            return BOGUS, f"{qname}: invalid SOA in a negative answer: {reason}"
        for nsec, sigs in entry.proof:
            status, reason = self.verify(nsec, sigs, entry.zone, keys, now)
            if status != SECURE:
                return BOGUS, f"{qname}: invalid proof of denial: {reason}"
        records = [nsec for nsec, _ in entry.proof]
        if entry.rcode == "NXDOMAIN":
            proved = _proves_no_name(qname, records)
        elif entry.rcode == "NOERROR":
            proved = _proves_no_type(qname, rdtype, records)
        else:
            return BOGUS, f"{qname}: the server answered {entry.rcode}"
        return (SECURE, "") if proved else (BOGUS, f"{qname}: the NSEC records do not prove {entry.rcode}")


def _nsec_types(nsec) -> set[str]:
    return set(nsec[0].to_text().split()[1:])


def _nsec_covers(nsec, name) -> bool:
    """Does this NSEC say that ``name`` lies in the gap after its owner? The last NSEC wraps to the apex."""
    following = nsec[0].next
    if nsec.name < following:
        return nsec.name < name < following
    return name > nsec.name or name < following


def _proves_no_name(qname, records: list) -> bool:
    if not any(_nsec_covers(nsec, qname) for nsec in records):
        return False
    # The name could still come from a wildcard at its closest existing ancestor, so that must not exist either.
    shared = max(qname.fullcompare(name)[2] for nsec in records for name in (nsec.name, nsec[0].next))
    wildcard = dns.name.Name((b"*",) + qname.labels[-shared:])
    return any(_nsec_covers(nsec, wildcard) for nsec in records)


def _proves_no_type(qname, rdtype, records: list) -> bool:
    for nsec in records:
        if nsec.name == qname:
            types = _nsec_types(nsec)
            return dns.rdatatype.to_text(rdtype) not in types and "CNAME" not in types
    return False


def _ds_matches(zone, ds, key) -> bool:
    if ds.key_tag != dns.dnssec.key_id(key) or ds.algorithm != key.algorithm:
        return False
    try:
        return dns.dnssec.make_ds(zone, key, ds.digest_type) == ds
    except Exception:  # unsupported digest type
        return False


def _find(section, name, rdtype, covers=dns.rdatatype.NONE):
    for rrset in section:
        if rrset.name == name and rrset.rdtype == rdtype and (covers == dns.rdatatype.NONE or rrset.covers == covers):
            return rrset
    return None


def wall_clock_for(plan_start) -> float:
    """Wall-clock time (epoch seconds) that corresponds to T+0 of the plan."""
    if plan_start is not None:
        return plan_start.timestamp()
    return 1_800_000_000.0  # a fixed moment, so runs are reproducible


__all__ = ["Network", "Resolver", "Verifier", "Outcome", "SECURE", "INSECURE", "BOGUS", "wall_clock_for"]
