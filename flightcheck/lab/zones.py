"""Signed zone snapshots for the lab: the root, the TLD and the zone under test.

The zone under test is rebuilt from the plan for every combination of RRset versions that a
server can serve, signed with exactly the keys the plan says, and cached.
"""

from __future__ import annotations

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from ..plan import DATA_PREFIX, DNSKEY, DS, Plan, PlanError
from ..timeline import build_timelines, served_version_index
from .keys import LabKey, generate_key

IN = dns.rdataclass.IN
ROOT = dns.name.root

ROOT_IP = "10.53.0.1"
TLD_IP = "10.53.0.2"
PRIMARY_IP = "10.53.0.3"
SECONDARY_IP = "10.53.0.4"
DEFAULT_ADDRESSES = {"root": ROOT_IP, "tld": TLD_IP, "ns1": PRIMARY_IP, "ns2": SECONDARY_IP}
DATA_ADDRESS = "192.0.2.{n}"
# A real zone can have an RRset named ns1, which must not take the place of the lab's own servers.
SERVER_1, SERVER_2 = "lab-ns1", "lab-ns2"
ROOT_KEY = "root-CSK"
TLD_KEY = "tld-CSK"


class ZoneSnapshot:
    """An authoritative view of one zone at one moment."""

    def __init__(self, origin: dns.name.Name, negative_ttl: int):
        self.origin = origin
        self.negative_ttl = negative_ttl
        self.rrsets: dict[tuple, dns.rrset.RRset] = {}
        self.sigs: dict[tuple, dns.rrset.RRset] = {}
        self.nsec: dict[dns.name.Name, dns.rrset.RRset] = {}
        self.delegations: set[dns.name.Name] = set()
        self.names: list[dns.name.Name] = []

    def add(self, name, rdtype, ttl: int, *rdatas: str):
        name = dns.name.from_text(name, self.origin) if isinstance(name, str) else name
        rdtype = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        parsed = [dns.rdata.from_text(IN, rdtype, text, origin=self.origin, relativize=False) for text in rdatas]
        self.add_rdatas(name, rdtype, ttl, parsed)

    def add_rdatas(self, name: dns.name.Name, rdtype, ttl: int, rdatas: list):
        if not rdatas:
            return
        self.rrsets[(name, rdtype)] = dns.rrset.from_rdata_list(name, ttl, rdatas)
        if rdtype == dns.rdatatype.NS and name != self.origin:
            self.delegations.add(name)

    # ---- structure

    def delegation_for(self, qname: dns.name.Name) -> dns.name.Name | None:
        """The delegation point at or above ``qname`` (excluding the apex), if any."""
        best = None
        for cut in self.delegations:
            if qname.is_subdomain(cut) and (best is None or len(cut) > len(best)):
                best = cut
        return best

    def is_glue(self, name: dns.name.Name) -> bool:
        return any(name.is_subdomain(cut) and name != cut for cut in self.delegations)

    def authoritative(self, name: dns.name.Name, rdtype) -> bool:
        if self.is_glue(name):
            return False
        if name in self.delegations and rdtype not in (dns.rdatatype.DS, dns.rdatatype.NSEC):
            return False
        return True

    def owner_names(self) -> list[dns.name.Name]:
        names = {name for (name, _rdtype) in self.rrsets if not self.is_glue(name)}
        return sorted(names)

    def types_at(self, name: dns.name.Name) -> list[str]:
        return sorted(dns.rdatatype.to_text(t) for (n, t) in self.rrsets if n == name)

    # ---- signing

    def finalize(self, signers, inception: float, expiration: float, signed: bool, signature_times=None):
        """Build the NSEC chain and sign every authoritative RRset.

        ``signers(name, rdtype)`` returns the LabKeys that sign that RRset. ``signature_times(name, rdtype, key)``
        can give the (inception, expiration) of one signature instead of the default ones.
        """
        self.names = self.owner_names()
        if signed:
            for i, name in enumerate(self.names):
                following = self.names[(i + 1) % len(self.names)]
                types = set(self.types_at(name)) | {"NSEC", "RRSIG"}
                text = f"{following.to_text()} {' '.join(sorted(types))}"
                rdata = dns.rdata.from_text(IN, dns.rdatatype.NSEC, text)
                self.nsec[name] = dns.rrset.from_rdata_list(name, self.negative_ttl, [rdata])
        if not signed:
            return
        for (name, rdtype), rrset in list(self.rrsets.items()) + [
            ((name, dns.rdatatype.NSEC), rrset) for name, rrset in self.nsec.items()
        ]:
            if not self.authoritative(name, rdtype):
                continue
            keys: list[LabKey] = signers(name, rdtype)
            sigs = []
            for key in keys:
                start, end = signature_times(name, rdtype, key) if signature_times else (inception, expiration)
                sigs.append(dns.dnssec.sign(rrset, key.private, self.origin, key.dnskey, inception=start, expiration=end))
            if sigs:
                self.sigs[(name, rdtype)] = dns.rrset.from_rdata_list(name, rrset.ttl, sigs)

    # ---- lookups used by the server

    def get(self, name, rdtype):
        if rdtype == dns.rdatatype.NSEC:
            return self.nsec.get(name)
        return self.rrsets.get((name, rdtype))

    def sig(self, name, rdtype):
        return self.sigs.get((name, rdtype))

    def exists(self, name: dns.name.Name) -> bool:
        if any(n == name for (n, _t) in self.rrsets):
            return True
        # empty non-terminal
        return any(n.is_subdomain(name) and n != name for (n, _t) in self.rrsets)

    def covering_nsec(self, qname: dns.name.Name) -> dns.rrset.RRset | None:
        if not self.nsec:
            return None
        before = [n for n in self.names if n < qname]
        owner = before[-1] if before else self.names[-1]
        return self.nsec[owner]

    def soa(self):
        return self.rrsets[(self.origin, dns.rdatatype.SOA)]


class LabWorld:
    """Keys, zone snapshots and the version each server serves at a given moment.

    ``ttl_scale`` divides every TTL that is served (used when real resolvers run on a compressed
    clock); plan times are scaled only when they become signature times, which resolvers compare with
    the real clock. ``wall_base`` is the real time at plan time ``t_begin``.
    """

    def __init__(
        self,
        plan: Plan,
        wall_base: float,
        addresses: dict[str, str] | None = None,
        ttl_scale: float = 1,
        keys: dict[str, LabKey] | None = None,
        t_begin: float = 0,
    ):
        self.t_begin = t_begin
        self.plan = plan
        self.zone = dns.name.from_text(plan.zone)
        if len(self.zone.labels) < 3:
            raise PlanError(f"{plan.zone}: the lab needs a zone with a parent below the root, e.g. bank.test.")
        # The parent, however deep, is delegated directly from the lab's root: only its DS matters here.
        self.tld = self.zone.parent()
        self.timelines = build_timelines(plan)
        self.wall_base = wall_base
        self.inception = wall_base - 2 * 86400
        self.expiration = wall_base + 120 * 86400
        self.addresses = {**DEFAULT_ADDRESSES, **(addresses or {})}
        self.ttl_scale = ttl_scale

        if keys is None:
            keys = generate_lab_keys(plan)
        self.root_key = keys[ROOT_KEY]
        self.tld_key = keys[TLD_KEY]
        self.keys: dict[str, LabKey] = {name: keys[name] for name in plan.keys}
        self.data_names = plan.data_names
        self._tld_cache: dict[int, ZoneSnapshot] = {}
        self._zone_cache: dict[tuple, ZoneSnapshot] = {}
        self.root = self._build_root()

    def ttl(self, seconds: float) -> int:
        return max(1, int(round(seconds / self.ttl_scale)))

    def wall_at(self, t: float) -> float:
        return self.wall_base + (t - self.t_begin) / self.ttl_scale

    # ---- trust anchor

    def trust_anchor(self) -> dns.rrset.RRset:
        return dns.rrset.from_rdata_list(ROOT, self.ttl(172800), [self.root_key.ds(ROOT)])

    # ---- which version is served

    def versions_at(self, t: float, lag: float) -> dict[str, int]:
        return {rrset: served_version_index(versions, t, lag) for rrset, versions in self.timelines.items()}

    def tld_at(self, t: float, lag: float = 0) -> ZoneSnapshot:
        index = served_version_index(self.timelines[DS], t, lag)
        if index not in self._tld_cache:
            self._tld_cache[index] = self._build_tld(index)
        return self._tld_cache[index]

    def zone_at(self, t: float, lag: float = 0) -> ZoneSnapshot:
        versions = self.versions_at(t, lag)
        key = (versions[DNSKEY],) + tuple(versions[DATA_PREFIX + name] for name in self.data_names)
        if key not in self._zone_cache:
            self._zone_cache[key] = self._build_zone(versions)
        return self._zone_cache[key]

    # ---- builders

    def _build_root(self) -> ZoneSnapshot:
        ttl, ip = self.ttl, self.addresses
        z = ZoneSnapshot(ROOT, ttl(86400))
        z.add("@", "SOA", ttl(86400), f"a.root-lab. hostmaster.root-lab. 1 1800 900 604800 {ttl(86400)}")
        z.add("@", "NS", ttl(518400), "a.root-lab.")
        z.add("a.root-lab.", "A", ttl(518400), ip["root"])
        z.add_rdatas(ROOT, dns.rdatatype.DNSKEY, ttl(172800), [self.root_key.dnskey])
        z.add(self.tld, "NS", ttl(172800), f"ns.{self.tld}")
        z.add(f"ns.{self.tld}", "A", ttl(172800), ip["tld"])
        z.add_rdatas(self.tld, dns.rdatatype.DS, ttl(86400), [self.tld_key.ds(self.tld)])
        z.finalize(lambda name, rdtype: [self.root_key], self.inception, self.expiration, signed=True)
        return z

    def _build_tld(self, ds_index: int) -> ZoneSnapshot:
        ttl, ip = self.ttl, self.addresses
        version = self.timelines[DS][ds_index]
        ds_keys = sorted(version.state.keys)
        parent_negative = self.plan.parent_negative_ttl
        negative = ttl(parent_negative if parent_negative is not None else version.state.ttl if not ds_keys else 300)
        z = ZoneSnapshot(self.tld, negative)
        z.add("@", "SOA", max(negative, ttl(300)), f"ns.{self.tld} hostmaster.{self.tld} {ds_index + 1} 1800 900 604800 {negative}")
        z.add("@", "NS", ttl(86400), f"ns.{self.tld}")
        z.add(f"ns.{self.tld}", "A", ttl(86400), ip["tld"])
        z.add_rdatas(self.tld, dns.rdatatype.DNSKEY, ttl(86400), [self.tld_key.dnskey])
        z.add(self.zone, "NS", ttl(86400), f"{SERVER_1}.{self.zone}", f"{SERVER_2}.{self.zone}")
        z.add(f"{SERVER_1}.{self.zone}", "A", ttl(86400), ip["ns1"])
        z.add(f"{SERVER_2}.{self.zone}", "A", ttl(86400), ip["ns2"])
        if ds_keys:
            z.add_rdatas(
                self.zone, dns.rdatatype.DS, ttl(version.state.ttl), [self.keys[k].ds(self.zone) for k in ds_keys]
            )
        z.finalize(lambda name, rdtype: [self.tld_key], self.inception, self.expiration, signed=True)
        return z

    def _build_zone(self, versions: dict[str, int]) -> ZoneSnapshot:
        ttl, ip = self.ttl, self.addresses
        dnskey = self.timelines[DNSKEY][versions[DNSKEY]].state
        data_states = {
            name: self.timelines[DATA_PREFIX + name][versions[DATA_PREFIX + name]].state
            for name in self.data_names
        }
        negative = 300 if self.plan.zone_negative_ttl is None else self.plan.zone_negative_ttl
        z = ZoneSnapshot(self.zone, ttl(negative))
        # The SOA TTL must not cut the negative TTL short: a resolver uses the smaller of TTL and MINIMUM (RFC 2308).
        z.add("@", "SOA", ttl(max(3600, negative)), f"{SERVER_1}.{self.zone} hostmaster.{self.zone} 1 1800 900 604800 {ttl(negative)}")
        z.add("@", "NS", ttl(86400), f"{SERVER_1}.{self.zone}", f"{SERVER_2}.{self.zone}")
        z.add(SERVER_1, "A", ttl(86400), ip["ns1"])
        z.add(SERVER_2, "A", ttl(86400), ip["ns2"])
        if dnskey.keys:
            z.add_rdatas(
                self.zone, dns.rdatatype.DNSKEY, ttl(dnskey.ttl), [self.keys[k].dnskey for k in sorted(dnskey.keys)]
            )
        data_owner = {}
        for number, (name, state) in enumerate(data_states.items(), 10):
            owner = dns.name.from_text(name, self.zone)
            data_owner[owner] = state
            z.add(owner, "A", ttl(state.ttl), DATA_ADDRESS.format(n=number))

        infra = sorted(next(iter(data_states.values())).signed_by) if data_states else []

        def signers(name, rdtype):
            if rdtype == dns.rdatatype.DNSKEY and name == self.zone:
                chosen = dnskey.signed_by
            elif name in data_owner and rdtype == dns.rdatatype.A:
                chosen = data_owner[name].signed_by
            else:
                chosen = infra
            return [self.keys[k] for k in sorted(chosen)]

        def signature_times(name, rdtype, key):
            state = None
            if rdtype == dns.rdatatype.DNSKEY and name == self.zone:
                state = dnskey
            elif name in data_owner and rdtype == dns.rdatatype.A:
                state = data_owner[name]
            inception, expires = state.rrsig.get(key.name, (None, None)) if state else (None, None)
            end = self.expiration if expires is None else self.wall_at(expires)
            start = self.inception if inception is None else self.wall_at(inception)
            return min(start, end - 1), end  # the default inception may be later than an expiry in the past

        signed = bool(dnskey.keys or dnskey.signed_by or any(s.signed_by for s in data_states.values()))
        z.finalize(signers, self.inception, self.expiration, signed=signed, signature_times=signature_times)
        return z


def key_mapping(plan: Plan, keys: dict[str, LabKey]) -> list[dict]:
    """Which synthetic key stands for which key of the plan. Only public values: the private ones are the lab's own."""
    sources = plan.source.get("provenance", {}).get("keys", {}) if plan.source else {}
    return [
        {
            "plan_key": name,
            "role": key.role,
            "algorithm": key.algorithm,
            "real_key_tag": sources.get(name, {}).get("key_tag"),
            "real_key": sources.get(name, {}).get("source", "defined in the plan"),
            "synthetic_key_tag": keys[name].tag,
        }
        for name, key in plan.keys.items()
    ]


def generate_lab_keys(plan: Plan) -> dict[str, LabKey]:
    """Fresh keys for every plan key plus the lab's root and TLD keys. A snapshot holds only public keys, so the
    lab always signs and builds DS records with these: nothing of the real keys or DS records is reused."""
    keys = {
        ROOT_KEY: generate_key(ROOT_KEY, 13, ksk=True),
        TLD_KEY: generate_key(TLD_KEY, 13, ksk=True),
    }
    for name, key in plan.keys.items():
        keys[name] = generate_key(name, key.algorithm, ksk=key.role in ("ksk", "csk"))
    return keys
