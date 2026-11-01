"""A small authoritative DNS server that answers from zone snapshots (wire format in, wire format out)."""

from __future__ import annotations

from typing import Callable

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset

from .zones import ZoneSnapshot


class AuthServer:
    """Answers queries for the zones returned by ``zones_at(t)``."""

    def __init__(self, name: str, zones_at: Callable[[float], list[ZoneSnapshot]]):
        self.name = name
        self.zones_at = zones_at

    def handle(self, wire: bytes, t: float) -> bytes:
        query = dns.message.from_wire(wire)
        response = self.respond(query, t)
        return response.to_wire()

    def respond(self, query: dns.message.Message, t: float) -> dns.message.Message:
        response = dns.message.make_response(query)
        if not query.question:
            response.set_rcode(dns.rcode.FORMERR)
            return response
        question = query.question[0]
        qname, qtype = question.name, question.rdtype
        dnssec = bool(query.ednsflags & dns.flags.DO)
        if dnssec:
            response.want_dnssec(True)

        zone = self._pick_zone(self.zones_at(t), qname, qtype)
        if zone is None:
            response.set_rcode(dns.rcode.REFUSED)
            return response

        cut = zone.delegation_for(qname)
        if cut is not None and not (qtype == dns.rdatatype.DS and qname == cut):
            self._referral(response, zone, cut, dnssec)
            return response

        response.flags |= dns.flags.AA
        rrset = zone.get(qname, qtype)
        if rrset is not None:
            self._add(response.answer, zone, rrset, qtype, dnssec)
            return response
        if zone.exists(qname):
            self._negative(response, zone, dnssec, [zone.get(qname, dns.rdatatype.NSEC)])
            return response
        response.set_rcode(dns.rcode.NXDOMAIN)
        proofs = [zone.covering_nsec(qname)]
        encloser = qname.parent()
        while encloser != zone.origin and not zone.exists(encloser):
            encloser = encloser.parent()
        wildcard = dns.name.from_text("*", encloser)
        proofs.append(zone.covering_nsec(wildcard))
        self._negative(response, zone, dnssec, proofs)
        return response

    def transfer_messages(self, query: dns.message.Message, t: float, per_message: int = 20) -> list[dns.message.Message]:
        """An AXFR of the zone being served now, in several messages: SOA first, everything else, and SOA again."""
        qname = query.question[0].name
        zone = next((z for z in self.zones_at(t) if z.origin == qname), None)
        if zone is None:
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.NOTAUTH)
            return [response]
        soa = zone.soa()
        others = [rrset for key, rrset in sorted(zone.rrsets.items()) if rrset is not soa]
        records = [soa, *others, *zone.nsec.values(), *zone.sigs.values(), soa]
        messages = []
        for start in range(0, len(records), per_message):
            response = dns.message.make_response(query)
            response.flags |= dns.flags.AA
            response.answer = records[start : start + per_message]
            messages.append(response)
        return messages

    @staticmethod
    def _pick_zone(zones: list[ZoneSnapshot], qname, qtype) -> ZoneSnapshot | None:
        candidates = [z for z in zones if qname.is_subdomain(z.origin)]
        if not candidates:
            return None
        candidates.sort(key=lambda z: len(z.origin), reverse=True)
        best = candidates[0]
        if qtype == dns.rdatatype.DS and qname == best.origin and len(candidates) > 1:
            return candidates[1]  # DS lives in the parent
        return best

    @staticmethod
    def _add(section: list, zone: ZoneSnapshot, rrset, rdtype, dnssec: bool):
        if rrset is None:
            return
        if rrset not in section:
            section.append(rrset)
        if dnssec:
            sig = zone.sig(rrset.name, rdtype)
            if sig is not None and sig not in section:
                section.append(sig)

    def _negative(self, response, zone: ZoneSnapshot, dnssec: bool, proofs: list):
        soa = zone.soa()
        ttl = min(soa.ttl, soa[0].minimum)
        negative_soa = dns.rrset.from_rdata_list(soa.name, ttl, list(soa))
        response.authority.append(negative_soa)
        if dnssec:
            sig = zone.sig(soa.name, dns.rdatatype.SOA)
            if sig is not None:
                response.authority.append(dns.rrset.from_rdata_list(sig.name, ttl, list(sig)))
            for proof in proofs:
                if proof is not None:
                    self._add(response.authority, zone, proof, dns.rdatatype.NSEC, True)

    def _referral(self, response, zone: ZoneSnapshot, cut, dnssec: bool):
        ns = zone.get(cut, dns.rdatatype.NS)
        response.authority.append(ns)
        if dnssec:
            ds = zone.get(cut, dns.rdatatype.DS)
            if ds is not None:
                self._add(response.authority, zone, ds, dns.rdatatype.DS, True)
            else:
                self._add(response.authority, zone, zone.get(cut, dns.rdatatype.NSEC), dns.rdatatype.NSEC, True)
        for rdata in ns:
            for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                glue = zone.get(rdata.target, rdtype)
                if glue is not None:
                    response.additional.append(glue)
