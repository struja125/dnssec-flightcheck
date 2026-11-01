"""Symbolic DNSSEC validation of one combination of cached RRset versions.

The check follows what a validating resolver does:

1. no DS at the parent            -> the delegation is insecure, data is accepted unsigned;
2. DS present                     -> the DNSKEY RRset must be signed by a published key that a DS
                                     record points to (RFC 4035 section 5.2);
3. DNSKEY RRset trusted           -> each data RRset must be signed by a key in that DNSKEY RRset.

With ``strict`` (Unbound's ``harden-algo-downgrade: yes``) every algorithm that appears in the DS
RRset must be usable both for the DNSKEY RRset and for the data.
"""

from __future__ import annotations

from dataclasses import dataclass

from .durations import format_offset
from .plan import Key, RRsetState

SECURE = "secure"
INSECURE = "insecure"
BOGUS = "bogus"


@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str = ""
    against: str = "dnskey"  # which RRset the failing RRset was validated against: "ds" or "dnskey"
    signature_time: bool = False  # the keys match, but no usable signature is inside its validity period


def _names(keys: frozenset[str]) -> str:
    return "{" + ", ".join(sorted(keys)) + "}" if keys else "{}"


def signature_valid(state: RRsetState, signer: str, at: float) -> bool:
    inception, expires = state.rrsig.get(signer, (None, None))
    return (inception is None or at >= inception) and (expires is None or at < expires)


def _period_failure(state: RRsetState, signers: frozenset[str], at: float, against: str) -> Verdict:
    details = []
    for signer in sorted(signers):
        inception, expires = state.rrsig[signer]
        if inception is not None and at < inception:
            details.append(f"{signer} is not valid before {format_offset(inception)}")
        else:
            details.append(f"{signer} expired at {format_offset(expires)}")
    return Verdict(
        BOGUS,
        f"no signature is inside its validity period ({', '.join(details)}); it needs new signatures, "
        "which moving the key steps cannot give it",
        against,
        signature_time=True,
    )


def check_dnskey(ds: RRsetState, dnskey: RRsetState, keys: dict[str, Key], strict: bool, at: float) -> Verdict:
    if not ds.keys:
        return Verdict(INSECURE, "no DS at the parent: insecure delegation", "ds")
    if not dnskey.keys:
        return Verdict(
            BOGUS,
            f"the DS RRset points to {_names(ds.keys)} but the zone publishes no DNSKEY at all",
            "ds",
        )
    anchors = ds.keys & dnskey.keys & dnskey.signed_by
    if not anchors:
        published = ds.keys & dnskey.keys
        if not published:
            detail = (
                f"none of the keys the DS RRset points to {_names(ds.keys)} "
                f"is in the DNSKEY RRset {_names(dnskey.keys)}"
            )
        else:
            detail = (
                f"the DS keys present in the DNSKEY RRset {_names(published)} do not sign it "
                f"(it is signed by {_names(dnskey.signed_by)})"
            )
        return Verdict(BOGUS, f"no chain of trust from DS to DNSKEY: {detail}", "ds")
    all_anchors = anchors
    # One valid signature from a key the DS points to is enough, so the others may have expired.
    anchors = frozenset(name for name in anchors if signature_valid(dnskey, name, at))
    if not anchors:
        return _period_failure(dnskey, all_anchors, at, "ds")
    if strict:
        needed = {keys[name].algorithm for name in ds.keys}
        have = {keys[name].algorithm for name in anchors}
        missing = needed - have
        if missing:
            return Verdict(
                BOGUS,
                "strict algorithm check: the DS RRset advertises algorithm(s) "
                f"{', '.join(str(a) for a in sorted(missing))} but the DNSKEY RRset has no matching "
                "self-signature of that algorithm",
                "ds",
            )
    return Verdict(SECURE, against="ds")


def check_data(
    ds: RRsetState, dnskey: RRsetState, data: RRsetState, keys: dict[str, Key], strict: bool, at: float
) -> Verdict:
    """Validate a data RRset, assuming the DNSKEY RRset itself is trusted."""
    if not ds.keys:
        return Verdict(INSECURE, "no DS at the parent: insecure delegation", "ds")
    if not data.signed_by:
        return Verdict(
            BOGUS, "the RRset carries no signatures although the delegation is secure", "ds"
        )
    usable = data.signed_by & dnskey.keys
    if not usable:
        return Verdict(
            BOGUS,
            f"it is signed only by {_names(data.signed_by)}, and none of these keys is in "
            f"the cached DNSKEY RRset {_names(dnskey.keys)}",
        )
    all_usable = usable
    usable = frozenset(name for name in usable if signature_valid(data, name, at))
    if not usable:
        return _period_failure(data, all_usable, at, "dnskey")
    if strict:
        needed = {keys[name].algorithm for name in ds.keys}
        have = {keys[name].algorithm for name in usable}
        missing = needed - have
        if missing:
            return Verdict(
                BOGUS,
                "strict algorithm check: no signature with algorithm(s) "
                f"{', '.join(str(a) for a in sorted(missing))} advertised in the DS RRset",
                "ds",
            )
    return Verdict(SECURE)
