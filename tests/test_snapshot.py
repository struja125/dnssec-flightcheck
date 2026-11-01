"""The snapshot collector, against the lab's authoritative servers. Nothing here touches the Internet."""

import base64
from datetime import datetime, timezone

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from flightcheck import snapshot as snap
from flightcheck.cli import EXIT_ERROR, main
from flightcheck.lab.authserver import AuthServer
from flightcheck.lab.zones import LabWorld
from flightcheck.plan import plan_from_dict

ZONE = dns.name.from_text("bank.test.")
WALL = 1_800_000_000
NS1, NS2, TLD = "192.0.2.1", "192.0.2.2", "192.0.2.53"


def plan(ds=("K1",), dnskey=("K1", "K2", "Z"), signed_by=("K1",), algorithm_of_k2=13):
    return plan_from_dict(
        {
            "keys": {"K1": {"role": "ksk"}, "K2": {"role": "ksk", "algorithm": algorithm_of_k2}, "Z": {"role": "zsk"}},
            "initial": {
                "ds": {"keys": list(ds), "ttl": "2h"},
                "dnskey": {"keys": list(dnskey), "signed_by": list(signed_by), "ttl": "1h"},
                "data": {"www": {"signed_by": ["Z"], "ttl": "5m"}},
            },
            "steps": [],
        }
    )


def lab_ask(parsed):
    """Answers as the lab's servers would, through wire format so answers are parsed as from a network."""
    world = LabWorld(parsed, WALL)
    servers = {
        NS1: AuthServer("ns1", lambda t: [world.zone_at(t)]),
        NS2: AuthServer("ns2", lambda t: [world.zone_at(t)]),
        TLD: AuthServer("tld", lambda t: [world.tld_at(t)]),
    }

    def ask(server, name, rdtype):
        query = dns.message.make_query(name, rdtype, want_dnssec=True, use_edns=0, payload=1232)
        return dns.message.from_wire(servers[server].handle(query.to_wire(), 0))

    return ask, world


NOW = datetime.fromtimestamp(WALL, timezone.utc)


def collect(parsed=None, children=(NS1, NS2), parents=(TLD), queries=(), ask=None):
    if ask is None:
        ask, _ = lab_ask(parsed or plan())
    parents = [parents] if isinstance(parents, str) else list(parents)
    return snap.collect_snapshot(ZONE, list(children), parents, list(queries), ask=ask, now=NOW)


def test_signed_zone_with_ds_and_dnskey():
    result = collect()
    assert result["zone"] == "bank.test." and result["method"] == "dns-query" and result["schema_version"] == 1
    assert result["ds"]["status"] == "present" and result["ds"]["server"] == TLD
    assert result["sources"] == {"child": [NS1, NS2], "parent": [TLD], "server_list": "given by the operator"}
    assert result["collected_at"].endswith("Z") and result["errors"] == []


def test_rrsig_metadata_is_kept():
    sig = collect()["dnskey"]["rrsig"][0]
    assert sig["covers"] == "DNSKEY" and sig["signer"] == "bank.test." and sig["algorithm"] == 13
    assert sig["inception"] < sig["expiration"] and sig["expiration"].endswith("Z") and sig["signature"]


def test_query_snapshot_is_partial_at_best():
    completeness = collect()["completeness"]
    assert completeness["status"] == "partial" and "not the whole zone" in completeness["scope"]


def test_servers_that_disagree_are_reported():
    ask, _ = lab_ask(plan())
    other_ask, _ = lab_ask(plan(dnskey=("K1", "Z")))

    def disagreeing(server, name, rdtype):
        return (other_ask if server == NS2 else ask)(server, name, rdtype)

    result = collect(ask=disagreeing)
    assert result["completeness"]["status"] == "inconsistent"
    assert any("bank.test. DNSKEY" in w and NS1 in w and NS2 in w for w in result["warnings"])


def test_answer_from_a_recursive_cache_is_not_used():
    ask, _ = lab_ask(plan())

    def cached(server, name, rdtype):
        response = ask(server, name, rdtype)
        response.flags &= ~dns.flags.AA
        return response

    result = collect(ask=cached)
    assert result["completeness"]["status"] == "failed" and "not_authoritative" in result["errors"][0]


def test_no_private_key_material_in_the_output():
    parsed = plan()
    ask, world = lab_ask(parsed)
    text = snap.to_yaml(collect(ask=ask))
    assert "PRIVATE" not in text and "private" not in text
    for key in world.keys.values():
        secret = key.private.private_numbers().private_value.to_bytes(32, "big")
        assert base64.b64encode(secret).decode() not in text and secret.hex() not in text


# ---- the command


def run(monkeypatch, tmp_path, ask, *extra):
    monkeypatch.setattr(snap, "query_server", ask)
    output = tmp_path / "snapshot.yaml"
    arguments = ["snapshot", "bank.test.", "--output", str(output), "--server", NS1, "--server", NS2, "--parent-server", TLD, *extra]
    return main(arguments), output


def test_command_writes_nothing_when_collection_fails(monkeypatch, tmp_path, capsys):
    def down(*_):
        raise dns.exception.Timeout()

    code, output = run(monkeypatch, tmp_path, down)
    assert code == EXIT_ERROR and not output.exists() and "timeout" in capsys.readouterr().err
