"""Snapshots by zone transfer, from the stable lab over real TCP on loopback. No Docker, no Internet."""

import itertools
import socket
import struct
import threading
import time
from pathlib import Path

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring
import pytest
import yaml

from flightcheck import axfr, snapshot as snap
from flightcheck.cli import EXIT_SAFE, main
from flightcheck.lab.authserver import AuthServer
from flightcheck.lab.keys import load_keys
from flightcheck.lab.network import lab_bootstrap, lab_init, load_world, serve
from flightcheck.plan import PlanError, load_plan
from flightcheck.planbuilder import build_plan, key_id, plan_text

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = ROOT / "lab" / "docker" / "bootstrap" / "bank-test.yaml"
ZONE = dns.name.from_text("bank.test.")
ADDRESSES = {"root": "127.0.0.70", "tld": "127.0.0.71", "ns1": "127.0.0.72", "ns2": "127.0.0.73"}
ports = itertools.count(5380)
CLIENT = "127.0.0.1"  # where loopback connections come from


def start_lab(tmp_path, source=None, allow=(CLIENT,)):
    port = next(ports)
    zone_file = BOOTSTRAP
    if source is not None:
        zone_file = tmp_path / f"zone-{port}.yaml"
        zone_file.write_text(yaml.safe_dump(source), encoding="utf-8")
    directory = tmp_path / f"lab-{port}"
    lab_bootstrap(str(zone_file), str(directory), port=port, addresses=ADDRESSES)
    kwargs = {"forever": True, "log": lambda *_: None, "axfr_allow": list(allow)}
    threading.Thread(target=serve, args=(str(directory), list(ADDRESSES)), kwargs=kwargs, daemon=True).start()
    time.sleep(0.5)
    return directory, port


def over_port(port):
    return (
        lambda server, zone, tsig: axfr.transfer_zone(server, zone, tsig, port=port, timeout=2, lifetime=5),
        lambda server, name, rdtype: snap.query_server(server, name, rdtype, port=port, timeout=1),
    )


def collect(port, children=("ns1", "ns2"), parent=True):
    transfer, ask = over_port(port)
    servers = [ADDRESSES[role] for role in children]
    return axfr.collect_axfr_snapshot(ZONE, servers, [ADDRESSES["tld"]] if parent else [], transfer=transfer, ask=ask)


def inputs(snapshot, rollover="zsk"):
    flags = 257 if rollover == "ksk" else 256
    return {
        "replace": key_id(next(k for k in snapshot["dnskey"]["keys"] if k["flags"] == flags)),
        "new_key": {"algorithm": "ECDSAP256SHA256"},
        "start": snapshot["collected_at"],
        "delays": {"propagation": "5m", "registry": "1h", "parent_propagation": "5m"},
        "margin": "1h",
        "resolver": {"max_cache_ttl": "1d"},
        "zone_ttl_bound": "1d",
    }


@pytest.fixture(scope="module")
def running(tmp_path_factory):
    return start_lab(tmp_path_factory.mktemp("axfr"))


@pytest.fixture(scope="module")
def both(running):
    return collect(running[1])


def scripted_server(script) -> int:
    """A TCP server that sends what ``script(query wire)`` returns, one list of messages, and then hangs up."""
    listener = socket.create_server(("127.0.0.1", 0))

    def run():
        while True:
            connection, _ = listener.accept()
            with connection:
                (length,) = struct.unpack("!H", connection.recv(2))
                wire = connection.recv(length)
                for message in script(wire):
                    connection.sendall(struct.pack("!H", len(message)) + message)

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


def real_messages(running, wire, per_message=5):
    _, _, world = load_world(str(running[0]))
    server = AuthServer("ns1", lambda t: [world.zone_at(t)])
    return server.transfer_messages(dns.message.from_wire(wire), 0, per_message)


def try_script(script):
    port = scripted_server(script)
    return axfr._attempt(lambda server, zone, tsig: axfr.transfer_zone(server, zone, tsig, port=port, timeout=1, lifetime=3), "127.0.0.1", ZONE, None)


# ---- A: ordinary mode is unchanged


def test_ordinary_mode_stays_the_default(running, tmp_path, monkeypatch):
    original = snap.query_server
    monkeypatch.setattr(snap, "query_server", lambda server, name, rdtype: original(server, name, rdtype, port=running[1], timeout=1))
    monkeypatch.setattr(axfr, "transfer_zone", lambda *a, **k: pytest.fail("a transfer was attempted"))
    output = tmp_path / "regular.yaml"
    arguments = ["snapshot", "bank.test.", "--server", ADDRESSES["ns1"], "--parent-server", ADDRESSES["tld"], "--query", "www.bank.test./A", "--output", str(output)]
    assert main(arguments) == EXIT_SAFE
    data = yaml.safe_load(output.read_text(encoding="utf-8"))
    assert data["method"] == "dns-query" and data["completeness"]["status"] == "partial" and "transfer" not in data


# ---- B and G: a real transfer keeps the records and their metadata


def test_transfer_gets_the_whole_zone(running, both):
    assert both["method"] == "axfr" and both["errors"] == []
    assert both["completeness"]["status"] == "complete"
    assert both["transfer"]["status"] == "complete" and both["transfer"]["cross_server"] == "consistent"
    names = {(r["name"], r["type"]) for r in both["rrsets"]}
    assert {("www.bank.test.", "A"), ("mail.bank.test.", "A"), ("lab-ns1.bank.test.", "A"), ("lab-ns2.bank.test.", "A")} == names
    assert len(both["denial_rrsets"]) == 5 and all(r["type"] == "NSEC" and r["rrsig"] for r in both["denial_rrsets"])
    assert both["unsigned_rrsets"] == []


# ---- C: several messages


def test_lab_transfer_really_spans_several_messages(running):
    assert len(list(dns.query.xfr(ADDRESSES["ns1"], ZONE, port=running[1], timeout=2, relativize=False))) > 1


# ---- D: broken transfers are never complete


def test_interrupted_transfer(running):
    result = try_script(lambda wire: [real_messages(running, wire)[0].to_wire()])
    assert result["zone"] is None and result["status"] == "incomplete"


def test_final_soa_with_another_serial(running):
    def script(wire):
        message = real_messages(running, wire, per_message=500)[0]
        last = message.answer[-1]
        changed = dns.rrset.from_rdata_list(last.name, last.ttl, [last[0].replace(serial=99)])
        message.answer = [*message.answer[:-1], changed]
        return [message.to_wire()]

    assert try_script(script)["zone"] is None


def test_records_outside_the_zone_reject_the_transfer(running):
    def script(wire):
        message = real_messages(running, wire, per_message=500)[0]
        message.answer.insert(1, dns.rrset.from_text("other.example.", 60, "IN", "A", "192.0.2.1"))
        return [message.to_wire()]

    result = try_script(script)
    assert result["zone"] is None and result["status"] == "malformed"


# ---- E and K: refusal and access


def test_client_not_on_the_list_is_refused(tmp_path):
    _, port = start_lab(tmp_path, allow=("192.0.2.99",))
    transfer, ask = over_port(port)
    result = axfr.collect_axfr_snapshot(ZONE, [ADDRESSES["ns1"]], [ADDRESSES["tld"]], transfer=transfer, ask=ask)
    assert result["completeness"]["status"] == "failed" and result["transfer"]["servers"][0]["status"] == "refused"
    assert "refused" in result["errors"][0]


def test_experiment_lab_refuses_to_offer_transfers(tmp_path):
    lab_init(str(ROOT / "scenarios" / "ksk-double-ds-good.yaml"), str(tmp_path / "lab"), port=5399)
    with pytest.raises(PlanError, match="stable lab"):
        serve(str(tmp_path / "lab"), ["ns1"], axfr_allow=[CLIENT], log=lambda *_: None)


def test_failed_transfer_does_not_fall_back_to_queries(tmp_path, monkeypatch):
    def no_queries(*_args, **_kwargs):
        pytest.fail("a failed transfer must not turn into queries")

    transfer = lambda *_: (_ for _ in ()).throw(EOFError())
    result = axfr.collect_axfr_snapshot(ZONE, ["127.0.0.1"], [], transfer=transfer, ask=no_queries)
    assert result["completeness"]["status"] == "failed" and result["method"] == "axfr"


def test_tsig_is_used_verified_and_kept_out_of_the_snapshot(running, tmp_path):
    secret = "c2VjcmV0LWZvci10ZXN0cw=="
    keyring = dns.tsigkeyring.from_text({"xfr-key.": secret})
    seen = []

    def script(wire):
        query = dns.message.from_wire(wire, keyring=keyring)
        seen.append(query.had_tsig)
        unsigned = real_messages(running, dns.message.make_query(ZONE, dns.rdatatype.AXFR).to_wire(), per_message=500)[0]
        response = dns.message.make_response(query)
        response.flags |= unsigned.flags
        response.answer = unsigned.answer
        return [response.to_wire()]

    port = scripted_server(script)
    key_file = tmp_path / "tsig.yaml"
    key_file.write_text(yaml.safe_dump({"name": "xfr-key.", "secret": secret}), encoding="utf-8")
    tsig = axfr.load_tsig(str(key_file))
    transfer = lambda server, zone, key: axfr.transfer_zone(server, zone, key, port=port, timeout=2, lifetime=5)
    result = axfr.collect_axfr_snapshot(ZONE, ["127.0.0.1"], [], tsig=tsig, transfer=transfer)
    assert seen == [True] and result["transfer"]["status"] == "complete"
    assert secret not in snap.to_yaml(result)


# ---- F: the DS comes from the parent


def test_ds_is_asked_from_the_parent(running, both):
    keys = load_keys(running[0] / "keys")
    assert both["ds"]["status"] == "present" and both["ds"]["server"] == ADDRESSES["tld"]
    assert both["ds"]["ttl"] == 86400 and both["ds"]["rrsig"]
    assert [r["digest"] for r in both["ds"]["records"]] == [keys["KSK1"].ds(ZONE).digest.hex()]
    assert both["transfer"]["parent_ds_collected"] is True


# ---- H: several servers


def test_one_server_is_a_complete_inventory_with_unverified_consistency(running):
    result = collect(running[1], children=("ns1",))
    assert result["transfer"]["status"] == "complete" and result["transfer"]["cross_server"] == "unverified"
    assert result["completeness"]["status"] == "partial"
    assert any("name servers" in line for line in result["warnings"])


def test_same_serial_with_different_contents_is_inconsistent(running, tmp_path):
    source = yaml.safe_load(BOOTSTRAP.read_text(encoding="utf-8"))
    source["initial"]["data"]["www"]["ttl"] = "2h"
    _, other = start_lab(tmp_path, source)
    first, ask = over_port(running[1])
    second, _ = over_port(other)
    choose = {ADDRESSES["ns1"]: first, ADDRESSES["ns2"]: second}
    transfer = lambda server, zone, tsig: choose[server](server, zone, tsig)
    result = axfr.collect_axfr_snapshot(ZONE, [ADDRESSES["ns1"], ADDRESSES["ns2"]], [ADDRESSES["tld"]], transfer=transfer, ask=ask)
    serials = [row["serial"] for row in result["transfer"]["servers"]]
    assert serials[0] == serials[1]
    assert result["completeness"]["status"] == "inconsistent" and result["transfer"]["cross_server"] == "inconsistent"
    assert any("different records" in line for line in result["warnings"])
    with pytest.raises(PlanError, match="inconsistent"):
        build_plan(result, "zsk", inputs(result))


# ---- I: the plan builder reads it


@pytest.mark.parametrize("rollover", ["zsk", "ksk"])
def test_plan_from_a_complete_transfer_runs_in_check_fix_and_lab(both, tmp_path, rollover):
    path, fixed = tmp_path / "plan.yaml", tmp_path / "fixed.yaml"
    path.write_text(plan_text(build_plan(both, rollover, inputs(both, rollover))), encoding="utf-8")
    parsed = load_plan(path)
    assert parsed.coverage == "complete" and parsed.source["provenance"]["snapshot"]["method"] == "axfr"
    assert "unobserved-records" not in parsed.data_names
    assert {"www", "mail", "lab-ns1-A", "lab-ns2-A", "apex-SOA", "apex-NS"} == set(parsed.data_names)
    assert main(["--no-color", "check", str(path)]) == EXIT_SAFE
    assert main(["--no-color", "fix", str(path), "--write", str(fixed)]) == EXIT_SAFE
    assert main(["--no-color", "lab", str(fixed), "--resolvers", "1", "--probe-interval", "3600"]) == 0
