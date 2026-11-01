"""The workflow from a running stable lab, through a snapshot over real sockets, to a plan. No Docker, no Internet."""

import base64
import itertools
import threading
import time
from pathlib import Path

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import pytest
import yaml

from flightcheck import snapshot as snap
from flightcheck.cli import EXIT_MODEL_LIMITED, main
from flightcheck.lab.keys import load_keys
from flightcheck.lab.network import lab_bootstrap, lab_init, load_world, serve
from flightcheck.plan import PlanError, load_plan
from flightcheck.planbuilder import build_plan, key_id, plan_text

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = ROOT / "lab" / "docker" / "bootstrap" / "bank-test.yaml"
ZONE = dns.name.from_text("bank.test.")
NAMES = ["www.bank.test./A", "mail.bank.test./A"]
ports = itertools.count(5360)  # a server cannot be stopped from here, so each lab gets its own port


def addresses():
    return {"root": "127.0.0.30", "tld": "127.0.0.31", "ns1": "127.0.0.32", "ns2": "127.0.0.33"}


def start_lab(tmp_path, source=None) -> tuple[Path, int]:
    """A stable lab with running servers, from the shipped bootstrap or another one."""
    port = next(ports)
    directory = tmp_path / f"lab-{port}"
    zone_file = BOOTSTRAP
    if source is not None:
        zone_file = tmp_path / f"zone-{port}.yaml"
        zone_file.write_text(yaml.safe_dump(source), encoding="utf-8")
    lab_bootstrap(str(zone_file), str(directory), port=port, addresses=addresses())
    threading.Thread(target=serve, args=(str(directory), list(addresses())), kwargs={"forever": True, "log": lambda *_: None}, daemon=True).start()
    time.sleep(0.5)
    return directory, port


def collect(port, parent=True):
    names = [snap.parse_query(text, ZONE) for text in NAMES]
    ask = lambda server, name, rdtype: snap.query_server(server, name, rdtype, port=port, timeout=1)
    servers = addresses()
    return snap.collect_snapshot(ZONE, [servers["ns1"], servers["ns2"]], [servers["tld"]] if parent else [], names, ask=ask)


def raw(port, server, name, rdtype):
    """An independent look at what a server sends, without the collector."""
    query = dns.message.make_query(name, rdtype, want_dnssec=True)
    return dns.query.tcp(query, addresses()[server], port=port, timeout=2)


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


def built(snapshot, rollover="zsk"):
    return yaml.safe_load(plan_text(build_plan(snapshot, rollover, inputs(snapshot, rollover))))


@pytest.fixture(scope="module")
def running(tmp_path_factory):
    return start_lab(tmp_path_factory.mktemp("bootstrap"))


@pytest.fixture(scope="module")
def collected(running):
    return collect(running[1])


# ---- A: a stable bootstrap


def test_bootstrap_refuses_a_plan_with_steps(tmp_path):
    with pytest.raises(PlanError, match="must have no steps"):
        lab_bootstrap(str(ROOT / "scenarios" / "ksk-double-ds-good.yaml"), str(tmp_path / "lab"))
    assert not (tmp_path / "lab").exists()


# ---- B and C: a real snapshot that is accurate


def test_snapshot_matches_the_keys_the_lab_made(running, collected):
    keys = load_keys(running[0] / "keys")
    published = {k["public_key"]: k for k in collected["dnskey"]["keys"]}
    assert set(published) == {base64.b64encode(keys[name].dnskey.key).decode() for name in ("KSK1", "ZSK1")}
    assert published[base64.b64encode(keys["ZSK1"].dnskey.key).decode()]["key_tag"] == dns.dnssec.key_id(keys["ZSK1"].dnskey)
    assert [record["digest"] for record in collected["ds"]["records"]] == [keys["KSK1"].ds(ZONE).digest.hex()]
    assert all(s["key_tag"] == keys["KSK1"].tag for s in collected["dnskey"]["rrsig"])
    assert all(s["key_tag"] == keys["ZSK1"].tag for r in collected["rrsets"] for s in r["rrsig"])


# ---- D: a plan from the snapshot


@pytest.mark.parametrize("rollover", ["zsk", "ksk"])
def test_plan_works_with_check_fix_and_lab(collected, tmp_path, rollover):
    path, fixed = tmp_path / "plan-from-snapshot.yaml", tmp_path / "fixed.yaml"
    path.write_text(plan_text(built(collected, rollover)), encoding="utf-8")
    parsed = load_plan(path)
    assert parsed.coverage == "sampled"
    assert parsed.source["provenance"]["keys"][inputs(collected, rollover)["replace"]]["public_key"]
    assert {"www", "mail", "apex-SOA", "apex-NS", "unobserved-records"} == set(parsed.data_names)
    assert main(["--no-color", "check", str(path)]) == EXIT_MODEL_LIMITED
    assert main(["--no-color", "fix", str(path), "--write", str(fixed)]) == EXIT_MODEL_LIMITED and fixed.exists()
    assert main(["--no-color", "lab", str(fixed), "--resolvers", "1", "--probe-interval", "3600"]) == 0


# ---- E: the plan follows the DNS answers


def test_another_zone_gives_another_plan(tmp_path, collected):
    source = yaml.safe_load(BOOTSTRAP.read_text(encoding="utf-8"))
    source["initial"]["dnskey"]["ttl"] = "2h"
    source["initial"]["ds"]["ttl"] = "3h"
    source["initial"]["data"]["www"]["ttl"] = "10m"
    source["initial"]["data"]["api"] = {"signed_by": ["ZSK1"], "ttl": "20m"}
    _, port = start_lab(tmp_path, source)
    changed = collect(port)
    first, second = built(collected), built(changed)
    assert second["initial"]["dnskey"]["ttl"] == 7200 and first["initial"]["dnskey"]["ttl"] == 3600
    assert second["initial"]["ds"]["ttl"] == 10800 and first["initial"]["ds"]["ttl"] == 86400
    assert second["initial"]["data"]["www"]["ttl"] == 600
    assert second["steps"][1]["at"] == first["steps"][1]["at"] + 3600  # one hour more of DNSKEY TTL to wait for
    assert not set(first["keys"]) & set(second["keys"]) - {"new-zsk-placeholder"}  # other keys, from other answers
    # The names the bootstrap used are never seen by the snapshot, so they cannot reach the plan.
    assert "KSK1" not in plan_text(second) and "ZSK1" not in plan_text(second)


# ---- F: nothing is invented


def test_missing_ds_answer_stops_the_plan(running):
    without_parent = collect(running[1], parent=False)
    assert without_parent["ds"]["status"] == "unknown"
    with pytest.raises(PlanError, match="DS state is unknown"):
        build_plan(without_parent, "zsk", inputs(without_parent))


# ---- G: TTLs are compressed once


def test_ttls_are_scaled_only_by_the_later_lab_run(collected, tmp_path):
    plan = built(collected)
    assert plan["initial"]["dnskey"]["ttl"] == collected["dnskey"]["ttl"] == 3600
    assert plan["initial"]["data"]["mail"]["ttl"] == 86400
    path = tmp_path / "plan-from-snapshot.yaml"
    path.write_text(plan_text(plan), encoding="utf-8")
    lab_init(str(path), str(tmp_path / "lab"), scale=600, start_delay=0, port=5399)
    _, parsed, world = load_world(str(tmp_path / "lab"))
    served = world.zone_at(-1)
    assert served.get(ZONE, dns.rdatatype.DNSKEY).ttl == 6
    assert served.get(dns.name.from_text("mail.bank.test."), dns.rdatatype.A).ttl == 144
    assert world.tld_at(-1).get(ZONE, dns.rdatatype.DS).ttl == 144
    assert parsed.initial["dnskey"].ttl == 3600  # the plan keeps plan seconds
