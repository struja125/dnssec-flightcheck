"""The network lab over real sockets on loopback addresses (no Docker needed)."""

import threading
import time

import dns.message
import dns.query
import pytest

from flightcheck.lab.network import UdpNetwork, lab_init, load_world, serve
from flightcheck.lab.resolver import Resolver

from .conftest import SCENARIOS

PORT = 5354
ADDRESSES = {"root": "127.0.0.10", "tld": "127.0.0.11", "ns1": "127.0.0.12", "ns2": "127.0.0.13"}


@pytest.fixture(scope="module")
def network_lab(tmp_path_factory):
    directory = tmp_path_factory.mktemp("netlab")
    lab_init(
        str(SCENARIOS / "ksk-double-ds-good.yaml"),
        str(directory),
        scale=600,
        start_delay=0,
        port=PORT,
        addresses=ADDRESSES,
    )
    threading.Thread(target=serve, args=(str(directory), list(ADDRESSES)), kwargs={"log": lambda *_: None}, daemon=True).start()
    time.sleep(1.0)
    return directory


def test_servers_answer_with_signatures(network_lab):
    query = dns.message.make_query("www.bank.test.", "A", want_dnssec=True)
    response = dns.query.udp(query, ADDRESSES["ns1"], port=PORT, timeout=2)
    assert response.answer and any(r.rdtype == 46 for r in response.answer)
    referral = dns.query.udp(dns.message.make_query("www.bank.test.", "A", want_dnssec=True), ADDRESSES["root"], port=PORT, timeout=2)
    assert referral.authority[0].name.to_text() == "test."


def test_emulated_resolver_validates_over_udp(network_lab):
    config, plan, world = load_world(str(network_lab))
    resolver = Resolver(
        "net", UdpNetwork(PORT), [ADDRESSES["root"]], world.trust_anchor(), wall_base=config.start_wall
    )
    outcome = resolver.resolve("www.bank.test.", "A", time.time() - config.start_wall)
    assert outcome.status == "secure", outcome.reason
