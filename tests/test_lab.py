import pytest

from flightcheck.lab.authserver import AuthServer
from flightcheck.lab.experiment import run_experiment
from flightcheck.lab.resolver import Network, Resolver, wall_clock_for
from flightcheck.lab.zones import PRIMARY_IP, ROOT_IP, SECONDARY_IP, TLD_IP, LabWorld

H = 3600


def lab(plan, trust_cache=True):
    wall = wall_clock_for(plan.start)
    world = LabWorld(plan, wall)
    network = Network()
    network.servers[ROOT_IP] = AuthServer("root", lambda t: [world.root])
    network.servers[TLD_IP] = AuthServer("tld", lambda t: [world.tld_at(t)])
    network.servers[PRIMARY_IP] = AuthServer("ns1", lambda t: [world.zone_at(t, 0)])
    network.servers[SECONDARY_IP] = AuthServer("ns2", lambda t: [world.zone_at(t, plan.propagation)])
    resolver = Resolver("r", network, [ROOT_IP], world.trust_anchor(), wall, trust_cache=trust_cache)
    return world, resolver


def test_resolver_breaks_with_stale_ds(scenario):
    _, resolver = lab(scenario("ksk-double-ds-bad"))
    assert resolver.resolve("www.bank.test.", "A", -3 * H).status == "secure"  # caches DS v0
    outcome = resolver.resolve("www.bank.test.", "A", 3 * H)  # new DNSKEY RRset, stale DS
    assert outcome.status == "bogus" and "DS" in outcome.reason
    assert resolver.resolve("www.bank.test.", "A", 30 * H).status == "secure"


@pytest.mark.parametrize("name", ["ksk-double-ds-bad"])
def test_lab_failures_stay_inside_predictions(scenario, name):
    experiment = run_experiment(scenario(name), resolvers=6, probe_interval=600, seed=3)
    assert experiment.consistent
    assert experiment.stats["behind-cache"].bogus > 0


def test_safe_plan_has_no_failures_in_the_lab(scenario):
    experiment = run_experiment(scenario("ksk-double-ds-good"), resolvers=4, probe_interval=900, seed=3)
    assert all(stats.bogus == 0 for stats in experiment.stats.values())
