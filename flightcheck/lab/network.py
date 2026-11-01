"""The lab over a real network: authoritative servers on UDP/TCP, a shared compressed clock,
generated resolver configurations, and a probe that measures what real resolvers answer.

Every process of one lab run reads the same lab directory written by ``lab-init``:

    lab.json        clock (start time, scale), addresses, port
    plan.yaml       the plan being executed
    keys/           private keys shared by all servers
    root.hints      root hints for resolvers
    root.ds         the lab's root trust anchor
    unbound.conf    ready-to-use resolver configurations
    named.conf
"""

from __future__ import annotations

import json
import shutil
import socketserver
import struct
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import yaml

from ..durations import format_duration, format_offset
from ..fixer import fix_plan
from ..plan import MODELS, RESOLVER_PROFILES, Plan, PlanError, load_plan
from ..report_html import render_html
from ..simulator import simulate
from .authserver import AuthServer
from .comparison import compare, comparison_lines, provenance_lines, provenance_row, validated_answer_rule
from .keys import load_keys, save_keys
from .resolver import BOGUS, INSECURE, SECURE, Network, Resolver
from .zones import LabWorld, generate_lab_keys, key_mapping

ROLES = ("root", "tld", "ns1", "ns2")
DOCKER_ADDRESSES = {"root": "10.53.0.10", "tld": "10.53.0.11", "ns1": "10.53.0.12", "ns2": "10.53.0.13"}
REAL_SOFTWARE = ("unbound", "bind")
EMULATED_MEMORY = (60, 1)  # (failed chain of trust, failed answer) of serve_resolver, in real seconds
RECOVERY_SECONDS = 20  # real seconds of measuring after the latest moment a resolver can still fail


def software_of(label: str) -> str | None:
    """The real resolver behind a label ("unbound", "bind-0"), or None for an emulated one."""
    return next((name for name in REAL_SOFTWARE if label == name or label.startswith(f"{name}-")), None)


def probe_model(label: str) -> str:
    """The model a resolver is compared with: only a validator behind a cache can meet every cached version."""
    return "conservative" if "behind-cache" in label else "fetch"


def lab_memory(software: str | None, scale: float) -> tuple[int, int]:
    """(failed chain of trust, failed answer) memory of a lab resolver, in real seconds.

    The chain-of-trust timers cannot be configured. On a compressed clock the generated configurations
    shorten the answer timers (val-bogus-ttl 1, servfail-ttl 0), at real time they keep their defaults.
    """
    if software is None:
        return EMULATED_MEMORY
    key_failure, answer = RESOLVER_PROFILES[software]
    if scale > 1:
        answer = {"unbound": 1, "bind": 0}[software]
    return key_failure, answer


def _tuned(plan: Plan, software: str | None, scale: float, memory: bool = True) -> Plan:
    key_failure, answer = lab_memory(software, scale) if memory else (0, 0)
    return replace(plan, key_failure_ttl=key_failure, bogus_ttl=answer, profile=software or plan.profile)


def recovery_time(scale: float) -> float:
    """Plan seconds to keep measuring after the zone is valid again, so every lab resolver can recover."""
    longest = max(sum(lab_memory(software, scale)) for software in (*REAL_SOFTWARE, None))
    return (longest + RECOVERY_SECONDS) * scale


@dataclass
class LabConfig:
    start_wall: float  # real time (epoch seconds) at which the plan clock shows t_begin
    scale: float  # plan seconds per real second
    t_begin: float
    t_end: float
    port: int = 53
    addresses: dict = field(default_factory=lambda: dict(DOCKER_ADDRESSES))

    def plan_time(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        return self.t_begin + (now - self.start_wall) * self.scale

    def real_seconds(self, plan_seconds: float) -> float:
        return plan_seconds / self.scale

    @property
    def end_wall(self) -> float:
        return self.start_wall + (self.t_end - self.t_begin) / self.scale

    def save(self, directory: Path) -> None:
        (directory / "lab.json").write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path) -> "LabConfig":
        return cls(**json.loads((directory / "lab.json").read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# lab-init


def lab_init(
    plan_path: str,
    out_dir: str,
    scale: float = 600,
    start_delay: float = 30,
    port: int = 53,
    addresses: dict | None = None,
    resolver_addresses: dict | None = None,
) -> LabConfig:
    directory = Path(out_dir)
    plan = load_plan(plan_path)
    target = directory / "plan.yaml"
    # A folder with a plan.yaml that no earlier lab run wrote holds someone's own file.
    if target.exists() and (target.resolve() == Path(plan_path).resolve() or not (directory / "lab.json").exists()):
        raise PlanError(f"{target}: the lab would overwrite this plan; choose another --out folder")
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(plan_path, target)
    keys = generate_lab_keys(plan)
    save_keys(keys, directory / "keys")
    mapping = yaml.safe_dump(key_mapping(plan, keys), sort_keys=False)
    (directory / "key_mapping.yaml").write_text(mapping, encoding="utf-8")

    prediction = simulate(plan, "conservative")
    longest_ttl = max((v.ttl for versions in prediction.timelines.values() for v in versions), default=3600)
    first_step = min((s.at for s in plan.steps), default=0)
    config = LabConfig(
        start_wall=time.time() + start_delay,
        scale=scale,
        t_begin=first_step - longest_ttl,
        t_end=prediction.view_range()[1] + recovery_time(scale),
        port=port,
        addresses={**DOCKER_ADDRESSES, **(addresses or {})},
    )
    config.save(directory)

    world = LabWorld(plan, config.start_wall, config.addresses, config.scale, load_keys(directory / "keys"), config.t_begin)
    ds = world.root_key.ds(dns.name.root)
    (directory / "root.ds").write_text(f". IN DS {ds.to_text()}\n", encoding="utf-8")
    (directory / "root.hints").write_text(
        f".            3600000 NS a.root-lab.\na.root-lab.  3600000 A  {config.addresses['root']}\n",
        encoding="utf-8",
    )
    (directory / "unbound.conf").write_text(_unbound_conf(world, config), encoding="utf-8")
    (directory / "named.conf").write_text(_named_conf(ds, config), encoding="utf-8")
    return config


def lab_bootstrap(plan_path: str, out_dir: str, port: int = 53, addresses: dict | None = None) -> LabConfig:
    """A lab that stays as it is, for ``snapshot`` to query: no steps, so nothing ever changes, and a real-time
    clock, so the TTLs in the snapshot are the plain ones and only a later lab run compresses them."""
    if load_plan(plan_path).steps:
        raise PlanError(f"{plan_path}: a bootstrap describes the zone as it is now, so it must have no steps")
    return lab_init(plan_path, out_dir, scale=1, start_delay=0, port=port, addresses=addresses)


def _unbound_conf(world: LabWorld, config: LabConfig) -> str:
    bogus_ttl = "val-bogus-ttl: 1" if config.scale > 1 else "# val-bogus-ttl keeps its default"
    return f"""# generated by flightcheck lab-init
server:
    interface: 0.0.0.0
    port: 53
    access-control: 0.0.0.0/0 allow
    do-ip6: no
    root-hints: "/lab/root.hints"
    trust-anchor-file: "/lab/root.ds"
    module-config: "validator iterator"
    # by default Unbound answers the reserved .test TLD itself and never asks the lab's servers
    local-zone: "test." nodefault
    # keep the lab clock honest: no minimum TTLs, short bogus caching, no prefetch, no stale data
    cache-min-ttl: 0
    {bogus_ttl}
    prefetch: no
    prefetch-key: no
    serve-expired: no
    do-not-query-localhost: no
    harden-dnssec-stripped: yes
    val-log-level: 2
    verbosity: 1
    use-syslog: no
    logfile: ""
    ede: yes
    username: ""
    chroot: ""
    pidfile: ""
"""


def _named_conf(ds, config: LabConfig) -> str:
    digest = ds.digest.hex().upper()
    servfail_ttl = "servfail-ttl 0;" if config.scale > 1 else "// servfail-ttl keeps its default"
    return f"""// generated by flightcheck lab-init
options {{
    directory "/var/cache/bind";
    listen-on {{ any; }};
    listen-on-v6 {{ none; }};
    recursion yes;
    allow-query {{ any; }};
    allow-recursion {{ any; }};
    dnssec-validation yes;
    // keep the lab clock honest
    prefetch 0;
    stale-answer-enable no;
    stale-cache-enable no;
    {servfail_ttl}
    min-cache-ttl 0;
    min-ncache-ttl 0;
}};

trust-anchors {{
    . static-ds {ds.key_tag} {ds.algorithm} {ds.digest_type} "{digest}";
}};

zone "." {{
    type hint;
    file "/lab/root.hints";
}};

logging {{
    channel stderr_log {{ stderr; severity info; print-time yes; }};
    category dnssec {{ stderr_log; }};
    category default {{ stderr_log; }};
}};
"""


def load_world(lab_dir: str) -> tuple[LabConfig, Plan, LabWorld]:
    directory = Path(lab_dir)
    config = LabConfig.load(directory)
    plan = load_plan(directory / "plan.yaml")
    world = LabWorld(plan, config.start_wall, config.addresses, config.scale, load_keys(directory / "keys"), config.t_begin)
    return config, plan, world


# ---------------------------------------------------------------------------
# authoritative servers


def _wire_response(response: dns.message.Message, query: dns.message.Message, max_size: int) -> bytes:
    try:
        return response.to_wire(max_size=max_size)
    except dns.exception.TooBig:
        truncated = dns.message.make_response(query)
        truncated.flags |= dns.flags.TC | (response.flags & dns.flags.AA)
        return truncated.to_wire()


class _Answerer:
    def __init__(self, respond):
        self.respond = respond
        self.lock = threading.Lock()

    def answer(self, wire: bytes, udp: bool) -> bytes | None:
        try:
            query = dns.message.from_wire(wire)
        except Exception:
            return None
        with self.lock:
            response = self.respond(query)
        size = 65535
        if udp:
            size = max(512, query.payload) if query.edns >= 0 else 512
        return _wire_response(response, query, size)


def _transfer_for(server: AuthServer, config: LabConfig, allowed: list[str], lock):
    """Answers AXFR queries for clients on the list, and leaves every other query to the normal path."""

    def transfer(wire: bytes, client: str) -> list[bytes] | None:
        try:
            query = dns.message.from_wire(wire)
        except Exception:
            return None
        if not query.question or query.question[0].rdtype != dns.rdatatype.AXFR:
            return None
        if client not in allowed:
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.REFUSED)
            return [response.to_wire()]
        with lock:
            return [message.to_wire() for message in server.transfer_messages(query, config.plan_time())]

    return transfer


def _start(answerer: _Answerer, host: str, port: int, transfer=None) -> list[socketserver.BaseServer]:
    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            reply = answerer.answer(data, udp=True)
            if reply:
                sock.sendto(reply, self.client_address)

    class TCPHandler(socketserver.StreamRequestHandler):
        def handle(self):
            while True:
                header = self.rfile.read(2)
                if len(header) < 2:
                    return
                (length,) = struct.unpack("!H", header)
                wire = self.rfile.read(length)
                messages = transfer(wire, self.client_address[0]) if transfer else None
                if messages is not None:
                    for message in messages:
                        self.wfile.write(struct.pack("!H", len(message)) + message)
                    continue
                reply = answerer.answer(wire, udp=False)
                if not reply:
                    return
                self.wfile.write(struct.pack("!H", len(reply)) + reply)

    socketserver.ThreadingUDPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    servers = [
        socketserver.ThreadingUDPServer((host, port), UDPHandler),
        socketserver.ThreadingTCPServer((host, port), TCPHandler),
    ]
    for server in servers:
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
    return servers


def serve(lab_dir: str, roles: list[str], forever: bool = False, log=print, axfr_allow: list[str] | None = None) -> None:
    config, plan, world = load_world(lab_dir)
    if axfr_allow and (plan.steps or config.scale != 1):
        # A running experiment has compressed TTLs and changing data, which a transfer would present as the zone.
        raise PlanError("zone transfers are only for a stable lab: use lab-bootstrap")
    zones = {
        "root": lambda t: [world.root],
        "tld": lambda t: [world.tld_at(t, plan.parent_propagation)],
        "ns1": lambda t: [world.zone_at(t, 0)],
        "ns2": lambda t: [world.zone_at(t, plan.propagation)],
    }
    running = []
    for role in roles:
        server = AuthServer(role, zones[role])
        answerer = _Answerer(lambda query, s=server: s.respond(query, config.plan_time()))
        host = config.addresses[role]
        # Only the zone's own servers hold a zone that the workflow transfers.
        transfer = _transfer_for(server, config, axfr_allow, answerer.lock) if axfr_allow and role in ("ns1", "ns2") else None
        running += _start(answerer, host, config.port, transfer)
        log(f"{role:4s} serving on {host}:{config.port}" + (f", AXFR for {', '.join(axfr_allow)}" if transfer else ""))
    log(f"plan clock: x{config.scale:g}, {format_offset(config.plan_time())} now, ends at {format_offset(config.t_end)}")
    try:
        while forever or time.time() < config.end_wall + 30:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    for server in running:
        server.shutdown()


# ---------------------------------------------------------------------------
# the emulated resolver as a network service


class UdpNetwork(Network):
    """Sends the emulated resolver's queries to real sockets (falls back to TCP on truncation)."""

    def __init__(self, port: int, timeout: float = 2.0):
        super().__init__()
        self.port = port
        self.timeout = timeout

    def query(self, ip, qname, rdtype, t):
        query = dns.message.make_query(qname, rdtype, want_dnssec=True, use_edns=0, payload=1232)
        query.flags &= ~dns.flags.RD
        self.queries += 1
        response = dns.query.udp(query, ip, port=self.port, timeout=self.timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, ip, port=self.port, timeout=self.timeout)
        return response


def serve_resolver(lab_dir: str, host: str, port: int = 53, trust_cache: bool = True, forever: bool = False, log=print):
    """Run the emulated validating resolver on ``host:port`` (answers RD queries for A records)."""
    config, plan, world = load_world(lab_dir)
    resolver = Resolver(
        f"emu@{host}",
        UdpNetwork(config.port),
        [config.addresses["root"]],
        world.trust_anchor(),
        wall_base=config.start_wall,
        max_cache_ttl=max(1, int(plan.max_cache_ttl / config.scale)),
        key_failure_ttl=EMULATED_MEMORY[0],
        bogus_ttl=EMULATED_MEMORY[1],
        trust_cache=trust_cache,
    )

    def respond(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        question = query.question[0]
        outcome = resolver.resolve(question.name, question.rdtype, time.time() - config.start_wall)
        if outcome.status == BOGUS:
            response.set_rcode(dns.rcode.SERVFAIL)
            if query.edns >= 0:
                response.use_edns(0, 0, 1232, options=[dns.edns.EDEOption(dns.edns.EDECode.DNSSEC_BOGUS, outcome.reason[:200])])
        else:
            if outcome.rrset is not None:
                response.answer.append(outcome.rrset)
            response.set_rcode(dns.rcode.from_text(outcome.rcode))
            if outcome.status == SECURE:
                response.flags |= dns.flags.AD
        return response

    answerer = _Answerer(respond)
    servers = _start(answerer, host, port)
    log(f"emulated {'validating' if trust_cache else 'behind-cache'} resolver on {host}:{port}")
    try:
        while forever or time.time() < config.end_wall + 30:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    for server in servers:
        server.shutdown()


# ---------------------------------------------------------------------------
# probe


@dataclass
class Sample:
    t: float  # plan time
    resolver: str
    name: str
    status: str  # secure / insecure / bogus / error
    rcode: str
    ede: list
    detail: str = ""


def probe(
    lab_dir: str,
    resolvers: dict[str, str],
    interval: float = 0.25,
    port: int = 53,
    timeout: float = 1.0,
    log=print,
) -> dict:
    config, plan, _world = load_world(lab_dir)
    names = [f"{name}.{plan.zone}" for name in plan.data_names]
    samples: list[Sample] = []
    wait = config.start_wall - time.time()
    if wait > 0:
        log(f"waiting {wait:.0f}s for the lab clock to start")
        time.sleep(wait)
    log(f"probing {', '.join(resolvers)} until {format_offset(config.t_end)} (about {config.end_wall - time.time():.0f}s)")
    next_report = time.time() + 10
    while time.time() < config.end_wall:
        for label, ip in resolvers.items():
            for name in names:
                samples.append(_ask(label, ip, port, name, timeout, config))
        if time.time() > next_report:
            bad = sum(1 for s in samples if s.status == BOGUS)
            log(f"  {format_offset(config.plan_time())}: {len(samples)} lookups, {bad} SERVFAIL")
            next_report += 10
        time.sleep(interval)
    return summarise(plan, config, resolvers, samples, interval)


def _ask(label, ip, port, name, timeout, config: LabConfig) -> Sample:
    query = dns.message.make_query(name, "A", want_dnssec=True, use_edns=0, payload=1232)
    t = config.plan_time()
    try:
        response = dns.query.udp(query, ip, port=port, timeout=timeout)
    except Exception as exc:  # timeouts and network errors
        return Sample(t, label, name, "error", "TIMEOUT", [], type(exc).__name__)
    rcode = dns.rcode.to_text(response.rcode())
    ede = [int(opt.code) for opt in response.options if isinstance(opt, dns.edns.EDEOption)]
    detail = "; ".join(opt.text or "" for opt in response.options if isinstance(opt, dns.edns.EDEOption))
    if response.rcode() == dns.rcode.SERVFAIL:
        status = BOGUS
    elif response.rcode() == dns.rcode.NOERROR and response.answer:
        status = SECURE if response.flags & dns.flags.AD else INSECURE
    else:
        status = "error"
    return Sample(t, label, name, status, rcode, ede, detail)


def comparison_for(plan: Plan, label: str, scale: float, model: str, samples: list[Sample], tolerance: float, max_gap: float) -> dict:
    """What one resolver did against the prediction for it. ``label`` chooses the timers of the prediction."""
    raw = simulate(_tuned(plan, software_of(label), scale, memory=False), model).failure_windows()
    return compare(
        samples, raw, resolver_windows(plan, label, scale, model), validated_answer_rule(plan, tolerance), tolerance, max_gap
    )


def resolver_windows(plan: Plan, label: str, scale: float, model: str) -> list[tuple[float, float]]:
    """When this resolver can fail, in plan time. Its timers run in real seconds, the plan clock ``scale`` times faster."""
    return simulate(_tuned(plan, software_of(label), scale), model, memory_scale=scale).failure_windows()


def summarise(plan: Plan, config: LabConfig, resolvers: dict, samples: list[Sample], interval: float) -> dict:
    tolerance = config.scale * (interval + 2)  # sampling and clock granularity, in plan seconds
    per_resolver = {}
    for label in resolvers:
        predicted = {model: resolver_windows(plan, label, config.scale, model) for model in MODELS}
        windows = {model: [(a, b + tolerance) for a, b in spans] for model, spans in predicted.items()}
        mine = [s for s in samples if s.resolver == label]
        bogus = [s for s in mine if s.status == BOGUS]
        max_gap = config.scale * (interval * 4 + 2)
        comparison = {model: comparison_for(plan, label, config.scale, model, mine, tolerance, max_gap) for model in MODELS}
        per_resolver[label] = {
            "model": probe_model(label),
            "comparison": comparison,
            "predicted_end": {model: max((b for _, b in spans), default=None) for model, spans in predicted.items()},
            "lookups": len(mine),
            "servfail": len(bogus),
            "errors": sum(1 for s in mine if s.status == "error"),
            "inside": {model: sum(1 for s in bogus if any(a <= s.t <= b for a, b in w)) for model, w in windows.items()},
            "first_servfail": bogus[0].t if bogus else None,
            "last_servfail": bogus[-1].t if bogus else None,
            "ede": sorted({code for s in bogus for code in s.ede}),
            "segments": _segments(mine, config.scale * interval * 4),
        }
    return {
        "plan": plan.name,
        "coverage": plan.coverage,
        "scale": config.scale,
        "interval": interval,
        "resolvers": resolvers,
        "per_resolver": per_resolver,
        "samples": [asdict(s) for s in samples],
    }


def _segments(samples: list[Sample], max_gap: float) -> list[tuple[float, float, str]]:
    status_of = {SECURE: "secure", INSECURE: "insecure", BOGUS: "bogus", "error": "bogus"}
    segments: list[tuple[float, float, str]] = []
    by_name: dict[str, list[Sample]] = {}
    for s in samples:
        by_name.setdefault(s.name, []).append(s)
    holds = []
    for series in by_name.values():
        for current, following in zip(series, series[1:] + [None]):
            end = following.t if following is not None else current.t + max_gap / 4
            holds.append((current.t, min(end, current.t + max_gap), status_of[current.status]))
    points = sorted({a for a, _, _ in holds} | {b for _, b, _ in holds})
    for left, right in zip(points, points[1:]):
        active = {status for a, b, status in holds if a <= left < b}
        if not active:
            continue
        status = "bogus" if "bogus" in active else "partly-insecure" if len(active) > 1 else active.pop()
        if segments and segments[-1][2] == status and segments[-1][1] == left:
            segments[-1] = (segments[-1][0], right, status)
        else:
            segments.append((left, right, status))
    return segments


def probe_report_text(result: dict, plan: Plan) -> str:
    lines = [f"FlightCheck network lab - {plan.name} (clock x{result['scale']:g})", *provenance_lines(plan)]
    predictions = {model: simulate(plan, model) for model in MODELS}
    for model, prediction in predictions.items():
        windows = ", ".join(
            f"{format_offset(f.start)} -> {format_offset(f.end)}" for f in prediction.failures
        ) or "none"
        lines.append(f"  predicted bogus ({model}): {windows}")
    for label, data in result["per_resolver"].items():
        lines.append(f"{label}: {data['lookups']} lookups, {data['servfail']} SERVFAIL, {data['errors']} errors")
        if data["servfail"]:
            lines.append(
                f"  first {format_offset(data['first_servfail'])}, last {format_offset(data['last_servfail'])}, "
                f"EDE codes {data['ede'] or '-'}"
            )
            for model, inside in data["inside"].items():
                end = data["predicted_end"][model]
                limit = "none" if end is None else format_offset(end)
                lines.append(f"  inside the {model} prediction: {inside}/{data['servfail']} (latest possible failure {limit})")
        lines.append(f"  compared with the {data['model']} model:")
        lines += comparison_lines(data["comparison"][data["model"]], "    ")
    lines.append(f"Times are plan time relative to T+0; one real second is {result['scale']:g} plan seconds.")
    return "\n".join(lines) + "\n"


def probe_report_html(result: dict, plan: Plan) -> str:
    conservative = simulate(plan, "conservative")
    fetch = simulate(plan, "fetch")
    measured = [(f"{label} (measured)", data["segments"]) for label, data in result["per_resolver"].items()]
    summary = []
    for label, data in result["per_resolver"].items():
        comparison = data["comparison"][data["model"]]
        inside = comparison["inside"]
        summary.append(
            (
                f"{label}: {comparison['classification']} ({data['model']} model)",
                f"{inside:,}/{data['servfail']:,}" if data["servfail"] else "0 failures",
                f"{data['lookups']:,} lookups, recovery: {comparison['recovery']}, EDE {data['ede'] or '-'}",
            )
        )
    summary.append(("clock", f"x{result['scale']:g}", f"one real second = {format_duration(result['scale'])} of plan time"))
    summary += provenance_row(plan)
    return render_html(conservative, fix=fix_plan(plan, "conservative"), extra=[fetch], measured=measured, lab_summary=summary)


__all__ = [
    "LabConfig",
    "lab_init",
    "load_world",
    "serve",
    "serve_resolver",
    "probe",
    "probe_report_text",
    "probe_report_html",
    "ROLES",
]
