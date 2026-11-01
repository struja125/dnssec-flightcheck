# DNSSEC FlightCheck: full reference

A pre-flight simulator for DNSSEC changes. Give it the current state of a zone and a planned
change (a ZSK or KSK rollover, an algorithm rollover, turning DNSSEC on or off). It tells you
**whether any validating resolver will see a bogus answer, when, why, and the earliest safe
moment for every step**, before anything is touched in production.

```
$ flightcheck check scenarios/ksk-double-ds-bad.yaml

Verdict: UNSAFE - resolvers can answer SERVFAIL for 23h 2m in total, from T+2h (Mon 02 Nov 14:00 UTC)
until T+1d 1h 2m (Tue 03 Nov 13:02 UTC).
The zone itself cannot be validated for 23h; the rest is resolvers remembering the failure
(worst profile: chain of trust 1m, answers 1m, added up after a failed chain of trust; an upper bound).

  [1] T+2h -> T+1d 1h  (23h)
      From T+2h the zone serves DNSKEY v1 (step "Swap KSK1 for KSK2 in the DNSKEY RRset"),
      but resolvers may still hold DS v0 in their cache until T+1d 1h. DNSKEY becomes bogus:
      no chain of trust from DS to DNSKEY: none of the keys the DS RRset points to {KSK1} is
      in the DNSKEY RRset {KSK2, ZSK1}. Resolvers can keep answering SERVFAIL for up to 2m after that.

Safe schedule (worst case + 1h margin)
             T+0  Submit DS for KSK2: ok
            T+2h  Swap KSK1 for KSK2 in the DNSKEY RRset: move to T+1d 2h (earliest T+1d 1h)
            T+4h  Remove the DS for KSK1: move to T+1d 3h 5m (earliest T+1d 2h 5m)
  The corrected plan is safe.
```

Open `examples/*.html` in a browser to see the reports: a timeline of every RRset version, how
long each one can stay in resolver caches, and the predicted and measured validation status.

## Why

Validating resolvers cache the parent's DS RRset, the zone's DNSKEY RRset and every signature
separately, each with its own TTL. If a step of a key change happens before all older copies have
expired, resolvers that hold mismatched data return SERVFAIL and the domain disappears for their
users. RFC 7583 describes the timing rules, but operators apply them by hand. Existing tools
(DNSViz, Zonemaster) check the *current* state of a zone. FlightCheck checks the *future*: every
moment of a planned change.

## Install

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e .[test]      # Windows
# .venv/bin/python -m pip install -e .[test]        # Linux / macOS
```

Requires Python 3.10+, `dnspython`, `cryptography` and `pyyaml`.

## Commands

| Command | What it does | Exit code |
|---|---|---|
| `flightcheck check PLAN [--html F] [--json F] [--both-models]` | simulate the plan, explain every failure | 0 safe, 1 unsafe, 2 bad plan, 3 safe for sampled records only, 4 incomplete (no bogus answers, but no valid final state) |
| `flightcheck fix PLAN [--write FIXED.yaml] [--html F]` | earliest safe time per step, split conflicting steps, write a corrected plan | 0 safe under both models, 1 no safe plan (nothing is written), 2 bad plan, 3 safe only under the selected model (saved with that `model` and a `Model-limited:` line in `description`), 4 incomplete (timing cannot help, nothing is written) |
| `flightcheck lab PLAN [--resolvers N] [--html F] [--json F]` | execute the plan in the built-in lab and compare measurements with the prediction | 0 if every failure was predicted, 1 otherwise |

`check` is meant for CI: put zone changes in a repository as plans and fail the pipeline when a
plan is unsafe.

```yaml
# .github/workflows/dnssec.yml
- run: pip install dnssec-flightcheck
- run: flightcheck check plans/next-rollover.yaml --html report.html
```

## Snapshot of a zone

`flightcheck snapshot` records what a zone publishes now. It only sends ordinary queries to authoritative servers
and handles no private keys. It asks for a zone transfer only with `--axfr`, from a `--server` you name: see
[SNAPSHOT-WORKFLOW.md](SNAPSHOT-WORKFLOW.md#snapshot-by-zone-transfer-axfr).

```bash
flightcheck snapshot example.com --output snapshot.yaml --query www.example.com/A --query example.com/MX
flightcheck snapshot example.com --output snapshot.yaml --server 192.0.2.1 --parent-server 192.0.2.53
```

Without `--server` or `--parent-server`, the system resolver only finds whom to ask. Each section says which
server it came from, and answers that are not authoritative are not used.

| `completeness.status` | Meaning | Exit | File |
|---|---|---|---|
| `complete` | every RRset of the zone was seen. Queries cannot establish this: only `--axfr` produces it | 0 | written |
| `partial` | the apex, the DS and the requested names were asked. The best a query snapshot can be | 0 | written |
| `inconsistent` | authoritative servers gave different data or TTLs | 1 | written, as evidence |
| `failed` | no server gave the SOA. Exit 2 is also used for bad arguments | 2 | not written |

`ds.status` is `present`, `absent_signed_denial` (an NSEC proves it, checked against the DNSKEY the parent serves
but not up to a trust anchor), `absent_unproven` (for example NSEC3, which is kept but not checked), or `unknown`.
A snapshot is not a plan, and `check` rejects it: it has no keys with roles and no steps.

`flightcheck plan` turns a snapshot and an inputs file into a candidate plan for `check` and `fix`. It changes nothing in DNS.

```bash
flightcheck plan snapshot.yaml --rollover zsk --inputs inputs.yaml --output plan.yaml
flightcheck check plan.yaml
flightcheck fix plan.yaml --write fixed.yaml
```

```yaml
# inputs.yaml: everything here is the operator's word, not something that was measured
replace: key-33366-1a2b3c4d5e           # a name from the error message or the plan: tag + hash of the public key
new_key: {algorithm: ECDSAP256SHA256}   # add public_key to name a real key; without it, a placeholder
start: 2026-11-02T12:00:00Z             # not before the snapshot was taken
delays: {propagation: 5m, registry: 1h, parent_propagation: 5m}
margin: 1h
resolver: {max_cache_ttl: 1d}           # or profile: unbound
zone_ttl_bound: 1d                      # the longest TTL any RRset you did not sample can have
roles: {key-27294-9f8e7d6c5b: ksk}      # only needed when flags and signatures leave doubt
```

| In the plan | Comes from |
|---|---|
| DS, DNSKEY, RRSIG times, TTLs of observed RRsets, `negative_ttl.zone` | the snapshot: real and public, at that moment |
| `delays`, `margin`, `resolver`, `unobserved-records` TTL | the operator: assumptions |
| the new key and the steps | planned: nothing of this exists yet |
| anything else in the zone | missing: only the bound stands for it |

The builder refuses inconsistent or failed snapshots, a DS state of `unknown` or `absent_unproven`, DS records or signatures
it cannot tie to one published key, and missing inputs. Generated plans carry `provenance.coverage: sampled`. For such a plan
`check` and `fix` say "SAFE for the sampled records only" and exit 3 instead of 0, JSON has `"ok": false`. A verdict is
about the model and these inputs, and it is not a guarantee for the production zone. Signers renewing
signatures during a change are not modeled: a signature that expires during the plan makes it unsafe until a step re-signs it.

### A plan from a snapshot in the lab

A plan from `flightcheck plan` is an ordinary plan, so `lab`, `lab-init`, `probe` and `real-lab` accept it as it is.

```bash
flightcheck lab plan.yaml --html lab.html
flightcheck fix plan.yaml --write fixed.yaml && flightcheck lab fixed.yaml
```

| In the lab | What it is |
|---|---|
| Keys, DS digests, RRSIGs | **synthetic**: generated for each run, with the real key's role and algorithm. Real public keys and DS digests are not used, and private keys are never asked for. `lab-init` writes the mapping to `key_mapping.yaml`, and `lab --json` includes it |
| TTLs, signature times, delays, steps | as in the plan. Signature times follow the compressed clock |
| Observed RRsets | an A record at a name derived from the original (`www`, `www-MX`, `apex-SOA`), with its TTL and signers. The real data and types are not reproduced |
| `unobserved-records` | one A record standing for everything nobody looked at. It tests the TTL bound, and it does **not** reproduce those records |
| The zone's servers, the parent, the root | the lab's own (`lab-ns1`, `lab-ns2`). A parent of any depth is delegated directly from the lab's root |
| Not reproduced | signers renewing signatures, NSEC3, the real NS set, CDS, the parent's earliest DS moment (only its last server is modeled) |

Every report repeats the snapshot, the assumptions and the coverage. A lab run never changes `provenance.coverage`, so
`check` still gives exit 3 afterwards. The three things stay different: a **prediction** of the model, an **observation** with
synthetic keys, and how the **production** zone behaves, which neither of them shows.

With Docker, which sees only its image and `lab/docker/out`:

```bash
mkdir -p lab/docker/out
```
```bash
cp fixed.yaml lab/docker/out/candidate.yaml
```
```bash
cd lab/docker && PLAN=/lab/candidate.yaml SCALE=600 docker compose up --build -d && docker compose logs -f probe; docker compose wait probe; docker compose down
```

## Writing a plan

```yaml
name: KSK rollover (double-DS)
zone: bank.test.
start: 2026-11-02T12:00:00Z     # optional, adds absolute times to the output
delays:
  propagation: 5m               # primary -> last secondary
  registry: 1h                  # DS submitted -> visible in the parent zone
resolver:
  max_cache_ttl: 7d             # resolvers cap TTLs at this value
  profile: worst                # how long resolvers remember a failure: worst, unbound or bind
  strict_algorithms: false      # true = Unbound harden-algo-downgrade
margin: 1h                      # added to every earliest safe time
model: conservative             # or: fetch

keys:
  KSK1: {role: ksk, algorithm: ECDSAP256SHA256}
  KSK2: {role: ksk, algorithm: ECDSAP256SHA256}
  ZSK1: {role: zsk, algorithm: ECDSAP256SHA256}

initial:
  ds:     {keys: [KSK1], ttl: 1d}                            # DS RRset at the parent
  dnskey: {keys: [KSK1, ZSK1], signed_by: [KSK1], ttl: 1h}   # published keys, who signs the set
  data:
    www:  {signed_by: [ZSK1], ttl: 1h}                       # any number of signed RRsets
    mail: {signed_by: [ZSK1], ttl: 1d}

steps:                                                       # times relative to T+0
  - name: Submit DS for KSK2
    at: 0h
    ds: {keys: [KSK1, KSK2]}
  - name: Swap the KSK
    at: 26h
    dnskey: {keys: [KSK2, ZSK1], signed_by: [KSK2]}
  - name: Remove the old DS
    at: 28h
    ds: {keys: [KSK2]}
```

Two optional additions change nothing for plans without them:

```yaml
negative_ttl: {zone: 5m, parent: 1h}   # min(SOA TTL, SOA MINIMUM). Without it, a missing DS or DNSKEY uses the RRset's ttl
initial:
  data:
    www:
      signed_by: [ZSK1, ZSK2]
      rrsig:                           # relative to T+0, and may be negative. A signer without an entry is valid all plan
        ZSK1: {inception: -30d, expires: 2d}
        ZSK2: {expires: 10d}
```

`rrsig` works on `dnskey` and data RRsets, in `initial` and in steps, where it re-signs: a step that gives a key a
new period replaces only that key's period, and a key that stops signing loses its period. One signature inside
its period is enough. A signature that expires before everything the plan replaced has left the caches makes the
plan unsafe. One that expires later is the signer's routine, so it only gives a warning, and the lab renews it too.
This means that moving a step later can make a plan unsafe. `fix` never moves a step earlier, so it cannot repair an
expired signature: add a step that re-signs in time.

A step changes only the fields it names. `data: {"*": {signed_by: [ZSK2]}}` changes every data
RRset. `ds: {keys: []}` removes the DS (insecure delegation); `dnskey: {keys: [], signed_by: []}`
unsigns the zone.

## How it works

For every version of every RRset FlightCheck knows when it is **served** (from its publication
until the next version reaches the last authoritative server) and until when it can be
**cached** (served time + TTL, capped by the resolver's maximum TTL). Time is cut at every moment
where the set of possible versions changes, and at each of those moments every combination of
versions a resolver could hold is validated symbolically:

1. no DS → insecure delegation;
2. a DS must point to a published key that signs the DNSKEY RRset;
3. every data RRset must be signed by a key in the trusted DNSKEY RRset
   (optionally with Unbound's strict algorithm rule).

The result is exact, not sampled.

Resolvers also keep a validation failure for a while after the data has become valid. The report
shows this as **recovering**, separately from the time the zone itself cannot be validated. Waiting
longer never depends on it: a plan without failures has nothing to remember, so these timers change
how long an outage lasts, not which plans are safe. Choose the timers with `resolver.profile` or
`--resolver-profile`, or set `key_failure_ttl` and `bogus_ttl`:

| Profile | Failed chain of trust | Failed answer | Source |
|---|---|---|---|
| `worst` (default) | 60 s | 60 s | the longest of the measured resolvers |
| `unbound` | 60 s | 60 s | Unbound 1.26: `BOGUS_KEY_TTL`, `val-bogus-ttl` |
| `bind` | 30 s | 1 s | BIND 9.16: `DNS_RESOLVER_BADCACHETTL`, `servfail-ttl` |

After a failed answer the bound is the answer timer. After a failed chain of trust it is both timers
added up: the failed chain is kept for the first, and an answer that fails against it at its last moment
is kept for the second. This order is what the emulated resolver does. For Unbound and BIND it is an
assumption from what the timers are for, so the bound is not a claim about how long they really take.
The measurements below were taken with the shorter bound and have not been analysed again.

Two resolver models are available:

* **conservative** (default, RFC 7583): any cached versions may be validated together. This is
  what a validator behind a non-validating cache (forwarder, CPE, stub validator) experiences.
* **fetch**: a validating resolver validates an RRset when it fetches it and then trusts its
  cache, so only the RRset being fetched has to be currently served.

A plan can also never give a bogus answer and still end in a state nobody would choose, because
validation needs only one working path. FlightCheck therefore checks where the plan ends, and reports
**INCOMPLETE** (exit 4) with the missing operation: a DS for a key that is not published or does not
sign the DNSKEY RRset, a signature by an unpublished key, a key the plan published but never used, a
key that stopped signing but was not removed, a signed zone left without a DS, or a final state that
breaks RFC 4035 section 2.2. Intermediate states may look like this, and only the final one counts. A
key kept ready on purpose says so with `standby: true`. Two keys left signing side by side are valid,
so FlightCheck cannot tell an unfinished rollover of that kind from a deliberate setup.

`fix` moves each step to the earliest moment at which it no longer causes a failure. If a step can
never be safe because it changes two RRsets that must change at different times (for example
"remove the DS and unsign the zone"), it is split into two steps automatically.

## The lab

`flightcheck lab` runs the plan against a small DNS hierarchy built in-process: a root zone with
its own trust anchor, a `.test` TLD and the zone under test with a primary and a lagging
secondary. Zones are signed with **real keys** (RSA, ECDSA, Ed25519) exactly as the plan says,
and every query and answer is encoded in DNS wire format. Two populations of emulated iterative
resolvers query it on a virtual clock (days of DNS time in seconds):

* validating resolvers that trust what they validated (compared with the fetch model);
* validators behind a non-validating cache (compared with the conservative model).

Resolvers start at staggered moments and receive lookups at random (Poisson) times, so at every
change their caches hold data of every age. The lab reports how many lookups failed and checks
that **every SERVFAIL falls inside a predicted window**. Results for the included scenarios:

| Scenario (bad version) | Predicted outage (conservative / fetch) | Lab, behind cache | Lab, validating |
|---|---|---|---|
| KSK swapped too early | 23h / 23h | 1,390 SERVFAIL, all inside | 1,349 SERVFAIL, all inside |
| ZSK used immediately | 23h 10m / 1h 5m | 1,375, all inside | 12, all inside |
| TTL lowered right before the change | 23h 5m / 23h 5m | 1,544, all inside | 1,467, all inside |
| Algorithm rollover rushed | 22h 5m / 22h | 1,443, all inside | 1,311, all inside |
| DNSSEC turned off at once | 1d 1h / 1d 1h | 1,897, all inside | 1,730, all inside |
| DNSSEC turned on at once | 55m / none | 12, all inside | none, as predicted |
| all six "good" versions | none | none | none |

(12 resolvers per population, a lookup every 5 minutes on average, seed 1. Predicted outages here
leave out the failure memory.)

The lab already caught one modelling mistake during development (in the emulator, not the
simulator): a cached insecure answer was being re-validated after the DS appeared, which real
resolvers do not do.

The emulated resolver also validates negative answers: a signed SOA and NSEC records that prove NXDOMAIN
(the name and the wildcard do not exist) or NODATA (the name exists without that type). It caches them for the
smallest of SOA TTL, SOA MINIMUM and NSEC TTL, separately from failures. NSEC3, wildcard answers and RFC 8198
aggressive caching are not supported, and the simulator does not predict lookups of names outside the plan.

## Real Unbound and BIND

`flightcheck real-lab` runs real resolver software against the lab's zones on loopback addresses.
It needs no Docker, no installation and no admin rights, and sends nothing outside the machine.

```bash
.venv/Scripts/python -m pip install -e .[test,real]
.venv/Scripts/python scripts/fetch_resolvers.py          # downloads into tools/
.venv/Scripts/python -m flightcheck real-lab scenarios/ksk-double-ds-bad.yaml --out netlab-ksk
.venv/Scripts/python scripts/run_all.py                  # all 12 scenarios, about 30 minutes
.venv/Scripts/python scripts/audit_results.py            # compares with the raw windows
.venv/Scripts/python scripts/run_all.py --dir scenarios/realtime --name realtime --scale 1 --instances 6 --parallel 2
.venv/Scripts/python scripts/audit_realtime.py           # real-time runs, with and without timers
```

Windows only for now: `fetch_resolvers.py` downloads Windows builds of Unbound 1.26.2 (MSYS2 UCRT64)
and BIND 9.16.50 (ISC). BIND 9.16 is end of life and is the last release with Windows builds, so use
it only inside this lab.

Each run starts 3 instances of each resolver on a x600 clock, with different cache ages and
background lookups of non-existent names. A run only counts if answers carry the AD flag whenever
the zone is secure. Results are in [results/summary.md](../results/summary.md), with one HTML report
per scenario:

| Result (12 scenarios) | |
|---|---|
| Lookups | 113,711 |
| Failed lookups (SERVFAIL) | 8,607 |
| Failures inside the raw predicted window | 8,188 |
| Failures before the predicted start | 0 |
| Failures after the predicted end, within the resolver's own timer | 419 |
| Failures in the six safe plans | 0 |

What this adds to the emulated lab:

* **Resolvers keep a failure after the chain is healthy again.** The simulator now includes this (see
  "How it works"). On a compressed clock these timers last hours of plan time, because they run in
  real seconds, and the comparison scales them accordingly.
* **A cached insecure answer stays insecure** for one more data TTL after the DS has reached the
  resolver (seen on Unbound in `go-secure-good`). The simulator's status row does not show this yet.

**Check in real time.** `scenarios/realtime/` has two plans with short TTLs that run with no compressed
clock, so TTLs and timers are all real. Each was run twice with 6 instances of each resolver
(`results/realtime/`, `results/realtime2/`, `results/realtime-audit.txt`):

| 4 runs, 118,170 lookups, 8,667 failures | Inside the predicted window |
|---|---|
| Simulator without failure memory | 8,307 (360 outside) |
| Simulator with failure memory | 8,667 (0 outside) |

Failures come in steps of the timers: Unbound instances failed for 60 or 120 seconds, BIND instances
for 30, 60 or 90 seconds on the chain-of-trust scenario. The predicted end is an upper bound: the last
failure came 3 to 70 seconds before it, depending on the resolver and scenario. Both counts allow 2.25
seconds for sampling (one lookup interval plus the lookup timeout). The 360 failures came from BIND's
chain-of-trust timer and Unbound's answer timer. Unbound's chain-of-trust timer did not reach past the
end of the window in these runs; it did in the compressed runs, by up to 48 seconds.

Limits of this measurement:

* The predicted window is a worst case, and 3 instances do not always reach it. The observed end
  follows each instance's cache age. `zsk-prepublish-bad` is the extreme: the fetch model predicts
  1.1 h, Unbound failed 4 times and BIND never. The cause of this difference has not been examined.
* These resolvers validate directly, so they test the fetch model. The longer conservative windows
  (validators behind a cache) were not reproduced with real software: `go-secure-bad` predicts 0.9 h
  in that model and real resolvers correctly showed no failures.
* The compressed clock rounds short TTLs: 5 minutes becomes 1 second at x600.
* Knot Resolver and PowerDNS Recursor are not included. The Docker setup below has still not been run.

## Reading a measurement

`lab`, `probe` and `real-lab` keep prediction and observation apart. All times are plan seconds relative
to T+0, and on a compressed clock one real second is `scale` plan seconds.

* **Raw mismatch**: when the records themselves can disagree.
* **Upper bound**: the raw mismatch plus the resolver's failure timers. It is the latest a failure can
  happen, not a predicted duration, and on a compressed clock it is much wider than the mismatch.
* **Failing inside the bound**: the time measured failures covered, in the same units.

| Comparison | Meaning |
|---|---|
| `observed_agreement` | failures inside the bound, none outside |
| `overprediction` | at least 90% of the raw mismatch was recorded, and failures were absent or covered less than half of it |
| `underprediction` | a SERVFAIL outside every bound |
| `inconclusive` | not enough of the mismatch was recorded, or lookups timed out outside the bound |
| `no_failures_expected_or_observed` | nothing predicted, nothing seen |

A window is a risk, so a window without failures is not a model error. The 90% and half are rules of
thumb for one recording, not statistics: samples are few and depend on each other.

**Recovery** is reported per resolver instance and name, and only from an answer that was seen: the first
validated answer after the *last* failure. An answer without the AD flag counts only while a copy of "no
DS" can be cached. The real moment lies between the last failure and that answer. Without such an
answer the report says `recovery_not_observed`. Earlier recoveries of an intermittent failure are counted, but
are not the reported recovery.

**Exit codes of `probe` and `real-lab`.** They judge the measurement, so an unsafe plan whose failures were
predicted gives 0. These are not the codes of `check` and `fix`.

| Exit | Meaning |
|---|---|
| 0 | nothing contradicts the prediction: agreement, overprediction, or no failures, with every expected recovery seen |
| 1 | underprediction: a SERVFAIL outside the bound |
| 2 | the run itself failed: bad plan, a resolver could not start, or no resolver answered at all |
| 3 | the run does not count: answers without validation, unexpected responses such as NXDOMAIN, or a resolver with no answers |
| 4 | inconclusive: the recording does not settle it, or an expected recovery was not seen |

Before this, `probe` always gave 0, and `real-lab` gave 1 only when a resolver did not validate.

## The network lab

The same zones can be served over UDP/TCP on a compressed clock (for example `--scale 600`: one
real second = ten minutes of plan time, TTLs are divided accordingly), so real resolver software
can be measured against the prediction.

| Command | Role |
|---|---|
| `flightcheck lab-init PLAN --out DIR [--scale 600] [--address root=IP,...]` | keys shared by all processes, the clock, root hints, trust anchor, `unbound.conf`, `named.conf` |
| `flightcheck serve --lab DIR [--role root tld ns1 ns2]` | authoritative servers (`ns2` lags by the plan's propagation delay) |
| `flightcheck emu-resolver --lab DIR --listen IP [--behind-cache]` | the emulated resolver as a network service |
| `flightcheck probe --lab DIR --resolver NAME=IP ... --html report.html` | queries every resolver (RD, DO), records RCODE, AD and Extended DNS Error codes, compares with the prediction |

**With Docker** (isolated `internal` network, Unbound and BIND from Alpine packages, plus both
emulated resolvers):

```bash
cd lab/docker
PLAN=scenarios/ksk-double-ds-bad.yaml SCALE=600 docker compose up --build -d
docker compose logs -f probe
docker compose wait probe
docker compose down
# report: lab/docker/out/report.html
```

**Without Docker** (loopback addresses, emulated resolvers only):

```bash
flightcheck lab-init scenarios/ksk-double-ds-bad.yaml --out reports/netlab --scale 1200 --start-in 12 \
    --address root=127.0.0.10,tld=127.0.0.11,ns1=127.0.0.12,ns2=127.0.0.13
flightcheck serve --lab reports/netlab &
flightcheck emu-resolver --lab reports/netlab --listen 127.0.0.20 &
flightcheck emu-resolver --lab reports/netlab --listen 127.0.0.21 --behind-cache &
flightcheck probe --lab reports/netlab --resolver validating=127.0.0.20 --resolver behind-cache=127.0.0.21 \
    --html reports/netlab/report.html
```

Status: the network path (servers, compressed clock, TCP fallback, probe, EDE parsing) runs on
loopback in the test suite and end-to-end with the emulated resolvers (KSK scenario: 260/260 and
250/250 SERVFAILs inside the predicted window). The Docker files and the generated Unbound/BIND
configurations have **not been run yet** (no Docker on the development machine); expect to adjust
them on the first run. Resolver features that change timing are switched off in the generated
configs (prefetch, serve-stale, long bogus/SERVFAIL caching), because one real second is many
minutes of plan time.

## Scenarios

`scenarios/` contains six pairs of plans, each in a broken and a safe version:

| Scenario | What goes wrong in the bad version |
|---|---|
| `zsk-prepublish` | new ZSK used for signing before it is in every cached DNSKEY RRset; old ZSK removed while 1-day signatures are cached |
| `ksk-double-ds` | KSK swapped before the old DS RRset expired from caches |
| `algorithm-rollover` | RSA → ECDSA with keys, signatures and DS changed at once |
| `ttl-trap` | DNSKEY TTL lowered right before the change; cached copies keep the old 1-day TTL |
| `go-insecure` | DS removed and zone unsigned in the same step |
| `go-secure` | zone signed and DS submitted in the same step |

## Testing scope (hackathon rules)

* **What is tested:** DNSSEC key changes on synthetic zones and their effect on validating
  resolvers.
* **Environment:** `check`, `fix` and `lab` run in one process and open no sockets. `real-lab` and
  the network lab use loopback addresses, or a Docker network marked `internal`. The only Internet
  use is downloading the resolvers once with `fetch_resolvers.py`.
* **Data:** synthetic zones under the reserved `.test` TLD and keys generated for each run.
* **External traffic:** none. The lab has its own root zone and trust anchor; resolvers in the lab
  can only reach the lab's servers.

## Roadmap

* Add cached insecure answers to the simulator's status.
* Examine why real resolvers rarely show the `zsk-prepublish-bad` failure; run more instances.
* First run of the Docker lab; add Knot Resolver and PowerDNS Recursor.
* Signature expiry and refresh (RRSIG validity windows, signer outages).
* Multi-signer DNSSEC (RFC 8901) and provider migrations.
* Import of key timing from BIND `dnssec-policy` and Knot `keymgr`.

## Tests

```bash
.venv/Scripts/python -m pytest -q
```
