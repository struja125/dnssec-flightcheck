# Snapshot-driven Docker workflow

An optional way to get the input for FlightCheck: start a stable DNSSEC network, read its state through
DNS queries, and build the rollover plan from what the servers answered. The operator doesn't describe DS,
DNSKEY, signatures or TTLs. The scenario workflow with `$env:PLAN = "scenarios/..."` is unchanged.

```
stable network -> snapshot over DNS -> plan -> check / fix -> lab run with synthetic keys -> report
```

> **Docker status:** these Docker commands have not been run. The same CLI commands were run on Windows
> with loopback addresses and emulated resolvers. Unbound and BIND were not part of that run.

## Demo (Windows PowerShell)

Start from the project folder with the environment active (see [README](../README.md)), and with Docker
Desktop running.

### 1. Start the stable network

```powershell
cd lab\docker
docker compose -f docker-compose.bootstrap.yml up --build -d
```

This starts root, TLD, `ns1` and `ns2` for `bank.test.`. There are no planned changes, no resolvers and no
probe, and the clock isn't compressed.

### 2. Collect the snapshot

```powershell
Start-Sleep -Seconds 5
docker compose -f docker-compose.bootstrap.yml run --rm snapshot
```

The servers need a moment to start. If this reports `failed`, run the second command again.

### 3. Inspect it and stop the network

```powershell
Get-Content out-snapshot\snapshot-bank.yaml
docker compose -f docker-compose.bootstrap.yml down
cd ..\..
```

Both Compose files use the same subnet, so stop this network before the lab run.

### 4. Write the operator inputs

```powershell
$start = (Get-Date).ToUniversalTime().AddMinutes(5).ToString("yyyy-MM-ddTHH:mm:ssZ")
(Get-Content lab\docker\inputs-zsk.example.yaml -Raw).Replace("START-TIME", $start) | Set-Content lab\docker\out-snapshot\inputs.yaml -Encoding ascii
flightcheck plan lab\docker\out-snapshot\snapshot-bank.yaml --rollover zsk --inputs lab\docker\out-snapshot\inputs.yaml --output lab\docker\out-snapshot\plan-from-snapshot.yaml
```

This first `plan` stops on purpose, because no key has been chosen yet. Its error lists the keys it found,
for example `key-37184-2dd37a7d71 (zsk)`. Each new network has new keys.

```powershell
notepad lab\docker\out-snapshot\inputs.yaml
```

Replace `CHOOSE-A-KEY` with the name of the `zsk` key. For a KSK rollover, choose the `ksk` key and use
`--rollover ksk` in the next step.

### 5. Generate the plan

```powershell
flightcheck plan lab\docker\out-snapshot\snapshot-bank.yaml --rollover zsk --inputs lab\docker\out-snapshot\inputs.yaml --output lab\docker\out-snapshot\plan-from-snapshot.yaml
```

### 6. Check it

```powershell
flightcheck check lab\docker\out-snapshot\plan-from-snapshot.yaml --html lab\docker\out-snapshot\prediction.html --both-models
```

The expected verdict is `SAFE for the sampled records only`, with exit code 3. The snapshot asked for only
some names, so a verdict for the whole zone isn't possible.

### 7. Optionally, fix it

```powershell
flightcheck fix lab\docker\out-snapshot\plan-from-snapshot.yaml --write lab\docker\out-snapshot\fixed.yaml
```

The builder's schedule is already safe, so `fix` keeps it. To see an unsafe plan, set all three `at:` values
in a copy of the plan to `0` and run `check` and `fix` on the copy. On the shipped zone, `check` then gives
`UNSAFE` and `fix` moves the second step to `T+2h 5m` and the third to `T+1d 3h 10m`.

### 8. Run the plan in the existing lab

```powershell
New-Item -ItemType Directory -Force lab\docker\out | Out-Null
Remove-Item lab\docker\out\report.html, lab\docker\out\probe.json -ErrorAction SilentlyContinue
Copy-Item lab\docker\out-snapshot\plan-from-snapshot.yaml lab\docker\out\plan-from-snapshot.yaml
cd lab\docker
$env:PLAN = "/lab/plan-from-snapshot.yaml"
$env:SCALE = "600"
docker compose up --build -d
docker compose logs -f probe
docker compose wait probe
```

`wait` prints the probe's exit code. By the lab's clock, a run with the shipped zone takes about 8 minutes at
`SCALE=600`, plus the image build the first time. This generated schedule is expected to give no SERVFAIL. Use `fixed.yaml` or an unsafe copy the same way.

### 9. Open the report and clean up

```powershell
start out\report.html
docker compose down
Remove-Item Env:PLAN, Env:SCALE
cd ..\..
```

## Snapshot by zone transfer (AXFR)

Step 2 can use a zone transfer instead of individual queries. The ordinary mode stays the default, and a
failed transfer never turns into ordinary queries. Run these while the stable network is up, from `lab\docker`:

```powershell
docker compose -f docker-compose.bootstrap.yml run --rm snapshot
Copy-Item out-snapshot\snapshot-bank.yaml out-snapshot\snapshot-regular.yaml
docker compose -f docker-compose.bootstrap.yml run --rm snapshot-axfr
```

Compare the two:

```powershell
Select-String -Path out-snapshot\snapshot-regular.yaml, out-snapshot\snapshot-axfr.yaml -Pattern "^method:|^completeness:|cross_server" -Context 0,1
```

Then continue from step 4 with `snapshot-axfr.yaml` and an output of your choice:

```powershell
cd ..\..
flightcheck plan lab\docker\out-snapshot\snapshot-axfr.yaml --rollover zsk --inputs lab\docker\out-snapshot\inputs.yaml --output lab\docker\out-snapshot\plan-from-axfr.yaml
flightcheck check lab\docker\out-snapshot\plan-from-axfr.yaml
```

The keys are the same in both snapshots as long as the network wasn't recreated. To run a transfer yourself,
use `flightcheck snapshot ZONE --axfr --server IP [--server IP] --parent-server IP --output FILE`.

### What the status means

| `completeness.status` | Meaning | Exit | File |
|---|---|---|---|
| `complete` | as many matching transfers as the zone has NS records, a known DS state, and signatures present | 0 | written |
| `partial` | a transfer finished, but another server failed or wasn't asked, the DS state is unknown, or an RRset in the zone is unsigned | 0 | written |
| `inconsistent` | servers transferred different records, even if their serials match | 1 | written |
| `failed` | no server finished a transfer | 2 | not written |

`transfer.status` describes the transfer alone, and `transfer.servers` has one row per server. So one server
gives `transfer.status: complete` with `cross_server: unverified`, and the snapshot stays `partial`.

- **Plans:** only `complete` gives `coverage: complete`, so `check` can then give exit 0 instead of 3. The verdict
  still rests on your delays and on a model. Signatures are recorded, not verified (`dnssec_validation`).
- **Sections:** `rrsets` holds signed data, `denial_rrsets` holds NSEC and NSEC3, and `unsigned_rrsets` holds
  everything unsigned, such as delegations and glue. Only `rrsets` and the apex sections reach a plan.
- **In the lab:** each RRset in a plan is still served as an A record with the same TTL and signers.

### Access

- **Lab:** `ns1` and `ns2` allow only `10.53.0.31`, the `snapshot-axfr` container. Others get REFUSED. Root, the TLD
  and the experiment lab never transfer, and no port is published. `serve --axfr-allow` refuses a lab with steps
  or a compressed clock.
- **Other servers:** a transfer goes only to a `--server` you name, and only when you pass `--axfr`. Use it only
  on servers you are allowed to transfer from. A refusal is reported, not worked around.
- **TSIG:** `--tsig-file FILE` signs the request. The file is YAML with `name`, `secret` and optionally `algorithm`,
  and the secret goes in neither the snapshot nor the output. The lab's servers don't use TSIG.

## Where the files are

| File | Contents |
|---|---|
| `lab/docker/bootstrap/bank-test.yaml` | the stable zone, read only by the servers |
| `lab/docker/out-snapshot/network/` | the stable network's lab directory, including its private lab keys |
| `lab/docker/out-snapshot/snapshot-bank.yaml` | what the servers answered |
| `lab/docker/out-snapshot/inputs.yaml` | the operator's inputs |
| `lab/docker/out-snapshot/plan-from-snapshot.yaml` | the candidate plan |
| `lab/docker/out-snapshot/fixed.yaml`, `prediction.html` | the optional corrected plan, and the prediction |
| `lab/docker/out/report.html`, `probe.json` | the measurement |
| `lab/docker/out/key_mapping.yaml` | which synthetic key stands for which snapshot key |

## Where each value comes from

| In the plan | Source |
|---|---|
| DS, DNSKEY, signers, signature times, TTLs, negative TTL | DNS answers, through the snapshot |
| delays, margin, resolver profile, TTL bound | the operator's inputs |
| new key and steps | generated by the plan builder |
| the rest of the zone | `unobserved-records`, using the operator's TTL bound |

The lab always signs with its own synthetic keys, and the second network has different keys from the first.
It rebuilds an equivalent state: the same roles, algorithms, TTLs and signing relationships, but not the same
keys. The public keys from the snapshot stay under `provenance.keys`. Snapshot TTLs are plain seconds, and
only the lab run divides them by `SCALE`, once. For example, a TTL of 1 day is served as 144 s at `SCALE=600`.

## Limits

- A snapshot is partial: it sees the apex, the DS and the requested names. Generated plans carry `coverage: sampled`.
- Collection reads the DNS answers only, and the snapshot container uses the shared folder just to write its file.
  If DNSKEY, DS or SOA is missing, `snapshot` or `plan` stops with an error.
- The lab reproduces observed names as A records with the same TTLs and signers. SOA and NS appear as
  `apex-SOA` and `apex-NS`.
- Observed signatures last about 120 days from the bootstrap. Choose a `start` soon after the snapshot, because
  a `start` past their expiry makes the plan unsafe.
- On Linux, Docker may create `out-snapshot` as root. Change its owner before writing there from the host.
