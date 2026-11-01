# DNSSEC FlightCheck: uputstvo

FlightCheck proverava plan promene DNSSEC ključeva **pre nego što se bilo šta promeni u produkciji**.
Kaže da li neki resolver može da vrati SERVFAIL, kada, zašto, i koji je najraniji bezbedan trenutak za
svaki korak.

Resolveri posebno keširaju DS, DNSKEY i potpise, svaki sa svojim TTL-om. Ako se korak uradi dok su stare
kopije još u kešu, resolver može da drži podatke koji se ne slažu, pa korisnici dobijaju SERVFAIL. DNSViz i
Zonemaster proveravaju *trenutno* stanje zone, a FlightCheck svaki trenutak *planirane* promene.

Alat ne menja ništa u DNS-u i ne traži privatne ključeve.

**Sadržaj:** [Instalacija](#instalacija) · [Korišćenje](#korišćenje) · [Testiranje](#testiranje) ·
[Demonstracija](#demonstracija) · [Izlazni kodovi](#izlazni-kodovi) · [Česti problemi](#česti-problemi)

## Instalacija

Potreban je Python 3.10 ili noviji. Internet treba samo za instalaciju. Komande pokrećite iz foldera
projekta, onog u kome je `pyproject.toml`.

**Windows (PowerShell):**

```powershell
py -m venv .venv
```
```powershell
.venv\Scripts\Activate.ps1
```
```powershell
python -m pip install -e ".[test]"
```

**macOS i Linux:**

```bash
python3 -m venv .venv
```
```bash
source .venv/bin/activate
```
```bash
python -m pip install -e ".[test]"
```

Ovo pravi izolovano okruženje u folderu `.venv` i instalira komandu `flightcheck`. Instalacija se radi
samo prvi put, a aktivacija (druga komanda) u svakom novom terminalu.

Komande ispod su iste na svim sistemima. HTML izveštaj otvarate sa `start report.html` na Windows-u,
`open report.html` na macOS-u ili `xdg-open report.html` na Linux-u.

## Korišćenje

### Osnovni tok: provera, popravka, ponovna provera

**1. Proverite plan.** U folderu `scenarios/` su gotovi planovi, svaki u lošoj (`-bad`) i dobroj (`-good`) verziji.

```bash
flightcheck check scenarios/ksk-double-ds-bad.yaml --html report.html
```

U ovom planu se KSK menja 2 sata posle slanja novog DS-a, a stari DS može da ostane u kešu ceo dan.
`T+0` je početak plana:

```
Verdict: UNSAFE - resolvers can answer SERVFAIL for 23h 2m in total, from T+2h until T+1d 1h 2m.

Safe schedule (worst case + 1h margin)
             T+0  Submit DS for KSK2: ok
            T+2h  Swap KSK1 for KSK2 in the DNSKEY RRset: move to T+1d 2h (earliest T+1d 1h)
            T+4h  Remove the DS for KSK1: move to T+1d 3h 5m (earliest T+1d 2h 5m)
```

**2. Napravite popravljen plan.** `fix` pomera korake na najraniji bezbedan trenutak. Originalni fajl
ostaje isti, a novi se ne upisuje ako bezbedan plan ne postoji.

```bash
flightcheck fix scenarios/ksk-double-ds-bad.yaml --write fixed.yaml
```

**3. Proverite popravljen plan.** Presuda je sada `SAFE`.

```bash
flightcheck check fixed.yaml
```

**4. Pustite oba plana u ugrađenom labu.** Lab izvršava plan sa pravim DNSSEC potpisima i emuliranim
resolverima na virtuelnom satu, bez mreže. Traje nekoliko sekundi.

```bash
flightcheck lab scenarios/ksk-double-ds-bad.yaml --html lab.html
```
```bash
flightcheck lab fixed.yaml
```

Loš plan treba da da `observed_agreement` (otkazi su unutar predviđenog prozora), a popravljen
`no_failures_expected_or_observed`.

### Sopstveni plan

Plan je YAML fajl sa ključevima, trenutnim stanjem i koracima. Vremena se pišu kao `30m`, `2h` ili `1d`.

```yaml
name: KSK rollover (double-DS)
zone: bank.test.
delays:
  propagation: 5m               # primary -> poslednji secondary
  registry: 1h                  # DS poslat -> vidljiv u roditeljskoj zoni
resolver:
  max_cache_ttl: 7d             # resolveri ograničavaju TTL na ovu vrednost
margin: 1h                      # dodaje se na svaki najraniji bezbedan trenutak

keys:
  KSK1: {role: ksk, algorithm: ECDSAP256SHA256}
  KSK2: {role: ksk, algorithm: ECDSAP256SHA256}
  ZSK1: {role: zsk, algorithm: ECDSAP256SHA256}

initial:
  ds:     {keys: [KSK1], ttl: 1d}                            # DS zapisi kod roditelja
  dnskey: {keys: [KSK1, ZSK1], signed_by: [KSK1], ttl: 1h}   # objavljeni ključevi i ko ih potpisuje
  data:
    www:  {signed_by: [ZSK1], ttl: 1h}                       # koliko god potpisanih zapisa

steps:                                                       # vremena u odnosu na T+0
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

Korak menja samo polja koja navede. Plan zatim proveravate komandama `check` i `fix`. Sva polja su
opisana u [docs/REFERENCE.md](docs/REFERENCE.md).

### Plan iz prave zone

`snapshot` beleži šta zona trenutno objavljuje, običnim upitima ka njenim autoritativnim serverima. To su
pravi DNS upiti ka internetu, zato ga pokrećite samo na zonama koje smete da ispitujete.

```bash
flightcheck snapshot example.com --output snapshot.yaml --query www.example.com/A
```

Snapshot ne zna šta nameravate da uradite, pa to upisujete u `inputs.yaml`:

```yaml
replace: key-33366-1a2b3c4d5e           # ključ koji se menja
new_key: {algorithm: ECDSAP256SHA256}
start: 2026-11-02T12:00:00Z             # ne pre trenutka snapshota
delays: {propagation: 5m, registry: 1h, parent_propagation: 5m}
margin: 1h
resolver: {max_cache_ttl: 1d}
zone_ttl_bound: 1d                      # najduži TTL zapisa koje niste videli
```

Ako ne znate ime ključa, za `replace` upišite bilo šta: poruka o grešci iz sledeće komande ispisuje
ključeve zone.

```bash
flightcheck plan snapshot.yaml --rollover zsk --inputs inputs.yaml --output plan.yaml
```
```bash
flightcheck check plan.yaml
```

Najbolji mogući rezultat je `SAFE for the sampled records only`, sa izlaznim kodom 3. Snapshot vidi samo
deo zone, a kašnjenja su vaše pretpostavke, pa to nije garancija za celu zonu.

### Plan iz pokrenute Docker mreže

Možete i da pokrenete stabilnu `bank.test.` mrežu u Docker-u, pročitate njeno stanje preko DNS upita i od toga
napravite plan, bez ručnog opisivanja zone. Stanje se čita običnim upitima ili, uz `--axfr`, prenosom cele zone.
Koraci za PowerShell su u [docs/SNAPSHOT-WORKFLOW.md](docs/SNAPSHOT-WORKFLOW.md).

## Testiranje

Projekat se testira na četiri nivoa, od najbržeg ka najsporijem.

| Nivo | Šta proverava | Trajanje |
|---|---|---|
| Automatski testovi | kod alata | oko 30 s |
| Ugrađeni lab | predikciju, sa emuliranim resolverima u jednom procesu | sekunde |
| Mrežni lab | isto preko pravog UDP/TCP-a na lokalnim adresama | oko 5 min |
| Pravi resolveri | predikciju, sa pravim Unbound-om i BIND-om | oko 7 min |

### Automatski testovi

```bash
python -m pytest -q
```

Očekivano je `104 passed`. Testovi ne koriste internet, a
Windows Firewall može da pita za dozvolu jer se otvaraju lokalne adrese 127.0.0.x.

Pojedinačni fajl ili grupa testova:

```bash
python -m pytest -q tests/test_fixer.py
```
```bash
python -m pytest -q -k snapshot
```

| Fajlovi u `tests/` | Oblast |
|---|---|
| `test_plan`, `test_validation` | čitanje i provera YAML planova |
| `test_simulator`, `test_final_state`, `test_signatures_and_denial` | simulacija, završno stanje, potpisi i negativni odgovori |
| `test_failure_memory`, `test_failure_timing` | koliko dugo resolveri pamte neuspeh |
| `test_fixer`, `test_fix_output` | popravka plana |
| `test_snapshot`, `test_planbuilder`, `test_snapshot_lab` | snapshot, pravljenje plana, plan iz snapshota u labu |
| `test_lab`, `test_network`, `test_real`, `test_measurement` | labovi i poređenje merenja sa predikcijom |

### Provera svih scenarija

Svih šest `-bad` planova treba da da izlazni kod 1, a svih šest `-good` planova izlazni kod 0.
Kod poslednje komande vidite sa `echo $LASTEXITCODE` u PowerShell-u, odnosno `echo $?` na macOS-u i Linux-u.

| Scenario | Šta je pogrešno u `-bad` verziji |
|---|---|
| `ksk-double-ds` | KSK zamenjen pre nego što je stari DS istekao iz keša |
| `zsk-prepublish` | novi ZSK korišćen odmah, a stari uklonjen dok su potpisi još u kešu |
| `algorithm-rollover` | prelazak sa RSA na ECDSA urađen odjednom |
| `ttl-trap` | TTL smanjen neposredno pre promene |
| `go-insecure` | DS i potpisi uklonjeni u istom koraku |
| `go-secure` | zona potpisana i DS poslat u istom koraku |

### Mrežni lab, bez Docker-a

Otvorite 4 terminala sa aktiviranim okruženjem i pokrenite komande redom, u roku od 60 sekundi. Na
macOS-u i Linux-u je za ovo lakše koristiti Docker, jer adrese 127.0.0.x ili port 53 traže dodatna podešavanja.

Terminal 1:

```bash
flightcheck lab-init scenarios/ksk-double-ds-bad.yaml --out netlab --scale 1200 --start-in 60 --address root=127.0.0.10,tld=127.0.0.11,ns1=127.0.0.12,ns2=127.0.0.13
```
```bash
flightcheck serve --lab netlab
```

Terminal 2:

```bash
flightcheck emu-resolver --lab netlab --listen 127.0.0.20
```

Terminal 3:

```bash
flightcheck emu-resolver --lab netlab --listen 127.0.0.21 --behind-cache
```

Terminal 4:

```bash
flightcheck probe --lab netlab --resolver validating=127.0.0.20 --resolver behind-cache=127.0.0.21 --html netlab/report.html
```

Na kraju treba da piše `the resolvers do not contradict the prediction`, sa izlaznim kodom 0.

### Pravi Unbound i BIND, bez Docker-a (samo Windows)

Skida programe u folder `tools/` (oko 35 MB), bez administratorskih prava.

```bash
python -m pip install -e ".[test,real]"
```
```bash
python scripts/fetch_resolvers.py
```
```bash
flightcheck real-lab scenarios/ksk-double-ds-bad.yaml --out netlab-ksk
```

Izveštaj je u `netlab-ksk/report.html`. Treba da piše `really validating: yes` za oba resolvera, inače
rezultat ne važi. Svih 12 scenarija pokreće `python scripts/run_all.py` (oko 30 minuta).

### Pravi resolveri u Docker-u

> Ovaj deo još nije pokrenut ni na jednoj mašini, pa prvi put računajte na sitne izmene konfiguracije.

Pokrenite Docker Desktop, uđite u folder `lab/docker` i pokrenite (macOS i Linux):

```bash
mkdir -p out
```
```bash
rm -f out/report.html out/probe.json
```
```bash
PLAN=scenarios/ksk-double-ds-bad.yaml SCALE=600 docker compose up --build -d
```
```bash
docker compose logs -f probe
```
```bash
docker compose wait probe
```
```bash
docker compose down
```

- Druga komanda briše stari izveštaj, da `out/report.html` sigurno potiče iz ovog pokretanja.
- `wait` ispisuje izlazni kod merenja. Ako nešto ne radi, pogledajte `docker compose logs unbound`,
  `docker compose logs bind` i `docker compose logs root`.
- Sopstveni plan kopirajte u `out/candidate.yaml` i zadajte `PLAN=/lab/candidate.yaml`. Nemojte ga nazvati
  `plan.yaml`, jer lab sam piše taj fajl.

## Demonstracija

Demo traje oko 5 minuta i radi bez interneta. Pre nastupa uradite instalaciju, pustite testove i
isprobajte sve komande jednom.

| Korak | Pokažite | Recite |
|---|---|---|
| 1. Problem | sadržaj `scenarios/ksk-double-ds-bad.yaml` | „Ovo je uobičajena zamena KSK-a. Na prvi pogled izgleda ispravno.” |
| 2. Provera | `flightcheck check scenarios/ksk-double-ds-bad.yaml --html demo.html --both-models`, pa otvorite `demo.html` | „Stari DS može da ostane u kešu ceo dan, pa korisnici mogu da dobijaju SERVFAIL do 23 sata. Alat kaže kada i zašto.” |
| 3. Popravka | `flightcheck fix scenarios/ksk-double-ds-bad.yaml --write fixed.yaml` | „Alat računa najraniji bezbedan trenutak za svaki korak i piše novi plan.” |
| 4. Provera popravke | `flightcheck check fixed.yaml` | „Isti koraci, drugi raspored, i presuda je SAFE.” |
| 5. Dokaz u labu | `flightcheck lab scenarios/ksk-double-ds-bad.yaml`, pa `flightcheck lab fixed.yaml` | „Sa pravim potpisima i emuliranim resolverima, otkazi se dešavaju u predviđenom prozoru, a posle popravke ih nema.” |
| 6. Pravi resolveri | `results/ksk-double-ds-bad.html` i `results/summary.md` | „Ovo su ranija merenja sa pravim Unbound-om i BIND-om: 8.607 SERVFAIL-ova u 12 scenarija, nijedan pre predviđenog početka i nijedan u bezbednim planovima.” |

**Ako nešto ne radi uživo:** gotovi izveštaji su u `examples/` i `results/`, na primer
`examples/check-ksk-double-ds-bad.html` i `examples/lab-ksk-double-ds-bad.html`.

**Docker uživo:** merenje traje nekoliko minuta, pa ga pokrenite pre nastupa. Koristite ga tek kad prođe bar
jedno probno pokretanje.

**Tvrdnje koje ne treba izgovoriti:**

- *„Plan je garantovano bezbedan.”* Tačno je: bezbedan u modelu, za zadate TTL-ove i kašnjenja.
- *„Testirano na produkcijskoj zoni.”* Labovi koriste sintetičke ključeve i sopstvenu root zonu.
- *„Provereno na svim resolverima.”* Merena su samo Unbound 1.26.2 i BIND 9.16.50, i samo u `fetch` modelu.
- *„Sve je provereno na pravim resolverima.”* Dublje zone, plan iz snapshota i istek potpisa provereni su
  samo emulatorom, a obnavljanje potpisa, NSEC3 i CDS nisu modelovani.

## Izlazni kodovi

| Kod | `check` i `fix` | `probe` i `real-lab` |
|---|---|---|
| 0 | bezbedno | ništa ne protivreči predikciji |
| 1 | nebezbedno | SERVFAIL van predviđene granice |
| 2 | loš ulaz | samo pokretanje nije uspelo |
| 3 | bezbedno uz ograničenje: uzorkovani zapisi ili samo jedan model | merenje se ne računa, npr. odgovori bez validacije |
| 4 | nepotpuno: nema loših odgovora, ali završno stanje nije valjano | merenje ne daje zaključak |

`probe` i `real-lab` ocenjuju merenje, a ne plan. Zato nebezbedan plan čiji su otkazi predviđeni daje 0.

## Česti problemi

| Problem | Rešenje |
|---|---|
| `py` ili `python` nije prepoznat | Python nije u PATH-u. Ponovo pokrenite instalaciju, štiklirajte „Add python.exe to PATH” i otvorite novi terminal. |
| PowerShell odbija `Activate.ps1` | Pokrenite `Set-ExecutionPolicy -Scope Process RemoteSigned` pa ponovite aktivaciju. Važi samo za taj prozor. |
| `flightcheck` nije prepoznat | Okruženje nije aktivirano u ovom terminalu ili instalacija nije urađena. |
| `pip install` ne prolazi | Proverite internet. Na fakultetskoj ili firmskoj mreži možda treba proxy. |
| `address already in use` u mrežnom labu | Prethodni proces još radi. Zatvorite stare terminale. |
| `pytest` pada samo na `test_network.py` | Firewall blokira lokalne adrese. Dozvolite Python u Windows Firewall-u. |

## Još informacija

[docs/REFERENCE.md](docs/REFERENCE.md) (na engleskom) opisuje sve opcije i polja plana, kako simulator radi,
modele resolvera i rezultate merenja.
