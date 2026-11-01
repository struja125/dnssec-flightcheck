# DNSSEC FlightCheck — brzo pokretanje (Snapshot → Plan → Check/Fix → Docker)

**Za evaluatore:** ovaj vodič demonstrira glavni tok projekta **bez korišćenja gotovih rollover scenarija**. Početno stanje uzimamo direktno sa autoritativnih DNS servera laboratorije. Detalji arhitekture, ograničenja i dodatne opcije su u [README.md](README.md).

**Preduslovi:** Python **3.10+**, Docker Engine + **Docker Compose v2** (na Windows-u Docker Desktop sa Linux kontejnerima), Git/raspakovan projekat. Python zavisnosti (`dnspython`, `cryptography`, `PyYAML`) instaliraju se pomoću `pip install -e .`.

## 1. Instalacija (iz korena projekta, gde je `pyproject.toml`)

**Windows — PowerShell:**

```powershell
py -m venv .venv
$PY = ".\.venv\Scripts\python.exe"
& $PY -m pip install -e .
function fc { & $PY -m flightcheck @args }
```

**Linux — Bash:**

```bash
python3 -m venv .venv
PY=./.venv/bin/python
"$PY" -m pip install -e .
fc() { "$PY" -m flightcheck "$@"; }
```

Sve naredne komande `fc ...` izvršavati u **istom terminalu** u kojem je definisana funkcija `fc`. Ako se terminal zatvori, ponovo definišite `$PY`/`PY` i `fc` (nije potrebna ponovna instalacija).

## 2. Prikupite trenutno DNSSEC stanje — izaberite JEDAN režim

**Iste Docker komande važe za Windows i Linux:**

```bash
cd lab/docker
docker compose -f docker-compose.bootstrap.yml up --build -d

# A) AXFR — kompletan prenos potpisane zone (preporučeni demo):
docker compose -f docker-compose.bootstrap.yml run --rm snapshot-axfr

# ILI B) običan snapshot, pojedinačni DNS upiti:
# docker compose -f docker-compose.bootstrap.yml run --rm snapshot

docker compose -f docker-compose.bootstrap.yml down
cd ../..
```

Rezultat je `lab/docker/out-snapshot/snapshot-axfr.yaml` (AXFR) ili `snapshot-bank.yaml` (običan snapshot). Očekivano: `complete` za uspešan AXFR sa usaglašenim serverima i prikupljenim DS-om; `partial` za uzorkovani DNS snapshot. **Samo jedna metoda je potrebna za nastavak.** Ako se AXFR ne izvrši, pogledajte logove bootstrapa ili koristite običan snapshot; neuspešan AXFR se ne pretvara automatski u običan.

## 3. Administratorski input → automatski generisan ZSK plan

U nastavku koristimo **AXFR** fajl. Za običan snapshot zamenite `snapshot-axfr.yaml` sa `snapshot-bank.yaml` u komandi `fc plan`.

Napravite `lab/docker/out-snapshot/inputs.yaml` iz postojećeg `lab/docker/inputs-zsk.example.yaml` i postavite `start` na **budući UTC trenutak**, nakon vremena prikupljanja snapshot-a (npr. za 15 minuta):

**Windows — PowerShell:**

```powershell
$start = (Get-Date).ToUniversalTime().AddMinutes(15).ToString("yyyy-MM-ddTHH:mm:ssZ")
(Get-Content lab\docker\inputs-zsk.example.yaml -Raw).Replace("START-TIME", $start) | Set-Content lab\docker\out-snapshot\inputs.yaml -Encoding ascii
```

**Linux — Bash (GNU date):**

```bash
sed "s/START-TIME/$(date -u -d '+15 minutes' +%Y-%m-%dT%H:%M:%SZ)/" lab/docker/inputs-zsk.example.yaml > lab/docker/out-snapshot/inputs.yaml
```

Prvo pokretanje naredne komande će namerno prijaviti da `CHOOSE-A-KEY` nije validan i ispisati dostupne `key-... (ksk)` i `key-... (zsk)` identifikatore:

```text
fc plan lab/docker/out-snapshot/snapshot-axfr.yaml --rollover zsk --inputs lab/docker/out-snapshot/inputs.yaml --output lab/docker/out-snapshot/plan.yaml
```

U `inputs.yaml` zamenite **`CHOOSE-A-KEY` identifikatorom sa oznakom `(zsk)`** iz ispisa, pa ponovite istu komandu. Na Windows-u otvorite `notepad lab\docker\out-snapshot\inputs.yaml`; na Linux-u koristite omiljeni editor. Identifikatori se menjaju kada se laboratorija ponovo generiše — **ne kopirati stare key tag-ove**. Ostale vrednosti (`delays`, `margin`, `resolver`) su pretpostavke administratora, a ne podaci iz AXFR-a.

## 4. Pokažite razliku: namerno loš plan → otkrivanje → automatska ispravka

Plan Builder najpre generiše kandidat za bezbedan raspored. Da bi se demonstriralo prepoznavanje problema, napravite **kopiju izvedenu iz tog plana**, sa sva tri koraka na `T+0` (bez korišćenja unapred pripremljenog scenarija).

**Windows — PowerShell:**

```powershell
$plan = Get-Content lab\docker\out-snapshot\plan.yaml -Raw
$plan -replace '(?m)^  at: [0-9]+(?=\r?$)', '  at: 0' | Set-Content lab\docker\out-snapshot\plan-bad.yaml -Encoding ascii
```

**Linux — Bash:**

```bash
sed -E 's/^  at: [0-9]+$/  at: 0/' lab/docker/out-snapshot/plan.yaml > lab/docker/out-snapshot/plan-bad.yaml
```

Zatim **na oba sistema**, iz korena projekta:

```text
fc check lab/docker/out-snapshot/plan-bad.yaml --both-models --html lab/docker/out-snapshot/bad.html
fc fix lab/docker/out-snapshot/plan-bad.yaml --write lab/docker/out-snapshot/plan-fixed.yaml --html lab/docker/out-snapshot/fix.html
fc check lab/docker/out-snapshot/plan-fixed.yaml --both-models --html lab/docker/out-snapshot/fixed.html
```

Očekivano: **`UNSAFE` → pomeranje koraka → `SAFE` prema modelima**. Loš plan namerno vraća izlazni kod `1`. Kod običnog (`partial`) snapshot-a bezbedan ishod je ograničen na uzorkovane zapise i može vratiti izlazni kod `3`; to nije greška izvršavanja. HTML rezultati su u `lab/docker/out-snapshot/`.

## 5. Opcionalno: Docker validacija plana na četiri resolvera

Izvršava se **konkretan plan nastao iz snapshot-a**, ne podrazumevani scenario. Bootstrap iz koraka 2 mora biti zaustavljen. Proveravaju se Unbound, BIND i dva emulirana resolvera. Za dva odvojena eksperimenta ponoviti korake, prvo sa `plan-bad.yaml`, pa sa `plan-fixed.yaml`.

**Windows — PowerShell, iz korena projekta:**

```powershell
New-Item -ItemType Directory -Force lab\docker\out | Out-Null
Copy-Item lab\docker\out-snapshot\plan-bad.yaml lab\docker\out\demo-plan.yaml
cd lab\docker
$env:PLAN = "/lab/demo-plan.yaml"
$env:SCALE = "600"
docker compose up --build -d
docker compose logs -f probe
docker compose wait probe
Copy-Item out\report.html out\report-bad.html
docker compose down
Remove-Item Env:PLAN, Env:SCALE
cd ..\..
```

**Linux — Bash, iz korena projekta:**

```bash
mkdir -p lab/docker/out
cp lab/docker/out-snapshot/plan-bad.yaml lab/docker/out/demo-plan.yaml
cd lab/docker
PLAN=/lab/demo-plan.yaml SCALE=600 docker compose up --build -d
docker compose logs -f probe
docker compose wait probe
cp out/report.html out/report-bad.html
docker compose down
cd ../..
```

Za **popravljeni** plan ponovite odgovarajući blok, ali umesto `plan-bad.yaml` kopirajte `plan-fixed.yaml`, a rezultat sačuvajte kao `out/report-fixed.html`. Pored HTML-a, sirovi podaci su u `out/probe.json` (kopirajte ga pre sledećeg eksperimenta ako želite da zadržite oba). `probe` izlazni kod `0` znači da su merenja u skladu sa predviđanjem — **ne znači automatski 0 SERVFAIL**.

## Kako tumačiti rezultat

- **Snapshot** prikazuje šta DNS zona trenutno objavljuje. **Input** opisuje nameru i pretpostavke administratora. **Plan/check/fix** ispituju buduće promene. Ovo su različite faze.
- `complete` AXFR potvrđuje obuhvat prenetog sadržaja prema proverama collectora, **ne predstavlja samostalni kriptografski dokaz** bezbednosti zone.
- Laboratorija koristi **sintetičke ključeve, ubrzano vreme i izolovanu mrežu**; ne menja produkcione DNS servere.
- Postoji poznat neuspešan automatizovani AXFR test u ovoj verziji projekta; praktični AXFR demo je ranije uspešno izvršen, ali kompletna regresiona provera nije potvrđena.
- Za detalje o parametrima, drugim rollover tipovima i rešavanju problema: [README.md](README.md).
