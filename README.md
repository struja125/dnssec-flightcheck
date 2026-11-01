# DNSSEC FlightCheck

**Provera i popravljanje DNSSEC rollover planova pre primene u stvarnoj DNS zoni.**

FlightCheck analizira predložene trenutke objavljivanja, zamene i uklanjanja DNSSEC ključeva (KSK/ZSK). Uzima u obzir keširane DS/DNSKEY zapise, DNSSEC potpise, TTL-ove, kašnjenja propagacije i ponašanje resolvera. Prikazuje **kada i zašto** može nastati `SERVFAIL`, predlaže bezbedniji raspored i omogućava proveru u izolovanoj laboratoriji.

Program **ne menja javni DNS**, ne zahteva privatne ključeve postojeće zone i nije alat za automatsko izvršavanje rollover-a u produkciji.

> **Za prvi put:** dovoljno je instalirati Python i izvršiti poglavlje [Prvi test za 2 minuta](#3-prvi-test-za-2-minuta-bez-docker-a). Za pravi mrežni demo sa Unbound/BIND resolverima instalirajte i Docker.

## Sadržaj

1. [Šta projekat omogućava](#1-šta-projekat-omogućava)
2. [Preduslovi i instalacija](#2-preduslovi-i-instalacija)
3. [Prvi test za 2 minuta — bez Docker-a](#3-prvi-test-za-2-minuta-bez-docker-a)
4. [Pokretanje Docker laboratorije sa četiri resolvera](#4-pokretanje-docker-laboratorije-sa-četiri-resolvera)
5. [Snapshot: obični DNS upiti ili AXFR](#5-snapshot-obični-dns-upiti-ili-axfr)
6. [Generisanje ZSK/KSK plana iz snapshot-a](#6-generisanje-zskksk-plana-iz-snapshot-a)
7. [Testiranje namerno lošeg plana i automatska ispravka](#7-testiranje-namerno-lošeg-plana-i-automatska-ispravka)
8. [Izvršavanje plana dobijenog iz snapshot-a u Docker-u](#8-izvršavanje-plana-dobijenog-iz-snapshot-a-u-docker-u)
9. [Sopstvena zona i administratorski ulazi](#9-sopstvena-zona-i-administratorski-ulazi)
10. [Testovi, rezultati i izlazni kodovi](#10-testovi-rezultati-i-izlazni-kodovi)
11. [Najčešće greške i rešenja](#11-najčešće-greške-i-rešenja)
12. [Struktura projekta, ograničenja i bezbednost](#12-struktura-projekta-ograničenja-i-bezbednost)

---

## 1. Šta projekat omogućava

| Režim | Komanda / alat | Namena |
|---|---|---|
| Analiza postojećeg plana | `flightcheck check` | Da li raspored može dovesti do DNSSEC grešaka? |
| Automatska ispravka | `flightcheck fix` | Predlog bezbednijeg vremena za pojedine korake. |
| Brzi lokalni eksperiment | `flightcheck lab` | Provera modela u ugrađenoj laboratoriji, bez Docker-a. |
| Običan snapshot | `flightcheck snapshot` | Prikupljanje odabranih zapisa iz autoritativnih DNS odgovora. |
| Potpuniji snapshot preko AXFR-a | `flightcheck snapshot --axfr` | Prenos cele potpisane zone preko TCP-a, ako server dozvoljava. |
| Automatski plan iz snapshot-a | `flightcheck plan` | Predlog KSK ili ZSK rollover rasporeda. |
| Mrežni eksperiment | `docker compose` | Stvarni DNS upiti ka Unbound, BIND i dva emulirana resolvera. |

**Dva glavna toka rada:**

```text
A) Već postoji plan:
   plan.yaml -> check -> fix -> check -> Docker laboratorija -> HTML/JSON

B) Plan pravimo iz trenutnog stanja:
   stabilna DNS mreža -> snapshot (DNS ili AXFR)
      -> inputs.yaml (namera administratora)
      -> plan -> check / fix -> Docker laboratorija -> HTML/JSON
```

**Važna razlika:** snapshot opisuje stanje zone *sada*; `inputs.yaml` govori *koji ključ želimo da zamenimo* i koje pretpostavke koristimo; YAML rollover plan sadrži *konkretna vremena budućih promena*. AXFR ne izvršava promene i sam po sebi ne daje željeni raspored.

---

## 2. Preduslovi i instalacija

### 2.1. Šta je potrebno?

- **Python 3.10 ili noviji** (preporučen Python **3.12**, jer ga koristi i Docker slika projekta).
- **pip** i **venv** za Python okruženje.
- **Docker Desktop** na Windows-u ili **Docker Engine + Docker Compose v2 plugin** na Linux-u — samo za Docker demonstracije.
- Internet za preuzimanje Pythona, paketa i Docker slika. Izolovana Docker laboratorija se zatim izvršava bez izlaska na internet.
- Terminal: **Windows PowerShell** ili **Linux bash**. Kod svih komandi ispod je označeno iz kog foldera se pokreću.

Python biblioteke koje projekat koristi već su deklarisane u `pyproject.toml`:

| Biblioteka | Uloga |
|---|---|
| `dnspython >= 2.6` | DNS upiti i AXFR preko TCP-a |
| `cryptography >= 42` | DNSSEC ključevi i potpisi u laboratoriji |
| `PyYAML >= 6` | Učitavanje i snimanje YAML fajlova |
| `pytest >= 8` | Automatizovani testovi (opciono, uključeno u uputstvu) |
| `zstandard >= 0.22` | Opciona zavisnost za dodatne `real` alate; nije potrebna za Docker demo |

**Ne treba ručno instalirati svaku biblioteku.** Komanda `pip install -e ".[test]"` instalira osnovne zavisnosti i `pytest`.

### 2.2. Preuzimanje projekta i izbor foldera

Preuzmite/raspakujte ZIP projekta. U ovom uputstvu koristi se verzija **`dnssec-flightcheck-real-resolvers3`** (bez razmaka pre broja `3`).

Otvorite terminal u **glavnom folderu projekta**, tj. onom u kojem se vide:

```text
README.md
pyproject.toml
flightcheck/
scenarios/
tests/
lab/docker/
```

Sve Python komande (`python -m flightcheck ...`) izvršavaju se **iz tog glavnog foldera**, osim kada eksplicitno piše drugačije. Docker Compose komande se izvršavaju iz **`lab/docker`**.

#### Windows 10/11 — PowerShell

1. Instalirajte Python sa <https://www.python.org/downloads/windows/>. Ako instalater nudi opciju **Add Python to PATH**, uključite je.
2. Za Docker eksperiment instalirajte <https://www.docker.com/products/docker-desktop/> i pokrenite Docker Desktop. Po potrebi uključite WSL 2 backend / virtualizaciju.
3. Raspakujte projekat i otvorite PowerShell u njegovom glavnom folderu.

Provera:

```powershell
py --version
docker --version
docker compose version
```

Ako još nemate Docker, poslednje dve komande neće raditi — to **ne sprečava** prvi test bez Docker-a.

Kreirajte Python virtualno okruženje i instalirajte projekat:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
```

**Bez aktivacije okruženja** možete proveriti da program radi:

```powershell
.\.venv\Scripts\python.exe -m flightcheck --help
```

Za kraće komande u ovom README-u aktivirajte okruženje:

```powershell
.\.venv\Scripts\Activate.ps1
python -m flightcheck --help
```

Ako PowerShell prijavi `running scripts is disabled on this system`, pokrenite samo u **trenutnom terminalu**:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Ta promena se ne čuva trajno. Alternativa je da potpuno preskočite aktivaciju i svuda koristite `.\.venv\Scripts\python.exe -m flightcheck`.

#### Linux — Ubuntu / Debian (bash)

Instalirajte Python i podršku za virtualna okruženja:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 --version
```

Proverite da je Python najmanje **3.10**. Ako vaša distribucija nudi stariju verziju, prvo instalirajte noviji Python odgovarajućim zvaničnim postupkom za tu distribuciju.

U glavnom folderu projekta:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m flightcheck --help
```

Za Docker deo instalirajte **Docker Engine** i **Docker Compose v2 plugin** prema zvaničnim uputstvima:

- <https://docs.docker.com/engine/install/ubuntu/>
- <https://docs.docker.com/compose/install/linux/>

Proverite:

```bash
docker --version
docker compose version
docker info
```

Ako se javlja `permission denied` za Docker socket, korisnik nema pristup Docker daemon-u. Možete koristiti odgovarajući administratorski postupak ili podesiti članstvo u grupi `docker` prema zvaničnoj dokumentaciji. **Članstvo u `docker` grupi praktično daje administratorska ovlašćenja** — nemojte ga automatski dodeljivati na deljenom računaru.

#### Pri svakom sledećem pokretanju

Ne treba ponovo instalirati pakete. Otvorite terminal u glavnom folderu projekta i aktivirajte postojeće okruženje:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux bash
source .venv/bin/activate
```

**Kako izaći iz okruženja:** `deactivate`.

---

## 3. Prvi test za 2 minuta — bez Docker-a

Ovo je preporučeni početak: ne zahteva DNS servere, Docker ni internet (nakon instalacije paketa).

> **Folder:** glavni folder projekta. **Komande su iste na Windows-u i Linux-u** uz aktivirano okruženje.

### 3.1. Proverite namerno loš KSK plan

```bash
python -m flightcheck check scenarios/ksk-double-ds-bad.yaml --both-models --html bad-check.html
```

Očekivana ocena je **`UNSAFE`**: raspored omogućava neusaglašenost između keširanog DS-a i DNSKEY skupa. Komanda može završiti **izlaznim kodom 1 — to je očekivan nalaz, ne kvar programa**.

Otvorite HTML u pregledaču:

```powershell
# Windows
start .\bad-check.html
```

```bash
# Linux desktop
xdg-open bad-check.html
```

Na Linux serveru bez grafičkog okruženja otvorite fajl u pregledaču sa svog računara ili ga kopirajte na računar koji ima pregledač.

### 3.2. Zatražite automatsku ispravku

```bash
python -m flightcheck fix scenarios/ksk-double-ds-bad.yaml --write fixed.yaml --html fixed-prediction.html
```

Originalni plan ostaje nepromenjen. Novi plan je `fixed.yaml`.

Proverite popravljeni plan:

```bash
python -m flightcheck check fixed.yaml --both-models --html fixed-check.html
```

Za fabrički primer očekuje se bezbedniji raspored. U produkciji rezultat zavisi od stvarnih TTL-ova, potpisa i zadatih pretpostavki.

### 3.3. Opcionalno: brza laboratorijska provera bez Docker-a

```bash
python -m flightcheck lab scenarios/ksk-double-ds-bad.yaml --html lab-bad.html
python -m flightcheck lab fixed.yaml --html lab-fixed.html
```

Ovo pokreće **ugrađeni eksperiment**; ne pokreće prave Unbound/BIND procese. Rezultati mogu biti u skladu sa predviđanjem čak i kada je plan `UNSAFE`, zato što su neuspešni DNS odgovori **unapred predviđeni**.

### Ostali gotovi scenariji

U `scenarios/` postoje parovi `-bad.yaml` i `-good.yaml`, uključujući `zsk-prepublish`, `ksk-double-ds`, `algorithm-rollover`, `ttl-trap`, `go-insecure` i `go-secure`.

Na primer:

```bash
python -m flightcheck check scenarios/zsk-prepublish-bad.yaml --html zsk-bad.html
python -m flightcheck check scenarios/zsk-prepublish-good.yaml --html zsk-good.html
```

---

## 4. Pokretanje Docker laboratorije sa četiri resolvera

Ovaj eksperiment koristi izolovanu mrežu sa sopstvenim root i parent serverom, dva autoritativna servera i četiri resolvera:

- **Unbound** — stvarni validating resolver;
- **BIND** — stvarni validating resolver;
- **emulated** — naš emulirani resolver;
- **emulated-behind-cache** — emulacija validatora iza keša.

> **Ovo je simulirana zona `bank.test.`, a ne produkcijski DNS.** Laboratorija generiše sopstvene DNSSEC ključeve i potpise.

### 4.1. Windows PowerShell

**Folder:** glavni folder projekta; Docker Desktop treba da bude pokrenut.

```powershell
cd .\lab\docker
New-Item -ItemType Directory -Force .\out | Out-Null
Remove-Item .\out\report.html, .\out\probe.json -ErrorAction SilentlyContinue

$env:PLAN = "scenarios/ksk-double-ds-bad.yaml"
$env:SCALE = "600"

docker compose up --build -d
docker compose logs -f probe
```

Kada se probe završi, proverite da je završio i otvorite izveštaj:

```powershell
docker compose ps -a
docker compose wait probe
start .\out\report.html
```

Sačuvajte izveštaj pod zasebnim imenom pre novog testa (da ga sledeći test ne prepiše):

```powershell
Copy-Item .\out\report.html .\out\report-ksk-bad.html
Copy-Item .\out\probe.json .\out\probe-ksk-bad.json
```

Ugasite laboratoriju i vratite se u glavni folder:

```powershell
docker compose down
Remove-Item Env:PLAN, Env:SCALE -ErrorAction SilentlyContinue
cd ..\..
```

### 4.2. Linux bash

**Folder:** glavni folder projekta.

```bash
cd lab/docker
mkdir -p out
rm -f out/report.html out/probe.json
PLAN=scenarios/ksk-double-ds-bad.yaml SCALE=600 docker compose up --build -d
docker compose logs -f probe
```

Posle završetka:

```bash
docker compose ps -a
docker compose wait probe
xdg-open out/report.html
cp out/report.html out/report-ksk-bad.html
cp out/probe.json out/probe-ksk-bad.json
docker compose down
cd ../..
```

`xdg-open` je opciono; neće raditi na serveru bez desktop okruženja.

### 4.3. Šta očekivati?

- `SCALE=600` znači da **1 stvarna sekunda predstavlja 600 simuliranih sekundi**, tj. 10 simuliranih minuta.
- Prvo pokretanje preuzima/gradi Docker slike i može trajati duže; merenje traje nekoliko minuta.
- U konzoli ćete videti napredak upita, broj `SERVFAIL` odgovora i završni pregled po resolveru.
- Izveštaji su `lab/docker/out/report.html` i `lab/docker/out/probe.json`.
- `probe exited with code 0` znači da **merenja ne protivreče predviđanju**; **ne znači nužno 0 SERVFAIL**. Loš plan može izazvati mnogo `SERVFAIL` odgovora koje je alat pravilno predvideo.

**Ne pokrećite istovremeno glavni Docker eksperiment i bootstrap mrežu iz sledećeg poglavlja.** Obe koriste podmrežu `10.53.0.0/24`.

---

## 5. Snapshot: obični DNS upiti ili AXFR

Snapshot prikuplja podatke potrebne za planiranje promene ključa. **Postoje dva opciona režima:**

| | Običan snapshot | AXFR snapshot |
|---|---|---|
| Izbor | `snapshot` (podrazumevano) | `snapshot --axfr` |
| Način prikupljanja | Pojedinačni DNS upiti | Prenos zone preko TCP-a |
| Opseg | Samo traženi RRset-ovi i osnovni zapisi | Sadržaj prenete zone |
| Tipičan status | `partial` | `complete` ako su ispunjeni svi uslovi |
| Prava pristupa | Standardni autoritativni DNS upiti | AXFR dozvola na autoritativnom serveru |

U laboratoriji je početno stanje definisano u `lab/docker/bootstrap/bank-test.yaml`, ali **snapshot podaci se prikupljaju DNS komunikacijom sa serverima**. Snapshot collector ne treba da prepisuje podatke direktno iz tog YAML-a.

### 5.1. Pokrenite stabilnu DNSSEC mrežu

**Windows PowerShell — iz glavnog foldera:**

```powershell
cd .\lab\docker
docker compose -f docker-compose.bootstrap.yml up --build -d
Start-Sleep -Seconds 5
```

**Linux bash — iz glavnog foldera:**

```bash
cd lab/docker
docker compose -f docker-compose.bootstrap.yml up --build -d
sleep 5
```

Stabilna mreža pokreće `root`, `tld`, `ns1` i `ns2`. Ne pokreće rollover, Unbound/BIND ni probe. Ključevi su sintetički, a vreme nije ubrzano.

### 5.2. Režim A: običan snapshot

**Windows i Linux — iz `lab/docker`:**

```bash
docker compose -f docker-compose.bootstrap.yml run --rm snapshot
```

Očekivani fajl:

```text
lab/docker/out-snapshot/snapshot-bank.yaml
```

Tipičan rezultat: `method: dns-query`, `completeness.status: partial`. To je očekivano jer nismo popisali sve zapise zone.

### 5.3. Režim B: AXFR — cela zona

**Windows i Linux — iz `lab/docker`:**

```bash
docker compose -f docker-compose.bootstrap.yml run --rm snapshot-axfr
```

Očekivani fajl:

```text
lab/docker/out-snapshot/snapshot-axfr.yaml
```

Za uspešan prenos dva autoritativna servera i roditeljski DS u isporučenoj Docker laboratoriji očekuje se nešto nalik sledećem (primer, ne garancija za bilo koju drugu zonu):

```yaml
method: axfr
completeness:
  status: complete
transfer:
  status: complete
  parent_ds_collected: true
  cross_server: consistent
errors: []
```

AXFR u bootstrap laboratoriji je dozvoljen **samo** namenskom collector kontejneru (`10.53.0.31`). Glavni experiment Compose ne uključuje AXFR servis. Ako server odbije AXFR, program neće krišom preći na obične DNS upite.

### 5.4. Uporedite rezultate oba načina

**Windows PowerShell — iz `lab/docker`:**

```powershell
Select-String -Path .\out-snapshot\snapshot-bank.yaml, .\out-snapshot\snapshot-axfr.yaml -Pattern '^method:|^completeness:|^transfer:|cross_server' -Context 0,1
```

**Linux bash — iz `lab/docker`:**

```bash
grep -nE '^method:|^completeness:|^transfer:|cross_server' out-snapshot/snapshot-bank.yaml out-snapshot/snapshot-axfr.yaml
```

Detaljnije otvorite fajlove u tekst-editoru ili uporedite njihove `rrsets` i TTL vrednosti.

### 5.5. Zaustavite bootstrap

**Windows / Linux — iz `lab/docker`:**

```bash
docker compose -f docker-compose.bootstrap.yml down
```

Zatim se vratite u glavni folder:

```powershell
# Windows
cd ..\..
```

```bash
# Linux
cd ../..
```

> Ako ponovo pokrenete bootstrap sa `up` nakon `down`, laboratorija može generisati **nove ključeve i nove key ID vrednosti**. Nemojte kombinovati identifikatore ključeva iz starog snapshot-a sa novim bez ponovne provere.

---

## 6. Generisanje ZSK/KSK plana iz snapshot-a

U ovom delu koristimo **već sačuvani snapshot** iz poglavlja 5. Docker bootstrap više ne mora biti uključen.

**Folder za sve komande:** glavni folder projekta, sa aktiviranim Python okruženjem.

### 6.1. Napravite `inputs.yaml`

U `inputs.yaml` administrator navodi:

- `replace`: identifikator postojećeg ključa koji želi da zameni;
- `new_key`: algoritam planiranog novog ključa;
- `start`: početak plana (UTC datum/vreme, ne pre `collected_at` iz snapshot-a);
- `delays`: očekivana propagacija i kašnjenje registracije DS-a;
- `margin`: dodatna sigurnosna vremenska margina;
- `resolver`: pretpostavke o keširanju;
- `zone_ttl_bound`: maksimalni TTL neviđenih zapisa — **obavezan za `partial` snapshot**, nije neophodan za `complete` AXFR.

Šablon već postoji: `lab/docker/inputs-zsk.example.yaml`.

**Windows PowerShell:**

```powershell
$start = (Get-Date).ToUniversalTime().AddMinutes(10).ToString('yyyy-MM-ddTHH:mm:ssZ')
(Get-Content lab\docker\inputs-zsk.example.yaml -Raw).Replace('START-TIME', $start) | Set-Content lab\docker\out-snapshot\inputs.yaml -Encoding ascii
notepad .\lab\docker\out-snapshot\inputs.yaml
```

**Linux bash:**

```bash
cp lab/docker/inputs-zsk.example.yaml lab/docker/out-snapshot/inputs.yaml
python - <<'PY'
from datetime import datetime, timedelta, timezone
from pathlib import Path
path = Path('lab/docker/out-snapshot/inputs.yaml')
start = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime('%Y-%m-%dT%H:%M:%SZ')
path.write_text(path.read_text().replace('START-TIME', start))
PY
nano lab/docker/out-snapshot/inputs.yaml
```

Sačuvajte i zatvorite editor. **Ne koristite fiksni datum iz tuđeg primera** — treba da bude nakon vremena vašeg snapshot-a, a potpisi treba da budu važeći za planirani interval.

Primer sadržaja (ključ je **primer**, mora se zameniti identifikatorom iz *vašeg* snapshot-a):

```yaml
replace: CHOOSE-A-KEY
new_key: {algorithm: ECDSAP256SHA256}
start: 2026-11-01T12:00:00Z

delays:
  propagation: 5m
  registry: 1h
  parent_propagation: 5m
margin: 1h
resolver:
  max_cache_ttl: 1d
  profile: worst
zone_ttl_bound: 1d
```

### 6.2. Pronađite identifikator postojećeg ključa

**Za ZSK rollover iz običnog snapshot-a:**

```bash
python -m flightcheck plan lab/docker/out-snapshot/snapshot-bank.yaml --rollover zsk --inputs lab/docker/out-snapshot/inputs.yaml --output lab/docker/out-snapshot/plan-from-snapshot.yaml
```

**Za ZSK rollover iz AXFR snapshot-a:**

```bash
python -m flightcheck plan lab/docker/out-snapshot/snapshot-axfr.yaml --rollover zsk --inputs lab/docker/out-snapshot/inputs.yaml --output lab/docker/out-snapshot/plan-from-axfr.yaml
```

Prvi pokušaj sa `CHOOSE-A-KEY` **namerno** daje poruku nalik:

```text
error: inputs: replace: CHOOSE-A-KEY is not a key of this zone
(keys: key-12345-xxxxxxxxxx (ksk), key-54321-yyyyyyyyyy (zsk))
```

To **nije kvar**: otvorite `inputs.yaml`, zamenite `CHOOSE-A-KEY` **tačnim celim ID-om** uz oznaku `(zsk)` i sačuvajte. Zatim ponovite odgovarajuću `plan` komandu.

Za **KSK rollover**, u `replace` upišite ključ označen sa `(ksk)` i koristite `--rollover ksk`. Za laboratorijski KSK scenario podrazumevan je *double-DS* postupak; za ZSK *pre-publish* postupak. Algoritam novog ključa u ovom Plan Builder-u mora biti kompatibilan sa algoritmom zamenjenog ključa.

**Nemojte** pretpostaviti da se key tag ili ceo ID neće promeniti sledeći put kada pokrenete novu bootstrap mrežu.

### 6.3. Proverite generisani plan i napravite HTML

Za AXFR primer:

```bash
python -m flightcheck check lab/docker/out-snapshot/plan-from-axfr.yaml --both-models --html lab/docker/out-snapshot/prediction-axfr.html
```

Za običan snapshot:

```bash
python -m flightcheck check lab/docker/out-snapshot/plan-from-snapshot.yaml --both-models --html lab/docker/out-snapshot/prediction-regular.html
```

Otvaranje na Windows-u:

```powershell
start .\lab\docker\out-snapshot\prediction-axfr.html
```

Na Linux desktopu:

```bash
xdg-open lab/docker/out-snapshot/prediction-axfr.html
```

**Status:** kod običnog snapshot-a očekuje se `SAFE for the sampled records only` ako su vremena dobra; kod potpunog AXFR-a moguća je šira ocena modela, ali čak ni `complete` **nije kriptografski dokaz bezbednosti produkcione zone**.

---

## 7. Testiranje namerno lošeg plana i automatska ispravka

Ovaj deo pokazuje glavnu ideju projekta: **administrator predlaže preuranjene promene, FlightCheck detektuje rizik i predlaže korekciju**.

Polazimo od već generisanog `plan-from-axfr.yaml` (alternativno možete koristiti `plan-from-snapshot.yaml`).

### 7.1. Napravite kopiju plana

**Windows PowerShell — iz glavnog foldera:**

```powershell
Copy-Item .\lab\docker\out-snapshot\plan-from-axfr.yaml .\lab\docker\out-snapshot\plan-bad.yaml
notepad .\lab\docker\out-snapshot\plan-bad.yaml
```

**Linux bash — iz glavnog foldera:**

```bash
cp lab/docker/out-snapshot/plan-from-axfr.yaml lab/docker/out-snapshot/plan-bad.yaml
nano lab/docker/out-snapshot/plan-bad.yaml
```

U kopiji pronađite `steps:` i za **drugi i treći korak** zamenite `at:` vrednosti sa `0`. Prvi korak je već na `0`.

Primer:

```yaml
steps:
  - name: Publish new-zsk-placeholder
    at: 0
    # ...
  - name: Sign with new-zsk-placeholder instead of OLD-ZSK
    at: 0
    # ...
  - name: Remove OLD-ZSK
    at: 0
    # ...
```

**Ovo je ilustracija samo polja vremena.** U stvarnom YAML-u ostavite sve ostale postojeće `dnskey`, `data` i `keys` vrednosti, kao i tačna imena koraka. Tri tačke (`...`) **ne treba upisivati** u stvarni fajl.

### 7.2. Analizirajte loš plan

```bash
python -m flightcheck check lab/docker/out-snapshot/plan-bad.yaml --both-models --html lab/docker/out-snapshot/bad-prediction.html
```

Na standardnom ZSK laboratorijskom primeru očekuje se `UNSAFE` i objašnjenje konflikta keširanih DNSKEY zapisa i potpisa. Izlazni kod `1` je nameran rezultat analize.

### 7.3. Neka FlightCheck sam izračuna popravku

```bash
python -m flightcheck fix lab/docker/out-snapshot/plan-bad.yaml --write lab/docker/out-snapshot/plan-fixed.yaml --html lab/docker/out-snapshot/fixed-prediction.html
```

Ponovo proverite novi plan:

```bash
python -m flightcheck check lab/docker/out-snapshot/plan-fixed.yaml --both-models --html lab/docker/out-snapshot/fixed-check.html
```

U ranije testiranom primeru sa TTL-ovima `DNSKEY=1h` i `mail=1d` FlightCheck je predložio približno:

| Korak | Loše vreme | Predloženo vreme u tom primeru |
|---|---:|---:|
| Objavi novi ZSK | T+0 | T+0 |
| Počni da potpisuješ novim ZSK | T+0 | T+2h05min |
| Ukloni stari ZSK | T+0 | T+27h10min |

Stvarni rezultat zavisi od konkretnog snapshot-a, TTL-ova, vremenskih margina i pretpostavki. Navedena vremena **nisu univerzalna DNSSEC pravila**.

---

## 8. Izvršavanje plana dobijenog iz snapshot-a u Docker-u

Ovo je **stvarni laboratorijski test** rasporeda koji je izračunat ili popravljen. **Ne menja originalnu zonu**: Docker pravi ekvivalentno laboratorijsko stanje sa sintetičkim ključevima.

Pre pokretanja proverite da je bootstrap mreža zaustavljena:

```bash
# Dok ste u lab/docker, ako je bootstrap možda još aktivan:
docker compose -f docker-compose.bootstrap.yml down
```

**Odaberite jedan plan:**

- `plan-from-axfr.yaml` — plan koji je generisao Plan Builder;
- `plan-bad.yaml` — namerno loš plan;
- `plan-fixed.yaml` — automatski popravljen plan.

### 8.1. Windows PowerShell

**Počnite iz glavnog foldera projekta.** Primer testira `plan-bad.yaml`; promenite izvor u `plan-fixed.yaml` kada radite drugi test.

```powershell
New-Item -ItemType Directory -Force .\lab\docker\out | Out-Null
Copy-Item .\lab\docker\out-snapshot\plan-bad.yaml .\lab\docker\out\candidate.yaml
cd .\lab\docker

Remove-Item .\out\report.html, .\out\probe.json -ErrorAction SilentlyContinue
$env:PLAN = "/lab/candidate.yaml"
$env:SCALE = "600"

docker compose up --build -d
docker compose logs -f probe
```

Zatim:

```powershell
docker compose wait probe
start .\out\report.html
Copy-Item .\out\report.html .\out\report-bad.html
Copy-Item .\out\probe.json .\out\probe-bad.json

docker compose down
Remove-Item Env:PLAN, Env:SCALE -ErrorAction SilentlyContinue
cd ..\..
```

Za **popravljeni plan** ponovite postupak, ali u prvom `Copy-Item` koristite `plan-fixed.yaml` i sačuvajte HTML kao `report-fixed.html`, a JSON kao `probe-fixed.json`.

### 8.2. Linux bash

**Počnite iz glavnog foldera projekta:**

```bash
mkdir -p lab/docker/out
cp lab/docker/out-snapshot/plan-bad.yaml lab/docker/out/candidate.yaml
cd lab/docker
rm -f out/report.html out/probe.json
PLAN=/lab/candidate.yaml SCALE=600 docker compose up --build -d
docker compose logs -f probe
```

Zatim:

```bash
docker compose wait probe
xdg-open out/report.html
cp out/report.html out/report-bad.html
cp out/probe.json out/probe-bad.json
docker compose down
cd ../..
```

Za popravljeni plan ponovite sa `plan-fixed.yaml` i sačuvajte rezultat pod imenima `report-fixed.html` i `probe-fixed.json`.

### 8.3. Kako tumačiti rezultate

Poređenje treba da odgovori na tri pitanja:

1. Da li je `check` predvideo DNSSEC neusaglašenost i njen mogući vremenski interval?
2. Da li su Unbound, BIND i emulirani resolveri tokom testiranja vratili `SERVFAIL`?
3. Da li je `fix` predložio raspored koji u istim laboratorijskim uslovima uklanja taj problem?

Važno: **nije neophodno da svaki resolver ima `SERVFAIL` čak ni kada je plan `UNSAFE`.** Model prikazuje mogući rizik, a pojedinačno ponašanje zavisi od stvarnog keširanja i trenutaka upita.

Datoteka `out/key_mapping.yaml` beleži vezu između identifikatora ključeva iz snapshot plana i novo-generisanih laboratorijskih ključeva. `out/report.html` je izveštaj o mrežnom eksperimentu; `prediction-axfr.html` je zaseban izveštaj o **predviđanju**.

---

## 9. Sopstvena zona i administratorski ulazi

### 9.1. Obični snapshot javne/administrirane zone

Možete koristiti sopstvenu zonu umesto laboratorijske `bank.test.`. Pokrenite iz glavnog foldera:

```bash
python -m flightcheck snapshot YOUR-ZONE.example --query www.YOUR-ZONE.example/A --output my-snapshot.yaml
```

Zamenite `YOUR-ZONE.example` stvarnim imenom zone. Ako znate adrese autoritativnih servera, navedite ih sa `--server` i `--parent-server`. Program pokušava da otkrije servere kada nisu zadati.

**Primer oblika komande za servere koje kontrolišete:**

```bash
python -m flightcheck snapshot bank.test. --server 10.53.0.12 --server 10.53.0.13 --parent-server 10.53.0.11 --query www.bank.test./A --output my-snapshot.yaml
```

Adrese `10.53.0.x` iz ovog primera dostupne su **unutar odgovarajuće Docker mreže**, ne direktno sa običnog Windows/Linux host terminala.

### 9.2. AXFR sa servera koji ga izričito dozvoljava

```bash
python -m flightcheck snapshot YOUR-ZONE.example --axfr --server YOUR-AUTH-SERVER-IP --parent-server YOUR-PARENT-SERVER-IP --output my-axfr.yaml
```

- AXFR je **opcion** i prenosi zonu samo od servera kojem imate pravo pristupa.
- Serveri obično ograničavaju AXFR na ovlašćene klijente (npr. sekundarne DNS servere ili interne alate).
- `--tsig-file FILE` je opciona podrška kada server zahteva TSIG. Nemojte izlagati TSIG tajne u repozitorijumu.
- Ako transfer nije dozvoljen, očekujte `REFUSED` ili grešku; alat neće automatski pokušavati drugi metod.
- Roditeljski `DS` nije deo AXFR-a child zone — prikuplja se posebnim DNS upitom.

### 9.3. Koja vremena administrator zadaje?

Imate dva načina rada:

**A. Želim predlog:** `snapshot`/`--axfr` + `inputs.yaml` + `flightcheck plan`. Administrator navodi ključ koji menja, početak, propagaciju, marginu i uslove resolvera; Plan Builder predlaže **vremena koraka**.

**B. Imam svoj raspored:** administrator pravi/menja YAML sa `steps[*].at`, zatim koristi `flightcheck check` i `flightcheck fix` za analizu i ispravku.

Vremena `at` su relativna u odnosu na `T+0`; primeri su `0`, `30m`, `2h`, `1d`. `start` je apsolutno UTC vreme početka plana.

---

## 10. Testovi, rezultati i izlazni kodovi

### Pokretanje automatizovanih testova

**Windows i Linux — glavni folder projekta, aktivno virtualno okruženje:**

```bash
python -m pytest -q
```

Samo testovi vezani za AXFR:

```bash
python -m pytest -q tests/test_axfr.py
```

**Poznato stanje isporučenog ZIP-a `real-resolvers3`:** u proveri ove konkretne verzije `tests/test_axfr.py` završio je sa **35 passed, 1 failed**. Neuspešan test je `test_records_outside_the_zone_do_not_reach_the_snapshot`: neispravni AXFR transfer se odbacuje, dok test očekuje rezultat sa učitanom zonom. To **nije** isto što i neuspeh praktičnog AXFR transfera u Docker laboratoriji, koji je uspešno demonstriran. Pre objave da „svi testovi prolaze“, treba uskladiti očekivanja testa i implementacije i ponoviti kompletan test suite.

### Izlazni kodovi `check` i `fix`

| Kod | Značenje |
|---|---|
| `0` | Bezbedno prema odgovarajućem modelu, bez ograničenja pokrivenosti koja alat označava kao problem. |
| `1` | `UNSAFE` — plan omogućava DNSSEC neusaglašenost ili bezbedna korekcija nije pronađena. |
| `2` | Greška u ulazu, konfiguraciji ili izvršavanju. |
| `3` | Bezbedno samo uz ograničenje modela / za uzorkovane zapise; **nije automatski neuspeh programa**. |
| `4` | Nepotpuno stanje/planski problem koji se ne rešava samo pomeranjem vremena. |

Kod `probe`/mrežnog eksperimenta `0` znači **nema kontradikcije između modela i merenja**, a ne „nijedan upit nije vratio SERVFAIL“.

### Gde se čuvaju izlazi?

| Putanja | Sadržaj |
|---|---|
| `lab/docker/out-snapshot/snapshot-bank.yaml` | Obični snapshot Docker zone. |
| `lab/docker/out-snapshot/snapshot-axfr.yaml` | AXFR snapshot Docker zone. |
| `lab/docker/out-snapshot/inputs.yaml` | Administratorove namere i pretpostavke. |
| `lab/docker/out-snapshot/plan-from-axfr.yaml` | Automatski generisan plan iz AXFR-a. |
| `lab/docker/out-snapshot/plan-bad.yaml` | Namerno loš plan za demonstraciju. |
| `lab/docker/out-snapshot/plan-fixed.yaml` | Automatski popravljeni plan. |
| `lab/docker/out-snapshot/*.html` | HTML predikcije / planovi. |
| `lab/docker/out/report.html` | HTML izveštaj iz stvarnog Docker merenja. |
| `lab/docker/out/probe.json` | Sirovi podaci o merenju. |
| `lab/docker/out/key_mapping.yaml` | Mapiranje sintetičkih ključeva. |

**Napomena:** `lab/docker/out-snapshot/network/` sadrži internu laboratorijsku konfiguraciju i privatne *sintetičke* ključeve. Ne postavljajte taj folder javno. Repo `.gitignore` isključuje `out` i `out-snapshot`.

---

## 11. Najčešće greške i rešenja

| Problem / poruka | Uzrok i postupak |
|---|---|
| `python` / `py` nije prepoznat | Instalirajte Python 3.10+, proverite PATH, otvorite novi terminal. Na Linux-u koristite `python3` za kreiranje venv-a. |
| `No module named flightcheck` | Niste u odgovarajućem Python okruženju ili niste instalirali projekat: pokrenite `python -m pip install -e ".[test]"` iz foldera sa `pyproject.toml`. |
| `running scripts is disabled` na Windows-u | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` samo za trenutni prozor, ili koristite `.\.venv\Scripts\python.exe` bez aktivacije. |
| `docker` nije prepoznat | Instalirajte/pokrenite Docker Desktop (Windows) ili Docker Engine (Linux). |
| `Cannot connect to the Docker daemon` | Docker Desktop nije pokrenut ili Linux Docker servis nije aktivan / nemate dozvolu. |
| `docker compose` ne radi, a `docker-compose` radi | Potrebna je **Compose v2** verzija sa komandama `docker compose ...` (bez crtice). |
| `network overlaps` ili konflikti subnet-a | Zaustavite prethodni bootstrap ili glavni eksperiment sa `docker compose ... down`. Po potrebi proverite druge Docker mreže koje koriste `10.53.0.0/24`. |
| `port 53 already in use` | Drugi DNS servis zauzima lokalni port; u isporučenom izolovanom Docker Compose-u port 53 se ne objavljuje hostu. Proverite da slučajno ne koristite zaseban host-mode lab. |
| `CHOOSE-A-KEY is not a key` | Očekivana poruka prilikom prvog pokušaja generisanja plana. Zamenite placeholder punim ID-om `(zsk)` ili `(ksk)` iz poruke. |
| `start is before the snapshot was taken` | `start` u `inputs.yaml` postavite nakon `collected_at` iz snapshot-a. |
| `signature expires` ili neočekivan `UNSAFE` | Proverite važenje postojećih RRSIG potpisa, vreme `start` i da li je trenutak zamene previše daleko od prikupljanja snapshot-a. |
| `SAFE for the sampled records only`, kod `3` | Normalno za običan snapshot. Model nije video celu zonu, pa ne tvrdi globalnu bezbednost. |
| AXFR `REFUSED` | Server nije dozvolio prenos vašem klijentu. U bootstrap-u koristite namenski `snapshot-axfr` servis; ne pokušavajte da zaobiđete ograničenje. |
| AXFR je `partial` iako je prenos sa jednog servera uspeo | Nije potvrđena konzistentnost svih potrebnih servera ili roditeljski DS; pogledajte `transfer.servers`, `cross_server`, `warnings`. |
| `Permission denied` u `out-snapshot` na Linux-u | Docker može napraviti fajlove u vlasništvu `root`. Nakon gašenja kontejnera, ako posedujete mašinu: `sudo chown -R "$(id -u):$(id -g)" lab/docker/out-snapshot lab/docker/out`. |
| `report.html` ne postoji | Proverite `docker compose ps -a` i `docker compose logs --tail=100 probe`; moguće je da se probe nije završio. |
| `report.html` prikazuje rezultate prethodnog testa | Obrišite stare `report.html`/`probe.json` pre novog `up` i sačuvajte svaki rezultat pod novim imenom. |
| `SERVFAIL` u lošem planu | To može biti **očekivani eksperimentalni rezultat**, a ne greška sistema. Uporedite vreme i broj sa predikcijom. |
| PowerShell prikazuje `←[1m` | To su ANSI kodovi boja iz izlaza. Po potrebi koristite globalnu opciju `python -m flightcheck --no-color check ...`. |

**Dodatna Docker dijagnostika — iz `lab/docker`:**

```bash
docker compose ps -a
docker compose logs --tail=100 probe
docker compose logs --tail=100 unbound
docker compose logs --tail=100 bind
docker compose logs --tail=100 ns1
```

---

## 12. Struktura projekta, ograničenja i bezbednost

### Glavni folderi

```text
DNSSEC-FlightCheck/
├── flightcheck/                  # Python CLI, snapshot, AXFR, plan, model, fix
│   ├── cli.py
│   ├── snapshot.py
│   ├── axfr.py
│   ├── planbuilder.py
│   ├── simulator.py
│   ├── fixer.py
│   └── lab/                      # DNS serveri, resolveri, mrežni probe
├── scenarios/                   # unapred definisani dobri i loši planovi
├── lab/docker/
│   ├── docker-compose.yml       # puni Docker eksperiment
│   ├── docker-compose.bootstrap.yml  # stabilna zona za snapshot
│   ├── bootstrap/bank-test.yaml
│   ├── inputs-zsk.example.yaml
│   ├── out/                      # rezultati eksperimenta (generiše se)
│   └── out-snapshot/             # snapshot/inputs/plan (generiše se)
├── tests/                       # automatizovani testovi
├── docs/REFERENCE.md            # opis plana, modela i parametara
├── docs/SNAPSHOT-WORKFLOW.md    # dodatni detalji snapshot toka
├── pyproject.toml
└── README.md
```

### Granice validnosti rezultata

- `check` i `fix` daju procenu prema **modelu i pretpostavkama administratora**. Ne garantuju ishod svakog produkcijskog resolvera.
- Običan snapshot je delimičan. AXFR može dati potpun inventar prenete zone, ali **ne dokazuje kriptografsku validnost svih potpisa niti stanje svih servera van onih koji su testirani**.
- AXFR prikuplja i dodatne RRset-ove, ali Plan Builder ne modeluje automatski sve vrste podataka koje postoje u DNS zoni; pročitajte `docs/SNAPSHOT-WORKFLOW.md` za detalje o `rrsets`, `denial_rrsets` i `unsigned_rrsets`.
- Docker laboratorija koristi **sintetičke ključeve i potpise**, komprimuje vreme i reprodukuje vremenske odnose i potpisivanje, a ne identičnu produkcijsku DNS zonu.
- Model ne obuhvata svako moguće ponašanje resolvera, obnovu potpisa i sve DNSSEC rubne slučajeve.
- Nikada nemojte automatski izvršavati predloženi raspored u produkciji bez provere od strane administratora.

### Bezbednosna pravila

- Koristite AXFR **isključivo na serverima na kojima imate izričitu dozvolu za prenos zone**.
- Nikada ne unosite privatne DNSSEC ključeve u `inputs.yaml` ili Git repozitorijum.
- TSIG tajne čuvajte odvojeno; opcioni `--tsig-file` ne sme završiti u javnom repozitorijumu.
- Ne postavljajte generisane privatne laboratorijske ključeve iz `out-snapshot/network/` na internet.

### Dalja dokumentacija

- [Detaljan opis komandi, modela i YAML polja](docs/REFERENCE.md)
- [Snapshot-driven postupak i AXFR](docs/SNAPSHOT-WORKFLOW.md)
- [Primeri HTML izveštaja](examples/)
- [Gotovi scenariji](scenarios/)

---

**Preporučeni redosled za prvi susret sa projektom:**

1. Instalirajte Python i projekat (poglavlje 2).
2. Pokrenite `check` i `fix` bez Docker-a (poglavlje 3).
3. Pokrenite Docker test gotovog scenarija (poglavlje 4).
4. Prikupite običan i AXFR snapshot (poglavlje 5).
5. Napravite plan iz snapshot-a, namerno ga pokvarite i ispravite (poglavlja 6–7).
6. Uporedite `report-bad.html` i `report-fixed.html` iz Docker-a (poglavlje 8).

**FlightCheck je alat za planiranje i eksperimentalnu proveru — ne za automatsko menjanje DNSSEC konfiguracije u produkciji.**
