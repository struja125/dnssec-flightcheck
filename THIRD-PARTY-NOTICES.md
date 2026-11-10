# Komponente trećih lica i licence / Third-party components and licenses

DNSSEC FlightCheck ne sadrži kopiran izvorni kod trećih lica. Biblioteke i alati navedeni
ispod **nisu deo ovog repozitorijuma**: preuzimaju se iz svojih zvaničnih izvora (PyPI,
Docker Hub, Alpine, ISC, MSYS2) tek kada ih korisnik instalira ili pokrene laboratoriju, i
svaki se koristi pod svojom licencom, bez izmena.

Licence Python paketa proverene su iz metapodataka paketa za navedene verzije. Novije verzije
mogu imati drugačije uslove, pa je pri ažuriranju potrebno ponovo proveriti licencu.

## 1. Python biblioteke koje program koristi (`pyproject.toml`)

| Komponenta | Proverena verzija | Licenca | Uloga | Izvor |
|---|---|---|---|---|
| dnspython | 2.9.2 | ISC | DNS poruke, zapisi, DNSSEC potpisi, AXFR | https://www.dnspython.org |
| cryptography | 50.0.2 | Apache-2.0 ili BSD-3-Clause (po izboru) | generisanje i potpisivanje ključeva u labu | https://cryptography.io |
| PyYAML | 6.0.3 | MIT | čitanje i pisanje YAML planova | https://pyyaml.org |
| zstandard (opciono, `[real]`) | 0.25.0 | BSD-3-Clause | raspakivanje MSYS2 paketa u `scripts/fetch_resolvers.py` | https://github.com/indygreg/python-zstandard |
| pytest (opciono, `[test]`) | 9.2.0 | MIT | pokretanje testova | https://pytest.org |
| setuptools (samo za instalaciju) | 84.2.1 | MIT | izgradnja paketa | https://github.com/pypa/setuptools |

Zavisnosti koje ovi paketi sami povlače:

| Komponenta | Proverena verzija | Licenca | Povlači je |
|---|---|---|---|
| cffi | 2.1.1 | MIT-0 | cryptography |
| pycparser | 3.12 | BSD-3-Clause | cffi |
| OpenSSL (ugrađen u wheel) | uz cryptography | Apache-2.0 | cryptography |
| iniconfig | 2.3.1 | MIT | pytest |
| packaging | 26.3 | Apache-2.0 ili BSD-2-Clause | pytest |
| pluggy | 1.7.0 | MIT | pytest |
| Pygments | 2.21.0 | BSD-2-Clause | pytest |
| colorama (samo Windows) | 0.4.6 | BSD-3-Clause | pytest |

## 2. Alati koje laboratorija preuzima i pokreće

Ovi programi se ne nalaze u repozitorijumu i program ih ne menja; Dockerfile-ovi i skripta
ih samo instaliraju iz zvaničnih izvora.

| Komponenta | Kako se dobija | Licenca |
|---|---|---|
| Python (slika `python:3.12-slim`) | Docker Hub, `lab/docker/Dockerfile` | PSF-2.0 (Python); Debian paketi pod svojim licencama |
| Alpine Linux 3.20 (bazna slika) | Docker Hub, `Dockerfile.bind`, `Dockerfile.unbound` | paketi pod svojim licencama |
| BIND 9 | Alpine paket; za Windows ISC build 9.16.50 preko `scripts/fetch_resolvers.py` | MPL-2.0 |
| Unbound | Alpine paket; za Windows MSYS2 paket preko `scripts/fetch_resolvers.py` | BSD-3-Clause |
| OpenSSL, expat, ldns, libevent, libwinpthread | MSYS2 paketi koje Unbound na Windows-u zahteva | Apache-2.0; MIT; BSD-3-Clause; BSD-3-Clause; MIT i ZPL-2.1 |
| gcc-libs (runtime DLL) | MSYS2 paket koji Unbound na Windows-u zahteva | GPL-3.0-or-later sa GCC Runtime Library Exception 3.1 |

## 3. Podaci i standardi

- U `flightcheck/plan.py` dve vrednosti trajanja keširanja greške (60 s za Unbound, 30 s i
  1 s za BIND) preuzete su kao činjenice iz izvornog koda tih resolvera, što je navedeno u
  komentaru. Kod resolvera nije kopiran.
- Pravila za rollover ključeva prate javne IETF standarde (RFC 4033–4035, RFC 6781,
  RFC 7583). Program implementira opisana pravila sopstvenim kodom.

## 4. Obaveze iz licenci

Projekat poštuje uslove gornjih licenci na sledeći način:

- **MIT, MIT-0, ISC, BSD-2-Clause, BSD-3-Clause, PSF-2.0, ZPL-2.1:** dozvoljavaju korišćenje,
  izmene i dalju distribuciju, i komercijalnu. Ko distribuira kopiju komponente (na primer u
  izgrađenoj Docker slici ili zapakovanoj instalaciji), mora da zadrži njenu napomenu o
  autorskim pravima i tekst licence. BSD-3-Clause ne dozvoljava korišćenje imena autora
  komponente za promociju bez njihove dozvole.
- **Apache-2.0:** isto kao gore, uz zadržavanje datoteke `NOTICE` ako postoji i označavanje
  izmenjenih datoteka. Licenca uključuje i patentnu licencu.
- **MPL-2.0 (BIND):** ako se izmene sami izvorni fajlovi BIND-a, te izmene moraju biti
  dostupne pod MPL-2.0. Ovaj projekat BIND ne menja, samo ga pokreće sa generisanom
  konfiguracijom.
- **GPL-3.0 sa GCC Runtime Library Exception:** izuzetak dozvoljava da se programi koji
  koriste ove runtime biblioteke distribuiraju pod bilo kojom licencom. Projekat ove DLL
  datoteke ne distribuira; skripta ih preuzima lokalno.

Licencni fajlovi Python paketa nalaze se uz svaki instalirani paket (`*.dist-info/`), pa se
automatski nalaze i u Docker slici koja se izgradi iz `lab/docker/Dockerfile`.

Ovaj spisak je pripremljen na osnovu metapodataka paketa i nije pravni savet. Pri
komercijalnoj distribuciji preporučuje se da se licence ponovo provere za verzije koje se
zaista isporučuju.

---

*English summary:* DNSSEC FlightCheck contains no copied third-party source code. The
libraries and tools above are not included in this repository; they are installed from their
official sources and used unmodified under their own licenses (ISC, MIT, MIT-0, BSD-2/3-Clause,
Apache-2.0, PSF-2.0, MPL-2.0, ZPL-2.1, and GPL-3.0 with the GCC Runtime Library Exception for
Windows runtime DLLs that are downloaded locally and not redistributed). Anyone who
redistributes a component must keep its copyright notice and license text.
