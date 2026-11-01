"""Download real Unbound and BIND Windows builds into tools/ (no installation, no admin rights).

    .venv\\Scripts\\python scripts\\fetch_resolvers.py

BIND comes from ISC (9.16 is the last release with Windows builds and is end of life, so use it
only inside this lab). Unbound comes from the MSYS2 UCRT64 package repository, together with the
DLLs it needs.
"""

from __future__ import annotations

import hashlib
import re
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import zstandard

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
DOWNLOADS = TOOLS / "downloads"
BIND_URL = "https://downloads.isc.org/isc/bind9/9.16.50/BIND9.16.50.x64.zip"
MIRROR = "https://mirror.msys2.org/mingw/ucrt64/"
UNBOUND_PACKAGES = ["unbound", "openssl", "expat", "ldns", "libwinpthread", "gcc-libs", "libevent"]


def fetch(url: str, target: Path) -> None:
    if target.exists():
        print(f"have {target.name}")
    else:
        print(f"download {url}")
        request = urllib.request.Request(url, headers={"User-Agent": "flightcheck-lab"})
        with urllib.request.urlopen(request, timeout=120) as response:
            target.write_bytes(response.read())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"  {target.stat().st_size:>10,} bytes  sha256 {digest}")


def latest_packages(listing: str) -> dict[str, str]:
    chosen = {}
    for name in UNBOUND_PACKAGES:
        pattern = rf'mingw-w64-ucrt-x86_64-{re.escape(name)}-(\d[^"<>/]*)-any\.pkg\.tar\.zst(?!\.sig)'
        matches = sorted(set(re.findall(pattern, listing)), key=_version_key)
        if not matches:
            raise SystemExit(f"package not found on the mirror: {name}")
        chosen[name] = f"mingw-w64-ucrt-x86_64-{name}-{matches[-1]}-any.pkg.tar.zst"
    return chosen


def _version_key(text: str):
    return [int(part) if part.isdigit() else 0 for part in re.split(r"[.\-+_~]", text)]


def extract_zst(package: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    with package.open("rb") as raw:
        with zstandard.ZstdDecompressor().stream_reader(raw) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as archive:
                archive.extractall(target, filter="data")


def main() -> int:
    DOWNLOADS.mkdir(parents=True, exist_ok=True)

    bind_zip = DOWNLOADS / BIND_URL.rsplit("/", 1)[1]
    fetch(BIND_URL, bind_zip)
    with zipfile.ZipFile(bind_zip) as archive:
        archive.extractall(TOOLS / "bind")

    request = urllib.request.Request(MIRROR, headers={"User-Agent": "flightcheck-lab"})
    with urllib.request.urlopen(request, timeout=120) as response:
        listing = response.read().decode("utf-8", "replace")
    for filename in latest_packages(listing).values():
        package = DOWNLOADS / filename
        fetch(MIRROR + filename, package)
        extract_zst(package, TOOLS / "unbound")
    print(f"BIND:    {TOOLS / 'bind' / 'named.exe'}")
    print(f"Unbound: {TOOLS / 'unbound' / 'ucrt64' / 'bin' / 'unbound.exe'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
