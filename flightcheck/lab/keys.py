"""Key generation for the lab."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import dns.dnssec
import dns.name
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

KSK_FLAGS = 257  # zone key + secure entry point
ZSK_FLAGS = 256  # zone key


@dataclass
class LabKey:
    name: str
    algorithm: int
    flags: int
    private: object
    dnskey: object  # dns.rdtypes.ANY.DNSKEY.DNSKEY

    @property
    def tag(self) -> int:
        return dns.dnssec.key_id(self.dnskey)

    def ds(self, owner: dns.name.Name):
        return dns.dnssec.make_ds(owner, self.dnskey, "SHA256")


def _private_key(algorithm: int):
    if algorithm in (5, 7, 8, 10):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if algorithm == 13:
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == 14:
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm == 15:
        return ed25519.Ed25519PrivateKey.generate()
    if algorithm == 16:
        return ed448.Ed448PrivateKey.generate()
    raise ValueError(f"the lab cannot generate keys for algorithm {algorithm}")


def generate_key(name: str, algorithm: int, ksk: bool) -> LabKey:
    private = _private_key(algorithm)
    flags = KSK_FLAGS if ksk else ZSK_FLAGS
    dnskey = dns.dnssec.make_dnskey(private.public_key(), algorithm, flags=flags)
    return LabKey(name, algorithm, flags, private, dnskey)


def save_keys(keys: dict[str, LabKey], directory: Path) -> None:
    """Write keys as PKCS#8 PEM files plus an index, so several lab processes can share them."""
    directory.mkdir(parents=True, exist_ok=True)
    index = {}
    for name, key in keys.items():
        pem = key.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        (directory / f"{name}.pem").write_bytes(pem)
        index[name] = {"algorithm": key.algorithm, "flags": key.flags}
    (directory / "keys.json").write_text(json.dumps(index, indent=2), encoding="utf-8")


def load_keys(directory: Path) -> dict[str, LabKey]:
    index = json.loads((directory / "keys.json").read_text(encoding="utf-8"))
    keys = {}
    for name, meta in index.items():
        private = serialization.load_pem_private_key((directory / f"{name}.pem").read_bytes(), password=None)
        dnskey = dns.dnssec.make_dnskey(private.public_key(), meta["algorithm"], flags=meta["flags"])
        keys[name] = LabKey(name, meta["algorithm"], meta["flags"], private, dnskey)
    return keys
