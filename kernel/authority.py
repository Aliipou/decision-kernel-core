"""Cryptographic authority — the runtime root of rule B (single authority).

The static conformance checker (contracts-spec/conformance) proves no NON-kernel
*source* constructs a Decision. But static analysis can be evaded at runtime. The
non-bypassable complement lives here: the kernel signs every Decision and
CapabilityToken with an Ed25519 private key that exists ONLY inside the kernel
process. Any consumer verifies with the published public key and REJECTS anything
whose `issued_by` is not the kernel identity or whose signature does not check.

So authority is not "a string we trust" — it is possession of a key no other
component holds. That is what makes the kernel the single source of truth at
runtime, not just by convention.

Honest limit: an attacker who compromises the kernel PROCESS can read the key.
Protecting it beyond that is the hardware root-of-trust tier (TPM/HSM) — a
deployment concern, not this module. Same boundary the audit notary documents.

Depends on `cryptography` (Ed25519).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KERNEL_IDENTITY = "decision-kernel-core"


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Deterministic bytes for signing/verifying: sorted keys, no whitespace,
    excluding any `signature` field already present."""
    payload = {k: v for k, v in obj.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class KernelAuthority:
    """Holds the kernel's signing key. Constructed once, inside the kernel."""

    identity = KERNEL_IDENTITY

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self._pub_hex = private_key.public_key().public_bytes_raw().hex()

    @classmethod
    def generate(cls) -> KernelAuthority:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_generate(cls, path: str | Path) -> KernelAuthority:
        p = Path(path)
        if p.exists():
            key = serialization.load_pem_private_key(p.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{p}: not an Ed25519 private key")
            return cls(key)
        auth = cls.generate()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(
            auth._key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        p.with_suffix(p.suffix + ".pub").write_text(auth.public_key_hex(), encoding="utf-8")
        return auth

    def public_key_hex(self) -> str:
        return self._pub_hex

    def sign(self, obj: dict[str, Any]) -> str:
        """Return the hex Ed25519 signature over the canonical form of `obj`."""
        return self._key.sign(canonical_bytes(obj)).hex()


def verify(obj: dict[str, Any], signature_hex: str, public_key_hex: str) -> bool:
    """True iff `signature_hex` is a valid signature over `obj` by `public_key_hex`."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), canonical_bytes(obj))
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_authority(obj: dict[str, Any], signature_hex: str, kernel_public_key_hex: str) -> bool:
    """Runtime rule B: accept `obj` (a Decision or token) ONLY if it claims the
    kernel identity AND carries a valid kernel signature. A forged decision from
    a non-kernel component fails here even if it evaded every static check."""
    if obj.get("issued_by") != KERNEL_IDENTITY:
        return False
    return verify(obj, signature_hex, kernel_public_key_hex)
