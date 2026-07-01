from __future__ import annotations

from kernel.authority import KERNEL_IDENTITY, KernelAuthority, verify, verify_authority


def test_sign_verify_roundtrip() -> None:
    a = KernelAuthority.generate()
    obj = {"issued_by": KERNEL_IDENTITY, "x": 1}
    sig = a.sign(obj)
    assert verify(obj, sig, a.public_key_hex())


def test_wrong_key_fails() -> None:
    a, b = KernelAuthority.generate(), KernelAuthority.generate()
    obj = {"issued_by": KERNEL_IDENTITY}
    assert not verify(obj, a.sign(obj), b.public_key_hex())


def test_tamper_fails() -> None:
    a = KernelAuthority.generate()
    obj = {"issued_by": KERNEL_IDENTITY, "verdict": "ALLOW"}
    sig = a.sign(obj)
    assert not verify({**obj, "verdict": "DENY"}, sig, a.public_key_hex())


def test_signature_field_excluded_from_canonical() -> None:
    a = KernelAuthority.generate()
    obj = {"issued_by": KERNEL_IDENTITY, "x": 1}
    sig = a.sign(obj)
    assert verify({**obj, "signature": sig}, sig, a.public_key_hex())


def test_verify_authority_rejects_non_kernel_issuer() -> None:
    a = KernelAuthority.generate()
    obj = {"issued_by": "agent-runtime"}  # valid signature, wrong authority
    assert not verify_authority(obj, a.sign(obj), a.public_key_hex())


def test_verify_authority_accepts_kernel() -> None:
    a = KernelAuthority.generate()
    obj = {"issued_by": KERNEL_IDENTITY, "verdict": "ALLOW"}
    assert verify_authority(obj, a.sign(obj), a.public_key_hex())
