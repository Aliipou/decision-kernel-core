from __future__ import annotations

from kernel import KernelAuthority, TokenStore, mint_token


def _mint(a: KernelAuthority, ttl: float = 30.0) -> dict:
    return mint_token(a, actor="agent:x", capability="tool:send", action_ref="n-1", ttl_seconds=ttl)


def _spend(store: TokenStore, tok: dict, pub: str, ref: str = "n-1", cap: str = "tool:send"):
    return store.verify_and_spend(tok, kernel_public_key_hex=pub, expected_action_ref=ref, expected_capability=cap)


def test_verify_and_spend_once() -> None:
    a = KernelAuthority.generate()
    store = TokenStore()
    tok = _mint(a)
    ok, why = _spend(store, tok, a.public_key_hex())
    assert ok, why
    ok2, why2 = _spend(store, tok, a.public_key_hex())
    assert not ok2 and "spent" in why2  # single-use


def test_wrong_action_ref_rejected() -> None:
    a = KernelAuthority.generate()
    ok, why = _spend(TokenStore(), _mint(a), a.public_key_hex(), ref="n-2")
    assert not ok and "action_ref" in why


def test_wrong_capability_rejected() -> None:
    a = KernelAuthority.generate()
    ok, why = _spend(TokenStore(), _mint(a), a.public_key_hex(), cap="tool:other")
    assert not ok and "capability" in why


def test_bad_signature_rejected() -> None:
    a = KernelAuthority.generate()
    tok = _mint(a)
    tok["signature"] = "00" * 64
    ok, why = _spend(TokenStore(), tok, a.public_key_hex())
    assert not ok and "signature" in why


def test_expired_rejected() -> None:
    a = KernelAuthority.generate()
    ok, why = _spend(TokenStore(), _mint(a, ttl=-1), a.public_key_hex())
    assert not ok and "expired" in why


def test_forged_issuer_rejected() -> None:
    # An attacker mints with their OWN key and claims the kernel identity.
    attacker = KernelAuthority.generate()
    kernel = KernelAuthority.generate()
    tok = _mint(attacker)  # already claims KERNEL_IDENTITY via mint_token
    ok, why = _spend(TokenStore(), tok, kernel.public_key_hex())
    assert not ok and "signature" in why  # not signed by the real kernel key
