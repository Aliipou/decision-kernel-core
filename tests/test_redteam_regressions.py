"""Regression tests adapted from the red-team PoCs (poc9 A/B + W-2) for the
kernel core: durable cross-instance token spend (HB-1), nonce/action_ref folded
into the fingerprint (W-1), and strict payload encoding (W-2)."""

from __future__ import annotations

import pytest

from kernel import (
    FileSpentStore,
    InMemorySpentStore,
    KernelAuthority,
    SpentStore,
    SpentStoreUnavailable,
    TokenStore,
    UnfingerprintablePayload,
    action_fingerprint,
    mint_token,
)


def _mint(a: KernelAuthority, binding: str = "fp-1") -> dict:
    return mint_token(
        a,
        actor="agent:x",
        capability="tool:send",
        action_ref="n-1",
        action_binding=binding,
    )


def _spend(store: TokenStore, tok: dict, pub: str):
    return store.verify_and_spend(
        tok,
        kernel_public_key_hex=pub,
        expected_action_ref="n-1",
        expected_capability="tool:send",
        expected_action_binding="fp-1",
    )


# --- HB-1: cross-instance token double-spend (poc9 A) -----------------------
def test_hb1_cross_instance_replay_rejected(tmp_path):
    """A second TokenStore backed by the SAME durable store must reject a token
    already spent by the first store instance."""
    store = FileSpentStore(tmp_path / "spent")
    a = KernelAuthority.generate()
    pub = a.public_key_hex()
    tok = _mint(a)

    ts1 = TokenStore(spent_store=store)
    ts2 = TokenStore(spent_store=store)  # a second worker/replica/process
    ok1, _ = _spend(ts1, tok, pub)
    ok2, why2 = _spend(ts2, tok, pub)
    assert ok1 is True
    assert ok2 is False and "spent" in why2


def test_hb1_fails_closed_when_store_unreachable():
    class BrokenStore:
        def try_spend(self, token_id: str) -> bool:
            raise SpentStoreUnavailable("simulated outage")

    a = KernelAuthority.generate()
    tok = _mint(a)
    ts = TokenStore(spent_store=BrokenStore())
    ok, why = _spend(ts, tok, a.public_key_hex())
    assert ok is False and "fail-closed" in why


def test_hb1_inmemory_is_explicit_optin():
    assert isinstance(InMemorySpentStore(), SpentStore)
    a = KernelAuthority.generate()
    tok = _mint(a)
    ts = TokenStore(spent_store=InMemorySpentStore())
    ok, _ = _spend(ts, tok, a.public_key_hex())
    assert ok is True


# --- W-1: nonce/action_ref bound (poc9 B) -----------------------------------
def test_w1_nonce_folded_into_fingerprint():
    authorized = {"actor": "agent:a", "capability": "tool:pay",
                  "payload": {"amount": 100}, "nonce": "n1", "action_ref": "REQ-1"}
    attacker = {"actor": "agent:a", "capability": "tool:pay",
                "payload": {"amount": 100}, "nonce": "DIFFERENT", "action_ref": "REQ-X"}
    assert action_fingerprint(authorized) != action_fingerprint(attacker)


# --- W-2: default=str collision closed --------------------------------------
def test_w2_object_string_collision_rejected():
    class Weird:
        def __str__(self) -> str:
            return "100"

    base = {"actor": "agent:a", "capability": "tool:pay"}
    with pytest.raises(UnfingerprintablePayload):
        action_fingerprint({**base, "payload": {"x": Weird()}})
    # the plain string still fingerprints fine
    assert isinstance(action_fingerprint({**base, "payload": {"x": "100"}}), str)
