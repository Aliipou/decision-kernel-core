"""Capability-token lifecycle — mandatory mediation at runtime.

On a permitting verdict the kernel MINTS a one-time, expiring, kernel-signed
capability token bound to a single action. The executor MUST present it and it is
VERIFIED (signature + expiry + not-already-spent + matching action/capability)
and then SPENT. A caller that bypasses the kernel cannot execute, because it
cannot mint a token the kernel would have signed.

Lifecycle: mint -> verify -> spend (once). A spent or expired token is dead.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from .authority import KERNEL_IDENTITY, KernelAuthority, verify_authority


def mint_token(
    authority: KernelAuthority,
    *,
    actor: str,
    capability: str,
    action_ref: str,
    action_binding: str,
    ttl_seconds: float = 30.0,
) -> dict[str, Any]:
    """Mint a signed, single-use capability token. Returns the token dict with a
    `signature` field (the mechanism a bypassing caller cannot forge).

    `action_binding` is the fingerprint of the security-relevant action content
    (see authority.action_fingerprint). Binding it here means the token authorizes
    THIS action, not merely a (nonce, capability) pair — closing the confused
    deputy where a valid token is re-attached to a different action."""
    token = {
        "token_id": f"tok-{uuid.uuid4().hex[:12]}",
        "actor": actor,
        "capability": capability,
        "action_ref": action_ref,
        "action_binding": action_binding,
        "issued_by": KERNEL_IDENTITY,
        "expires_at": (datetime.now(UTC) + timedelta(seconds=ttl_seconds)).isoformat(),
    }
    token["signature"] = authority.sign(token)
    return token


class TokenStore:
    """Tracks spent token_ids so a token is honored at most once."""

    def __init__(self) -> None:
        self._spent: set[str] = set()

    def verify_and_spend(
        self,
        token: dict[str, Any],
        *,
        kernel_public_key_hex: str,
        expected_action_ref: str,
        expected_capability: str,
        expected_action_binding: str,
    ) -> tuple[bool, str]:
        """Verify a token and consume it. Returns (ok, reason). Fails closed on
        bad signature/identity, expiry, mismatch, or reuse."""
        sig = token.get("signature")
        if not isinstance(sig, str) or not verify_authority(token, sig, kernel_public_key_hex):
            return False, "bad or missing kernel signature"
        if token.get("action_ref") != expected_action_ref:
            return False, "token action_ref does not match the action being executed"
        if token.get("capability") != expected_capability:
            return False, "token capability does not match the effect being executed"
        if token.get("action_binding") != expected_action_binding:
            return False, "token action_binding does not match the action being executed"
        try:
            expires = datetime.fromisoformat(token["expires_at"])
        except (KeyError, ValueError):
            return False, "missing/invalid expires_at"
        if datetime.now(UTC) >= expires:
            return False, "token expired"
        token_id = token.get("token_id")
        if not isinstance(token_id, str):
            return False, "missing token_id"
        if token_id in self._spent:
            return False, "token already spent (replay)"
        self._spent.add(token_id)
        return True, "ok"
