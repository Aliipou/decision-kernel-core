"""Minimal deterministic decision engine — the kernel's core logic.

Given an action and a static policy (and an OPTIONAL advisory threat class from
fdk-research), it produces exactly one Decision. Deterministic: the same
(policy, action, threat_class) always yields the same verdict — no ML in the
decision path (see contracts-spec/CONTAINMENT.md). On a permitting verdict the
kernel signs the decision and mints a one-time capability token.

This is the seam AuthGate's full enforcement migrates into (see MIGRATION.md);
the logic here is intentionally slim but real.
"""

from __future__ import annotations

from typing import Any

from .authority import KernelAuthority
from .decision import PERMITTING, Decision, Verdict
from .token import mint_token

# The fixed, policy-level containment profile applied on CONTAIN. Deterministic —
# not tuned by a model at decision time.
_CONTAINMENT = {
    "sandbox": True,
    "network": "none",
    "allowed_tools": [],
    "persistence": False,
    "privilege_escalation": False,
    "time_limit_seconds": 5,
}


def _has_capability(grants: list[str], capability: str) -> bool:
    return "*" in grants or capability in grants


class Kernel:
    """The single decision authority. Holds the signing key and the policy."""

    def __init__(self, authority: KernelAuthority, policy: dict[str, Any]) -> None:
        self._authority = authority
        self._grants: dict[str, list[str]] = policy.get("grants", {})
        self._bindings: dict[str, list[str]] = policy.get("purpose_bindings", {})
        self._redactions: list[dict[str, Any]] = policy.get("redactions", [])
        self._contain_classes: set[str] = set(policy.get("contain_threat_classes", ["malicious"]))
        self._default_deny: bool = policy.get("default", "deny") == "deny"

    def public_key_hex(self) -> str:
        return self._authority.public_key_hex()

    def _evaluate(self, action: dict[str, Any], threat_class: str | None) -> Decision:
        actor = action.get("actor", "")
        ref = action.get("nonce") or action.get("action_ref") or ""
        capability = action.get("capability") or f"tool:{action.get('tool', '')}"

        # 1. Capability: the actor must hold the requested capability.
        if not _has_capability(self._grants.get(actor, []), capability):
            return Decision(Verdict.DENY, f"actor '{actor}' lacks capability '{capability}'", ref)

        # 2. Containment: a suspected-malicious actor (advisory) runs only sandboxed.
        #    Deterministic policy mapping — never an ML choice.
        if threat_class in self._contain_classes:
            return Decision(
                Verdict.CONTAIN,
                f"threat class '{threat_class}' -> internal sandbox containment",
                ref,
                obligations=("sandboxed", "network:none", "no-persistence"),
                containment=dict(_CONTAINMENT),
            )

        # 3. Purpose binding: each data label's purpose must permit this action.
        for label in action.get("data_labels", []):
            allowed = self._bindings.get(label)
            if allowed is None:
                if self._default_deny:
                    return Decision(
                        Verdict.DENY, f"unknown data purpose '{label}' -> default-deny", ref
                    )
                continue
            if action.get("action_purpose") not in allowed:
                return Decision(
                    Verdict.DENY,
                    f"purpose mismatch: '{label}' may not serve '{action.get('action_purpose')}'",
                    ref,
                )

        # 4. Data minimization -> LIMIT.
        payload = dict(action.get("payload", {}))
        for rule in self._redactions:
            if rule.get("action_purpose") != action.get("action_purpose"):
                continue
            hit = [
                f
                for f in rule.get("redact_fields", [])
                if f in payload and payload[f] not in (None, "")
            ]
            if hit:
                for f in hit:
                    payload[f] = "[REDACTED]"
                return Decision(
                    Verdict.LIMIT,
                    f"allowed, but redacted {sorted(hit)}",
                    ref,
                    obligations=tuple(f"redacted:{f}" for f in sorted(hit)),
                    transformed_payload=payload,
                )

        # 5. Otherwise ALLOW.
        return Decision(Verdict.ALLOW, "all checks passed", ref)

    def decide(self, action: dict[str, Any], threat_class: str | None = None) -> dict[str, Any]:
        """Return {decision, signature, token}. `token` is None for non-permitting
        verdicts. The signature is over the decision dict; the token is separately
        signed. Both are verifiable with `public_key_hex()`."""
        decision = self._evaluate(action, threat_class)
        decision_dict = decision.to_dict()
        signature = self._authority.sign(decision_dict)
        token = None
        if decision.verdict in PERMITTING:
            token = mint_token(
                self._authority,
                actor=action.get("actor", ""),
                capability=action.get("capability") or f"tool:{action.get('tool', '')}",
                action_ref=decision.action_ref,
            )
        return {"decision": decision_dict, "signature": signature, "token": token}
