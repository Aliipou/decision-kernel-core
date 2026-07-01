"""The kernel's output must conform to contracts-spec, and the runtime
single-authority rule must actually reject a forged decision.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from kernel import Kernel, KernelAuthority, verify_authority

_CONTRACTS = Path(__file__).resolve().parent.parent / "contracts"

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(json.loads((_CONTRACTS / f"{name}.schema.json").read_text(encoding="utf-8")))


def _action(**kw: Any) -> dict[str, Any]:
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {"ssn": "123-45-6789"},
        "capability": "tool:send_email",
        "nonce": "n-1",
    }
    base.update(kw)
    return base


def test_every_verdict_conforms_to_decision_schema() -> None:
    k = Kernel(KernelAuthority.generate(), POLICY)
    dval = _validator("decision")
    tval = _validator("capability_token")
    cases = [
        k.decide(_action(actor="agent:evil")),          # DENY
        k.decide(_action(payload={})),                  # ALLOW
        k.decide(_action()),                            # LIMIT (ssn)
        k.decide(_action(), threat_class="malicious"),  # CONTAIN
    ]
    for r in cases:
        dval.validate(r["decision"])
        if r["token"] is not None:
            tval.validate(r["token"])


def test_runtime_rule_b_rejects_forged_decision() -> None:
    k = Kernel(KernelAuthority.generate(), POLICY)
    pub = k.public_key_hex()

    genuine = k.decide(_action(payload={}))
    assert verify_authority(genuine["decision"], genuine["signature"], pub)  # real kernel ALLOW accepted

    # A non-kernel component fabricates an ALLOW it never had authority to make.
    forged = {
        "verdict": "ALLOW",
        "reason": "i say so",
        "action_ref": "n-9",
        "issued_by": "agent-runtime",
        "obligations": [],
        "transformed_payload": None,
        "timestamp": "2026-07-01T00:00:00Z",
    }
    assert not verify_authority(forged, "00" * 64, pub)                 # wrong issuer + bad sig
    assert not verify_authority({**forged, "issued_by": "decision-kernel-core"}, "00" * 64, pub)  # claim kernel, but can't sign
