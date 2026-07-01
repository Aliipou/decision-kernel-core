from __future__ import annotations

from typing import Any

from kernel import Kernel, KernelAuthority

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"], "agent:admin": ["*"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def _kernel() -> Kernel:
    return Kernel(KernelAuthority.generate(), POLICY)


def _action(**kw: Any) -> dict[str, Any]:
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {},
        "capability": "tool:send_email",
        "nonce": "n-1",
    }
    base.update(kw)
    return base


def test_deny_without_capability() -> None:
    r = _kernel().decide(_action(actor="agent:evil"))
    assert r["decision"]["verdict"] == "DENY"
    assert r["token"] is None  # no token on a refusal


def test_allow_mints_token() -> None:
    r = _kernel().decide(_action())
    assert r["decision"]["verdict"] == "ALLOW"
    assert r["token"] is not None


def test_limit_redacts_and_mints_token() -> None:
    r = _kernel().decide(_action(payload={"ssn": "123-45-6789", "body": "hi"}))
    assert r["decision"]["verdict"] == "LIMIT"
    assert r["decision"]["transformed_payload"]["ssn"] == "[REDACTED]"
    assert r["token"] is not None


def test_contain_on_malicious_threat() -> None:
    r = _kernel().decide(_action(), threat_class="malicious")
    d = r["decision"]
    assert d["verdict"] == "CONTAIN"
    assert d["containment"]["network"] == "none"
    assert d["containment"]["persistence"] is False
    assert r["token"] is not None  # sandboxed execution still runs, under a token


def test_deny_on_purpose_mismatch() -> None:
    r = _kernel().decide(_action(action_purpose="marketing"))
    assert r["decision"]["verdict"] == "DENY"


def test_deterministic_same_input_same_verdict() -> None:
    k = _kernel()
    a = _action()
    assert k.decide(a)["decision"]["verdict"] == k.decide(a)["decision"]["verdict"]
