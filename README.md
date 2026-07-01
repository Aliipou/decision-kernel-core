# decision-kernel-core — the sole decision authority

The Decision OS kernel. Where the contract rules become **runtime reality**.

- **Deterministic.** The same `(policy, action, threat_class)` always yields the
  same verdict. No ML in the decision path.
- **Single authority, cryptographically grounded.** The kernel holds an Ed25519
  private key no other component has. Every `Decision` and `CapabilityToken` is
  signed. Consumers verify with the public key and reject anything whose
  `issued_by` is not the kernel or whose signature fails — so authority is
  *possession of a key*, not a convention a static check hopes holds.
- **Mandatory mediation.** A permitting verdict mints a one-time, expiring,
  signed capability token bound to one action. The executor verifies-and-spends
  it; a caller that bypasses the kernel cannot execute, because it cannot mint a
  token the kernel would have signed.
- **Minimal dependencies.** stdlib + `cryptography` + the vendored contracts.
  Nothing from research/agent/control layers (enforced by `tests/test_boundaries`).

## Verdicts

`ALLOW` · `DENY` · `LIMIT` (minimized) · `CONTAIN` (sandboxed — the defensive
response to a suspected-malicious actor) · `DEFER`. Conforms to
`contracts-spec` (vendored under `contracts/`, pinned to `CONTRACTS_VERSION`).

## Shape

```
kernel/
  authority.py   # Ed25519 sign/verify; verify_authority = runtime rule B
  decision.py    # Decision -> contract-conforming dict
  token.py       # capability-token lifecycle (mint / verify / spend once)
  engine.py      # deterministic engine + Kernel facade (decide -> signed decision + token)
contracts/       # vendored, pinned contracts-spec schemas
tests/           # authority, tokens, engine (all 5 verdicts), contract conformance, rule A
```

## Use

```python
from kernel import Kernel, KernelAuthority

k = Kernel(KernelAuthority.load_or_generate("kernel_key.pem"), policy)
result = k.decide(action, threat_class="malicious")   # advisory threat from fdk-research
# result = {"decision": {...signed...}, "signature": "...", "token": {...} | None}
```

## Honest limit

An attacker who compromises the kernel **process** can read the signing key. Beyond
that is the hardware root-of-trust tier (TPM/HSM) — a deployment concern. Static
rule-B (contracts-spec/conformance) + this runtime rule-B are defense in depth;
neither alone is total.
