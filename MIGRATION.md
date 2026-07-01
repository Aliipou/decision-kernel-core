# AuthGate → decision-kernel-core migration plan

The kernel here is intentionally **minimal but real**: capability check, purpose
binding, redaction→LIMIT, threat→CONTAIN, ALLOW, each emitted as a signed
Decision with a minted token. The existing `authgate-gate` already has the
hardened, battle-tested versions of most of this. Migration folds AuthGate's
enforcement in *behind the same contract*, incrementally, without regressing.

## Principle

The kernel's **contract** (signed Decision + token, deterministic verdicts) is
frozen. AuthGate logic migrates in as the *implementation* behind it — consumers
never see the change.

## Slices (in order, each independently shippable)

1. **Capability layer.** Replace the kernel's `_has_capability` with AuthGate's
   `CapabilityRegistry`/`CapabilityLayer` (normalized capabilities, wildcard
   handling). *Boundary:* still returns a `Verdict`.
2. **Purpose policy.** Replace the inline purpose-binding with AuthGate's
   `PolicyEngine` — including the recursive + content-based redaction (the deep
   `meta.ssn`/alias/echo scrub and the sensitive-pattern content screen), so
   `LIMIT` matches AuthGate's hardened minimization rather than the slim
   top-level redact here.
3. **Runtime/temporal layer.** Bring in AuthGate's `RuntimeMonitor`/`RuntimeLayer`
   (per-session budget/step/nonce with the concurrency lock fix) so the kernel
   also rules on trajectories, not just single actions. Session state keyed by
   the normalized `session_id`.
4. **Audit.** Emit each signed Decision to the `audit-ledger` (hash-chained,
   append-only) and anchor the head to the notary (out-of-process tamper
   evidence). AuthGate's `HashChainedAudit` + `notary` move here/there.
5. **Threat input.** Wire `fdk-research`'s advisory `threat_assessment` events as
   the `threat_class` input to `CONTAIN` — advisory only; the kernel decides.

## Non-negotiables during migration

- The kernel keeps importing **only** contracts + stdlib + `cryptography` (rule A;
  enforced by `tests/test_boundaries.py`). No research/agent imports ever.
- Every emitted Decision stays **signed** and schema-conforming (runtime rule B).
- Determinism is preserved: no ML enters the decision path; FDK stays advisory.
