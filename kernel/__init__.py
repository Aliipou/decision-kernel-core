"""decision-kernel-core — the sole decision authority of the Decision OS.

Deterministic. Imports only stdlib + cryptography + the vendored contracts. Emits
signed Decisions and mints signed, one-time capability tokens. The runtime root
of the single-authority rule.
"""

from .authority import KERNEL_IDENTITY, KernelAuthority, verify, verify_authority
from .decision import PERMITTING, Decision, Verdict
from .engine import Kernel
from .token import TokenStore, mint_token

__all__ = [
    "KERNEL_IDENTITY",
    "KernelAuthority",
    "verify",
    "verify_authority",
    "Decision",
    "Verdict",
    "PERMITTING",
    "Kernel",
    "mint_token",
    "TokenStore",
]
