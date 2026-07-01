"""The Decision — the kernel's sole output, conforming to contracts-spec.

Only the kernel constructs these. Each is emitted together with a kernel
signature (see authority.py); consumers verify before acting on it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .authority import KERNEL_IDENTITY


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    LIMIT = "LIMIT"
    CONTAIN = "CONTAIN"
    DEFER = "DEFER"


# Verdicts under which the kernel mints a capability token (the effect may run).
PERMITTING = {Verdict.ALLOW, Verdict.LIMIT, Verdict.CONTAIN}


@dataclass(frozen=True)
class Decision:
    """A kernel ruling on one action. Serializes to the contracts-spec
    `decision` schema via `to_dict()`."""

    verdict: Verdict
    reason: str
    action_ref: str
    obligations: tuple[str, ...] = ()
    transformed_payload: dict[str, Any] | None = None
    containment: dict[str, Any] | None = None
    issued_by: str = KERNEL_IDENTITY
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "verdict": self.verdict.value,
            "reason": self.reason,
            "action_ref": self.action_ref,
            "issued_by": self.issued_by,
            "obligations": list(self.obligations),
            "transformed_payload": self.transformed_payload,
            "timestamp": self.timestamp,
        }
        if self.containment is not None:
            out["containment"] = self.containment
        return out
