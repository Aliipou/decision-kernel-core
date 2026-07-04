"""Drift guard: the schemas vendored here must stay identical to the canonical
decision-os-contracts package.

decision-kernel-core vendors a copy of the contract schemas under `contracts/`
(so the kernel can validate its own output without importing the package at
runtime). That duplication is a dual source of truth — and dual truths drift.
This test fails the moment the vendored copy diverges from the installed
canonical schema, forcing a deliberate re-sync instead of a silent fork.
"""

from __future__ import annotations

import json
from pathlib import Path

import decision_os_contracts as contracts
import pytest

_VENDORED = Path(__file__).resolve().parent.parent / "contracts"
_SCHEMAS = ["decision", "capability_token", "action"]


@pytest.mark.parametrize("name", _SCHEMAS)
def test_vendored_schema_matches_canonical(name: str) -> None:
    vendored = json.loads((_VENDORED / f"{name}.schema.json").read_text(encoding="utf-8"))
    canonical = contracts.load_schema(name)
    assert vendored == canonical, (
        f"vendored contracts/{name}.schema.json has DRIFTED from decision-os-contracts "
        f"{contracts.__version__}. Re-sync it (copy the canonical schema over the "
        f"vendored copy) rather than letting the two diverge."
    )


def test_vendored_contracts_version_matches_package() -> None:
    vendored_version = (_VENDORED / "CONTRACTS_VERSION").read_text(encoding="utf-8").strip()
    assert vendored_version == contracts.__version__, (
        f"contracts/CONTRACTS_VERSION ({vendored_version}) != decision-os-contracts "
        f"({contracts.__version__}); bump the vendored marker when re-syncing schemas."
    )
