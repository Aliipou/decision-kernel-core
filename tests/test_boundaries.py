"""Rule A, enforced on the kernel itself (self-contained).

The canonical checker lives in contracts-spec/conformance; here we assert the
same invariant directly so the kernel's own CI is green and honest without a
cross-repo dependency: kernel/ imports no research/agent/control layer and uses
no dynamic-import escape hatch.
"""

from __future__ import annotations

import ast
from pathlib import Path

_KERNEL = Path(__file__).resolve().parent.parent / "kernel"
_FORBIDDEN = {"research", "fdk_research", "agent_runtime", "control_plane", "sklearn", "torch", "tensorflow"}
_DYNAMIC = {"__import__", "import_module"}


def _modules(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


def test_kernel_imports_no_forbidden_layer() -> None:
    bad = []
    for py in _KERNEL.rglob("*.py"):
        for mod in _modules(ast.parse(py.read_text(encoding="utf-8"))):
            if mod in _FORBIDDEN or mod.split(".")[0] in _FORBIDDEN:
                bad.append(f"{py.name}: {mod}")
    assert not bad, bad


def test_kernel_has_no_dynamic_imports() -> None:
    bad = []
    for py in _KERNEL.rglob("*.py"):
        for node in ast.walk(ast.parse(py.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                f = node.func
                name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
                if name in _DYNAMIC:
                    bad.append(f"{py.name}:{node.lineno}")
    assert not bad, bad
