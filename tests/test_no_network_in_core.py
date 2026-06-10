"""Mechanically enforce: core/ and packs/scanners/ never import networking
modules (ADR-0006). The explanation pack is the only allowed network surface."""

from __future__ import annotations

import ast
from pathlib import Path

import modelseal

_FORBIDDEN = {"socket", "urllib", "http", "ftplib", "telnetlib", "asyncio", "requests"}
_PKG_ROOT = Path(modelseal.__file__).parent
_GUARDED_DIRS = [_PKG_ROOT / "core", _PKG_ROOT / "packs" / "scanners"]


def _imported_names(source: str) -> set[str]:
    names: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_no_network_imports_in_guarded_dirs():
    offenders = {}
    for d in _GUARDED_DIRS:
        for py in d.rglob("*.py"):
            bad = _imported_names(py.read_text(encoding="utf-8")) & _FORBIDDEN
            if bad:
                offenders[str(py)] = sorted(bad)
    assert not offenders, f"network imports leaked into guarded code: {offenders}"
