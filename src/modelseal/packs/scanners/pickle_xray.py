"""Pickle x-ray: static, non-executing opcode analysis (AC-3, AC-5).

Walks the pickle opcode stream with stdlib ``pickletools.genops`` — the artifact
is never unpickled / executed. Concrete signatures live in ``rules.py`` (§5).
"""

from __future__ import annotations

import io
import pickletools
from pathlib import Path

from modelseal.core.contracts import Finding, Scanner, Severity
from modelseal.packs.scanners import rules

# File suffixes commonly holding a bare pickle stream (not a zip container).
_PICKLE_SUFFIXES = {".pkl", ".pickle", ".bin", ".pt", ".pth", ".ckpt", ".npy", ".joblib", ".dat"}

# A pickle stream in protocol 2+ starts with the PROTO opcode byte.
_PROTO_BYTE = 0x80
_SEVERITY = {1: Severity.WARN, 2: Severity.FAIL}


def looks_like_pickle(header: bytes, path: Path) -> bool:
    if header[:1] == bytes([_PROTO_BYTE]):
        return True
    return path.suffix.lower() in _PICKLE_SUFFIXES


def scan_pickle_stream(data: bytes, location: str) -> list[Finding]:
    """Inspect one pickle byte stream. Reused for nested archive members."""
    findings: list[Finding] = []
    recent_strings: list[str] = []
    saw_reconstruct = False
    imports_seen: list[tuple[str, str]] = []

    for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
        name = opcode.name
        loc = f"{location}@{pos}"

        if name in rules.RECONSTRUCT_OPCODES:
            saw_reconstruct = True

        if name == "GLOBAL" and isinstance(arg, str):
            module, _, attr = arg.partition(" ")
            imports_seen.append((module, attr))
            _flag_import(findings, module, attr, loc)
        elif name == "STACK_GLOBAL":
            # module/attr were pushed as the two preceding string opcodes.
            if len(recent_strings) >= 2:
                module, attr = recent_strings[-2], recent_strings[-1]
                imports_seen.append((module, attr))
                _flag_import(findings, module, attr, loc)
        elif isinstance(arg, str):
            recent_strings.append(arg)
            if len(recent_strings) > 8:
                recent_strings.pop(0)

    # Object reconstruction combined with an unclassified external import is the
    # generic shape behind code execution; surface as WARN even when no denylist
    # pair matched (conservative, ADR-0004).
    if saw_reconstruct and imports_seen and not findings:
        findings.append(
            Finding(
                "MS-PICKLE-RECONSTRUCT",
                Severity.WARN,
                location,
                "object reconstruction references external symbols; review provenance",
            )
        )
    return findings


def _flag_import(findings: list[Finding], module: str, attr: str, loc: str) -> None:
    verdict = rules.classify_import(module, attr)
    if verdict is None:
        return
    reason, sev = verdict
    findings.append(
        Finding("MS-PICKLE-DANGEROUS-IMPORT", _SEVERITY[sev], loc, reason)
    )


class PickleScanner(Scanner):
    name = "pickle"

    def sniff(self, header: bytes, path: Path) -> bool:
        return looks_like_pickle(header, path)

    def scan(self, path: Path) -> list[Finding]:
        data = path.read_bytes()
        return scan_pickle_stream(data, str(path))
