"""Core data contracts for modelseal.

stdlib only. No network imports anywhere in this module or its package siblings
under ``core`` / ``packs.scanners`` (enforced by tests/test_no_network_in_core.py).
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


class Severity(enum.IntEnum):
    """Ordered severity. Higher = worse. IntEnum so max() / comparison is trivial."""

    INFO = 0
    WARN = 1
    FAIL = 2

    @property
    def label(self) -> str:
        return self.name


# Report-level verdict derived deterministically from the worst Finding severity.
_VERDICT_BY_SEVERITY = {
    Severity.INFO: "PASS",
    Severity.WARN: "WARN",
    Severity.FAIL: "FAIL",
}


@dataclass(frozen=True)
class Finding:
    """A single detection result. ``rule_id`` is stable across versions (AC-26)."""

    rule_id: str
    severity: Severity
    location: str
    message: str


@dataclass(frozen=True)
class Provenance:
    """Provenance record for one artifact.

    hash_verified: None means no expected hash was supplied -> surfaced as WARN
    (AC-13: never an implicit PASS). True/False means a checksum comparison ran.
    """

    path: str
    sha256: str
    size: int
    fmt: str
    source_meta: dict = field(default_factory=dict)
    hash_verified: bool | None = None


@dataclass
class Report:
    """Aggregate of one scan run.

    verdict is computed from findings only; explanation (optional LLM layer)
    never influences verdict / severity / exit code (AC-22).
    """

    findings: list[Finding] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    explanation: str | None = None

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def verdict(self) -> str:
        return _VERDICT_BY_SEVERITY[self.max_severity]

    @property
    def exit_code(self) -> int:
        """PASS=0, WARN=1, FAIL=2 (AC-2, CI gate)."""
        return int(self.max_severity)


class Scanner(ABC):
    """Format-specific inspector. Selected by content, not extension (AC-9)."""

    #: short identifier used in rule_id prefixes and diagnostics
    name: str = "scanner"

    @abstractmethod
    def sniff(self, header: bytes, path: Path) -> bool:
        """Return True if this scanner claims the artifact based on its content."""

    @abstractmethod
    def scan(self, path: Path) -> list[Finding]:
        """Inspect the artifact statically (never load/execute it) and return findings."""


class Provider(ABC):
    """Optional explanation-layer LLM abstraction. Never affects verdict (AC-22)."""

    @abstractmethod
    def explain(self, findings: list[Finding]) -> str:
        """Return a plain-language explanation / remediation draft for the findings."""


class MockProvider(Provider):
    """Deterministic provider for tests / LLM-absent environments (AC-24)."""

    def explain(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings to explain."
        lines = [f"- [{f.severity.label}] {f.rule_id}: {f.message}" for f in findings]
        return "Mock explanation:\n" + "\n".join(lines)
