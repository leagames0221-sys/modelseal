"""Scan engine: content-based format detection -> scanner dispatch -> fail-closed aggregation.

stdlib only. The engine never imports ``packs`` (dependency points one way);
scanners are injected. A top-level registry assembles the default set.
"""

from __future__ import annotations

from pathlib import Path

from modelseal.core.contracts import Finding, Provenance, Report, Scanner, Severity
from modelseal.core.provenance import build_provenance

# Bytes read from the head of each artifact for content-based sniffing (AC-9).
_HEADER_BYTES = 4096

# Rule emitted when an artifact cannot be parsed at all -> fail-closed (AC-8).
RULE_UNPARSEABLE = "MS-UNPARSEABLE"
# Rule emitted when no scanner claims the artifact (unknown format).
RULE_UNKNOWN_FORMAT = "MS-UNKNOWN-FORMAT"


class Engine:
    """Dispatches artifacts to scanners and aggregates findings, fail-closed."""

    def __init__(self, scanners: list[Scanner]):
        self._scanners = list(scanners)

    def _select(self, header: bytes, path: Path) -> Scanner | None:
        for scanner in self._scanners:
            try:
                if scanner.sniff(header, path):
                    return scanner
            except Exception:
                # A scanner that crashes during sniff must not mask others.
                continue
        return None

    def scan_artifact(self, path: Path) -> tuple[list[Finding], list]:
        """Scan a single file. Returns (findings, [provenance])."""
        findings: list[Finding] = []
        try:
            with path.open("rb") as fh:
                header = fh.read(_HEADER_BYTES)
        except OSError as exc:
            findings.append(
                Finding(RULE_UNPARSEABLE, Severity.FAIL, str(path), f"unreadable: {exc}")
            )
            # Still emit a (minimal) provenance record so downstream consumers
            # such as the baseline never receive an artifact without one.
            return findings, [
                Provenance(path=str(path), sha256="", size=0, fmt="unreadable")
            ]

        fmt = "unknown"
        scanner = self._select(header, path)
        if scanner is None:
            findings.append(
                Finding(
                    RULE_UNKNOWN_FORMAT,
                    Severity.WARN,
                    str(path),
                    "no scanner recognized this artifact's content",
                )
            )
        else:
            fmt = scanner.name
            try:
                findings.extend(scanner.scan(path))
            except Exception as exc:
                # Bypass defense: a scanner forced to error must FAIL, never silently
                # pass the artifact through (AC-8, ADR-0004).
                findings.append(
                    Finding(
                        RULE_UNPARSEABLE,
                        Severity.FAIL,
                        str(path),
                        f"scan aborted ({type(exc).__name__}); treated as fail-closed",
                    )
                )

        prov = build_provenance(path, fmt)
        # Provenance with no expected hash is surfaced as WARN, not implicit PASS (AC-13).
        if prov.hash_verified is None:
            findings.append(
                Finding(
                    "MS-PROVENANCE-UNVERIFIED",
                    Severity.WARN,
                    str(path),
                    "no expected hash or baseline supplied; provenance unverified",
                )
            )
        elif prov.hash_verified is False:
            findings.append(
                Finding(
                    "MS-PROVENANCE-MISMATCH",
                    Severity.FAIL,
                    str(path),
                    "artifact hash does not match the expected hash",
                )
            )
        return findings, [prov]

    def scan_path(
        self, target: Path, expected_hashes: dict[str, str] | None = None
    ) -> Report:
        """Scan a file or recurse a directory of artifacts into one Report."""
        report = Report()
        for artifact in _iter_artifacts(target):
            findings, prov = self.scan_artifact(artifact)
            # Re-evaluate provenance against an expected hash if one was supplied.
            if expected_hashes and prov:
                findings, prov = _apply_expected_hash(
                    artifact, findings, prov, expected_hashes
                )
            report.findings.extend(findings)
            report.provenance.extend(prov)
        return report


def _iter_artifacts(target: Path):
    if target.is_dir():
        for p in sorted(target.rglob("*")):
            if p.is_file():
                yield p
    elif target.is_file():
        yield target
    # Non-existent path yields nothing; caller surfaces empty report.


def _apply_expected_hash(path, findings, prov, expected_hashes):
    from modelseal.core.provenance import verify_against_expected

    key = str(path)
    expected = expected_hashes.get(key) or expected_hashes.get(path.name)
    if expected is None:
        return findings, prov
    new_prov, ok = verify_against_expected(prov[0], expected)
    # Drop the "unverified" WARN we optimistically added and replace with a verdict.
    filtered = [
        f for f in findings if f.rule_id != "MS-PROVENANCE-UNVERIFIED"
    ]
    if ok:
        filtered.append(
            Finding(
                "MS-PROVENANCE-OK",
                Severity.INFO,
                key,
                "artifact hash matches the expected hash",
            )
        )
    else:
        filtered.append(
            Finding(
                "MS-PROVENANCE-MISMATCH",
                Severity.FAIL,
                key,
                "artifact hash does not match the expected hash",
            )
        )
    return filtered, [new_prov]


def scan_path(target, expected_hashes: dict[str, str] | None = None) -> Report:
    """Convenience: scan with the default scanner set."""
    from modelseal.registry import default_scanners

    return Engine(default_scanners()).scan_path(Path(target), expected_hashes)
