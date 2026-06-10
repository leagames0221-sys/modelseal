"""Approval baseline: snapshot approved artifacts, then diff later scans against it.

The differentiator (no prior-art OSS has this): detect that a once-approved
artifact silently changed, and FAIL when the change raises its risk (AC-14..18).

Manifest is plain JSON (human-readable, reviewable -> AC-18). stdlib only.
"""

from __future__ import annotations

import json
from pathlib import Path

from modelseal.core.contracts import Finding, Severity
from modelseal.core.engine import Engine, _iter_artifacts

MANIFEST_VERSION = 1


def _artifact_summary(engine: Engine, path: Path) -> dict:
    """Per-artifact baseline entry: hash + format + scan summary (ADR-0005)."""
    findings, prov = engine.scan_artifact(path)
    max_sev = max((f.severity for f in findings), default=Severity.INFO)
    rule_ids = sorted({f.rule_id for f in findings})
    # Fail-closed: even if an engine ever yields no provenance, the baseline
    # must record the artifact (as unreadable) rather than crash.
    sha256, fmt = (prov[0].sha256, prov[0].fmt) if prov else ("", "unreadable")
    return {
        "sha256": sha256,
        "fmt": fmt,
        "max_severity": Severity(max_sev).name,
        "rule_ids": rule_ids,
    }


def _relkey(target: Path, artifact: Path) -> str:
    if target.is_dir():
        return artifact.relative_to(target).as_posix()
    return artifact.name


class Baseline:
    """An approved snapshot. Build via ``approve``; compare via ``diff``."""

    def __init__(self, artifacts: dict[str, dict], version: int = MANIFEST_VERSION):
        self.version = version
        self.artifacts = artifacts

    # --- persistence (human-readable JSON) ---

    def to_json(self) -> str:
        return json.dumps(
            {"version": self.version, "artifacts": self.artifacts},
            indent=2,
            sort_keys=True,
        )

    def save(self, manifest_path: Path) -> None:
        manifest_path.write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, manifest_path: Path) -> Baseline:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return cls(data.get("artifacts", {}), data.get("version", MANIFEST_VERSION))

    # --- build / compare ---

    @classmethod
    def approve(cls, target: Path, engine: Engine) -> Baseline:
        artifacts = {
            _relkey(target, art): _artifact_summary(engine, art)
            for art in _iter_artifacts(target)
        }
        return cls(artifacts)

    def diff(self, target: Path, engine: Engine) -> list[Finding]:
        """Compare current target against this baseline -> findings (AC-15..17)."""
        findings: list[Finding] = []
        current = {
            _relkey(target, art): art for art in _iter_artifacts(target)
        }
        baseline_keys = set(self.artifacts)
        current_keys = set(current)

        for key in sorted(baseline_keys - current_keys):
            findings.append(
                Finding("MS-BASELINE-REMOVED", Severity.WARN, key,
                        "artifact present in baseline is missing now")
            )
        for key in sorted(current_keys - baseline_keys):
            findings.append(
                Finding("MS-BASELINE-ADDED", Severity.WARN, key,
                        "artifact not present in the approved baseline")
            )
        for key in sorted(baseline_keys & current_keys):
            old = self.artifacts[key]
            new = _artifact_summary(engine, current[key])
            if old["sha256"] == new["sha256"]:
                continue
            # Content silently changed since approval (AC-16).
            findings.append(
                Finding("MS-BASELINE-CHANGED", Severity.WARN, key,
                        "artifact content changed since it was approved")
            )
            old_sev = Severity[old["max_severity"]]
            new_sev = Severity[new["max_severity"]]
            if new_sev > old_sev:
                # A change that raises risk is an unconditional FAIL (AC-17).
                findings.append(
                    Finding("MS-BASELINE-SEVERITY-UP", Severity.FAIL, key,
                            f"risk rose since approval ({old_sev.name} -> {new_sev.name})")
                )
        return findings
