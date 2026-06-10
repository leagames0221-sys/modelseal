"""Report rendering: human-readable / JSON / SARIF 2.1.0 (AC-25).

stdlib only (json). SARIF structure modeled on the modelaudit output convention.
"""

from __future__ import annotations

import json

from modelseal.core.contracts import Report, Severity

# SARIF level mapping for our three severities.
_SARIF_LEVEL = {Severity.INFO: "note", Severity.WARN: "warning", Severity.FAIL: "error"}


def render_human(report: Report) -> str:
    lines = [f"verdict: {report.verdict}  ({len(report.findings)} findings)"]
    for f in report.findings:
        lines.append(f"  [{f.severity.label:4}] {f.rule_id}  {f.location}")
        lines.append(f"         {f.message}")
    for p in report.provenance:
        verified = {True: "ok", False: "MISMATCH", None: "unverified"}[p.hash_verified]
        lines.append(f"  prov  {p.path}  sha256={p.sha256[:16]}..  fmt={p.fmt}  hash={verified}")
    if report.explanation:
        lines.append("")
        lines.append(report.explanation)
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(
        {
            "verdict": report.verdict,
            "exit_code": report.exit_code,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.label,
                    "location": f.location,
                    "message": f.message,
                }
                for f in report.findings
            ],
            "provenance": [
                {
                    "path": p.path,
                    "sha256": p.sha256,
                    "size": p.size,
                    "fmt": p.fmt,
                    "source_meta": p.source_meta,
                    "hash_verified": p.hash_verified,
                }
                for p in report.provenance
            ],
            "explanation": report.explanation,
        },
        indent=2,
    )


def render_sarif(report: Report) -> str:
    rule_ids = sorted({f.rule_id for f in report.findings})
    results = [
        {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": f.location}}}
            ],
        }
        for f in report.findings
    ]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "modelseal",
                        "informationUri": "https://github.com/leagames0221-sys/modelseal",
                        "rules": [{"id": rid} for rid in rule_ids],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    return render_human(report)
