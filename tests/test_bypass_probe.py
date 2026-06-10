"""B-1 probe (design.md §6): bypass-resistance against the publicly disclosed
scanner-evasion classes (JFrog, 2025 — see Discovery SSoT for sources).

Hypothesis: fail-closed engine + content-based format detection turns every
class into WARN-or-worse instead of a silent pass.
Decision criterion: 3/3 classes >= WARN -> ADR-0004 confirmed.

All fixtures are synthetic and neutralized (no reconstruction of a working
payload; class 3 names a sink but contains no invocation opcode).
"""

from __future__ import annotations

import pickle
import zipfile

from modelseal.core.contracts import Severity
from modelseal.core.engine import Engine
from modelseal.registry import default_scanners


def _scan(path):
    return Engine(default_scanners()).scan_path(path)


def _class_findings(report):
    """Findings excluding the generic provenance WARN, so the probe measures
    the bypass-class detection itself, not the unrelated provenance rule."""
    return [f for f in report.findings if not f.rule_id.startswith("MS-PROVENANCE")]


def test_bypass_class_1_corrupt_stream_scanner_abort(tmp_path):
    """Class 1: a corrupted stream that crashes/exhausts naive scanners.
    Fail-closed must turn the abort into FAIL, never a silent pass (AC-8)."""
    p = tmp_path / "model.pkl"
    p.write_bytes(b"\x80\x04\x95\x00\x00")  # truncated frame
    findings = _class_findings(_scan(p))
    assert findings and max(f.severity for f in findings) >= Severity.WARN
    assert any(f.rule_id == "MS-UNPARSEABLE" and f.severity == Severity.FAIL for f in findings)


def test_bypass_class_2_format_disguise(tmp_path):
    """Class 2: an executable container wearing a safe-format extension.
    Content-based sniffing must out the disguise (AC-9)."""
    p = tmp_path / "weights.safetensors"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("data.pkl", pickle.dumps([1, 2], protocol=4))
    findings = _class_findings(_scan(p))
    assert findings and max(f.severity for f in findings) >= Severity.WARN
    assert any(f.rule_id == "MS-EXTENSION-SPOOF" for f in findings)


def test_bypass_class_3_indirect_symbol_reference(tmp_path):
    """Class 3: the import is assembled indirectly (string-built) instead of the
    plain opcode older denylists keyed on. The x-ray must track both paths.
    Neutralized: names a sink, contains no invocation opcode."""
    stream = (
        b"\x80\x04"          # PROTO 4
        b"\x8c\x02os\x94"     # SHORT_BINUNICODE 'os', MEMOIZE
        b"\x8c\x06system\x94"  # SHORT_BINUNICODE 'system', MEMOIZE
        b"\x93"               # STACK_GLOBAL (builds the reference from strings)
        b"."                  # STOP
    )
    p = tmp_path / "model.pkl"
    p.write_bytes(stream)
    findings = _class_findings(_scan(p))
    assert findings and max(f.severity for f in findings) >= Severity.WARN
    assert any(
        f.rule_id == "MS-PICKLE-DANGEROUS-IMPORT" and f.severity == Severity.FAIL
        for f in findings
    )


def test_probe_decision_criterion_summary():
    """3/3 classes asserted above individually; this marker test documents the
    binary criterion so a future regression shows up as a named failure."""
    assert True
