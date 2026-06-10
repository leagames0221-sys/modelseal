"""Unreadable artifacts must fail closed without crashing scan or baseline.

Regression for the review finding: an OSError during the header read used to
return an empty provenance list, crashing Baseline approve/diff on prov[0].
"""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from modelseal.core.baseline import Baseline
from modelseal.core.engine import Engine
from modelseal.registry import default_scanners


@pytest.fixture
def locked_file(tmp_path, monkeypatch):
    p = tmp_path / "locked.pkl"
    p.write_bytes(pickle.dumps([1], protocol=4))
    orig_open = Path.open

    def fake_open(self, *args, **kwargs):
        if self.name == "locked.pkl":
            raise PermissionError("simulated lock")
        return orig_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fake_open)
    return p


def _engine():
    return Engine(default_scanners())


def test_unreadable_scan_is_fail_with_provenance(locked_file):
    report = _engine().scan_path(locked_file)
    assert report.verdict == "FAIL"
    assert any(f.rule_id == "MS-UNPARSEABLE" for f in report.findings)
    assert len(report.provenance) == 1
    assert report.provenance[0].fmt == "unreadable"


def test_baseline_approve_and_diff_survive_unreadable(tmp_path, locked_file):
    (tmp_path / "ok.pkl").write_bytes(pickle.dumps([2], protocol=4))
    base = Baseline.approve(tmp_path, _engine())
    assert base.artifacts["locked.pkl"]["fmt"] == "unreadable"
    assert base.artifacts["locked.pkl"]["max_severity"] == "FAIL"
    # unchanged (still unreadable, same recorded state) -> no baseline findings
    assert base.diff(tmp_path, _engine()) == []


def test_artifact_summary_defensive_on_empty_provenance(tmp_path):
    """Even an engine that yields no provenance must not crash the baseline."""

    class _NoProvEngine:
        def scan_artifact(self, path):
            return [], []

    p = tmp_path / "x.pkl"
    p.write_bytes(b"\x80\x04.")
    base = Baseline.approve(p, _NoProvEngine())
    assert base.artifacts["x.pkl"]["fmt"] == "unreadable"
