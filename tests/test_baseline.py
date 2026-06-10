import pickle

from modelseal.core.baseline import Baseline
from modelseal.core.engine import Engine
from modelseal.registry import default_scanners


def _engine():
    return Engine(default_scanners())


def test_approve_then_unchanged_diff_is_clean(benign_pickle, tmp_path):
    manifest = tmp_path / "baseline.json"
    Baseline.approve(benign_pickle, _engine()).save(manifest)
    findings = Baseline.load(manifest).diff(benign_pickle, _engine())
    assert findings == []


def test_silent_change_is_warn(benign_pickle, tmp_path):
    base = Baseline.approve(benign_pickle, _engine())
    benign_pickle.write_bytes(pickle.dumps({"layer": [9, 9]}, protocol=4))
    findings = base.diff(benign_pickle, _engine())
    assert any(f.rule_id == "MS-BASELINE-CHANGED" for f in findings)


def test_risk_increase_is_fail(benign_pickle):
    base = Baseline.approve(benign_pickle, _engine())
    # Replace approved-benign content with a denylisted-import stream.
    benign_pickle.write_bytes(b"\x80\x04" + b"c" + b"os\nsystem\n" + b".")
    findings = base.diff(benign_pickle, _engine())
    assert any(f.rule_id == "MS-BASELINE-SEVERITY-UP" for f in findings)
    assert max(f.severity for f in findings).name == "FAIL"


def test_added_and_removed(tmp_path):
    d = tmp_path / "models"
    d.mkdir()
    (d / "a.pkl").write_bytes(pickle.dumps([1], protocol=4))
    base = Baseline.approve(d, _engine())
    (d / "a.pkl").unlink()
    (d / "b.pkl").write_bytes(pickle.dumps([2], protocol=4))
    findings = base.diff(d, _engine())
    rule_ids = {f.rule_id for f in findings}
    assert "MS-BASELINE-REMOVED" in rule_ids
    assert "MS-BASELINE-ADDED" in rule_ids


def test_manifest_is_human_readable_json(benign_pickle):
    text = Baseline.approve(benign_pickle, _engine()).to_json()
    assert '"sha256"' in text and '"max_severity"' in text
