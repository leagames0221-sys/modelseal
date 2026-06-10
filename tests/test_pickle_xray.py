from modelseal.core.contracts import Severity
from modelseal.packs.scanners.pickle_xray import PickleScanner


def _scan(path):
    return PickleScanner().scan(path)


def test_dangerous_import_is_fail(dangerous_pickle):
    findings = _scan(dangerous_pickle)
    assert any(f.rule_id == "MS-PICKLE-DANGEROUS-IMPORT" for f in findings)
    assert max(f.severity for f in findings) == Severity.FAIL


def test_benign_pickle_has_no_findings(benign_pickle):
    assert _scan(benign_pickle) == []


def test_reconstruct_with_safe_import_is_warn(reconstruct_pickle):
    findings = _scan(reconstruct_pickle)
    assert findings, "expected a reconstruct advisory"
    assert all(f.severity == Severity.WARN for f in findings)
    assert any(f.rule_id == "MS-PICKLE-RECONSTRUCT" for f in findings)


def test_sniff_by_proto_byte(benign_pickle):
    header = benign_pickle.read_bytes()[:8]
    assert PickleScanner().sniff(header, benign_pickle)
