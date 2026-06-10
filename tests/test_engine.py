from modelseal.core.engine import Engine
from modelseal.core.provenance import sha256_file
from modelseal.registry import default_scanners


def _engine():
    return Engine(default_scanners())


def test_dangerous_artifact_fails(dangerous_pickle):
    report = _engine().scan_path(dangerous_pickle)
    assert report.verdict == "FAIL"
    assert report.exit_code == 2


def test_zip_checkpoint_nested_pickle_fails(zip_checkpoint):
    report = _engine().scan_path(zip_checkpoint)
    assert report.verdict == "FAIL"
    assert any("!archive/data.pkl" in f.location for f in report.findings)


def test_extension_spoof_detected(spoofed_zip):
    report = _engine().scan_path(spoofed_zip)
    assert any(f.rule_id == "MS-EXTENSION-SPOOF" for f in report.findings)


def test_unparseable_is_fail_closed(truncated_pickle):
    report = _engine().scan_path(truncated_pickle)
    assert report.verdict == "FAIL"
    assert any(f.rule_id == "MS-UNPARSEABLE" for f in report.findings)


def test_unknown_format_is_warn(unknown_file):
    report = _engine().scan_path(unknown_file)
    assert any(f.rule_id == "MS-UNKNOWN-FORMAT" for f in report.findings)


def test_provenance_unverified_is_warn(benign_pickle):
    report = _engine().scan_path(benign_pickle)
    assert any(f.rule_id == "MS-PROVENANCE-UNVERIFIED" for f in report.findings)
    assert report.verdict == "WARN"


def test_expected_hash_match_is_ok(benign_pickle):
    digest = sha256_file(benign_pickle)
    report = _engine().scan_path(benign_pickle, {benign_pickle.name: digest})
    assert any(f.rule_id == "MS-PROVENANCE-OK" for f in report.findings)
    assert not any(f.rule_id == "MS-PROVENANCE-UNVERIFIED" for f in report.findings)
    assert report.verdict == "PASS"


def test_expected_hash_mismatch_is_fail(benign_pickle):
    report = _engine().scan_path(benign_pickle, {benign_pickle.name: "0" * 64})
    assert report.verdict == "FAIL"
    assert any(f.rule_id == "MS-PROVENANCE-MISMATCH" for f in report.findings)


def test_directory_scan_covers_all(tmp_path, benign_pickle, dangerous_pickle):
    # both fixtures live under tmp_path already
    report = _engine().scan_path(tmp_path)
    assert report.verdict == "FAIL"
    assert len(report.provenance) >= 2
