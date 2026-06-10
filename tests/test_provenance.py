from modelseal.core.provenance import (
    build_provenance,
    sha256_file,
    verify_against_expected,
)


def test_sha256_stable(benign_pickle):
    assert sha256_file(benign_pickle) == sha256_file(benign_pickle)


def test_build_provenance_unverified(benign_pickle):
    prov = build_provenance(benign_pickle, "pickle")
    assert prov.hash_verified is None
    assert prov.size > 0
    assert len(prov.sha256) == 64


def test_verify_match_and_mismatch(benign_pickle):
    prov = build_provenance(benign_pickle, "pickle")
    ok_prov, ok = verify_against_expected(prov, prov.sha256.upper())
    assert ok and ok_prov.hash_verified is True
    bad_prov, bad = verify_against_expected(prov, "0" * 64)
    assert not bad and bad_prov.hash_verified is False
