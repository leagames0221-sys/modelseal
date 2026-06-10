"""safetensors / GGUF header-integrity tests (AC-19, AC-20). Synthetic files only."""

from __future__ import annotations

import json
import struct

from modelseal.core.engine import Engine
from modelseal.registry import default_scanners


def _engine():
    return Engine(default_scanners())


def _make_safetensors(tmp_path, name="model.safetensors", buffer=b"\x00" * 8, header=None):
    header = header or {"t": {"dtype": "F32", "shape": [2], "data_offsets": [0, len(buffer)]}}
    blob = json.dumps(header).encode("utf-8")
    p = tmp_path / name
    p.write_bytes(struct.pack("<Q", len(blob)) + blob + buffer)
    return p


def _make_gguf(tmp_path, name="model.gguf", magic=b"GGUF", version=3, tensors=1, kvs=1):
    p = tmp_path / name
    head = magic + struct.pack("<I", version) + struct.pack("<QQ", tensors, kvs)
    p.write_bytes(head + b"\x00" * 64)
    return p


# --- safetensors ---

def test_valid_safetensors_passes(tmp_path):
    p = _make_safetensors(tmp_path)
    report = _engine().scan_path(p)
    assert not any(f.rule_id == "MS-SAFETENSORS-MALFORMED" for f in report.findings)
    assert any(pr.fmt == "safetensors" for pr in report.provenance)


def test_safetensors_header_longer_than_file_fails(tmp_path):
    p = tmp_path / "model.safetensors"
    p.write_bytes(struct.pack("<Q", 10_000) + b"{}")
    report = _engine().scan_path(p)
    assert any(f.rule_id == "MS-SAFETENSORS-MALFORMED" for f in report.findings)
    assert report.verdict == "FAIL"


def test_safetensors_offsets_outside_buffer_fail(tmp_path):
    header = {"t": {"dtype": "F32", "shape": [2], "data_offsets": [0, 999]}}
    p = _make_safetensors(tmp_path, buffer=b"\x00" * 8, header=header)
    report = _engine().scan_path(p)
    assert report.verdict == "FAIL"


def test_safetensors_unindexed_gap_fails(tmp_path):
    header = {"t": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}
    p = _make_safetensors(tmp_path, buffer=b"\x00" * 8, header=header)
    report = _engine().scan_path(p)
    assert any(f.rule_id == "MS-SAFETENSORS-MALFORMED" for f in report.findings)


def test_safetensors_bad_json_fails(tmp_path):
    blob = b"{not json"
    p = tmp_path / "model.safetensors"
    p.write_bytes(struct.pack("<Q", len(blob)) + blob)
    report = _engine().scan_path(p)
    assert report.verdict == "FAIL"


# --- gguf ---

def test_valid_gguf_passes(tmp_path):
    p = _make_gguf(tmp_path)
    report = _engine().scan_path(p)
    assert not any(f.rule_id == "MS-GGUF-MALFORMED" for f in report.findings)
    assert any(pr.fmt == "gguf" for pr in report.provenance)


def test_gguf_wrong_magic_with_claiming_extension_fails(tmp_path):
    p = _make_gguf(tmp_path, magic=b"XXXX")
    report = _engine().scan_path(p)
    assert any(f.rule_id == "MS-GGUF-MALFORMED" for f in report.findings)
    assert report.verdict == "FAIL"


def test_gguf_unknown_version_fails(tmp_path):
    p = _make_gguf(tmp_path, version=999)
    report = _engine().scan_path(p)
    assert report.verdict == "FAIL"


def test_gguf_absurd_counts_fail(tmp_path):
    p = _make_gguf(tmp_path, tensors=2**60)
    report = _engine().scan_path(p)
    assert report.verdict == "FAIL"
