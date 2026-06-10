"""Shared fixtures. All 'malicious' samples are neutralized synthetic streams
that name a sink but are never deserialized by modelseal (§5-3, AC-3)."""

from __future__ import annotations

import pickle
import zipfile
from pathlib import Path

import pytest


@pytest.fixture
def benign_pickle(tmp_path: Path) -> Path:
    p = tmp_path / "weights.pkl"
    p.write_bytes(pickle.dumps({"layer": [1, 2, 3], "bias": 0.5}, protocol=4))
    return p


@pytest.fixture
def reconstruct_pickle(tmp_path: Path) -> Path:
    # datetime pickles via object reconstruction (REDUCE) referencing a
    # non-dangerous stdlib symbol — exercises the conservative WARN path.
    import datetime

    p = tmp_path / "recon.pkl"
    p.write_bytes(pickle.dumps(datetime.datetime(2026, 6, 10, 12, 0), protocol=4))
    return p


@pytest.fixture
def dangerous_pickle(tmp_path: Path) -> Path:
    # Hand-built stream: PROTO 4, GLOBAL referencing a denylisted sink, STOP.
    # No reconstruction opcode -> inert even if (hypothetically) loaded.
    raw = b"\x80\x04" + b"c" + b"os\nsystem\n" + b"."
    p = tmp_path / "danger.pkl"
    p.write_bytes(raw)
    return p


@pytest.fixture
def zip_checkpoint(dangerous_pickle: Path, tmp_path: Path) -> Path:
    p = tmp_path / "model.pt"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("archive/data.pkl", dangerous_pickle.read_bytes())
    return p


@pytest.fixture
def spoofed_zip(tmp_path: Path) -> Path:
    # A zip container wearing a "safe-format" extension.
    p = tmp_path / "model.safetensors"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("data.pkl", pickle.dumps([1, 2], protocol=4))
    return p


@pytest.fixture
def truncated_pickle(tmp_path: Path) -> Path:
    # PROTO + a FRAME opcode with a missing length -> opcode walker raises.
    p = tmp_path / "broken.pkl"
    p.write_bytes(b"\x80\x04\x95\x00\x00")
    return p


@pytest.fixture
def unknown_file(tmp_path: Path) -> Path:
    p = tmp_path / "notes.xyz"
    p.write_bytes(b"just some bytes, not a model")
    return p
