"""Prove the scanner never deserializes the artifact (AC-3).

If any code path called pickle.load/loads on the artifact, these patched
functions would raise and fail the test. Static opcode walking must not."""

from __future__ import annotations

import pickle

import pytest

from modelseal.core.engine import Engine
from modelseal.registry import default_scanners


@pytest.fixture
def _forbid_deserialize(monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("artifact was deserialized — non-execution invariant broken")

    monkeypatch.setattr(pickle, "load", _boom)
    monkeypatch.setattr(pickle, "loads", _boom)
    yield


def test_scan_does_not_deserialize(_forbid_deserialize, dangerous_pickle, zip_checkpoint):
    engine = Engine(default_scanners())
    assert engine.scan_path(dangerous_pickle).verdict == "FAIL"
    assert engine.scan_path(zip_checkpoint).verdict == "FAIL"
