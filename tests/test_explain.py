"""Explanation layer: optional, fail-soft, never changes the verdict (AC-21..24)."""

from __future__ import annotations

import io
import json

from modelseal.core.contracts import Finding, MockProvider, Severity
from modelseal.packs.explain import ollama_provider as op


def _finding():
    return Finding("MS-TEST", Severity.WARN, "x.pkl", "test finding")


def test_mock_provider_lists_findings():
    out = MockProvider().explain([_finding()])
    assert "MS-TEST" in out


def test_ollama_provider_offline_via_monkeypatch(monkeypatch):
    captured = {}

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=0):
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp(json.dumps({"response": "plain-language explanation"}).encode())

    monkeypatch.setattr(op.urllib.request, "urlopen", fake_urlopen)
    out = op.OllamaProvider().explain([_finding()])
    assert out == "plain-language explanation"
    assert captured["body"]["stream"] is False
    assert captured["body"]["options"]["temperature"] == 0
    assert "MS-TEST" in captured["body"]["prompt"]


def test_cli_explain_fail_soft(monkeypatch, benign_pickle, capsys):
    """Provider unreachable -> explanation notes it; verdict/exit unchanged (AC-23)."""
    from modelseal import cli

    def boom(self, findings):
        raise ConnectionError("no ollama")

    monkeypatch.setattr(op.OllamaProvider, "explain", boom)
    code = cli.main(["scan", str(benign_pickle), "--format", "json", "--explain"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1  # provenance-unverified WARN, unaffected by explain failure
    assert "unavailable" in data["explanation"]


def test_explain_empty_findings():
    assert "nothing to explain" in op.OllamaProvider().explain([]).lower()
