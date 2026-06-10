import json

from modelseal.core.engine import Engine
from modelseal.core.render import render
from modelseal.registry import default_scanners


def _report(path):
    return Engine(default_scanners()).scan_path(path)


def test_json_is_parseable(dangerous_pickle):
    data = json.loads(render(_report(dangerous_pickle), "json"))
    assert data["verdict"] == "FAIL"
    assert data["exit_code"] == 2
    assert data["findings"]


def test_sarif_is_valid_210(dangerous_pickle):
    doc = json.loads(render(_report(dangerous_pickle), "sarif"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "modelseal"
    assert doc["runs"][0]["results"]


def test_human_mentions_verdict(benign_pickle):
    out = render(_report(benign_pickle), "human")
    assert "verdict:" in out
