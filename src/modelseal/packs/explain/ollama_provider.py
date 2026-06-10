"""Optional explanation layer backed by a local Ollama instance.

The ONLY module in the package allowed to import networking (ADR-0006).
Output is attached to Report.explanation and never influences the verdict,
severity, or exit code (AC-21..23). stdlib urllib only — no new dependencies.
"""

from __future__ import annotations

import json
import os
import urllib.request

from modelseal.core.contracts import Finding, Provider

_DEFAULT_URL = "http://localhost:11434/api/generate"
_DEFAULT_MODEL = "gemma3:4b"
_TIMEOUT_S = 60

_PROMPT_TEMPLATE = (
    "You are a security assistant for an AI-model artifact scanner. "
    "The deterministic scan already decided the verdict; do NOT change or dispute it. "
    "Explain the following findings in plain language for a reviewer and suggest "
    "safe next steps (e.g. verify the source, prefer a non-executable format, "
    "re-approve the baseline only after review).\n\nFindings:\n{findings}\n"
)


class OllamaProvider(Provider):
    def __init__(self, url: str | None = None, model: str | None = None):
        self.url = url or os.environ.get("MODELSEAL_OLLAMA_URL", _DEFAULT_URL)
        self.model = model or os.environ.get("MODELSEAL_OLLAMA_MODEL", _DEFAULT_MODEL)

    def explain(self, findings: list[Finding]) -> str:
        if not findings:
            return "No findings; nothing to explain."
        listing = "\n".join(
            f"- [{f.severity.label}] {f.rule_id} at {f.location}: {f.message}"
            for f in findings
        )
        payload = json.dumps(
            {
                "model": self.model,
                "prompt": _PROMPT_TEMPLATE.format(findings=listing),
                "stream": False,
                "options": {"temperature": 0},
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=payload, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:  # noqa: S310 (localhost)
            body = json.loads(resp.read().decode("utf-8"))
        return str(body.get("response", "")).strip()
