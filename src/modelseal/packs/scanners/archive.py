"""Archive scanner: zip-based checkpoints (e.g. modern .pt) (AC-7, AC-9).

Enumerates members and applies the pickle x-ray to nested serialized data.
Never extracts to disk or executes anything.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from modelseal.core.contracts import Finding, Scanner, Severity
from modelseal.packs.scanners.pickle_xray import _PICKLE_SUFFIXES, scan_pickle_stream

_ZIP_MAGIC = b"PK\x03\x04"
# Per-member read cap to stay consumer-laptop friendly on huge checkpoints.
_MEMBER_CAP = 64 * 1024 * 1024


def looks_like_zip(header: bytes) -> bool:
    return header[:4] == _ZIP_MAGIC


class ArchiveScanner(Scanner):
    name = "archive"

    def sniff(self, header: bytes, path: Path) -> bool:
        return looks_like_zip(header)

    def scan(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        # Extension spoofing: a "safe-looking" suffix on a zip container (AC-9).
        if path.suffix.lower() in {".safetensors", ".gguf"}:
            findings.append(
                Finding(
                    "MS-EXTENSION-SPOOF",
                    Severity.WARN,
                    str(path),
                    "extension claims a non-archive format but content is a zip container",
                )
            )
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                member = info.filename
                suffix = Path(member).suffix.lower()
                if suffix and suffix not in _PICKLE_SUFFIXES:
                    continue
                with zf.open(info) as fh:
                    data = fh.read(_MEMBER_CAP)
                findings.extend(scan_pickle_stream(data, f"{path}!{member}"))
        return findings
