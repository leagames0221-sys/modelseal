"""GGUF header-integrity scanner (AC-19, AC-20).

Format (primary source: github.com/ggml-org/ggml docs/gguf.md):
  [0:4]   magic 'GGUF'
  [4:8]   u32 version (current = 3; endianness matches the model)
  [8:16]  u64 tensor_count
  [16:24] u64 metadata_kv_count

Like safetensors this carries no code; we validate that a file claiming the
format actually is one, with plausible counts.
"""

from __future__ import annotations

import struct
from pathlib import Path

from modelseal.core.contracts import Finding, Scanner, Severity

RULE_MALFORMED = "MS-GGUF-MALFORMED"
_MAGIC = b"GGUF"
_KNOWN_VERSIONS = {1, 2, 3}


def _fail(path: Path, why: str) -> list[Finding]:
    return [Finding(RULE_MALFORMED, Severity.FAIL, str(path), why)]


class GgufScanner(Scanner):
    name = "gguf"

    def sniff(self, header: bytes, path: Path) -> bool:
        return header[:4] == _MAGIC or path.suffix.lower() == ".gguf"

    def scan(self, path: Path) -> list[Finding]:
        size = path.stat().st_size
        if size < 24:
            return _fail(path, "file too small to hold a GGUF header")
        with path.open("rb") as fh:
            head = fh.read(24)
        if head[:4] != _MAGIC:
            return _fail(path, "extension claims GGUF but the magic bytes do not match")

        (version_le,) = struct.unpack("<I", head[4:8])
        (version_be,) = struct.unpack(">I", head[4:8])
        if version_le in _KNOWN_VERSIONS:
            endian = "<"
        elif version_be in _KNOWN_VERSIONS:
            endian = ">"  # big-endian model, valid per spec v3
        else:
            return _fail(path, "GGUF version field is not a known version")

        tensor_count, kv_count = struct.unpack(f"{endian}QQ", head[8:24])
        # Plausibility: each tensor/KV needs at least a few bytes of payload;
        # counts larger than the file itself indicate a forged header.
        if tensor_count > size or kv_count > size:
            return _fail(path, "declared tensor/metadata counts exceed what the file can hold")
        return []
