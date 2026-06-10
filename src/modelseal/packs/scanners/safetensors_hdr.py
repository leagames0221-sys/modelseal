"""safetensors header-integrity scanner (AC-19, AC-20).

Format (primary source: github.com/huggingface/safetensors README):
  [0:8]   u64 little-endian N = JSON header length
  [8:8+N] UTF-8 JSON starting with '{' (trailing 0x20 padding allowed)
  rest    tensor buffer; data_offsets are buffer-relative, must not overlap
          and must index the buffer completely; header capped at 100MB.

This format carries no code; the check is declaration-vs-reality integrity:
a malformed "safe-looking" file is exactly the disguise we must catch.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from modelseal.core.contracts import Finding, Scanner, Severity

RULE_MALFORMED = "MS-SAFETENSORS-MALFORMED"
_HEADER_CAP = 100 * 1024 * 1024  # spec DOS limit


def _fail(path: Path, why: str) -> list[Finding]:
    return [Finding(RULE_MALFORMED, Severity.FAIL, str(path), why)]


class SafetensorsScanner(Scanner):
    name = "safetensors"

    def sniff(self, header: bytes, path: Path) -> bool:
        if path.suffix.lower() == ".safetensors":
            return True  # extension claims the format -> we validate the claim
        if len(header) < 9:
            return False
        (n,) = struct.unpack("<Q", header[:8])
        return 0 < n <= _HEADER_CAP and header[8:9] == b"{"

    def scan(self, path: Path) -> list[Finding]:
        size = path.stat().st_size
        if size < 9:
            return _fail(path, "file too small to hold a safetensors header")
        with path.open("rb") as fh:
            (n,) = struct.unpack("<Q", fh.read(8))
            if n == 0 or n > _HEADER_CAP:
                return _fail(path, "declared header length is zero or exceeds the 100MB cap")
            if 8 + n > size:
                return _fail(path, "declared header length exceeds the actual file size")
            raw = fh.read(n)
        if not raw.startswith(b"{"):
            return _fail(path, "header does not start with a JSON object")
        try:
            header = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _fail(path, "header is not valid UTF-8 JSON")
        if not isinstance(header, dict):
            return _fail(path, "header JSON is not an object")

        buffer_size = size - 8 - n
        ranges: list[tuple[int, int]] = []
        for key, entry in header.items():
            if key == "__metadata__":
                if not isinstance(entry, dict) or not all(
                    isinstance(k, str) and isinstance(v, str) for k, v in entry.items()
                ):
                    return _fail(path, "__metadata__ must be a string-to-string mapping")
                continue
            if not isinstance(entry, dict):
                return _fail(path, f"tensor entry {key!r} is not an object")
            offsets = entry.get("data_offsets")
            if (
                not isinstance(offsets, list)
                or len(offsets) != 2
                or not all(isinstance(o, int) for o in offsets)
            ):
                return _fail(path, f"tensor entry {key!r} lacks valid data_offsets")
            begin, end = offsets
            if not (0 <= begin <= end <= buffer_size):
                return _fail(
                    path, f"tensor {key!r} data_offsets fall outside the actual buffer"
                )
            ranges.append((begin, end))

        # No overlaps; buffer must be completely indexed (spec constraints).
        ranges.sort()
        cursor = 0
        for begin, end in ranges:
            if begin < cursor:
                return _fail(path, "tensor data ranges overlap")
            if begin > cursor:
                return _fail(path, "tensor data ranges leave an unindexed gap in the buffer")
            cursor = end
        if cursor != buffer_size:
            return _fail(
                path, "declared tensor data does not match the actual buffer size"
            )
        return []
