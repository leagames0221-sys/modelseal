"""Provenance: cryptographic hash + size + format record, and expected-hash check.

stdlib only (hashlib). Signature verification (sigstore-style) is out of scope
for the zero-dependency core and deferred to a future optional pack (ADR-0003).
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

from modelseal.core.contracts import Provenance

_CHUNK = 1 << 20  # 1 MiB streaming read, consumer-laptop friendly.


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def build_provenance(
    path: Path, fmt: str, source_meta: dict | None = None
) -> Provenance:
    """Record sha256 / size / format. hash_verified stays None until checked (AC-10, AC-13)."""
    return Provenance(
        path=str(path),
        sha256=sha256_file(path),
        size=path.stat().st_size,
        fmt=fmt,
        source_meta=dict(source_meta or {}),
        hash_verified=None,
    )


def verify_against_expected(
    prov: Provenance, expected_sha256: str
) -> tuple[Provenance, bool]:
    """Compare actual vs expected hash (AC-11). Returns (updated provenance, ok)."""
    ok = prov.sha256.lower() == expected_sha256.strip().lower()
    return replace(prov, hash_verified=ok), ok
