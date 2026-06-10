"""Default scanner assembly.

Top-level (not ``core``) so that ``core`` never imports ``packs``. This module
imports only stdlib-backed scanners (no network).
"""

from __future__ import annotations

from modelseal.core.contracts import Scanner
from modelseal.packs.scanners.archive import ArchiveScanner
from modelseal.packs.scanners.gguf_hdr import GgufScanner
from modelseal.packs.scanners.pickle_xray import PickleScanner
from modelseal.packs.scanners.safetensors_hdr import SafetensorsScanner


def default_scanners() -> list[Scanner]:
    # Order matters: archive (zip magic) first so a zip wearing a safe-format
    # extension is unpacked (and flagged) rather than mis-sniffed; bare pickle
    # last because its suffix heuristic is the broadest.
    return [ArchiveScanner(), SafetensorsScanner(), GgufScanner(), PickleScanner()]
