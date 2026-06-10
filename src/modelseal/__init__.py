"""modelseal — inspection gate for AI model artifacts.

Public API:
    scan_path(path)         -> Report
    Report, Finding, Severity, Provenance
    Baseline                (approve / diff)
"""

from modelseal.core.baseline import Baseline
from modelseal.core.contracts import (
    Finding,
    Provenance,
    Report,
    Scanner,
    Severity,
)
from modelseal.core.engine import scan_path

__all__ = [
    "scan_path",
    "Report",
    "Finding",
    "Severity",
    "Provenance",
    "Scanner",
    "Baseline",
]

__version__ = "0.1.0"
