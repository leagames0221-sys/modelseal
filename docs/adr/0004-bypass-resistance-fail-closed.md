# ADR-0004 — Bypass resistance: fail-closed + content-based detection + disclosed-class regression

## Context
In 2025 JFrog disclosed multiple zero-day bypasses of the de-facto standard
pickle scanner — evidence that "the detector itself gets evaded" is the current
frontier. Full symbolic execution of the pickle VM (fickling's approach) is
LGPL-licensed and weeks of effort.

## Decision
Do not reimplement symbolic execution. Instead:
1. **Fail-closed**: any parse failure or scanner exception becomes a FAIL
   finding (`MS-UNPARSEABLE`) — structurally neutralizing the
   "crash/early-exit the scanner to slip past" class.
2. **Content-based format detection**: scanners are selected by magic bytes /
   structure, never by extension; disguises surface as findings.
3. **Disclosed-class regression suite**: each publicly documented evasion class
   is reproduced as a neutralized synthetic fixture (`tests/test_bypass_probe.py`)
   and must land at WARN-or-worse forever.

Probe result (2026-06-10): 3/3 classes detected at WARN-or-worse — decision
criterion met.

## Consequences
The fail-open hole that the incumbent scanners fell into is closed at the
design level. Full semantic analysis of the pickle VM is *not* guaranteed and
is documented as a limitation.

## Alternatives considered
Reimplementing symbolic execution — rejected: re-deriving an LGPL design at
high cost for marginal gain over fail-closed + regression coverage.
