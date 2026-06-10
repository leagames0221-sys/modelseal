# ADR-0005 — Baseline manifest = file hash + scan summary

## Context
The baseline must support "an approved artifact silently changed" (WARN) and
"the change raised its risk" (unconditional FAIL). How much per-artifact state
should the manifest carry?

## Decision
Per artifact: SHA-256 + detected format + a scan summary of
`{max_severity, rule_ids}`. On diff, a changed artifact is re-scanned and its
summary compared against the approved one. No full opcode statistics are stored.

## Consequences
The manifest stays small, human-readable JSON (reviewable in a PR). Risk-raise
detection is a cheap deterministic comparison.

## Alternatives considered
- Hash only — rejected: cannot implement risk-raise detection.
- Full opcode/tensor statistics — rejected: heavy state for no requirement the
  summary doesn't already satisfy.
