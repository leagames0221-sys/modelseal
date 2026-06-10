# ADR-0001 — Decomposed prior art: what we imitate, what we build

## Context
Four mature OSS scanners exist for model artifacts: picklescan (MIT), modelscan
(Apache-2.0), modelaudit (MIT), fickling (LGPL-3.0). A verified survey (2026-06)
showed all four concentrate on malicious-code detection; none ship provenance
verification or an approval-baseline diff.

## Decision
- **Malicious-code x-ray**: adopt the *published classifications and inspection
  structure* of picklescan / modelscan / modelaudit, reimplemented from scratch
  on stdlib `pickletools`. No third-party code vendored.
- **fickling (LGPL-3.0)**: design inspiration only — no code adopted (license
  boundary; permitted licenses are MIT/Apache/BSD/ISC).
- **SARIF output**: structure modeled on modelaudit's convention.
- **Provenance and baseline diff**: hash-record and normalized-manifest-diff
  patterns reused from internal cross-project experience; these two are the
  original contribution of this tool.

## Consequences
No license contamination. The differentiators (provenance, baseline) are owned
code. Detection rules carry source attribution in `packs/scanners/rules.py`.

## Alternatives considered
Importing picklescan as a dependency — rejected: violates the zero-dependency
core and would inherit the publicly disclosed bypass weaknesses (see ADR-0004).
