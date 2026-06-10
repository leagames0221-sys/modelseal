# modelseal — Requirements (EARS)

> Status: approved 2026-06-10.
> Documentation discipline: this spec never enumerates concrete dangerous
> opcode/import names in prose; it references the classifications published by
> prior scanners. Concrete signatures live only in code + fixtures (see §5).

## 0. Mission

An inspection gate CLI for off-the-shelf AI model files: a non-executing x-ray
for pickle-family artifacts (deterministic), provenance verification, and an
approval-baseline diff that catches artifacts which were "tampered, of unknown
origin, or silently changed". Free, local, zero-dependency core.

Differentiator (verified against the four public OSS scanners — picklescan,
modelscan, modelaudit, fickling): all four concentrate on malicious-code
detection; **none ship provenance verification or an approval-baseline diff**.
②③ below are therefore the original contribution.

## 1. Terms (fixed EARS subjects)

- **Artifact** — one model file, or a model directory (a set of artifacts).
- **Scanner** — a format-specific inspector returning Findings. Format is
  determined by **content** (magic bytes / structure), never by extension.
- **Finding** — one detection: `{rule_id, severity: INFO|WARN|FAIL, location, message}`.
- **Report** — aggregate of one scan: verdict `PASS|WARN|FAIL` + findings;
  renderable as SARIF / JSON / human-readable.
- **Provenance** — origin record (cryptographic hash, size, format, source
  metadata, verification result).
- **Baseline** — a normalized snapshot (manifest) of artifacts at approval
  time; later scans diff against it.
- **Provider** — optional explanation-layer LLM abstraction (default: local
  Ollama). **Never participates in the verdict.**

## 2. Acceptance criteria (EARS)

### 2.1 Core contract / CLI
- **AC-1** THE SYSTEM SHALL provide `scan` / `approve` / `diff` subcommands.
- **AC-2** WHEN `scan` completes THE SYSTEM SHALL reflect the verdict in the
  exit code (PASS=0 / WARN=1 / FAIL=2) so CI can gate on it.
- **AC-3** THE SYSTEM SHALL never load, execute, or deserialize an artifact
  (static analysis only).
- **AC-4** THE SYSTEM SHALL run every inspection without any external network
  communication (zero data egress; mechanically enforced by tests).

### 2.2 ① Malicious-code x-ray (pickle family, deterministic)
- **AC-5** WHEN scanning a pickle-family artifact THE SYSTEM SHALL analyze the
  opcode stream non-executively via stdlib `pickletools` machinery.
- **AC-6** THE SYSTEM SHALL apply a detection rule set based on the known
  dangerous opcode classes / import classifications published by prior
  scanners (picklescan / modelscan / modelaudit), emitting severity-tagged
  Findings. Concrete signatures are kept in code/fixtures only (§5).
- **AC-7** WHEN scanning an archive-type artifact (zip-based checkpoints) THE
  SYSTEM SHALL enumerate members and inspect nested serialized data with the
  same rules.
- **AC-8** IF parsing an artifact fails midway (corrupt / truncated / unknown
  structure) THEN THE SYSTEM SHALL report it as "uninspectable" and **FAIL
  (fail-closed)** — countering the disclosed class of bypasses that work by
  making the scanner exit early.
- **AC-9** WHEN the detected format disagrees with the extension (spoofing /
  polyglot indicators) THE SYSTEM SHALL emit WARN-or-worse and continue with
  **content-based** detection.

### 2.3 ② Provenance
- **AC-10** WHEN scanning THE SYSTEM SHALL produce a Provenance record with
  SHA-256, size, and detected format.
- **AC-11** WHERE an expected hash is supplied THE SYSTEM SHALL compare it to
  the actual hash and report a mismatch as FAIL.
- **AC-12** WHERE source metadata is supplied THE SYSTEM SHALL persist it in
  the Provenance record and include it in the Report.
- **AC-13** IF neither an expected hash nor a Baseline is supplied THEN THE
  SYSTEM SHALL surface "provenance unverified" as WARN (never an implicit PASS).

### 2.4 ③ Approval-baseline diff
- **AC-14** WHEN `approve` runs THE SYSTEM SHALL save a normalized manifest
  (per-artifact hash, format, scan summary) as the Baseline.
- **AC-15** WHEN `diff` runs against a Baseline THE SYSTEM SHALL
  deterministically enumerate added / removed / changed artifacts.
- **AC-16** IF an artifact's content changed after approval THEN THE SYSTEM
  SHALL report the change as WARN-or-worse (silent-change detection).
- **AC-17** IF the changed artifact now produces a higher severity than at
  approval time THEN THE SYSTEM SHALL report FAIL (a risk-raising change is an
  unconditional failure).
- **AC-18** THE SYSTEM SHALL store the Baseline in a human-readable, reviewable
  text format.

### 2.5 Non-code-execution formats (safetensors / GGUF)
- **AC-19** WHERE an artifact is a non-code-execution format THE SYSTEM SHALL
  apply header-integrity validation (declaration vs reality) plus ② and ③
  (the code x-ray is pickle-family-specific by design).
- **AC-20** IF a non-code-execution format's header declaration and actual
  content disagree THEN THE SYSTEM SHALL report FAIL (catching disguises that
  wear a "safe" format).

### 2.6 Optional LLM explanation layer (verdict-neutral)
- **AC-21** WHERE a Provider is enabled THE SYSTEM SHALL attach a
  plain-language explanation / remediation draft for the Findings.
- **AC-22** THE SYSTEM SHALL never let Provider output alter verdict /
  severity / exit code.
- **AC-23** IF the Provider is unset or unreachable THEN THE SYSTEM SHALL skip
  the explanation and complete on the deterministic result alone.
- **AC-24** THE SYSTEM SHALL expose a Provider ABC with environment-variable
  swapping (default: local Ollama) and a mock for LLM-absent testing.

### 2.7 Output / observability
- **AC-25** THE SYSTEM SHALL render Reports as SARIF 2.1.0 / JSON /
  human-readable text.
- **AC-26** THE SYSTEM SHALL give every Finding a stable `rule_id`, comparable
  across baselines and versions.

### 2.8 Distribution / constraints
- **AC-27** THE SYSTEM SHALL keep the core at **zero runtime dependencies**
  (stdlib only); any new runtime dependency requires an ADR.
- **AC-28** THE SYSTEM SHALL work fully (explanation layer when Ollama is
  present) from `clone -> one command`, free, on a consumer laptop.
- **AC-29** THE SYSTEM SHALL document a capability comparison against the four
  prior OSS scanners and its threat-area positioning in the README.
- **AC-30** THE SYSTEM SHALL pin the prior-art adoption policy (what is
  decomposed-adopted vs inspiration-only, with licenses) in ADR-0001.

## 3. Out of scope (this version)
- Statistical weight-level backdoor/trojan detection (research area).
- Dynamic sandbox loading (contradicts the non-execution principle, AC-3).
- Model-hub API integration (acquisition is the user's side; this tool inspects).
- Training / fine-tuning inspection.

## 5. Documentation discipline (security)
1. Never enumerate concrete dangerous opcode/import names in prose docs;
   reference the classifications published by prior scanners instead.
2. Concrete signatures and payload specifics live only in code
   (`packs/scanners/rules.py`, with source/license attribution) and test
   fixtures.
3. Fixtures are neutralized synthetic samples only (no working payloads, no
   real malware ever committed).
