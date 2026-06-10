# modelseal

[![CI](https://github.com/leagames0221-sys/modelseal/actions/workflows/ci.yml/badge.svg)](https://github.com/leagames0221-sys/modelseal/actions/workflows/ci.yml)
![free](https://img.shields.io/badge/cost-free-brightgreen)
![local](https://img.shields.io/badge/runs-100%25%20local-blue)
![zero-deps](https://img.shields.io/badge/runtime%20deps-0-blueviolet)
![license](https://img.shields.io/badge/license-MIT-green)

**Inspection gate for AI model artifacts** — a non-executing pickle x-ray,
provenance verification, and approval-baseline diff for the model files you
download and deploy.

## Motivation

The AI supply chain has scanners for packages, source code, and runtime I/O.
The **model artifact itself** is the remaining gap, and it is hot for a reason:

- Loading a pickle-based checkpoint can execute code on your machine — this is a
  real, actively exploited attack path, not a theoretical one.
- In 2025, researchers disclosed zero-day bypasses in the de-facto standard
  pickle scanner: the *detector itself* gets evaded.
- "Safe-looking" formats can be spoofed by renaming an executable container.
- An artifact you approved last week can silently change underneath you.

The mature OSS scanners (picklescan, modelscan, modelaudit, fickling) all focus
on the first problem — malicious-code detection. **None of them verify where an
artifact came from, or whether it changed since you approved it.** modelseal
gates all three.

## What it does

| Layer | What | Key rules |
|---|---|---|
| ① **Malicious-code x-ray** | Static, **non-executing** opcode analysis of pickle-family artifacts (stdlib `pickletools`); nested archives included | `MS-PICKLE-DANGEROUS-IMPORT`, `MS-PICKLE-RECONSTRUCT` |
| ② **Provenance** | SHA-256 + size + format record; expected-hash verification; *unverified provenance is surfaced, never silently passed* | `MS-PROVENANCE-UNVERIFIED/-MISMATCH/-OK` |
| ③ **Approval baseline** | Snapshot approved artifacts; detect silent changes; a change that **raises** risk fails the gate unconditionally | `MS-BASELINE-CHANGED/-SEVERITY-UP/-ADDED/-REMOVED` |
| Format integrity | safetensors / GGUF header-vs-reality validation; extension spoofing detection | `MS-SAFETENSORS-MALFORMED`, `MS-GGUF-MALFORMED`, `MS-EXTENSION-SPOOF` |
| Fail-closed engine | Anything unparseable is a FAIL, never a silent pass | `MS-UNPARSEABLE` |

### Comparison with prior art

| Capability | picklescan | modelscan | modelaudit | fickling | **modelseal** |
|---|---|---|---|---|---|
| Malicious-code detection (pickle) | ✅ | ✅ | ✅ | ✅ | ✅ (decomposed reimplementation) |
| Provenance / expected-hash verification | — | — | — | — | ✅ |
| Approval-baseline diff (silent-change / risk-raise) | — | — | — | — | ✅ |
| Fail-closed on unparseable input | partial | partial | partial | n/a | ✅ (by design + regression-tested) |
| Runtime dependencies | several | several | several | several | **0 (stdlib only)** |

Detection classifications are sourced from the public scanners above and
reimplemented from scratch (attribution in `src/modelseal/packs/scanners/rules.py`;
fickling is design-inspiration only due to its LGPL license). See `docs/adr/0001`.

## Install & use

```bash
pip install -e .          # zero runtime dependencies

modelseal scan path/to/model.pt              # exit 0=PASS 1=WARN 2=FAIL
modelseal scan models/ --format sarif        # human | json | sarif (CI / code scanning)
modelseal scan model.pt --expect-hash model.pt=<sha256>

modelseal approve models/ --manifest baseline.json   # record what you reviewed
modelseal diff models/ --manifest baseline.json      # did anything silently change?
```

CI gate in one line:

```yaml
- run: modelseal diff models/ --manifest baseline.json   # non-zero exit blocks the pipeline
```

### Optional explanation layer (local LLM)

```bash
modelseal scan model.pt --explain     # plain-language summary via local Ollama
```

Requires a local [Ollama](https://ollama.com) (`MODELSEAL_OLLAMA_URL` /
`MODELSEAL_OLLAMA_MODEL` to override). The explanation **never changes the
verdict** — if Ollama is absent, the deterministic result stands unchanged.
No data leaves your machine: networking is mechanically confined to the
explain layer (AST-enforced in tests).

## Design

```
core/   (stdlib only, no network)        packs/scanners/  (stdlib, no network)
  contracts, engine (fail-closed),         pickle x-ray, archive, safetensors,
  provenance, baseline, render, ABC        gguf — selected by content, not extension
                                         packs/explain/   (urllib, the only network surface)
```

- Deterministic core decides; the LLM layer only explains (never the verdict).
- Scanners are selected by **content** (magic bytes / structure), so renaming an
  executable container to a "safe" extension surfaces as a finding.
- Bypass resistance: every publicly disclosed scanner-evasion class is
  reproduced as a neutralized synthetic fixture and must land at WARN-or-worse
  (`tests/test_bypass_probe.py`, 3/3 as of 2026-06).
- Specs, decisions and trade-offs: `docs/spec/`, `docs/adr/`.

## Threat-area mapping

| Area | Where modelseal sits |
|---|---|
| OWASP ML Security Top 10 — ML06 (supply chain) / ML10 (model poisoning, artifact level) | ①②③ |
| OWASP LLM Top 10 2025 — LLM03 (supply chain) / LLM05 (improper output handling — n/a, runtime tools cover this) | ①② |
| CI/CD model-registry gating | ③ + exit codes + SARIF |

## Limitations (honest)

- **Not a semantic pickle VM**: the x-ray tracks symbol references and
  reconstruction opcodes conservatively; it does not symbolically execute the
  stream. Pair with provenance + baseline rather than relying on ① alone.
- **No cryptographic signature verification yet** — hash comparison and source
  recording only (stdlib has no public-key verification; planned as an optional
  pack, see `docs/adr/0003`).
- **Weights-level backdoors are out of scope** (statistical/trojan analysis is a
  research area; no deterministic test exists).
- Findings on *unknown* formats are advisory (`MS-UNKNOWN-FORMAT` WARN) — the
  gate is strict only about formats that claim to be something verifiable.

## License

MIT
