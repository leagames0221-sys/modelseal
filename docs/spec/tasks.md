# modelseal — Tasks

> Status: Phases 1–3 complete (2026-06-10).
> Documentation discipline per requirements §5 applies to every deliverable.

## Task breakdown (dependency order)

| ID | Task | Deliverable | AC | Status |
|---|---|---|---|---|
| T-01 | scaffold + pyproject (`dependencies=[]`) | repo skeleton | AC-27 | ✅ |
| T-02 | core contracts | `core/contracts.py` | AC-26 | ✅ |
| T-03 | engine (content sniffing, fail-closed) | `core/engine.py` | AC-3,8,9 | ✅ |
| T-04 | provenance | `core/provenance.py` | AC-10..13 | ✅ |
| T-05 | baseline | `core/baseline.py` | AC-14..18 | ✅ |
| T-06 | pickle x-ray | `packs/scanners/{pickle_xray,rules,archive}.py` | AC-5..9 | ✅ |
| T-07 | format integrity | `packs/scanners/{safetensors_hdr,gguf_hdr}.py` | AC-19,20 | ✅ |
| T-08 | rendering | `core/render.py` (SARIF/JSON/human) | AC-25,26 | ✅ |
| T-09 | CLI | `cli.py` (exit 0/1/2) | AC-1,2 | ✅ |
| T-10 | explain layer | `packs/explain/ollama_provider.py` | AC-21..24 | ✅ |
| T-11 | tests + bypass probe | `tests/` (43 tests; probe 3/3) | AC-3,4 + ADR-0004 | ✅ |
| T-12 | README + ADRs | `README.md`, `docs/adr/0001..0006` | AC-29,30 | ✅ |
| T-13 | CI | pytest+ruff matrix (3.11/3.12) + secret scanning | — | ✅ |

Common verification per task: file-system check → `pytest` + `ruff check`
green → CLI smoke.

## Phases

- **Phase 1** — deterministic core (x-ray + provenance + baseline + CLI): the
  differentiators stand on their own, fully offline.
- **Phase 2** — format integrity (safetensors/GGUF), explain layer, and the
  bypass-resistance probe (decision criterion met: 3/3 disclosed classes ≥ WARN).
- **Phase 3** — ADRs, full README (comparison table, threat-area mapping,
  honest limitations), CI.

## Out of scope (this version)

Weight-level backdoor detection / dynamic sandbox / model-hub API integration /
fine-tuning inspection (see requirements §3).
