# ADR-0006 — Network isolation to packs/explain + Provider ABC

## Context
Scanning must never transmit data externally; an optional local-LLM layer may
explain findings. Both needs must coexist without trust leakage.

## Decision
Networking imports are allowed **only** in `packs/explain` — enforced
mechanically by an AST-walking test over `core` and `packs/scanners`
(`tests/test_no_network_in_core.py`). The explanation layer sits behind a
`Provider` ABC (default: local Ollama via stdlib urllib; `MODELSEAL_OLLAMA_URL`
/ `MODELSEAL_OLLAMA_MODEL` env-swappable) and:
- never influences verdict / severity / exit code,
- fails soft: provider unreachable -> deterministic result stands unchanged,
- has a MockProvider so the full pipeline tests without any LLM.

## Consequences
With the explain layer disabled the tool is fully offline. The audit surface
for data egress is a single directory.

## Alternatives considered
Direct SDK integration — rejected: adds dependencies and makes the provider
non-swappable.
