# modelseal — Design

> Status: approved 2026-06-10. Language: Python (pytest + ruff, hatchling).
> Zero-runtime-dependency core. Documentation discipline per requirements §5.

## 1. Architecture

```
   modelseal scan / approve / diff (cli.py)
        │
 ┌──────▼───────────────────────────────────────────────┐
 │ core/ (stdlib only, no network)                       │
 │  engine: content-based format detection → Scanner     │
 │          dispatch → aggregation (fail-closed:         │
 │          unparseable = FAIL)                          │
 │  provenance: SHA-256 + expected-hash + source record  │
 │  baseline: manifest save / diff / risk-raise = FAIL   │
 │  render: SARIF 2.1.0 / JSON / human-readable          │
 └──────┬───────────────────────────────┬────────────────┘
        │ Scanner ABC                   │ Provider ABC
 ┌──────▼──────────────────────┐  ┌─────▼────────────────┐
 │ packs/scanners/ (stdlib)    │  │ packs/explain/ (opt.) │
 │  pickle x-ray (signatures   │  │  Ollama via urllib —  │
 │  confined to rules.py §5),  │  │  the ONLY network     │
 │  archive (nested), safe-    │  │  surface; explains    │
 │  tensors / gguf integrity   │  │  findings, never the  │
 └─────────────────────────────┘  │  verdict              │
                                  └───────────────────────┘
```

The deterministic core completes the verdict; the explain layer only annotates
the Report (AC-22).

## 2. File structure

```
src/modelseal/
├── core/            # stdlib only, network imports forbidden
│   ├── contracts.py # Severity, Finding, Provenance, Report, Scanner/Provider ABC
│   ├── engine.py    # content sniffing → dispatch → fail-closed aggregation
│   ├── provenance.py
│   ├── baseline.py  # human-readable JSON manifest, approve/diff
│   ├── render.py    # SARIF / JSON / human
│   └── provider.py  # (reserved; MockProvider currently in contracts)
├── packs/
│   ├── scanners/    # core + stdlib, no network
│   │   ├── pickle_xray.py   # non-executing opcode walk
│   │   ├── rules.py         # ★ sole home of concrete signatures (§5)
│   │   ├── archive.py       # zip checkpoints, nested dispatch, spoof detection
│   │   ├── safetensors_hdr.py
│   │   └── gguf_hdr.py
│   └── explain/     # ★ the only directory allowed to import networking
│       └── ollama_provider.py
├── registry.py      # default scanner assembly (keeps core ignorant of packs)
└── cli.py           # scan/approve/diff, exit 0/1/2
tests/               # fixtures are neutralized synthetic samples only
docs/adr/            # ADR-0001..0006
```

### Dependency rules

| Module | May depend on | Forbidden | Why |
|---|---|---|---|
| `core/*` | stdlib | packs / 3rd-party / network | zero-dep core (AC-27) |
| `packs/scanners/*` | core + stdlib | network / 3rd-party | inspections are offline (AC-4) |
| `packs/explain/*` | core + stdlib urllib | extra packages | network isolation (ADR-0006) |
| `cli.py` | core + packs | — | assembly layer |

Invariant: `core` and `packs/scanners` never reach a networking module in
their import graph — enforced by `tests/test_no_network_in_core.py` (AST walk).

## 3. Key contracts

```python
class Severity(IntEnum): INFO; WARN; FAIL          # ordered
@dataclass(frozen=True)
class Finding: rule_id; severity; location; message
@dataclass(frozen=True)
class Provenance: path; sha256; size; fmt; source_meta; hash_verified  # None = unverified -> WARN
@dataclass
class Report: findings; provenance; explanation    # verdict/exit derived from max severity
class Scanner(ABC): sniff(header, path) -> bool; scan(path) -> list[Finding]
```

Baseline manifest entry: `{sha256, fmt, scan_summary: {max_severity, rule_ids}}`
(ADR-0005) — risk-raise detection is a cheap deterministic comparison.

## 4. Decisions

Recorded as ADRs (see `docs/adr/`):
- **0001** decomposed prior art — what is imitated vs built, license boundaries.
- **0002** zero-dep core + scanner packs boundary.
- **0003** provenance = hash comparison first; signatures as a future optional pack.
- **0004** bypass resistance = fail-closed + content-based detection +
  disclosed-class regression fixtures (probe result 2026-06-10: 3/3 classes
  detected at WARN-or-worse).
- **0005** baseline manifest granularity (hash + scan summary).
- **0006** network isolation to `packs/explain` + Provider ABC.

## 5. Test strategy

- pytest + ruff; mock provider lets the full pipeline run with no LLM.
- `test_no_network_in_core.py` — AST-enforced network isolation.
- `test_non_execution.py` — deserialization functions are patched to raise;
  scans must complete anyway (proves AC-3 mechanically).
- `test_bypass_probe.py` — each publicly disclosed scanner-evasion class as a
  neutralized synthetic fixture; must stay WARN-or-worse forever.
