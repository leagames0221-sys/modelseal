# ADR-0002 — Zero-dependency core + scanner packs boundary

## Context
Where do format-specific scanners live: inside `core` or as a separate layer?

## Decision
`core` holds only format-agnostic machinery (contracts, engine, provenance,
baseline, render, provider ABC). Format scanners live in `packs/scanners` and
are injected into the engine; `core` never imports `packs`. The whole runtime
is stdlib-only (`dependencies = []`); adding a runtime dependency requires a
new ADR.

## Consequences
Supporting a new format = one new scanner file; `core` stays untouched.
`clone -> pip install` works with no transitive supply-chain surface.

## Alternatives considered
Scanners inside `core` — rejected: every format addition would churn core
(open-closed violation) and blur the network-isolation boundary (ADR-0006).
