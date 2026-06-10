# ADR-0003 — Provenance: hash comparison first, cryptographic signatures later

## Context
The Python standard library provides cryptographic hashing (hashlib) but no
public-key signature verification. Full signature verification (sigstore-style)
would require third-party dependencies, in tension with the zero-dependency core.

## Decision
v0.1 provenance = SHA-256 computation, expected-hash comparison, and source
metadata recording. Crucially, *unverified provenance is surfaced as WARN* —
never an implicit pass. Signature verification is deferred to a future optional
pack (which will require its own ADR).

## Consequences
Zero-dependency core holds. The core value — "never silently trust an artifact
of unknown origin" — is delivered by the hash layer. The signature gap is an
honest, documented limitation in the README.

## Alternatives considered
Adding `cryptography` as a dependency now — rejected: breaks the zero-dep DNA
for a feature the optional-pack route can deliver later without compromise.
