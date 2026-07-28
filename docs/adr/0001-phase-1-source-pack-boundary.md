# ADR 0001: Phase 1 Source Pack Boundary

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I compiler maintainers

## Context

Domain Source Packs are untrusted, portable build inputs. Phase 1 needs
deterministic discovery and useful aggregated diagnostics without introducing
Domain IR, package, runtime, or network behavior. Path and schema resolution
must behave consistently across supported platforms.

## Decision

1. `domain.yaml` uses strict typed deserialization and rejects unknown fields.
2. Every source and manifest reference is rooted under one canonical source
   directory. Absolute paths, traversal, missing targets, and all symbolic
   links are rejected.
3. Source files are read through a 16 MiB bound; CSV and JSONL are additionally
   bounded to 100,000 records.
4. Inventory entries are sorted by normalized relative path. SHA-256
   fingerprints include path, byte size, and content hash, but no timestamps.
5. `sources.lock` is deterministic JSON and is excluded from its own inventory.
6. JSON Schema draft 2020-12 supports bundled relative references registered
   in memory. External URL, root-absolute, and traversal `$ref` values fail
   before compilation. Resolver features that can access HTTP or files are
   disabled.
7. Core validation accumulates structured diagnostics. CLI rendering and
   process exit mapping remain in `d2i-cli`.

## Consequences

- Identical content produces identical inventory and lock hashes across
  timestamp-only changes and directory enumeration order.
- Source packs cannot use symlinks, including safe in-root links. This is a
  deliberate portability and cycle-prevention restriction.
- Large source material must be split before compilation.
- `serde_yaml` is accepted temporarily despite its deprecated status and
  `unsafe-libyaml` dependency; migration is tracked in the dependency policy.
- The procedure and rule checks are reference-level validation only. Their
  complete typed contracts belong to Phase 2 IR and require a later ADR if
  they change this source boundary.
