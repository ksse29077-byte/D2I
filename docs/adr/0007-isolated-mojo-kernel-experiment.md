# ADR 0007: Isolated Mojo Score-Kernel Experiment

- Status: Accepted experiment; Mojo candidate rejected pending evidence
- Date: 2026-07-27
- Decision owners: D2I runtime maintainers

## Context

The existing benchmark profile identifies `case-retriever-compact` as the
largest executor latency at p50 8 ms. Its repeated case-match scoring is a pure,
bounded loop that can be isolated without exposing package, policy, or decision
contracts. The current host has Rust 1.86 but no Mojo compiler.

## Decision

1. Optimize the Rust baseline first by normalizing the query once.
2. Represent each case with three match bits and produce a 0-100 integer score.
3. Keep the active kernel in safe Rust under `d2i-kernel`.
4. Export an optional stateless C symbol named
   `d2i_score_match_masks_v1` from candidate libraries.
5. Pin experimental source to Mojo 1.0.0b2. Do not invoke Mojo from Cargo.
6. Require exact output equality, the same input and hardware, zero observable
   boundary copies, and at least 1.20x p50 speedup for adoption.
7. Record unavailable, incorrect, load-failed, and insufficient-gain outcomes
   as explicit rejection decisions.

## Consequences

- Core workspace builds and tests without Mojo, including with all Cargo
  features enabled.
- The package format and runtime ABI marker do not depend on Mojo.
- A C fixture verifies the import contract and result equality, but is not
  treated as Mojo performance evidence.
- Mojo remains rejected because no Mojo library can be built or measured on
  this host.
- The entire candidate path is removable without changing the Rust kernel or
  package artifacts.
