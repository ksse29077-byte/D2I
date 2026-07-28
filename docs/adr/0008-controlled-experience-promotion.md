# ADR 0008: Controlled Experience Promotion

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I compiler and safety maintainers

## Context

Operational outcomes can improve retrieval, rules, executors, and routing, but
direct online updates would break package immutability, reproducibility, and
offline safety. Feedback is untrusted and can be duplicated, poisoned,
misattributed, or drawn from a shifted distribution.

## Decision

1. Store strict Episode v1 records in an access-controlled append-only
   SHA-256 hash chain.
2. Bind each episode and candidate to a verified build ID and package content
   hash.
3. Quarantine untrusted, unknown-outcome, and base-mismatched episodes.
4. Split by situation hash to prevent train/validation/test leakage.
5. Emit adaptation proposals as non-executable metadata in a physically
   separate candidate bundle.
6. Require the existing packaged gold set, baseline comparison, zero critical
   error increase, no regression, no leakage, no poisoning flags, and no
   unresolved distribution shift.
7. Require explicit human approval, shadow/canary metadata, and the exact base
   rollback target.
8. Sign each promotion with Ed25519 and chain promotion records by hash.
9. Interpret promotion only as approval for a future build input. Never mutate
   a production package in place.

## Consequences

- Every candidate and promotion is reproducible and auditable by content hash.
- Production packages and loaded runtimes remain unchanged during Phase 8.
- Rule and refit proposals require later implementation and evaluation.
- Ed25519 key custody and approver identity binding remain deployment concerns.
- Candidate evaluation is metadata-only until a future compiler consumes an
  approved proposal into a new immutable package.
