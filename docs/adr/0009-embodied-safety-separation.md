# ADR 0009: Separate Embodied Cognition From Safety And Motor Control

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I compiler, robotics, and safety maintainers

## Context

Robot sensor and action flows add hard deadlines, physical side effects,
hardware variability, fleet rollout risk, and emergency behavior. Folding
these responsibilities into the reference runtime would blur ownership and
could allow a cognition failure to bypass a safety controller.

## Decision

1. Implement embodied integration as the separate `d2i-embodied` product.
2. Keep D2I responsible only for cognition, high-level planning, evidence, and
   episodic memory.
3. Represent outputs as high-level `ActionIntent` values, never raw motor
   commands.
4. Reject `safety_loop` actions from the D2I planning path.
5. Require an intent-bound, unexpired external safety permit before hardware
   dispatch.
6. Default ROS 2, safety, and hardware implementations to unavailable or
   fail-closed until documented APIs are supplied.
7. Bind simulation replay to world, build, and package hashes and use trace
   time only.
8. Store robot episodes in an access-controlled append-only hash chain.
9. Represent fleet promotion as a signed staged-rollout record requiring
   package signature attestation, simulation qualification, hardware profiles,
   cohorts, approval, and a verified distinct rollback package.
10. Do not contact robots or mutate packages during promotion.
11. Require fresh signed runtime-binding evidence and consume it through a
    manifest-pinned append-only activation ledger before production adapter
    construction.

## Consequences

- The compiler/runtime remain usable without ROS 2 or robot dependencies.
- Emergency and motor-control correctness remains owned by dedicated external
  controllers.
- Concrete ROS 2 QoS, message, hardware, and safety protocols remain unresolved
  integration contracts.
- Fleet promotion is auditable but does not deploy.
- External key custody, package-signature verification, and ledger anchoring
  are required for production.
- Runtime binding proofs are one-shot, expire within 15 minutes, and cannot be
  activated twice through the same verified ledger.

## Validation

- Draft 2020-12 sensor/action schema tests
- safety-loop rejection and permit-binding tests
- in-memory ROS transport contract test
- deterministic simulation replay test
- hardware dispatch safety gate test
- robot-memory access and tamper test
- fleet signature, qualification, rollback, and package-immutability test
- runtime evidence signature/type-hash/QoS drift tests
- activation replay, rollback, expiry, and hash-chain tamper tests
