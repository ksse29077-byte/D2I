# ADR 0010: Separate Desktop Autonomy From Cognition And Learning

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I runtime, security, and desktop integration maintainers

## Context

D2I decisions are currently side-effect-free. Autonomous PC use adds local
files, processes, credentials, UI state, browsers, network communication,
destructive operations, replay risk, and time-of-check/time-of-use races.
Training before this boundary exists would produce action proposals without a
safe execution contract.

## Decision

1. Implement desktop autonomy as the separate `d2i-desktop` product.
2. Keep model inference and dataset preparation outside desktop adapters.
3. Accept only a closed, typed `DesktopOperation`; never accept shell text,
   scripts, arbitrary code, or untyped tool JSON at the execution boundary.
4. Bind every action to one successful, policy-allowed `DecisionEnvelope`,
   including build, package, request, decision, and evidence hashes.
5. Derive capability and risk in trusted Rust code rather than trusting model
   labels.
6. Require an exact policy-pinned adapter descriptor and deny network by
   default.
7. Require human approval for external communication, credentials, destructive
   actions, and privileged operations. Approval is Ed25519-signed and bound to
   the policy decision and adapter preparation.
8. Split execution into side-effect-free `prepare` and permit-bound `commit`.
   Recheck preconditions at commit.
9. Consume action IDs, approval IDs, and monotonically increasing session
   sequences once.
10. Sync an append-only hash-chain record before commit and append the outcome
    afterward. Never place returned payload bytes in the audit ledger.
11. Supply a deterministic virtual conformance adapter and a concrete local
    read-only filesystem adapter.
12. Keep host write, process, browser, native UI, clipboard, credential, and
    network adapters fail-closed until each reviewed platform API and isolation
    contract is implemented.

## Consequences

- Learning data can target a stable action vocabulary without granting host
  authority.
- Policy and approval are portable across future Windows, browser, and remote
  desktop adapters.
- Local file reads and directory listings are usable now beneath canonical
  allowlisted roots.
- Autonomous host mutation is intentionally unavailable in this baseline.
- A process crash after the external side effect but before the outcome append
  can leave a pending audit record; recovery must reconcile it before resuming.

## Validation

- Decision-envelope and evidence binding test
- canonical-root, symlink, bounded-read, and TOCTOU checks
- high-risk approval invariant and Ed25519 binding test
- approval/action replay rejection
- payload-free audit and hash-chain tamper test
- Draft 2020-12 action and policy schema tests
- deterministic virtual adapter conformance test
