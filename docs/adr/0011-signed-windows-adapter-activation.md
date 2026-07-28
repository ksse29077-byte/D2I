# ADR 0011: Signed Activation For Isolated Windows Adapters

- Status: Accepted
- Date: 2026-07-27
- Decision owners: D2I runtime, security, and Windows integration maintainers

Principal/network isolation, protected key custody, signed browser-egress
evidence, and protected ledger storage are refined by ADR 0012.

## Context

ADR 0010 defined desktop action, policy, approval, preparation, permit, and
audit contracts but deliberately left host-mutating integrations unavailable.
Activating Windows UI Automation, browser, file-write, and process capabilities
requires exact host and worker identity, independent certification, replay
protection, and capability-minimal isolation.

## Decision

1. Define one exact `WindowsAdapterConfiguration` for each capability group:
   UI Automation, W3C WebDriver, file write, and process management.
2. Pin the canonical worker executable hash, configuration hash, adapter
   descriptor, exact Windows build/architecture/session, and separate Ed25519
   attestor and certifier keys in a reviewed `WindowsRuntimeManifest`.
3. Have `ConcreteWindowsRuntimeBindingProbe` start the hash-pinned worker,
   place it in a bounded Windows Job Object, run a capability-specific probe,
   and sign an observation valid for no more than 15 minutes.
4. Permit an independent certifier to sign only a clean, exact comparison
   between the manifest and fresh probe evidence.
5. Consume each binding, evidence, and certificate exactly once in a
   manifest-pinned append-only activation ledger before constructing an
   adapter.
6. Consume the resulting opaque activation authority in a capability-specific
   adapter constructor. Recheck kind, descriptor, configuration hash, and
   certification lifetime on every prepare and commit.
7. Run each adapter in a separate instance of the same reviewed binary using a
   bounded framed stdin/stdout protocol. Configuration is immutable after the
   first request. Protocol failure or timeout terminates the whole Job Object.
8. Apply Job Object kill-on-close, active-process, and per-process-memory
   limits. Only the process adapter may create child processes.
9. Restrict UI Automation to exact PID, executable hash, title hash, unique
   AutomationId, and reviewed Invoke, Value, or Toggle control patterns.
10. Restrict browser control to a loopback W3C WebDriver endpoint, pinned
    session IDs and origins, CSS selectors, and protocol commands. Do not
    execute JavaScript.
11. Restrict file writes to canonical non-reparse roots, hash preconditions,
    same-volume temporary files, write-through atomic move, and post-write hash
    verification.
12. Restrict process launch to direct executable plus argv, exact executable
    hash, canonical working directory, and policy argument prefix. Permit
    termination only for children managed by that worker.
13. Keep clipboard and credential-provider integrations unavailable.

## Consequences

- The four Windows capability groups are independently reviewed, certified,
  activated, and policy-pinned.
- A valid certificate is necessary but insufficient: persistent one-time
  activation and the ordinary desktop policy/approval/audit path are also
  mandatory.
- A Job Object provides process-tree lifetime and resource containment. It is
  not a different Windows security principal, AppContainer, ACL boundary, or
  network sandbox.
- This ADR originally required a network-enabled policy for every process
  launch. ADR 0012 supersedes that temporary rule with a zero-capability
  AppContainer and denies network-requesting process intents.
- Browser origin is checked before interaction and after navigation. A redirect
  can still cause network traffic before the post-navigation check; deployment
  must enforce browser egress independently.
- Secure desktop access, browser download/upload governance, credential
  retrieval, external chain-head anchoring, and OS-authenticated key custody
  remain deployment requirements.

## Validation

- concrete probe and dual Ed25519 signature verification
- certificate tamper and activation replay rejection
- manifest-pinned append-only activation chain verification
- atomic canonical-root file write
- direct managed-child launch and termination
- Windows UI Automation top-level window enumeration
- loopback W3C WebDriver navigation with origin enforcement
- Draft 2020-12 schemas for configuration and activation artifacts
- workspace format, lint, test, and release build gates
