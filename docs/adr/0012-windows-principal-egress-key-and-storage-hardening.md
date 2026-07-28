# ADR 0012: Windows Principal, Egress, Key, And Storage Hardening

- Status: Accepted
- Date: 2026-07-28
- Decision owners: D2I runtime, security, and Windows integration maintainers

## Context

ADR 0011 activated four independently certified Windows adapters, but its Job
Object boundary did not provide a distinct principal or network isolation.
Probe and certification keys were raw local files, browser egress was an
unverified deployment assumption, and local audit/activation storage did not
pin its Windows ACL identity.

UI Automation must remain in the interactive user session. A WebDriver worker
contacts only loopback, while the external browser is the actual network actor.
Process children can use a stronger Windows token boundary independently.

## Decision

1. Extend the host binding with exact user SID, integrity-level RID, elevation
   type, and AppContainer state. Sign these fields in runtime evidence.
2. Provision one named AppContainer profile per reviewed process deployment.
   Pin both profile name and derived `S-1-15-2-*` SID in configuration and
   manifest.
3. Create each process child with
   `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, the pinned AppContainer SID,
   and zero capabilities. Verify the suspended child's token SID before
   resuming it. Retain Job Object limits and managed-child termination.
4. Mark the process adapter network-incapable and reject every
   `network_requested = true` intent. Deployment grants the profile only the
   minimum read/execute or read/write path ACLs it needs.
5. Keep UI Automation, file, and WebDriver workers in the ordinary session
   worker. Do not claim that their Job Object is a principal boundary.
6. Require WebDriver manifests to pin an external egress enforcement ID,
   policy hash, provider identity/key, session IDs, and allowed origins.
   Certification requires fresh provider-signed, deny-by-default evidence with
   an exact scope match. The certificate expires no later than that evidence.
7. Protect Ed25519 private keys with current-user DPAPI entropy bound to schema,
   key ID, role, user SID, and public key. Probe, certifier, and egress commands
   accept only a role-correct protected artifact.
8. Apply protected DACLs granting full control only to SYSTEM and the current
   user on protected key artifacts and Windows audit/activation storage.
   Persist owner/DACL descriptor hashes and verify them before read or append.
9. Keep external chain-head anchoring, organization identity, key rotation and
   revocation, browser firewall/proxy implementation, backup, and recovery as
   deployment responsibilities.

ADR 0013 subsequently implements one concrete loopback-only WFP provider while
retaining this external-provider boundary for other reviewed enforcers.

## Consequences

- Network-denied process actions now have an enforced Windows principal
  boundary in addition to resource containment.
- Network-enabled child processes remain unavailable until a separately
  designed and certified capability profile is approved.
- Browser activation fails closed without an external enforcer's valid signed
  evidence. D2I verifies evidence but does not configure WFP, a firewall, or a
  proxy.
- DPAPI prevents another Windows user from opening a copied local key envelope.
  It is not a replacement for HSM-backed organization custody or account
  separation.
- Protected DACL fingerprints detect descriptor drift. The authorized owner
  can still rewrite local data and hashes, so external anchoring remains
  required for stronger non-repudiation.
- UI Automation remains intentionally outside AppContainer because isolated
  window access would prevent the required interactive control.

## Validation

- DPAPI round-trip, purpose mismatch, and tamper rejection
- protected DACL descriptor stability and drift rejection
- zero-capability AppContainer token SID verification
- AppContainer process launch and managed termination
- process-network request denial
- signed browser-egress exact-scope and freshness verification
- actual WinForms `ValuePattern.SetValue` mutation
- stateful W3C WebDriver navigation, click, text, and select mutations
- opt-in real-browser local-form mutation test for deployments with a driver
  and active session
- full configuration, evidence, key, certification, and activation CLI path
- workspace format, lint, test, and release build gates

## Windows References

- AppContainer isolation:
  <https://learn.microsoft.com/windows/win32/secauthz/appcontainer-isolation>
- AppContainer process creation:
  <https://learn.microsoft.com/windows/win32/secauthz/implementing-an-appcontainer>
- `SECURITY_CAPABILITIES`:
  <https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-security_capabilities>
- `UpdateProcThreadAttribute`:
  <https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute>
- DPAPI `CryptProtectData`:
  <https://learn.microsoft.com/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata>
- `SetNamedSecurityInfo`:
  <https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfoa>
