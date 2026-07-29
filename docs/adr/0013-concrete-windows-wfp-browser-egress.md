# ADR 0013: Concrete Windows WFP Browser Egress

Runtime verification of this policy is superseded by
[ADR 0016](0016-least-privilege-wfp-verifier-broker.md). AppContainer processes
no longer receive direct WFP engine access under the v3 policy.

- Status: Accepted
- Date: 2026-07-28
- Decision owners: D2I runtime, security, and Windows integration maintainers

## Context

ADR 0012 defined signed browser-egress evidence but intentionally left the
enforcer deployment-specific. The external Microsoft Edge process is the
network actor; constraining the loopback WebDriver worker does not constrain
browser traffic. Windows Firewall rules also cannot safely express an HTTP
origin allowlist: rules operate on applications, addresses, ports, and
protocols, and a conflicting block takes precedence over an allow.

WFP can enforce an application/address boundary at ALE connect layers. It
still cannot authenticate HTTP origins or hostnames without a proxy or callout.

## Decision

1. Add the concrete provider identity `d2i.windows.wfp.loopback.v1`. It supports
   loopback-only browser deployments, not general Internet origin allowlists.
2. Pin the canonical browser executable path and SHA-256 in
   `WindowsWfpBrowserEgressPolicy`; include that policy in the certified
   `WindowsAdapterConfiguration`.
3. Install one fixed WFP identity marker, one maximum-weight persistent
   sublayer, and four persistent filters in one transaction:
   - IPv4 `127.0.0.0/8` permit, then application-wide IPv4 block;
   - IPv6 `::1/128` permit, then application-wide IPv6 block.
4. Match the browser with `FWPM_CONDITION_ALE_APP_ID` at
   `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`. Loopback permits have higher weight
   than catch-all blocks in the same sublayer. Filter blocks retain WFP's hard
   block behavior.
5. Keep the persistent sublayer and filters providerless. The provider object
   is an identity marker only, avoiding BFE disabling filters whose provider
   lacks an auto-start Windows service.
6. Verify every provider, sublayer, filter, action, flag, weight, layer,
   condition, application ID, and loopback range after installation and before
   probe, bind, prepare, and commit. Missing, disabled, or changed objects fail
   closed.
7. Give no WFP rights to the general Users group. A dedicated zero-capability
   AppContainer verifier SID receives only `READ_CONTROL | FWPM_ACTRL_OPEN`
   (`0x00020040`) on the filter engine and
   `READ_CONTROL | FWPM_ACTRL_READ` (`0x00020080`) on the six exact policy
   objects. It uses only exact-key reads; it receives no enumerate, add, delete,
   write, classify, subscribe, statistics, transaction, or change-security
   right.
   SYSTEM and Administrators retain the normalized WFP full-control mask
   `0x000f07ff`; the DACL is protected and contains exactly these three allow
   ACEs. Owner, group, SID, ACE type, mask, inheritance, and DACL protection
   are verified on install and every runtime check. The verifier's engine ACE
   is also verified and is revoked and rechecked during policy removal.
8. Run runtime WFP verification in the dedicated AppContainer process and
   return only a bounded exact-key observation. A privileged verifier service
   was considered but rejected for this deployment because it would add an
   always-privileged IPC and service-lifecycle boundary where object ACLs can
   provide the required read-only capability directly.
9. Require elevated deployment rights for WFP installation and removal.
   Installation is transactional, and a failed post-install exact check recalls
   the just-installed objects before returning an error.
10. Pin Microsoft Edge and EdgeDriver canonical paths, PE product versions, and
   SHA-256 hashes in a separate artifact. Require the first three version
   components to match.
11. Before production attestation, launch the pinned Edge image through the
    pinned EdgeDriver and run a functional boundary test. A local HTTP server
    bound to all IPv4 interfaces must first be reachable through the host's
    non-loopback address by the control process. Edge must then reach the same
    server through `127.0.0.1` and must not reach it through the non-loopback
    address during a bounded observation window.
12. Treat speculative and idle Edge preconnections as observations rather than
    positive signals. The bounded server accepts multiple connections and
    accepts only a complete request carrying the random path, nonce, and Host.
    The returned nonce must also appear in Edge page source. IPv4 and IPv6
    loopback telemetry remain separate.
13. Verify the exact WFP objects before and after the functional test. Emit a
    schema-validated report containing the policy observation, EdgeDriver pin
    hash, positive and negative observations, and a fail-closed pass value.
    The deployment `functional-attest` command opens the protected provider key
    and signs evidence only after this report passes.
14. Sign only functional attestation schema v2 for the concrete provider. The
    signed payload binds runtime and host/session, exact WFP object IDs, policy,
    Edge and EdgeDriver versions and hashes, canonical report hash, one-time
    activation challenge, all functional results, timestamps, expiry, and key
    ID. Concrete v1 evidence is rejected rather than inferred or migrated.
15. Consume the challenge and report hash in the existing protected activation
    ledger. Reused challenges, reports, evidence, certificates, or
    certifications and non-increasing observation time fail as replay.
    Deployment events use a separate protected hash-chained audit containing
    only bounded IDs and hashes.

## Consequences

- Concrete browser autonomy can be run with no non-loopback browser egress.
- Allowed browser origins must be `localhost`, `127.0.0.1`, or `[::1]`.
- Internet origin allowlisting remains unavailable until an enforcing local
  proxy or reviewed WFP callout can authenticate destinations above the IP
  layer.
- An administrator can still remove WFP objects. Per-operation verification
  narrows this race and fails subsequent work, but does not replace protected
  deployment administration or system-level monitoring.
- The verifier AppContainer is deliberately unable to enumerate the WFP
  namespace. Adding dynamic policy objects requires a reviewed ACL and schema
  migration.
- The functional test uses no Internet service. Its non-loopback control
  request distinguishes WFP enforcement from a generally unreachable test
  endpoint, while the loopback request distinguishes enforcement from a
  broken browser session.
- The existing signed external-provider contract remains available for a
  separately reviewed firewall, proxy, or WFP implementation.

## Validation

- exact policy and EdgeDriver JSON schema tests
- rejection of non-loopback origins for the concrete provider
- rejection of concrete-provider evidence through the generic signer
- HTTP `Content-Length` completion tests with a persistent connection
- exact Edge/EdgeDriver `150.0.4078.99` pin creation and verification
- real headless Edge navigation, text input, select, and submit E2E
- bounded local probe-server test and self-test report schema validation
- idle, malformed, partial-request, nonce, Host, and response-body validation
- exact protected object DACL and least-privilege verifier-process validation
- attestation v2 signature, expiry, stale report, policy, driver, report,
  runtime, host, and challenge mutation rejection
- activation challenge/report uniqueness and ledger time-rollback rejection
- protected deployment audit content and ACL tamper rejection
- deterministic UIA fixture pinned by PID, executable hash, and title hash
- opt-in real Edge WFP E2E requiring loopback delivery and non-loopback denial
- WFP installation attempt fails with `ERROR_ACCESS_DENIED` in a non-elevated
  session rather than emitting evidence or partial success

## Windows References

- WFP filter creation:
  <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0>
- WFP application IDs:
  <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmgetappidfromfilename0>
- WFP filter arbitration:
  <https://learn.microsoft.com/windows/win32/fwp/filter-arbitration>
- WFP access rights:
  <https://learn.microsoft.com/windows/win32/fwp/access-right-identifiers>
- WFP access control:
  <https://learn.microsoft.com/windows/win32/fwp/access-control>
- Provider security:
  <https://learn.microsoft.com/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovidersetsecurityinfobykey0>
- Filter security:
  <https://learn.microsoft.com/windows-hardware/drivers/ddi/fwpmk/nf-fwpmk-fwpmfiltersetsecurityinfobykey0>
- Microsoft Edge WebDriver:
  <https://learn.microsoft.com/microsoft-edge/webdriver/>
