# ADR 0016: Least-Privilege WFP Verifier Broker

- Status: Accepted
- Date: 2026-07-29
- Scope: Windows WFP browser-egress runtime verification only

## Context

The concrete WFP browser-egress policy and functional self-test pass from an
elevated deployment process. The former runtime verifier launched the
hash-pinned `d2i-desktop` image in a zero-capability AppContainer and called
`FwpmEngineGetSecurityInfo0` directly. From a medium parent token that call
fails with `ERROR_ACCESS_DENIED (0x00000005)`. Running the same path with an
enabled Administrators SID succeeds.

This is an access-check consequence, not a missing WFP object. The AppContainer
token is restricted. Granting the AppContainer SID `READ_CONTROL` and
`FWPM_ACTRL_OPEN` does not make the ordinary user-side access check succeed.
Granting broad engine rights to the user or AppContainer would expand the
runtime attack surface.

Microsoft documents the relevant rights separately:

- `FwpmEngineOpen0` requires `FWPM_ACTRL_OPEN`.
- fixed-key `Fwpm*GetByKey0` calls require `FWPM_ACTRL_READ` on the object.
- `FwpmEngineGetSecurityInfo0` follows the standard security-descriptor access
  contract and requires `READ_CONTROL` for owner/group/DACL reads.
- enumeration, add/delete, transaction, and security-descriptor mutation use
  distinct rights and are not required by this verifier.

References:

- <https://learn.microsoft.com/en-us/windows/win32/fwp/access-right-identifiers>
- <https://learn.microsoft.com/en-us/windows/win32/fwp/access-control>
- <https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmenginegetsecurityinfo0>
- <https://learn.microsoft.com/en-us/windows/win32/services/service-changes-for-windows-vista>
- <https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info>
- <https://learn.microsoft.com/en-us/windows/win32/services/localservice-account>
- <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
- <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid>
- <https://learn.microsoft.com/en-us/windows/uwp/communication/interprocess-communication>
- <https://learn.microsoft.com/en-us/windows/apps/develop/communication/interprocess-communication>

## Decision

Use a dedicated, demand-start, own-process Windows service:

- account: `NT AUTHORITY\LocalService`
- identity: a dedicated Service SID
- SID type: `SERVICE_SID_TYPE_RESTRICTED`
- start type: `SERVICE_DEMAND_START`
- required privileges: an empty service privilege allowlist
- executable: the hash-pinned, service-only `d2i-wfp-verifier-broker.exe`
- endpoint: one local, first-instance, remote-rejecting Named Pipe
- lifetime: one request, then service stop

The restricted Service SID is present as an enabled SID and a restricting SID.
Only that SID receives the WFP engine open/read-control ACE and fixed D2I
object read/read-control ACE. The AppContainer receives no WFP ACE.

The broker executable receives four additional fixed WFP filters:

- IPv4 loopback permit
- IPv4 non-loopback block
- IPv6 loopback permit
- IPv6 non-loopback block

These filters are application-ID bound, persistent, ACL protected, verified by
fixed GUID, and included in the signed receipt object set. The service-only
binary accepts no general CLI command and is loopback-only while the policy is
installed. The deployment/self-test CLI and medium runtime use the separate
`d2i-desktop.exe` image, so their control-process reachability is not confused
with the broker's network boundary.

## IPC Contract

An attempted direct AppContainer connection to the service pipe failed with
`ERROR_FILE_NOT_FOUND` while the same pipe was live and reachable by the
medium process. Adding an AppContainer ACE and Low Mandatory Label did not
change that result. This matches the documented AppContainer Named Pipe rule:
pipe access is package-scoped, and `\\.\pipe\LOCAL\` does not create a
cross-package service channel.

The accepted path is therefore:

```text
approved AppContainer child
-> one-time bounded handoff in an ACL-isolated runtime directory
-> approved medium d2i-desktop relay
-> authenticated Named Pipe
-> verifier service
```

The pipe is reachable only by SYSTEM, the Service SID, and the deployment user
SID. Its mandatory label is medium; the AppContainer has no pipe ACE and never
connects to the verifier service. The pipe uses
`\\.\pipe\LOCAL\<fixed-name>` and:

- `FILE_FLAG_FIRST_PIPE_INSTANCE`
- `PIPE_REJECT_REMOTE_CLIENTS`
- one instance and one operation
- explicit protected DACL for SYSTEM, the Service SID, and deployment user SID
- a Medium Mandatory Label
- maximum 64 KiB length-prefixed request and response
- bounded connect, read, and write deadlines
- identification-only client SQOS; the broker never impersonates
- `GetNamedPipeClientProcessId` before request processing and before response
- kernel-observed relay PID, user SID, session, integrity RID, elevation type,
  executable path, and executable hash validation

The AppContainer writes one request to a random, per-call runtime directory
whose protected DACL contains only SYSTEM, the interactive user, and the exact
AppContainer SID. It then waits for one relay response file. Paths and file
names are fixed relative to that directory, all writes are create-new, records
are bounded, symlinks and reparse escapes are rejected, and the whole directory
is removed on success or failure. The service never reads or writes this
directory.

`LocalService` cannot normally inspect a medium caller's token. Immediately
before connecting, the relay grants the exact Service SID query-only access to
its own process object (`PROCESS_QUERY_LIMITED_INFORMATION`) and token object
(`TOKEN_QUERY`). The relay grants the same two rights to the AppContainer child
objects it owns. These ACEs do not grant terminate, suspend, memory, handle
duplication, token adjustment, impersonation, or process-creation rights. They
also do not alter a WFP descriptor: the client updates only its own ephemeral
kernel process/token DACLs, and those objects disappear when the processes
exit.

After reading the request, the relay starts the demand-start service and sends
it unchanged. The service independently:

- requires the pipe client to match the pinned medium host token, session, and
  runtime executable hash
- requires the request relay PID to equal the kernel pipe-client PID
- opens the request's live AppContainer PID read-only
- checks user SID, session, AppContainer SID, low integrity, default elevation,
  and runtime executable hash
- checks the AppContainer is a direct child of the connected relay
- repeats the child identity and parent checks before writing the response

The request ID, challenge, relay PID, and AppContainer PID are in the signed
receipt. The relay can transport but cannot alter or redirect a valid receipt.
The AppContainer validates the receipt before emitting it, and the medium
runtime validates and consumes it again.

Unknown JSON fields, malformed frames, duplicate service starts, a pre-created
pipe endpoint, oversized input, stale deadlines, and identity mismatches fail
closed. Service-specific exit codes preserve the first bounded reject stage
without exposing request contents.

## Receipt and Key

The installer generates a dedicated Ed25519 key in memory. Its private seed is
protected with local-machine DPAPI using purpose-bound entropy and stored in a
file whose protected DACL grants read access only to SYSTEM, Administrators,
and the restricted Service SID. The dedicated service image similarly grants
that SID read/execute, but not write. The broker has no file-write code path.

`WfpVerificationRequest` pins:

- request ID and 32-byte random challenge
- relay PID and AppContainer child PID
- runtime, machine, user, and session binding
- canonical WFP policy digest
- provider, sublayer, browser filter, and verifier-network filter GUIDs
- Edge, EdgeDriver, functional report, and functional attestation hashes
- issued time and deadline

`SignedWfpVerificationReceipt` binds those values to:

- Service SID, verifier build ID, and verifier executable hash
- the same relay and AppContainer PID binding
- exact object and ACL results
- verifier executable IPv4/IPv6 loopback-only result
- verification timestamps and boot-monotonic sequence
- result/failure code and signer key ID

The AppContainer verifies the signature, request ID, challenge, TTL, all
bindings and hashes, verifier identity, all GUIDs, exact results, and the
functional attestation before emitting a receipt. The medium runtime verifies
and consumes it again in a probe-owned replay ledger. The protected activation
ledger prevents an attestation-backed binding from being activated twice.

## Audit

The broker does not write the filesystem. After AppContainer validation, the
medium runtime appends receipt-derived hash/ID/status events to the existing
protected deployment audit ledger. Failure to open, append, or reverify the
audit chain prevents binding evidence creation. Error text is hashed before it
enters the ledger.

## Rejected Alternatives

### Direct AppContainer WFP access

Rejected because it requires broadening engine or user rights and still
interacts poorly with restricted-token access checks.

### Administrator or sudo runtime

Rejected because deployment elevation must not become an adapter runtime
requirement.

### Restricted helper launched by the medium runtime

Rejected because the medium caller cannot safely mint the required WFP access
identity, and a reusable privileged host would expand the callable surface.

### Existing general privileged host endpoint

Rejected because no reviewed endpoint with the required single-operation,
Service-SID, no-write, no-network contract exists in this repository.

### General RPC or new IPC framework

Rejected because the service side still fits a one-operation Named Pipe and
its direct Windows caller-PID contract. Direct cross-package AppContainer
Named Pipe access is not supported by the documented package boundary, while
the existing bounded AppContainer artifact exchange can carry the secret-free
request and signed response without introducing a general IPC framework.

## Consequences

- WFP installation must occur after broker provisioning so object ACLs pin the
  Service SID.
- Functional attestation must exist before the immutable broker service
  allowlist is finalized.
- Broker-backed adapter configurations must pin a protected deployment audit
  root.
- Legacy v2 policies remain readable for elevated install/recall compatibility
  but are rejected by runtime verification.
- The dedicated broker executable is loopback-only for all token identities
  while the v3 WFP policy remains installed.
- The approved medium runtime is a data-only relay. It gains no WFP read or
  mutation right, receipt key access, service impersonation right, or general
  broker operation.
- Query-only Service SID ACEs exist only on the relay and child process/token
  kernel objects for the lifetime of those processes.
- Runtime handoff cleanup closes the AppContainer process handle before
  removing its one-time directory and treats cleanup failure as a failed
  verification. Deployment recall removes only the policy-matched service
  configuration, DPAPI key, and staged image from exact single-purpose roots.
- No Cognitive IR, Module SDK, UIA/Web observation, natural-language, GUI, or
  credential functionality is introduced by this decision.
