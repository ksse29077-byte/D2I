# Desktop Autonomy Foundation

`products/d2i-desktop` is the side-effect boundary between a D2I runtime
decision and an operating-system action. It has no dependency on
`d2i-learning` or `d2i-embodied`.

## Execution Protocol

```text
verified DecisionEnvelope
  -> typed DesktopActionIntent
  -> actor / capability / path / executable / origin policy
  -> adapter prepare (no side effect)
  -> optional human review of exact preparation
  -> signed HumanApproval
  -> short-lived ExecutionPermit
  -> durable Prepared audit record
  -> adapter commit with precondition recheck
  -> payload-free outcome audit record
```

`DesktopActionIntent` carries request, build, package, decision, evidence,
session, sequence, expiry, and idempotency identities. Capability and risk are
computed from the closed `DesktopOperation` enum. Model output cannot mark a
destructive operation as read-only.

## Policy

`DesktopPolicy` is deny-by-default and pins:

- actor roles;
- capabilities;
- canonical read and write roots;
- executable paths, hashes, argument prefixes, and network eligibility;
- network origins;
- exact adapter descriptor hashes;
- approver public keys;
- action lifetime and per-session action budgets.

External communication, credential-sensitive, destructive, and privileged
operations always require a signed human approval. A policy may additionally
require approval for reversible or read-only work.

## Adapters

`UnavailableDesktopAdapter` is the default and cannot prepare or execute.

`OfflineConformanceDesktopAdapter` is a deterministic virtual desktop used to
exercise every capability contract without reading or changing the host.
Browser, process, and UI results from this adapter are simulation evidence, not
proof of an OS integration.

`LocalReadOnlyDesktopAdapter` is a concrete host adapter for only:

- bounded regular-file reads;
- bounded deterministic directory listings.

It canonicalizes configured roots, rejects symlink roots and targets, verifies
root confinement, captures a preparation snapshot, and rejects target changes
at commit. Returned bytes are never copied into the audit ledger.

Four Windows adapters are now available behind signed runtime certification and
one-time persistent activation:

- `WindowsUiAutomationAdapter`: top-level window enumeration and exact
  PID/executable-hash/title-hash/AutomationId Invoke, Value, and Toggle actions;
- `WindowsWebDriverAdapter`: loopback W3C WebDriver with pinned sessions,
  origins, and CSS selectors, without JavaScript execution. Its concrete
  Windows mode continuously verifies an exact browser-hash-pinned WFP
  loopback-only policy;
- `WindowsFileWriteAdapter`: canonical non-reparse roots, hash preconditions,
  atomic replacement, and post-write verification;
- `WindowsProcessAdapter`: direct executable plus argv, hash-pinned binaries,
  canonical working directories, zero-capability AppContainer children, and
  managed-child-only termination.

Each adapter runs in a dedicated Windows Job Object worker with kill-on-close,
active-process, per-process-memory, request-size, and timeout bounds. The
worker executable and immutable configuration are hash-pinned. Process
children add a reviewed AppContainer profile/SID with no capabilities; the
other workers remain ordinary user-session processes because UI Automation
cannot cross that window-isolation boundary.

## Windows Certification And Activation

```text
reviewed WindowsRuntimeManifest
  + fresh ConcreteWindowsRuntimeBindingProbe evidence
  + deployment attestor signature
  -> independent exact-match certification
  + certifier signature
  -> append-only one-time activation ledger
  -> opaque ActivatedWindowsBinding
  -> one capability-specific adapter constructor
```

Evidence and certification expire within 15 minutes. Host build, architecture,
interactive session, user SID, integrity level, elevation type, adapter
descriptor, worker hash, configuration hash, capability readiness, Job Object
limits, and process AppContainer SID must match exactly. WebDriver bindings
also require fresh, provider-signed deny-by-default egress evidence whose
policy hash, sessions, origins, and provider key match the manifest. Duplicate
binding, evidence, or certificate identities and observation-time rollback are
rejected. A configuration containing `WindowsWfpBrowserEgressPolicy` also
requires the evidence enforcement ID, provider ID, and policy hash to match.
The provider, sublayer, four filters, application ID, actions, weights, and
loopback ranges are checked before probe, bind, prepare, and commit.
Concrete WFP bindings accept only functional attestation v2. The attestation
also pins the exact EdgeDriver hash, canonical self-test report hash, and
one-time activation challenge. The protected activation ledger consumes the
challenge and report hash and rejects either value appearing again.

Runtime WFP checks do not grant WFP visibility to an ordinary medium-token
process or the Users group. A zero-capability verifier AppContainer has only
`READ_CONTROL | FWPM_ACTRL_OPEN` on the filter engine and
`READ_CONTROL | FWPM_ACTRL_READ` on the fixed provider, sublayer, and four
filters. It performs exact-key reads and emits a bounded observation. Any
engine ACE, owner, SID, object DACL, condition, weight, or application binding
drift fails closed.

## Approval Flow

For directly allowed read-only work, `DesktopExecutor::execute` performs
prepare and commit in one call.

For approval-required work:

1. Call `DesktopExecutor::prepare`.
2. Present the returned policy decision and `PreparedAction` through the
   organization approval service.
3. Sign with `sign_approval` or produce the identical external Ed25519
   artifact.
4. Call `DesktopExecutor::commit`.

An abandoned preparation must be closed with `DesktopExecutor::cancel`.

## Audit And Recovery

`initialize_audit_ledger` creates a session-pinned manifest and JSONL hash
chain. The executor syncs an authorized preparation before calling the adapter,
then records success or failure. Audit records contain hashes and bounded
metadata only.

On Windows, audit and activation roots, manifests/policies, and record files
receive protected DACLs granting full control only to the current user and
SYSTEM. Their owner/DACL descriptor hashes are pinned and checked before read
or append. A changed descriptor fails closed.

`verify_audit_ledger` detects tampering, sequence rollback, broken predecessor
hashes, duplicate preparation, and terminal records without a prepared
predecessor. A nonempty `pending_prepared_actions` result requires operator
reconciliation before the session is resumed.

`replay_audit` compares the verified session, record count, terminal chain hash,
and pending-action state with a checked-in expectation. A fresh executor
refuses to attach to a nonempty ledger; crash recovery is therefore fail-closed
rather than silently replaying a side effect.

## CLI

```text
cargo run -p d2i-desktop -- policy-check examples/desktop/desktop-policy.template.json
cargo run -p d2i-desktop -- adapter-check examples/desktop/offline-adapter.json
cargo run -p d2i-desktop -- intent-check action.json
cargo run -p d2i-desktop -- audit-check desktop-audit
cargo run -p d2i-desktop -- audit-replay desktop-audit expected-audit.json
cargo run -p d2i-desktop -- local-readonly-descriptor C:\approved-root
cargo run -p d2i-desktop -- windows-config-check windows-file.json
cargo run -p d2i-desktop -- windows-manifest-check windows-manifest.json
cargo run -p d2i-desktop -- windows-appcontainer-provision D2I.Process.Production
cargo run -p d2i-desktop -- windows-appcontainer-grant D2I.Process.Production read_write true C:\D2I-Approved
cargo run -p d2i-desktop -- windows-key-protect attestor-key.hex runtime-attestor-key binding_attestor attestor-key.protected.json
cargo run -p d2i-desktop -- windows-key-protect certifier-key.hex release-certifier-key certifier certifier-key.protected.json
cargo run -p d2i-desktop -- windows-key-protect egress-key.hex edge-egress-provider browser_egress_provider egress-provider-key.protected.json
cargo run -p d2i-desktop -- windows-browser-egress-sign egress-input.json egress-provider-key.protected.json egress-evidence.json
cargo run -p d2i-desktop -- windows-wfp-egress-policy production-edge-loopback "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" wfp-policy.json
cargo run -p d2i-desktop -- windows-edgedriver-pin "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" C:\D2I\msedgedriver.exe edge-driver-pin.json
cargo run -p d2i-desktop -- windows-wfp-egress-install wfp-policy.json
cargo run -p d2i-desktop -- windows-wfp-egress-check wfp-policy.json
cargo run -p d2i-desktop -- windows-wfp-egress-remove wfp-policy.json
cargo run -p d2i-desktop -- windows-wfp-egress-runtime-check windows-webdriver.json
cargo run -p d2i-desktop -- windows-edgedriver-check edge-driver-pin.json
cargo run -p d2i-desktop -- windows-wfp-egress-self-test wfp-policy.json edge-driver-pin.json activation-challenge-0001 5000 wfp-self-test-report.json
cargo run -p d2i-desktop -- windows-wfp-egress-functional-attest wfp-policy.json edge-driver-pin.json egress-input-v2.json egress-provider-key.protected.json activation-challenge-0001 5000 wfp-functional-report.json wfp-attestation-v2.json
cargo run -p d2i-desktop -- windows-wfp-egress-attestation-check wfp-attestation-v2.json <provider-public-key> <now-unix-seconds>
cargo run -p d2i-desktop -- windows-deployment-audit-init deployment-audit deployment-audit-1 deployment-session-1 128 <now-unix-ms>
cargo run -p d2i-desktop -- windows-deployment-audit-record deployment-audit deployment-event.json
cargo run -p d2i-desktop -- windows-deployment-audit-check deployment-audit
cargo run -p d2i-desktop -- windows-probe windows-file.json binding-1 integration-1 1000 1600 runtime-attestor attestor-key.protected.json evidence.json
cargo run -p d2i-desktop -- windows-certify windows-manifest.json evidence.json certificate-1 release-certifier certifier-key.protected.json 1001 report.json certificate.json
cargo run -p d2i-desktop -- windows-certification-check windows-manifest.json evidence.json certificate.json 1002
cargo run -p d2i-desktop -- windows-activation-init activation-ledger ledger-1 windows-manifest.json deployment-agent 10000
cargo run -p d2i-desktop -- windows-activate activation-ledger deployment-agent windows-manifest.json evidence.json certificate.json 1002
cargo run -p d2i-desktop -- windows-activation-check activation-ledger
```

`windows-probe` starts only the configured isolated worker and performs its
bounded capability probe. The browser probe contacts only the configured
loopback WebDriver endpoint. Concrete WFP checks run in the dedicated
least-privilege verifier profile. WFP policy installation and removal require
an elevated deployment session. `windows-browser-egress-sign` remains for
reviewed external providers and rejects the concrete WFP provider ID; the
legacy concrete `windows-wfp-egress-attest` path is explicitly rejected.

`windows-edgedriver-pin` records canonical browser/driver paths, PE product
versions, and SHA-256 hashes. Verification requires the first three components
of the four-part Edge and EdgeDriver versions to match.
`windows-wfp-egress-self-test` verifies the exact WFP objects before and after
starting a fresh pinned Edge session and profile. Its bounded multi-connection
servers tolerate idle/preconnect sockets but accept only complete requests
with the random path, nonce, and Host. Edge must also render the response nonce.
It first proves that an all-interface local test server is reachable through a
non-loopback IPv4 address by the control process, then requires Edge loopback
delivery and the absence of direct-IP, DNS, and redirect non-loopback delivery.
IPv6 loopback is required; non-loopback IPv6 must be blocked or reported as
explicitly blocked when no usable interface exists. It performs no Internet
request and writes a
`windows-wfp-browser-egress-self-test-report.schema.json` artifact.
`windows-wfp-egress-functional-attest` runs the same test and opens the
protected provider key only after it passes; this is the production deployment
path. The v2 attestation is valid for at most five minutes and binds the report,
policy, Edge, EdgeDriver, runtime, host/session, scope, and one-time challenge.
`windows-wfp-egress-attestation-check` returns the canonical attestation hash
needed by the manifest.

`windows-key-protect` is the only command that
accepts an initial bounded raw key. It emits a current-user DPAPI envelope
bound to key ID, role, user SID, and public key, then applies the protected
DACL. Probe, egress signing, and certification accept only the role-correct
protected artifact.

The default suite uses a stateful W3C protocol fixture. To run the opt-in
mutation test against an already-created real browser session:

```text
$env:D2I_TEST_WEBDRIVER_ENDPOINT = "http://127.0.0.1:4444"
$env:D2I_TEST_WEBDRIVER_SESSION_ID = "<active-session-id>"
cargo test -p d2i-desktop --test windows_adapters real_webdriver_mutates_and_submits_local_html_form -- --ignored
```

The test serves a loopback HTML form and verifies navigation, text input,
option selection, submit click, and the received form values.

After an elevated deployment has installed the policy, run the opt-in
functional WFP E2E with the exact checked artifacts:

```text
$env:D2I_TEST_WFP_POLICY = "H:\D2I_Compiler_Codex_Work_Order\build\windows-e2e\wfp-policy.json"
$env:D2I_TEST_EDGE_DRIVER_PIN = "H:\D2I_Compiler_Codex_Work_Order\build\windows-e2e\edge-driver-pin.json"
cargo test -p d2i-desktop --test windows_adapters installed_wfp_policy_blocks_real_edge_non_loopback_egress -- --ignored
```

The final deployment replay consumes the fresh concrete artifacts and performs
activation-ledger admission, adapter binding, loopback Click/Type/Select, a
normal-process non-loopback control connection, same-Edge non-loopback denial,
and identical activation replay rejection:

```text
$env:D2I_TEST_WINDOWS_CONFIG = "<windows-webdriver-config.json>"
$env:D2I_TEST_WINDOWS_MANIFEST = "<windows-webdriver-manifest.json>"
$env:D2I_TEST_WINDOWS_EVIDENCE = "<windows-binding-evidence.json>"
$env:D2I_TEST_WINDOWS_CERTIFICATION = "<windows-binding-certification.json>"
$env:D2I_TEST_WINDOWS_ACTIVATION_ROOT = "<new-activation-ledger-path>"
$env:D2I_TEST_WINDOWS_ACTIVATOR_ID = "deployment-agent"
$env:D2I_TEST_LOOPBACK_FIXTURE_PORT = "18080"
cargo test -p d2i-desktop --test windows_adapters deployed_wfp_v2_binding_reactivates_webdriver_and_preserves_egress_denial -- --ignored
```

## Learning Boundary

Candidate GUI, web, function-calling, shell, and code datasets are tracked by
`d2i-learning`, not by this product. Their records are inert and cannot call an
adapter. A future normalizer must bind visual or DOM observations to typed,
bounded transition records before any offline learning or evaluation.

Raw coordinates are insufficient for production execution because viewport,
display scaling, application identity, and observation revision are missing.
Likewise, DOM selectors require origin, frame, and document-revision binding.
Shell text, scripts, arbitrary code, dataset function names, cookies, and
credentials are never accepted as `DesktopOperation` values. Any learned
proposal must still produce a verified `DecisionEnvelope` and traverse the
normal policy, preparation, approval, permit, commit, and audit protocol.

## Deployment Requirements And Limits

- Process children run in a reviewed zero-capability AppContainer. Process
  intents requesting network are unavailable and denied.
- Browser sessions require a firewall, proxy, WFP, or equivalent egress
  enforcer. The concrete Windows provider configures and continuously verifies
  an application-scoped WFP loopback-only boundary. It accepts only
  `localhost`, `127.0.0.1`, and `[::1]` origins. Other external providers must
  supply separately reviewed signed evidence.
- WFP does not authenticate HTTP origins or hostnames. Non-loopback origin
  allowlisting requires an enforcing proxy or reviewed WFP callout and remains
  unavailable.
- UI Automation does not cross the Windows secure desktop. Credential
  references, browser download/upload, clipboard, and arbitrary coordinates
  remain unavailable.
- DPAPI binds local signing material to the current Windows user, but
  organization identity, rotation, revocation, HSM-backed custody, and
  separation of attestor/certifier accounts remain deployment controls.
- Protected local storage does not replace external chain-head anchoring,
  backup, retention, and crash reconciliation.
