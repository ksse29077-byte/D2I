# ADR 0017: Windows Read-Only Observation Plane

- Status: Accepted
- Date: 2026-07-29
- Scope: Concrete UIA and WebDriver observation into Cognitive IR v1

## Context

Cognitive IR v1 already defines `ObservationProvider` and
`ObservationSnapshot`. The Windows adapters already provide signed runtime
certification, one-time activation, isolated workers, exact executable and
session binding, protected audit storage, and a concrete WFP browser-egress
trust chain. Observation must reuse those boundaries without adding an action
path or changing the public Cognitive IR contract.

UI Automation and WebDriver expose provider-specific, ephemeral identities.
UIA RuntimeId and WebDriver element IDs are unsuitable as durable Cognitive IR
identities. UI and page text are also untrusted data, and credential-bearing
values must not cross the collection boundary.

Relevant platform contracts:

- <https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-howto-walk-uiautomation-tree>
- <https://learn.microsoft.com/en-us/dotnet/framework/ui-automation/use-the-automationid-property>
- <https://www.w3.org/TR/webdriver2/>
- <https://learn.microsoft.com/en-us/microsoft-edge/webdriver/>

## Decision

Add two concrete implementations of the existing `ObservationProvider`:

- `WindowsUiaObservationProvider`
- `WindowsWebObservationProvider`

Each provider owns one already activated capability-specific adapter, one exact
target declaration, explicit `ObservationLimits`, and one protected Windows
deployment audit handle. The provider can issue only the new internal
`Observe` worker command. It cannot issue `DesktopOperation`, action payload,
navigation, script, cookie, storage, screenshot, clipboard, file, or process
commands.

The existing public Cognitive IR v1 structs and schema remain unchanged.
Provider-specific normalized metadata is stored in
`ObservableElement.value`; exact stable target evidence is stored in
`ObservationSnapshot.target_binding`.

## UIA Binding And Collection

The UIA target pins:

- process ID;
- canonical executable path and SHA-256;
- the existing top-level window identity of process ID plus title hash;
- interactive session ID;
- activated configuration digest.

The isolated worker reopens and rehashes the process image, verifies the
session, and requires exactly one matching top-level window before walking
children. It reads ControlType, AutomationId, Name, ClassName, FrameworkId,
enabled/offscreen/focus state, supported read patterns, value read-only state,
toggle, selection, expand/collapse, grid dimensions, validation state, and
bounding rectangle where the provider exposes them.

RuntimeId is used only as a snapshot-local duplicate/cycle guard. It is never
returned and never enters a state hash. Stale, inaccessible, cross-process, and
duplicate elements produce a bounded partial result or a structured failure.
The worker process request timeout is the hard bound around a potentially
blocking provider call; the collector additionally checks its deadline between
UIA operations.

## Web Binding And Collection

The Web target pins:

- installed Edge and EdgeDriver versions, paths, and SHA-256 values;
- activated WebDriver session ID and loopback origin;
- activated configuration digest;
- concrete WFP policy and functional attestation.

The adapter obtains a fresh signed WFP verification receipt before and after
collection. It independently rechecks the policy, attestation, Edge pin,
session, and origin. Receipt hashes are written to protected audit but are not
placed in the stable target binding because challenges and receipt sequences
are intentionally ephemeral.

The read-only collector remains inside its single-process Job Object and does
not open the verifier service pipe. Before and after collection, the provider
hash-pins and starts the already certified `d2i-desktop` worker image as a
one-shot medium relay. The relay accepts exactly one bounded framed
`VerifyBrowserEgress` command with no opaque payload, invokes the existing
broker receipt contract, and returns only the optional signed receipt. The
parent closes relay stdin after the request, enforces the certified request
timeout and response limit, and kills and waits for the relay on every result.
This preserves collector isolation while satisfying the broker's existing
relay PID, token, session, executable-hash, AppContainer-child, and parent
lineage checks.

The worker uses only standard W3C WebDriver reads: current URL, title, element
tag, text, attributes, properties, rectangle, enabled/selected state, CSS
visibility, computed role, and computed label. The only POST operation is
`Find Elements`, including child lookup with `./*`; it is a protocol read.
Current URL, origin, and title are checked again after collection. Any redirect
or document identity change fails closed.

No JavaScript, CDP, navigation, click, input, selection change, cookie,
storage, screenshot, download, upload, or non-loopback operation is available
through this command.

## Redaction And Trust

UIA password elements and Web password/hidden inputs are classified before
their value pattern/property is read. Identifier and accessible-name hints for
passwords, secrets, tokens, API keys, cookies, credentials, session IDs,
private keys, email, phone, address, national identifiers, and birth data also
block value reads.

The snapshot contains a deterministic redacted marker and
`RedactionMetadata`, never the original value. Worker payload validation
rejects a sensitive element carrying any non-redacted value.

UIA text is labeled `ObservedUiState` and `UntrustedDocumentContent`. Web text
is labeled `ObservedUiState` and `UntrustedWebContent`. Prompt-like page or UI
text remains ordinary untrusted data and is not interpreted as an instruction.
Protected audit receives hashes, counts, IDs, status, and result codes only.

## Bounds And Determinism

`ObservationLimits` bounds tree depth, element count, per-element UTF-8 bytes,
snapshot bytes, duration, skipped/inaccessible count, locator hints, options,
and table rows/columns. Every limit is itself capped by the worker protocol.
Tree/count/table/option limits return an explicitly partial snapshot. Snapshot
size is reduced deterministically and marked `snapshot_byte_limit`. Deadline,
malformed response, or worker protocol violations fail closed.

Children are ordered by canonical semantic subtree hash. Snapshot-local IDs are
assigned only after ordering. UIA RuntimeId, WebDriver element ID, collection
time, observation ID, logical sequence, WFP receipt challenge, and receipt
sequence do not enter `state_hash`. Focus and bounding rectangle remain
observable semantic state, so a real focus or window geometry change changes
the hash; cursor position is not collected.

## Audit

The existing protected deployment ledger records:

- observation and source-collection start;
- exact target verification;
- source completion with bounded metrics;
- applied limits and blocked sensitive reads;
- success with state hash;
- stale target, process hash, origin, and general failures.

An audit open, ACL, append, or chain-verification failure prevents collection
or snapshot release.

## Rejected Alternatives

### New Cognitive IR version

Rejected because the existing extensible `value` and `target_binding` fields
preserve all required normalized semantics without changing public behavior.

### Raw UIA or DOM serialization

Rejected because it leaks provider-specific handles, increases sensitive-data
exposure, and is not deterministic across runs.

### JavaScript or DevTools accessibility extraction

Rejected because it adds an execution channel and expands the reviewed browser
surface. Standard W3C semantics are the v1 boundary.

### Observation through action adapters

Rejected because an observation must not acquire an action permit or share a
command that can mutate state.

## Consequences And Limits

- The v1 Web tree covers the current browsing context and ordinary W3C child
  elements. Frames, shadow roots, browser chrome, and semantics unavailable
  through standard W3C endpoints require a separate Core RFC.
- UIA providers may omit hidden or virtualized children. Such absence is not
  treated as proof of visibility; exposed `IsOffscreen` state is retained.
- Per-call cancellation inside a third-party UIA COM provider is unavailable.
  The isolated worker timeout and Job Object kill-on-close remain the hard
  fail-closed boundary.
- The providers are connected only to `ObservationProvider`. Production module
  loading, Element Grounder integration, and action execution are out of scope.
- The egress relay is deliberately not a general IPC endpoint. It is a
  short-lived child over inherited stdin/stdout and supports the existing
  browser-egress verification operation only.
- No dependency or license change is introduced.
