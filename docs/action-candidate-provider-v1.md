# Action Candidate Provider Contract v1

## Purpose

Action Candidate Provider v1 defines the strict Core-owned fixture boundary
between a uniquely grounded application semantic target and an existing
Cognitive IR v1 `ActionProposal`.

The implementation is:

- `crates/d2i-action-candidates`
- `schemas/cognitive/action-candidate-provider-v1.schema.json`
- ADR 0021

It produces proposal data only. It does not implement or invoke a standalone
module, map a proposal to `DesktopOperation`, or execute an action.

## Reviewed Existing Contracts

The following contracts are sufficient and remain unchanged:

- Cognitive IR v1 `ActionProposal`
- Cognitive IR v1 `CapabilityDescriptor`
- `ActionCandidateProvider::next_candidate`
- Cognitive Module Contract v1 and `ModuleResultEnvelope`
- Module SDK public APIs

The new contract is additive because the generic Cognitive IR records do not
own application-pack, semantic-target, or observed-element bindings.

## ActionCapabilityBinding

A sealed binding contains:

- schema and stable binding identity
- exact Application Pack SHA-256
- one semantic target ID
- one UIA or WebDriver source kind
- a sorted, unique, bounded set of allowed observed element kinds
- one closed action kind
- the exact Cognitive IR v1 `CapabilityDescriptor`
- canonical binding SHA-256

Action kind, source, and capability operation must agree exactly:

| Action kind | Source | Capability operation |
| --- | --- | --- |
| `invoke` | `uia` | `uia.invoke` |
| `set_text` | `uia` | `uia.set_value` |
| `toggle` | `uia` | `uia.toggle` |
| `click` | `web_driver` | `webdriver.click` |
| `type_text` | `web_driver` | `webdriver.type` |
| `select` | `web_driver` | `webdriver.select` |

Irreversible descriptors and `unsupported_irreversible` confirmation fail
closed.

## Fixture Bridge

`bridge_fixture_action_candidate` requires:

- a sealed `ApplicationPack`
- a validated `ObservationFixtureBridge`
- a sealed `ActionCapabilityBinding`
- valid Cognitive IR v1 `GoalSpec`, `WorldState`, and `PlanGraph`
- a bounded `ActionCandidateBridgeRequest`

Before emitting a proposal it proves:

1. all pack, observation, binding, goal, world, and plan hashes/IDs agree
2. the grounding case resolves exactly once
3. the expected element resolves exactly once and passed the existing
   redaction/secret/status checks
4. semantic target, element kind, source, and capability binding agree
5. WorldState advertises the capability
6. WorldState current step resolves to a `ProposeAction` plan node bound to
   that same capability
7. request input kind agrees with the sealed operation
8. preconditions and required postconditions are bounded and secret-free

The resulting proposal expires at the source observation sequence. A fresh
observation therefore requires a new proposal.

## Typed Arguments

`ActionProposal.arguments` is narrowed to:

```text
schema_version
operation
target
input
```

The target contains only stable IDs, hashes, sequence, semantic target,
observed element kind, and the capability-binding hash. It never contains an
executable selector, locator, coordinate, automation handle, adapter handle,
URL, raw text value, credential, or approval token.

Text and select inputs carry SHA-256 digests. Supplying the corresponding
bytes to a future trusted execution mapper requires a separate reviewed
contract.

## Authority And Trust

Risk, confirmation requirement, and capability ID are copied from the trusted
descriptor. Observed labels, values, locator hints, and web/document text are
not consulted when choosing those fields.

Proposal evidence contains only bound IDs and hashes. Unknown fields,
substituted lifecycle values, stale hashes, unavailable capabilities,
operation/source mismatches, raw secret-like values, and output mutation fail
closed.

## Hashing

Bindings, proposals, and bridge artifacts use SHA-256 over compact canonical
JSON. Object keys are recursively sorted, array order is preserved, and the
artifact's own hash field is omitted from its self-hash.

Identical inputs produce identical proposal IDs, proposal hashes, and bridge
hashes. A changed typed input changes all affected identities.

## Current Limitations

- The bridge is fixture-only and uses the external grounding oracle.
- No standalone Action Candidate Provider module is implemented.
- No actual Element Grounder result adapter is connected.
- No proposal-to-`DesktopOperation` mapper exists.
- No policy, activation, approval, execution, or post-action verification is
  performed.
- Rich production capability metadata described by the desktop cognitive
  addendum is not added to frozen Cognitive IR v1.
