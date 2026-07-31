# Plan Ranker Threat Model

## Boundary

The module accepts strict bounded candidate metadata through the D2I Module SDK.
It returns ranking and rejection metadata only. Policy, activation, binding,
execution, audit, and host adapters remain outside the module.

## Threats And Controls

- Malformed candidate payloads and unknown fields are rejected by strict JSON
  Schema and typed deserialization.
- Prompt-injection text cannot become a rule because the schema has no
  instruction or candidate-description field. Untrusted labels remain data.
- Rank manipulation is bounded to integer cost and likelihood evidence supplied
  by trusted upstream boundaries. The module does not recalibrate either value.
- Duplicate IDs and hashes fail the whole invocation without partial ranking.
- Stale observation and plan bindings are rejected by the SDK envelope check.
- Oversized input, candidate collections, evidence collections, output, and
  logical work fail closed under declared limits.
- Nondeterministic ties are prevented by bytewise hash and ID ordering and a
  fixed insertion-sort implementation.
- Manifest, artifact, and schema substitution are rejected by SHA-256 binding.
- Provenance is bound to the canonical input hash; candidate evidence IDs are
  echoed as bounded metadata and never dereferenced.
- Raw secret fields are rejected by the SDK. The module accepts no credential
  values or secret handles.
- Ranking cannot be mistaken for policy approval: output contains no executable
  action, permit, adapter target, or raw action arguments.
- No network, filesystem, environment, process, browser, UI, device, or other
  host authority is available to module code.

## Residual Limits

The module trusts the caller's normalized cost, success likelihood, gate facts,
candidate hash, and evidence identity. It cannot detect dishonest but
schema-valid upstream metadata. Production integration requires a separate Core
RFC and trusted caller implementation.
