# Knowledge Retriever Threat Model

## Protected assets and trust boundaries

Protected assets are authorized evidence text and locators, access metadata,
provenance, deterministic result identity, resource availability, and the
caller-visible distinction among success, failure, and unsupported behavior.
The invocation envelope, manifest, schemas, artifact, fixtures, query,
terminology, and all knowledge items are untrusted until the SDK and typed
module validation complete. `InvocationContext` is the trusted caller boundary.

The module receives no adapter, policy implementation, filesystem, process,
environment, network, secret store, clock, random source, or persistent state.
It returns data only; it has no authority to execute an action.

## Attacker model and attacks

An attacker may control query text, knowledge text and metadata, ordering,
duplicate volume, structured claims, provenance-like strings, dates, tags,
locators, and unsupported modes. Relevant attacks include:

- prompt injection and embedded instructions
- evidence, locator, content-hash, or provenance spoofing
- unauthorized evidence or hidden-count leakage
- ranking manipulation and authority-rank abuse
- duplicate flooding and stale/superseded evidence
- structured conflict concealment or fabrication
- oversized payloads, deeply nested JSON, malformed JSON/Unicode, and
  duplicate JSON keys
- secret-like fields and raw credential material
- deterministic replay drift from iteration order, time, randomness, or
  floating-point ranking
- dependency and artifact supply-chain substitution
- false citations or invented excerpts

## Mitigations

- SDK strict JSON parsing rejects duplicates, excessive nesting, malformed
  input, raw secret field names, schema/version drift, stale lifecycle
  bindings, and excessive envelope budgets.
- Module schemas set `additionalProperties: false` and finite string,
  collection, numeric, and nesting bounds.
- All knowledge text remains data; the implementation never parses it as a
  command or derives authority from it.
- Access filtering occurs before scoring, duplicate processing, conflict
  detection, counting, and warnings.
- Exact input excerpts and locators are copied without transformation.
- Hashes, IDs, dates, intervals, authority, tags, and duplicate IDs are
  validated fail-closed.
- Superseded items can be excluded before scoring. Duplicate content is
  reduced after deterministic ranking.
- Conflicts require explicit structured claims with matching key and scope.
- Integer scoring, `BTreeMap`/`BTreeSet`, stable sorting, and an ID tie-break
  prevent iteration-order drift.
- Logical operations, ticks, memory declaration, input/output sizes, retries,
  and concurrency are bounded and checked by the SDK.
- Artifact and schemas are SHA-256 bound to the manifest; dependencies are
  existing exact workspace pins.

## Residual risk

Caller-supplied authority ranks, access labels, terminology, and provenance are
not independently authenticated by this module. Lexical retrieval can miss
semantically equivalent language. Simple date validation does not prove a real
calendar date or legal effective-time interpretation. In-process logical
timeouts are not hard thread preemption. These limitations require trusted
upstream snapshot construction, policy review, and downstream domain judgment.

## Explicitly unsupported security boundary

The module does not claim to secure external storage, source ingestion,
identity providers, policy engines, production loaders, Runtime ABI modules,
native processes, networks, customer documents, or final legal/medical/safety
decisions. It does not remediate malicious source data; it only validates and
filters the supplied bounded snapshot.
