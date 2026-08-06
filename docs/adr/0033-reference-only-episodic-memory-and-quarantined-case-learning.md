# ADR 0033: Reference-Only Episodic Memory and Quarantined Case Learning

## Status

Accepted

## Context

WORK-500 closes a selected Case through a bounded model-backed planning loop,
but the Role still has no safe long-term Case memory. Reusing Planner ledger
state as memory would mix restart authority with historical context. Persisting
raw UI, prompts, locators, or action traces would also enlarge the credential,
privacy, prompt-injection, and replay attack surfaces.

## Decision

A `CaseEpisodeV1` is a terminal-only, non-authoritative projection. Role,
Intake, Case, Queue/Ownership, Planner, protected audit, Evidence Index, and
terminal Case records remain authoritative. An Episode stores bounded typed
IDs, exact ledger sequence/head references, artifact hashes, terminal outcome,
classifications, and redaction evidence. It does not copy source payloads.
Verified completion, explicit refusal, and escalation may be sealed; active or
pending Cases may not.

Episode identity is derived from Case ID and the terminal Case Instance hash.
Re-sealing identical semantics is an exact duplicate; reusing a Case ID with a
different terminal hash is an integrity conflict. Sealing verifies current
authoritative heads, the Role memory boundary, a signed namespace approval,
organization binding, finite retention, data classes, and resolvable sources.
It grants no execution, reopening, or mutation authority.

The namespace is derived from a verified Role bundle and exact-bound to that
bundle's contract hash, memory-boundary hash, a newly signed organizational
approval, a newly signed subset delegation, and an active Role Instance. A
previous Role version's approval, delegation, or instance cannot be reused by
a memory-enabled version.

Cross-Case reuse applies the narrower Role and namespace policy:

- `forbidden` returns no Episode data or hash.
- `hash_reference_only` returns bounded identity, outcome, class, time,
  retention, evidence, and Episode hashes without free text or prior plans.
- `approved_summary_only` additionally requires a current signed, redacted,
  exact Episode summary in the same organization and compatible Role scope.

Queries use exact typed filters and deterministic ordering. v1 has no vector,
embedding, fuzzy, free-text, or model-ranked retrieval. Historical context is
always `historical_non_authoritative`; fresh observation, current policy,
current authority, current Case state, and current evidence take precedence.
Memory cannot add a capability or target, satisfy a requirement, mint
activation, declare completion, omit observation, or force an action sequence.
Every Provider/Planner attachment creates a one-consumption memory-use receipt.

Desktop owns a current-user DACL-protected content-addressed store, append-only
hash-chain ledger, deterministic index, atomic replacement, single-writer
lock, rollback/tamper checks, and crash repair. Retention uses trusted caller
time and the shorter Role/namespace maximum. A signed hold prevents purge.
Tombstones permanently prevent ID/hash reuse and summary retrieval. v1 does
not claim physical secure erase.

Repeated valid Episodes may create only a `quarantined` learning candidate.
General procedure, planner, recovery, and prompt-template patterns need at
least two independent Episodes. Offline export preserves identical production
package hashes. Even an `approved_for_offline_build` review is not deployment
or package mutation authority.

## Consequences

- Planner restart state and long-term memory have separate ownership.
- Current General Office `1.0.0` remains hash-only with learning disabled.
- A separately compiled and approved `1.1.0` fixture proves signed summary
  reuse and candidate quarantine without expanding execution capability.
- Raw credentials, tokens, UI payloads, locators, commands, unrestricted
  personal data, provider prompts, and chain-of-thought are rejected.
- Crash repair reconstructs references and indexes only; it never blindly
  replays a Provider, action, KRN run, or activation.
- Core treats office, HR, IT, and safety work-class IDs as opaque fixture data.

## Alternatives

Planner-ledger reuse was rejected because operational recovery state has a
different lifetime and authority. Raw Episode/RAG retrieval was rejected due
to data exposure and prompt injection. Vector search was deferred because v1
requires exact deterministic scope. Online prompt, policy, package, or weight
mutation was rejected because production learning requires offline evaluation,
review, compile, signing, and promotion boundaries.

## Rollback And Migration

WORK-600 is additive. Disable memory attachment and keep WORK-100 through
WORK-500 unchanged. Store rollback to an older chain head fails closed. New
Episode, summary, query, retention, or candidate semantics require new schema
versions. Migration may read verified v1 references but cannot rewrite v1
objects, tombstones, or ledger history.
