# Episodic Memory and Case Learning Records v1

## Product Gate

WORK-600 removes the manual reconstruction of terminal Case history and the
manual preparation of repeated-pattern learning candidates:

```text
verified WORK-500 terminal Case
  -> exact authoritative ledger-head verification
  -> exactly-one reference-only Case Episode
  -> protected current-user memory store
  -> exact policy-bounded query
  -> historical_non_authoritative attachment
  -> actual local Provider and Adaptive Planner
  -> fresh observation wins
  -> verified closure
```

Repeated valid Episodes may produce a quarantined offline candidate. They do
not mutate a model, prompt, Role, Policy, Application Pack, routing decision,
or production package.

## Ownership

`d2i-episodic-memory` owns platform-neutral namespace, Episode, sealing,
summary, exact query, attachment, use receipt, retention, tombstone, canonical
JSON, strict parsing, and replay contracts. `d2i-case-learning` owns candidate,
evaluation, review, quarantine, and offline export contracts.

`d2i-desktop` owns DACL-protected persistence, content-addressed objects,
single-writer coordination, append-only ledger, atomic index, tamper/rollback
checks, and deterministic crash repair. Neither Core crate depends on Windows,
Desktop, a model runtime, an adapter, or the network.

## Data Boundary

Episodes preserve typed IDs, source ledger IDs and sequence/head hashes,
artifact hashes, terminal outcome, bounded class IDs, requirement references,
redaction proof, retention, evidence, and protected audit terminal hash.
Authoritative source artifacts remain in their existing ledgers.

Raw credentials, tokens, API keys, authorization material, private keys, raw
UI payloads, locators, selectors, coordinates, clipboard content, unrestricted
personal data, executable commands, activation material, provider prompts, and
chain-of-thought are not representable memory content and fail closed.

## Role Policy

The effective policy is the narrower Role and signed namespace scope.
`forbidden` returns nothing. `hash_reference_only` returns only bounded hash
metadata. `approved_summary_only` requires a current signed summary with exact
organization, namespace, Role, Episode, data-class, and redaction binding.

The canonical General Office `1.0.0` Role remains hash-only and learning-off.
The `general-office-operations-employee-memory-v1` fixture is separately
versioned `1.1.0`, compiled, approved, delegated, and instantiated for summary
and candidate tests. The namespace binds the verified bundle's exact contract,
memory-boundary, signed approval, signed delegation, and active Role Instance
hashes. The `1.0.0` approval and delegation are not reused. Execution
capabilities are unchanged.

## Persistence And Recovery

The Desktop store contains `manifest.json`, `ledger.json`, `index.json`,
content-addressed `objects/`, and permanent `tombstones/`. Every durable file
and directory has a verified current-user DACL fingerprint. Reparse points,
non-regular files, unknown objects, stale indexes, object/hash mismatch,
rollback, concurrent writers, and bound exhaustion fail closed.

Recovery repairs only exact durable objects and deterministic indexes. It
never replays a model call, action, activation, KRN run, or adapter operation.

## Inspection

```powershell
cargo run -p d2i-episodic-memory --bin d2i-memory -- episode verify --input episode.json
cargo run -p d2i-episodic-memory --bin d2i-memory -- summary verify --input summary.json
cargo run -p d2i-episodic-memory --bin d2i-memory -- query verify --input query.json
cargo run -p d2i-episodic-memory --bin d2i-memory -- attachment verify --input attachment.json
cargo run -p d2i-episodic-memory --bin d2i-memory -- tombstone verify --input tombstone.json
cargo run -p d2i-episodic-memory --bin d2i-memory -- replay --bundle artifacts
cargo run -p d2i-case-learning --bin d2i-case-learning -- candidate verify --input candidate.json
cargo run -p d2i-case-learning --bin d2i-case-learning -- export verify --bundle artifacts
```

The inspection CLIs are read-only and perform no inference, store mutation,
Queue claim, ownership transfer, activation, KRN execution, adapter action,
credential loading, or network access.

## Official Runner

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/workforce/run-episodic-memory-learning-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -OutputRoot target\d2i-workforce-memory\completion
```

`All` runs deterministic contracts, schemas, store, policy, Role fixture, and
WORK-100 through WORK-500/KRN regressions. `Completion` additionally reruns the
pinned Qwen3-4B WORK-500 product gate, seals Path A/B Episodes, runs an actual
attachment-bound Path C model invocation, proves Save-only fresh-state
planning, quarantines a two-Episode candidate, exports it offline with zero
production mutation, replays 128 Episodes 100 times, scans artifacts, and
verifies zero process/profile/credential/activation/store residuals.

All 22 public memory artifacts have strict Draft 2020-12 schemas, including
the sealing decision and query receipt. Duplicate keys, unknown fields,
unsupported versions, unbounded collections, and non-lowercase hashes fail
closed.

## Limits

Retrieval is exact typed filtering only. There is no vector search, online
learning, automatic package promotion, production connector, SLA calculation,
KPI reporting, or recipient routing. The actual Windows path remains the
narrow General Office name-save fixture.
