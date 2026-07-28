# Controlled Experience Learning

## Boundary

Phase 8 compiles reviewed operational experience into a separate candidate
bundle. It does not update a loaded runtime, rewrite a production `.d2ip`, or
execute generated code. A signed promotion record approves a candidate only as
an input to a future compiler build.

```text
Decision Envelope + reviewed outcome
  -> strict Episode v1
  -> append-only hash-chain store
  -> deterministic split and quarantine
  -> non-executable adaptation proposals
  -> separate candidate bundle
  -> existing gold-set baseline/candidate evaluation
  -> hard regression and critical-error gates
  -> human approval + Ed25519 signed promotion record
  -> future build input
```

## Episode And Store

`schemas/learning/episode.schema.json` defines situation, selected route,
action, output, outcome, correction, policy, provenance, trust, build ID, and
package hash. Rust deserialization rejects unknown fields and validates the
same cross-field constraints. Corrected and failed outcomes require a reviewed
correction. Side-effect observations require an allow result and human
approval.

An experience store has exactly:

```text
experience-store/
|-- store-policy.json
`-- episodes.jsonl
```

The policy allowlists build IDs and roles for append, export, and candidate
build. Entry count and age impose retention limits. Every append verifies the
complete chain and records sequence, previous hash, episode hash, and entry
hash. There is intentionally no update or delete API.

## Candidate Bundle

A candidate is written through a sibling staging directory and verified before
rename:

```text
candidate.d2ic/
|-- candidate.json
|-- hashes.sha256
|-- dataset/
|   |-- train.jsonl
|   |-- validation.jsonl
|   |-- test.jsonl
|   `-- quarantine.json
|-- adaptations/proposals.json
`-- reports/dataset.json
```

Split groups are hashes of normalized situations. One group can occur in only
one split, and duplicate situations are deterministically reduced. Untrusted,
unknown-outcome, or base-mismatched episodes are quarantined. Category absence
from training is a distribution-shift flag and blocks promotion. Conflicting
observations for the same situation are quarantined as poisoning flags.

Adaptations are data-only proposals:

- retrieval weight deltas
- human-reviewed rule candidates
- framework-neutral executor refit requests
- bounded routing thresholds

No proposal is applied to the base package or runtime.

## Evaluation And Promotion

Evaluation requires the existing gold set embedded in the verified base
package. Its provenance hash must equal the bundled bytes. Baseline and
candidate-overlay modes run through the same reference runtime. Phase 8's
candidate overlay is metadata-only, so it proves pipeline integrity and
non-regression but does not claim improved quality.

Promotion fails on any absolute quality failure, task or field regression,
critical-error increase, repeatability failure, split leakage, unresolved
poisoning, or distribution shift. The append-only promotion ledger records:

- candidate ID and content hash
- base build ID and package hash
- candidate dataset hash and gold dataset hash
- evaluation hash and evaluator
- human approval
- shadow/canary plan
- exact rollback target
- signer public key and Ed25519 signature

The record state is `approved_for_next_build`, not `production`.

## CLI

Run `cargo run -p d2i-learning -- --help` for the complete command surface.
Commands initialize and verify stores, append and export episodes, build and
verify candidates, run offline evaluation, and append or verify promotion
records. All inputs are local bounded files and no command performs network
access.

## External Dataset Admission

External corpora use a separate strict registry and never enter the operational
episode store implicitly. Candidate metadata, license scope, provenance risks,
review attestations, immutable revisions, local artifact sizes, and hashes are
checked before offline use. See `docs/dataset-registry.md`.

Desktop-agent candidates additionally declare third-party, executable, and
credential/session-content risks. Their actions are inert dataset records and
cannot become `DesktopOperation` values, shell invocations, browser events, or
code execution during admission. See
`docs/dataset-intake-desktop-agents.md`.

`dataset-check` reports unresolved candidate requirements.
`dataset-verify` additionally streams and hashes every approved local artifact.
Neither command downloads data or starts training.

## Deferred

- applying an approved candidate during a future compiler build
- organization key management and certificate identity
- remote approval workflow
- automatic retention deletion
- model-framework training implementations
- dataset download, normalization, deduplication, PII removal, and content
  filtering pipelines
- desktop/mobile/web transition normalizers and typed transition IR
- shadow/canary deployment orchestration
