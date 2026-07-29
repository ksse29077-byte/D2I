# Knowledge Module

`knowledge-retriever` is an industry-independent, deterministic, rule-based
reference module. It searches only the immutable `Knowledge Snapshot` supplied
inside the invocation and returns a verifiable `Evidence Bundle`. It does not
generate a natural-language answer or make a final domain decision.

## Supported scenarios

- definitions, rules, requirements, prohibitions, permissions, exceptions
- procedures, roles and responsibilities, thresholds, cases, and evidence
- effective-date filtering and version-oriented retrieval
- exact phrase, token overlap, caller terminology aliases, and metadata tags
- access filtering before scoring
- superseded-item exclusion and duplicate-content elimination
- explicitly structured claim conflict detection
- stable replay and result hashing through `d2i-module-sdk`

Semantic/vector search, PDF/OCR parsing, network or database search, file
loading, answer generation, domain judgment, action execution, persistent
index mutation, and online learning return the SDK `unsupported` terminal
status. There is no fallback module.

## Input and output

Input schema `knowledge-retriever-input-v1` contains a bounded query, up to 64
immutable knowledge items, caller-supplied terminology, and an access context.
Every knowledge item carries exact text, document/revision/section identity,
locator, type, authority rank, effective interval, supersession/content hash,
tags, access labels, provenance, and an optional structured claim.

Output schema `knowledge-retriever-output-v1` contains a domain status,
normalized query, exact evidence excerpts and locators, conflicts, gaps,
warnings, applied-filter summary, deterministic ordering rule, and logical
operation count. The SDK result envelope adds the terminal status, resource
usage, replay metadata, provenance, and canonical output hash.

## Retrieval and ranking

The module normalizes case and whitespace, tokenizes Unicode alphanumeric
sequences, and expands caller-provided aliases. It then applies access,
supersession, temporal, and metadata filters before scoring.

The bounded integer score is capped at 10,000 basis points:

| Signal | Maximum contribution |
| --- | ---: |
| exact normalized phrase | 4,000 |
| query token overlap | 3,000 |
| requested knowledge type | 1,000 |
| matching metadata tags | 1,000 |
| effective-date match | 500 |
| authority rank | 1,000 |
| structured claim for verification | 500 |
| version specificity | 100 |

The cap makes the final score stable even when signals sum above 10,000.
`relevance_score_bps` and the envelope confidence are relative ranking signals,
not truth probabilities. Results sort by score descending, authority descending,
then knowledge item ID ascending. Duplicate content hashes keep the best
ranked authorized candidate. Array order never depends on hash-map iteration.

Conflicts are created only when two returned items contain explicit structured
claims with the same claim key and scope but different normalized values. The
module never infers conflicts from free text.

## Security boundary

All knowledge text is untrusted data. It cannot grant a capability, change
policy, request an action, or become an executable instruction. Unauthorized
items are removed before scoring and do not affect exposed counts, conflicts,
warnings, IDs, or gaps. Raw secret fields are rejected by the SDK. The module
has no network, filesystem, environment-variable, process, privilege,
persistence, or side-effect authority and uses no system time or randomness.

Domain Judge remains responsible for final domain decisions. Application Packs
remain responsible for product workflows and presentation. Production loading,
Runtime ABI integration, CognitiveExecutor wiring, and package mutation are out
of scope.

## Resource limits

- query: 2,048 bytes and 64 normalized terms
- knowledge items: 64; text: 4,096 bytes per item
- tags: 16 per tag class per item; terminology aliases: 128
- results: 16
- input/output: 524,288 / 131,072 bytes
- declared memory: 8,388,608 bytes
- logical operations and timeout ticks: 100,000
- retries: 0; concurrent invocations: 1; retention: none

## Build and verification

```text
cargo run -p d2i-cli -- module validate modules/knowledge-retriever --json
cargo test --manifest-path modules/knowledge-retriever/Cargo.toml --test conformance --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo build --workspace --release
```

## Known limitations

- lexical matching does not infer synonyms beyond supplied terminology
- dates are validated as bounded `YYYY-MM-DD` values without calendar or
  timezone interpretation
- authority rank is caller-supplied metadata, not an independently verified
  legal or organizational hierarchy
- access decisions rely on the caller-provided, trusted access context
- the reference SDK uses logical resource declarations rather than hard
  in-process preemption

The crate source and reference artifact follow the workspace Apache-2.0
declaration. Fixtures are synthetic only; there is no training data or model.
