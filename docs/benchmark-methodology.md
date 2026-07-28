# Benchmark Methodology

## Principles

Benchmark claims must compare equivalent tasks at equivalent quality. A speed
claim is not valid without a reproducible artifact.

## Required Context

Each benchmark artifact should include:

- benchmark ID
- build ID
- date in UTC
- hardware CPU, core count, RAM, and GPU if used
- operating system
- Rust compiler version
- compiler version
- dataset ID, hash, and case count
- warmup count and measured iterations
- cold and warm run separation

## Required Metrics

- task success rate
- critical error rate
- p50 latency
- p95 latency
- p99 latency
- cold start time
- warm start time
- peak RSS
- allocated bytes when measurable
- copy count and copy bytes when measurable
- activated modules
- timeout rate
- field-level accuracy
- deterministic repeatability rate

## Phase 4 Implementation

`d2ic benchmark` executes the package's hash-verified evaluation cases through
the offline reference runtime. It records build and dataset identity,
wall-clock p50/p95/p99, first-run and warm median latency, task and field
correctness, critical errors, copies, activated modules, timeouts, and
repeatability.

The current safe standard-library collector reports OS, architecture, logical
CPU count, compiler version, and Unix measurement time. `peak_rss_bytes` and
`allocated_bytes` are explicitly `null`; CPU model, RAM, GPU, and exact `rustc`
version are not collected. Copy metrics cover request and envelope
serialization performed by the benchmark harness and are not allocator-level
measurements.

These artifacts are regression evidence, not a throughput or latency
superiority claim. Such a claim requires a controlled host description,
warmup policy, isolation, repeated runs, and equivalent quality gates.

## Phase 5 Adapter Comparison

`d2ic adapter-conformance` runs identical package evaluation vectors through
the reference runtime and selected adapter. It also runs invalid-request and
unsupported-skill vectors. The report retains exact decision comparison,
output-schema validity, stable error-category equality, and independent
p50/p95/p99 latency summaries.

The mock adapter delegates to the reference implementation, so its latency
ratio proves report wiring only. It is not evidence about the proprietary
runtime and must not be published as a performance comparison.

## Phase 6 ABI Copy Metrics

`AbiCopyMetrics` counts input and output borrowed views, their logical byte
sizes, host output allocations, and explicit copies attributable to the native
ABI boundary. The v1 loader passes existing input bytes and a host-owned output
allocation directly, so successful fixture runs report zero boundary copies.

This metric does not observe copies performed internally by a module, platform
loader relocation, Arrow/DLPack device transfer, allocator traffic, or peak
RSS. A zero ABI-boundary copy count is an ownership-contract result, not a
whole-program zero-copy or performance claim.

## Phase 7 Kernel Experiment

`d2i-kernel-bench` measures the isolated case-retriever match-score kernel with
a deterministic repeating mask corpus. It records item count, warmup and
measured iterations, p50/p95/p99 nanoseconds, fixed working memory, observable
ABI copies, required tools, build steps, exact correctness, and adoption
decision.

The Rust and candidate paths receive identical masks and caller-owned output.
Peak RSS is `null` because no reviewed process-memory collector exists. Working
memory is exactly one input byte plus one two-byte score per item. Boundary
copy metrics do not include platform loader relocation.

Adoption requires exact integer output and at least `1.20x` p50 speedup on the
same host. Mojo 1.0.0b2 is unavailable on the Phase 7 host, so the retained
artifact reports `rejected_unavailable`; no Mojo performance claim is made.

## Phase 8 Promotion Evaluation

Candidate evaluation uses the existing hash-verified package gold set and runs
the baseline and metadata-only candidate mode through the same reference
runtime. It retains dataset ID/hash, evaluator, measured iterations, both
benchmark reports, policy thresholds, and all gate reasons.

Promotion rejects absolute quality failure, task or field regression, any
critical-error increase, repeatability failure, leakage, unresolved poisoning,
or distribution shift. Because Phase 8 proposals are not executed, a passing
report demonstrates pipeline integrity and non-regression only; it is not an
improvement claim.
