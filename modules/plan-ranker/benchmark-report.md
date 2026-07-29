# Deterministic Benchmark Plan And Report

The reference fixture is `fixtures/valid/maximum-candidates.json` with 64
synthetic candidates. Acceptance requires 100 of 100 repeated invocations to
produce the same canonical result hash, exact expected order, no more than
4,096 logical operations, and output below 1 MiB.

No wall-clock performance threshold or performance claim is part of Plan
Ranker v1. Final measured contract results are recorded in the pull request
after execution.
