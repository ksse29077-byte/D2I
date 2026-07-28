# Module Submission Checklist

- [ ] Issue linked and module owner identified
- [ ] Scope limited to one declared module capability
- [ ] D2I Core changes are zero, or an approved RFC is linked
- [ ] Module Manifest v1 complete
- [ ] Input and output schemas strict and versioned
- [ ] Artifact and schema SHA-256 values current
- [ ] Unit tests and conformance report attached
- [ ] Evaluation report and acceptance thresholds attached
- [ ] Benchmark reference and result attached
- [ ] Failure and unsupported cases documented
- [ ] Threat model complete
- [ ] Model card present or marked not applicable
- [ ] Data card present or marked no training data
- [ ] `licenses.json` and commercial-use status verified
- [ ] No hidden network, filesystem, environment, privilege, or side effect
- [ ] No raw secret input or output
- [ ] Deterministic replay hashes match when determinism is declared
- [ ] `cargo fmt --all -- --check` passes
- [ ] workspace Clippy with `-D warnings` passes
- [ ] workspace tests and release build pass
- [ ] PR is not configured for automatic merge

The reviewer must treat `skipped` as unresolved, not passed.
