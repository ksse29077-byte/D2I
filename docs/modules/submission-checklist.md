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
- [ ] module-local `Cargo.lock` is committed and `--locked` metadata passes
- [ ] `scripts/modules/check-module.ps1` reports `pass`
- [ ] module-local fmt, Clippy `-D warnings`, tests, conformance, replay, and release build pass
- [ ] Review conversations are resolved and the PR is conflict-free
- [ ] No Core-owned path changed, or a separate Core PR has a current-head non-author CODEOWNER approval
- [ ] PR is not configured for automatic merge
- [ ] root `Cargo.toml` and root `Cargo.lock` are unchanged

Module-only PRs may be manually squash-merged by their author without a
third-party approval. Optional reviewers must treat `skipped` as unresolved,
not passed.
