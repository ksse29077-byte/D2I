# Cognitive Module Review Checklist

## Author

- [ ] Issue fields and definition of done are complete
- [ ] Scope is one assigned module and no Core-owned file changed
- [ ] Manifest, schemas, artifact hashes, and license metadata validate
- [ ] Unit, fixture, conformance, replay, evaluation, and benchmark evidence exists
- [ ] Normal, error, unsupported, stale, boundary, and security behavior is tested
- [ ] Untrusted content cannot become an instruction or action
- [ ] Network, filesystem, process, secret, privilege, persistence, and side effects remain denied
- [ ] Full workspace fmt, Clippy, tests, and release build pass
- [ ] No failure, skipped check, or unsupported runner is reported as pass

## Peer Reviewer

- [ ] Capability behavior matches the linked issue and existing schemas
- [ ] Unsupported and fallback behavior fails closed
- [ ] Error codes, confidence semantics, provenance, and result binding are correct
- [ ] Evaluation metrics, thresholds, critical errors, and fixture coverage are credible
- [ ] Deterministic replay evidence is stable
- [ ] Code is bounded, readable, and free of hidden authority
- [ ] Dependency, model, data, and commercial-use declarations are complete
- [ ] Tests were not weakened and rollback is practical

## Core Owner Trigger

Core-owner review is mandatory for any Core-owned path, new schema, new
capability category, network requirement, side effect, model-backed module,
external dependency, confidence semantic change, security-boundary change,
production package proposal, or Runtime ABI proposal. A contract change must
move to its own approved Core RFC and PR.

## Final Merge

- [ ] Required CI status checks pass on the current head
- [ ] Required peer and CODEOWNERS approvals exist
- [ ] Stale approvals were dismissed after material changes
- [ ] Every review conversation is resolved
- [ ] No automatic merge is configured
- [ ] PR title follows `<type>(<scope>): <summary>`
- [ ] Maintainer performs a manual squash merge
