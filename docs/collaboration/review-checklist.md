# Cognitive Module Review Checklist

## Author

- [ ] Issue fields and definition of done are complete
- [ ] Scope is one assigned module and no Core-owned file changed
- [ ] Manifest, schemas, artifact hashes, and license metadata validate
- [ ] Unit, fixture, conformance, replay, evaluation, and benchmark evidence exists
- [ ] Normal, error, unsupported, stale, boundary, and security behavior is tested
- [ ] Untrusted content cannot become an instruction or action
- [ ] Network, filesystem, process, secret, privilege, persistence, and side effects remain denied
- [ ] The official module-local checker reports fmt, Clippy, tests, conformance, replay, and release pass
- [ ] No failure, skipped check, or unsupported runner is reported as pass

## Peer Reviewer

Peer review is optional for a module-only PR. Use this checklist when another
developer volunteers a review or when the author requests one.

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
- [ ] The PR is ready, conflict-free, and limited to exactly one standalone module directory
- [ ] No Core approval is required, or a non-author Core CODEOWNER approved the current head
- [ ] Every review conversation is resolved
- [ ] No automatic merge is configured
- [ ] PR title follows `<type>(<scope>): <summary>`
- [ ] The module author or maintainer performs a manual squash merge
