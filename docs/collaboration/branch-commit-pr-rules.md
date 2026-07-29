# Branch, Commit, And PR Rules

## Branches

- Cognitive Module: `module/<issue-number>-<module-id>`
- Core contract change only: `core/<issue-number>-<contract-change>`
- Documentation only: `docs/<issue-number>-<subject>`

Examples are `module/42-plan-ranker`,
`module/57-safety-domain-evaluator`, and
`core/61-module-contract-v2`.

An issue must exist before the branch. One branch normally handles one issue.
Direct pushes to `main` are prohibited. A force push is allowed only on the
author's unmerged topic branch and only when it does not disrupt reviewers.
Never force push or delete `main`.

A module branch may not change Core-owned paths. Stop and open a Core RFC when
that appears necessary. Do not mix a module feature and Core contract revision
in one branch or PR.

Do not commit unrelated formatting, generated `target/` output, unrequested
artifacts, credentials, secret keys, raw customer data, or personal data.

## Commits

Use:

```text
<type>(<scope>): <summary>
```

Allowed types are `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `perf`,
and `security`. Use the module ID as scope when practical.

Examples:

```text
feat(plan-ranker): add deterministic candidate scoring
test(plan-ranker): add stale observation fixtures
docs(plan-ranker): document confidence semantics
fix(verifier): reject mismatched result binding
```

Prefer coherent commits for manifest/contract references, implementation,
fixtures/tests, evaluation/benchmark, and documentation/license evidence.
These are guidance, not a requirement to split trivial changes artificially.

## Pull Requests

Open the Cognitive Module PR template and link the issue with `Closes #N`.
Keep one module per PR. Declare out-of-scope work, Core changes, network,
side effects, data/model licenses, security negatives, conformance result,
evaluation, benchmark, limitations, and rollback.

The PR title must follow the commit format because team PRs are squash merged.
Do not enable automatic merge. Repository maintainers must configure GitHub to
allow squash merge and disable merge commits and rebase merge for this policy
to be mechanically consistent.

A module-only PR does not require a third-party approval. Its author may
manually squash-merge after the required checks pass on the current head, all
conversations are resolved, the PR is ready and conflict-free, and governance
confirms that no Core-owned path changed. Peer review is optional.

Core-owned changes require a separate Core PR and a current-head approval from
a non-author Core CODEOWNER. A PR-body checkbox or author declaration is not
approval evidence.
