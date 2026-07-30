# GitHub Baseline Audit

Audit date: 2026-07-29 Asia/Seoul

## Confirmed

- Repository: `ksse29077-byte/D2I`, public
- Default branch: `main`
- Local and remote baseline:
  `68d5e5f9453b7ea9d58d42f5e1ad3e5184065f2e`
- Existing active workflow: `.github/workflows/ci.yml`
- Issues: enabled, with zero open issues at audit time
- Pull requests: zero open at audit time
- Labels: nine GitHub defaults only
- Tags: none locally or through the public repository API
- Releases: none through the public repository API
- Web commit signoff requirement: false
- Existing module PR template:
  `.github/PULL_REQUEST_TEMPLATE/module.md`
- Existing Issue Forms and CODEOWNERS before this governance change: none

The default labels were `bug`, `documentation`, `duplicate`, `enhancement`,
`good first issue`, `help wanted`, `invalid`, `question`, and `wontfix`.

The original CI used `ubuntu-latest`. A governance-branch run showed that the
exact workspace Clippy command treats Windows-only imports/constants as unused
on Linux. A headless `windows-latest` run passed Clippy but could not satisfy a
concrete process-adapter integration precondition. The workflow therefore runs
fmt, exact workspace Clippy, and release build on `windows-latest`, and runs the
exact workspace test command on `ubuntu-latest`. This preserves executable
required checks without modifying, suppressing, or skipping Windows/WFP tests.
Concrete Windows adapter integration remains a separate local/manual
environment check.

## Remote CI Findings

Governance-branch runs exposed two baseline failures outside this task:

- Headless Windows: `signed_process_binding_manages_only_its_child` failed
  because the zero-capability child exited before termination and was no longer
  in the worker's managed-child set.
- Ubuntu: `source::tests::relative_references_reject_traversal_and_absolute_paths`
  failed because `C:\outside.json` was not rejected as absolute on Linux.

No related source or test was changed, skipped, allowed to fail, or reported as
passing. The split workflow keeps Windows fmt/Clippy/release and portable
workspace test outcomes separately visible. `workspace-test` must not
become a required branch check until a dedicated Core-owned portability fix is
approved. The module PR workflow has static and local execution evidence but
cannot report on GitHub until a PR event exists.

## Not Confirmed

The branch-protection endpoint returned `401 Requires authentication`.
Unauthenticated repository metadata did not expose merge-method settings.
Therefore this audit does not claim that direct pushes, force pushes, deletion,
approvals, CODEOWNERS review, status checks, auto-merge, squash merge, rebase,
or merge commits are configured.

Use [the branch protection manual](branch-protection.md) with repository-owner
access, then record the enabled rules and exact status-check names.

## Local Worktree Separation

The audit found the current collaboration worktree and a separate
`codex/wfp-verifier-broker` worktree at the same baseline. This governance work
does not import, modify, wait for, or integrate that WFP branch.

## Missing Work-Order Files

`D2I_COMPILER_MASTER_WORK_ORDER.md`,
`D2I_DESKTOP_COGNITIVE_RUNTIME_ADDENDUM.md`, and `TASKS.md` were not present in
this worktree. `AGENTS.md`, repository architecture, ADR 0014, ADR 0015,
Cognitive IR v1, Module Contract/Manifest/SDK/Conformance documentation,
schemas, source, examples, and tests were used as the available source of
truth. Missing files were not inferred.
