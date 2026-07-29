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
on Linux. The workflow now uses `windows-latest`, matching the repository's
Windows desktop targets, without modifying or suppressing Windows/WFP code.

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
