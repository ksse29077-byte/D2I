# D2I Repository Reading Order

D2I is an Industrial Autonomous Workforce OS. The Compiler documents in this
directory remain authoritative for the compile-time subsystem and preserve the
legacy Compiler phase history.

Read in this order:

1. `../AGENTS.md`
2. `../docs/product/autonomous-workforce-os.md`
3. `D2I_COMPILER_MASTER_WORK_ORDER.md`
4. `D2I_DESKTOP_COGNITIVE_RUNTIME_ADDENDUM.md`
5. `TASKS.md`
6. `CODEX_RUNBOOK.md`
7. `CODEX_BOOTSTRAP_PROMPT.md`
8. Relevant ADRs and `../docs/architecture.md`

## Operating Rule

Use an isolated worktree when useful. After scoped and full checks, commit,
fetch, rebase onto the latest `origin/main`, rerun required checks, and push
without force using `git push origin HEAD:main`. Confirm local, tracking, and
remote main SHAs and a clean worktree.

Pull requests, approval waits, and web merges are not completion gates for the
current Solo Direct-to-Main workflow. Code review remains available when it
adds value.

Do not restart a legacy Compiler phase or rewrite an existing proprietary
runtime. Select the first incomplete active task in `TASKS.md` and preserve
unknown integrations behind a narrow `RuntimeAdapter` or equivalent boundary.
