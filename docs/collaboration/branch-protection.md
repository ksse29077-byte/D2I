# Main Branch Protection Manual

This is a repository-owner checklist. The 2026-07-29 unauthenticated GitHub
API audit could confirm the public repository, `main` default branch, and one
active `ci` workflow, but branch-protection details require authenticated
administrative access. Nothing in this document claims that protection is
already enabled.

## Repository Merge Settings

In **Settings -> General -> Pull Requests**:

- [ ] Allow squash merging
- [ ] Disable merge commits
- [ ] Disable rebase merging
- [ ] Disable automatic merge
- [ ] Set the default squash commit message to the PR title
- [ ] Require PR titles to follow `<type>(<scope>): <summary>` by review policy

Squash merge is the single team strategy. It preserves linear history and
makes the reviewed PR title the final conventional commit.

## Main Ruleset

Prefer a repository ruleset targeting the exact branch `main`. If the account
plan does not expose rulesets, configure equivalent branch protection.

- [ ] Require a pull request before merging
- [ ] Require at least one approving review
- [ ] Require approval from CODEOWNERS
- [ ] Dismiss stale approvals when new commits are pushed
- [ ] Require approval of the most recent reviewable push by someone else
- [ ] Require all conversations to be resolved
- [ ] Require status checks to pass and require the branch to be up to date
- [ ] Add `ci / rust` after it has reported once
- [ ] Add `ci / workspace-test` only after the documented portability blocker is fixed and the check reports green
- [ ] Add `module-pr / module-governance` after it has reported once
- [ ] Block force pushes
- [ ] Block branch deletion
- [ ] Require linear history
- [ ] Restrict direct updates to `main`

GitHub exposes status names only after a workflow reports them. Verify the
exact displayed names on the first PR before making them required.

At the 2026-07-29 audit, `ci / workspace-test` exposed a pre-existing
cross-platform failure: `d2i-core` accepts `C:\outside.json` as relative on
Linux while its test requires rejection. Do not mark that failing check as
required until a separate Core-owned fix is reviewed. Do not waive or hide the
failure. Full Windows workspace tests remain a mandatory local report, and the
headless concrete adapter limitation remains separately visible in the
baseline audit.

## Bypass And Administration

The recommended bypass list is empty. Administrators are subject to the same
rules. If emergency bypass is retained, document the named actors, reason,
expiry, required incident record, and follow-up review. A bypass never permits
credentials, customer data, weakened tests, or an unversioned contract change.

## Signing Review

Evaluate required signed commits after confirming every contributor and bot can
sign. The repository currently reports `web_commit_signoff_required: false`;
that is not a cryptographic signed-commit policy. Do not enable a signing
requirement until recovery and bot behavior are tested.

## Verification

After saving the rules:

1. Attempt a direct non-admin push to `main`; it must be rejected.
2. Open a documentation PR and confirm `ci / rust`.
3. Open a synthetic module PR and confirm both required checks.
4. Touch a CODEOWNERS path and confirm owner review is requested.
5. Push a new commit and confirm stale approval dismissal.
6. Leave a conversation unresolved and confirm merge is blocked.
7. Confirm force push and `main` deletion are blocked.
8. Confirm only manual squash merge is offered.

Record screenshots or settings exports in the operations system, not in a
module feature PR.
