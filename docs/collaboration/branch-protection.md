# Main Branch Protection Manual

This is a repository-owner checklist. The 2026-07-29 authenticated API audit
performed with the `graykavinjeo` push credential found no repository ruleset
and no legacy `main` branch protection. That credential does not have
administrative permission to create either protection. The intended ruleset
payload is checked in at `.github/main-ruleset.json`; it must be applied and
verified by a repository administrator.

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
- [ ] Set required approving reviews to `0`
- [ ] Do not make CODEOWNERS review a repository-wide branch rule
- [ ] Require all conversations to be resolved
- [ ] Require status checks to pass and require the branch to be up to date
- [ ] Require `rust`
- [ ] Require `workspace-test`
- [ ] Require `module-governance`
- [ ] Require `core-approval`
- [ ] Block force pushes
- [ ] Block branch deletion
- [ ] Require linear history
- [ ] Restrict direct updates to `main`

The general approval count is zero so a validated module-only PR can be
manually merged by its author. Core protection is not removed:
`core-approval` runs only the trusted base-branch script,
classifies Core-owned paths without executing PR code, and requires an
`APPROVED` GitHub review from a non-author CODEOWNER for the exact current
head. `module-governance` continues module artifact, fixture,
conformance, replay, and trust-boundary validation. CODEOWNERS requests the
appropriate reviewers, while the trusted workflow makes path-specific approval
enforceable.

The earlier Linux path-validation blocker was fixed by PR #3, and
`workspace-test` has reported successfully on subsequent PRs. Do not
remove, waive, or disguise this required check.

## Bypass And Administration

The checked-in ruleset has an empty bypass list. Administrators are subject to
the same rules. If an emergency bypass is later introduced, keep it to named
repository administrators and document the actor, reason, expiry, incident
record, and follow-up review. A bypass never permits credentials, customer
data, weakened tests, or an unversioned contract change.

## Signing Review

Evaluate required signed commits after confirming every contributor and bot can
sign. The repository currently reports `web_commit_signoff_required: false`;
that is not a cryptographic signed-commit policy. Do not enable a signing
requirement until recovery and bot behavior are tested.

## Verification

After saving the rules:

1. Attempt a direct non-admin push to `main`; it must be rejected.
2. Open a module-only PR and confirm all four required checks report.
3. Confirm the module-only PR is mergeable with zero approvals after checks
   pass and conversations are resolved.
4. Touch a Core-owned path and confirm `core-approval` fails
   with the file, approvers, approval method, and policy path.
5. Submit a non-author CODEOWNER approval on the current head and confirm the
   governance check reruns and succeeds.
6. Push another commit and confirm the old Core approval no longer satisfies
   the exact-head check.
7. Leave a conversation unresolved and confirm merge is blocked.
8. Confirm force push and `main` deletion are blocked.
9. Confirm only manual squash merge is offered.

Record screenshots or settings exports in the operations system, not in a
module feature PR.
