# Module Assignment Checklist

## Before Assignment

- [ ] Create the Cognitive Module Issue; do not invent an issue number
- [ ] Fill every required Issue Form section with repository-backed references
- [ ] Confirm Module ID, owner, classification, priority, purpose, and exclusions
- [ ] Confirm existing capability and input/output schema IDs and versions
- [ ] Mark any missing contract as `Core 또는 Schema 검토 필요`
- [ ] Define finite time, size, memory, operation, retry, and persistence limits
- [ ] Define fixtures, metrics, acceptance thresholds, critical errors, and benchmark
- [ ] Resolve data, model, dependency, license, and commercial-use status
- [ ] Resolve untrusted content, secrets, personal data, and threat model
- [ ] Add recommended labels only after those labels exist in GitHub
- [ ] Assign the GitHub issue to the named owner

## Work Order Gate

- [ ] Give the employee GPT only the Issue URL/number and assignee
- [ ] Require repository and issue inspection
- [ ] Stop on `Issue 보완 필요`
- [ ] Exact allowed paths, fixtures, checks, and Core exclusions are complete
- [ ] The generated Codex work order passes the module-scope readiness check

## Start Authorization

- [ ] Branch is `module/<issue-number>-<module-id>`
- [ ] Branch starts from the current approved baseline
- [ ] No overlapping module assignment exists
- [ ] Core RFC dependencies are approved and merged
- [ ] The assignee understands that production loading, host side effects, and hidden network are prohibited

Assignment is ready only when every applicable item is checked. This checklist
authorizes development, not merge or production activation.
