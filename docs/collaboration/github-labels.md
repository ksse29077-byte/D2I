# Recommended GitHub Labels

The repository currently has only GitHub's default labels. The following
labels are a provisioning plan; this commit does not create them in GitHub.

| Label | Purpose | Color |
| --- | --- | --- |
| `area:cognitive-module` | Module implementation and evaluation | `1D76DB` |
| `area:cognitive-core` | Core-owned contract or runtime law | `B60205` |
| `type:feature` | New bounded behavior | `0E8A16` |
| `type:contract-change` | Core RFC and versioned contract work | `D93F0B` |
| `type:evaluation` | Metrics, fixtures, and benchmarks | `5319E7` |
| `type:security` | Security boundary or negative tests | `B60205` |
| `status:proposal` | Not ready for assignment | `FBCA04` |
| `status:ready` | Complete and approved for assignment | `0E8A16` |
| `status:in-progress` | Assigned implementation underway | `1D76DB` |
| `status:blocked` | Waiting on an explicit dependency | `D93F0B` |
| `status:review` | PR or owner review underway | `5319E7` |
| `risk:low` | Low contract and security impact | `C2E0C6` |
| `risk:medium` | Requires focused review | `FBCA04` |
| `risk:high` | Core/security owner review required | `B60205` |
| `runtime:deterministic` | Deterministic replay required | `0E8A16` |
| `runtime:model-backed` | Learned model; Core review required | `5319E7` |
| `network:denied` | Reference default, no network | `C2E0C6` |
| `network:required-review` | Network proposal; implementation blocked | `B60205` |

Provision these labels in repository settings before adding them to Issue Form
front matter or CI requirements. Until then, forms use an empty label list and
do not claim automation that GitHub cannot apply.
