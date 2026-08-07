# General Office Capability and Artifact Workspace v1

OFFICE-100 opens Track O by adding two shared foundations: quarantined public
capability-source intake and a safe local artifact workspace. It removes the
human dependency of manually locating, copying, renaming, versioning, and
moving approved office artifacts while preserving exact authority and fresh
verification.

## Capability Intake

`CapabilitySourceRecordV1` binds exact source revision, content hash, license,
runtime requirements, exposure, security advisories, tool catalog, assessment,
and evidence. `McpToolCatalogSnapshotV1` stores normalized tool IDs and schema
hashes without embedding third-party code. `OfficeCapabilityCandidateV1` is a
reference-only proposal for a later D2I-owned semantic contract.

There is no runtime-approved source state. Models never call MCP. Production
never downloads from GitHub, NPM, or PyPI. Official API/SDK material is the
primary authority; community code is compatibility and test knowledge.

## Workspace Contract

The model and Planner may produce only `WorkspaceOperationIntentV1` with
artifact/workspace/folder IDs and a bounded filename. The trusted runtime joins
Role, Case, lease, Work Grant, signed workspace policy, root binding, exact
source hash/generation, Policy decision, and activation in
`WorkspaceOperationBindingV1`.

The Desktop dispatcher verifies the signed profile, current-user/SYSTEM DACL,
canonical local root identity, worker executable hash, one-shot activation,
operation class, and source identity. A hidden child worker receives one exact
copy, rename, move, or version-commit request over bounded stdin. It has no
network, command, script, arbitrary process, or arbitrary path operation.

## File Lifecycle

Original files are immutable. Editing starts from a working copy. Each version
records source/parent identity, generation, content hash, receipt, Case, Role,
data class, and fresh verification. Writes use a synced temporary sibling and
same-volume atomic move. The caller reopens the destination and verifies hash,
size, location, and old/new state before issuing a verified receipt.

External hash change, Office lock artifact, or ambiguous filesystem state stops
mutation. A fresh observation is required before replanning. Blind copy,
rename, move, or version replay is prohibited.

## Workspace Security

- Local fixed-volume root only; network share and removable media are denied.
- Traversal, absolute, drive-relative, UNC, device, ADS, percent-encoded,
  mixed-slash, control-character, reserved-name, case-collision, and 8.3 alias
  forms are rejected.
- Every existing path component is checked for symlink, junction, and reparse
  behavior before access.
- Resources are bounded by file, total bytes, file/directory count, and depth.
- The content-addressed registry is DACL protected, append-only, hash chained,
  single-writer, atomically indexed, mutation checked, and recovery repairable.
- Protected evidence contains IDs and hashes; no credentials or unrestricted
  user content are logged.

## E2E and Recovery

The official Completion runner uses only synthetic files in a fresh temporary
workspace. Cases A-J cover discovery, working copy, Korean rename, version
generation 1-to-2, output move, external-change recovery, traversal, reparse,
immutable-original overwrite, and Office lock conflict. It also rejects
duplicate activation and proves no raw absolute path entered cognitive
artifacts.

Crash windows A-H cover no-temp, orphan-temp cleanup, index repair, rename
identity recovery, version-hash repair, move identity recovery, stale source,
and lock-state change. Contract replay evaluates 128 scenarios 100 times; it
does not perform 12,800 physical mutations.

## Commands

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-office-capability-workspace-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office-capability-workspace/all
```

Completion requires a sealed EDGE-100 root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-office-capability-workspace-v1.ps1 `
  -Mode Completion `
  -Edge100EvidenceRoot C:\path\to\edge100-completion `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

Use `-Resume` only for exact-bound safe checkpoints. `-Fresh` removes only the
configured output root below repository `target`.

## Non-goals

OFFICE-100 does not edit Office document contents, automate HWP/Excel/
PowerPoint, download through a browser, use network shares, send email or
messages, use clipboard, or run public MCP/Python/Node code in production.
