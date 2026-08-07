# ADR 0038: General Office Capability Priority, Untrusted Public Skill Intake, and Evidence-Bound Artifact Workspace

- Status: Accepted
- Date: 2026-08-08

## Context

Track K, Track W, and EDGE-100 provide a safe bounded execution loop,
persistent digital employees, and enterprise API work. The product's canonical
goal is general office and computer work. Expanding next into physical sensor,
OT, and robot planes would leave common office document workflows without a
safe shared file lifecycle.

Public MCP and skill projects provide useful operation taxonomies and edge-case
knowledge, but expose caller-selected paths, broad COM, Python/Node runtime,
process launch, network, uncertain licenses, and published vulnerabilities.
They cannot become authority merely because their tool surface is convenient.

## Decision

Track O, OFFICE-100 through OFFICE-900, precedes EDGE-200 through EDGE-400.
HWP/HWPX is first-class for the Korean market alongside Word, Excel,
PowerPoint, and PDF.

Authority order is official API/SDK, public format, mature library, community
MCP, then UIA fallback. Public sources are revision/hash/license/advisory pinned
and quarantined. Their catalogs and candidates are reference-only. No model-to-
MCP path, runtime download, remote MCP, or production Python dependency is
allowed.

The shared artifact workspace uses opaque IDs and relative tokens outside the
trusted runtime. A signed profile and root binding pin organization/Role scope,
local root identity, DACL, limits, operations, retention, immutable-original,
version, backup, and delete policy. Network shares, removable media, traversal,
symlinks, junctions, and reparse points are denied in v1.

Every mutation binds Role, Case, lease, Work Grant, exact artifact hash and
generation, semantic intent, Policy, and one-shot activation. A hidden,
executable-hash-bound worker performs one bounded operation. Atomic writes and
fresh post-operation inspection precede a verified receipt. External
modification, lock change, or ambiguous crash state forces fresh observation;
blind replay is forbidden.

Originals are immutable by default. Working copies and versions preserve
content identity, parent lineage, Case/Role provenance, receipts, and
verification. The protected registry is content addressed, append-only, hash
chained, DACL protected, single-writer, bounded, rollback checked, and
deterministically repairable.

Future application packs expose semantic operations and own backend selection.
HWP Automation/SDK/HWPX mutation, Excel COM/Office.js/file-level code, and
PowerPoint COM/Office.js/file-level code stay behind separate bounded workers.
Core never branches on an application family and never exposes arbitrary COM.

## Consequences

General office Cases can safely discover, copy, rename, version, move, and
verify files before content-editing packs exist. Public tool ecosystems can be
studied without making supply-chain availability or trust part of Completion.
The extra identity, policy, and verification steps intentionally trade some
latency for deterministic fail-closed behavior.

OFFICE-100 does not claim HWP, Excel, or PowerPoint editing. Those begin in
OFFICE-200 through OFFICE-400. Browser download, email/messenger, and long-
horizon multi-app work remain later Track O tasks.

## Alternatives

Direct model-to-MCP execution was rejected because tool schema is not
authority and broad path/process/network scopes bypass D2I Policy and KRN.
Vendoring public servers was rejected because it imports runtime language,
dependency, license, and update risk. Putting application-specific planning in
Core was rejected because it hardcodes product taxonomy and couples the
Cognitive plane to backend details. Continuing to EDGE-200 first was rejected
because it does not open the primary general-office product workflow.
