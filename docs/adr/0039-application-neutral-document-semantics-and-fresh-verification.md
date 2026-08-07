# ADR 0039: Application-Neutral Document Semantics and Fresh Verification

- Status: Accepted
- Date: 2026-08-08

## Context

OFFICE-100 established approved artifact discovery, immutable originals,
working copies, version lineage, and an executable-bound file worker. It did
not understand or mutate document content. OFFICE-200 must produce useful HWPX
and DOCX documents without turning XML paths, COM dispatch names, application
menus, or public MCP tools into model authority.

HWPX is a public ZIP/XML format suitable for a bounded D2I-owned backend.
Legacy HWP is a different binary format and Hancom Automation requires
separate installation and commercial license evidence. DOCX likewise supports
a deterministic file backend, while installed desktop Word provides a live
compatibility path only in an interactive current-user session.

## Decision

The Cognitive and Policy planes use closed application-neutral document
operations and stable semantic node IDs. Raw XML, XPath, COM expressions,
ProgIDs, method names, absolute paths, scripts, commands, and external URLs are
not operation fields. Backend selection is deterministic from format,
descriptor, signed approval, installed application identity, supported
operation, and license evidence.

HWPX and DOCX are first-class file formats. Their parsers and writers remain
separate adapters over a shared `DocumentSemanticSnapshotV1`. Input packages
are read in bounded memory and reject traversal, duplicate or symlink entries,
decompression excess, malformed XML, DTD/entity declarations, external
relationships, macros, OLE/ActiveX, and executable active content. Unknown
safe parts are preserved. Originals are immutable and each mutation creates a
new atomic generation.

Legacy HWP mutation requires a separately approved licensed Hancom Automation
backend or a future certified D2I binary backend. Without explicit commercial
automation license evidence it reports
`requires_licensed_hancom_backend`; installed HWP alone is insufficient.

Word COM runs only in a dedicated hidden current-user child worker. The worker
uses a fixed CLSID and reviewed fixed method lowering, forces Office automation
security, binds the exact WINWORD path/hash/session/document/generation, and
protects pre-existing Word processes. It is never a service or session-zero
automation path. Completion installs and exact-verifies an application-scoped
WFP loopback-only policy, using a temporary zero-capability AppContainer SID as
the verifier principal, and removes both policy and profile after the bounded
sequence.

One Policy admission and one KRN activation authorize exactly one semantic
mutation. After every operation the child saves and closes, the parent freshly
reopens the generated package, compares content and semantic state, writes a
diff and verification, and only then permits the next operation. Ambiguous
save outcomes require inspection before recovery; blind replay is forbidden.

The protected OFFICE-100 registry remains the only durable truth. Document
packs, descriptors, signed approvals, snapshots, intents, bindings, receipts,
diffs, verification, quality, equivalence, replay, WFP evidence, and
certification are hash-linked in that store. Public HWP/Office MCP projects are
design and offline conformance references only and are absent from production.

## Consequences

General Office Cases can create and structurally verify Korean HWPX and DOCX
reports, including headings, paragraphs, tables, embedded images, styles, and
bounded layout. Actual Word can open, modify, save, close, and freshly verify a
DOCX without exposing broad COM or network authority.

The extra save/close/reopen cycle is intentionally slower than a long-lived
automation session. It gives each mutation an independently observable result
and prevents one activation from becoming a document macro.

Password-protected files, digitally signed mutation, tracked-change fidelity,
macros, active content, legacy DOC mutation, browser download, full visual
rendering, and PDF interchange remain outside v1. Excel begins at OFFICE-300
and is not implemented here.

## Alternatives

Direct model-to-COM, model-generated XML, and public MCP execution were
rejected because they create arbitrary authority and supply-chain runtime
dependencies. Using only Word or Hancom UI automation was rejected because it
is non-deterministic, license- and installation-dependent, and difficult to
verify safely. Treating HWP and HWPX as one format was rejected because it
would overclaim legacy support. Batch mutation under one activation was
rejected because partial failure cannot be safely replayed.
