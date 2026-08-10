# ADR 0042: Organization-Scoped Design Grammar and Render Quality

- Status: Accepted
- Date: 2026-08-10
- Owners: Core, Office capability, Desktop trust boundary
- Scope: D2I-OFFICE-450

## Context

OFFICE-100 through OFFICE-400 can govern artifacts, edit HWPX/DOCX/XLSX/PPTX,
use installed Office applications, and verify fresh results. Those contracts do
not establish that a newly generated artifact follows one organization's
approved visual language or is ready for business submission without manual
design editing.

Sending company files or a prose request such as "make it attractive" to a
language model is not an acceptable design authority. It exposes excess
content, is difficult to reproduce, and can invent coordinates, colors,
typography, layouts, or visually emphasized facts outside approved policy.

## Decision

Add the platform-neutral `d2i-design-intelligence` crate. Approved artifact
manifests and bounded semantic snapshots compile into content-addressed,
organization-scoped `OrganizationDesignPackV1` values. The Desktop layer only
adapts existing PPTX/HWPX/DOCX snapshots into normalized design features and
reuses existing OFFICE-200/300/400 execution and verification authority.

The hierarchy is exact:

```text
organization -> artifact class -> template family -> exemplar -> grammar
```

No Core enum contains company, department, industry, or work-class taxonomy.
Organization and artifact-class values remain opaque pack data.

## Model Boundary

The language model may receive verified claim references, language, tone,
character and bullet limits, and a bounded list of semantic choices. It may
rewrite prose or choose among those options. It cannot emit or control raw
coordinates, width/height, RGB values, font families, font sizes, line spacing,
margins, PPTX/HWPX/DOCX XML, CSS/HTML layout, COM, VBA, scripts, or mutation
operations.

D2I owns truth, structure, template selection, typography, spacing, grid,
layout, table/chart/image/logo policy, content fit, artifact mutation,
rendering, visual verification, and final closure.

## Corpus and Gold Weighting

Corpus records bind exact organization, artifact hash, format, artifact class,
approval state, data classification, provenance, holdout state, and optional
unit rating. `gold`, `approved`, `legacy_approved`, `deprecated`, and `rejected`
are closed labels. Gold has the strongest positive weight; deprecated and
rejected artifacts cannot become positive production rules. Unit-level Gold
may override a merely approved deck or document without copying its text.

Features store normalized geometry and role/distribution summaries. Exemplar
records store roles, density, hashes, lengths, and line counts rather than full
business prose. Images contribute slot, aspect, fit, and visual-weight facts;
asset reuse still requires separate workspace approval.

## Family and Grammar Compilation

Family discovery is deterministic. Random seed-dependent clustering is
forbidden. Distinct families remain separate instead of being averaged into an
unrepresentative style. Low-data corpora remain `template_lock`; sufficient
single-family evidence may become `family_learned`; broad approved evidence may
become `organization_learned`.

The pack contains typography, spacing, layout, table, chart, image, logo,
profile, provenance, family, and holdout bindings. Font binaries are never
packaged. Missing required fonts are explicit; substitution is allowed only
from an operator-approved fallback list.

## Truth and Visual Claims

OFFICE-300 typed facts remain authoritative for numbers, KPI values, chart
series, and table totals. `VisualClaimIntegrityReportV1` verifies that every
visually emphasized fact exists in that authoritative set. Design cannot
create, modify, or conceal a business fact.

## Critics and Refinement

The hard critic rejects font, overflow, canvas/page, overlap, alignment,
spacing, margin, color-role, logo, table, image, chart, placeholder, required
section, organization, template-family, KPI, and fact violations. The soft
critic measures geometry, hierarchy, spacing, color, and density distance
against a selected family envelope. Text identity is not a style metric.

Refinement is deterministic, uses a closed operation enum, and is capped at
five rounds. It may switch an approved layout, split content, resize within the
approved range, adjust grammar spacing, reflow a table, change approved image
fit, request claim-preserving shorter language, or move content to an allowed
slot. It cannot invent geometry or silently shrink below policy minima.

## Approval and Learning

Compilation produces a quarantined candidate. Production requires holdout
validation and a separate Ed25519-signed organization approval bound to pack
hash, artifact classes, environment, signer, and validity. Production packs
are immutable. Feedback creates a quarantined preference/candidate record;
offline evaluation and approval are required for a new version.

## Runtime Evidence

PPTX quality uses the existing exact-image, macro-disabled, WFP-isolated,
private-desktop PowerPoint render path. HWPX quality uses Rust-native bounded
structural reopen; Hancom rendering remains unavailable without approved
commercial automation license evidence. Completion requires two-organization
isolation, actual pinned Qwen at the language/semantic boundary, actual PNG
rendering, HWPX conformance, protected audit, A-L recovery evidence, 128 x 100
deterministic replay, signed certification, and zero owned residual state.

## Format Authorities

The PresentationML package boundary follows Microsoft's official description
of presentation, slide master, slide layout, slide, theme, shape, picture, and
table parts:

- <https://learn.microsoft.com/en-us/office/open-xml/presentation/structure-of-a-presentationml-document>
- <https://learn.microsoft.com/en-us/office/vba/api/powerpoint.slide.shapes>

The HWPX boundary follows Hancom's published HWP/OWPML format material. The
Hancom OWPML object model and DVC are Apache-2.0 design and offline-conformance
references only; neither is linked into or invoked by the production runtime:

- <https://shop.hancom.co.kr/support/downloadCenter/hwpOwpml>
- <https://github.com/hancom-io/hwpx-owpml-model>
- <https://github.com/hancom-io/dvc>

## Alternatives

### Let the LLM design the artifact

Rejected because it creates excessive context, non-deterministic visual
authority, weak organization binding, and unverifiable fact emphasis.

### Use only exact templates

Retained as `template_lock` fallback but rejected as the sole solution because
content fit and multiple approved artifact families require bounded adaptation.

### Train a visual preference model now

Deferred. A future versioned optional ranker may score bounded candidates, but
it cannot bypass deterministic hard constraints, pack approval, or rendering.

### Bundle proprietary fonts or use public design MCPs at runtime

Rejected. Font installation/licensing is an operator concern. Public tools are
untrusted research inputs and cannot become production execution authority.

## Consequences

The system gains reproducible organization style without enlarging model or
adapter authority. Schema and compiler surface area increase, and actual
PowerPoint Completion still requires one elevated Windows deployment session.
PDF interchange, image generation, online asset download, arbitrary new visual
style generation, and licensed Hancom rendering remain outside v1.
