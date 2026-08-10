# Organizational Design Intelligence v1

OFFICE-450 turns approved organization artifacts into bounded design programs.
It does not fine-tune a model and does not make a language model the design
executor.

## Pipeline

```text
approved manifest
-> bounded PPTX/HWPX/DOCX semantic snapshot
-> normalized design features
-> Gold-weighted deterministic family discovery
-> quarantined Design Pack candidate
-> holdout and tenant-isolation validation
-> signed immutable organization approval
-> exact pack and exemplar selection
-> deterministic typography/layout solver
-> existing Office mutation authority
-> PowerPoint render or HWPX structural reopen
-> hard and soft critics
-> bounded refinement
-> verified artifact and protected audit
```

The public contracts live in `crates/d2i-design-intelligence`. Desktop
extraction is in `products/d2i-desktop/src/design_work.rs`. All 50 production
contract schemas are generated under `schemas/design`; the generator is the
drift authority and rejects file-set or content differences.

## Isolation

Every corpus, feature, profile, family, pack, approval, index, query, solver
request, and critique binds an organization. A collection containing a second
organization is rejected before compilation. Artifact class is an opaque pack
identifier, not Core taxonomy. Alpha and Beta fixtures use distinct family and
exemplar namespaces and cross-tenant queries fail closed.

## Content Minimization

Features contain normalized slot geometry, semantic roles, distributions,
density, approved style identifiers, and hashes. Exemplar records contain no
full source text. Raw Office packages, XML, paths, font binaries, credentials,
and rejected-artifact prose do not enter model context.

The actual Qwen gate receives one verified typed fact, one character-bounded
language requirement, one semantic target, and one allowed language capability.
Raw corpus/XML/coordinate/color/font/font-size and layout authority counters
must all be zero.

## Quality

The hard critic is a release gate. Final hard violations, fact mismatch,
unverified KPI, wrong organization pack, wrong family, overflow, off-canvas,
forbidden overlap, font-policy violation, image/logo distortion, and table or
chart policy violations must be zero. The soft critic must remain inside the
selected family holdout envelope. Intentional bad fixtures must fail and Gold
holdout fixtures must pass.

The certified synthetic corpus contains 40 PPTX decks, 10 HWPX documents, and
10 DOCX documents across two organizations. Training and holdout remain
separate: the holdout includes 48 PPTX slide units and 10 HWPX documents.
Artifact-class exact mapping, template-family top-1 retrieval, and layout-family
selection are computed from those held-out units rather than written as fixed
success values.

Refinement is at most five rounds and selects only closed repair operations.
The preferred overflow order is another approved layout, split, new page or
slide, claim-preserving language compression, allowed font-range reduction,
then human exception.

## Commands

Deterministic non-admin gates:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-design-intelligence-v1.ps1 `
  -Mode All
```

Certified product gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-design-intelligence-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office400EvidenceRoot C:\path\to\sealed-office400 `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

`Completion` requires an elevated interactive token only for temporary exact
WFP installation. PowerPoint runs on a private desktop and does not take input
focus. `All` is not product certification.

## Limits

There is no online self-training, bundled proprietary font, arbitrary style
hallucination, image generation, browser asset download, public MCP execution,
video/audio/animation design intelligence, PDF workflow, or licensed Hancom
rendering in v1.
