# ADR 0041: Bounded Presentation Context, Typed-Fact Planning, and Private-Desktop PowerPoint

- Status: Accepted
- Date: 2026-08-09
- Decision owner: D2I Core / Track O

## Context

OFFICE-400 must create and edit presentations from large templates and
OFFICE-300 spreadsheet results without putting a complete PPTX, raw XML,
arbitrary geometry, workbook cells, or COM expressions in model context.
PowerPoint chart creation also requires a real presentation window on the
installed Office build, while D2I must not steal focus from the user's input
desktop.

## Decision

`d2i-presentation-capability` owns versioned semantic snapshots, closed query
plans, context slices, briefs, slide plans, typed mutations, signed backend
approvals, exact operation bindings, receipts, semantic diffs, verification,
replay, Completion, and certification. It contains no vendor COM type and no
filesystem path or executable command supplied by a model.

Presentation context is selected before model invocation. V1 admits at most
eight template slides, sixteen OFFICE-300 typed facts, 32 KiB by contract, and
16 KiB in the product Completion. A 120-slide source template and a
160,000-cell workbook therefore remain private. Models emit only a semantic
brief and slide plan. They never emit PresentationML, chart formulas, VBA,
COM method names, scripts, or raw paths.

Two separately approved backends lower the same semantic mutation contract:

1. `pptx_file` performs bounded ZIP/XML inspection and deterministic,
   append-only PPTX generation changes.
2. `powerpoint_com` performs the small set of live operations that require
   installed PowerPoint: text, embedded image, table, chart, save-copy, and
   rendering.

The live worker creates a private Windows desktop, moves its COM apartment to
that desktop, and opens PowerPoint with a real window there. The application
is visible only on the private desktop, never on the interactive input
desktop. `AutomationSecurity` is force-disabled before file open and alerts
are non-interactive. The worker saves to a new generation with `SaveCopyAs`,
closes the document, quits the application, restores the original thread
desktop, and closes the private desktop handle.

Charts are generated with the fixed `Shapes.AddChart2` lowering. Categories
and integer values come only from an exact `PresentationFactBindingV1` over
OFFICE-300 query facts. The embedded ChartData workbook is internal and has no
external relationship. PPTX admission recursively validates the embedded
`.xlsx` ZIP and rejects traversal, expansion excess, macros, external links,
connections, OLE, ActiveX, scripts, and executable content.

PowerPoint and chart Excel are binary-hash and PID-snapshot bound. WFP applies
exact temporary non-loopback denial to both executables during Completion.
Graceful COM close is attempted first. If Office leaves a dedicated
`/automation -Embedding` Excel server, only a post-snapshot PID whose live
image exactly matches the sibling approved `EXCEL.EXE` may be terminated.
The fallback is recorded in the worker and protected audit receipt. Existing
user Office processes are never selected by name for termination.

Every mutation still requires Role/Case/lease/Work Grant authority, signed
workspace and backend approval, Policy admission, one-shot activation, exact
source generation and hashes, a pinned worker, a new artifact generation,
independent fresh reopen, semantic diff, structural verification, protected
audit, and verified closure.

## Consequences

- Large deck and workbook size no longer determines model context size.
- Table, summary, and chart values share the same typed fact lineage.
- A hidden-window API limitation does not interrupt the user's desktop.
- File-level chart authoring remains unsupported in v1; live PowerPoint owns
  fixed chart creation.
- Visual quality v1 is structural verification plus actual 1280x720 PNG
  rendering. It is not a general aesthetic evaluator.
- Exact-image termination of dedicated chart Excel is an audited compatibility
  fallback for the installed Office build, not authority to terminate user
  Excel processes.

## Official API Basis

- `Slides.AddSlide`: https://learn.microsoft.com/en-gb/office/vba/api/powerpoint.slides.addslide
- `Application.AutomationSecurity`: https://learn.microsoft.com/en-us/office/vba/api/powerpoint.application.automationsecurity
- `Shapes.AddChart2`: https://learn.microsoft.com/fr-fr/office/vba/api/powerpoint.shapes.addchart2
- `Shapes.AddPicture`: https://learn.microsoft.com/pt-br/office/vba/api/powerpoint.shapes.addpicture
- `Presentation.SaveCopyAs`: https://learn.microsoft.com/en-us/office/vba/api/powerpoint.presentation.savecopyas
- `ChartData.Workbook`: https://learn.microsoft.com/en-us/office/vba/api/powerpoint.chartdata.workbook
- `Slide.Export`: https://learn.microsoft.com/es-es/office/vba/api/powerpoint.slide.export
- `TextFrame2`: https://learn.microsoft.com/en-us/office/vba/api/office.textframe2
