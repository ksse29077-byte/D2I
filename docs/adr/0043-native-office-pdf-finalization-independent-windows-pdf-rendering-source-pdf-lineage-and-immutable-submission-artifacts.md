# ADR 0043: Native Office PDF Finalization and Immutable Submission Artifacts

- Status: Accepted
- Date: 2026-08-10
- Owners: Core, Office capability, Desktop trust boundary
- Scope: D2I-OFFICE-500

## Context

OFFICE-200 through OFFICE-450 produce verified editable DOCX, XLSX, PPTX, and
HWPX artifacts. Submission workflows also need a stable fixed-format artifact,
but successful export alone does not prove that a PDF is loadable, complete,
visually faithful, current, or related to the approved source generation.

PDF must not replace typed facts or an editable verified source as truth. A
default PDF viewer, print driver, browser, public conversion service, or model
cannot be trusted with finalization authority.

## Decision

Add `d2i-pdf-interchange` as a platform-neutral contract crate and use three
closed native exporters on Windows:

```text
word_fixed_pdf
excel_fixed_pdf
powerpoint_fixed_pdf
```

The exporters call the application's official `ExportAsFixedFormat` API on a
D2I private desktop. They run with macros, links, events, and refresh disabled,
under exact executable binding and temporary WFP loopback-only policy. No
printer automation, `ShellExecute`, `SendKeys`, browser print, arbitrary COM,
or external exporter is permitted.

Every exported PDF is freshly reopened by a separate zero-capability
AppContainer worker using `Windows.Data.Pdf`. It renders bounded PNG pages to a
white background at a fixed width, records geometry and deterministic visual
fingerprints, and never opens Edge, Acrobat, or the default PDF application.
The renderer is job-bounded, WFP-isolated, and write-confined to one temporary
sandbox. Only D2I-owned processes and temporary objects may be removed.

## Truth and Lineage

The verified editable source, source semantic snapshot, and typed fact lineage
remain authoritative. PDF is a fixed projection. A successful finalization
creates an immutable `FinalArtifactPairV1` containing exact source generation,
source/PDF hashes, export profile, backend, receipt, independent verification,
and provenance. Any source hash or generation change supersedes the pair and
removes submission readiness.

`ready_for_submission` requires native export, a fresh stable output, an
independent load and render, page/geometry checks, source lineage, security
checks, and a signed finalization seal. A model statement can satisfy none of
these gates.

## Profiles and Compliance Claims

The closed profiles are `submission_static`, `internal_review`, and
`archive_pdfa_requested`. PDF/A request, exporter flag delivery, and external
conformance verification are recorded separately. Passing an Office PDF/A flag
does not establish certified PDF/A conformance. Structure tags do not establish
PDF/UA compliance.

HWPX remains an editable verified artifact. HWPX-to-PDF reports
`requires_licensed_hancom_render_backend` until an approved licensed backend and
license evidence exist; Word, LibreOffice, and print-driver detours are
forbidden.

## External PDFs

An imported PDF is `ExternalUntrustedPdf`. V1 permits bounded preflight,
sandbox load, page metadata, PNG render, and fingerprints. It cannot become an
editable artifact, authoritative fact source, redistribution-safe document, or
automatic model input. Password collection and arbitrary PDF JavaScript/form
sanitization are not claimed.

## Verification and Recovery

Completion requires two Word, two Excel, and two PowerPoint exports; at least
15 independently rendered pages; at least five PPT source-to-PDF visual
comparisons; one bounded actual Qwen profile-selection call; source-change
invalidation; crash windows A-M; 128 scenarios by 100 deterministic replays;
protected audit; signed certification; and zero residual Office, worker, WFP,
AppContainer, viewer, lock, activation, credential, PDF, or PNG state.

## Official Authorities

- <https://learn.microsoft.com/en-us/office/vba/api/word.document.exportasfixedformat>
- <https://learn.microsoft.com/en-us/office/vba/api/excel.workbook.exportasfixedformat>
- <https://learn.microsoft.com/en-us/office/vba/api/powerpoint.presentation.exportasfixedformat>
- <https://learn.microsoft.com/en-us/uwp/api/windows.data.pdf.pdfdocument>
- <https://learn.microsoft.com/en-us/uwp/api/windows.data.pdf.pdfpage.rendertostreamasync>
- <https://learn.microsoft.com/en-us/uwp/api/windows.data.pdf.pdfpagerenderoptions>

## Alternatives

### Print to PDF or browser printing

Rejected because printer/default-application state is ambient and does not
provide exact source, exporter, output, or no-viewer binding.

### Treat exported PDF as truth

Rejected because fixed-format rendering loses editable semantics and cannot
supersede verified facts or source lineage.

### Use an external converter or PDF library

Deferred. V1 adds no production dependency and uses installed signed Office
plus the Windows PDF platform. A future backend requires a separate signed
approval, security review, license review, and independent equivalence tests.

## Consequences

D2I gains bounded verified submission artifacts without enlarging model
authority or introducing a converter dependency. Product Completion remains a
Windows deployment gate requiring installed signed Word, Excel, and PowerPoint
and one elevated session for temporary WFP policy installation. PDF editing,
OCR, signing, reconstruction, certified accessibility, and licensed Hancom
rendering remain outside v1.
