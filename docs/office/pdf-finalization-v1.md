# PDF Finalization v1

PDF finalization is an evidence gate, not a file-extension conversion.

## Readiness

`ready_for_submission` is true only when all of these bind to one source
generation and one output artifact:

- verified source snapshot and quality result;
- signed, unexpired backend approval;
- closed export profile and finalization intent;
- exact policy decision and consumed one-shot activation;
- signed Office application and worker hashes;
- native fixed-format export receipt and stable output hash;
- independent PDF load, page render, geometry, and lineage checks;
- visual fidelity evidence when a PPTX design reference exists;
- protected audit terminal and signed finalization seal.

The pair is immutable. A source mutation creates a new source generation,
supersedes the old pair, and makes the old submission manifest unusable. An
ambiguous worker response is observed from the filesystem and PDF backend
before any retry; blind duplicate export is forbidden.

## Format Rules

Word page count is compared with Word's native page statistic. Excel exports
only approved visible sheets and verifies the resulting print scope.
PowerPoint excludes hidden slides, verifies slide count and aspect ratio, and
compares independently rendered PDF pages with existing source renders.

PDF/A reporting has three independent values: request selected, exporter flag
delivered, and external conformance verified. OFFICE-500 leaves the third false
because no approved independent validator is part of v1. PDF/UA is not claimed.

HWPX-to-PDF is not silently routed through Word, LibreOffice, or a printer. Its
exact status is `requires_licensed_hancom_render_backend`.

## Recovery

Crash windows A-M cover intent through source-generation change during
finalization. Durable evidence is reused only after exact hash and cleanup
verification. Repair may complete a missing snapshot, verification, pair,
seal, manifest, or Case update; it does not repeat a proven native export.
