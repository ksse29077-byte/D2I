# Document Design v1

HWPX and DOCX design features reuse the OFFICE-200 Rust-native semantic
snapshots. Page class, section and node structure, style catalog hash, heading,
paragraph, table, image, density, and layout summaries are lowered into common
design roles without exposing package paths or raw XML.

Document and presentation grammars may share brand role names but remain
format-specific. Presentation spacing or slide slots are never copied into an
A4 report. HWPX result-report families retain their own page setup, margins,
heading hierarchy, body rhythm, table system, image/caption role, and footer.

HWPX output is freshly reopened and structurally verified. Hancom DVC is an
official conformance reference, not production execution authority. Actual
Hancom rendering and legacy HWP automation remain unavailable until a
commercial license and separately approved backend are present. DOCX live
rendering continues to use only the existing OFFICE-200 Word authority when a
task explicitly requires it.
