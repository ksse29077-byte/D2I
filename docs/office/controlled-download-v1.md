# Controlled Download v1

OFFICE-600 downloads files through the one-shot network worker, never through
Edge. A download remains untrusted from intent through Workspace promotion.

## Pipeline

```text
download-allowed brief and source policy
-> exact source snapshot/link intent
-> URL and fresh DNS admission
-> bounded worker download
-> create-new partial file and atomic quarantine rename
-> DownloadQuarantineRecordV1
-> Windows IAttachmentExecute CheckPolicy and Save
-> fresh existence, size, and SHA-256 observation
-> extension, MIME, magic, package, macro, and parser validation
-> exact promotion authorization
-> atomic no-overwrite Workspace import
-> DownloadPromotionReceiptV1
```

`Prompt`, `Disable`, `Unavailable`, deletion, mutation without a new bound hash,
or a missing file cannot promote. Attachment Services is one trust signal; it
does not replace format validation.

`Prompt` is an explicit human-exception outcome. Product runtime code never
changes Attachment Manager policy, suppresses a security warning, invokes a
prompt automatically, or rewrites the source URL to obtain `Enable`. The
administrator-only Completion qualification may temporarily stage the
installed ADMX user-scoped Low Risk inclusion as `.txt` only. It requires TXT
`Enable` while CSV and PDF remain `Prompt`, then restores the exact original
registry types and bytes. Zone preservation, antivirus notification,
SmartScreen, and the remaining Attachment Manager policy stay unchanged.
Failure evidence retains only the structured trust result while all owned
quarantine and network temporary directories are removed.

## Format Gates

- PDF: Windows.Data.Pdf bounded load/render; password, page, geometry, timeout,
  and pixel limits apply.
- DOCX and HWPX: OFFICE-200 bounded package parsers and semantic inspection.
- XLSX: OFFICE-300 package admission and workbook inspection.
- PPTX: OFFICE-400 package admission and presentation inspection.
- TXT and CSV: valid UTF-8, line and byte limits, no embedded NUL.
- PNG and JPEG: recognized magic and bounded non-zero dimensions.

OOXML/HWPX packages reject traversal, duplicate or excessive entries, expansion
bombs, macros, executable/OLE content, external links/relationships, connection
files, and generic archives. `.docm`, `.xlsm`, `.pptm`, executables, scripts,
shortcuts, disk images, and archives are never eligible. Extension, declared
content type, detected magic, expected class, and parser result must agree.

## Filename and Workspace Safety

Untrusted `Content-Disposition` is hashed, not trusted as a path. Traversal,
absolute or separator-bearing names, ADS colons, controls, trailing dot/space,
Windows device names, and unsafe suffixes are rejected. Promotion generates a
semantic filename from the artifact ID and detected class.

Workspace import streams at most 256 MiB, rejects symbolic links and reparse
points, creates a same-directory temporary file with no overwrite, verifies the
streamed hash, atomically renames, then re-observes the final artifact. The
receipt binds the quarantine record, trust report, validation report, source
snapshot/link, workspace generation, policy, final hash, and artifact ID.

Validation and promotion never convert external content into authoritative
facts. The resulting artifact remains labeled `external-untrusted-artifact`.
