# PDF Render Verification v1

The OFFICE-500 verifier uses `Windows.Data.Pdf` directly. It does not launch a
browser, Acrobat, the default PDF application, a print path, Python, Node, or an
external conversion service.

## Sandbox

Each request receives a fresh zero-capability AppContainer profile and a fresh
directory containing only a copied renderer executable and copied PDF. The
input tree is read/execute, render and report directories are read/write, and
all other paths remain inaccessible. A Windows Job permits one process, caps
memory at 768 MiB, kills the owned tree on close, and enforces a 120-second
deadline. Temporary exact WFP policy denies non-loopback egress for both the
application and verifier image.

Profile, WFP policy, job, copied input, generated PNG files, and sandbox ACLs
are cleaned on success and failure. Existing user processes are baseline
preserved. Exact viewer-image PID snapshots prove that Completion did not
launch Edge or a desktop PDF reader.

## Render Contract

The renderer validates expected PDF SHA-256 and file size before load. Every
page is rendered as PNG at 1800 pixels wide with a white background and high
contrast disabled. It records page dimensions, rotation, output dimensions,
PNG hash, non-white ratio, blankness, luminance/color/edge/occupancy buckets,
and a canonical fingerprint hash.

Requests bound page count, PDF bytes, total pixels, dimensions, output PNG
bytes, worker memory, per-page time, total time, and freshness. External PDFs
use stricter page and byte limits. Unknown fields, stale requests, malformed
PDFs, password-required loads, oversize inputs, excessive page counts, pixel
budget escapes, and timeouts fail closed.

## Fidelity

Geometry checks page count, dimensions, rotation, hidden-unit leakage, and
unexpected blank pages. PPTX finalization also compares at least five existing
PowerPoint source renders with PDF page renders using a calibrated normalized
non-white occupancy envelope. These deterministic metrics detect catastrophic
layout loss; they are not a claim of subjective visual perfection.
