# PowerPoint Backend v1

The live backend is a closed PowerPoint Object Model lowering, not a generic
COM bridge. Supported v1 operations are `SetText`, `InsertImage`,
`InsertTable`, and `InsertChart`. Every request contains semantic IDs, bounded
text, typed facts, exact source/application/worker hashes, a new destination
generation, and resource limits.

The worker uses a dedicated private Windows desktop because this PowerPoint
build requires a real presentation window for `Shapes.AddChart2`. No desktop
switch occurs. The user cannot see or focus the private window. Modal input,
SendKeys, default-setting changes, add-in changes, and arbitrary COM dispatch
from Cognitive output are prohibited.

Charts use a fixed clustered-column/bar/line mapping and an internal ChartData
workbook. D2I writes typed integer facts through `Cells.Item`, binds a fixed
internal range, closes the workbook, quits its dedicated Excel application,
and records every chart Excel PID. After a bounded graceful wait, exact-image
termination is permitted only for post-snapshot PIDs bound to the approved
Office `EXCEL.EXE`. The final PPTX reader recursively validates the embedded
workbook and rejects active or external material.

The worker returns process, private-desktop, macro-security, render, overflow,
temporary-file, and cleanup evidence. A parent dispatcher independently
reopens the saved generation and produces the authoritative receipt, semantic
diff, verification, and protected audit entry.
