# Presentation bootstrap fixture

`minimal-template.pptx` is a one-slide bootstrap package generated offline with
`python-pptx` 1.0.2 (MIT). It contains no macros, external relationships,
embedded workbook, OLE object, ActiveX control, or network reference.

The production runtime does not depend on Python. Rust embeds this fixed package,
revalidates every package entry, relationship, content type, and XML part, then
creates deterministic new generations. The fixture may be replaced with any
equivalent validated PresentationML bootstrap package after its hash and live
PowerPoint compatibility tests are updated.
