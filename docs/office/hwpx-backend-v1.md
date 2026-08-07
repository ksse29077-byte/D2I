# HWPX File Backend v1

HWPX is the first-class Korean document format in OFFICE-200. The backend is a
D2I-owned Rust ZIP/XML adapter; it does not launch HWP and does not depend on a
Hancom Automation license.

The reader validates the HWPX mimetype as the first stored entry, required
package parts, relative entry names, unique entries, supported compression,
bounded expansion, and bounded XML. It lowers sections, paragraphs, headings,
tables, images, and page layout to stable semantic nodes. The writer preserves
unknown safe parts and creates a new atomic package generation after one
semantic operation. A fresh independent reopen verifies the generated state.

The production dependencies are `zip = 4.6.1` with default features disabled
and only the zlib-rs deflate path, and `quick-xml = 0.41.0`. Both are MIT
licensed and pinned in `Cargo.lock`. They provide only bounded package/XML
mechanics; D2I owns path, active-content, resource, semantic, authority, and
verification policy. They can be replaced behind the HWPX adapter without
changing Cognitive or KRN contracts.

Hancom's `hwpx-owpml-model` revision
`1453388472c703a4b299a0834f425cdac16644b9` and DVC revision
`19a985ec047df629240cbcbe2cec17f19ad1a014` are design/offline conformance
references, not production runtime dependencies. The Apache-2.0 fixture source
and exact provenance are recorded in `fixtures/office/document/SOURCES.md`.

Legacy `.hwp` is not HWPX. Its v1 mutation status is
`requires_licensed_hancom_backend`. Installed HWP and a valid binary signature
do not constitute commercial Automation license evidence.
