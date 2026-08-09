# ADR 0040: Bounded Spreadsheet Query, Typed Facts, Context Slicing, and Excel Calculation

## Status

Accepted for D2I-OFFICE-300 implementation. Product Completion remains subject
to the elevated Excel WFP gate.

## Context

A spreadsheet can contain millions of cells while a local model has a finite
context window. Sending a workbook, worksheet XML, COM dump, or a broad cell
range to Qwen would create unbounded cost, disclose unrelated data, and let
cell text act as prompt injection. Model-authored formulas, SQL, XPath, COM, or
scripts would also turn a semantic request into an execution language.

XLSX is a ZIP/XML package. Excel adds valuable compatibility and calculation,
but its object model and process lifecycle are broader than the mutation D2I
needs. A workbook write is not a verified outcome until a separate bounded
parser reopens the saved generation and compares semantic state.

## Decision

D2I uses this read path:

```text
bounded XLSX parser
-> private workbook semantic index
-> closed SpreadsheetQueryV1 algebra
-> evidence-bound SpreadsheetTypedFactV1 values
-> deterministic SpreadsheetContextSliceV1
-> VerifiedObservation Situation facts
-> local model
```

Workbook values stay in the private index. The public semantic snapshot holds
stable sheet, table, column, range, count, type, and hash metadata. The v1
query algebra is limited to lookup, predicate filter, and grouped aggregate.
It has typed operands, exact column IDs, finite scan/result limits, no user
expression language, and deterministic ordering and hashing.

A context slice is bounded by all of fact count, canonical serialized bytes,
and estimated tokens. OFFICE-300 defaults cap a slice at 64 facts, 32 KiB, and
8,192 estimated tokens; product E2E uses the narrower 8 facts, 8 KiB, and 2,048
tokens. Each fact carries type, unit, source table and columns, source range
hash, source row count, confidence, priority, evidence, and a self-hash. Raw
credential-like values are rejected before slicing. Untrusted cell text remains
data and never becomes an instruction or authority.

The write path remains:

```text
semantic mutation
-> Policy admission (OfficeSpreadsheet)
-> exact Role/Case/lease/Work Grant/workspace/backend binding
-> one-shot activation
-> executable-hash-bound worker
-> new immutable generation
-> independent fresh reopen
-> semantic diff and postcondition verification
-> protected Office audit/store
```

XLSX file mutation is D2I-owned Rust. It supports bounded value update and row
append. It does not claim formula calculation. Formula mutation uses a hidden,
interactive-current-user Excel COM worker. The worker has a fixed CLSID and a
reviewed method/property set. It exposes no generic ProgID, member name, VBA,
formula text, macro, query, process, filesystem, or network operation.

Formula intent is a tagged enum: sum range, difference, product, or ratio over
stable semantic IDs. The trusted worker alone lowers these variants to fixed
A1 formulas. Excel is exact-path/hash bound, macros/events/alerts/update-links
are disabled, full recalculation is requested, and the saved XLSX is reopened
by the independent parser. Completion installs and exactly verifies an
application-scoped IPv4/IPv6 WFP loopback-only policy before and after Excel.

XLSX package admission rejects duplicate or shadow entries, traversal, ZIP64,
encryption, expansion excess, DTD/entity/processing-instruction XML, malformed
relationships, external links, connections, query tables, macros, scripts,
OLE/embeddings, ActiveX, and executable content. Originals are immutable and
all writes create a new atomic generation.

CSV identifiers are reserved in the contract but the v1 CSV production
backend is disabled. Public spreadsheet MCPs remain research/design inputs and
are not downloaded, invoked, or placed on the production path. Production uses
no Python or Node runtime.

## Consequences

- Tens of thousands of cells can be scanned without entering model context.
- Query/result/slice hashes are reproducible and evidence can be traced back
  to exact workbook ranges without logging the workbook.
- The model cannot create arbitrary queries, formulas, COM calls, or paths.
- Excel calculation is available only on an installed licensed desktop client
  in an interactive user session and never as background server automation.
- Visual fidelity, charts, pivots, Power Query, data model, macros, protected or
  signed workbooks, and external links are explicit v1 exceptions.
- Excel may remain alive after a graceful COM `Quit`; only the newly observed,
  exact-image-bound PID may be terminated, and that cleanup mode is recorded
  in the worker receipt.

## Alternatives Rejected

- **Whole workbook or worksheet in Qwen context:** unbounded, privacy unsafe,
  and hostile-cell sensitive.
- **Model-authored SQL/Python/formula/COM:** creates an ambient execution
  language and bypasses semantic admission.
- **openpyxl or public MCP in production:** adds Python/public-tool authority
  and does not provide the trusted Excel calculation boundary.
- **Excel COM only:** prevents deterministic offline package security and fresh
  verification on systems without Excel.
- **File backend claiming calculated formulas:** cannot prove recalculated
  cached values and would create false completion.

## References

- Microsoft SpreadsheetML document structure and cell-value documentation.
- Microsoft Excel `Workbooks.Open`, `Range.Value2`,
  `CalculateFullRebuild`, `AutomationSecurity`, and `DisplayAlerts` contracts.
- ADR 0038 and ADR 0039.
