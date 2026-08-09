# Spreadsheet Work v1

OFFICE-300 adds application-neutral spreadsheet inspection, deterministic
query, bounded context slicing, and verified XLSX mutation. It does not make a
model a spreadsheet interpreter or expose a generic Excel automation API.

## Context Boundary

The workbook parser builds a private typed index. Only a query result can
produce `SpreadsheetTypedFactV1` values, and only a deterministic context slice
can project those facts into `SituationFactV1`. The model never receives XLSX
bytes, worksheet XML, a full cell dump, formulas, paths, COM objects, or
credentials.

| Boundary | Limit |
| --- | ---: |
| Workbook bytes | 256 MiB |
| Populated cells | 2,000,000 |
| Query scan cells | 1,000,000 |
| Query facts | 256 |
| Context facts | 64 |
| Context bytes | 32 KiB |
| Product E2E context | 8 facts / 8 KiB / 2,048 tokens |

`Lookup`, `Filter`, and `Aggregate` are the complete v1 query algebra. Query
plans reference stable table/column IDs and typed values. There is no SQL,
regex, Python, JavaScript, formula expression, fuzzy classifier, or arbitrary
operator field.

## Write Backends

| Backend | Enabled operations | Boundary |
| --- | --- | --- |
| XLSX file | set existing value, append row | D2I Rust ZIP/XML worker; no formula calculation |
| Excel COM | set value, append row, typed formula | Installed desktop Excel, hidden current-user process, fixed COM lowering |
| CSV file | none in v1 | Contract identifier reserved; production disabled |

Every mutation consumes one exact activation and produces a new generation.
The parent process independently reopens the output and verifies the snapshot,
diff, postconditions, immutable original, protected audit append, and process
cleanup. Excel Completion additionally requires exact WFP loopback-only policy
verification before and after dispatch.

## Formula Contract

The only formula variants are:

- sum over one stable range ID
- difference between two stable cell IDs
- product of two stable cell IDs
- ratio of two stable cell IDs

Raw formula strings are absent from Rust and JSON contracts. External workbook
references, URLs, DDE, RTD, WEBSERVICE, HYPERLINK, macros, connections, query
tables, and data-model parts are rejected before observation.

## Commands

Run deterministic contracts, schemas, package attacks, workers, and regressions:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-spreadsheet-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office300-spreadsheet-work/all
```

Run product Completion from one elevated interactive deployment session:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-spreadsheet-work-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office200EvidenceRoot C:\path\to\sealed-office200 `
  -OutputRoot target/d2i-office300-spreadsheet-work/completion `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

`All` is non-elevated and is not product Completion. `Completion` requires
actual pinned Qwen, installed Authenticode-valid Excel, exact WFP policy,
signed backend approvals, protected audit, replay, certification, and zero
owned residual state.

## Certified Completion

The certified reference run processed 20,000 rows by eight columns (160,000
cells), produced 128 query facts, and admitted eight facts in a 5,455-byte
model context. One actual pinned Qwen invocation completed without a raw
workbook dump. The file worker and installed Excel COM worker each performed
one verified mutation; all three workbook generations were independently
reopened. Exact temporary WFP isolation, ten crash windows, deterministic
replay, protected audit, signed certification, and terminal cleanup passed.
All safety counters and owned residual counters are zero. Exact report,
certification, replay, and audit hashes remain in the sealed Completion
artifacts rather than being copied into the source tree they attest.

## Known Limits

Charts, pivots, Power Query, data model, macros, add-ins, external links,
password protection, digital signatures, tracked collaboration, visual layout
quality, arbitrary styles, CSV mutation, browser download, email, clipboard,
and background Office services are outside v1. Excel licensing and activation
remain the operator's responsibility; D2I does not bypass them.
