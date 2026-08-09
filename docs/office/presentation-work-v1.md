# PowerPoint Presentation Work v1

OFFICE-400 turns an approved presentation template, an OFFICE-300 typed-fact
slice, and a bounded semantic slide plan into a verified PPTX generation. It
does not expose package XML, workbook cells, COM, scripts, or arbitrary paths
to a model.

## Pipeline

```text
120-slide template -> semantic snapshot -> closed template query
160,000-cell workbook -> OFFICE-300 aggregate query -> typed facts
template query + facts -> <=8 slides / <=16 facts / <=16 KiB context
context -> semantic brief -> five-slide plan
plan -> Policy + one-shot activation -> PPTX/PowerPoint worker
new generation -> fresh reopen -> semantic diff -> structural verification
-> protected audit -> signed Completion certification
```

The reference E2E creates a July 2026 internal training report with 55
completed, 120 planned, and 18 pending participants. Those values are counts
from an actual deterministic aggregate over a 20,000-row by eight-column
synthetic workbook. The summary, table, and chart bind to the same fact IDs.

## Backends

`pptx_file` handles bounded inspection, slide append, and title/text/package
mutations. `powerpoint_com` handles fixed text, embedded image, table, chart,
save-copy, and PNG rendering operations. Backend approvals are separately
signed and exact-bound to the workspace profile, capability pack, operation
set, worker hash, and installed application hash.

PowerPoint runs on a D2I private Windows desktop. Its required application
window is unavailable to the interactive input desktop, so foreground focus
and user typing are preserved. Macro automation security is force-disabled,
WFP denies non-loopback egress for PowerPoint and chart Excel, and all owned
PIDs are removed without touching baseline user processes.

## Commands

Run non-elevated deterministic checks:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-presentation-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-office400-presentation-work/all
```

Run the one elevated certified product gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-presentation-work-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office300EvidenceRoot C:\path\to\sealed-office300 `
  -ReuseVerifiedPredecessorEvidence `
  -Resume `
  -OutputRoot target/d2i-office400-presentation-work/completion
```

`-Resume` may reuse only a pinned actual-Qwen report and sealed OFFICE-300
evidence whose hashes and zero-residual gates still verify. `-Fresh` removes
only the selected OFFICE-400 output root below `target`.
