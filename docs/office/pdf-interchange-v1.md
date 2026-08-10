# PDF Interchange v1

OFFICE-500 turns a verified editable Office artifact into a separately verified
fixed-format projection. The source remains truth; the PDF is a submission
artifact with exact lineage.

## Contract Flow

```text
verified source generation
-> signed export backend approval
-> finalization intent and closed profile
-> exact request and one-shot activation binding
-> native Office fixed-format export
-> fresh PDF snapshot
-> independent Windows PDF render
-> geometry and visual verification
-> immutable source/PDF pair
-> signed finalization seal
-> interchange and submission manifests
```

`crates/d2i-pdf-interchange` owns the platform-neutral contracts. The 25
generated Draft 2020-12 schemas under `schemas/pdf` reject unknown fields,
unbounded collections, raw absolute paths, credentials, scripts, arbitrary COM,
and external exporter pointers.

## Trust Boundary

The Desktop runtime selects a closed backend and builds the signed binding.
Only the isolated Windows worker sees a resolved filesystem path. Word, Excel,
and PowerPoint receive no network egress, execute on a private desktop, and use
only the official fixed-format export API. The activation is one-shot and exact
to organization, Case, Role, lease, Work Grant, workspace, source generation,
profile, backend, application, worker, policy, and output artifact.

The PDF renderer is a different executable in a zero-capability AppContainer.
It receives one copied PDF, one bounded output directory, one report path, and
fixed resource limits. It cannot mutate the source or promote PDF content into
facts.

## Profiles

- `submission_static`: print optimization, minimal metadata, no hidden content,
  external links rejected, no viewer auto-open.
- `internal_review`: the same active-content and network denial with internal
  structure aids allowed by the fixed profile.
- `archive_pdfa_requested`: passes the supported Office PDF/A request flag and
  separately records that external conformance is unverified.

## External PDF

An external PDF is render-only untrusted input. Bounds are stricter than for a
D2I-generated PDF. Malformed, password-protected, oversized, excessive-page,
and timed-out inputs fail closed. V1 does not collect a PDF password and does
not infer authoritative facts from rendered pages.

## Command

Deterministic non-admin gates:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-pdf-interchange-v1.ps1 `
  -Mode All
```

Certified product gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-pdf-interchange-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office450EvidenceRoot C:\path\to\sealed-office450 `
  -OutputRoot target\d2i-office500-pdf-interchange `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

`All` is not certified product Completion. `-Resume` may reuse only model
evidence whose exact model/runtime hashes and zero-authority counters still
validate.
