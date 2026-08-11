# Browser Research v1

OFFICE-600 converts a public research question into a bounded, cited result
without letting external page content execute or become authority.

## Flow

```text
ResearchBriefV1
-> disclosure decision and public query
-> configured discovery hints or seed URLs
-> URL admission and fresh public DNS
-> one-shot network worker fetch
-> bounded network-denied extraction
-> hash-bound ResearchPageSnapshotV1
-> D2I-owned loopback HTML projection
-> read-only Edge/WebDriver observation
-> evidence ranking and same-body deduplication
-> conflict and unknown tracking
-> deterministic sufficiency gate
-> cited ResearchReportV1
```

The browser receives no external URL. External anchors become stable link IDs;
selection returns to the protected source store and repeats URL admission.
Search snippets cannot be cited until their target is fetched and snapshotted.

## Limits

The default profile allows at most 24 pages, 64 requests, 16 origins, 512 links
per page, 8 MiB per raw HTML body, 256 KiB extracted text per page, 64 evidence
excerpts, 64 KiB model evidence, five redirects, and link depth three. The
network worker accepts only one signed action and fixed GET/HEAD behavior.

External research defaults to `public` disclosure. Internal, confidential, or
restricted material requires an exact approved declassification rule; otherwise
query construction returns `research_query_disclosure_blocked`.

## Evidence Rules

- Transport success, TLS, search rank, and domain name do not establish truth.
- Every factual claim cites a bounded evidence excerpt from a fetched snapshot.
- Numeric claim tokens must occur in cited evidence.
- Duplicate body hashes contribute only once.
- Unresolved conflicts, known unknowns, stale sources, insufficient source
  diversity, or exhausted budget prevent completion.
- Model output is a proposal over typed evidence only. It has no raw URL,
  download, network, credential, or Workspace authority.

## Browser Boundary

Edge remains loopback-only under exact application-bound WFP policy. The
ephemeral snapshot server serves only registered session/page/link routes, uses
a restrictive CSP, and records link selection without navigating externally.
Completion requires zero browser external requests, downloads, and form submits.
The model report separately binds the provider `Denied` network policy, actual
zero-capability AppContainer cleanup, and zero newly residual `llama-cli`
processes. Completion security and residual counters are derived from validated
WFP/browser reports, exact process baselines, and owned temporary paths rather
than inserted as unobserved constants.

Completion events are appended to the existing protected desktop audit ledger.
The verified record count and terminal record hash are bound into
`ResearchWorkCompletionReportV1`, which is in turn bound by the signed
certification.

## Runner

Deterministic local gates:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-browser-research-v1.ps1 `
  -Mode All `
  -Fresh
```

Certified product gate:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-browser-research-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office500EvidenceRoot C:\path\to\sealed-office500 `
  -Edge C:\path\to\msedge.exe `
  -EdgeDriver C:\path\to\msedgedriver.exe `
  -ExternalCanaryUrl https://approved.example/public `
  -ExternalDownloadCanaryUrl https://approved.example/file.pdf `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

`All` is intentionally offline and non-admin. Completion is the only gate that
uses external Internet and temporary elevated WFP state.
The deployment machine must have an organizational Attachment Manager policy
under which the approved canary receives `CheckPolicy = Enable`; `Prompt`
creates a human exception and cannot be auto-clicked or treated as successful
promotion.

## Dependencies

The only new direct production parser dependency is `scraper 0.27.0` (ISC),
backed by locked memory-safe Rust packages including `html5ever 0.39.0`
(MIT OR Apache-2.0), `ego-tree 0.11.0` (ISC), `cssparser 0.37.0` (MPL-2.0),
`selectors 0.38.0` (MPL-2.0), and `tendril 0.5.1` (MIT OR Apache-2.0).
`url 2.5.8` (MIT OR Apache-2.0) is also direct for strict URL processing.
Distribution must retain the corresponding license notices. No Python, Node,
Playwright, cloud-search SDK, or public browser MCP is a production dependency.
