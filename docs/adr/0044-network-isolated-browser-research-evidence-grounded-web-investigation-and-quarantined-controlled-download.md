# ADR 0044: Network-Isolated Browser Research and Quarantined Controlled Download

- Status: Accepted
- Date: 2026-08-11
- Owners: Core, Office capability, Desktop trust boundary
- Scope: D2I-OFFICE-600

## Context

D2I needs public-web research without giving a browser, model, parser, or main
Desktop process ambient Internet authority. Web content may contain prompt
injection, active HTML, private-network targets, redirects, misleading search
snippets, hostile files, and filenames intended to escape a quarantine.
Successful retrieval also does not establish that a claim is sufficiently
supported or that a downloaded file is safe to promote into a Workspace.

## Decision

Keep Edge and EdgeDriver under the existing application-bound WFP loopback-only
policy. Add a separate one-shot `d2i-office600-network-worker` as the only D2I
component with external HTTPS fetch authority. Its input is a strict signed
request over private stdin. It accepts only GET or HEAD, fixed headers, direct
Schannel TLS, no cookies, authentication, proxy discovery, browser, model,
Office COM, child process, credential, shell, or arbitrary filesystem access.

Every URL passes disclosure policy, strict parsing, scheme/port/userinfo/host
checks, fresh DNS resolution, prohibited-address rejection, and source policy.
WinHTTP automatic redirects are disabled. Every redirect is parsed, admitted,
and resolved again, and the observed connection address must match the fresh
public address set. HTTPS downgrade, redirect loops, internal pivots, mixed DNS,
and DNS rebinding fail closed.

External HTML is never executed. A network-denied Rust parser extracts bounded
title, heading, paragraph, list, table, and link text into a
`ResearchPageSnapshotV1`. Raw URLs stay in a protected source table; the safe
HTML projection contains stable link IDs and is served only from an ephemeral
loopback snapshot server. Edge performs read-only WebDriver observation of this
D2I-owned projection. Browser downloads and form submission remain disabled.

Search results are discovery hints, not evidence. Claims require fetched,
hash-bound snapshots and cited evidence excerpts. Same-body snapshots are
deduplicated. Sufficiency is a deterministic gate over source count, freshness,
question coverage, conflicts, unknowns, and budget state. Prompt-injection text
is untrusted data and cannot change Role, Policy, network, download, promotion,
or Case authority. Model context contains only bounded evidence text and stable
IDs, with explicit zero counters for raw HTML, raw URLs, downloads, credentials,
network authority, and Workspace promotion authority.

Downloads never use the browser. The network worker writes a bounded file to a
D2I quarantine by create-new partial file and atomic rename. Promotion requires
an exact source snapshot/link binding, Windows `IAttachmentExecute` CheckPolicy
and Save result of Enable, a post-Save file rehash, format-specific parser
success, extension/MIME/magic agreement, macro and external-relationship denial,
and an atomic no-overwrite Workspace import. Promoted artifacts retain an
`external-untrusted-artifact` label; validation does not turn content into fact.

## Contracts and Verification

`d2i-browser-research` owns 42 strict Draft 2020-12 contracts and their schema
generator. The Desktop runner separates deterministic `All` from elevated
`Completion`. Completion requires sealed OFFICE-500 evidence, pinned and signed
Edge/EdgeDriver, exact WFP evidence, actual approved public HTTPS requests over
at least two origins, one external controlled download, actual Attachment
Services, five WebDriver snapshot observations, at least two pinned Qwen calls,
one model-free Case, 24 total Cases, crash windows A-N, 128 by 100 logical replay,
signed certification, and zero security and residual counters.

## Alternatives

### Give Edge direct Internet access

Rejected. Browser renderer compromise, JavaScript, extension behavior, forms,
authentication state, and auto-download would share the external authority.

### Give the model an HTTP tool or raw URL

Rejected. A model proposal is not URL, disclosure, source-trust, download, or
promotion authority and raw query strings may contain identifiers.

### Execute sanitized third-party HTML

Rejected. Sanitizer drift is not the browser security boundary. D2I generates a
new closed HTML projection instead.

### Treat search snippets, TLS, or parser success as truth

Rejected. They establish discovery, transport, or format properties only.
Factual completion still requires cited evidence and deterministic sufficiency.

## Consequences

V1 supports bounded public GET/HEAD research and controlled PDF, DOCX, HWPX,
XLSX, PPTX, TXT, CSV, PNG, and JPEG intake without widening browser or model
authority. It deliberately excludes authenticated research, user-cookie reuse,
live JavaScript sites, POST/forms, CAPTCHA bypass, generic crawling, executable
or archive promotion, macro-enabled Office files, automatic OCR, and online
B_Core integration.
