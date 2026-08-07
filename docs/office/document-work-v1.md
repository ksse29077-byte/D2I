# HWPX and Word Document Work v1

OFFICE-200 turns an approved General Office document request into a verified
HWPX or DOCX generation without asking the user to drive application menus.
The authority path is:

```text
bounded goal and approved excerpts
-> semantic document intent
-> Policy admission
-> one-shot activation
-> KRN document dispatcher
-> exact file or Word worker
-> new generation
-> fresh reopen
-> semantic diff and postcondition verification
-> protected Office registry version
```

## Contracts

`d2i-document-capability` owns 19 strict Draft 2020-12 contracts for semantic
snapshots, capability packs, backend descriptors and approvals, bounded text,
styles, tables, images, layout, operation intent and binding, receipts, diffs,
post-operation verification, structural quality, cross-format equivalence,
replay, Completion, and certification. Unknown fields, duplicate JSON keys,
unbounded strings/collections, malformed hashes, and raw path/XML/COM/script
fields fail closed.

Supported v1 semantics are inspect, create from template, append paragraph,
insert heading, bounded replace, approved paragraph style, insert/set table,
insert embedded PNG/JPEG, bounded A4 layout, save version, and removal of a
generated node where the backend supports it. The model receives semantic IDs
and approved bounded excerpts, never raw package XML or a COM object dump.

## Execution and Verification

The HWPX and DOCX workers accept one strict request over bounded stdin. The
dispatcher verifies Role, Case, lease, Work Grant, workspace profile/root,
artifact generation/hash, fresh semantic snapshot, capability pack, backend
descriptor, signed backend approval, Policy decision, activation, and worker
hash. The activation ledger is consumed only after all preflight checks.

Every output is a new generation in the approved workspace. The child reopens
the saved package and returns a snapshot; the parent independently reopens it
again and compares exact content identity and semantic state before creating a
verified receipt. Originals are rehashed and must remain unchanged.

The representative Completion creates one report through eight HWPX file
mutations, five DOCX file mutations, and three actual Word COM mutations. It
uses 16 globally unique one-shot activations, 12 actual pinned Qwen calls,
fresh reopens after every mutation, cross-format structural equivalence, 128
synthetic scenarios across 100 deterministic replay passes, protected audit,
and signed terminal certification.

## Security

- ZIP entries are bounded and cannot traverse, alias, duplicate, symlink, or
  exceed package, expansion, entry, XML, text, table, or image limits.
- DTD, entity, processing instruction, external relationship, remote image,
  macro, OLE executable, ActiveX, and external template content is rejected.
- Document text is untrusted data. It cannot introduce a command or authority.
- No production Python, Node, public MCP, arbitrary process, command, network,
  clipboard, browser, or credential path is present.
- Word is hidden, current-user interactive only, executable-hash bound, and
  WFP loopback-only for the live sequence. Existing Word processes are never
  terminated by name.
- Ambiguous mutation, stale generation, wrong target, reused activation, or
  changed source forces rejection or fresh observation before recovery.

## Commands

Deterministic gates do not require elevation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-document-work-v1.ps1 `
  -Mode All `
  -OutputRoot target/office200-all `
  -Fresh
```

Completion requires one elevated interactive deployment session because it
installs and removes the exact WINWORD WFP policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/office/run-document-work-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Office100EvidenceRoot C:\path\to\office100-completion `
  -OutputRoot target/office200-completion `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

Use `-Resume` only with the same source tree, arguments, runtime/model hashes,
and predecessor. Changed inputs invalidate dependent checkpoints. Supplying a
Hancom license artifact does not silently enable Automation; a licensed
backend must also exist and be separately approved.

## Limits

Legacy HWP mutation is not claimed without licensed Hancom Automation. Word
requires an installed licensed desktop client and an interactive user session;
there is no Windows service automation. Password-protected or digitally signed
documents, macro content, full visual quality, browser download, email,
messenger, Excel, PowerPoint, and full PDF workflows are outside OFFICE-200.
