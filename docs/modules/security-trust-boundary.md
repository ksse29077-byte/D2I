# Module Security and Trust Boundary

Module inputs, manifests, schemas, artifacts, fixtures, documents, web pages,
emails, and UI text are untrusted until their applicable contracts are
validated.

The loader validates bounded regular paths below the module root, artifact and
schema hashes, strict versions, execution/security defaults, and license
metadata. The SDK validates exact module/capability/schema identity, stale
observation and plan bindings, deadline, trust labels, redactions, resource
budgets, typed conversion, output schema, confidence, and result hash.

Raw fields named password, secret, credential, raw token, authentication token,
or authorization are prohibited at the envelope boundary. The only
`credential` exception is status metadata directly inside `gate_results` with
the exact string value `passed`, `failed`, or `unknown`. Any other location,
type, value, spelling, or case remains prohibited. This status reports a gate
decision and must never contain credential material. Use redaction markers and
secret handles managed outside the module contract. Never return credential
material in evidence, warnings, errors, provenance, or output payload.

Untrusted content may be classified, summarized, reduced, or quoted as data.
It may not alter policy, request a capability, become an action instruction, or
grant side-effect authority. The reference reporter omits untrusted event text
from completed actions.

Panic, timeout, invalid output, replay mismatch, resource exhaustion, hidden
network need, artifact drift, dependency failure, and unsupported behavior all
fail closed.

No concrete WFP, UIA, WebDriver, activation ledger, protected audit, Windows
binding, file, process, or network implementation is part of this platform.
