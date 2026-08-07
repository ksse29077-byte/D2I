# Enterprise API Execution Plane v1

## Purpose

EDGE-100 lets a bounded digital employee observe and mutate an approved
enterprise API through signed semantic operations. It is an execution-plane
host contract, not a generic HTTP client and not a vendor-certified connector.

The authority chain is:

```text
Role and Case scope
-> signed Connector Pack and organization approval
-> exact endpoint and opaque credential reference
-> model-selected semantic operation
-> Policy admission
-> one-shot activation
-> trusted connector worker
-> operation receipt
-> fresh API observation
-> verified closure or human exception
```

## Closed Boundary

The model sees an operation ID, capability, semantic target, approved argument
hashes, normalized fields, and postcondition. It never receives or selects raw
URLs, HTTP methods, headers, cookies, authorization values, API keys, request
bodies, SQL, redirects, or proxy settings.

`EnterpriseConnectorPackV1` fixes the operation set, read/mutation split,
request and response schema hashes, resource classes, semantic targets,
capabilities, transport, TLS, redirect, proxy, rate, retry, pagination,
request, response, and duration limits. `EnterpriseConnectorApprovalV1` binds
that pack to one organization, environment, Role set, operation set,
capability set, origin, port, credential profile, validity interval, nonce,
signer, and signature.

## Network And Credential Handling

Production contracts accept HTTPS only and require trust-chain, hostname,
expiry, and protocol checks. Ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
PAC, and automatic redirects are denied. The reference certification uses
only signed test-mode `http://127.0.0.1:<ephemeral-port>` and separate hidden
server and worker processes. Wrong ports, metadata endpoints, external
destinations, and redirect behavior are rejected before a request.

The Completion secret is generated at runtime. Cognitive, Workforce, Case,
Memory, Connector Pack, report, audit, and protected-store artifacts retain
only `EnterpriseCredentialReferenceV1`. Secret material crosses bounded stdin
to the trusted worker and is not written to disk. Runtime artifacts are scanned
for common credential markers before Completion can succeed.

## Mutation And Verification

The reference operation `update-work-order-status` materializes a fixed PATCH
inside the worker. It requires `If-Match` state and a deterministic idempotency
key. Stale state permits one fresh read and replan. Rate-limit recovery is
bounded. Commit-then-drop is resolved from fresh remote state without a blind
write replay. Authentication failure and malformed or untrusted responses
produce a human exception.

An operation receipt is evidence, not completion. Every successful or resolved
write is followed by a fresh read and `EnterprisePostActionVerificationV1`.
The Case closes only when the normalized remote state satisfies the expected
postcondition.

## Reference Duty Cycle

The actual Completion covers eight Cases:

| Case | Condition | Result |
| --- | --- | --- |
| A | Normal update | Verified closure |
| B | Already correct | Verified closure without write |
| C | First write stale | Fresh read, Qwen replan, verified closure |
| D | First write rate-limited | Bounded retry, verified closure |
| E | Server commits then drops response | Fresh-state resolution, no blind replay |
| F | Authentication rejected | Human exception |
| G | Untrusted action instruction in response | Rejected before model/write |
| H | Malformed JSON | Rejected before model/write |

The deterministic replay covers 128 synthetic Case/operation sequences for 100
runs. Cross-domain fixtures use general enterprise, ERP, MES, and CMMS labels
without changing Core behavior.

## Commands

Deterministic gates:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/edge/run-enterprise-api-plane-v1.ps1 `
  -Mode All `
  -OutputRoot target/d2i-edge-enterprise-api
```

Actual Completion:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/edge/run-enterprise-api-plane-v1.ps1 `
  -Mode Completion `
  -Runtime C:\path\to\llama-cli.exe `
  -Model C:\path\to\Qwen3-4B-Q4_K_M.gguf `
  -Work900EvidenceRoot C:\path\to\verified-work900 `
  -OutputRoot target/d2i-edge-enterprise-api/completion `
  -ReuseVerifiedPredecessorEvidence `
  -Fresh
```

After a transient failure, repeat with `-Resume` instead of `-Fresh`. Verified
checkpoints are reused only when their input, dependency, artifact, model,
runtime, source, and cleanup hashes still match.

## Limits

The certified implementation is JSON API v1, loopback reference-server only,
single-Case mutation concurrency, and one-shot execution. It has no direct
database path, vendor certification, external communication, enterprise proxy,
background daemon, or sensor/camera/IoT support. Production non-loopback use
requires an approved connector pack, credential broker integration, production
TLS transport, and an exact destination policy for the connector executable.
