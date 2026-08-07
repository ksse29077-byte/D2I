# ADR 0037: Signed Enterprise Connector Packs, Credential-Isolated API Execution, Idempotent Mutation, and Fresh Remote Verification

## Status

Accepted

## Context

Track W closes bounded office work through the Windows UI execution plane.
Organizations also expose approved work through ERP, MES, CMMS, and internal
APIs. Treating those systems as a generic HTTP tool would let model output
choose URLs, methods, headers, credentials, or arbitrary request bodies. It
would also make a successful HTTP status look like verified business closure.

System-family names are customer and Domain Pack metadata. Core cannot branch
on ERP, MES, CMMS, finance, office, IT, or safety taxonomy. Execution authority
must continue to come from Policy admission, one-shot activation, and the Safe
Execution Kernel rather than from connector approval or credential presence.

## Decision

`d2i-enterprise-api-plane` owns platform-neutral, strict, versioned contracts
for an execution plane descriptor, signed connector pack and approval, exact
endpoint binding, opaque credential reference, observations, operation intent
and binding, receipts, post-action verification, network policy, idempotency,
health, replay, Completion, and certification.

A connector pack contains closed semantic operations. Each operation fixes its
capability, semantic target, HTTP method, relative path template, request and
response schemas, side-effect class, idempotency rule, concurrency rule,
limits, and verification operation. Cognitive and Workforce layers may select
an operation ID and approved argument references. They cannot submit an
arbitrary URL, method, header, body, query, or credential.

Desktop owns a dedicated connector worker. The trusted parent validates the
signed pack, approval, endpoint, worker executable hash, Policy admission, and
one-shot activation before spawning it. A runtime-only secret is sent through
bounded stdin and exists only in fixture and worker process memory. Proxy
environment variables are removed. Reports, stores, Case records, model
context, logs, and audit contain only opaque references and hashes.

Production connector packs require HTTPS, OS trust-chain, hostname and expiry
verification, weak-protocol rejection, deny-redirect, and deny-ambient-proxy.
The v1 certification profile uses a signed non-production fixture bound only
to `127.0.0.1` and one ephemeral port. The worker has a closed operation enum
and refuses other hosts, ports, methods, paths, redirects, and external
destinations. A production non-loopback deployment additionally requires a
privileged exact-destination policy bound to the approved worker executable.

Mutation operations require a deterministic idempotency key and an expected
resource version. A stale response causes one fresh observation and replan. A
rate limit allows only a bounded retry. An unknown write outcome is never
blindly replayed; it is resolved by an idempotency result or fresh state. A 2xx
receipt is not completion. Closure requires a separate fresh observation and
postcondition verification.

The reference Completion uses a separate server process, separate connector
worker processes, actual IPv4 loopback sockets, the pinned Qwen3-4B model and
llama.cpp runtime, existing Policy admission, one-shot enterprise activation,
protected content-addressed evidence, and the reusable Workforce checkpoint
contract. It processes eight bounded General Office Cases and keeps domain
family compatibility examples only in fixtures.

## Consequences

- Models cannot become arbitrary HTTP clients or receive raw credentials.
- Connector pack and approval artifacts narrow configuration but are not
  execution tokens.
- Existing KRN authority and fresh-verification rules apply to API writes.
- ERP, MES, CMMS, and general enterprise labels remain opaque pack metadata.
- Direct SQL, ODBC, JDBC, arbitrary OData/GraphQL, SOAP, and database mutation
  are outside v1.
- The reference certification proves the host contract with hermetic loopback
  I/O; it does not claim SAP, Oracle, Maximo, or customer production approval.

## Alternatives

A generic `http_request(url, method, headers, body)` adapter was rejected
because it permits SSRF, credential exposure, and authority expansion. Direct
database access was rejected because it bypasses application semantics and
remote verification. Putting credentials in Connector Packs was rejected
because signed metadata is not a secret store. Accepting a 2xx response as
closure was rejected because transport success is not verified organizational
state. Reusing the browser WFP profile unchanged was rejected because it is
bound to the browser executable and loopback-only browser contract, not to an
enterprise connector destination.

## Rollback And Migration

Remove or revoke the connector approval and endpoint binding, stop issuing
enterprise activation records, and stop invoking the bounded runner. Existing
Role, Work Intake, Case, Queue, Policy, KRN, audit, and Track W evidence remain
authoritative. A vendor connector, production TLS implementation, enterprise
proxy, non-loopback WFP policy, direct database plane, or background service
requires a separately approved version and deployment evidence.
