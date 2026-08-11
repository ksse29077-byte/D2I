# Research Network Plane v1

The Research Network Plane is the sole non-loopback network authority introduced
by OFFICE-600. It is not a general HTTP client, browser broker, or model tool.

## Process Boundary

`d2i-office600-network-worker` is one-shot and receives one strict JSON request
through private stdin. The request binds organization, Case, source policy,
network profile, URL admission decision, operation, method, byte limit, worker
executable hash, nonce, signer, and short validity window. Unknown fields and
stale, mismatched, or replayed authority fail closed.

The worker has no browser, model, Office COM, credentials, arbitrary headers,
proxy discovery, cookie jar, authentication, shell, child process, or arbitrary
filesystem contract. Its current directory must be an empty D2I-owned output
directory. A successful body is committed by `download.partial` plus atomic
rename.

## Admission

External access is HTTPS port 443 only. File, FTP, data, blob, JavaScript,
WebSocket, browser-internal schemes, userinfo, IP literals, malformed encoding,
invalid DNS labels, local names, internal suffixes, and non-default ports are
rejected. Every DNS result must be public. Loopback, RFC1918, link-local, CGNAT,
multicast, unspecified, benchmark/documentation ranges, IPv6 ULA/link-local,
IPv4-mapped prohibited ranges, and metadata addresses are denied.

WinHTTP uses Schannel default certificate and hostname verification, direct
access with no WPAD, fixed headers, no cookies/authentication, and no automatic
redirect. Response headers, declared length, decoded streamed body, timeouts,
requests, origins, and redirects are bounded. Only identity, gzip, and deflate
content encoding are accepted. The connected remote address from
`WINHTTP_OPTION_CONNECTION_INFO` must match the freshly admitted address set.

Every 3xx Location consumes redirect budget and repeats parsing, source policy,
DNS, and admission. HTTPS-to-HTTP, public-to-private, loops, missing Location,
or more than five redirects fail closed.

## Evidence and Privacy

Raw query strings and URLs remain in a protected source store. Public reports
use stable source IDs, protected references, origin IDs, and hashes. Receipts
record status, content type and length, bounded byte count, body hash, remote
address hash, certificate hash, redirect decision hashes, elapsed time, and a
closed result code. A receipt does not itself make source content authoritative.

## Deployment Proof

Completion installs temporary exact-image WFP policy and proves:

```text
network worker -> approved external HTTPS succeeds
Edge/EdgeDriver -> arbitrary external HTTPS fails
model worker -> arbitrary external HTTPS fails
other D2I workers -> arbitrary external HTTPS fails
```

Every terminal path removes the temporary WFP objects, AppContainer profiles,
processes, sockets, partial files, browser profile, and quarantine residue.
