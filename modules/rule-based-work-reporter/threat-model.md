# Threat Model

The module receives bounded typed payloads after envelope and schema
validation. Relevant threats are malformed or oversized JSON, stale replay
bindings, untrusted text that resembles an instruction, secret-bearing fields,
panic, timeout, resource exhaustion, schema substitution, and artifact or
manifest tampering.

The SDK rejects invalid envelopes, stale lifecycle bindings, undeclared schema
or capability IDs, raw secret field names, invalid output, and hash mismatch.
The reporter does not copy untrusted event summaries into confirmed facts or
completed actions. The module has no network, filesystem, process, UI,
WebDriver, policy, activation, audit-storage, or adapter handle.
