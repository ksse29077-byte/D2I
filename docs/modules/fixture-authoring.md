# Fixture Authoring

A fixture JSON contains:

- `schema_version`, stable `fixture_id`, and `fixture_kind`
- a complete `ModuleInvocationEnvelope`
- trusted caller `InvocationContext`
- expected status, optional error code/hash/payload
- bounded `replay_count`

Supported fixture kinds cover valid, invalid, unsupported, untrusted content,
expired deadline, payload size, output schema violation, panic, timeout,
deterministic replay, artifact mismatch, manifest tampering, capability
mismatch, invalid confidence, and secret leakage.

Invocation and context observation hash, plan generation, and trust labels must
match unless the fixture intentionally tests staleness. Resource budgets may
not exceed manifest limits. Use synthetic hashes and data; never put real
credentials in a fixture.

Fixtures are read as strict JSON. Duplicate keys, invalid UTF-8, excessive
nesting, oversized files, symlinks, unknown fields, and malformed enums fail.

Panic, timeout, malformed output, and resource behavior require a purpose-built
test module because data fixtures cannot grant a module hidden behavior.
Artifact and manifest tampering fixtures operate on copied module directories
because the loader must fail before invocation.

For deterministic fixtures, set `replay_count` above one and compare the full
canonical result-envelope hash, not wall-clock duration.
