# Module Conformance Suite

Run:

```text
cargo run -p d2i-cli -- module validate <module-dir> --json
cargo run -p d2i-cli -- module conformance modules/rule-based-work-reporter --json
```

`module validate` checks manifest structure, versions, capability/schema
references, execution/security defaults, path traversal, file bounds, schema
compilation, artifact hash, schema hashes, licensing, and evaluation metadata.

`module conformance` executes JSON fixtures in deterministic lexical path order
for a built-in Rust reference module. It checks typed invocation/result
contracts, expected terminal status/error/payload/hash, repeated result hashes,
module self-check, network denial, and side-effect denial.

Stable report statuses are `pass`, `fail`, `unsupported`, and `skipped`.
Skipped is never pass. Stable conformance exit codes are:

- `0`: passed
- `10`: failed
- `11`: unsupported runner
- `12`: harness internal failure

The repository CLI maps module validation/conformance failure to process exit
code `7`, while preserving the conformance exit code inside the JSON report.

Tests additionally exercise panic containment, logical timeout, output schema
violation, secret leakage, malformed/duplicate/deep JSON, invalid confidence,
resource exhaustion, artifact mismatch, manifest identity drift, and
intentionally broken modules.

Arbitrary native modules are not dynamically loaded. The CLI returns
unsupported rather than guessing a production ABI.
