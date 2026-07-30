# Module Conformance Suite

Run one standalone module from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/<module-id> `
  -OutputPath build/module-checks/<module-id>.json
```

Run every discovered module after a Core contract change:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-all-modules.ps1 `
  -OutputRoot build/module-checks
```

The checker requires a standalone workspace and local lockfile, verifies the
direct D2I dependency boundary, and runs locked metadata, formatting, Clippy,
all tests, the module-local conformance target, deterministic replay fixtures,
and a release build. Manifest structure, path confinement, schema compilation,
artifact/schema hashes, license metadata, network denial, and side-effect
denial are exercised by the SDK conformance target.

Stable report statuses are `pass`, `fail`, `unsupported`, and `skipped`.
Skipped is never pass. Stable conformance exit codes are:

- `0`: passed
- `10`: failed
- `11`: unsupported runner
- `12`: harness internal failure

The Core CLI does not link any standalone implementation. `d2ic module
conformance` returns structured `unsupported` with the official module-local
command instead of guessing a production loader.

Tests additionally exercise panic containment, logical timeout, output schema
violation, secret leakage, malformed/duplicate/deep JSON, invalid confidence,
resource exhaustion, artifact mismatch, manifest identity drift, and
intentionally broken modules.

Arbitrary native modules are not dynamically loaded.
