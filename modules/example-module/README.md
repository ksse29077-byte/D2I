# Cognitive Module Starter

Copy this directory, rename the package/module/capability IDs, replace
`ExampleInput`, `ExampleOutput`, and `ExampleModule`, then update the schemas,
artifact descriptor hashes, manifest, fixtures, and documentation.

The `Module` trait receives typed input and a bounded invocation context. It
does not receive adapters, policy or activation implementations, audit
storage, filesystem handles, environment variables, or network clients.

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/example-module
```

The production CLI intentionally does not dynamically load arbitrary module
artifacts. The module-local checker validates the manifest and deterministic
fixture suite without registering this package in the Core workspace.
