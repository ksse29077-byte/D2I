# Cognitive Module Template

Create a rendered standalone copy from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/new-module.ps1 `
  -ModuleId my-module
```

The `Module` trait receives typed input and a bounded invocation context. It
does not receive adapters, policy or activation implementations, audit
storage, filesystem handles, environment variables, or network clients.

After replacing the starter behavior and documentation, run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/modules/check-module.ps1 `
  -ModulePath modules/my-module
```

The production CLI intentionally does not dynamically load arbitrary module
artifacts. Generation creates only `modules/<module-id>` and its local
`Cargo.lock`; it does not edit the Core workspace or root lockfile.
