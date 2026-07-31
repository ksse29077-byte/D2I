# First Kernel E2E Runbook

## Run

From a Windows checkout:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/e2e/run-first-kernel-e2e.ps1 `
  -Mode All
```

Modes are `Happy`, `Recovery`, `Unsafe`, `Clarification`, and `All`.
`All` is the release gate. It builds the root desktop binaries and each
standalone module host in independent target directories, then runs happy
twice and every negative/recovery scenario.

## Exit Codes

- `0`: requested completed outcome, or all expected outcomes passed
- `10`: individual clarification outcome
- `11`: individual escalation outcome
- `12`: stopped or failed task outcome
- `13`: infrastructure or contract failure
- `14`: cleanup failure

## Artifacts

The default output is `target/d2i-e2e/<normalized-run-id>/`.
`finished.json` summarizes all scenarios using relative paths. Each scenario
contains `result.json` plus bounded runner logs. Core JSON artifacts contain no
absolute paths. Build logs and isolated Cargo target directories remain under
the run output for diagnosis.

Valid `All` output requires five expected outcomes, identical normalized hashes
for both happy runs, actual module invocations, exact mutation counts, and zero
module-host, worker, app, activation, payload, and temporary-state residuals.

## Failure Handling

Do not reinterpret exit `10` or `11` as infrastructure failure when that mode
was requested. For exit `13`, inspect the scenario `runner.stderr.log` and
build logs. Do not bypass module hashes, policy, activation, verification,
recovery, or cleanup checks. Rerun with a new output root after correcting the
cause; an existing output root is intentionally rejected.
