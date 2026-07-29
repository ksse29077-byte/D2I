# Windows Reproduction Runner

`scripts/ci/run-windows-reproduction.ps1` is the Core-owned runner for repeated
Windows Rust test reproduction. Do not replace it with a module-local or
out-of-repository script.

The runner executes repetitions sequentially. `-Mode Serial` forces the Rust
test harness to use one test thread; `-Mode Parallel` leaves the test harness at
its default thread count.

## Single Cohort

Run from any current directory:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\path\to\D2I\scripts\ci\run-windows-reproduction.ps1 `
  -Worktree C:\path\to\D2I `
  -Label module-11 `
  -OutputRoot C:\path\to\diagnostics\module-11 `
  -Runs 100 `
  -TestFilter loader::tests::case_name `
  -Mode Serial `
  -Exact `
  -TimeoutSeconds 900
```

`-CargoTargetDir` is optional. When omitted, the runner creates a label-specific
target directory under `OutputRoot\targets`.

## Paired Comparison

Use one invocation when comparing a Base worktree with a Candidate worktree:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File C:\path\to\D2I\scripts\ci\run-windows-reproduction.ps1 `
  -Worktree C:\path\to\D2I-base `
  -Label base `
  -CandidateWorktree C:\path\to\D2I-candidate `
  -CandidateLabel module-11 `
  -OutputRoot C:\path\to\diagnostics\comparison `
  -Runs 100 `
  -TestFilter loader::tests::case_name `
  -Mode Serial `
  -Exact
```

Base and Candidate always receive disjoint `CARGO_TARGET_DIR` values. If an
explicit Base `-CargoTargetDir` is supplied, the Candidate target defaults to a
separate suffixed directory. `-CandidateCargoTargetDir` may override it, but
the runner rejects overlapping target directories.

## Preflight

Before Cargo starts, the runner verifies and records:

- the absolute worktree and `Cargo.toml`;
- the exact Git repository root, HEAD, and short status;
- `git`, `cargo`, and `rustc` paths and versions;
- the Windows user name, SID, and administrator state;
- a writable output root disjoint from every worktree;
- disjoint worktree and Cargo target paths;
- a normalized comparison contract covering command, privilege, test filter,
  execution mode, exact matching, and timeout.

Failure before a test binary starts is a `harness_failure`. The runner writes a
terminal `finished.json` whenever the output root has passed its safety and
write checks.

## Cargo Isolation

Every Cargo child is created with:

- `WorkingDirectory` equal to the absolute worktree;
- an absolute `--manifest-path <worktree>\Cargo.toml`;
- the cohort-specific `CARGO_TARGET_DIR`;
- a one-time `D2I_REPRODUCTION_OWNER` marker;
- redirected `stdout.log` and `stderr.log`;
- a bounded timeout.

The runner snapshots PIDs before each case and tracks only descendants of its
new Cargo PID. Records include PID, parent PID, creation time, command line, and
classification: `cargo`, `rustc`, `test_harness`, `test_worker`, or
`tool_child`. Cleanup checks PID plus creation time and never terminates by
process name. Existing user processes are outside the owned tree.

## Result Contract

Each `<label>\run-NNNN\result.json` includes:

- `label`, `worktree`, `git_head`, and `git_status`;
- `command`, `command_arguments`, `working_directory`, and `manifest_path`;
- `cargo_target_dir`, `run_id`, `test_name`, and `serial_or_parallel`;
- `cargo_exit_code`, `test_binary_started`, `status`, and `error_summary`;
- user and administrator evidence;
- ownership marker, runner PID, timestamps, and timeout;
- stdout, stderr, and result paths;
- classified `new_processes` and `residual_owned_processes`.

`status` has exactly four meanings:

- `pass`: a test binary ran and Cargo exited zero;
- `test_failure`: a test binary ran and returned an assertion or test error;
- `harness_failure`: setup, launch, logging, pre-test Cargo, or cleanup failed;
- `timeout`: the bounded deadline elapsed and owned cleanup succeeded.

Harness failures and timeouts are not test failures and are not valid test
runs.

The root `finished.json` includes `requested_runs`, `valid_test_runs`,
`passed_runs`, `test_failures`, `harness_failures`, `timeouts`,
`residual_owned_processes`, `complete`, and `valid_for_comparison`. It also
records cohort summaries and the normalized comparison contract hash.

`valid_for_comparison` is false if any requested run is missing, any run is a
harness failure or timeout, any test binary was not observed, owned processes
remain, or paired command, privilege, mode, and filter contracts differ.

## Exit Codes

- `0`: every requested run is valid and all tests passed;
- `1`: every requested run is valid, with one or more real test failures;
- `2`: harness failure, timeout, incomplete evidence, cleanup failure, or an
  invalid comparison.

Run the hermetic positive and negative suite with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts\ci\test-windows-reproduction.ps1
```
