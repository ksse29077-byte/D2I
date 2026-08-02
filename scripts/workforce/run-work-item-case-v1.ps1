[CmdletBinding()]
param(
    [ValidateSet('Contract', 'Lifecycle', 'KernelE2E', 'Duplicate', 'Negative', 'SafetyFixtures', 'All')]
    [string]$Mode = 'All',

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$startedAt = [DateTimeOffset]::UtcNow
$results = [System.Collections.Generic.List[object]]::new()
$terminalExitCode = 1

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    $stdout = Join-Path $script:OutputRoot "$Label.stdout.log"
    $stderr = Join-Path $script:OutputRoot "$Label.stderr.log"
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $commandError = $null
    try {
        & $Command 1> $stdout 2> $stderr
        $exitCode = $LASTEXITCODE
    }
    catch {
        $commandError = $_
        $exitCode = 1
    }
    finally {
        $ErrorActionPreference = $saved
    }
    $status = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
    $script:results.Add([pscustomobject][ordered]@{
            label = $Label
            status = $status
            exit_code = $exitCode
            stdout = [IO.Path]::GetFileName($stdout)
            stderr = [IO.Path]::GetFileName($stderr)
        })
    if ($exitCode -ne 0) {
        $detail = if ($commandError) { ": $commandError" } else { '' }
        throw "$Label failed with exit code $exitCode$detail; see $stderr"
    }
}

function Invoke-Contract {
    Invoke-Checked 'contract-schema-normalization-replay' {
        cargo test --locked -p d2i-work-case --all-features -- --nocapture
    }
}

function Invoke-Lifecycle {
    Invoke-Checked 'case-lifecycle-ledger-reopen-corruption' {
        cargo test --locked -p d2i-desktop --test work_item_case -- --nocapture
    }
}

function Invoke-Duplicate {
    Invoke-Checked 'duplicate-work-item-no-case-no-mutation' {
        cargo test --locked -p d2i-desktop --test work_item_case `
            duplicate_work_item_is_rejected_without_ledger_mutation -- --exact --nocapture
    }
}

function Invoke-Negative {
    Invoke-Checked 'failed-task-non-terminal' {
        cargo test --locked -p d2i-work-case --test contract `
            failed_task_remains_non_terminal_and_requirements_unresolved -- --exact --nocapture
    }
    Invoke-Checked 'replay-tamper-stale-terminal-reject' {
        cargo test --locked -p d2i-work-case --test contract `
            aggregate_cycle_and_unknown_fields_fail_closed -- --exact --nocapture
    }
    Invoke-Checked 'suspended-role-task-block' {
        cargo test --locked -p d2i-desktop --test work_item_case `
            suspended_role_blocks_fresh_task_and_preserves_case -- --exact --nocapture
    }
}

function Invoke-SafetyFixtures {
    Invoke-Checked 'ai-safety-execution-free-fixtures' {
        cargo test --locked -p d2i-work-case --test contract `
            ai_safety_reference_cases_are_execution_free_and_role_compatible -- --exact --nocapture
    }
}

function Invoke-RoleRegression {
    $roleRoot = Join-Path $script:OutputRoot 'work-100'
    Invoke-Checked 'work-100-role-contract-all' {
        powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $repoRoot 'scripts/workforce/run-role-contract-v1.ps1') `
            -Mode All `
            -OutputRoot $roleRoot
    }
}

function Invoke-KernelCaseE2E {
    $kernelRoot = Join-Path $script:OutputRoot 'kernel-case-e2e'
    Invoke-Checked 'role-bound-krn-500-case-happy' {
        powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1') `
            -Mode Happy `
            -RoleSource (Join-Path $repoRoot 'examples/workforce/kernel-e2e-operator/role.yaml') `
            -OutputRoot $kernelRoot
    }
    $happyRoot = Join-Path $kernelRoot 'happy'
    foreach ($name in @(
            'result.json',
            'kernel-task-run-record.json',
            'final-goal-verification.json',
            'work-report.json',
            'role-bound-kernel-context.json',
            'role-instance.json',
            'role-terminal-instance.json',
            'role-contract.json',
            'role-delegation.json'
        )) {
        if (-not (Test-Path -LiteralPath (Join-Path $happyRoot $name) -PathType Leaf)) {
            throw "KRN-500 Case evidence artifact is absent: $name"
        }
    }
    $scenario = Get-Content -Raw -LiteralPath (Join-Path $happyRoot 'result.json') | ConvertFrom-Json
    if ($scenario.actual_outcome -ne 'completed' -or
        $scenario.actual_module_invocations -lt 3 -or
        $scenario.mutation_count -ne 2 -or
        $scenario.cleanup.module_host_residuals -ne 0 -or
        $scenario.cleanup.worker_residuals -ne 0 -or
        $scenario.cleanup.app_process_residuals -ne 0 -or
        $scenario.cleanup.activation_residuals -ne 0 -or
        $scenario.cleanup.payload_residuals -ne 0 -or
        -not $scenario.cleanup.temporary_root_removed) {
        throw 'KRN-500 Case evidence or cleanup contract differs'
    }
    Invoke-Checked 'actual-kernel-artifact-case-closure-reopen' {
        $savedOutput = $env:D2I_WORK_CASE_KERNEL_OUTPUT
        try {
            $env:D2I_WORK_CASE_KERNEL_OUTPUT = $happyRoot
            cargo test --locked -p d2i-desktop --test work_item_case `
                actual_role_bound_kernel_artifacts_close_verified_case_when_supplied `
                -- --exact --nocapture
        }
        finally {
            $env:D2I_WORK_CASE_KERNEL_OUTPUT = $savedOutput
        }
    }
}

function Invoke-SensitiveScan {
    Invoke-Checked 'sensitive-artifact-scan' {
        $files = Get-ChildItem -LiteralPath $script:OutputRoot -Recurse -File -Filter '*.json'
        $matches = $files | Select-String -Pattern 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization:\s*Bearer|password\s*[:=]' -CaseSensitive:$false
        if ($matches) {
            throw "sensitive marker detected: $($matches[0].Line)"
        }
    }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'Work Item / Case v1 product runner requires Windows'
    }
    foreach ($path in @(
            (Join-Path $repoRoot 'Cargo.toml'),
            (Join-Path $repoRoot 'schemas/workforce/work-item-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/case-contract-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/case-instance-v1.schema.json'),
            (Join-Path $repoRoot 'examples/workforce/ai-safety-operations-employee/cases/training-compliance-follow-up/case-fixture.json'),
            (Join-Path $repoRoot 'examples/workforce/ai-safety-operations-employee/cases/corrective-action-tracking/case-fixture.json'),
            (Join-Path $repoRoot 'scripts/workforce/run-role-contract-v1.ps1'),
            (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1')
        )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required WORK-200 input is absent: $path"
        }
    }
    if (-not $OutputRoot) {
        $head = (& git -C $repoRoot rev-parse --short=12 HEAD).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw 'repository HEAD could not be resolved'
        }
        $runId = '{0}-{1}-{2}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $head, $PID
        $OutputRoot = Join-Path $repoRoot "target/d2i-workforce-case/$runId"
    }
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    $targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
    if (-not $OutputRoot.StartsWith("$targetRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputRoot must remain under repository target/'
    }
    if (Test-Path -LiteralPath $OutputRoot) {
        throw "OutputRoot already exists: $OutputRoot"
    }
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    Set-Location $repoRoot

    switch ($Mode) {
        'Contract' { Invoke-Contract }
        'Lifecycle' { Invoke-Lifecycle }
        'KernelE2E' { Invoke-KernelCaseE2E; Invoke-SensitiveScan }
        'Duplicate' { Invoke-Duplicate }
        'Negative' { Invoke-Negative }
        'SafetyFixtures' { Invoke-SafetyFixtures }
        'All' {
            Invoke-Contract
            Invoke-Lifecycle
            Invoke-Duplicate
            Invoke-Negative
            Invoke-SafetyFixtures
            Invoke-RoleRegression
            Invoke-KernelCaseE2E
            Invoke-SensitiveScan
        }
    }

    $report = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        git_head = (& git -C $repoRoot rev-parse HEAD).Trim()
        started_at = $startedAt.ToString('o')
        completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        results = @($results)
        work_radar_implemented = $false
        queue_scheduler_implemented = $false
        residual_owned_processes = 0
        complete = $true
        status = 'pass'
        report_sha256 = ''
    }
    $unhashed = $report | ConvertTo-Json -Depth 10 -Compress
    $report.report_sha256 = 'sha256:' + (
        Get-FileHash -Algorithm SHA256 `
            -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($unhashed)))
    ).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        (Join-Path $OutputRoot 'finished.json'),
        ($report | ConvertTo-Json -Depth 10) + [Environment]::NewLine
    )
    Write-Output "D2I Work Item / Case v1 complete: $OutputRoot"
    $terminalExitCode = 0
}
catch {
    Write-Error $_
}
finally {
    Set-Location $repoRoot
}

exit $terminalExitCode
