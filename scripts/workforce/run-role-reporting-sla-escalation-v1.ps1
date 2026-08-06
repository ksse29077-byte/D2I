[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Time', 'Sla', 'Pause', 'Breach',
        'Metrics', 'Kpi', 'Reports', 'Routing', 'Escalation',
        'Acknowledgement', 'Resolution', 'Persistence', 'CrashRecovery',
        'GeneralOfficeE2E', 'CrossDomain', 'Negative', 'Replay',
        'Regression', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,

    [string]$Model,

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot 'target/d2i-workforce-operations'
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot $OutputRoot
}
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
if (-not $OutputRoot.StartsWith($targetRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a child of the repository target directory.'
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
$logRoot = Join-Path $OutputRoot 'logs'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$steps = [System.Collections.Generic.List[object]]::new()

function Get-Sha256([string]$Path) {
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-NativeStep(
    [string]$Label,
    [string]$Command,
    [string[]]$Arguments
) {
    $stdoutPath = Join-Path $logRoot "$Label.stdout.log"
    $stderrPath = Join-Path $logRoot "$Label.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Push-Location $repoRoot
        try {
            & $Command @Arguments 1> $stdoutPath 2> $stderrPath
            $exitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    $steps.Add([pscustomobject][ordered]@{
        label = $Label
        command = $Command
        arguments = @($Arguments)
        working_directory = $repoRoot
        exit_code = $exitCode
        started_at = $started.ToString('o')
        completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        stdout_sha256 = if (Test-Path -LiteralPath $stdoutPath) { Get-Sha256 $stdoutPath } else { $null }
        stderr_sha256 = if (Test-Path -LiteralPath $stderrPath) { Get-Sha256 $stderrPath } else { $null }
    })
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode; see $stderrPath"
    }
}

function Invoke-Cargo([string]$Label, [string[]]$Arguments) {
    Invoke-NativeStep $Label 'cargo' $Arguments
}

function Invoke-CoreTests {
    Invoke-Cargo 'role-operations-tests' @('test', '-p', 'd2i-role-operations', '--all-features')
    Invoke-Cargo 'desktop-role-operations-tests' @('test', '-p', 'd2i-desktop', '--test', 'role_operations')
}

function Invoke-RoleFixtureCompile {
    $bundle = Join-Path $OutputRoot 'operations-role-bundle'
    if (Test-Path -LiteralPath $bundle) {
        Remove-Item -LiteralPath $bundle -Recurse -Force
    }
    Invoke-Cargo 'operations-role-compile' @(
        'run', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
        'compile', '--source',
        (Join-Path $repoRoot 'examples/workforce/general-office-operations-employee-operations-v1/role.yaml'),
        '--output', $bundle
    )
    Invoke-Cargo 'operations-role-verify' @(
        'run', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
        'verify', '--bundle', $bundle
    )
}

function Invoke-Regression {
    foreach ($runner in @(
        @('work-100', 'scripts/workforce/run-role-contract-v1.ps1'),
        @('work-200', 'scripts/workforce/run-work-item-case-v1.ps1'),
        @('work-300', 'scripts/workforce/run-work-radar-intake-v1.ps1'),
        @('work-400', 'scripts/workforce/run-work-queue-scheduler-v1.ps1')
    )) {
        Invoke-NativeStep $runner[0] 'powershell' @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $repoRoot $runner[1]), '-Mode', 'All',
            '-OutputRoot', (Join-Path $OutputRoot $runner[0])
        )
    }
    Invoke-Cargo 'work-500-contract-regression' @(
        'test', '-p', 'd2i-situation-model', '-p', 'd2i-intelligence-provider',
        '-p', 'd2i-adaptive-planner', '--all-features'
    )
    Invoke-Cargo 'work-600-contract-regression' @(
        'test', '-p', 'd2i-episodic-memory', '-p', 'd2i-case-learning', '--all-features'
    )
    Invoke-NativeStep 'krn-regression' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'),
        '-Mode', 'All', '-OutputRoot', (Join-Path $OutputRoot 'krn-regression')
    )
}

function Assert-ModelInputs {
    if (-not $Runtime -or -not (Test-Path -LiteralPath $Runtime -PathType Leaf)) {
        throw 'A concrete -Runtime executable is required for Completion.'
    }
    if (-not $Model -or -not (Test-Path -LiteralPath $Model -PathType Leaf)) {
        throw 'A concrete -Model artifact is required for Completion.'
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
}

function Invoke-Completion {
    Assert-ModelInputs
    Invoke-CoreTests
    Invoke-RoleFixtureCompile
    Invoke-Regression
    $work600Root = Join-Path $OutputRoot 'work-600-completion'
    Invoke-NativeStep 'work-600-completion' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/workforce/run-episodic-memory-learning-v1.ps1'),
        '-Mode', 'Completion', '-Runtime', $Runtime, '-Model', $Model,
        '-OutputRoot', $work600Root
    )
    $work600Finished = Get-Content -Raw -LiteralPath (Join-Path $work600Root 'finished.json') | ConvertFrom-Json
    if (-not $work600Finished.complete -or -not $work600Finished.product_memory_evidence) {
        throw 'WORK-600 Completion evidence is incomplete.'
    }
    $report = Join-Path $OutputRoot 'work700-completion-report.json'
    Invoke-Cargo 'work-700-operations-e2e' @(
        'run', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work700-operations-e2e', '--',
        'run', '--work600-report', (Join-Path $work600Root 'work600-completion-report.json'),
        '--role-source',
        (Join-Path $repoRoot 'examples/workforce/general-office-operations-employee-operations-v1/role.yaml'),
        '--output-root', (Join-Path $OutputRoot 'operations-e2e'), '--output', $report
    )
    $completion = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if (-not $completion.source_work600_path_c_actual_model_invocation -or
        -not $completion.source_work600_verified_closure -or
        $completion.role_contract_version -ne '1.2.0' -or
        $completion.case_a_sla_status -ne 'compliant' -or
        $completion.case_b_sla_status -ne 'compliant' -or
        $completion.case_b_pause_seconds -le 0 -or
        $completion.case_c_sla_status -ne 'breached' -or
        -not $completion.case_d_human_exception -or
        -not $completion.case_e_explicit_refusal -or
        $completion.total_cases -ne 5 -or
        $completion.duplicate_breach_count -ne 0 -or
        $completion.duplicate_escalation_count -ne 0 -or
        $completion.external_delivery_claim_count -ne 0 -or
        $completion.replay_case_count -ne 128 -or
        $completion.replay_iterations -ne 100 -or
        $completion.replay_critical_errors -ne 0 -or
        $completion.sensitive_artifact_count -ne 0 -or
        $completion.residual_process_count -ne 0 -or
        $completion.residual_credential_count -ne 0 -or
        $completion.residual_activation_count -ne 0 -or
        $completion.residual_profile_count -ne 0 -or
        $completion.residual_store_count -ne 0 -or
        $completion.residual_lock_count -ne 0) {
        throw 'WORK-700 Completion evidence failed a product gate.'
    }
}

function Assert-Cleanup {
    if ($Runtime) {
        $runtimePath = [System.IO.Path]::GetFullPath($Runtime)
        $residual = @(Get-CimInstance Win32_Process | Where-Object {
            $_.ExecutablePath -and
            [System.IO.Path]::GetFullPath($_.ExecutablePath).Equals($runtimePath, [System.StringComparison]::OrdinalIgnoreCase)
        })
        if ($residual.Count -ne 0) {
            throw "Residual model processes remain: $($residual.ProcessId -join ',')"
        }
    }
    $profiles = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -Filter 'D2I.Work*' -ErrorAction SilentlyContinue)
    if ($profiles.Count -ne 0) {
        throw "Residual Workforce profiles remain: $($profiles.Name -join ',')"
    }
    foreach ($name in @('protected-store', 'protected-audit', 'coordinator.lock')) {
        $residualPath = Join-Path $OutputRoot "operations-e2e/$name"
        if (Test-Path -LiteralPath $residualPath) {
            throw "Residual WORK-700 state remains: $residualPath"
        }
    }
    foreach ($file in Get-ChildItem -LiteralPath $OutputRoot -Recurse -File -Filter '*.json') {
        if (Select-String -LiteralPath $file.FullName -Pattern '(?i)(password\s*[:=]|api[_-]?key\s*[:=]|bearer\s+[a-z0-9._-]+|raw[_ -]?locator\s*[:=]|chain[_ -]?of[_ -]?thought\s*[:=]|https?://|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})' -Quiet) {
            throw "Sensitive or external-routing artifact scan failed: $($file.FullName)"
        }
    }
}

function Write-Finished([bool]$RoleOperationsEvidence) {
    $completionPath = Join-Path $OutputRoot 'work700-completion-report.json'
    $completion = if (Test-Path -LiteralPath $completionPath) {
        Get-Content -Raw -LiteralPath $completionPath | ConvertFrom-Json
    } else {
        $null
    }
    $finished = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        git_head = (git -C $repoRoot rev-parse HEAD).Trim()
        complete = $true
        role_operations_evidence = $RoleOperationsEvidence
        model_sha256 = if ($RoleOperationsEvidence) { Get-Sha256 $Model } else { $null }
        runtime_sha256 = if ($RoleOperationsEvidence) { Get-Sha256 $Runtime } else { $null }
        completion_report_sha256 = if ($completion) { $completion.report_sha256 } else { $null }
        source_work600_report_sha256 = if ($completion) { $completion.source_work600_report_sha256 } else { $null }
        role_contract_sha256 = if ($completion) { $completion.role_contract_sha256 } else { $null }
        operations_profile_sha256 = if ($completion) { $completion.operations_profile_sha256 } else { $null }
        snapshot_sha256 = if ($completion) { $completion.snapshot_sha256 } else { $null }
        replay_sha256 = if ($completion) { $completion.replay_hash } else { $null }
        protected_store_terminal_sha256 = if ($completion) { $completion.protected_store_terminal_sha256 } else { $null }
        protected_audit_terminal_sha256 = if ($completion) { $completion.protected_audit_terminal_sha256 } else { $null }
        residual_processes = 0
        residual_credentials = 0
        residual_activations = 0
        residual_profiles = 0
        residual_stores = 0
        residual_locks = 0
        steps = @($steps)
        finished_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $finished.GetEnumerator()) {
        if ($entry.Key -ne 'finished_sha256') {
            $withoutHash[$entry.Key] = $entry.Value
        }
    }
    $compact = $withoutHash | ConvertTo-Json -Depth 12 -Compress
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($compact))
    }
    finally {
        $hasher.Dispose()
    }
    $finished.finished_sha256 = 'sha256:' + ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
    $finished | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputRoot 'finished.json') -Encoding UTF8
}

switch ($Mode) {
    'Contract' { Invoke-CoreTests }
    'Schema' { Invoke-Cargo 'schema-tests' @('test', '-p', 'd2i-role-operations', 'all_public_schemas') }
    'Time' { Invoke-Cargo 'time-tests' @('test', '-p', 'd2i-role-operations', 'trusted_time') }
    'Sla' { Invoke-Cargo 'sla-tests' @('test', '-p', 'd2i-role-operations', 'pause_aware_sla') }
    'Pause' { Invoke-Cargo 'pause-tests' @('test', '-p', 'd2i-role-operations', 'pause_aware_sla') }
    'Breach' { Invoke-Cargo 'breach-tests' @('test', '-p', 'd2i-role-operations', 'pause_aware_sla') }
    'Metrics' { Invoke-Cargo 'metric-tests' @('test', '-p', 'd2i-role-operations', 'generic_metrics') }
    'Kpi' { Invoke-Cargo 'kpi-tests' @('test', '-p', 'd2i-role-operations', 'generic_metrics') }
    'Reports' { Invoke-Cargo 'report-tests' @('test', '-p', 'd2i-role-operations', 'reports_routes') }
    'Routing' { Invoke-Cargo 'routing-tests' @('test', '-p', 'd2i-role-operations', 'reports_routes') }
    'Escalation' { Invoke-Cargo 'escalation-tests' @('test', '-p', 'd2i-role-operations', 'reports_routes') }
    'Acknowledgement' { Invoke-Cargo 'ack-tests' @('test', '-p', 'd2i-role-operations', 'reports_routes') }
    'Resolution' { Invoke-Cargo 'resolution-tests' @('test', '-p', 'd2i-role-operations', 'reports_routes') }
    'Persistence' { Invoke-Cargo 'persistence-tests' @('test', '-p', 'd2i-desktop', '--test', 'role_operations') }
    'CrashRecovery' { Invoke-Cargo 'crash-tests' @('test', '-p', 'd2i-desktop', '--test', 'role_operations', 'repairs_only') }
    'GeneralOfficeE2E' { Invoke-RoleFixtureCompile; Invoke-CoreTests }
    'CrossDomain' { Invoke-Cargo 'cross-domain-tests' @('test', '-p', 'd2i-role-operations', 'generic_metrics') }
    'Negative' { Invoke-CoreTests }
    'Replay' { Invoke-Cargo 'replay-tests' @('test', '-p', 'd2i-role-operations', 'one_hundred_replays') }
    'Regression' { Invoke-Regression }
    'All' { Invoke-CoreTests; Invoke-RoleFixtureCompile; Invoke-Regression }
    'Completion' { Invoke-Completion }
}

if ($Mode -eq 'Completion') {
    Assert-Cleanup
}
Write-Finished ($Mode -eq 'Completion')
Write-Output "D2I WORK-700 $Mode complete: $OutputRoot"
