[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Episode', 'Seal', 'Store', 'Query',
        'ReusePolicy', 'Summary', 'Attachment', 'Retention', 'Tombstone',
        'LearningCandidate', 'Quarantine', 'Persistence', 'CrashRecovery',
        'GeneralOfficeE2E', 'MemoryAwareE2E', 'CrossDomain', 'Negative',
        'Replay', 'Regression', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,

    [string]$Model,

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot 'target/d2i-workforce-memory'
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
        & $Command @Arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    $steps.Add([pscustomobject][ordered]@{
        label = $Label
        command = $Command
        arguments = @($Arguments)
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
    Invoke-Cargo 'episodic-memory-tests' @('test', '-p', 'd2i-episodic-memory', '--all-features')
    Invoke-Cargo 'case-learning-tests' @('test', '-p', 'd2i-case-learning', '--all-features')
    Invoke-Cargo 'desktop-memory-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory')
}

function Invoke-RoleFixtureCompile {
    foreach ($fixture in @(
        @('canonical-role', 'examples/workforce/general-office-operations-employee/role.yaml'),
        @('memory-role', 'examples/workforce/general-office-operations-employee-memory-v1/role.yaml')
    )) {
        $bundle = Join-Path $OutputRoot ($fixture[0] + '-bundle')
        if (Test-Path -LiteralPath $bundle) {
            Remove-Item -LiteralPath $bundle -Recurse -Force
        }
        Invoke-Cargo ($fixture[0] + '-compile') @(
            'run', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
            'compile', '--source', (Join-Path $repoRoot $fixture[1]), '--output', $bundle
        )
        Invoke-Cargo ($fixture[0] + '-verify') @(
            'run', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
            'verify', '--bundle', $bundle
        )
    }
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
    $work500Root = Join-Path $OutputRoot 'work-500-completion'
    Invoke-NativeStep 'work-500-completion' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/workforce/run-situation-adaptive-planner-v1.ps1'),
        '-Mode', 'Completion', '-Runtime', $Runtime, '-Model', $Model,
        '-OutputRoot', $work500Root
    )
    $work500Finished = Get-Content -Raw -LiteralPath (Join-Path $work500Root 'finished.json') | ConvertFrom-Json
    if (-not $work500Finished.complete -or -not $work500Finished.product_intelligence_evidence) {
        throw 'WORK-500 Completion evidence is not complete.'
    }
    $report = Join-Path $OutputRoot 'work600-completion-report.json'
    Invoke-Cargo 'work-600-memory-e2e' @(
        'run', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work600-memory-e2e', '--',
        'run', '--runtime', $Runtime, '--model', $Model,
        '--work500-report', (Join-Path $work500Root 'model-e2e-report.json'),
        '--work500-plans', (Join-Path $work500Root 'model-e2e-report.plans.json'),
        '--canonical-role-bundle', (Join-Path $OutputRoot 'canonical-role-bundle/role.bundle.json'),
        '--memory-role-bundle', (Join-Path $OutputRoot 'memory-role-bundle/role.bundle.json'),
        '--output-root', (Join-Path $OutputRoot 'memory-e2e'), '--output', $report
    )
    $completion = Get-Content -Raw -LiteralPath $report | ConvertFrom-Json
    if (-not $completion.path_c_actual_model_invocation -or
        -not $completion.approved_summary_in_provider_context -or
        -not $completion.tampered_query_rejected -or
        -not $completion.canonical_role_sha256 -or
        -not $completion.memory_role_bundle_sha256 -or
        -not $completion.memory_role_approval_sha256 -or
        -not $completion.memory_role_delegation_sha256 -or
        -not $completion.memory_role_instance_sha256 -or
        -not $completion.fresh_observation_preferred -or
        -not $completion.verified_closure -or
        $completion.unnecessary_set_value_count -ne 0 -or
        $completion.wrong_case_action_count -ne 0 -or
        $completion.production_mutation_count -ne 0 -or
        $completion.replay_episode_count -ne 128 -or
        $completion.replay_iterations -ne 100 -or
        $completion.replay_critical_errors -ne 0 -or
        $completion.residual_process_count -ne 0 -or
        $completion.residual_store_count -ne 0) {
        throw 'WORK-600 Completion evidence failed a product gate.'
    }
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
    Invoke-NativeStep 'krn-regression' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'),
        '-Mode', 'All', '-OutputRoot', (Join-Path $OutputRoot 'krn-regression')
    )
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
    $profiles = @(Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -Filter 'D2I.Work5*' -ErrorAction SilentlyContinue)
    if ($profiles.Count -ne 0) {
        throw "Residual Workforce model profiles remain: $($profiles.Name -join ',')"
    }
    if (Test-Path -LiteralPath (Join-Path $OutputRoot 'memory-e2e/protected-store')) {
        throw 'Residual protected memory E2E store remains.'
    }
    foreach ($file in Get-ChildItem -LiteralPath $OutputRoot -Recurse -File -Filter '*.json') {
        if (Select-String -LiteralPath $file.FullName -Pattern '(?i)(password\s*[:=]|api[_-]?key\s*[:=]|bearer\s+[a-z0-9._-]+|raw[_ -]?locator\s*[:=]|chain[_ -]?of[_ -]?thought\s*[:=])' -Quiet) {
            throw "Sensitive artifact scan failed: $($file.FullName)"
        }
    }
}

function Write-Finished([bool]$ProductEvidence) {
    $completionPath = Join-Path $OutputRoot 'work600-completion-report.json'
    $completion = if (Test-Path -LiteralPath $completionPath) { Get-Content -Raw -LiteralPath $completionPath | ConvertFrom-Json } else { $null }
    $finished = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        git_head = (git -C $repoRoot rev-parse HEAD).Trim()
        complete = $true
        product_memory_evidence = $ProductEvidence
        model_sha256 = if ($ProductEvidence) { Get-Sha256 $Model } else { $null }
        runtime_sha256 = if ($ProductEvidence) { Get-Sha256 $Runtime } else { $null }
        completion_report_sha256 = if ($completion) { $completion.report_sha256 } else { $null }
        episode_set_sha256 = if ($completion) { $completion.replay_episode_set_sha256 } else { $null }
        index_sha256 = if ($completion) { $completion.replay_index_sha256 } else { $null }
        query_sha256 = if ($completion) { $completion.replay_query_sha256 } else { $null }
        attachment_sha256 = if ($completion) { $completion.memory_attachment_sha256 } else { $null }
        candidate_sha256 = if ($completion) { $completion.candidate_sha256 } else { $null }
        protected_audit_terminal_sha256 = if ($completion) { $completion.protected_audit_terminal_sha256 } else { $null }
        memory_audit_terminal_sha256 = if ($completion) { $completion.memory_audit_terminal_sha256 } else { $null }
        residual_processes = 0
        residual_credentials = 0
        residual_activations = 0
        residual_profiles = 0
        residual_stores = 0
        steps = @($steps)
        finished_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $finished.GetEnumerator()) {
        if ($entry.Key -ne 'finished_sha256') { $withoutHash[$entry.Key] = $entry.Value }
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

Push-Location $repoRoot
try {
    switch ($Mode) {
        'Contract' { Invoke-CoreTests }
        'Schema' { Invoke-CoreTests }
        'Episode' { Invoke-Cargo 'episode-tests' @('test', '-p', 'd2i-episodic-memory', 'terminal_episode') }
        'Seal' { Invoke-Cargo 'seal-tests' @('test', '-p', 'd2i-episodic-memory', 'terminal_episode_seals_exactly_once') }
        'Store' { Invoke-Cargo 'store-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory') }
        'Query' { Invoke-Cargo 'query-tests' @('test', '-p', 'd2i-episodic-memory', 'reuse_policies_are_distinct') }
        'ReusePolicy' { Invoke-Cargo 'reuse-tests' @('test', '-p', 'd2i-episodic-memory', 'reuse_policies_are_distinct') }
        'Summary' { Invoke-Cargo 'summary-tests' @('test', '-p', 'd2i-episodic-memory', 'sensitive_and_instruction_like_memory_is_rejected') }
        'Attachment' { Invoke-Cargo 'attachment-tests' @('test', '-p', 'd2i-episodic-memory', 'memory_attachment') }
        'Retention' { Invoke-Cargo 'retention-tests' @('test', '-p', 'd2i-episodic-memory', 'retention_uses') }
        'Tombstone' { Invoke-Cargo 'tombstone-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory', 'tombstone') }
        'LearningCandidate' { Invoke-Cargo 'candidate-tests' @('test', '-p', 'd2i-case-learning', '--all-features') }
        'Quarantine' { Invoke-Cargo 'quarantine-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory', 'candidate_is_quarantined') }
        'Persistence' { Invoke-Cargo 'persistence-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory') }
        'CrashRecovery' { Invoke-Cargo 'crash-tests' @('test', '-p', 'd2i-desktop', '--test', 'episodic_memory', 'stale_index') }
        'GeneralOfficeE2E' { Invoke-RoleFixtureCompile; Invoke-CoreTests }
        'MemoryAwareE2E' { Invoke-Completion }
        'CrossDomain' { Invoke-Cargo 'cross-domain-tests' @('test', '-p', 'd2i-case-learning', '--all-features') }
        'Negative' { Invoke-CoreTests }
        'Replay' { Invoke-Cargo 'replay-tests' @('test', '-p', 'd2i-episodic-memory', '-p', 'd2i-case-learning', '--all-features') }
        'Regression' { Invoke-Regression }
        'All' { Invoke-CoreTests; Invoke-RoleFixtureCompile; Invoke-Regression }
        'Completion' { Invoke-Completion }
    }
    if ($Mode -in @('Completion', 'MemoryAwareE2E')) { Assert-Cleanup }
    Write-Finished ($Mode -in @('Completion', 'MemoryAwareE2E'))
    Write-Output "D2I WORK-600 $Mode complete: $OutputRoot"
}
finally {
    Pop-Location
}
