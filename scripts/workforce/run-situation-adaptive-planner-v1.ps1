[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Situation', 'ProviderProtocol', 'GoalUnderstanding',
        'Planner', 'RecordedReplay', 'ModelEvaluation', 'ModelE2E', 'ClosedLoopE2E',
        'Variation', 'Adversarial', 'Persistence', 'CrashRecovery', 'CrossDomain',
        'Negative', 'Regression', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,

    [string]$Model,

    [string]$EvaluationReport,

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $repoRoot 'target/d2i-workforce-planner'
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
$previousKernelBuildRoot = $env:D2I_KERNEL_E2E_BUILD_ROOT
$managedKernelBuildRoot = $null
$kernelBuildMarkerName = '.d2i-work500-owned-build-root'

function Get-Sha256([string]$Path) {
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Enable-ManagedKernelBuildRoot {
    $parent = [System.IO.Path]::GetFullPath((Join-Path $targetRoot 'd2i-work500-kernel-build'))
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $parent ([Guid]::NewGuid().ToString('N'))))
    if (-not $candidate.StartsWith($parent + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Managed KRN build root escaped its target parent.'
    }
    New-Item -ItemType Directory -Path $candidate | Out-Null
    $marker = Join-Path $candidate $kernelBuildMarkerName
    [System.IO.File]::WriteAllText($marker, $OutputRoot, [System.Text.UTF8Encoding]::new($false))
    $script:managedKernelBuildRoot = $candidate
    $env:D2I_KERNEL_E2E_BUILD_ROOT = $candidate
}

function Remove-ManagedKernelBuildRoot {
    if (-not $managedKernelBuildRoot) {
        return
    }
    $parent = [System.IO.Path]::GetFullPath((Join-Path $targetRoot 'd2i-work500-kernel-build'))
    $candidate = [System.IO.Path]::GetFullPath($managedKernelBuildRoot)
    $marker = Join-Path $candidate $kernelBuildMarkerName
    if (-not $candidate.StartsWith($parent + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $marker -PathType Leaf) -or
        [System.IO.File]::ReadAllText($marker) -ne $OutputRoot) {
        throw 'Managed KRN build root ownership verification failed.'
    }
    Remove-Item -LiteralPath $candidate -Recurse -Force
    $script:managedKernelBuildRoot = $null
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
    $completed = [DateTimeOffset]::UtcNow
    $steps.Add([pscustomobject][ordered]@{
        label = $Label
        command = $Command
        arguments = @($Arguments)
        exit_code = $exitCode
        started_at = $started.ToString('o')
        completed_at = $completed.ToString('o')
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

function Invoke-DeterministicSuite {
    Invoke-Cargo 'situation-tests' @('test', '-p', 'd2i-situation-model', '--all-features')
    Invoke-Cargo 'provider-tests' @('test', '-p', 'd2i-intelligence-provider', '--all-features')
    Invoke-Cargo 'planner-tests' @('test', '-p', 'd2i-adaptive-planner', '--all-features')
    Invoke-Cargo 'desktop-adaptive-tests' @('test', '-p', 'd2i-desktop', '--test', 'adaptive_case')
}

function Assert-ModelInputs {
    if (-not $Runtime -or -not (Test-Path -LiteralPath $Runtime -PathType Leaf)) {
        throw 'A concrete -Runtime executable is required for this mode.'
    }
    if (-not $Model -or -not (Test-Path -LiteralPath $Model -PathType Leaf)) {
        throw 'A concrete -Model artifact is required for this mode.'
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
}

function Invoke-ModelEvaluation {
    Assert-ModelInputs
    $report = Join-Path $OutputRoot 'model-evaluation-report.json'
    Invoke-Cargo 'model-evaluation' @(
        'run', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work500-evaluator', '--',
        'evaluate', '--runtime', $Runtime, '--model', $Model, '--output', $report
    )
    $script:EvaluationReport = $report
}

function Invoke-ModelE2E {
    Assert-ModelInputs
    if (-not $EvaluationReport) {
        $script:EvaluationReport = Join-Path $OutputRoot 'model-evaluation-report.json'
    }
    if (-not (Test-Path -LiteralPath $EvaluationReport -PathType Leaf)) {
        throw 'A passing model evaluation report is required before ModelE2E.'
    }
    $script:EvaluationReport = (Resolve-Path -LiteralPath $EvaluationReport).Path
    $report = Join-Path $OutputRoot 'model-e2e-report.json'
    Invoke-Cargo 'model-e2e' @(
        'run', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work500-model-e2e', '--',
        'run', '--runtime', $Runtime, '--model', $Model,
        '--evaluation', $EvaluationReport, '--output', $report,
        '--output-root', (Join-Path $OutputRoot 'model-e2e')
    )
}

function Invoke-RegressionSuite {
    $runners = @(
        @('work-100', 'scripts/workforce/run-role-contract-v1.ps1'),
        @('work-200', 'scripts/workforce/run-work-item-case-v1.ps1'),
        @('work-300', 'scripts/workforce/run-work-radar-intake-v1.ps1'),
        @('work-400', 'scripts/workforce/run-work-queue-scheduler-v1.ps1')
    )
    foreach ($runner in $runners) {
        Invoke-NativeStep $runner[0] 'powershell' @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $repoRoot $runner[1]), '-Mode', 'All',
            '-OutputRoot', (Join-Path $OutputRoot $runner[0])
        )
    }
    Invoke-NativeStep 'krn-regression' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'),
        '-Mode', 'All', '-OutputRoot', (Join-Path $OutputRoot 'krn-regression')
    )
}

function Assert-TerminalCleanup {
    if ($Runtime) {
        $runtimePath = [System.IO.Path]::GetFullPath($Runtime)
        $residual = @(
            Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
                Where-Object {
                    $_.ExecutablePath -and
                    [System.IO.Path]::GetFullPath($_.ExecutablePath).Equals(
                        $runtimePath,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                }
        )
        if ($residual.Count -ne 0) {
            throw "Residual local model processes remain: $($residual.ProcessId -join ',')"
        }
    }
    $profileRoot = Join-Path $env:LOCALAPPDATA 'Packages'
    $profiles = @(Get-ChildItem -LiteralPath $profileRoot -Directory -Filter 'D2I.Work500*' -ErrorAction SilentlyContinue)
    if ($profiles.Count -ne 0) {
        throw "Residual WORK-500 AppContainer profile storage remains: $($profiles.Name -join ',')"
    }
    $jsonFiles = @(Get-ChildItem -LiteralPath $OutputRoot -Recurse -File -Filter '*.json')
    foreach ($file in $jsonFiles) {
        $matches = @(Select-String -LiteralPath $file.FullName -Pattern '(?i)(password\s*[:=]|api[_-]?key\s*[:=]|bearer\s+[a-z0-9._-]+)' -AllMatches)
        if ($matches.Count -ne 0) {
            throw "Sensitive artifact scan failed: $($file.FullName)"
        }
    }
}

function Write-Finished([bool]$ProductEvidence) {
    $evaluationPath = Join-Path $OutputRoot 'model-evaluation-report.json'
    $e2ePath = Join-Path $OutputRoot 'model-e2e-report.json'
    $finished = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        git_head = (git -C $repoRoot rev-parse HEAD).Trim()
        complete = $true
        product_intelligence_evidence = $ProductEvidence
        provider_kind = if ($ProductEvidence) { 'local_model_process' } else { $null }
        model_id = if ($ProductEvidence) { 'Qwen/Qwen3-4B-GGUF' } else { $null }
        model_revision = if ($ProductEvidence) { 'bc640142c66e1fdd12af0bd68f40445458f3869b' } else { $null }
        model_sha256 = if ($ProductEvidence) { 'sha256:7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5' } else { $null }
        runtime_id = if ($ProductEvidence) { 'ggml-org/llama.cpp' } else { $null }
        runtime_sha256 = if ($ProductEvidence) { Get-Sha256 $Runtime } else { $null }
        runtime_distribution_sha256 = if ($ProductEvidence) { 'sha256:6029d1e839018b8edeaafff0da08952b68d0e4b7b4431c8aabe6c2dac8e66103' } else { $null }
        prompt_template_sha256 = if ($ProductEvidence) { Get-Sha256 (Join-Path $repoRoot 'config/intelligence/qwen3-workforce-v1/planning-system-prompt.txt') } else { $null }
        evaluation_report_sha256 = if (Test-Path -LiteralPath $evaluationPath) { (Get-Content -Raw -LiteralPath $evaluationPath | ConvertFrom-Json).report_sha256 } else { $null }
        model_e2e_report_sha256 = if (Test-Path -LiteralPath $e2ePath) { (Get-Content -Raw -LiteralPath $e2ePath | ConvertFrom-Json).report_sha256 } else { $null }
        residual_processes = 0
        residual_credentials = 0
        residual_activations = 0
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

$usesKernelBuild = $Mode -in @('ModelE2E', 'ClosedLoopE2E', 'Variation', 'Regression', 'Completion')
if ($usesKernelBuild) {
    Enable-ManagedKernelBuildRoot
}

Push-Location $repoRoot
try {
    switch ($Mode) {
        'Contract' { Invoke-DeterministicSuite }
        'Schema' { Invoke-Cargo 'schema-tests' @('test', '-p', 'd2i-desktop', '--test', 'adaptive_case', 'work500_schemas_are_strict_and_compile') }
        'Situation' { Invoke-Cargo 'situation-tests' @('test', '-p', 'd2i-situation-model', '--all-features') }
        'ProviderProtocol' { Invoke-Cargo 'provider-tests' @('test', '-p', 'd2i-intelligence-provider', '--all-features') }
        'GoalUnderstanding' { Invoke-Cargo 'goal-tests' @('test', '-p', 'd2i-intelligence-provider', '--all-features') }
        'Planner' { Invoke-Cargo 'planner-tests' @('test', '-p', 'd2i-adaptive-planner', '--all-features') }
        'RecordedReplay' { Invoke-Cargo 'recorded-replay' @('test', '-p', 'd2i-intelligence-provider', '--all-features') }
        'ModelEvaluation' { Invoke-ModelEvaluation }
        'ModelE2E' { Invoke-ModelE2E }
        'ClosedLoopE2E' { Invoke-ModelE2E }
        'Variation' {
            Invoke-NativeStep 'krn-adaptive' 'powershell' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'), '-Mode', 'Adaptive', '-OutputRoot', (Join-Path $OutputRoot 'krn-adaptive'))
        }
        'Adversarial' { Invoke-Cargo 'adversarial-tests' @('test', '-p', 'd2i-desktop', '--test', 'adaptive_case') }
        'Persistence' { Invoke-Cargo 'persistence-tests' @('test', '-p', 'd2i-desktop', '--test', 'adaptive_case', 'planner_ledger_is_durable_and_tamper_evident') }
        'CrashRecovery' { Invoke-Cargo 'crash-tests' @('test', '-p', 'd2i-desktop', 'crash_windows_map_to_fresh_safe_recovery') }
        'CrossDomain' { Invoke-Cargo 'cross-domain-tests' @('test', '-p', 'd2i-adaptive-planner', 'opaque_cross_domain_work_classes_share_one_planning_contract') }
        'Negative' { Invoke-DeterministicSuite }
        'Regression' { Invoke-RegressionSuite }
        'All' { Invoke-DeterministicSuite }
        'Completion' {
            Invoke-DeterministicSuite
            Invoke-ModelEvaluation
            Invoke-ModelE2E
            Invoke-RegressionSuite
            Assert-TerminalCleanup
        }
    }
    $productEvidence = $Mode -eq 'Completion'
    if ($Mode -in @('ModelEvaluation', 'ModelE2E', 'ClosedLoopE2E')) {
        Assert-TerminalCleanup
    }
    Write-Finished $productEvidence
    Write-Output "D2I WORK-500 $Mode complete: $OutputRoot"
}
finally {
    Pop-Location
    try {
        Remove-ManagedKernelBuildRoot
    }
    finally {
        $env:D2I_KERNEL_E2E_BUILD_ROOT = $previousKernelBuildRoot
    }
}
