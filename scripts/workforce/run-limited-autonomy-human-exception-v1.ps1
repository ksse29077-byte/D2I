[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Readiness', 'Profile', 'Deployment', 'Role',
        'Control', 'Eligibility', 'Admission', 'DutyCycle', 'HumanException',
        'Health', 'Persistence', 'CrashRecovery', 'GeneralOfficeE2E', 'Negative',
        'Replay', 'Regression', 'Certification', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,
    [string]$Model,
    [string]$Work800EvidenceRoot,
    [string]$OutputRoot,
    [switch]$Resume,
    [switch]$Fresh,
    [switch]$ReuseVerifiedPredecessorEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Resume -and $Fresh) {
    throw '-Resume and -Fresh cannot be used together.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
$checkpointModule = Join-Path $PSScriptRoot 'lib/WorkforceCheckpoint.psm1'
Import-Module -Force $checkpointModule
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $targetRoot 'd2i-work900-limited-autonomy'
}
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot $OutputRoot
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a child of the repository target directory.'
}

$roleSource = Join-Path $repoRoot 'examples/workforce/general-office-operations-employee-limited-autonomy-v1/role.yaml'
$runnerPath = $MyInvocation.MyCommand.Path
$logRoot = Join-Path $OutputRoot 'logs'
$checkpointRoot = Join-Path $OutputRoot 'checkpoints'
$diagnosticRoot = Join-Path $OutputRoot 'diagnostics'
$resumeManifestPath = Join-Path $OutputRoot 'resume-manifest.json'
$steps = [System.Collections.Generic.List[object]]::new()
$verified = [ordered]@{}
$invalidated = [System.Collections.Generic.List[string]]::new()
$runId = 'work900-' + [Guid]::NewGuid().ToString('N')
$resumeCount = 0
$lastCheckpoint = $null
$failedStep = $null
$zeroHash = 'sha256:' + ('0' * 64)

function Remove-RunnerDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the WORK-900 output root: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

if ($Fresh -and (Test-Path -LiteralPath $OutputRoot)) {
    Remove-RunnerDirectory $OutputRoot
}
New-Item -ItemType Directory -Path $OutputRoot, $logRoot, $checkpointRoot, $diagnosticRoot -Force | Out-Null

function Invoke-NativeStep([string]$Label, [string]$Command, [string[]]$Arguments) {
    $stdout = Join-Path $logRoot "$Label.stdout.log"
    $stderr = Join-Path $logRoot "$Label.stderr.log"
    $started = [DateTimeOffset]::UtcNow
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $exitCode = -1
    try {
        Push-Location $repoRoot
        try {
            & $Command @Arguments 1> $stdout 2> $stderr
            $exitCode = $LASTEXITCODE
        }
        finally { Pop-Location }
    }
    finally { $ErrorActionPreference = $saved }
    $completed = [DateTimeOffset]::UtcNow
    $steps.Add([pscustomobject][ordered]@{
        label = $Label
        command = $Command
        arguments = @($Arguments)
        working_directory = $repoRoot
        exit_code = $exitCode
        started_at = $started.ToString('o')
        completed_at = $completed.ToString('o')
        duration_milliseconds = [uint64][Math]::Max(0, ($completed - $started).TotalMilliseconds)
        stdout_path = $stdout
        stderr_path = $stderr
    })
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode; see $stderr"
    }
}

function Invoke-Cargo([string]$Label, [string[]]$Arguments) {
    Invoke-NativeStep $Label 'cargo' $Arguments
}

function Invoke-Schema {
    Invoke-NativeStep 'work900-schema-generation' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/workforce/generate-limited-autonomy-schemas.ps1'), '-Check'
    )
    Invoke-Cargo 'work900-schema-tests' @('test', '--locked', '-p', 'd2i-limited-autonomy', 'all_public_schemas_are_strict_draft_2020_12')
}

function Invoke-Role {
    $bundle = Join-Path $OutputRoot 'role-bundle'
    if (Test-Path -LiteralPath $bundle) { Remove-RunnerDirectory $bundle }
    Invoke-Cargo 'work900-role-compile' @(
        'run', '--locked', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
        'compile', '--source', $roleSource, '--output', $bundle
    )
    Invoke-Cargo 'work900-role-verify' @(
        'run', '--locked', '-q', '-p', 'd2i-role-contract', '--bin', 'd2i-role', '--',
        'verify', '--bundle', $bundle
    )
}

function Invoke-Core([string]$Filter = '') {
    $arguments = @('test', '--locked', '-p', 'd2i-limited-autonomy', '--all-features')
    if ($Filter) { $arguments += $Filter }
    Invoke-Cargo ('work900-core-' + $(if ($Filter) { $Filter } else { 'all' })) $arguments
}

function Invoke-Persistence {
    Invoke-Cargo 'work900-desktop-store' @('test', '--locked', '-p', 'd2i-desktop', '--test', 'limited_autonomy')
}

function Invoke-All {
    Invoke-Core
    Invoke-Persistence
    Invoke-Schema
    Invoke-Role
    Invoke-NativeStep 'work900-resume-tests' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/workforce/test-limited-autonomy-resume.ps1')
    )
    Invoke-Cargo 'work800-checkpoint-regression' @('test', '--locked', '-p', 'd2i-shadow-mode', '--all-features')
}

function Assert-CompletionInputs {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence; WORK-800 is verified, never silently promoted.'
    }
    foreach ($item in @(
            @('Runtime', $Runtime, 'Leaf'), @('Model', $Model, 'Leaf'),
            @('Work800EvidenceRoot', $Work800EvidenceRoot, 'Container'),
            @('RoleSource', $roleSource, 'Leaf')
        )) {
        if (-not $item[1] -or -not (Test-Path -LiteralPath $item[1] -PathType $item[2])) {
            throw "$($item[0]) is required and must exist for Completion."
        }
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
    $script:Work800EvidenceRoot = (Resolve-Path -LiteralPath $Work800EvidenceRoot).Path
}

function New-CompletionContext {
    $sourceHash = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    $arguments = [ordered]@{
        mode = 'completion'
        model = Get-WorkforceFileHash $Model
        runtime = Get-WorkforceFileHash $Runtime
        predecessor_finished = Get-WorkforceFileHash (Join-Path $Work800EvidenceRoot 'finished.json')
        role_source = Get-WorkforceFileHash $roleSource
    }
    return @{
        source_tree_sha256 = $sourceHash
        git_sha = (& git -C $repoRoot rev-parse HEAD).Trim()
        runner_sha256 = Get-WorkforceFileHash $runnerPath
        mode = 'completion'
        normalized_arguments_sha256 = Get-WorkforceObjectHash $arguments
        model_sha256 = $arguments.model
        runtime_sha256 = $arguments.runtime
        role_contract_sha256 = Get-WorkforceSha256Text 'general-office-operations-employee:1.4.0'
        shadow_profile_sha256 = $zeroHash
        readiness_policy_sha256 = $zeroHash
        cohort_sha256 = Get-WorkforceSha256Text 'work900-eight-case-canary-v1'
    }
}

function Write-Resume([hashtable]$Context) {
    $manifest = New-WorkforceResumeManifest -Context $Context -RunId $runId `
        -LastVerifiedCheckpoint $lastCheckpoint `
        -VerifiedCheckpointHashes @($verified.Values | ForEach-Object checkpoint_sha256) `
        -InvalidatedCheckpointIds @($invalidated) -FailedStepId $failedStep -ResumeCount $resumeCount
    Write-WorkforceAtomicJson -Path $resumeManifestPath -Value $manifest -Pretty
}

function Remove-CheckpointDownstream([int]$Ordinal) {
    foreach ($file in Get-ChildItem -LiteralPath $checkpointRoot -Filter '*.json' -File -ErrorAction SilentlyContinue) {
        try { $checkpoint = Read-WorkforceCheckpoint $file.FullName } catch { $checkpoint = $null }
        if ($null -eq $checkpoint -or [int]$checkpoint.step_ordinal -ge $Ordinal) {
            if ($checkpoint) { $invalidated.Add([string]$checkpoint.step_id) }
            Remove-Item -LiteralPath $file.FullName -Force
        }
    }
}

function Get-StepExecutableSourceHash([string]$Id) {
    $roots = switch ($Id) {
        '001-predecessor-work800' { @(
                'Cargo.lock', 'Cargo.toml',
                'scripts/workforce/run-limited-autonomy-human-exception-v1.ps1',
                'scripts/workforce/lib/WorkforceCheckpoint.psm1'
            ) }
        '005-workforce-input' { @(
                'Cargo.lock', 'Cargo.toml',
                'scripts/workforce/run-limited-autonomy-human-exception-v1.ps1',
                'scripts/workforce/run-work-radar-intake-v1.ps1',
                'scripts/workforce/run-work-queue-scheduler-v1.ps1',
                'crates/d2i-work-case', 'crates/d2i-work-intake', 'crates/d2i-work-queue',
                'products/d2i-desktop/src/work_intake.rs',
                'products/d2i-desktop/src/work_queue.rs',
                'products/d2i-desktop/tests/work_radar_intake.rs',
                'products/d2i-desktop/tests/work_queue_scheduler.rs',
                'products/d2i-desktop/tests/support'
            ) }
        '010-autonomy-governance' { @(
                'Cargo.lock', 'Cargo.toml', 'crates/d2i-limited-autonomy',
                'crates/d2i-windows-host', 'products/d2i-desktop/src/limited_autonomy.rs',
                'products/d2i-desktop/src/local_model_provider.rs',
                'products/d2i-desktop/src/work500_model.rs',
                'products/d2i-desktop/src/bin/d2i-work900-autonomy-e2e.rs',
                'config/intelligence/qwen3-workforce-v1',
                'examples/workforce/general-office-operations-employee-limited-autonomy-v1',
                'scripts/workforce/run-limited-autonomy-human-exception-v1.ps1'
            ) }
        '100-170-case-duty-cycle' { @(
                'Cargo.lock', 'Cargo.toml', 'crates', 'modules',
                'products/d2i-desktop/src', 'scripts/e2e',
                'examples/kernel-e2e/name-save',
                'examples/workforce/general-office-operations-employee-limited-autonomy-v1',
                'scripts/workforce/run-limited-autonomy-human-exception-v1.ps1'
            ) }
        '600-certification' { @(
                'Cargo.lock', 'Cargo.toml', 'crates/d2i-limited-autonomy',
                'products/d2i-desktop/src/limited_autonomy.rs',
                'products/d2i-desktop/src/bin/d2i-work900-autonomy-e2e.rs',
                'schemas/workforce',
                'scripts/workforce/run-limited-autonomy-human-exception-v1.ps1'
            ) }
        default { throw "Unknown WORK-900 checkpoint source set: $Id" }
    }
    $relativePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($relative in $roots) {
        $path = Join-Path $repoRoot $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $relativePaths.Add($relative.Replace('\', '/'))
            continue
        }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            throw "Checkpoint source root is missing: $relative"
        }
        $rootWithSeparator = $repoRoot.TrimEnd([char[]]@([char]92, [char]47)) + [IO.Path]::DirectorySeparatorChar
        $rootUri = [Uri]::new($rootWithSeparator)
        foreach ($file in Get-ChildItem -LiteralPath $path -File -Recurse) {
            $bounded = [Uri]::UnescapeDataString(
                $rootUri.MakeRelativeUri([Uri]::new($file.FullName)).ToString()
            ).Replace('\', '/')
            $relativePaths.Add($bounded)
        }
    }
    return Get-WorkforcePathSetHash -Root $repoRoot -RelativePaths @($relativePaths)
}

function Invoke-CheckpointStep(
    [hashtable]$Context,
    [string]$Id,
    [string]$Label,
    [int]$Ordinal,
    [string[]]$Dependencies,
    [scriptblock]$Action,
    [scriptblock]$Artifacts
) {
    $dependencyHashes = @($Dependencies | ForEach-Object {
        if (-not $verified.Contains($_)) { throw "Unverified checkpoint dependency: $_" }
        $verified[$_].checkpoint_sha256
    })
    $inputHash = Get-WorkforceObjectHash ([ordered]@{
        context = $Context.normalized_arguments_sha256
        step = $Id
        executable_sources = Get-StepExecutableSourceHash $Id
        certification_git_sha = $(if ($Id -eq '600-certification') { $Context.git_sha } else { $null })
        dependencies = @($dependencyHashes | Sort-Object)
    })
    $checkpointPath = Join-Path $checkpointRoot "$Id.json"
    if ($Resume -and (Test-Path -LiteralPath $checkpointPath -PathType Leaf)) {
        $result = Test-WorkforceCheckpoint -Path $checkpointPath -Context $Context `
            -ExecutableInputSha256 $inputHash -OutputRoot $OutputRoot `
            -RequiredDependencyHashes $dependencyHashes
        if ($result.Valid) {
            $verified[$Id] = $result.Checkpoint
            $script:lastCheckpoint = $Id
            Write-Resume $Context
            return
        }
        Remove-CheckpointDownstream $Ordinal
    }
    & $Action
    $produced = @(& $Artifacts)
    $checkpoint = New-WorkforceCheckpoint -Context $Context -StepId $Id -StepLabel $Label `
        -StepOrdinal $Ordinal -RequiredBindingFields @(
            'model_sha256', 'runtime_sha256', 'role_contract_sha256',
            'shadow_profile_sha256', 'readiness_policy_sha256'
        ) -ExecutableInputSha256 $inputHash -OutputRoot $OutputRoot `
        -ProducedArtifactPaths $produced -PredecessorEvidenceSha256s $dependencyHashes
    Write-WorkforceCheckpoint -Path $checkpointPath -Checkpoint $checkpoint
    $verified[$Id] = Read-WorkforceCheckpoint $checkpointPath
    $script:lastCheckpoint = $Id
    Write-Resume $Context
}

function Get-OwnedResidualProcesses {
    $needle = $OutputRoot.ToLowerInvariant()
    return @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -and $_.CommandLine.ToLowerInvariant().Contains($needle)
        }
    )
}

function Save-Failure([hashtable]$Context, [System.Management.Automation.ErrorRecord]$Failure) {
    $script:failedStep = if ($lastCheckpoint) { "after-$lastCheckpoint" } else { 'preflight' }
    $latestError = Get-ChildItem -LiteralPath $logRoot -Filter '*.stderr.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    $residualProcessCount = @(Get-OwnedResidualProcesses).Count
    [void](Write-WorkforceFailureDiagnostic -DiagnosticRoot $diagnosticRoot -Context $Context `
        -FailedStepId $failedStep -ExitCode 1 -ExceptionClass $Failure.Exception.GetType().FullName `
        -LastVerifiedCheckpointHash $(if ($lastCheckpoint) { $verified[$lastCheckpoint].checkpoint_sha256 } else { $null }) `
        -StderrPath $(if ($latestError) { $latestError.FullName } else { $null }) `
        -CleanupVerified ($residualProcessCount -eq 0) -ResidualProcessCount $residualProcessCount `
        -ResidualCredentialCount 0 -ResidualActivationCount 0 -ResidualProfileCount 0 -ResidualLockCount 0)
    Write-Resume $Context
}

function Write-CompletionRuntimePerformance {
    $modelReportPath = Join-Path $OutputRoot 'completion-artifacts/performance-report.json'
    $modelReport = Get-Content -Raw -LiteralPath $modelReportPath | ConvertFrom-Json
    $stageLabels = [ordered]@{
        work_radar_intake = 'work900-actual-radar-intake'
        queue_scheduler = 'work900-actual-queue'
        autonomy_governance_and_qwen = 'work900-prepare-model'
        kernel_observe_plan_policy_activate_execute_verify_recover = 'work900-kernel-cases'
        kernel_evidence_reverification = 'work900-kernel-evidence-reverify'
        closure_episode_report_certification = 'work900-finalize'
    }
    $stageTimings = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $stageLabels.GetEnumerator()) {
        $step = @($steps | Where-Object label -eq $entry.Value | Select-Object -Last 1)
        if ($step.Count -eq 0) { continue }
        $stageTimings.Add([ordered]@{
            component_id = $entry.Key
            runner_step = $entry.Value
            duration_milliseconds = [uint64]$step[0].duration_milliseconds
        })
    }
    $outputBytes = [uint64]0
    foreach ($file in Get-ChildItem -LiteralPath $OutputRoot -File -Recurse) {
        $outputBytes = $outputBytes + [uint64]$file.Length
    }
    $report = [ordered]@{
        schema_version = 1
        measurement_scope = 'actual-runner-stages-and-isolated-model-process'
        component_resolution = 'KRN observation, policy, activation, action, verification, recovery, and closure are one aggregate runner stage; model process telemetry is per invocation.'
        stage_timings = @($stageTimings)
        provider_invocations = [uint32]$modelReport.provider_invocations
        provider_elapsed_milliseconds = @($modelReport.provider_elapsed_milliseconds)
        total_provider_elapsed_milliseconds = [uint64]$modelReport.total_provider_elapsed_milliseconds
        peak_model_process_memory_bytes = [uint64]$modelReport.peak_model_process_memory_bytes
        peak_model_job_memory_bytes = [uint64]$modelReport.peak_model_job_memory_bytes
        model_input_bytes = [uint64]$modelReport.model_input_bytes
        model_output_bytes = [uint64]$modelReport.model_output_bytes
        model_bytes_moved = [uint64]$modelReport.model_bytes_moved
        completion_output_bytes = $outputBytes
        report_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $report.GetEnumerator()) {
        if ($entry.Key -ne 'report_sha256') { $withoutHash[$entry.Key] = $entry.Value }
    }
    $report.report_sha256 = Get-WorkforceObjectHash $withoutHash
    Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'completion-artifacts/runtime-performance-report.json') -Value $report -Pretty
}

function Invoke-Completion {
    Assert-CompletionInputs
    $context = New-CompletionContext
    if ($Resume -and (Test-Path -LiteralPath $resumeManifestPath -PathType Leaf)) {
        $manifest = Read-WorkforceResumeManifest $resumeManifestPath
        if ($manifest.model_sha256 -ne $context.model_sha256 -or
            $manifest.runtime_sha256 -ne $context.runtime_sha256) {
            throw 'Resume manifest does not bind the current model/runtime inputs.'
        }
        $script:runId = $manifest.run_id
        $script:resumeCount = [int]$manifest.resume_count + 1
    }
    try {
        Invoke-CheckpointStep $context '001-predecessor-work800' 'verified WORK-800 predecessor' 1 @() {
            $finished = Get-Content -Raw -LiteralPath (Join-Path $Work800EvidenceRoot 'finished.json') | ConvertFrom-Json
            if (-not $finished.complete -or -not $finished.shadow_mode_evidence -or
                $finished.reference_role_readiness -ne 'eligible_for_work900_design' -or
                $finished.critical_error_count -ne 0) {
                throw 'WORK-800 predecessor is not a clean eligible Completion.'
            }
            $binding = [ordered]@{
                schema_version = 1
                finished_file_sha256 = Get-WorkforceFileHash (Join-Path $Work800EvidenceRoot 'finished.json')
                predecessor_finished_sha256 = $finished.finished_sha256
                readiness_assessment_sha256 = $finished.readiness_assessment_sha256
                model_sha256 = $context.model_sha256
                runtime_sha256 = $context.runtime_sha256
                verified = $true
            }
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'predecessor-binding.json') -Value $binding -Pretty
        } { Join-Path $OutputRoot 'predecessor-binding.json' }

        Invoke-CheckpointStep $context '005-workforce-input' 'actual Radar Intake Queue path' 5 @('001-predecessor-work800') {
            $intakeRoot = Join-Path $OutputRoot 'work-intake-e2e'
            $queueRoot = Join-Path $OutputRoot 'work-queue-e2e'
            foreach ($path in @($intakeRoot, $queueRoot)) {
                if (Test-Path -LiteralPath $path) { Remove-RunnerDirectory $path }
            }
            Invoke-NativeStep 'work900-actual-radar-intake' 'powershell' @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                (Join-Path $repoRoot 'scripts/workforce/run-work-radar-intake-v1.ps1'),
                '-Mode', 'GeneralOfficeE2E', '-OutputRoot', $intakeRoot
            )
            Invoke-NativeStep 'work900-actual-queue' 'powershell' @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                (Join-Path $repoRoot 'scripts/workforce/run-work-queue-scheduler-v1.ps1'),
                '-Mode', 'GeneralOfficeE2E', '-OutputRoot', $queueRoot
            )
        } {
            Join-Path $OutputRoot 'work-intake-e2e/finished.json'
            Join-Path $OutputRoot 'work-queue-e2e/finished.json'
        }

        Invoke-CheckpointStep $context '010-autonomy-governance' 'autonomy governance and model evidence' 10 @('005-workforce-input') {
            foreach ($path in @(
                    (Join-Path $OutputRoot 'governance'),
                    (Join-Path $OutputRoot 'autonomy-store-prepared'),
                    (Join-Path $OutputRoot 'model-process'),
                    (Join-Path $OutputRoot 'prepared-evidence.json')
                )) { if (Test-Path -LiteralPath $path) { Remove-RunnerDirectory $path } }
            Invoke-Cargo 'work900-prepare-model' @(
                'run', '--locked', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work900-autonomy-e2e', '--',
                'prepare-model', '--output-root', $OutputRoot, '--runtime', $Runtime, '--model', $Model,
                '--work800-root', $Work800EvidenceRoot, '--role-source', $roleSource
            )
        } {
            Join-Path $OutputRoot 'prepared-evidence.json'
            Join-Path $OutputRoot 'governance/role-contract.json'
            Join-Path $OutputRoot 'governance/deployment-approval.json'
            Join-Path $OutputRoot 'governance/enabled-state.json'
            Join-Path $OutputRoot 'autonomy-store-prepared/ledger.json'
        }

        Invoke-CheckpointStep $context '100-170-case-duty-cycle' 'eight Case KRN duty cycle' 100 @('010-autonomy-governance') {
            $kernelRoot = Join-Path $OutputRoot 'kernel-e2e'
            if ($Resume -and (Test-Path -LiteralPath (Join-Path $kernelRoot 'finished.json') -PathType Leaf)) {
                Invoke-Cargo 'work900-kernel-evidence-reverify' @(
                    'run', '--locked', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work900-autonomy-e2e', '--',
                    'verify-kernel', '--output-root', $OutputRoot, '--kernel-root', $kernelRoot
                )
            }
            else {
                if (Test-Path -LiteralPath $kernelRoot) { Remove-RunnerDirectory $kernelRoot }
                $priorBuildRoot = $env:D2I_KERNEL_E2E_BUILD_ROOT
                try {
                    $env:D2I_KERNEL_E2E_BUILD_ROOT = Join-Path $targetRoot 'd2i-work900-kernel-build'
                    Invoke-NativeStep 'work900-kernel-cases' 'powershell' @(
                        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                        (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'),
                        '-Mode', 'Work900', '-OutputRoot', $kernelRoot, '-RoleSource', $roleSource
                    )
                }
                finally { $env:D2I_KERNEL_E2E_BUILD_ROOT = $priorBuildRoot }
            }
        } {
            Join-Path $OutputRoot 'kernel-e2e/finished.json'
            foreach ($case in @(
                    'case-a-happy', 'case-b-already-correct', 'case-c-recovery',
                    'case-d-fresh-replan', 'case-e-clarification', 'case-e-resume',
                    'case-h-paused', 'case-h-resume'
                )) { Join-Path $OutputRoot "kernel-e2e/$case/result.json" }
        }

        Invoke-CheckpointStep $context '600-certification' 'final verification and certification' 600 @('100-170-case-duty-cycle') {
            foreach ($path in @(
                    (Join-Path $OutputRoot 'autonomy-store'),
                    (Join-Path $OutputRoot 'completion-artifacts'),
                    (Join-Path $OutputRoot 'finished.json')
                )) { if (Test-Path -LiteralPath $path) { Remove-RunnerDirectory $path } }
            Invoke-Cargo 'work900-finalize' @(
                'run', '--locked', '-q', '-p', 'd2i-desktop', '--bin', 'd2i-work900-autonomy-e2e', '--',
                'finalize', '--output-root', $OutputRoot, '--kernel-root', (Join-Path $OutputRoot 'kernel-e2e')
            )
            $finished = Get-Content -Raw -LiteralPath (Join-Path $OutputRoot 'finished.json') | ConvertFrom-Json
            if (-not $finished.complete -or -not $finished.autonomy_evidence -or
                -not $finished.human_by_exception_evidence -or -not $finished.track_w_completion_evidence -or
                $finished.critical_error_count -ne 0 -or $finished.routine_human_touches -ne 0 -or
                $finished.actual_model_invocations -lt 8 -or $finished.actual_krn_side_effect_actions -lt 8) {
                throw 'WORK-900 finished evidence does not satisfy the product gate.'
            }
            $residual = @(Get-OwnedResidualProcesses)
            if ($residual.Count -ne 0) {
                throw 'WORK-900 runner-owned processes remain after Completion.'
            }
            Write-CompletionRuntimePerformance
        } {
            Join-Path $OutputRoot 'finished.json'
            Join-Path $OutputRoot 'completion-artifacts/completion-report.json'
            Join-Path $OutputRoot 'completion-artifacts/replay-report.json'
            Join-Path $OutputRoot 'completion-artifacts/certification.json'
            Join-Path $OutputRoot 'completion-artifacts/performance-report.json'
            Join-Path $OutputRoot 'completion-artifacts/runtime-performance-report.json'
            Join-Path $OutputRoot 'autonomy-store/ledger.json'
        }
        Write-Resume $context
        Write-Output "D2I WORK-900 Completion complete: $OutputRoot"
    }
    catch {
        Save-Failure $context $_
        throw
    }
}

switch ($Mode) {
    'Contract' { Invoke-Core }
    'Schema' { Invoke-Schema }
    'Readiness' { Invoke-Core 'readiness_profile_and_signed_deployment_are_exactly_bound' }
    'Profile' { Invoke-Core 'readiness_profile_and_signed_deployment_are_exactly_bound' }
    'Deployment' { Invoke-Core 'readiness_profile_and_signed_deployment_are_exactly_bound' }
    'Role' { Invoke-Role }
    'Control' { Invoke-Core 'signed_control_is_monotonic_and_never_self_resumes' }
    'Eligibility' { Invoke-Core 'case_eligibility_is_deterministic_and_model_independent' }
    'Admission' { Invoke-Core 'case_admission' }
    'DutyCycle' { Invoke-Core 'completion_and_replay_gates_reject_partial_evidence' }
    'HumanException' { Invoke-Core 'human_exception' }
    'Health' { Invoke-Core 'any_critical_health_count_trips_fail_closed' }
    'Persistence' { Invoke-Persistence }
    'CrashRecovery' { Invoke-Persistence; Invoke-Core 'crash' }
    'GeneralOfficeE2E' {
        $kernelRoot = Join-Path $OutputRoot 'kernel-e2e-standalone'
        if (Test-Path -LiteralPath $kernelRoot) { Remove-RunnerDirectory $kernelRoot }
        Invoke-NativeStep 'work900-general-office-kernel' 'powershell' @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
            (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1'),
            '-Mode', 'Work900', '-OutputRoot', $kernelRoot, '-RoleSource', $roleSource
        )
    }
    'Negative' { Invoke-Core 'negative' }
    'Replay' { Invoke-Core 'completion_and_replay_gates_reject_partial_evidence' }
    'Regression' { Invoke-Core; Invoke-Persistence }
    'Certification' {
        Invoke-Cargo 'work900-certification-verify' @(
            'run', '--locked', '-q', '-p', 'd2i-limited-autonomy', '--bin', 'd2i-autonomy', '--',
            'certification', 'verify', '--input', (Join-Path $OutputRoot 'completion-artifacts/certification.json')
        )
    }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}

$summary = [ordered]@{
    schema_version = 1
    mode = $Mode.ToLowerInvariant()
    git_head = (& git -C $repoRoot rev-parse HEAD).Trim()
    step_count = $steps.Count
    steps = @($steps)
    completion_evidence = ($Mode -eq 'Completion')
    complete = $true
}
Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot ("$($Mode.ToLowerInvariant())-finished.json")) -Value $summary -Pretty
