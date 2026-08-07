[CmdletBinding()]
param(
    [ValidateSet(
        'Roadmap', 'SourceSurvey', 'SourceContracts', 'McpCatalog', 'CapabilityCandidate',
        'WorkspaceContract', 'Schema', 'RootBinding', 'Artifact', 'Observation',
        'Operations', 'Versioning', 'Persistence', 'CrashRecovery', 'GeneralOfficeE2E',
        'Negative', 'Replay', 'Regression', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Edge100EvidenceRoot,
    [string]$OutputRoot,
    [switch]$Resume,
    [switch]$Fresh,
    [switch]$ReuseVerifiedPredecessorEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Resume -and $Fresh) { throw '-Resume and -Fresh cannot be used together.' }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
$checkpointModule = Join-Path $repoRoot 'scripts/workforce/lib/WorkforceCheckpoint.psm1'
Import-Module -Force $checkpointModule
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office-capability-workspace' }
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot = Join-Path $repoRoot $OutputRoot }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a child of the repository target directory.'
}

$stateRoot = Join-Path $OutputRoot '.runner'
$logRoot = Join-Path $stateRoot 'logs'
$checkpointRoot = Join-Path $stateRoot 'checkpoints'
$resumeManifestPath = Join-Path $stateRoot 'resume-manifest.json'
$diagnosticRoot = Join-Path $stateRoot 'diagnostics'
$executionRoot = Join-Path $OutputRoot 'execution'
$sourceLock = Join-Path $repoRoot 'sources/office/office-capability-sources.lock.json'
$runnerPath = $MyInvocation.MyCommand.Path
$zeroHash = 'sha256:' + ('0' * 64)
$verified = [ordered]@{}
$invalidated = [System.Collections.Generic.List[string]]::new()
$runId = 'office100-' + [Guid]::NewGuid().ToString('N')
$resumeCount = 0
$lastCheckpoint = $null
$failedStep = $null

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the OFFICE-100 output root: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

if ($Fresh -and (Test-Path -LiteralPath $OutputRoot)) { Remove-OwnedDirectory $OutputRoot }
New-Item -ItemType Directory -Path $OutputRoot, $stateRoot, $logRoot, $checkpointRoot, $diagnosticRoot -Force | Out-Null

function Invoke-NativeStep([string]$Label, [string]$Command, [string[]]$Arguments) {
    $stdout = Join-Path $logRoot "$Label.stdout.log"
    $stderr = Join-Path $logRoot "$Label.stderr.log"
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
    if ($exitCode -ne 0) { throw "$Label failed with exit code $exitCode; see $stderr" }
}

function Invoke-Cargo([string]$Label, [string[]]$Arguments) {
    Invoke-NativeStep $Label 'cargo' $Arguments
}

function Invoke-SourceContracts([string]$Filter = '') {
    $arguments = @('test', '--locked', '-p', 'd2i-office-capability', '--all-features')
    if ($Filter) { $arguments += $Filter }
    Invoke-Cargo ('office100-source-' + $(if ($Filter) { $Filter } else { 'all' })) $arguments
}

function Invoke-Schema {
    Invoke-NativeStep 'office100-schema-drift' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-office-capability-schemas.ps1'), '-Check'
    )
    Invoke-SourceContracts 'all_fourteen_office_schemas_are_strict_draft_2020_12'
}

function Invoke-WorkspaceTests {
    Invoke-Cargo 'office100-desktop-integration' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'office_workspace', '--all-features'
    )
    Invoke-Cargo 'office100-desktop-store-worker' @(
        'test', '--locked', '-p', 'd2i-desktop', '--lib', 'office_workspace', '--all-features'
    )
}

function Invoke-Regression {
    Invoke-Cargo 'office100-policy-admission' @(
        'test', '--locked', '-p', 'd2i-policy-admission', '--all-features'
    )
    Invoke-Cargo 'office100-trusted-execution' @(
        'test', '--locked', '-p', 'd2i-trusted-action-execution', '--all-features'
    )
}

function Invoke-All {
    Invoke-SourceContracts
    Invoke-Schema
    Invoke-WorkspaceTests
    Invoke-Regression
}

function Get-WithoutFieldHash([object]$Value, [string]$Field) {
    $without = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -ne $Field) { $without[$property.Name] = $property.Value }
    }
    return Get-WorkforceObjectHash $without
}

function Assert-Predecessor {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence.'
    }
    if (-not $Edge100EvidenceRoot -or -not (Test-Path -LiteralPath $Edge100EvidenceRoot -PathType Container)) {
        throw 'Edge100EvidenceRoot is required and must exist for Completion.'
    }
    $script:Edge100EvidenceRoot = (Resolve-Path -LiteralPath $Edge100EvidenceRoot).Path
    $finishedPath = Join-Path $Edge100EvidenceRoot 'finished.json'
    $runnerFinishedPath = Join-Path $Edge100EvidenceRoot 'runner-finished.json'
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $runnerFinished = Get-Content -Raw -LiteralPath $runnerFinishedPath -Encoding UTF8 | ConvertFrom-Json
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $runnerFinished.summary_sha256 -ne (Get-WithoutFieldHash $runnerFinished 'summary_sha256') -or
        $runnerFinished.execution_finished_sha256 -ne $finished.finished_sha256 -or
        -not $finished.complete -or -not $finished.enterprise_api_plane_evidence -or
        -not $finished.track_x_edge100_evidence -or $finished.critical_errors -ne 0 -or
        $finished.credential_leak -ne 0 -or $finished.external_network -ne 0 -or
        $finished.residual_process -ne 0 -or $finished.residual_credential -ne 0 -or
        $finished.residual_network_policy -ne 0 -or $finished.residual_profile -ne 0 -or
        $finished.residual_store -ne 0 -or $finished.residual_lock -ne 0 -or
        -not $runnerFinished.complete -or $runnerFinished.residual_owned_processes -ne 0) {
        throw 'EDGE-100 predecessor is not a sealed clean Completion.'
    }
    $binding = [ordered]@{
        schema_version = 1
        predecessor_finished_sha256 = $finished.finished_sha256
        finished_file_sha256 = Get-WorkforceFileHash $finishedPath
        runner_finished_sha256 = $runnerFinished.summary_sha256
        verified = $true
    }
    Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'predecessor-binding.json') -Value $binding -Pretty
    return $finished.finished_sha256
}

function New-CompletionContext {
    if (-not $Edge100EvidenceRoot) { throw 'Edge100EvidenceRoot is required for Completion.' }
    $resolvedPredecessor = (Resolve-Path -LiteralPath $Edge100EvidenceRoot).Path
    $arguments = [ordered]@{
        mode = 'completion'
        predecessor = Get-WorkforceFileHash (Join-Path $resolvedPredecessor 'finished.json')
        source_lock = Get-WorkforceFileHash $sourceLock
    }
    return @{
        source_tree_sha256 = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
        git_sha = (& git -C $repoRoot rev-parse HEAD).Trim()
        runner_sha256 = Get-WorkforceFileHash $runnerPath
        mode = 'completion'
        normalized_arguments_sha256 = Get-WorkforceObjectHash $arguments
        model_sha256 = $zeroHash
        runtime_sha256 = $zeroHash
        role_contract_sha256 = Get-WorkforceSha256Text 'general-office-operations-employee'
        shadow_profile_sha256 = $zeroHash
        readiness_policy_sha256 = $zeroHash
        cohort_sha256 = Get-WorkforceSha256Text 'office100-workspace-cases-a-j'
    }
}

function Write-Resume([hashtable]$Context) {
    $manifest = New-WorkforceResumeManifest -Context $Context -RunId $runId `
        -LastVerifiedCheckpoint $lastCheckpoint `
        -VerifiedCheckpointHashes @($verified.Values | ForEach-Object checkpoint_sha256) `
        -InvalidatedCheckpointIds @($invalidated) -FailedStepId $failedStep -ResumeCount $resumeCount
    Write-WorkforceAtomicJson -Path $resumeManifestPath -Value $manifest -Pretty
}

function Invoke-CheckpointStep(
    [hashtable]$Context, [string]$Id, [string]$Label, [int]$Ordinal,
    [string[]]$Dependencies, [scriptblock]$Action, [scriptblock]$Artifacts
) {
    $dependencyHashes = @($Dependencies | ForEach-Object {
        if (-not $verified.Contains($_)) { throw "Unverified checkpoint dependency: $_" }
        $verified[$_].checkpoint_sha256
    })
    $inputHash = Get-WorkforceObjectHash ([ordered]@{
        context = $Context.normalized_arguments_sha256
        source_tree = $Context.source_tree_sha256
        step = $Id
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
        foreach ($file in Get-ChildItem -LiteralPath $checkpointRoot -Filter '*.json' -File) {
            $checkpoint = Read-WorkforceCheckpoint $file.FullName
            if ([int]$checkpoint.step_ordinal -ge $Ordinal) {
                $invalidated.Add([string]$checkpoint.step_id)
                Remove-Item -LiteralPath $file.FullName -Force
            }
        }
    }
    & $Action
    $checkpoint = New-WorkforceCheckpoint -Context $Context -StepId $Id -StepLabel $Label `
        -StepOrdinal $Ordinal -RequiredBindingFields @(
            'model_sha256', 'runtime_sha256', 'role_contract_sha256',
            'shadow_profile_sha256', 'readiness_policy_sha256'
        ) -ExecutableInputSha256 $inputHash -OutputRoot $OutputRoot `
        -ProducedArtifactPaths @(& $Artifacts) -PredecessorEvidenceSha256s $dependencyHashes
    Write-WorkforceCheckpoint -Path $checkpointPath -Checkpoint $checkpoint
    $verified[$Id] = Read-WorkforceCheckpoint $checkpointPath
    $script:lastCheckpoint = $Id
    Write-Resume $Context
}

function Get-OwnedResidualProcesses {
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $line = if ($_.CommandLine) { $_.CommandLine.ToLowerInvariant() } else { '' }
        $line.Contains('d2i-office100-workspace-e2e') -and $line.Contains('--file-worker')
    })
}

function Invoke-Completion {
    $context = New-CompletionContext
    if ($Resume -and (Test-Path -LiteralPath $resumeManifestPath -PathType Leaf)) {
        $manifest = Read-WorkforceResumeManifest $resumeManifestPath
        $script:runId = $manifest.run_id
        $script:resumeCount = [int]$manifest.resume_count + 1
    }
    try {
        Invoke-CheckpointStep $context '001-predecessor-edge100' 'verified EDGE-100 predecessor' 1 @() {
            [void](Assert-Predecessor)
        } { Join-Path $OutputRoot 'predecessor-binding.json' }

        Invoke-CheckpointStep $context '010-deterministic-gates' 'contracts schemas negatives recovery and regressions' 10 @('001-predecessor-edge100') {
            Invoke-All
            $gate = [ordered]@{ schema_version = 1; all_deterministic_gates = $true; gate_sha256 = $null }
            $gate.gate_sha256 = Get-WithoutFieldHash ([pscustomobject]$gate) 'gate_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'deterministic-gates.json') -Value $gate -Pretty
        } { Join-Path $OutputRoot 'deterministic-gates.json' }

        Invoke-CheckpointStep $context '100-workspace-e2e' 'actual synthetic workspace Cases A-J' 100 @('010-deterministic-gates') {
            if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
            Invoke-Cargo 'office100-build-e2e' @(
                'build', '--locked', '-p', 'd2i-desktop', '--bin', 'd2i-office100-workspace-e2e'
            )
            $predecessor = Get-Content -Raw -LiteralPath (Join-Path $OutputRoot 'predecessor-binding.json') -Encoding UTF8 | ConvertFrom-Json
            Invoke-NativeStep 'office100-actual-e2e' (Join-Path $targetRoot 'debug/d2i-office100-workspace-e2e.exe') @(
                '--output-root', $executionRoot,
                '--source-lock', $sourceLock,
                '--source-tree-sha256', $context.source_tree_sha256,
                '--predecessor-sha256', $predecessor.predecessor_finished_sha256
            )
        } {
            Join-Path $executionRoot 'finished.json'
            Join-Path $executionRoot 'certification.json'
            Join-Path $executionRoot 'workspace-e2e.json'
            Join-Path $executionRoot 'crash-recovery.json'
        }

        Invoke-CheckpointStep $context '600-certification' 'completion evidence and cleanup verified' 600 @('100-workspace-e2e') {
            $finishedPath = Join-Path $executionRoot 'finished.json'
            $summaryPath = Join-Path $executionRoot 'workspace-e2e.json'
            $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
            $summary = Get-Content -Raw -LiteralPath $summaryPath -Encoding UTF8 | ConvertFrom-Json
            Invoke-Cargo 'office100-verify-completion' @(
                'run', '--locked', '-q', '-p', 'd2i-office-capability', '--bin', 'd2i-office', '--',
                'completion', '--input', $finishedPath
            )
            if (-not $finished.complete -or -not $finished.office_capability_foundation_evidence -or
                -not $finished.office_workspace_evidence -or -not $finished.track_o_started -or
                $finished.workspace_cases -lt 10 -or $finished.routine_verified -lt 6 -or
                $finished.path_escape_count -ne 0 -or $finished.wrong_file_count -ne 0 -or
                $finished.original_overwrite_count -ne 0 -or $finished.duplicate_mutation_count -ne 0 -or
                $finished.stale_write_count -ne 0 -or $finished.reparse_escape_count -ne 0 -or
                $finished.symlink_escape_count -ne 0 -or
                $finished.raw_absolute_path_in_model_context_count -ne 0 -or
                $finished.arbitrary_command_count -ne 0 -or $finished.arbitrary_code_execution_count -ne 0 -or
                $finished.credential_leak_count -ne 0 -or $finished.network_access_count -ne 0 -or
                $finished.false_completion_count -ne 0 -or $finished.critical_error_count -ne 0 -or
                -not $summary.wrong_role_rejected -or -not $summary.wrong_case_rejected -or
                -not $summary.wrong_admission_rejected -or
                -not $summary.workspace_removed -or -not $summary.outside_fixture_removed -or
                @(Get-OwnedResidualProcesses).Count -ne 0) {
                throw 'OFFICE-100 Completion evidence failed terminal verification.'
            }
            Copy-Item -LiteralPath $finishedPath -Destination (Join-Path $OutputRoot 'finished.json') -Force
            $runnerSummary = [ordered]@{
                schema_version = 1
                complete = $true
                checkpoint_set_sha256 = Get-WorkforceCheckpointSetHash -Checkpoints @($verified.Values)
                execution_finished_sha256 = $finished.finished_sha256
                residual_owned_processes = 0
                next_task = 'D2I-OFFICE-200'
                summary_sha256 = $null
            }
            $runnerSummary.summary_sha256 = Get-WithoutFieldHash ([pscustomobject]$runnerSummary) 'summary_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'runner-finished.json') -Value $runnerSummary -Pretty
        } {
            Join-Path $OutputRoot 'finished.json'
            Join-Path $OutputRoot 'runner-finished.json'
        }
        Write-Resume $context
        Write-Output "D2I OFFICE-100 Completion complete: $OutputRoot"
    }
    catch {
        $script:failedStep = if ($lastCheckpoint) { "after-$lastCheckpoint" } else { 'preflight' }
        $residual = @(Get-OwnedResidualProcesses).Count
        [void](Write-WorkforceFailureDiagnostic -DiagnosticRoot $diagnosticRoot -Context $context `
            -FailedStepId $failedStep -ExitCode 1 -ExceptionClass $_.Exception.GetType().FullName `
            -LastVerifiedCheckpointHash $(if ($lastCheckpoint) { $verified[$lastCheckpoint].checkpoint_sha256 } else { $null }) `
            -CleanupVerified ($residual -eq 0) -ResidualProcessCount $residual `
            -ResidualCredentialCount 0 -ResidualActivationCount 0 -ResidualProfileCount 0 -ResidualLockCount 0)
        Write-Resume $context
        throw
    }
}

switch ($Mode) {
    'Roadmap' {
        $tasksPath = Join-Path $repoRoot 'order/TASKS.md'
        if ((Get-Content -Raw -LiteralPath $tasksPath) -notmatch 'D2I-OFFICE-200.*first active task') {
            throw 'Track O roadmap differs.'
        }
    }
    'SourceSurvey' { Invoke-SourceContracts 'source_lock_pins_official_and_public_sources_without_runtime_approval' }
    'SourceContracts' { Invoke-SourceContracts }
    'McpCatalog' { Invoke-SourceContracts 'source_lock_pins_official_and_public_sources_without_runtime_approval' }
    'CapabilityCandidate' { Invoke-SourceContracts 'catalog_candidate_and_artifact_contracts_are_exact' }
    'WorkspaceContract' { Invoke-WorkspaceTests }
    'Schema' { Invoke-Schema }
    'RootBinding' { Invoke-WorkspaceTests }
    'Artifact' { Invoke-WorkspaceTests }
    'Observation' { Invoke-WorkspaceTests }
    'Operations' { Invoke-WorkspaceTests }
    'Versioning' { Invoke-WorkspaceTests }
    'Persistence' { Invoke-WorkspaceTests }
    'CrashRecovery' { Invoke-WorkspaceTests }
    'GeneralOfficeE2E' { Invoke-WorkspaceTests }
    'Negative' { Invoke-SourceContracts; Invoke-WorkspaceTests }
    'Replay' { Invoke-SourceContracts 'replay_is_identical_for_128_scenarios_across_100_runs' }
    'Regression' { Invoke-Regression }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}
