[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'ConnectorPack', 'Approval', 'Endpoint', 'Credential',
        'NetworkPolicy', 'Observation', 'Pagination', 'Execution', 'Idempotency',
        'Concurrency', 'Verification', 'Recovery', 'RateLimit', 'Persistence',
        'CrashRecovery', 'WorkSource', 'GeneralE2E', 'CrossDomain', 'Negative',
        'Replay', 'Regression', 'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,
    [string]$Model,
    [string]$Work900EvidenceRoot,
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
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-edge-enterprise-api' }
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
$roleSource = Join-Path $repoRoot 'examples/workforce/general-office-operations-employee-enterprise-api-v1/role.yaml'
$runnerPath = $MyInvocation.MyCommand.Path
$zeroHash = 'sha256:' + ('0' * 64)
$verified = [ordered]@{}
$invalidated = [System.Collections.Generic.List[string]]::new()
$runId = 'edge100-' + [Guid]::NewGuid().ToString('N')
$resumeCount = 0
$lastCheckpoint = $null
$failedStep = $null

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the EDGE-100 output root: $resolved"
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

function Invoke-Contract([string]$Filter = '') {
    $arguments = @('test', '--locked', '-p', 'd2i-enterprise-api-plane', '--all-features')
    if ($Filter) { $arguments += $Filter }
    Invoke-Cargo ('edge100-contract-' + $(if ($Filter) { $Filter } else { 'all' })) $arguments
}

function Invoke-Schema {
    Invoke-NativeStep 'edge100-schema-drift' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/edge/generate-enterprise-api-schemas.ps1'), '-Check'
    )
    Invoke-Contract 'all_public_schemas_are_strict_and_compile'
}

function Invoke-DesktopIntegration {
    Invoke-Cargo 'edge100-desktop-process-integration' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'enterprise_api_plane', '--all-features'
    )
    Invoke-Cargo 'edge100-desktop-store' @(
        'test', '--locked', '-p', 'd2i-desktop', '--lib', 'enterprise_api', '--all-features'
    )
}

function Invoke-WorkSource {
    Invoke-Cargo 'edge100-eight-case-work-intake' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'enterprise_api_work_intake', '--all-features'
    )
    Invoke-Cargo 'edge100-signed-work-source-case' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'work_radar_intake',
        'general_office_signal_creates_exactly_one_persistent_case_and_commits_checkpoint', '--all-features'
    )
    Invoke-Cargo 'edge100-queue-regression' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'work_queue_scheduler', '--all-features'
    )
}

function Invoke-Regression {
    Invoke-Cargo 'edge100-policy-admission' @('test', '--locked', '-p', 'd2i-policy-admission', '--all-features')
    Invoke-Cargo 'edge100-trusted-execution' @('test', '--locked', '-p', 'd2i-trusted-action-execution', '--all-features')
    Invoke-WorkSource
}

function Invoke-All {
    Invoke-Contract
    Invoke-Schema
    Invoke-DesktopIntegration
    Invoke-Regression
}

function Assert-CompletionInputs {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence; WORK-900 evidence is verified, never silently promoted.'
    }
    foreach ($item in @(
            @('Runtime', $Runtime, 'Leaf'), @('Model', $Model, 'Leaf'),
            @('Work900EvidenceRoot', $Work900EvidenceRoot, 'Container'),
            @('RoleSource', $roleSource, 'Leaf')
        )) {
        if (-not $item[1] -or -not (Test-Path -LiteralPath $item[1] -PathType $item[2])) {
            throw "$($item[0]) is required and must exist for Completion."
        }
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
    $script:Work900EvidenceRoot = (Resolve-Path -LiteralPath $Work900EvidenceRoot).Path
}

function Get-WithoutFieldHash([object]$Value, [string]$Field) {
    $without = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -ne $Field) { $without[$property.Name] = $property.Value }
    }
    return Get-WorkforceObjectHash $without
}

function Assert-Predecessor {
    $finishedPath = Join-Path $Work900EvidenceRoot 'finished.json'
    $preparedPath = Join-Path $Work900EvidenceRoot 'prepared-evidence.json'
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $prepared = Get-Content -Raw -LiteralPath $preparedPath -Encoding UTF8 | ConvertFrom-Json
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $prepared.prepared_sha256 -ne (Get-WithoutFieldHash $prepared 'prepared_sha256')) {
        throw 'WORK-900 canonical predecessor hash verification failed.'
    }
    if (-not $finished.complete -or -not $finished.autonomy_evidence -or
        -not $finished.human_by_exception_evidence -or -not $finished.track_w_completion_evidence -or
        $finished.critical_error_count -ne 0 -or $finished.routine_human_touches -ne 0 -or
        $finished.residual_processes -ne 0 -or $finished.residual_profiles -ne 0 -or
        $finished.residual_locks -ne 0 -or $finished.residual_activations -ne 0 -or
        $finished.residual_credentials -ne 0) {
        throw 'WORK-900 predecessor is not a clean Track W Completion.'
    }
    if ($prepared.model_sha256 -ne (Get-WorkforceFileHash $Model) -or
        $prepared.runtime_sha256 -ne (Get-WorkforceFileHash $Runtime)) {
        throw 'WORK-900 predecessor model/runtime binding differs.'
    }
    $binding = [ordered]@{
        schema_version = 1
        predecessor_finished_sha256 = $finished.finished_sha256
        predecessor_prepared_sha256 = $prepared.prepared_sha256
        finished_file_sha256 = Get-WorkforceFileHash $finishedPath
        model_sha256 = $prepared.model_sha256
        runtime_sha256 = $prepared.runtime_sha256
        verified = $true
    }
    Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'predecessor-binding.json') -Value $binding -Pretty
}

function New-CompletionContext {
    $arguments = [ordered]@{
        mode = 'completion'
        model = Get-WorkforceFileHash $Model
        runtime = Get-WorkforceFileHash $Runtime
        predecessor = Get-WorkforceFileHash (Join-Path $Work900EvidenceRoot 'finished.json')
        role_source = Get-WorkforceFileHash $roleSource
    }
    return @{
        source_tree_sha256 = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
        git_sha = (& git -C $repoRoot rev-parse HEAD).Trim()
        runner_sha256 = Get-WorkforceFileHash $runnerPath
        mode = 'completion'
        normalized_arguments_sha256 = Get-WorkforceObjectHash $arguments
        model_sha256 = $arguments.model
        runtime_sha256 = $arguments.runtime
        role_contract_sha256 = Get-WorkforceSha256Text 'general-office-operations-employee:1.5.0'
        shadow_profile_sha256 = $zeroHash
        readiness_policy_sha256 = $zeroHash
        cohort_sha256 = Get-WorkforceSha256Text 'edge100-eight-case-api-duty-cycle-v1'
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

function Get-StepSourceHash([string]$Id) {
    $roots = switch ($Id) {
        '001-predecessor-work900' { @('Cargo.lock', 'scripts/edge/run-enterprise-api-plane-v1.ps1') }
        '010-deterministic-gates' { @(
                'Cargo.lock', 'Cargo.toml', 'crates/d2i-enterprise-api-plane',
                'crates/d2i-policy-admission', 'products/d2i-desktop/src/enterprise_api.rs',
                'products/d2i-desktop/tests/enterprise_api_plane.rs',
                'products/d2i-desktop/tests/enterprise_api_work_intake.rs',
                'schemas/execution-planes',
                'scripts/edge/generate-enterprise-api-schemas.ps1',
                'examples/workforce/general-office-operations-employee-enterprise-api-v1'
            ) }
        '100-actual-enterprise-e2e' { @(
                'Cargo.lock', 'Cargo.toml', 'crates/d2i-enterprise-api-plane',
                'products/d2i-desktop/src/enterprise_api.rs',
                'products/d2i-desktop/src/bin/d2i-edge100-enterprise-e2e.rs',
                'products/d2i-desktop/src/bin/d2i-edge100-enterprise-fixture.rs',
                'products/d2i-desktop/src/bin/d2i-edge100-connector-worker.rs',
                'examples/workforce/general-office-operations-employee-enterprise-api-v1'
            ) }
        '600-certification' { @(
                'crates/d2i-enterprise-api-plane', 'products/d2i-desktop/src/enterprise_api.rs',
                'products/d2i-desktop/src/bin/d2i-edge100-enterprise-e2e.rs',
                'scripts/edge/run-enterprise-api-plane-v1.ps1'
            ) }
        default { throw "Unknown EDGE-100 checkpoint source set: $Id" }
    }
    $paths = [System.Collections.Generic.List[string]]::new()
    $rootWithSeparator = $repoRoot.TrimEnd([char[]]@([char]92, [char]47)) + [IO.Path]::DirectorySeparatorChar
    $rootUri = [Uri]::new($rootWithSeparator)
    foreach ($relative in $roots) {
        $path = Join-Path $repoRoot $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) { $paths.Add($relative.Replace('\', '/')); continue }
        if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Checkpoint source root is missing: $relative" }
        foreach ($file in Get-ChildItem -LiteralPath $path -File -Recurse) {
            $paths.Add([Uri]::UnescapeDataString($rootUri.MakeRelativeUri([Uri]::new($file.FullName)).ToString()).Replace('\', '/'))
        }
    }
    return Get-WorkforcePathSetHash -Root $repoRoot -RelativePaths @($paths)
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
        step = $Id
        executable_sources = Get-StepSourceHash $Id
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
    $needles = @($OutputRoot.ToLowerInvariant(), 'd2i-edge100-enterprise-fixture', 'd2i-edge100-connector-worker')
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $line = if ($_.CommandLine) { $_.CommandLine.ToLowerInvariant() } else { '' }
        $line.Contains($needles[0]) -or $line.Contains($needles[1]) -or $line.Contains($needles[2])
    })
}

function Assert-ExistingExecution {
    $finishedPath = Join-Path $executionRoot 'finished.json'
    $certificationPath = Join-Path $executionRoot 'certification.json'
    if (-not (Test-Path -LiteralPath $finishedPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $certificationPath -PathType Leaf)) {
        throw 'Existing EDGE-100 execution evidence is incomplete.'
    }
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $certification = Get-Content -Raw -LiteralPath $certificationPath -Encoding UTF8 | ConvertFrom-Json
    $certificationPayload = [ordered]@{}
    foreach ($property in $certification.PSObject.Properties) {
        if ($property.Name -notin @('certification_sha256', 'signature_hex')) {
            $certificationPayload[$property.Name] = $property.Value
        }
    }
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $certification.certification_sha256 -ne (Get-WorkforceObjectHash $certificationPayload) -or
        $certification.completion_report_sha256 -ne $finished.finished_sha256 -or
        $finished.model_sha256 -ne (Get-WorkforceFileHash $Model) -or
        $finished.runtime_sha256 -ne (Get-WorkforceFileHash $Runtime) -or
        -not $finished.complete -or $finished.critical_errors -ne 0 -or
        $finished.residual_process -ne 0 -or $finished.residual_credential -ne 0 -or
        $finished.residual_network_policy -ne 0 -or $finished.residual_profile -ne 0 -or
        $finished.residual_store -ne 0 -or $finished.residual_lock -ne 0 -or
        @(Get-OwnedResidualProcesses).Count -ne 0) {
        throw 'Existing EDGE-100 execution evidence failed revalidation.'
    }
}

function Invoke-Completion {
    Assert-CompletionInputs
    $context = New-CompletionContext
    if ($Resume -and (Test-Path -LiteralPath $resumeManifestPath -PathType Leaf)) {
        $manifest = Read-WorkforceResumeManifest $resumeManifestPath
        if ($manifest.model_sha256 -ne $context.model_sha256 -or $manifest.runtime_sha256 -ne $context.runtime_sha256) {
            throw 'Resume manifest does not bind the current model/runtime inputs.'
        }
        $script:runId = $manifest.run_id
        $script:resumeCount = [int]$manifest.resume_count + 1
    }
    try {
        Invoke-CheckpointStep $context '001-predecessor-work900' 'verified WORK-900 predecessor' 1 @() {
            Assert-Predecessor
        } { Join-Path $OutputRoot 'predecessor-binding.json' }

        Invoke-CheckpointStep $context '010-deterministic-gates' 'contracts schemas process and Track W regressions' 10 @('001-predecessor-work900') {
            Invoke-All
            $gate = [ordered]@{ schema_version = 1; all_deterministic_gates = $true; gate_sha256 = $null }
            $gate.gate_sha256 = Get-WithoutFieldHash ([pscustomobject]$gate) 'gate_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'deterministic-gates.json') -Value $gate -Pretty
        } { Join-Path $OutputRoot 'deterministic-gates.json' }

        Invoke-CheckpointStep $context '100-actual-enterprise-e2e' 'actual Qwen and enterprise API duty cycle' 100 @('010-deterministic-gates') {
            if ($Resume -and (Test-Path -LiteralPath (Join-Path $executionRoot 'finished.json') -PathType Leaf)) {
                Assert-ExistingExecution
            }
            else {
                if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
                Invoke-Cargo 'edge100-build-e2e-binaries' @(
                    'build', '--locked', '-p', 'd2i-desktop',
                    '--bin', 'd2i-edge100-enterprise-e2e',
                    '--bin', 'd2i-edge100-enterprise-fixture',
                    '--bin', 'd2i-edge100-connector-worker'
                )
                Invoke-NativeStep 'edge100-actual-e2e' (Join-Path $targetRoot 'debug/d2i-edge100-enterprise-e2e.exe') @(
                    '--output-root', $executionRoot,
                    '--runtime', $Runtime,
                    '--model', $Model,
                    '--work900-root', $Work900EvidenceRoot,
                    '--role-source', $roleSource,
                    '--fixture', (Join-Path $targetRoot 'debug/d2i-edge100-enterprise-fixture.exe'),
                    '--worker', (Join-Path $targetRoot 'debug/d2i-edge100-connector-worker.exe')
                )
            }
        } {
            Join-Path $executionRoot 'finished.json'
            Join-Path $executionRoot 'certification.json'
            (Get-ChildItem -LiteralPath (Join-Path $executionRoot 'protected-enterprise-store/ledger') -File |
                Sort-Object Name | Select-Object -Last 1).FullName
        }

        Invoke-CheckpointStep $context '600-certification' 'completion evidence and cleanup verified' 600 @('100-actual-enterprise-e2e') {
            $finishedPath = Join-Path $executionRoot 'finished.json'
            $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
            if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
                -not $finished.complete -or -not $finished.enterprise_api_plane_evidence -or
                -not $finished.track_x_edge100_evidence -or $finished.total_cases -ne 8 -or
                $finished.verified_closures -ne 5 -or $finished.human_exceptions -ne 3 -or
                $finished.actual_model_invocations -lt 7 -or $finished.work_items -ne 8 -or
                $finished.persistent_cases -ne 8 -or $finished.queue_claims -ne 8 -or
                $finished.api_writes -lt 5 -or $finished.api_reads -le $finished.api_writes -or
                $finished.verified_writes -lt 4 -or $finished.blind_write_replays -ne 0 -or
                $finished.duplicate_server_mutations -ne 0 -or $finished.credential_leak -ne 0 -or
                $finished.external_network -ne 0 -or $finished.false_completion -ne 0 -or
                $finished.escalation_miss -ne 0 -or $finished.critical_errors -ne 0) {
                throw 'EDGE-100 finished evidence does not satisfy the Completion gate.'
            }
            if (@(Get-OwnedResidualProcesses).Count -ne 0) { throw 'EDGE-100 owned processes remain after Completion.' }
            Copy-Item -LiteralPath $finishedPath -Destination (Join-Path $OutputRoot 'finished.json') -Force
            $summary = [ordered]@{
                schema_version = 1
                complete = $true
                checkpoint_set_sha256 = Get-WorkforceCheckpointSetHash -Checkpoints @($verified.Values)
                execution_finished_sha256 = $finished.finished_sha256
                residual_owned_processes = 0
                summary_sha256 = $null
            }
            $summary.summary_sha256 = Get-WithoutFieldHash ([pscustomobject]$summary) 'summary_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'runner-finished.json') -Value $summary -Pretty
        } {
            Join-Path $OutputRoot 'finished.json'
            Join-Path $OutputRoot 'runner-finished.json'
        }
        Write-Resume $context
        Write-Output "D2I EDGE-100 Completion complete: $OutputRoot"
    }
    catch {
        $script:failedStep = if ($lastCheckpoint) { "after-$lastCheckpoint" } else { 'preflight' }
        $residualProcessCount = @(Get-OwnedResidualProcesses).Count
        [void](Write-WorkforceFailureDiagnostic -DiagnosticRoot $diagnosticRoot -Context $context `
            -FailedStepId $failedStep -ExitCode 1 -ExceptionClass $_.Exception.GetType().FullName `
            -LastVerifiedCheckpointHash $(if ($lastCheckpoint) { $verified[$lastCheckpoint].checkpoint_sha256 } else { $null }) `
            -CleanupVerified ($residualProcessCount -eq 0) `
            -ResidualProcessCount $residualProcessCount -ResidualCredentialCount 0 `
            -ResidualActivationCount 0 -ResidualProfileCount 0 -ResidualLockCount 0)
        Write-Resume $context
        throw
    }
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'ConnectorPack' { Invoke-Contract 'signed_connector_and_exact_operation_are_verified' }
    'Approval' { Invoke-Contract 'signed_connector_and_exact_operation_are_verified' }
    'Endpoint' { Invoke-Contract 'exact_destination_denies_ssrf_redirect_and_wrong_port' }
    'Credential' { Invoke-Contract 'strict_parser_rejects_duplicate_keys_floats_unknown_fields_and_secrets' }
    'NetworkPolicy' { Invoke-Contract 'exact_destination_denies_ssrf_redirect_and_wrong_port' }
    'Observation' { Invoke-DesktopIntegration }
    'Pagination' { Invoke-Contract 'signed_connector_and_exact_operation_are_verified' }
    'Execution' { Invoke-DesktopIntegration }
    'Idempotency' { Invoke-Contract 'activation_is_one_shot_and_exactly_bound' }
    'Concurrency' { Invoke-Contract 'recovery_is_bounded_and_never_blindly_replays_unknown_writes' }
    'Verification' { Invoke-DesktopIntegration }
    'Recovery' { Invoke-Contract 'recovery_is_bounded_and_never_blindly_replays_unknown_writes' }
    'RateLimit' { Invoke-Contract 'recovery_is_bounded_and_never_blindly_replays_unknown_writes' }
    'Persistence' { Invoke-DesktopIntegration }
    'CrashRecovery' { Invoke-DesktopIntegration }
    'WorkSource' { Invoke-WorkSource }
    'GeneralE2E' { Invoke-DesktopIntegration; Invoke-WorkSource }
    'CrossDomain' { Invoke-Contract 'opaque_system_families_share_one_deterministic_core_contract' }
    'Negative' { Invoke-Contract; Invoke-DesktopIntegration }
    'Replay' { Invoke-Contract 'deterministic_128_case_replay_matches_for_100_runs' }
    'Regression' { Invoke-Regression }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}
