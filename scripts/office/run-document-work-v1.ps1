[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'SemanticModel', 'HwpxRead', 'HwpxWrite',
        'HwpxConformance', 'DocxRead', 'DocxWrite', 'WordDiscovery', 'WordLive',
        'HancomDiscovery', 'HancomLicense', 'HancomLive', 'Text', 'Style', 'Table',
        'Image', 'Layout', 'Verification', 'Quality', 'CrossFormat', 'Persistence',
        'CrashRecovery', 'GeneralOfficeE2E', 'Negative', 'Replay', 'Regression',
        'Completion', 'All'
    )]
    [string]$Mode = 'All',

    [string]$Runtime,
    [string]$Model,
    [string]$Office100EvidenceRoot,
    [string]$OutputRoot,
    [string]$HancomLicenseEvidence,
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
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office200-document-work' }
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot = Join-Path $repoRoot $OutputRoot }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a child of the repository target directory.'
}

$stateRoot = Join-Path $OutputRoot '.runner'
$logRoot = Join-Path $stateRoot 'logs'
$checkpointRoot = Join-Path $stateRoot 'checkpoints'
$diagnosticRoot = Join-Path $stateRoot 'diagnostics'
$resumeManifestPath = Join-Path $stateRoot 'resume-manifest.json'
$executionRoot = Join-Path $OutputRoot 'execution'
$modelReportPath = Join-Path $OutputRoot 'model-report.json'
$runnerPath = $MyInvocation.MyCommand.Path
$verified = [ordered]@{}
$invalidated = [System.Collections.Generic.List[string]]::new()
$runId = 'office200-' + [Guid]::NewGuid().ToString('N')
$resumeCount = 0
$lastCheckpoint = $null
$failedStep = $null

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the OFFICE-200 output root: $resolved"
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

function Get-WithoutFieldHash([object]$Value, [string]$Field) {
    $without = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($property.Name -ne $Field) { $without[$property.Name] = $property.Value }
    }
    return Get-WorkforceObjectHash $without
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-WordExecutable {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\WINWORD.EXE'
    )) {
        if (Test-Path -LiteralPath $key) {
            $value = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($value) { $candidates.Add([string]$value) }
        }
    }
    $candidates.Add('C:\Program Files\Microsoft Office\Root\Office16\WINWORD.EXE')
    $candidates.Add('C:\Program Files (x86)\Microsoft Office\Root\Office16\WINWORD.EXE')
    $word = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $word) { throw 'Installed desktop Microsoft Word was not found.' }
    $word = (Resolve-Path -LiteralPath $word).Path
    $signature = Get-AuthenticodeSignature -LiteralPath $word
    if ($signature.Status -ne 'Valid') { throw 'WINWORD.EXE Authenticode signature is not valid.' }
    return $word
}

function Invoke-DocumentContracts {
    Invoke-Cargo 'office200-contracts' @('test', '--locked', '-p', 'd2i-document-capability', '--all-features')
}

function Invoke-Schema {
    Invoke-NativeStep 'office200-schema-drift' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-document-work-schemas.ps1'), '-Check'
    )
}

function Invoke-DocumentIntegration {
    Invoke-Cargo 'office200-desktop-document-work' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'document_work', '--all-features'
    )
    Invoke-Cargo 'office200-desktop-package-unit' @(
        'test', '--locked', '-p', 'd2i-desktop', '--lib', 'document_package', '--all-features'
    )
}

function Invoke-Regression {
    Invoke-Cargo 'office200-policy-admission' @('test', '--locked', '-p', 'd2i-policy-admission', '--all-features')
    Invoke-Cargo 'office200-trusted-execution' @('test', '--locked', '-p', 'd2i-trusted-action-execution', '--all-features')
    Invoke-Cargo 'office200-office100-regression' @('test', '--locked', '-p', 'd2i-office-capability', '--all-features')
}

function Invoke-All {
    Invoke-DocumentContracts
    Invoke-Schema
    Invoke-DocumentIntegration
    Invoke-Regression
}

function Assert-Predecessor {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence.'
    }
    if (-not $Office100EvidenceRoot -or -not (Test-Path -LiteralPath $Office100EvidenceRoot -PathType Container)) {
        throw 'Office100EvidenceRoot is required and must exist for Completion.'
    }
    $script:Office100EvidenceRoot = (Resolve-Path -LiteralPath $Office100EvidenceRoot).Path
    $finishedPath = Join-Path $Office100EvidenceRoot 'finished.json'
    $runnerFinishedPath = Join-Path $Office100EvidenceRoot 'runner-finished.json'
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $runnerFinished = Get-Content -Raw -LiteralPath $runnerFinishedPath -Encoding UTF8 | ConvertFrom-Json
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $runnerFinished.summary_sha256 -ne (Get-WithoutFieldHash $runnerFinished 'summary_sha256') -or
        $runnerFinished.execution_finished_sha256 -ne $finished.finished_sha256 -or
        -not $finished.complete -or -not $finished.office_capability_foundation_evidence -or
        -not $finished.office_workspace_evidence -or $finished.path_escape_count -ne 0 -or
        $finished.wrong_file_count -ne 0 -or $finished.original_overwrite_count -ne 0 -or
        $finished.network_access_count -ne 0 -or $finished.credential_leak_count -ne 0 -or
        $finished.false_completion_count -ne 0 -or $finished.critical_error_count -ne 0 -or
        $finished.residual_process_count -ne 0 -or $finished.residual_profile_count -ne 0 -or
        $finished.residual_lock_count -ne 0 -or $finished.residual_store_count -ne 0 -or
        -not $runnerFinished.complete -or $runnerFinished.residual_owned_processes -ne 0) {
        throw 'OFFICE-100 predecessor is not a sealed clean Completion.'
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
    if (-not $Runtime -or -not (Test-Path -LiteralPath $Runtime -PathType Leaf)) {
        throw 'Runtime is required and must identify llama-cli.exe.'
    }
    if (-not $Model -or -not (Test-Path -LiteralPath $Model -PathType Leaf)) {
        throw 'Model is required and must identify the pinned Qwen GGUF.'
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    $arguments = [ordered]@{
        mode = 'completion'
        runtime = Get-WorkforceFileHash $Runtime
        model = Get-WorkforceFileHash $Model
        predecessor = [IO.Path]::GetFullPath($Office100EvidenceRoot)
        hancom_license = if ($HancomLicenseEvidence) { Get-WorkforceFileHash $HancomLicenseEvidence } else { $null }
    }
    return @{
        source_tree_sha256 = $sourceTree
        git_sha = (& git -C $repoRoot rev-parse HEAD).Trim()
        runner_sha256 = Get-WorkforceFileHash $runnerPath
        mode = 'completion'
        normalized_arguments_sha256 = Get-WorkforceObjectHash $arguments
        model_sha256 = Get-WorkforceFileHash $Model
        runtime_sha256 = Get-WorkforceFileHash $Runtime
        role_contract_sha256 = Get-WorkforceSha256Text 'general-office-operations-employee'
        shadow_profile_sha256 = Get-WorkforceSha256Text 'not-applicable-office200'
        readiness_policy_sha256 = Get-WorkforceSha256Text 'office200-completion-gates-v1'
        cohort_sha256 = Get-WorkforceSha256Text 'office200-document-cases-a-p'
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
        $line.Contains('d2i-office200-') -or $line.Contains('office200-model-process')
    })
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated interactive deployment session for exact Word WFP policy installation; All remains non-elevated.'
    }
    if ($HancomLicenseEvidence) {
        throw 'Hancom license evidence was supplied, but the licensed Hancom Automation backend is not enabled in OFFICE-200 v1.'
    }
    $word = Resolve-WordExecutable
    $context = New-CompletionContext
    if ($Resume -and (Test-Path -LiteralPath $resumeManifestPath -PathType Leaf)) {
        $manifest = Read-WorkforceResumeManifest $resumeManifestPath
        $script:runId = $manifest.run_id
        $script:resumeCount = [int]$manifest.resume_count + 1
    }
    try {
        Invoke-CheckpointStep $context '001-predecessor-office100' 'verified OFFICE-100 predecessor' 1 @() {
            [void](Assert-Predecessor)
        } { Join-Path $OutputRoot 'predecessor-binding.json' }

        Invoke-CheckpointStep $context '010-deterministic-gates' 'contracts schemas attacks and regressions' 10 @('001-predecessor-office100') {
            Invoke-All
            $gate = [ordered]@{ schema_version = 1; all_deterministic_gates = $true; gate_sha256 = $null }
            $gate.gate_sha256 = Get-WithoutFieldHash ([pscustomobject]$gate) 'gate_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'deterministic-gates.json') -Value $gate -Pretty
        } { Join-Path $OutputRoot 'deterministic-gates.json' }

        Invoke-CheckpointStep $context '040-actual-qwen' 'actual pinned Qwen document planning' 40 @('010-deterministic-gates') {
            if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
            Invoke-Cargo 'office200-build-model-e2e' @(
                'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office200-model-e2e'
            )
            Invoke-NativeStep 'office200-actual-qwen' (Join-Path $targetRoot 'release/d2i-office200-model-e2e.exe') @(
                $Runtime, $Model, $modelReportPath
            )
        } { $modelReportPath }

        Invoke-CheckpointStep $context '100-document-e2e' 'HWPX DOCX and live Word verified document production' 100 @('040-actual-qwen') {
            if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
            Invoke-Cargo 'office200-build-document-cli' @(
                'build', '--locked', '--release', '-p', 'd2i-document-capability',
                '--bin', 'd2i-document'
            )
            Invoke-Cargo 'office200-build-e2e' @(
                'build', '--locked', '--release', '-p', 'd2i-desktop',
                '--bin', 'd2i-office200-document-worker',
                '--bin', 'd2i-office200-word-worker',
                '--bin', 'd2i-office200-completion-e2e'
            )
            $predecessor = Get-Content -Raw -LiteralPath (Join-Path $OutputRoot 'predecessor-binding.json') -Encoding UTF8 | ConvertFrom-Json
            Invoke-NativeStep 'office200-actual-document-e2e' (Join-Path $targetRoot 'release/d2i-office200-completion-e2e.exe') @(
                $executionRoot,
                (Join-Path $targetRoot 'release/d2i-office200-document-worker.exe'),
                (Join-Path $targetRoot 'release/d2i-office200-word-worker.exe'),
                $word,
                $modelReportPath,
                $predecessor.predecessor_finished_sha256,
                $context.source_tree_sha256
            )
        } {
            Join-Path $executionRoot 'finished.json'
            Join-Path $executionRoot 'certification.json'
            Join-Path $executionRoot 'certification-public-key.hex'
        }

        Invoke-CheckpointStep $context '600-certification' 'terminal completion and signature verification' 600 @('100-document-e2e') {
            $finishedPath = Join-Path $executionRoot 'finished.json'
            $certificationPath = Join-Path $executionRoot 'certification.json'
            $publicKeyPath = Join-Path $executionRoot 'certification-public-key.hex'
            Invoke-NativeStep 'office200-verify-completion' (Join-Path $targetRoot 'release/d2i-document.exe') @(
                'completion', 'verify', '--input', $finishedPath
            )
            Invoke-NativeStep 'office200-verify-certification' (Join-Path $targetRoot 'release/d2i-document.exe') @(
                'certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath
            )
            $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
            if (-not $finished.complete -or @(Get-OwnedResidualProcesses).Count -ne 0) {
                throw 'OFFICE-200 terminal completion or cleanup verification failed.'
            }
            Copy-Item -LiteralPath $finishedPath -Destination (Join-Path $OutputRoot 'finished.json') -Force
            $runnerSummary = [ordered]@{
                schema_version = 1
                complete = $true
                checkpoint_set_sha256 = Get-WorkforceCheckpointSetHash -Checkpoints @($verified.Values)
                execution_finished_sha256 = $finished.finished_sha256
                residual_owned_processes = 0
                next_task = 'D2I-OFFICE-300'
                summary_sha256 = $null
            }
            $runnerSummary.summary_sha256 = Get-WithoutFieldHash ([pscustomobject]$runnerSummary) 'summary_sha256'
            Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'runner-finished.json') -Value $runnerSummary -Pretty
        } {
            Join-Path $OutputRoot 'finished.json'
            Join-Path $OutputRoot 'runner-finished.json'
        }
        Write-Resume $context
        Write-Output "D2I OFFICE-200 Completion complete: $OutputRoot"
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
    'Contract' { Invoke-DocumentContracts }
    'Schema' { Invoke-Schema }
    'WordDiscovery' { Resolve-WordExecutable }
    'WordLive' {
        $word = Resolve-WordExecutable
        Invoke-Cargo 'office200-build-word-live' @(
            'build', '--locked', '--release', '-p', 'd2i-desktop',
            '--bin', 'd2i-office200-word-worker', '--bin', 'd2i-office200-document-e2e'
        )
        $wordLiveRoot = Join-Path $OutputRoot 'word-live'
        if (Test-Path -LiteralPath $wordLiveRoot) { Remove-OwnedDirectory $wordLiveRoot }
        Invoke-NativeStep 'office200-word-live' (Join-Path $targetRoot 'release/d2i-office200-document-e2e.exe') @(
            $wordLiveRoot, (Join-Path $targetRoot 'release/d2i-office200-word-worker.exe'), $word
        )
    }
    'HancomDiscovery' {
        Get-ChildItem 'C:\Program Files*\HNC\*\Hwp.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
    }
    'HancomLicense' {
        if (-not $HancomLicenseEvidence) { Write-Output 'requires_licensed_hancom_backend' }
        elseif (-not (Test-Path -LiteralPath $HancomLicenseEvidence -PathType Leaf)) { throw 'HancomLicenseEvidence does not exist.' }
        else { Write-Output 'License evidence supplied; live backend remains separately gated.' }
    }
    'HancomLive' { throw 'Licensed Hancom Automation backend is not enabled in OFFICE-200 v1.' }
    'Negative' { Invoke-DocumentContracts; Invoke-DocumentIntegration }
    'Regression' { Invoke-Regression }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
    default { Invoke-DocumentContracts; Invoke-DocumentIntegration }
}
