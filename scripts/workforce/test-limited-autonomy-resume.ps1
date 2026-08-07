[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module -Force (Join-Path $PSScriptRoot 'lib/WorkforceCheckpoint.psm1')
$root = Join-Path $repoRoot "target/work900-resume-self-test-$PID"
$passed = 0
$failed = 0

function Assert-True([bool]$Condition, [string]$Label) {
    if (-not $Condition) {
        $script:failed++
        throw "WORK-900 resume self-test failed: $Label"
    }
    $script:passed++
}

function Context([string]$Source, [string]$Model = 'model-a') {
    $hash = { param($text) Get-WorkforceSha256Text $text }
    return @{
        source_tree_sha256 = & $hash $Source
        git_sha = (& git -C $repoRoot rev-parse HEAD).Trim()
        runner_sha256 = & $hash 'runner-v1'
        mode = 'completion'
        normalized_arguments_sha256 = & $hash 'arguments-v1'
        model_sha256 = & $hash $Model
        runtime_sha256 = & $hash 'runtime-a'
        role_contract_sha256 = & $hash 'role-1.4.0'
        shadow_profile_sha256 = & $hash 'autonomy-profile-v1'
        readiness_policy_sha256 = & $hash 'readiness-binding-v1'
        cohort_sha256 = & $hash 'canary-eight'
    }
}

try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    $artifact = Join-Path $root 'artifact.json'
    Write-WorkforceAtomicJson -Path $artifact -Value ([ordered]@{ schema_version = 1; status = 'verified' }) -Pretty
    $context = Context 'source-a'
    $inputHash = Get-WorkforceSha256Text 'step-input-a'
    $checkpoint = New-WorkforceCheckpoint -Context $context -StepId '010-autonomy-governance' `
        -StepLabel 'governance' -StepOrdinal 10 -RequiredBindingFields @('model_sha256') `
        -ExecutableInputSha256 $inputHash -OutputRoot $root -ProducedArtifactPaths @($artifact)
    $path = Join-Path $root 'checkpoint.json'
    Write-WorkforceCheckpoint -Path $path -Checkpoint $checkpoint

    $valid = Test-WorkforceCheckpoint -Path $path -Context $context `
        -ExecutableInputSha256 $inputHash -OutputRoot $root
    Assert-True $valid.Valid 'a valid checkpoint is reusable'
    Assert-True ($valid.Checkpoint.step_ordinal -eq 10) 'checkpoint ordinal is retained'

    $wrongSource = Test-WorkforceCheckpoint -Path $path -Context (Context 'source-b') `
        -ExecutableInputSha256 $inputHash -OutputRoot $root
    Assert-True $wrongSource.Valid 'unrelated source-tree drift does not invalidate bounded evidence'
    $wrongModel = Test-WorkforceCheckpoint -Path $path -Context (Context 'source-a' 'model-b') `
        -ExecutableInputSha256 $inputHash -OutputRoot $root
    Assert-True (-not $wrongModel.Valid) 'model change invalidates checkpoint and downstream autonomy'
    $wrongInput = Test-WorkforceCheckpoint -Path $path -Context $context `
        -ExecutableInputSha256 (Get-WorkforceSha256Text 'step-input-b') -OutputRoot $root
    Assert-True (-not $wrongInput.Valid) 'executable input change invalidates checkpoint'
    $wrongDependency = Test-WorkforceCheckpoint -Path $path -Context $context `
        -ExecutableInputSha256 $inputHash -OutputRoot $root `
        -RequiredDependencyHashes @((Get-WorkforceSha256Text 'missing-dependency'))
    Assert-True (-not $wrongDependency.Valid) 'dependency change invalidates downstream checkpoint'

    Add-Content -LiteralPath $artifact -Value 'tamper'
    $tamperedArtifact = Test-WorkforceCheckpoint -Path $path -Context $context `
        -ExecutableInputSha256 $inputHash -OutputRoot $root
    Assert-True (-not $tamperedArtifact.Valid) 'artifact tamper is rejected'
    Write-WorkforceAtomicJson -Path $artifact -Value ([ordered]@{ schema_version = 1; status = 'verified' }) -Pretty

    $manifest = New-WorkforceResumeManifest -Context $context -RunId 'work900-self-test' `
        -LastVerifiedCheckpoint '010-autonomy-governance' `
        -VerifiedCheckpointHashes @($checkpoint.checkpoint_sha256) -ResumeCount 1
    $manifestPath = Join-Path $root 'resume-manifest.json'
    Write-WorkforceAtomicJson -Path $manifestPath -Value $manifest -Pretty
    $readManifest = Read-WorkforceResumeManifest $manifestPath
    Assert-True ($readManifest.resume_count -eq 1) 'resume count is durable'
    Assert-True ($readManifest.last_verified_checkpoint -eq '010-autonomy-governance') 'last safe checkpoint is durable'

    $raw = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $raw.resume_count = 2
    $raw | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $manifestRejected = $false
    try { [void](Read-WorkforceResumeManifest $manifestPath) } catch { $manifestRejected = $true }
    Assert-True $manifestRejected 'resume manifest tamper is rejected'

    $diagnostics = Join-Path $root 'diagnostics'
    $failure = Write-WorkforceFailureDiagnostic -DiagnosticRoot $diagnostics -Context $context `
        -FailedStepId 'case-h-after-action' -ExitCode 1 -ExceptionClass 'SelfTestFailure' `
        -CleanupVerified $true -ResidualProcessCount 0 -ResidualCredentialCount 0 `
        -ResidualActivationCount 0 -ResidualProfileCount 0 -ResidualLockCount 0
    Assert-True ((Test-Path -LiteralPath (Join-Path $diagnostics 'failure.json')) -and $failure.failure_sha256) `
        'bounded failure diagnostics survive cleanup'

    Write-Output "WORK-900 resume self-tests passed: $passed"
}
finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}

if ($failed -ne 0) { exit 1 }
