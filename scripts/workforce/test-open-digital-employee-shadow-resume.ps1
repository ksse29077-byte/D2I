[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$modulePath = Join-Path $PSScriptRoot 'lib/Work800Checkpoint.psm1'
Import-Module -Force $modulePath
$root = Join-Path $repoRoot "target/work800-resume-self-test-$PID"
$output = Join-Path $root 'output'
$checkpointRoot = Join-Path $output 'checkpoints'
$logRoot = Join-Path $output 'logs'
$passed = [System.Collections.Generic.List[string]]::new()

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Hash-Text([string]$Text) {
    return Get-Work800Sha256Text $Text
}

function New-Context([string]$Runner = 'runner-a', [string]$Model = 'model-a', [string]$Cohort = 'cohort-a', [string]$Readiness = 'readiness-a') {
    return @{
        source_tree_sha256 = Hash-Text 'source-a'
        git_sha = '0123456789abcdef0123456789abcdef01234567'
        runner_sha256 = Hash-Text $Runner
        mode = 'completion'
        normalized_arguments_sha256 = Hash-Text 'normalized-arguments'
        model_sha256 = Hash-Text $Model
        runtime_sha256 = Hash-Text 'runtime-a'
        role_contract_sha256 = Hash-Text 'role-a'
        shadow_profile_sha256 = Hash-Text 'profile-a'
        readiness_policy_sha256 = Hash-Text $Readiness
        cohort_sha256 = Hash-Text $Cohort
    }
}

function New-TestCheckpoint(
    [string]$Id,
    [int]$Ordinal,
    [hashtable]$Context,
    [string]$Artifact,
    [string[]]$Required,
    [bool]$Cleanup = $true,
    [string[]]$Dependencies = @()
) {
    $stdout = Join-Path $logRoot "$Id.stdout.log"
    $stderr = Join-Path $logRoot "$Id.stderr.log"
    [System.IO.File]::WriteAllText($stdout, "ok-$Id", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($stderr, '', [System.Text.UTF8Encoding]::new($false))
    $checkpoint = New-Work800Checkpoint `
        -Context $Context -StepId $Id -StepLabel $Id -StepOrdinal $Ordinal `
        -RequiredBindingFields $Required -ExecutableInputSha256 (Hash-Text "input-$Id") `
        -OutputRoot $output -ProducedArtifactPaths @($Artifact) `
        -StdoutPath $stdout -StderrPath $stderr -CleanupVerified $Cleanup `
        -PredecessorEvidenceSha256s $Dependencies
    $path = Join-Path $checkpointRoot "$Id.json"
    Write-Work800Checkpoint -Path $path -Checkpoint $checkpoint
    return $path
}

function Invoke-Test([string]$Name, [scriptblock]$Body) {
    & $Body
    $passed.Add($Name)
}

try {
    New-Item -ItemType Directory -Path $checkpointRoot, $logRoot -Force | Out-Null
    $artifact1 = Join-Path $output 'artifact-1.json'
    $artifact2 = Join-Path $output 'artifact-2.json'
    $artifact3 = Join-Path $output 'artifact-3.json'
    [System.IO.File]::WriteAllText($artifact1, '{"result":"one"}', [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($artifact2, '{"result":"two"}', [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText($artifact3, '{"result":"three"}', [System.Text.UTF8Encoding]::new($false))
    $base = New-Context
    $bindings = @('runner_sha256', 'normalized_arguments_sha256', 'model_sha256', 'runtime_sha256', 'cohort_sha256')

    Invoke-Test 'forced-step-3-failure-resumes-after-step-2' {
        $one = New-TestCheckpoint 'step-1' 1 $base $artifact1 $bindings
        $oneCheckpoint = Read-Work800Checkpoint $one
        $two = New-TestCheckpoint 'step-2' 2 $base $artifact2 $bindings $true @($oneCheckpoint.checkpoint_sha256)
        Assert-True (Test-Work800Checkpoint $one $base (Hash-Text 'input-step-1') $output).Valid 'step 1 was not reusable'
        Assert-True (Test-Work800Checkpoint $two $base (Hash-Text 'input-step-2') $output @($oneCheckpoint.checkpoint_sha256)).Valid 'step 2 was not reusable'
        Assert-True (-not (Test-Path (Join-Path $checkpointRoot 'step-3.json'))) 'failed step 3 acquired a checkpoint'
    }

    Invoke-Test 'artifact-tamper-invalidates-checkpoint' {
        $copy = Join-Path $output 'tampered-artifact.json'
        Copy-Item $artifact1 $copy
        $path = New-TestCheckpoint 'artifact-tamper' 10 $base $copy $bindings
        Add-Content -LiteralPath $copy -Value 'mutation'
        Assert-True (-not (Test-Work800Checkpoint $path $base (Hash-Text 'input-artifact-tamper') $output).Valid) 'tampered artifact was accepted'
    }

    Invoke-Test 'runner-hash-invalidates-downstream' {
        $path = New-TestCheckpoint 'runner-binding' 20 $base $artifact1 $bindings
        $changed = New-Context -Runner 'runner-b'
        Assert-True (-not (Test-Work800Checkpoint $path $changed (Hash-Text 'input-runner-binding') $output).Valid) 'runner mutation was accepted'
    }

    Invoke-Test 'model-hash-invalidates-model-backed-downstream' {
        $path = New-TestCheckpoint 'model-binding' 30 $base $artifact1 $bindings
        $changed = New-Context -Model 'model-b'
        Assert-True (-not (Test-Work800Checkpoint $path $changed (Hash-Text 'input-model-binding') $output).Valid) 'model mutation was accepted'
    }

    Invoke-Test 'cohort-change-invalidates-holdout' {
        $path = New-TestCheckpoint 'cohort-binding' 40 $base $artifact1 $bindings
        $changed = New-Context -Cohort 'cohort-b'
        Assert-True (-not (Test-Work800Checkpoint $path $changed (Hash-Text 'input-cohort-binding') $output).Valid) 'cohort mutation was accepted'
    }

    Invoke-Test 'readiness-only-change-reuses-raw-session' {
        $sessionBindings = @('runner_sha256', 'normalized_arguments_sha256', 'model_sha256', 'runtime_sha256', 'cohort_sha256', 'shadow_profile_sha256')
        $path = New-TestCheckpoint 'raw-session' 50 $base $artifact1 $sessionBindings
        $changed = New-Context -Readiness 'readiness-b'
        Assert-True (Test-Work800Checkpoint $path $changed (Hash-Text 'input-raw-session') $output).Valid 'readiness-only change invalidated raw session evidence'
    }

    Invoke-Test 'cleanup-failure-never-checkpoints-success' {
        $path = New-TestCheckpoint 'cleanup-failure' 60 $base $artifact1 $bindings $false
        Assert-True (-not (Test-Work800Checkpoint $path $base (Hash-Text 'input-cleanup-failure') $output).Valid) 'cleanup failure was reusable'
    }

    Invoke-Test 'human-action-crash-is-not-blindly-replayed' {
        $ambiguous = Join-Path $output 'human-action-ambiguous.json'
        [System.IO.File]::WriteAllText($ambiguous, '{"commitment_durable":true,"post_observation":null}', [System.Text.UTF8Encoding]::new($false))
        $checkpoint = Join-Path $checkpointRoot 'human-action.json'
        Assert-True (-not (Test-Path $checkpoint)) 'ambiguous human action acquired a success checkpoint'
        $state = Get-Content -Raw $ambiguous | ConvertFrom-Json
        Assert-True ($state.commitment_durable -and $null -eq $state.post_observation) 'human crash fixture is not ambiguous'
    }

    Invoke-Test 'failure-diagnostic-precedes-cleanup-and-redacts-secret' {
        $stdout = Join-Path $logRoot 'failed.stdout.log'
        $stderr = Join-Path $logRoot 'failed.stderr.log'
        [System.IO.File]::WriteAllText($stdout, 'bounded output', [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::WriteAllText($stderr, 'password=never-persist-this', [System.Text.UTF8Encoding]::new($false))
        $diagnostic = Write-Work800FailureDiagnostic `
            -DiagnosticRoot (Join-Path $output 'diagnostics') -Context $base `
            -FailedStepId 'failed-step' -ExitCode 17 -ExceptionClass 'InjectedFailure' `
            -StdoutPath $stdout -StderrPath $stderr -CleanupVerified $true `
            -ResidualProcessCount 0 -ResidualCredentialCount 0 `
            -ResidualActivationCount 0 -ResidualProfileCount 0 -ResidualLockCount 0
        Assert-True ($diagnostic.bounded_stderr_tail -eq '[REDACTED_BY_SECRET_SCANNER]') 'diagnostic secret was not redacted'
        Assert-True (Test-Path (Join-Path $output 'diagnostics/failed-step.stderr.tail.log')) 'stderr tail was not preserved'
    }

    Invoke-Test 'resume-finished-hash-verifies' {
        $finished = [ordered]@{ schema_version = 1; resumed = $true; fresh_step_count = 1; reused_checkpoint_count = 2; finished_sha256 = $null }
        $payload = [ordered]@{ schema_version = 1; resumed = $true; fresh_step_count = 1; reused_checkpoint_count = 2 }
        $finished.finished_sha256 = Get-Work800ObjectHash $payload
        Assert-True ($finished.finished_sha256 -eq (Get-Work800ObjectHash $payload)) 'resumed finished hash differs'
    }

    Invoke-Test 'fresh-and-resumed-normalized-semantics-match' {
        $fresh = [ordered]@{ cases = 60; readiness = 'eligible_for_work900_design'; critical_errors = 0 }
        $resumed = [ordered]@{ critical_errors = 0; readiness = 'eligible_for_work900_design'; cases = 60 }
        Assert-True ((Get-Work800ObjectHash $fresh) -eq (Get-Work800ObjectHash $resumed)) 'normalized semantic result differs'
    }

    Invoke-Test 'checkpoint-and-diagnostic-contain-no-sensitive-data' {
        $bad = New-Context
        $bad.role_contract_sha256 = 'password=prohibited'
        $rejected = $false
        try {
            $checkpoint = New-Work800Checkpoint `
                -Context $bad -StepId 'sensitive' -StepLabel 'sensitive' -StepOrdinal 99 `
                -RequiredBindingFields @('role_contract_sha256') `
                -ExecutableInputSha256 (Hash-Text 'input-sensitive') `
                -OutputRoot $output -ProducedArtifactPaths @($artifact1)
            Write-Work800Checkpoint -Path (Join-Path $checkpointRoot 'sensitive.json') -Checkpoint $checkpoint
        }
        catch { $rejected = $true }
        Assert-True $rejected 'sensitive checkpoint payload was written'
        $allDiagnostics = Get-ChildItem -LiteralPath (Join-Path $output 'diagnostics') -File | ForEach-Object { Get-Content -Raw $_.FullName }
        Assert-True (-not (($allDiagnostics -join "`n") -match '(?i)password=never-persist-this')) 'secret survived diagnostic scan'
    }

    [pscustomobject][ordered]@{
        schema_version = 1
        test_count = $passed.Count
        passed = @($passed)
        complete = ($passed.Count -eq 12)
    } | ConvertTo-Json -Depth 8
}
finally {
    if (-not $env:D2I_WORK800_KEEP_SELF_TEST -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
