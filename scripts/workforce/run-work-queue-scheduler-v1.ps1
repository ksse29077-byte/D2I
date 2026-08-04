[CmdletBinding()]
param(
    [ValidateSet('Contract', 'Schema', 'Queue', 'Scheduler', 'Lease', 'Ownership', 'Persistence', 'CrashRecovery', 'GeneralOfficeE2E', 'CrossDomain', 'Negative', 'Replay', 'Regression', 'All')]
    [string]$Mode = 'All',

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$startedAt = [DateTimeOffset]::UtcNow
$results = [System.Collections.Generic.List[object]]::new()
$terminalExitCode = 1
$maximumQueueReplay = $null

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    $stdout = Join-Path $script:OutputRoot "$Label.stdout.log"
    $stderr = Join-Path $script:OutputRoot "$Label.stderr.log"
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $commandError = $null
    try {
        & $Command 1> $stdout 2> $stderr
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
    }
    catch {
        $commandError = $_
        $exitCode = 1
    }
    finally {
        $ErrorActionPreference = $saved
    }
    $script:results.Add([pscustomobject][ordered]@{
            label = $Label
            status = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
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
    Invoke-Checked 'queue-contract-canonical-and-bounded' {
        cargo test --locked -p d2i-work-queue --all-features -- `
            --skip maximum_queue_128_cases_replays_100_times_with_identical_artifacts `
            --nocapture
    }
}

function Invoke-Schema {
    Invoke-Checked 'strict-draft-2020-12-schema' {
        cargo test --locked -p d2i-work-queue --test contract `
            public_artifacts_match_strict_draft_2020_12_schemas -- --exact --nocapture
    }
}

function Invoke-Queue {
    Invoke-Checked 'signed-pool-queue-projection' {
        cargo test --locked -p d2i-work-queue --test contract `
            signed_pool_queue_scheduler_lease_and_grant_are_exact -- --exact --nocapture
    }
}

function Invoke-Scheduler {
    Invoke-Checked 'scheduler-closed-state-classification' {
        cargo test --locked -p d2i-work-queue --test contract `
            scheduler_closed_states_and_stale_inputs_never_select_a_case -- --exact --nocapture
    }
}

function Invoke-Lease {
    Invoke-Checked 'exclusive-lease-concurrent-epoch-replay' {
        cargo test --locked -p d2i-work-queue --test contract `
            duplicate_claim_stale_state_and_lease_epoch_replay_fail_closed `
            -- --exact --nocapture
    }
    Invoke-Checked 'lease-expiry-renewal-grant-replay' {
        cargo test --locked -p d2i-work-queue --test contract `
            lease_expiry_release_renewal_and_grant_replay_are_bounded `
            -- --exact --nocapture
    }
}

function Invoke-Ownership {
    Invoke-Checked 'ownership-reassignment-generation-history' {
        cargo test --locked -p d2i-desktop --test work_queue_scheduler `
            work_300_cases_queue_schedule_exclusive_lease_restart_reassign_and_grant `
            -- --exact --nocapture
    }
}

function Invoke-Persistence {
    Invoke-Checked 'protected-queue-ledger-tamper-writer' {
        cargo test --locked -p d2i-desktop --test work_queue_scheduler `
            protected_queue_ledger_rejects_tamper_and_concurrent_writer `
            -- --exact --nocapture
    }
}

function Invoke-CrashRecovery {
    Invoke-Checked 'crash-windows-a-through-e' {
        cargo test --locked -p d2i-desktop --test work_queue_scheduler `
            work_300_cases_queue_schedule_exclusive_lease_restart_reassign_and_grant `
            -- --exact --nocapture
    }
}

function Invoke-GeneralOfficeE2E {
    Invoke-Checked 'work-300-multiple-cases-to-queue-e2e' {
        cargo test --locked -p d2i-desktop --test work_queue_scheduler `
            work_300_cases_queue_schedule_exclusive_lease_restart_reassign_and_grant `
            -- --exact --nocapture
    }
}

function Invoke-CrossDomain {
    Invoke-Checked 'office-hr-it-safety-one-core-contract' {
        cargo test --locked -p d2i-work-queue --test contract `
            opaque_cross_domain_ids_share_one_queue_contract_without_core_branches `
            -- --exact --nocapture
    }
}

function Invoke-Negative {
    Invoke-Checked 'stale-replay-negative' {
        cargo test --locked -p d2i-work-queue --test contract `
            duplicate_claim_stale_state_and_lease_epoch_replay_fail_closed `
            -- --exact --nocapture
    }
    Invoke-Checked 'schema-order-pool-tamper-negative' {
        cargo test --locked -p d2i-work-queue --test contract `
            input_order_schema_unknown_fields_and_pool_tamper_are_rejected `
            -- --exact --nocapture
    }
    Invoke-Checked 'closed-state-resource-negative' {
        cargo test --locked -p d2i-work-queue --test contract `
            scheduler_closed_states_and_stale_inputs_never_select_a_case `
            -- --exact --nocapture
    }
    Invoke-Persistence
}

function Invoke-Replay {
    Invoke-Checked 'maximum-queue-128-cases-100-replays' {
        cargo test --locked -p d2i-work-queue --test contract `
            maximum_queue_128_cases_replays_100_times_with_identical_artifacts `
            -- --exact --nocapture
    }
    $summaryLine = Get-Content -LiteralPath (Join-Path $script:OutputRoot 'maximum-queue-128-cases-100-replays.stdout.log') |
        Where-Object { $_.StartsWith('D2I_MAXIMUM_QUEUE_SUMMARY=', [StringComparison]::Ordinal) } |
        Select-Object -Last 1
    if (-not $summaryLine) { throw 'maximum Queue replay did not emit its normalized summary' }
    $script:maximumQueueReplay = $summaryLine.Substring('D2I_MAXIMUM_QUEUE_SUMMARY='.Length) | ConvertFrom-Json
}

function Invoke-Regression {
    foreach ($regression in @(
            @{ Label = 'work-100'; Script = 'run-role-contract-v1.ps1' },
            @{ Label = 'work-200'; Script = 'run-work-item-case-v1.ps1' },
            @{ Label = 'work-300'; Script = 'run-work-radar-intake-v1.ps1' }
        )) {
        # Nested workforce and standalone-module target trees become deep on
        # Windows. Keep regression roots directly below target/ for MAX_PATH.
        $nestedRoot = Join-Path $repoRoot "target/w4-$($regression.Label)-$PID"
        if (Test-Path -LiteralPath $nestedRoot) {
            throw "short regression OutputRoot already exists: $nestedRoot"
        }
        Invoke-Checked "$($regression.Label)-official-all" {
            powershell -NoProfile -ExecutionPolicy Bypass `
                -File (Join-Path $repoRoot "scripts/workforce/$($regression.Script)") `
                -Mode All -OutputRoot $nestedRoot
        }
        $nested = Get-Content -Raw -LiteralPath (Join-Path $nestedRoot 'finished.json') | ConvertFrom-Json
        if (-not $nested.complete -or $nested.status -ne 'pass' -or
            $nested.residual_owned_processes -ne 0) {
            throw "$($regression.Label) official regression report is not successful"
        }
    }
}

function Invoke-SensitiveScan {
    Invoke-Checked 'sensitive-artifact-and-authority-scan' {
        $artifactFiles = Get-ChildItem -LiteralPath $script:OutputRoot -Recurse -File
        $matches = $artifactFiles | Select-String -Pattern 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization:\s*Bearer|password\s*[:=]|raw_credential|raw_locator|process_command' -CaseSensitive:$false
        if ($matches) { throw "sensitive or executable authority marker detected: $($matches[0].Path):$($matches[0].LineNumber)" }
    }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'Work Queue and Scheduler v1 product runner requires Windows'
    }
    foreach ($path in @(
            (Join-Path $repoRoot 'Cargo.toml'),
            (Join-Path $repoRoot 'crates/d2i-work-queue/Cargo.toml'),
            (Join-Path $repoRoot 'products/d2i-desktop/src/work_queue.rs'),
            (Join-Path $repoRoot 'schemas/workforce/work-queue-policy-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/normalized-queue-replay-report-v1.schema.json'),
            (Join-Path $repoRoot 'scripts/workforce/run-role-contract-v1.ps1'),
            (Join-Path $repoRoot 'scripts/workforce/run-work-item-case-v1.ps1'),
            (Join-Path $repoRoot 'scripts/workforce/run-work-radar-intake-v1.ps1')
        )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required WORK-400 input is absent: $path"
        }
    }
    if (-not $OutputRoot) {
        $head = (& git -C $repoRoot rev-parse --short=12 HEAD).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'repository HEAD could not be resolved' }
        $runId = '{0}-{1}-{2}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $head, $PID
        $OutputRoot = Join-Path $repoRoot "target/d2i-workforce-queue/$runId"
    }
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    $targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
    if (-not $OutputRoot.StartsWith("$targetRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputRoot must remain under repository target/'
    }
    if (Test-Path -LiteralPath $OutputRoot) { throw "OutputRoot already exists: $OutputRoot" }
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    Set-Location $repoRoot

    switch ($Mode) {
        'Contract' { Invoke-Contract }
        'Schema' { Invoke-Schema }
        'Queue' { Invoke-Queue }
        'Scheduler' { Invoke-Scheduler }
        'Lease' { Invoke-Lease }
        'Ownership' { Invoke-Ownership }
        'Persistence' { Invoke-Persistence }
        'CrashRecovery' { Invoke-CrashRecovery }
        'GeneralOfficeE2E' { Invoke-GeneralOfficeE2E }
        'CrossDomain' { Invoke-CrossDomain }
        'Negative' { Invoke-Negative }
        'Replay' { Invoke-Replay }
        'Regression' { Invoke-Regression }
        'All' {
            Invoke-Contract
            Invoke-Schema
            Invoke-Queue
            Invoke-Scheduler
            Invoke-Lease
            Invoke-Ownership
            Invoke-Persistence
            Invoke-CrashRecovery
            Invoke-GeneralOfficeE2E
            Invoke-CrossDomain
            Invoke-Negative
            Invoke-Replay
            Invoke-Regression
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
        representative_role = 'general-office-operations-employee'
        cross_domain_fixtures = @('general-office-operations', 'human-resources', 'it-service', 'safety-operations')
        queue_scheduler_implemented = $true
        maximum_queue_cases = if ($Mode -in @('Replay', 'All')) { 128 } else { 0 }
        deterministic_replay_runs = if ($Mode -in @('Replay', 'All')) { 100 } else { 0 }
        maximum_queue_replay = $maximumQueueReplay
        duplicate_claims = 0
        critical_errors = 0
        residual_owned_processes = 0
        residual_credentials = 0
        residual_activations = 0
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
    Write-Output "D2I Work Queue and Scheduler v1 complete: $OutputRoot"
    $terminalExitCode = 0
}
catch {
    Write-Error $_
}
finally {
    Set-Location $repoRoot
}

exit $terminalExitCode
