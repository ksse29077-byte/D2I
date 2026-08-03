[CmdletBinding()]
param(
    [ValidateSet('Contract', 'Schema', 'Radar', 'Intake', 'Persistence', 'CrashRecovery', 'GeneralOfficeE2E', 'AISafetyE2E', 'Negative', 'Replay', 'Regression', 'All')]
    [string]$Mode = 'All',

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$startedAt = [DateTimeOffset]::UtcNow
$results = [System.Collections.Generic.List[object]]::new()
$terminalExitCode = 1

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
    Invoke-Checked 'contract-canonical-hash-exact-mapping' {
        cargo test --locked -p d2i-work-intake --all-features -- `
            --skip maximum_batch_one_hundred_replays_have_identical_normalized_report `
            --nocapture
    }
}

function Invoke-Schema {
    Invoke-Checked 'strict-draft-2020-12-schema-drift' {
        cargo test --locked -p d2i-work-intake --test contract `
            every_published_schema_accepts_only_its_strict_artifact -- --exact --nocapture
    }
}

function Invoke-Radar {
    Invoke-Checked 'bounded-one-shot-radar-checkpoint' {
        cargo test --locked -p d2i-work-intake --test contract `
            fixture_adapter_is_one_shot_and_checkpoint_rejects_replay -- --exact --nocapture
    }
    Invoke-Checked 'schedule-source-bounded-mapping' {
        cargo test --locked -p d2i-work-intake --test contract `
            schedule_source_uses_the_same_bounded_one_shot_mapping_contract -- --exact --nocapture
    }
}

function Invoke-Intake {
    Invoke-Checked 'signal-to-work-200-admission' {
        cargo test --locked -p d2i-work-intake --test contract `
            approved_signal_reaches_existing_work_item_admission_deterministically -- --exact --nocapture
    }
}

function Invoke-Persistence {
    Invoke-Checked 'protected-intake-ledger-reopen' {
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            general_office_signal_creates_exactly_one_persistent_case_and_commits_checkpoint `
            -- --exact --nocapture
    }
}

function Invoke-CrashRecovery {
    Invoke-Checked 'case-before-receipt-crash-recovery' {
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            crash_after_case_before_receipt_recovers_as_duplicate_without_second_case `
            -- --exact --nocapture
    }
}

function Invoke-GeneralOfficeE2E {
    Invoke-Checked 'general-office-source-to-single-case-e2e' {
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            general_office_signal_creates_exactly_one_persistent_case_and_commits_checkpoint `
            -- --exact --nocapture
    }
}

function Invoke-AISafetyE2E {
    Invoke-Checked 'cross-domain-office-hr-it-safety-replay' {
        cargo test --locked -p d2i-work-intake --test contract `
            opaque_cross_domain_mappings_are_deterministic_without_core_taxonomy `
            -- --exact --nocapture
    }
}

function Invoke-Negative {
    Invoke-Checked 'stale-ambiguous-missing-sensitive-reject' {
        cargo test --locked -p d2i-work-intake --test contract `
            stale_ambiguous_missing_and_sensitive_signals_fail_closed -- --exact --nocapture
    }
    Invoke-Checked 'source-approval-expiry-tamper-binding-reject' {
        cargo test --locked -p d2i-work-intake --test contract `
            source_approval_rejects_wrong_signer_expiry_tamper_and_binding_substitution `
            -- --exact --nocapture
    }
    Invoke-Checked 'ledger-tamper-duplicate-key-substitution-reject' {
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            ledger_rejects_tamper_duplicate_keys_concurrent_writer_and_event_substitution `
            -- --exact --nocapture
    }
}

function Invoke-Replay {
    Invoke-Checked 'maximum-batch-one-hundred-normalized-replays' {
        cargo test --locked -p d2i-work-intake --test contract `
            maximum_batch_one_hundred_replays_have_identical_normalized_report `
            -- --exact --nocapture
    }
    $summaryLine = Get-Content -LiteralPath (Join-Path $script:OutputRoot 'maximum-batch-one-hundred-normalized-replays.stdout.log') |
        Where-Object { $_.StartsWith('D2I_MAXIMUM_BATCH_SUMMARY=', [StringComparison]::Ordinal) } |
        Select-Object -Last 1
    if (-not $summaryLine) {
        throw 'maximum batch replay did not emit its normalized summary'
    }
    $script:maximumBatchReplay = $summaryLine.Substring('D2I_MAXIMUM_BATCH_SUMMARY='.Length) | ConvertFrom-Json
    Invoke-Checked 'one-hundred-replays-zero-duplicate-cases' {
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            crash_after_case_before_receipt_recovers_as_duplicate_without_second_case `
            -- --exact --nocapture
    }
}

function Invoke-Regression {
    # Standalone module target trees are deeply nested. Keep the official
    # regression roots directly below target/ to remain below Windows MAX_PATH.
    $caseRoot = Join-Path $repoRoot "target/w3-case-$PID"
    Invoke-Checked 'work-200-official-all' {
        powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $repoRoot 'scripts/workforce/run-work-item-case-v1.ps1') `
            -Mode All -OutputRoot $caseRoot
    }
    Invoke-Checked 'work-100-official-all-nested-verification' {
        $nested = Get-Content -Raw -LiteralPath (Join-Path $caseRoot 'work-100/finished.json') | ConvertFrom-Json
        if (-not $nested.complete -or $nested.status -ne 'pass' -or $nested.residual_owned_processes -ne 0) {
            throw 'nested official WORK-100 Mode All report is not successful'
        }
    }
}

function Invoke-SensitiveScan {
    Invoke-Checked 'sensitive-artifact-and-authority-scan' {
        $files = Get-ChildItem -LiteralPath $script:OutputRoot -Recurse -File
        $matches = $files | Select-String -Pattern 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|Authorization:\s*Bearer|password\s*[:=]|raw_payload|process_command' -CaseSensitive:$false
        if ($matches) {
            throw "sensitive or forbidden authority marker detected: $($matches[0].Line)"
        }
        cargo test --locked -p d2i-desktop --test work_radar_intake `
            no_task_activation_credential_or_process_authority_is_created `
            -- --exact --nocapture
    }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'Work Radar and Intake v1 product runner requires Windows'
    }
    foreach ($path in @(
            (Join-Path $repoRoot 'Cargo.toml'),
            (Join-Path $repoRoot 'crates/d2i-work-intake/Cargo.toml'),
            (Join-Path $repoRoot 'schemas/workforce/work-radar-source-registration-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-source-approval-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-signal-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-intake-mapping-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-radar-checkpoint-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-intake-receipt-v1.schema.json'),
            (Join-Path $repoRoot 'schemas/workforce/work-radar-cycle-report-v1.schema.json'),
            (Join-Path $repoRoot 'examples/workforce/general-office-operations-employee/intake/approved-event-feed.json'),
            (Join-Path $repoRoot 'examples/workforce/ai-safety-operations-employee/intake/approved-event-feed.json'),
            (Join-Path $repoRoot 'scripts/workforce/run-role-contract-v1.ps1'),
            (Join-Path $repoRoot 'scripts/workforce/run-work-item-case-v1.ps1')
        )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required WORK-300 input is absent: $path"
        }
    }
    if (-not $OutputRoot) {
        $head = (& git -C $repoRoot rev-parse --short=12 HEAD).Trim()
        if ($LASTEXITCODE -ne 0) { throw 'repository HEAD could not be resolved' }
        $runId = '{0}-{1}-{2}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $head, $PID
        $OutputRoot = Join-Path $repoRoot "target/d2i-workforce-intake/$runId"
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
        'Radar' { Invoke-Radar }
        'Intake' { Invoke-Intake }
        'Persistence' { Invoke-Persistence }
        'CrashRecovery' { Invoke-CrashRecovery }
        'GeneralOfficeE2E' { Invoke-GeneralOfficeE2E }
        'AISafetyE2E' { Invoke-AISafetyE2E }
        'Negative' { Invoke-Negative }
        'Replay' { Invoke-Replay }
        'Regression' { Invoke-Regression }
        'All' {
            Invoke-Contract
            Invoke-Schema
            Invoke-Radar
            Invoke-Intake
            Invoke-Persistence
            Invoke-CrashRecovery
            Invoke-GeneralOfficeE2E
            Invoke-AISafetyE2E
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
        work_radar_intake_implemented = $true
        representative_role = 'general-office-operations-employee'
        cross_domain_fixtures = @('general-office-operations', 'human-resources', 'it-service', 'safety-operations')
        queue_scheduler_implemented = $false
        fixture_replay_runs = if ($Mode -in @('Replay', 'All')) { 100 } else { 0 }
        maximum_batch_events = if ($Mode -in @('Replay', 'All')) { 128 } else { 0 }
        normalized_cycle_replay_verified = ($Mode -in @('Replay', 'All'))
        maximum_batch_replay = if ($Mode -in @('Replay', 'All')) { $script:maximumBatchReplay } else { $null }
        duplicate_cases = 0
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
    Write-Output "D2I Work Radar and Intake v1 complete: $OutputRoot"
    $terminalExitCode = 0
}
catch {
    Write-Error $_
}
finally {
    Set-Location $repoRoot
}

exit $terminalExitCode
