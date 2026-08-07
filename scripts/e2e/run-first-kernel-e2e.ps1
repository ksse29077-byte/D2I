[CmdletBinding()]
param(
    [ValidateSet('Happy', 'AlreadyCorrect', 'Adaptive', 'Work900', 'Recovery', 'Unsafe', 'Clarification', 'PausedAfterSet', 'All')]
    [string]$Mode = 'All',

    [string]$OutputRoot,

    [string]$RoleSource
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$previousTargetDir = $env:CARGO_TARGET_DIR
$terminalExitCode = 13

function ConvertTo-ComparableFullPath([string]$Path) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($fullPath.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
        return '\\' + $fullPath.Substring(8)
    }
    if ($fullPath.StartsWith('\\?\', [StringComparison]::OrdinalIgnoreCase)) {
        return $fullPath.Substring(4)
    }
    return $fullPath
}

function Get-Sha256([string]$Path) {
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-CargoBuild(
    [string]$Label,
    [string]$TargetDirectory,
    [string[]]$Arguments,
    [string]$LogDirectory
) {
    New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
    $stdoutPath = Join-Path $LogDirectory "$Label.stdout.log"
    $stderrPath = Join-Path $LogDirectory "$Label.stderr.log"
    $env:CARGO_TARGET_DIR = $TargetDirectory
    $savedErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & cargo @Arguments 1> $stdoutPath 2> $stderrPath
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "$Label build failed with exit code $exitCode; see $stderrPath"
    }
}

function Assert-ScenarioResult(
    [string]$ResultPath,
    [string]$ExpectedMode,
    [string]$ExpectedOutcome
) {
    if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) {
        throw "scenario did not produce result.json: $ExpectedMode"
    }
    $result = Get-Content -Raw -LiteralPath $ResultPath | ConvertFrom-Json
    if ($result.schema_version -ne 1 -or
        $result.mode -ne $ExpectedMode -or
        $result.expected_outcome -ne $ExpectedOutcome -or
        $result.actual_outcome -ne $ExpectedOutcome) {
        throw "scenario result contract differs: $ExpectedMode"
    }
    $cleanup = $result.cleanup
    if ($cleanup.module_host_residuals -ne 0 -or
        $cleanup.worker_residuals -ne 0 -or
        $cleanup.app_process_residuals -ne 0 -or
        $cleanup.activation_residuals -ne 0 -or
        $cleanup.payload_residuals -ne 0 -or
        -not $cleanup.temporary_root_removed) {
        $script:terminalExitCode = 14
        throw "scenario cleanup contract failed: $ExpectedMode"
    }
    return $result
}

function Invoke-Scenario(
    [string]$ScenarioLabel,
    [string]$ScenarioMode,
    [int]$ExpectedExitCode,
    [string]$ExpectedOutcome,
    [string]$Runner,
    [string]$Worker,
    [hashtable]$ModuleHosts,
    [hashtable]$ModuleHashes,
    [string]$RunRoot
) {
    $scenarioRoot = Join-Path $RunRoot $ScenarioLabel
    New-Item -ItemType Directory -Path $scenarioRoot -Force | Out-Null
    $stdoutPath = Join-Path $scenarioRoot 'runner.stdout.log'
    $stderrPath = Join-Path $scenarioRoot 'runner.stderr.log'
    $arguments = @(
        '--mode', $ScenarioMode,
        '--output-root', $scenarioRoot,
        '--worker-executable', $Worker,
        '--fixture-script', (Join-Path $repoRoot 'products/d2i-desktop/tests/support/kernel_e2e_name_save_fixture.ps1'),
        '--application-pack', (Join-Path $repoRoot 'examples/kernel-e2e/name-save/application-pack.json'),
        '--goal-module-root', (Join-Path $repoRoot 'modules/goal-compiler'),
        '--goal-host', $ModuleHosts['goal-compiler'],
        '--goal-host-sha256', $ModuleHashes['goal-compiler'],
        '--grounder-module-root', (Join-Path $repoRoot 'modules/element-grounder'),
        '--grounder-host', $ModuleHosts['element-grounder'],
        '--grounder-host-sha256', $ModuleHashes['element-grounder'],
        '--ranker-module-root', (Join-Path $repoRoot 'modules/plan-ranker'),
        '--ranker-host', $ModuleHosts['plan-ranker'],
        '--ranker-host-sha256', $ModuleHashes['plan-ranker']
    )
    if ($RoleSource) {
        $arguments += @('--role-source', $RoleSource)
    }
    & $Runner @arguments 1> $stdoutPath 2> $stderrPath
    $actualExitCode = $LASTEXITCODE
    if ($actualExitCode -ne $ExpectedExitCode) {
        throw "$ScenarioLabel returned $actualExitCode; expected $ExpectedExitCode; see $stderrPath"
    }
    $result = Assert-ScenarioResult `
        -ResultPath (Join-Path $scenarioRoot 'result.json') `
        -ExpectedMode $ScenarioMode `
        -ExpectedOutcome $ExpectedOutcome
    if ($RoleSource -and (-not $result.role_context_sha256 -or -not $result.role_ledger_chain_head)) {
        throw "role-bound scenario omitted Role context or ledger head: $ScenarioLabel"
    }
    return [pscustomobject][ordered]@{
        label = $ScenarioLabel
        mode = $ScenarioMode
        exit_code = $actualExitCode
        expected_outcome = $ExpectedOutcome
        result_path = "$ScenarioLabel/result.json"
        normalized_replay_sha256 = $result.normalized_replay_sha256
        result_sha256 = $result.result_sha256
        actual_module_invocations = $result.actual_module_invocations
        mutation_count = $result.mutation_count
        recovery_cycle_count = $result.recovery_cycle_count
    }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'D2I KRN-500 E2E requires Windows'
    }
    foreach ($path in @(
            (Join-Path $repoRoot 'Cargo.toml'),
            (Join-Path $repoRoot 'products/d2i-desktop/tests/support/kernel_e2e_name_save_fixture.ps1'),
            (Join-Path $repoRoot 'examples/kernel-e2e/name-save/application-pack.json'),
            (Join-Path $repoRoot 'modules/goal-compiler/Cargo.toml'),
            (Join-Path $repoRoot 'modules/element-grounder/Cargo.toml'),
            (Join-Path $repoRoot 'modules/plan-ranker/Cargo.toml')
        )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required KRN-500 input is absent: $path"
        }
    }
    if ($RoleSource) {
        $RoleSource = [IO.Path]::GetFullPath($RoleSource)
        if (-not (Test-Path -LiteralPath $RoleSource -PathType Leaf)) {
            throw "RoleSource is absent: $RoleSource"
        }
    }
    $cargo = Get-Command cargo -ErrorAction Stop
    if (-not $cargo.Source) {
        throw 'cargo executable could not be resolved'
    }
    $gitHead = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'repository HEAD could not be resolved'
    }
    if (-not $OutputRoot) {
        $shortHead = $gitHead.Substring(0, 12)
        $runId = '{0}-{1}-{2}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $shortHead, $PID
        $OutputRoot = Join-Path $repoRoot "target/d2i-e2e/$runId"
    }
    $runRoot = ConvertTo-ComparableFullPath $OutputRoot
    $targetRoot = ConvertTo-ComparableFullPath (Join-Path $repoRoot 'target')
    if (-not $runRoot.StartsWith("$targetRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputRoot must remain under repository target/'
    }
    if (Test-Path -LiteralPath $runRoot) {
        throw "OutputRoot already exists: $runRoot"
    }
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    $logRoot = Join-Path $runRoot 'build-logs'
    $buildRoot = if ($env:D2I_KERNEL_E2E_BUILD_ROOT) {
        $candidate = ConvertTo-ComparableFullPath $env:D2I_KERNEL_E2E_BUILD_ROOT
        if (-not $candidate.StartsWith("$targetRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
            throw 'D2I_KERNEL_E2E_BUILD_ROOT must remain under repository target/'
        }
        $candidate
    }
    else {
        Join-Path $runRoot 'build'
    }
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

    $rootTarget = Join-Path $buildRoot 'root'
    Invoke-CargoBuild 'desktop' $rootTarget @(
        'build', '--locked', '--manifest-path', (Join-Path $repoRoot 'Cargo.toml'),
        '-p', 'd2i-desktop', '--bin', 'd2i-desktop', '--bin', 'd2i-kernel-e2e'
    ) $logRoot

    $moduleHosts = @{}
    foreach ($moduleId in @('goal-compiler', 'element-grounder', 'plan-ranker')) {
        $moduleTarget = Join-Path $buildRoot "modules/$moduleId"
        Invoke-CargoBuild "module-$moduleId" $moduleTarget @(
            'build', '--locked', '--manifest-path', (Join-Path $repoRoot "modules/$moduleId/Cargo.toml"),
            '--bin', 'e2e-host'
        ) $logRoot
        $moduleHosts[$moduleId] = Join-Path $moduleTarget 'debug/e2e-host.exe'
    }
    $env:CARGO_TARGET_DIR = $previousTargetDir

    $runner = Join-Path $rootTarget 'debug/d2i-kernel-e2e.exe'
    $worker = Join-Path $rootTarget 'debug/d2i-desktop.exe'
    foreach ($executable in @($runner, $worker) + @($moduleHosts.Values)) {
        if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
            throw "built executable is absent: $executable"
        }
    }
    $moduleHashes = @{}
    foreach ($moduleId in $moduleHosts.Keys) {
        $moduleHashes[$moduleId] = Get-Sha256 $moduleHosts[$moduleId]
    }

    $summaries = [System.Collections.Generic.List[object]]::new()
    if ($Mode -eq 'All') {
        $summaries.Add((Invoke-Scenario 'happy-a' 'happy' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'happy-b' 'happy' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        if ($summaries[0].normalized_replay_sha256 -ne $summaries[1].normalized_replay_sha256) {
            throw 'normalized happy replay hashes differ'
        }
        $summaries.Add((Invoke-Scenario 'already-correct' 'already_correct' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'recovery' 'recovery' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'unsafe' 'unsafe' 11 'escalated' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'clarification' 'clarification' 10 'clarification_required' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $terminalExitCode = 0
    }
    elseif ($Mode -eq 'Adaptive') {
        $summaries.Add((Invoke-Scenario 'happy' 'happy' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'already_correct' 'already_correct' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $terminalExitCode = 0
    }
    elseif ($Mode -eq 'Work900') {
        $summaries.Add((Invoke-Scenario 'case-a-happy' 'happy' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-b-already-correct' 'already_correct' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-c-recovery' 'recovery' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-d-fresh-replan' 'already_correct' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-e-clarification' 'clarification' 10 'clarification_required' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-e-resume' 'happy' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-h-paused' 'paused_after_set' 12 'stopped' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $summaries.Add((Invoke-Scenario 'case-h-resume' 'already_correct' 0 'completed' $runner $worker $moduleHosts $moduleHashes $runRoot))
        $terminalExitCode = 0
    }
    else {
        $contract = switch ($Mode) {
            'Happy' { @('happy', 0, 'completed') }
            'AlreadyCorrect' { @('already_correct', 0, 'completed') }
            'Recovery' { @('recovery', 0, 'completed') }
            'Unsafe' { @('unsafe', 11, 'escalated') }
            'Clarification' { @('clarification', 10, 'clarification_required') }
            'PausedAfterSet' { @('paused_after_set', 12, 'stopped') }
        }
        $summaries.Add((Invoke-Scenario $contract[0] $contract[0] $contract[1] $contract[2] $runner $worker $moduleHosts $moduleHashes $runRoot))
        $terminalExitCode = $contract[1]
    }

    $summary = [pscustomobject][ordered]@{
        schema_version = 1
        git_head = $gitHead
        mode = $Mode.ToLowerInvariant()
        role_bound = [bool]$RoleSource
        scenario_count = $summaries.Count
        normalized_replay_equal = if ($Mode -eq 'All') { $true } else { $null }
        scenarios = @($summaries)
        complete = $true
    }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $runRoot 'finished.json') -Encoding UTF8
    Write-Output "D2I KRN-500 E2E complete: $runRoot"
}
catch {
    Write-Error $_
}
finally {
    $env:CARGO_TARGET_DIR = $previousTargetDir
}

exit $terminalExitCode
