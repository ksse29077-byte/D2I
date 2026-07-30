[CmdletBinding()]
param(
    [string]$RunnerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RunnerPath)) {
    $RunnerPath = Join-Path $PSScriptRoot 'run-windows-reproduction.ps1'
}

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw "Assertion failed: $Message"
    }
}

function Assert-Equal {
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ("$Actual" -ne "$Expected") {
        throw "Assertion failed: $Message. Expected '$Expected', got '$Actual'."
    }
}

function New-FixtureRepository {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$PackageName
    )

    New-Item -ItemType Directory -Path (Join-Path $Path 'src') -Force | Out-Null
    @"
[package]
name = "$PackageName"
version = "0.1.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"@ | Set-Content -LiteralPath (Join-Path $Path 'Cargo.toml') -Encoding UTF8

    @'
#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn pass_case() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn assertion_failure() {
        assert_eq!(1, 2);
    }

    #[test]
    fn hanging_worker() {
        let mut child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .spawn()
            .expect("fixture worker should start");
        thread::sleep(Duration::from_secs(30));
        let _ = child.wait();
    }
}
'@ | Set-Content -LiteralPath (Join-Path $Path 'src\lib.rs') -Encoding UTF8

    & git -C $Path init --quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to initialize fixture repository at $Path"
    }
    & git -C $Path config user.name 'D2I Runner Test'
    & git -C $Path config user.email 'runner-test@invalid.example'
    & git -C $Path config core.autocrlf false
    & git -C $Path add Cargo.toml src/lib.rs
    & git -C $Path commit --quiet -m 'fixture'
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to commit fixture repository at $Path"
    }
}

function Invoke-RunnerProcess {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [int]$ExpectedExitCode,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $hostExecutable = (Get-Process -Id $PID).Path
    $invocationArguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $script:ResolvedRunnerPath
    ) + $Arguments

    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $hostExecutable @invocationArguments 2>&1 |
                ForEach-Object { "$_" })
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    if ($exitCode -ne $ExpectedExitCode) {
        throw (
            "Runner case '$Name' exited $exitCode instead of $ExpectedExitCode.`n" +
            ($output -join "`n")
        )
    }

    return [pscustomobject]@{
        exit_code = $exitCode
        output = $output
    }
}

function Read-JsonFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected JSON file was not created: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

$script:ResolvedRunnerPath = (Resolve-Path -LiteralPath $RunnerPath).Path
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "d2i-windows-reproduction-self-test-$([guid]::NewGuid().ToString('N'))"
)
$baseWorktree = Join-Path $temporaryRoot 'base'
$candidateWorktree = Join-Path $temporaryRoot 'candidate'
$missingManifestWorktree = Join-Path $temporaryRoot 'missing-manifest'
$callerDirectory = Join-Path $temporaryRoot 'caller'
$outputDirectory = Join-Path $temporaryRoot 'output'

try {
    New-FixtureRepository -Path $baseWorktree -PackageName 'd2i-runner-base-fixture'
    New-FixtureRepository -Path $candidateWorktree -PackageName 'd2i-runner-candidate-fixture'
    New-Item -ItemType Directory -Path $missingManifestWorktree -Force | Out-Null
    New-Item -ItemType Directory -Path $callerDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null

    $passOutput = Join-Path $outputDirectory 'pass'
    Push-Location $callerDirectory
    try {
        Invoke-RunnerProcess `
            -Name 'positive run from unrelated current directory' `
            -ExpectedExitCode 0 `
            -Arguments @(
                '-Worktree', $baseWorktree,
                '-Label', 'base',
                '-OutputRoot', $passOutput,
                '-Runs', '1',
                '-TestFilter', 'tests::pass_case',
                '-Mode', 'Serial',
                '-Exact',
                '-TimeoutSeconds', '60'
            ) | Out-Null
    }
    finally {
        Pop-Location
    }

    $passFinished = Read-JsonFile -Path (Join-Path $passOutput 'finished.json')
    $passResult = Read-JsonFile `
        -Path (Join-Path $passOutput 'base\run-0001\result.json')
    Assert-Equal $passFinished.requested_runs 1 'positive requested run count'
    Assert-Equal $passFinished.valid_test_runs 1 'positive valid run count'
    Assert-Equal $passFinished.passed_runs 1 'positive pass count'
    Assert-Equal $passFinished.harness_failures 0 'positive harness failure count'
    Assert-True $passFinished.complete 'positive run should be complete'
    Assert-True $passFinished.valid_for_comparison 'positive run should be comparable'
    Assert-Equal $passFinished.residual_owned_processes 0 'positive residual process count'
    Assert-Equal $passResult.status 'pass' 'positive run status'
    Assert-True $passResult.test_binary_started 'positive test binary observation'
    Assert-Equal $passResult.working_directory (
        (Resolve-Path -LiteralPath $baseWorktree).Path
    ) 'working directory must be the worktree'
    Assert-Equal $passResult.manifest_path (
        (Resolve-Path -LiteralPath (Join-Path $baseWorktree 'Cargo.toml')).Path
    ) 'manifest path must be absolute and exact'
    Assert-True (
        $passResult.command.Contains('--manifest-path')
    ) 'recorded command must contain --manifest-path'
    Assert-True (
        @($passResult.new_processes | Where-Object {
                $_.classification -eq 'cargo'
            }).Count -eq 1
    ) 'Cargo must be recorded as an owned process'
    Assert-True (
        @($passResult.new_processes | Where-Object {
                $_.classification -eq 'runner'
            }).Count -eq 0
    ) 'runner must not be recorded as a test worker'
    Assert-Equal @($passResult.residual_owned_processes).Count 0 (
        'runner and Cargo must not be residual workers'
    )

    $failureOutput = Join-Path $outputDirectory 'test-failure'
    Invoke-RunnerProcess `
        -Name 'test assertion failure' `
        -ExpectedExitCode 1 `
        -Arguments @(
            '-Worktree', $baseWorktree,
            '-Label', 'base',
            '-OutputRoot', $failureOutput,
            '-Runs', '1',
            '-TestFilter', 'tests::assertion_failure',
            '-Mode', 'Serial',
            '-Exact',
            '-CargoTargetDir', $passResult.cargo_target_dir,
            '-TimeoutSeconds', '60'
        ) | Out-Null
    $failureFinished = Read-JsonFile -Path (Join-Path $failureOutput 'finished.json')
    $failureResult = Read-JsonFile `
        -Path (Join-Path $failureOutput 'base\run-0001\result.json')
    Assert-Equal $failureResult.status 'test_failure' 'assertion failure classification'
    Assert-True $failureResult.test_binary_started 'failed test binary observation'
    Assert-Equal $failureFinished.valid_test_runs 1 'failed test is still a valid run'
    Assert-Equal $failureFinished.test_failures 1 'test failure count'
    Assert-Equal $failureFinished.harness_failures 0 'assertion is not harness failure'
    Assert-True $failureFinished.valid_for_comparison (
        'an observed assertion failure remains valid comparison evidence'
    )
    Assert-Equal $failureFinished.residual_owned_processes 0 (
        'failed test cleanup must reach zero'
    )

    $missingOutput = Join-Path $outputDirectory 'missing-manifest'
    Invoke-RunnerProcess `
        -Name 'missing Cargo.toml' `
        -ExpectedExitCode 2 `
        -Arguments @(
            '-Worktree', $missingManifestWorktree,
            '-Label', 'invalid',
            '-OutputRoot', $missingOutput,
            '-Runs', '1',
            '-TestFilter', 'tests::pass_case'
        ) | Out-Null
    $missingFinished = Read-JsonFile -Path (Join-Path $missingOutput 'finished.json')
    Assert-Equal $missingFinished.valid_test_runs 0 'missing manifest valid run count'
    Assert-Equal $missingFinished.test_failures 0 'missing manifest test failure count'
    Assert-Equal $missingFinished.harness_failures 1 'missing manifest harness failure count'
    Assert-True (-not $missingFinished.complete) 'preflight rejection cannot be complete'
    Assert-True (-not $missingFinished.valid_for_comparison) (
        'preflight rejection cannot be compared'
    )
    Assert-True (
        $missingFinished.error_summary.Contains('Cargo.toml not found')
    ) 'missing manifest error summary'
    Assert-True (
        -not (Test-Path -LiteralPath (Join-Path $missingOutput 'invalid\run-0001'))
    ) 'missing manifest must be rejected before a run starts'

    $pairedOutput = Join-Path $outputDirectory 'paired'
    Invoke-RunnerProcess `
        -Name 'paired target isolation' `
        -ExpectedExitCode 0 `
        -Arguments @(
            '-Worktree', $baseWorktree,
            '-Label', 'base',
            '-CandidateWorktree', $candidateWorktree,
            '-CandidateLabel', 'candidate',
            '-OutputRoot', $pairedOutput,
            '-Runs', '1',
            '-TestFilter', 'tests::pass_case',
            '-Mode', 'Parallel',
            '-Exact',
            '-TimeoutSeconds', '60'
        ) | Out-Null
    $pairedFinished = Read-JsonFile -Path (Join-Path $pairedOutput 'finished.json')
    Assert-Equal $pairedFinished.requested_runs 2 'paired requested run count'
    Assert-Equal $pairedFinished.valid_test_runs 2 'paired valid run count'
    Assert-Equal $pairedFinished.comparison_kind 'paired' 'paired comparison kind'
    Assert-True $pairedFinished.comparison_contracts_match (
        'paired normalized command and privilege contract'
    )
    Assert-True $pairedFinished.valid_for_comparison 'paired run comparison validity'
    Assert-True (
        -not "$($pairedFinished.cohorts[0].cargo_target_dir)".Equals(
            "$($pairedFinished.cohorts[1].cargo_target_dir)",
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) 'Base and Candidate target directories must differ'
    Assert-Equal $pairedFinished.cohorts[0].comparison_contract_sha256 (
        $pairedFinished.cohorts[1].comparison_contract_sha256
    ) 'Base and Candidate comparison contracts'

    $timeoutOutput = Join-Path $outputDirectory 'timeout'
    Invoke-RunnerProcess `
        -Name 'owned process timeout cleanup' `
        -ExpectedExitCode 2 `
        -Arguments @(
            '-Worktree', $baseWorktree,
            '-Label', 'base',
            '-OutputRoot', $timeoutOutput,
            '-Runs', '1',
            '-TestFilter', 'tests::hanging_worker',
            '-Mode', 'Serial',
            '-Exact',
            '-CargoTargetDir', $passResult.cargo_target_dir,
            '-TimeoutSeconds', '3'
        ) | Out-Null
    $timeoutFinished = Read-JsonFile -Path (Join-Path $timeoutOutput 'finished.json')
    $timeoutResult = Read-JsonFile `
        -Path (Join-Path $timeoutOutput 'base\run-0001\result.json')
    Assert-Equal $timeoutResult.status 'timeout' 'timeout classification'
    Assert-Equal $timeoutFinished.valid_test_runs 0 (
        'timeout must not count as a valid test run'
    )
    Assert-Equal $timeoutFinished.timeouts 1 'timeout count'
    Assert-True (-not $timeoutFinished.valid_for_comparison) (
        'requested and valid run mismatch must invalidate comparison'
    )
    Assert-Equal $timeoutFinished.residual_owned_processes 0 (
        'timeout cleanup must reach zero residual owned processes'
    )
    Assert-Equal @($timeoutResult.residual_owned_processes).Count 0 (
        'timeout result must not retain Cargo, test harness, or worker'
    )
    Assert-True (
        @($timeoutResult.new_processes | Where-Object {
                $_.classification -eq 'test_worker'
            }).Count -ge 1
    ) 'fixture worker should be distinguished from Cargo and the test harness'

    Write-Output 'Windows reproduction runner self-tests: PASS'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporary = (Resolve-Path -LiteralPath $temporaryRoot).Path
        $systemTemporary = (Resolve-Path -LiteralPath ([System.IO.Path]::GetTempPath())).Path
        if (-not $resolvedTemporary.StartsWith(
                $systemTemporary,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
            throw "Refusing to remove unexpected self-test path: $resolvedTemporary"
        }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}

exit 0
