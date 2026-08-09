[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ModulePath,

    [string]$OutputPath,

    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$BaseSha,

    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$HeadSha = 'HEAD',

    [string[]]$ChangedFilesOverride,

    [string]$CargoTargetDir,

    [ValidateRange(30, 7200)]
    [int]$StepTimeoutSeconds = 1800
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$startedAt = [DateTimeOffset]::UtcNow
$checks = [System.Collections.Generic.List[object]]::new()
$failure = $null
$moduleRoot = $null
$moduleId = $null
$gitHead = $null
$temporaryOutput = $false

function Add-Check(
    [string]$Name,
    [string]$Status,
    [string]$Message,
    [int]$ExitCode = 0,
    [string]$StdoutPath = '',
    [string]$StderrPath = ''
) {
    $checks.Add([pscustomobject][ordered]@{
            name = $Name
            status = $Status
            message = $Message
            exit_code = $ExitCode
            stdout_path = $StdoutPath
            stderr_path = $StderrPath
        })
}

function Quote-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

function Invoke-CargoStep(
    [string]$Name,
    [string[]]$Arguments,
    [string]$WorkingDirectory,
    [string]$LogDirectory
) {
    $cargo = Get-Command cargo -ErrorAction Stop
    $stdoutPath = Join-Path $LogDirectory "$Name.stdout.log"
    $stderrPath = Join-Path $LogDirectory "$Name.stderr.log"
    $argumentLine = (@($Arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join ' ')
    $process = Start-Process `
        -FilePath $cargo.Source `
        -ArgumentList $argumentLine `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath `
        -NoNewWindow `
        -PassThru
    # Windows PowerShell 5 can lose ExitCode unless the process handle is materialized before wait.
    $null = $process.Handle
    if (-not $process.WaitForExit($StepTimeoutSeconds * 1000)) {
        & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null
        Add-Check $Name 'timeout' "cargo step exceeded ${StepTimeoutSeconds}s" 124 $stdoutPath $stderrPath
        throw "cargo step '$Name' timed out"
    }
    $process.WaitForExit()
    $process.Refresh()
    $exitCode = [int]$process.ExitCode
    if ($exitCode -ne 0) {
        Add-Check $Name 'fail' "cargo exited with $exitCode" $exitCode $stdoutPath $stderrPath
        throw "cargo step '$Name' failed with exit code $exitCode"
    }
    Add-Check $Name 'pass' 'command completed' 0 $stdoutPath $stderrPath
    return $stdoutPath
}

try {
    if (-not (Test-Path -LiteralPath $ModulePath -PathType Container)) {
        throw "module path does not exist: $ModulePath"
    }
    $moduleRoot = (Resolve-Path -LiteralPath $ModulePath).Path
    $modulesRoot = (Resolve-Path (Join-Path $repoRoot 'modules')).Path
    if (-not $moduleRoot.StartsWith("$modulesRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'ModulePath must identify a directory under modules/'
    }
    if ((Split-Path (Split-Path $moduleRoot -Parent) -Leaf) -ne 'modules') {
        throw 'ModulePath must identify one immediate modules/<module-id> directory'
    }
    $moduleId = Split-Path $moduleRoot -Leaf
    $manifestPath = Join-Path $moduleRoot 'Cargo.toml'
    $lockPath = Join-Path $moduleRoot 'Cargo.lock'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw 'standalone module Cargo.toml is missing'
    }
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw 'standalone module Cargo.lock is missing'
    }
    $moduleManifests = @(
        'module-manifest.yaml',
        'module-manifest.json'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $moduleRoot $_) -PathType Leaf }
    if ($moduleManifests.Count -ne 1) {
        throw 'exactly one module-manifest.yaml or module-manifest.json is required'
    }
    Add-Check 'preflight' 'pass' 'standalone module files are present'

    $gitHead = (& git -C $repoRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot resolve repository HEAD'
    }
    $rootLockPath = Join-Path $repoRoot 'Cargo.lock'
    $rootLockBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash

    if (-not $OutputPath) {
        $OutputPath = Join-Path $env:TEMP "d2i-module-check-$moduleId-$PID.json"
        $temporaryOutput = $true
    }
    $outputFullPath = [IO.Path]::GetFullPath($OutputPath)
    if ($outputFullPath.StartsWith(
            "$moduleRoot$([IO.Path]::DirectorySeparatorChar)",
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'OutputPath must remain outside the module workspace'
    }
    $outputDirectory = Split-Path $outputFullPath -Parent
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    $logDirectory = Join-Path $outputDirectory "$moduleId-logs"
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

    if ($PSBoundParameters.ContainsKey('ChangedFilesOverride') -or $BaseSha) {
        if ($PSBoundParameters.ContainsKey('ChangedFilesOverride')) {
            $changedFiles = @($ChangedFilesOverride)
        }
        else {
            $changedFiles = @(git -C $repoRoot diff --name-only "$BaseSha...$HeadSha")
            if ($LASTEXITCODE -ne 0) {
                throw 'cannot enumerate changed files for scope validation'
            }
        }
        $changedFiles = @(
            $changedFiles |
                ForEach-Object { $_.Trim().Replace('\', '/') } |
                Where-Object { $_ }
        )
        $outside = @($changedFiles | Where-Object { $_ -notlike "modules/$moduleId/*" })
        if ($outside.Count -gt 0) {
            throw "changed-scope includes paths outside modules/$moduleId"
        }
        Add-Check 'changed_scope' 'pass' "all changed paths belong to modules/$moduleId"
    }
    else {
        Add-Check 'changed_scope' 'not_applicable' 'no comparison range was supplied'
    }

    if ($CargoTargetDir) {
        $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($CargoTargetDir)
    }

    $metadataLog = Invoke-CargoStep `
        -Name 'metadata' `
        -Arguments @('metadata', '--manifest-path', $manifestPath, '--locked', '--no-deps', '--format-version', '1') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory
    $metadata = Get-Content -Raw -LiteralPath $metadataLog | ConvertFrom-Json
    if ([IO.Path]::GetFullPath($metadata.workspace_root) -ne [IO.Path]::GetFullPath($moduleRoot)) {
        throw "cargo workspace_root is not the module directory: $($metadata.workspace_root)"
    }
    if (@($metadata.workspace_members).Count -ne 1) {
        throw 'standalone module workspace must contain exactly one member'
    }
    $package = @($metadata.packages | Where-Object { $_.id -eq $metadata.workspace_members[0] })
    if ($package.Count -ne 1) {
        throw 'cannot identify the standalone module package'
    }
    $forbiddenD2iDependencies = @(
        $package[0].dependencies |
            Where-Object {
                $_.name -like 'd2i-*' -and
                $_.name -notin @('d2i-module-sdk', 'd2i-cognitive-ir')
            } |
            ForEach-Object { $_.name }
    )
    if ($forbiddenD2iDependencies.Count -gt 0) {
        throw "module directly depends on forbidden Core packages: $($forbiddenD2iDependencies -join ', ')"
    }
    $forbiddenPathDependencies = @(
        $package[0].dependencies |
            Where-Object {
                $_.path -and
                $_.name -notin @('d2i-module-sdk', 'd2i-cognitive-ir')
            } |
            ForEach-Object { $_.name }
    )
    if ($forbiddenPathDependencies.Count -gt 0) {
        throw "module has an unapproved local path dependency: $($forbiddenPathDependencies -join ', ')"
    }
    Add-Check 'dependency_boundary' 'pass' 'direct D2I dependencies are limited to SDK and Cognitive IR'

    Invoke-CargoStep `
        -Name 'fmt' `
        -Arguments @('fmt', '--manifest-path', $manifestPath, '--all', '--', '--check') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory | Out-Null
    Invoke-CargoStep `
        -Name 'clippy' `
        -Arguments @('clippy', '--manifest-path', $manifestPath, '--locked', '--all-targets', '--all-features', '--', '-D', 'warnings') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory | Out-Null
    Invoke-CargoStep `
        -Name 'tests' `
        -Arguments @('test', '--manifest-path', $manifestPath, '--locked', '--all-features') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory | Out-Null
    Invoke-CargoStep `
        -Name 'manifest_conformance_replay' `
        -Arguments @('test', '--manifest-path', $manifestPath, '--locked', '--all-features', '--test', 'conformance') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory | Out-Null
    Invoke-CargoStep `
        -Name 'release_build' `
        -Arguments @('build', '--manifest-path', $manifestPath, '--locked', '--all-features', '--release') `
        -WorkingDirectory $moduleRoot `
        -LogDirectory $logDirectory | Out-Null

    $rootLockAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash
    if ($rootLockBefore -ne $rootLockAfter) {
        throw 'standalone module check modified the root Cargo.lock'
    }
    Add-Check 'root_lock_unchanged' 'pass' 'root Cargo.lock digest is unchanged'
}
catch {
    $failure = $_.Exception.Message
    Add-Check 'terminal' 'fail' $failure 1
}

$completedAt = [DateTimeOffset]::UtcNow
$status = if ($failure) { 'fail' } else { 'pass' }
$report = [ordered]@{
    schema_version = 1
    module_id = $moduleId
    module_path = $moduleRoot
    workspace_root = $moduleRoot
    git_head = $gitHead
    cargo_target_dir = $CargoTargetDir
    status = $status
    started_at = $startedAt.ToString('o')
    completed_at = $completedAt.ToString('o')
    checks = @($checks)
    error_summary = $failure
    report_hash = ''
}
$unhashed = $report | ConvertTo-Json -Depth 8 -Compress
$report.report_hash = 'sha256:' + (
    Get-FileHash `
        -Algorithm SHA256 `
        -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($unhashed)))
).Hash.ToLowerInvariant()
$json = $report | ConvertTo-Json -Depth 8
if ($OutputPath) {
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath), $json + [Environment]::NewLine)
}
Write-Output $json
if ($temporaryOutput) {
    Remove-Item -LiteralPath ([IO.Path]::GetFullPath($OutputPath)) -Force -ErrorAction SilentlyContinue
}
if ($failure) {
    exit 1
}
