[CmdletBinding()]
param(
    [string]$OutputRoot,

    [string]$CargoTargetRoot,

    [ValidateRange(30, 7200)]
    [int]$StepTimeoutSeconds = 1800
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$moduleRoot = Join-Path $repoRoot 'modules'
$checker = Join-Path $PSScriptRoot 'check-module.ps1'
$engine = (Get-Process -Id $PID).Path
$startedAt = [DateTimeOffset]::UtcNow

function Quote-ProcessArgument([string]$Value) {
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    $escaped = $Value -replace '(\\*)"', '$1$1\"'
    $escaped = $escaped -replace '(\\+)$', '$1$1'
    return '"' + $escaped + '"'
}

if (-not $OutputRoot) {
    $OutputRoot = Join-Path $env:TEMP "d2i-all-module-checks-$PID"
}
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$modules = @(
        Get-ChildItem -LiteralPath $moduleRoot -Directory |
        Where-Object {
            (Test-Path -LiteralPath (Join-Path $_.FullName 'Cargo.toml') -PathType Leaf) -and
            (
                (Test-Path -LiteralPath (Join-Path $_.FullName 'module-manifest.yaml') -PathType Leaf) -or
                (Test-Path -LiteralPath (Join-Path $_.FullName 'module-manifest.json') -PathType Leaf)
            )
        } |
        Sort-Object Name
)
if ($modules.Count -eq 0) {
    throw 'no standalone modules were discovered'
}

$results = [System.Collections.Generic.List[object]]::new()
foreach ($module in $modules) {
    $resultPath = Join-Path $OutputRoot "$($module.Name).json"
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $checker,
        '-ModulePath', $module.FullName,
        '-OutputPath', $resultPath,
        '-StepTimeoutSeconds', $StepTimeoutSeconds
    )
    if ($CargoTargetRoot) {
        $arguments += @(
            '-CargoTargetDir',
            (Join-Path ([IO.Path]::GetFullPath($CargoTargetRoot)) $module.Name)
        )
    }
    $argumentLine = (@($arguments | ForEach-Object { Quote-ProcessArgument $_ }) -join ' ')
    $process = Start-Process -FilePath $engine -ArgumentList $argumentLine -PassThru -NoNewWindow
    # Avoid Start-Process -Wait hanging on inherited handles and preserve the real child exit code.
    $null = $process.Handle
    $moduleTimeoutMilliseconds = [Math]::Min(
        ([int64]$StepTimeoutSeconds * 5 + 300) * 1000,
        [int]::MaxValue
    )
    if (-not $process.WaitForExit([int]$moduleTimeoutMilliseconds)) {
        & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null
        throw "module checker timed out for $($module.Name)"
    }
    $process.WaitForExit()
    $process.Refresh()
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "module checker did not produce $resultPath"
    }
    $result = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
    $results.Add($result)
    if ($process.ExitCode -ne 0 -and $result.status -eq 'pass') {
        throw "module checker exit code disagrees with report for $($module.Name)"
    }
}

$failed = @($results | Where-Object { $_.status -ne 'pass' })
$report = [ordered]@{
    schema_version = 1
    discovered_modules = @($modules | ForEach-Object { $_.Name })
    module_count = $modules.Count
    passed = $modules.Count - $failed.Count
    failed = $failed.Count
    status = if ($failed.Count -eq 0) { 'pass' } else { 'fail' }
    started_at = $startedAt.ToString('o')
    completed_at = [DateTimeOffset]::UtcNow.ToString('o')
    modules = @(
        $results | ForEach-Object {
            [ordered]@{
                module_id = $_.module_id
                status = $_.status
                report_hash = $_.report_hash
            }
        }
    )
    report_hash = ''
}
$unhashed = $report | ConvertTo-Json -Depth 8 -Compress
$report.report_hash = 'sha256:' + (
    Get-FileHash `
        -Algorithm SHA256 `
        -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($unhashed)))
).Hash.ToLowerInvariant()
$json = $report | ConvertTo-Json -Depth 8
$reportPath = Join-Path $OutputRoot 'all-modules.json'
[IO.File]::WriteAllText($reportPath, $json + [Environment]::NewLine)
Write-Output $json
if ($failed.Count -gt 0) {
    exit 1
}
