[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$moduleId = "template-smoke-$PID"
$modulePath = Join-Path $repoRoot "modules/$moduleId"
$resultPath = Join-Path $env:TEMP "$moduleId-result.json"
$negativeResultPath = Join-Path $env:TEMP "$moduleId-negative-result.json"
$logPath = Join-Path $env:TEMP "$moduleId-logs"
$targetPath = Join-Path $env:TEMP "$moduleId-target"
$engine = (Get-Process -Id $PID).Path
$rootLockPath = Join-Path $repoRoot 'Cargo.lock'
$rootLockBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash

try {
    & (Join-Path $PSScriptRoot 'new-module.ps1') -ModuleId $moduleId
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $modulePath -PathType Container)) {
        throw 'new-module did not create the expected standalone directory'
    }

    $checker = Join-Path $PSScriptRoot 'check-module.ps1'
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$checker`"",
        '-ModulePath', "`"$modulePath`"",
        '-OutputPath', "`"$resultPath`"",
        '-CargoTargetDir', "`"$targetPath`"",
        '-StepTimeoutSeconds', '600'
    )
    $process = Start-Process `
        -FilePath $engine `
        -ArgumentList $arguments `
        -Wait `
        -NoNewWindow `
        -PassThru
    $process.Refresh()
    if ($process.ExitCode -ne 0) {
        throw "generated template module check failed with $($process.ExitCode)"
    }
    $result = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
    if ($result.status -ne 'pass' -or $result.workspace_root -ne $modulePath) {
        throw 'generated template module report is not a standalone pass'
    }
    $rootLockAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash
    if ($rootLockBefore -ne $rootLockAfter) {
        throw 'module generation or checking changed the root Cargo.lock'
    }

    $manifestPath = Join-Path $modulePath 'Cargo.toml'
    $manifest = [IO.File]::ReadAllText($manifestPath)
    $manifest = $manifest.Replace(
        "[dependencies]`r`n",
        "[dependencies]`r`nd2i-desktop = { path = `"../../products/d2i-desktop`" }`r`n"
    ).Replace(
        "[dependencies]`n",
        "[dependencies]`nd2i-desktop = { path = `"../../products/d2i-desktop`" }`n"
    )
    [IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($false))
    cargo generate-lockfile --manifest-path $manifestPath
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot generate the negative dependency fixture lockfile'
    }
    $negativeArguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$checker`"",
        '-ModulePath', "`"$modulePath`"",
        '-OutputPath', "`"$negativeResultPath`"",
        '-CargoTargetDir', "`"$targetPath`"",
        '-StepTimeoutSeconds', '600'
    )
    $negativeProcess = Start-Process `
        -FilePath $engine `
        -ArgumentList $negativeArguments `
        -Wait `
        -NoNewWindow `
        -PassThru
    $negativeProcess.Refresh()
    if ($negativeProcess.ExitCode -eq 0) {
        throw 'module checker accepted a forbidden d2i-desktop dependency'
    }
    $negativeResult = Get-Content -Raw -LiteralPath $negativeResultPath | ConvertFrom-Json
    if ($negativeResult.error_summary -notmatch 'forbidden Core packages') {
        throw 'forbidden dependency failure was not structured and actionable'
    }

    Write-Output 'Module template generation, hash binding, local lock, and standalone check passed.'
}
finally {
    foreach ($path in @($modulePath, $targetPath, $logPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Recurse -Force
        }
    }
    Remove-Item -LiteralPath $resultPath, $negativeResultPath -Force -ErrorAction SilentlyContinue
}
