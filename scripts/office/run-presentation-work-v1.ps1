[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Context', 'Query', 'SlidePlan', 'PptxRead', 'PptxWrite',
        'PowerPointDiscovery', 'PowerPointLive', 'Text', 'Image', 'Table', 'Chart',
        'Layout', 'FactBinding', 'Quality', 'Rendering', 'Model', 'Negative',
        'CrashRecovery', 'Replay', 'Regression', 'RunnerSelfTest', 'Completion', 'All'
    )]
    [string]$Mode = 'All',
    [string]$Runtime,
    [string]$Model,
    [string]$Office300EvidenceRoot,
    [string]$OutputRoot,
    [switch]$Resume,
    [switch]$Fresh,
    [switch]$ReuseVerifiedPredecessorEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Resume -and $Fresh) { throw '-Resume and -Fresh cannot be used together.' }

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
$cargoTargetRoot = if ($env:CARGO_TARGET_DIR) {
    if ([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) {
        [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
    }
    else {
        [IO.Path]::GetFullPath((Join-Path $repoRoot $env:CARGO_TARGET_DIR))
    }
}
else {
    $targetRoot
}
Import-Module -Force (Join-Path $repoRoot 'scripts/workforce/lib/WorkforceCheckpoint.psm1')
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office400-presentation-work' }
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot = Join-Path $repoRoot $OutputRoot }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must be a child of the repository target directory.'
}
$logRoot = Join-Path $OutputRoot '.runner/logs'
$executionRoot = Join-Path $OutputRoot 'execution'
$modelReportPath = Join-Path $OutputRoot 'model-report.json'

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside the OFFICE-400 output root: $resolved"
    }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

if ($Fresh -and (Test-Path -LiteralPath $OutputRoot)) { Remove-OwnedDirectory $OutputRoot }
New-Item -ItemType Directory -Path $OutputRoot, $logRoot -Force | Out-Null

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

function Get-WithZeroHashField([object]$Value, [string]$Field) {
    $zeroed = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        $zeroed[$property.Name] = if ($property.Name -eq $Field) {
            'sha256:' + ('0' * 64)
        }
        else {
            $property.Value
        }
    }
    return Get-WorkforceObjectHash $zeroed
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-PowerPointExecutable {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERPNT.EXE',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\POWERPNT.EXE'
    )) {
        if (Test-Path -LiteralPath $key) {
            $value = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($value) { $candidates.Add([string]$value) }
        }
    }
    $candidates.Add('C:\Program Files\Microsoft Office\Root\Office16\POWERPNT.EXE')
    $candidates.Add('C:\Program Files (x86)\Microsoft Office\Root\Office16\POWERPNT.EXE')
    $powerpoint = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $powerpoint) { throw 'Installed desktop Microsoft PowerPoint was not found.' }
    $powerpoint = (Resolve-Path -LiteralPath $powerpoint).Path
    if ((Get-AuthenticodeSignature -LiteralPath $powerpoint).Status -ne 'Valid') {
        throw 'POWERPNT.EXE Authenticode signature is not valid.'
    }
    $excel = Join-Path (Split-Path -Parent $powerpoint) 'EXCEL.EXE'
    if (-not (Test-Path -LiteralPath $excel -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $excel).Status -ne 'Valid') {
        throw 'The chart Excel executable is absent or unsigned.'
    }
    return $powerpoint
}

function Invoke-Contract {
    Invoke-Cargo 'office400-contract' @('test', '--locked', '-p', 'd2i-presentation-capability', '--all-features')
}

function Invoke-Schema {
    Invoke-NativeStep 'office400-schema' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-presentation-work-schemas.ps1'), '-Check'
    )
}

function Invoke-Desktop {
    Invoke-Cargo 'office400-desktop' @('test', '--locked', '-p', 'd2i-desktop', '--test', 'presentation_work', '--all-features')
    Invoke-Cargo 'office400-package' @('test', '--locked', '-p', 'd2i-desktop', '--lib', 'presentation_package', '--all-features')
    Invoke-Cargo 'office400-pptx' @('test', '--locked', '-p', 'd2i-desktop', '--lib', 'pptx_presentation', '--all-features')
}

function Invoke-Regression {
    Invoke-Cargo 'office400-policy' @('test', '--locked', '-p', 'd2i-policy-admission', '--all-features')
    Invoke-Cargo 'office400-trusted-execution' @('test', '--locked', '-p', 'd2i-trusted-action-execution', '--all-features')
    Invoke-Cargo 'office400-office100' @('test', '--locked', '-p', 'd2i-office-capability', '--all-features')
    Invoke-Cargo 'office400-office300' @('test', '--locked', '-p', 'd2i-spreadsheet-capability', '--all-features')
}

function Invoke-All {
    Invoke-RunnerSelfTest
    Invoke-Contract
    Invoke-Schema
    Invoke-Desktop
    Invoke-Regression
}

function Assert-PinnedModel {
    if (-not $Runtime -or -not (Test-Path -LiteralPath $Runtime -PathType Leaf)) {
        throw 'Runtime is required and must identify the pinned llama-cli executable.'
    }
    if (-not $Model -or -not (Test-Path -LiteralPath $Model -PathType Leaf)) {
        throw 'Model is required and must identify the pinned Qwen GGUF.'
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
}

function Assert-Predecessor {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence.'
    }
    if (-not $Office300EvidenceRoot -or -not (Test-Path -LiteralPath $Office300EvidenceRoot -PathType Container)) {
        throw 'Office300EvidenceRoot is required and must exist.'
    }
    $script:Office300EvidenceRoot = (Resolve-Path -LiteralPath $Office300EvidenceRoot).Path
    $finishedPath = Join-Path $Office300EvidenceRoot 'finished.json'
    $runnerPath = Join-Path $Office300EvidenceRoot 'runner-finished.json'
    $certificationPath = Join-Path $Office300EvidenceRoot 'execution/certification.json'
    $publicKeyPath = Join-Path $Office300EvidenceRoot 'execution/certification-public-key.hex'
    foreach ($path in @($finishedPath, $runnerPath, $certificationPath, $publicKeyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "OFFICE-300 evidence is missing: $path" }
    }
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $runner = Get-Content -Raw -LiteralPath $runnerPath -Encoding UTF8 | ConvertFrom-Json
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $runner.summary_sha256 -ne (Get-WithoutFieldHash $runner 'summary_sha256') -or
        $runner.execution_finished_sha256 -ne $finished.finished_sha256 -or
        -not $finished.complete -or -not $runner.complete -or
        $finished.residual.excel_processes -ne 0 -or
        $finished.residual.file_workers -ne 0 -or
        $finished.residual.temporary_packages -ne 0 -or
        $finished.residual.activations -ne 0 -or
        $finished.residual.wfp_objects -ne 0 -or
        $finished.residual.profiles -ne 0 -or
        $finished.residual.credentials -ne 0 -or
        $runner.residual_owned_processes -ne 0) {
        throw 'OFFICE-300 predecessor is not a sealed clean Completion.'
    }
    Invoke-Cargo 'office400-build-office300-verifier' @(
        'build', '--locked', '--release', '-p', 'd2i-spreadsheet-capability', '--bin', 'd2i-spreadsheet'
    )
    Invoke-NativeStep 'office400-verify-office300-certification' (Join-Path $cargoTargetRoot 'release/d2i-spreadsheet.exe') @(
        'certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath
    )
    return $finished.finished_sha256
}

function Invoke-Model {
    Assert-PinnedModel
    if ($Resume -and (Test-Path -LiteralPath $modelReportPath -PathType Leaf)) {
        $existing = Get-Content -Raw -LiteralPath $modelReportPath -Encoding UTF8 | ConvertFrom-Json
        if ($existing.schema_version -ne 1 -or
            $existing.report_sha256 -ne (Get-WithZeroHashField $existing 'report_sha256') -or
            $existing.model_artifact_sha256 -ne (Get-WorkforceFileHash $Model) -or
            $existing.runtime_artifact_sha256 -ne (Get-WorkforceFileHash $Runtime) -or
            $existing.actual_qwen_cases -lt 4 -or $existing.provider_invocations -lt 4 -or
            $existing.replan_count -lt 1 -or -not $existing.semantic_intent_only -or
            $existing.raw_pptx_dump_count -ne 0 -or $existing.raw_workbook_dump_count -ne 0) {
            throw 'Refusing to reuse a stale or mismatched actual-Qwen presentation report.'
        }
        Write-Output "Reusing bounded actual-Qwen report: $modelReportPath"
        return
    }
    if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
    Invoke-Cargo 'office400-build-model' @('build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office400-model-e2e')
    Invoke-NativeStep 'office400-model' (Join-Path $cargoTargetRoot 'release/d2i-office400-model-e2e.exe') @($Runtime, $Model, $modelReportPath)
}

function Get-OwnedResidualProcesses {
    param(
        [uint32[]]$BaselinePowerPointProcessIds = @(),
        [uint32[]]$BaselineExcelProcessIds = @(),
        [object[]]$Processes = $null
    )
    if ($null -eq $Processes) { $Processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue) }
    return @($Processes | Where-Object {
        $name = if ($_.Name) { ([string]$_.Name).ToLowerInvariant() } else { '' }
        $line = if ($_.CommandLine) { ([string]$_.CommandLine).ToLowerInvariant() } else { '' }
        ($name -like 'd2i-office400-*.exe') -or
        ($name -eq 'llama-cli.exe' -and $line.Contains('office400-model-process')) -or
        ($name -eq 'powerpnt.exe' -and [uint32]$_.ProcessId -notin $BaselinePowerPointProcessIds) -or
        ($name -eq 'excel.exe' -and [uint32]$_.ProcessId -notin $BaselineExcelProcessIds)
    })
}

function Invoke-RunnerSelfTest {
    $processes = @(
        [pscustomobject]@{ ProcessId = 10; Name = 'POWERPNT.EXE'; CommandLine = 'preexisting user deck' }
        [pscustomobject]@{ ProcessId = 11; Name = 'EXCEL.EXE'; CommandLine = 'preexisting user workbook' }
        [pscustomobject]@{ ProcessId = 12; Name = 'POWERPNT.EXE'; CommandLine = '/automation' }
        [pscustomobject]@{ ProcessId = 13; Name = 'EXCEL.EXE'; CommandLine = '/automation -Embedding' }
        [pscustomobject]@{ ProcessId = 14; Name = 'd2i-office400-powerpoint-worker.exe'; CommandLine = $null }
        [pscustomobject]@{ ProcessId = 15; Name = 'llama-cli.exe'; CommandLine = 'target/office400-model-process' }
        [pscustomobject]@{ ProcessId = 16; Name = 'llama-cli.exe'; CommandLine = 'unrelated model session' }
        [pscustomobject]@{ ProcessId = 17; Name = 'cargo.exe'; CommandLine = $OutputRoot }
    )
    $owned = @(Get-OwnedResidualProcesses -BaselinePowerPointProcessIds @(10) -BaselineExcelProcessIds @(11) -Processes $processes)
    $actual = @($owned.ProcessId | Sort-Object)
    $expected = @(12, 13, 14, 15)
    if (($actual -join ',') -ne ($expected -join ',')) {
        throw "OFFICE-400 runner process ownership self-test differs: $($actual -join ',')"
    }
}

function Invoke-PowerPointLive {
    $powerpoint = Resolve-PowerPointExecutable
    $root = Join-Path $OutputRoot ('powerpoint-live-' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    Invoke-Cargo 'office400-build-powerpoint-live' @('build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office400-powerpoint-live-e2e')
    Invoke-NativeStep 'office400-powerpoint-live' (Join-Path $cargoTargetRoot 'release/d2i-office400-powerpoint-live-e2e.exe') @($powerpoint, $root)
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated deployment session for exact PowerPoint and chart Excel WFP installation; All remains non-elevated.'
    }
    Assert-PinnedModel
    $predecessor = Assert-Predecessor
    $powerpoint = Resolve-PowerPointExecutable
    $baseline = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    $baselinePowerPoint = @($baseline | Where-Object { $_.Name -and ([string]$_.Name).Equals('POWERPNT.EXE', [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { [uint32]$_.ProcessId })
    $baselineExcel = @($baseline | Where-Object { $_.Name -and ([string]$_.Name).Equals('EXCEL.EXE', [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { [uint32]$_.ProcessId })
    if (@(Get-OwnedResidualProcesses -BaselinePowerPointProcessIds $baselinePowerPoint -BaselineExcelProcessIds $baselineExcel).Count -ne 0) {
        throw 'OFFICE-400 preflight found a stale owned worker or model process.'
    }
    Invoke-All
    Invoke-Model
    if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
    Invoke-Cargo 'office400-build-verifier' @('build', '--locked', '--release', '-p', 'd2i-presentation-capability', '--bin', 'd2i-presentation')
    Invoke-Cargo 'office400-build-workers' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop',
        '--bin', 'd2i-office400-presentation-worker',
        '--bin', 'd2i-office400-powerpoint-worker',
        '--bin', 'd2i-office400-completion-e2e'
    )
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    Invoke-NativeStep 'office400-completion' (Join-Path $cargoTargetRoot 'release/d2i-office400-completion-e2e.exe') @(
        $executionRoot,
        (Join-Path $cargoTargetRoot 'release/d2i-office400-presentation-worker.exe'),
        (Join-Path $cargoTargetRoot 'release/d2i-office400-powerpoint-worker.exe'),
        $powerpoint,
        $modelReportPath,
        $predecessor,
        $sourceTree
    )
    $finishedPath = Join-Path $executionRoot 'finished.json'
    $certificationPath = Join-Path $executionRoot 'certification.json'
    $publicKeyPath = Join-Path $executionRoot 'certification-public-key.hex'
    Invoke-NativeStep 'office400-verify-completion' (Join-Path $cargoTargetRoot 'release/d2i-presentation.exe') @('completion', 'verify', '--input', $finishedPath)
    Invoke-NativeStep 'office400-verify-certification' (Join-Path $cargoTargetRoot 'release/d2i-presentation.exe') @('certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath)
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $owned = @(Get-OwnedResidualProcesses -BaselinePowerPointProcessIds $baselinePowerPoint -BaselineExcelProcessIds $baselineExcel)
    if (-not $finished.complete -or $finished.residual.powerpoint_processes -ne 0 -or
        $finished.residual.chart_excel_processes -ne 0 -or $owned.Count -ne 0) {
        throw 'OFFICE-400 terminal Completion or cleanup verification failed.'
    }
    Copy-Item -LiteralPath $finishedPath -Destination (Join-Path $OutputRoot 'finished.json') -Force
    $summary = [ordered]@{
        schema_version = 1
        complete = $true
        execution_finished_sha256 = $finished.finished_sha256
        model_report_sha256 = (Get-Content -Raw -LiteralPath $modelReportPath | ConvertFrom-Json).report_sha256
        residual_owned_processes = 0
        next_task = 'D2I-OFFICE-500'
        summary_sha256 = $null
    }
    $summary.summary_sha256 = Get-WithoutFieldHash ([pscustomobject]$summary) 'summary_sha256'
    Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'runner-finished.json') -Value $summary -Pretty
    Write-Output "D2I OFFICE-400 Completion complete: $OutputRoot"
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'PowerPointDiscovery' { Resolve-PowerPointExecutable }
    'PowerPointLive' { Invoke-PowerPointLive }
    'Model' { Invoke-Model }
    'Negative' { Invoke-Contract; Invoke-Desktop }
    'Regression' { Invoke-Regression }
    'RunnerSelfTest' { Invoke-RunnerSelfTest }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
    default { Invoke-Contract; Invoke-Desktop }
}
