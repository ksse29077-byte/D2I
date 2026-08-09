[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Query', 'ContextSlice', 'FileWorker',
        'ExcelDiscovery', 'ExcelLive', 'Model', 'Negative', 'Replay',
        'Regression', 'RunnerSelfTest', 'Completion', 'All'
    )]
    [string]$Mode = 'All',
    [string]$Runtime,
    [string]$Model,
    [string]$Office200EvidenceRoot,
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
$checkpointModule = Join-Path $repoRoot 'scripts/workforce/lib/WorkforceCheckpoint.psm1'
Import-Module -Force $checkpointModule
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office300-spreadsheet-work' }
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
        throw "Refusing to remove a path outside the OFFICE-300 output root: $resolved"
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

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ExcelExecutable {
    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\EXCEL.EXE',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\EXCEL.EXE'
    )) {
        if (Test-Path -LiteralPath $key) {
            $value = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($value) { $candidates.Add([string]$value) }
        }
    }
    $candidates.Add('C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE')
    $candidates.Add('C:\Program Files (x86)\Microsoft Office\Root\Office16\EXCEL.EXE')
    $excel = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $excel) { throw 'Installed desktop Microsoft Excel was not found.' }
    $excel = (Resolve-Path -LiteralPath $excel).Path
    $signature = Get-AuthenticodeSignature -LiteralPath $excel
    if ($signature.Status -ne 'Valid') { throw 'EXCEL.EXE Authenticode signature is not valid.' }
    return $excel
}

function Invoke-Contract {
    Invoke-Cargo 'office300-contract' @('test', '--locked', '-p', 'd2i-spreadsheet-capability', '--all-features')
}

function Invoke-Schema {
    Invoke-NativeStep 'office300-schema' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-spreadsheet-work-schemas.ps1'), '-Check'
    )
}

function Invoke-Desktop {
    Invoke-Cargo 'office300-desktop' @(
        'test', '--locked', '-p', 'd2i-desktop', '--test', 'spreadsheet_work', '--all-features'
    )
    Invoke-Cargo 'office300-package' @(
        'test', '--locked', '-p', 'd2i-desktop', '--lib', 'spreadsheet_package', '--all-features'
    )
    Invoke-Cargo 'office300-xlsx' @(
        'test', '--locked', '-p', 'd2i-desktop', '--lib', 'xlsx_spreadsheet', '--all-features'
    )
}

function Invoke-Regression {
    Invoke-Cargo 'office300-policy' @('test', '--locked', '-p', 'd2i-policy-admission', '--all-features')
    Invoke-Cargo 'office300-trusted-execution' @('test', '--locked', '-p', 'd2i-trusted-action-execution', '--all-features')
    Invoke-Cargo 'office300-office100' @('test', '--locked', '-p', 'd2i-office-capability', '--all-features')
    Invoke-Cargo 'office300-office200' @('test', '--locked', '-p', 'd2i-document-capability', '--all-features')
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
    if (-not $Office200EvidenceRoot -or -not (Test-Path -LiteralPath $Office200EvidenceRoot -PathType Container)) {
        throw 'Office200EvidenceRoot is required and must exist.'
    }
    $script:Office200EvidenceRoot = (Resolve-Path -LiteralPath $Office200EvidenceRoot).Path
    $finishedPath = Join-Path $Office200EvidenceRoot 'finished.json'
    $runnerPath = Join-Path $Office200EvidenceRoot 'runner-finished.json'
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $runner = Get-Content -Raw -LiteralPath $runnerPath -Encoding UTF8 | ConvertFrom-Json
    if ($finished.finished_sha256 -ne (Get-WithoutFieldHash $finished 'finished_sha256') -or
        $runner.summary_sha256 -ne (Get-WithoutFieldHash $runner 'summary_sha256') -or
        $runner.execution_finished_sha256 -ne $finished.finished_sha256 -or
        -not $finished.complete -or -not $runner.complete -or
        $finished.residual.worker_owned_word_processes -ne 0 -or
        $finished.residual.worker_owned_hwp_processes -ne 0 -or
        $finished.residual.com_workers -ne 0 -or
        $finished.residual.document_file_locks -ne 0 -or
        $finished.residual.temporary_packages -ne 0 -or
        $finished.residual.activations -ne 0 -or
        $finished.residual.profiles -ne 0 -or
        $finished.residual.credentials -ne 0 -or
        $finished.residual.workspace_locks -ne 0 -or
        $runner.residual_owned_processes -ne 0) {
        throw 'OFFICE-200 predecessor is not a sealed clean Completion.'
    }
    return $finished.finished_sha256
}

function Invoke-Model {
    Assert-PinnedModel
    if ($Resume -and (Test-Path -LiteralPath $modelReportPath -PathType Leaf)) {
        $existing = Get-Content -Raw -LiteralPath $modelReportPath -Encoding UTF8 | ConvertFrom-Json
        if ($existing.schema_version -ne 1 -or
            $existing.model_artifact_sha256 -ne (Get-WorkforceFileHash $Model) -or
            $existing.runtime_artifact_sha256 -ne (Get-WorkforceFileHash $Runtime)) {
            throw 'Refusing to reuse an actual-Qwen report with stale or mismatched pinned artifacts.'
        }
        Write-Output "Reusing bounded actual-Qwen report: $modelReportPath"
        return
    }
    if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
    Invoke-Cargo 'office300-build-model' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office300-model-e2e'
    )
    Invoke-NativeStep 'office300-model' (Join-Path $targetRoot 'release/d2i-office300-model-e2e.exe') @(
        $Runtime, $Model, $modelReportPath
    )
}

function Get-OwnedResidualProcesses {
    param(
        [uint32[]]$BaselineExcelProcessIds = @(),
        [object[]]$Processes = $null
    )
    if ($null -eq $Processes) {
        $Processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
    }
    return @($Processes | Where-Object {
        $name = if ($_.Name) { ([string]$_.Name).ToLowerInvariant() } else { '' }
        $line = if ($_.CommandLine) { ([string]$_.CommandLine).ToLowerInvariant() } else { '' }
        ($name -like 'd2i-office300-*.exe') -or
        ($name -eq 'llama-cli.exe' -and $line.Contains('office300-model-process')) -or
        ($name -eq 'excel.exe' -and [uint32]$_.ProcessId -notin $BaselineExcelProcessIds)
    })
}

function Invoke-RunnerSelfTest {
    $processes = @(
        [pscustomobject]@{ ProcessId = 10; Name = 'EXCEL.EXE'; CommandLine = 'preexisting user workbook' }
        [pscustomobject]@{ ProcessId = 11; Name = 'EXCEL.EXE'; CommandLine = '/automation -Embedding' }
        [pscustomobject]@{ ProcessId = 12; Name = 'd2i-office300-excel-worker.exe'; CommandLine = $null }
        [pscustomobject]@{ ProcessId = 13; Name = 'llama-cli.exe'; CommandLine = 'target/office300-model-process' }
        [pscustomobject]@{ ProcessId = 14; Name = 'llama-cli.exe'; CommandLine = 'unrelated model session' }
        [pscustomobject]@{ ProcessId = 15; Name = 'powershell.exe'; CommandLine = $OutputRoot }
        [pscustomobject]@{ ProcessId = 16; Name = 'sudo.exe'; CommandLine = $OutputRoot }
        [pscustomobject]@{ ProcessId = 17; Name = 'cargo.exe'; CommandLine = $OutputRoot }
    )
    $owned = @(Get-OwnedResidualProcesses -BaselineExcelProcessIds @(10) -Processes $processes)
    $actual = @($owned.ProcessId | Sort-Object)
    $expected = @(11, 12, 13)
    if (($actual -join ',') -ne ($expected -join ',')) {
        throw "OFFICE-300 runner process ownership self-test differs: $($actual -join ',')"
    }
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated interactive deployment session for exact Excel WFP policy installation; All remains non-elevated.'
    }
    Assert-PinnedModel
    $predecessor = Assert-Predecessor
    $excel = Resolve-ExcelExecutable
    $baselineExcelProcessIds = @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -and ([string]$_.Name).Equals('EXCEL.EXE', [StringComparison]::OrdinalIgnoreCase) } |
            ForEach-Object { [uint32]$_.ProcessId }
    )
    if (@(Get-OwnedResidualProcesses -BaselineExcelProcessIds $baselineExcelProcessIds).Count -ne 0) {
        throw 'OFFICE-300 preflight found a stale owned worker or model process.'
    }
    Invoke-All
    Invoke-Model
    if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
    Invoke-Cargo 'office300-build-completion' @(
        'build', '--locked', '--release', '-p', 'd2i-spreadsheet-capability',
        '--bin', 'd2i-spreadsheet'
    )
    Invoke-Cargo 'office300-build-workers' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop',
        '--bin', 'd2i-office300-spreadsheet-worker',
        '--bin', 'd2i-office300-excel-worker',
        '--bin', 'd2i-office300-completion-e2e'
    )
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    Invoke-NativeStep 'office300-completion' (Join-Path $targetRoot 'release/d2i-office300-completion-e2e.exe') @(
        $executionRoot,
        (Join-Path $targetRoot 'release/d2i-office300-spreadsheet-worker.exe'),
        (Join-Path $targetRoot 'release/d2i-office300-excel-worker.exe'),
        $excel,
        $modelReportPath,
        $predecessor,
        $sourceTree
    )
    $finishedPath = Join-Path $executionRoot 'finished.json'
    $certificationPath = Join-Path $executionRoot 'certification.json'
    $publicKeyPath = Join-Path $executionRoot 'certification-public-key.hex'
    Invoke-NativeStep 'office300-verify-completion' (Join-Path $targetRoot 'release/d2i-spreadsheet.exe') @(
        'completion', 'verify', '--input', $finishedPath
    )
    Invoke-NativeStep 'office300-verify-certification' (Join-Path $targetRoot 'release/d2i-spreadsheet.exe') @(
        'certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath
    )
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    if (-not $finished.complete -or
        @(Get-OwnedResidualProcesses -BaselineExcelProcessIds $baselineExcelProcessIds).Count -ne 0) {
        throw 'OFFICE-300 terminal Completion or cleanup verification failed.'
    }
    Copy-Item -LiteralPath $finishedPath -Destination (Join-Path $OutputRoot 'finished.json') -Force
    $summary = [ordered]@{
        schema_version = 1
        complete = $true
        execution_finished_sha256 = $finished.finished_sha256
        model_report_sha256 = (Get-Content -Raw -LiteralPath $modelReportPath | ConvertFrom-Json).report_sha256
        residual_owned_processes = 0
        next_task = 'D2I-OFFICE-400'
        summary_sha256 = $null
    }
    $summary.summary_sha256 = Get-WithoutFieldHash ([pscustomobject]$summary) 'summary_sha256'
    Write-WorkforceAtomicJson -Path (Join-Path $OutputRoot 'runner-finished.json') -Value $summary -Pretty
    Write-Output "D2I OFFICE-300 Completion complete: $OutputRoot"
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'ExcelDiscovery' { Resolve-ExcelExecutable }
    'ExcelLive' {
        if (-not (Test-IsAdministrator)) { throw 'ExcelLive requires an elevated WFP deployment session.' }
        Invoke-Completion
    }
    'Model' { Invoke-Model }
    'Negative' { Invoke-Contract; Invoke-Desktop }
    'Regression' { Invoke-Regression }
    'RunnerSelfTest' { Invoke-RunnerSelfTest }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
    default { Invoke-Contract; Invoke-Desktop }
}
