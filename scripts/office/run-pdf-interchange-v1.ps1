[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Profile', 'Finalization', 'WordDiscovery', 'WordExport',
        'ExcelDiscovery', 'ExcelExport', 'PowerPointDiscovery', 'PowerPointExport',
        'PdfLoad', 'PdfRender', 'Geometry', 'Fidelity', 'ExternalPdf', 'Manifest',
        'Model', 'Negative', 'CrashRecovery', 'Replay', 'Regression', 'RunnerSelfTest',
        'Completion', 'All'
    )]
    [string]$Mode = 'All',
    [string]$Runtime,
    [string]$Model,
    [string]$Office450EvidenceRoot,
    [string]$OutputRoot,
    [switch]$ReuseVerifiedPredecessorEvidence,
    [switch]$Fresh,
    [switch]$Resume
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Fresh -and $Resume) { throw '-Fresh and -Resume cannot be used together.' }
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
$cargoTargetRoot = if ($env:CARGO_TARGET_DIR) {
    if ([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) { [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR) }
    else { [IO.Path]::GetFullPath((Join-Path $repoRoot $env:CARGO_TARGET_DIR)) }
}
else { $targetRoot }
Import-Module -Force (Join-Path $repoRoot 'scripts/workforce/lib/WorkforceCheckpoint.psm1')
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office500-pdf-interchange' }
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot = Join-Path $repoRoot $OutputRoot }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must remain inside this repository target directory.'
}
$logRoot = Join-Path $OutputRoot '.runner/logs'
$executionRoot = Join-Path $OutputRoot 'execution'
$modelReportPath = Join-Path $OutputRoot 'model-report.json'

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $resolved = [IO.Path]::GetFullPath($Path)
    if ($resolved -ne $OutputRoot -and
        -not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a path outside OFFICE-500 OutputRoot: $resolved"
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

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-OfficeExecutable([string]$Name) {
    $keyName = $Name.ToUpperInvariant() + '.EXE'
    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($key in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$keyName",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\$keyName"
    )) {
        if (Test-Path -LiteralPath $key) {
            $candidate = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($candidate) { $candidates.Add([string]$candidate) }
        }
    }
    $candidates.Add("C:\Program Files\Microsoft Office\Root\Office16\$keyName")
    $path = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $path) { throw "Installed Microsoft Office executable was not found: $keyName" }
    $path = (Resolve-Path -LiteralPath $path).Path
    if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') {
        throw "Office executable signature is invalid: $path"
    }
    return $path
}

function Assert-PinnedModel {
    if (-not $Runtime -or -not (Test-Path -LiteralPath $Runtime -PathType Leaf)) {
        throw 'Runtime must identify the pinned llama-cli executable.'
    }
    if (-not $Model -or -not (Test-Path -LiteralPath $Model -PathType Leaf)) {
        throw 'Model must identify the pinned Qwen3-4B GGUF.'
    }
    $script:Runtime = (Resolve-Path -LiteralPath $Runtime).Path
    $script:Model = (Resolve-Path -LiteralPath $Model).Path
}

function Assert-Predecessor {
    if (-not $ReuseVerifiedPredecessorEvidence) {
        throw 'Completion requires -ReuseVerifiedPredecessorEvidence.'
    }
    if (-not $Office450EvidenceRoot -or -not (Test-Path -LiteralPath $Office450EvidenceRoot -PathType Container)) {
        throw 'Office450EvidenceRoot must identify sealed OFFICE-450 evidence.'
    }
    $script:Office450EvidenceRoot = (Resolve-Path -LiteralPath $Office450EvidenceRoot).Path
    $finishedPath = Join-Path $Office450EvidenceRoot 'finished.json'
    $certificationPath = Join-Path $Office450EvidenceRoot 'execution/certification.json'
    $publicKeyPath = Join-Path $Office450EvidenceRoot 'execution/certification-public-key.hex'
    foreach ($path in @($finishedPath, $certificationPath, $publicKeyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "OFFICE-450 evidence is missing: $path" }
    }
    Invoke-Cargo 'office500-build-predecessor-verifier' @(
        'build', '--locked', '--release', '-p', 'd2i-design-intelligence', '--bin', 'd2i-design'
    )
    Invoke-NativeStep 'office500-verify-predecessor-completion' (Join-Path $cargoTargetRoot 'release/d2i-design.exe') @(
        'completion', 'verify', '--input', $finishedPath
    )
    Invoke-NativeStep 'office500-verify-predecessor-certification' (Join-Path $cargoTargetRoot 'release/d2i-design.exe') @(
        'certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath
    )
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    if (-not $finished.complete -or $finished.residual.powerpoint_processes -ne 0 -or
        $finished.residual.excel_processes -ne 0 -or $finished.residual.word_processes -ne 0 -or
        $finished.residual.design_workers -ne 0 -or $finished.residual.model_workers -ne 0 -or
        $finished.residual.wfp_objects -ne 0 -or $finished.residual.profiles -ne 0) {
        throw 'OFFICE-450 predecessor is not a clean sealed Completion.'
    }
    return [string]$finished.finished_sha256
}

function Invoke-Contract {
    Invoke-Cargo 'office500-contract' @('test', '--locked', '-p', 'd2i-pdf-interchange', '--all-features')
}

function Invoke-Schema {
    Invoke-NativeStep 'office500-schema' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-pdf-interchange-schemas.ps1'), '-Check'
    )
}

function Invoke-Regression {
    foreach ($package in @(
        'd2i-office-capability', 'd2i-document-capability', 'd2i-spreadsheet-capability',
        'd2i-presentation-capability', 'd2i-design-intelligence'
    )) {
        Invoke-Cargo "office500-regression-$package" @('test', '--locked', '-p', $package, '--all-features')
    }
}

function Invoke-RunnerSelfTest {
    $probe = Join-Path $OutputRoot '.runner-self-test'
    if (Test-Path -LiteralPath $probe) { Remove-OwnedDirectory $probe }
    New-Item -ItemType Directory -Path $probe | Out-Null
    $resolved = [IO.Path]::GetFullPath($probe)
    if (-not $resolved.StartsWith($OutputRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Runner ownership self-test escaped OutputRoot.'
    }
    Remove-OwnedDirectory $probe
    $outside = Join-Path $targetRoot 'd2i-office500-runner-outside-probe'
    New-Item -ItemType Directory -Path $outside -Force | Out-Null
    $rejected = $false
    try { Remove-OwnedDirectory $outside }
    catch { $rejected = $true }
    finally { Remove-Item -LiteralPath $outside -Force }
    if (-not $rejected) { throw 'Runner ownership self-test accepted an outside path.' }

    $closedModes = @(
        'Contract', 'Schema', 'Profile', 'Finalization', 'WordDiscovery', 'WordExport',
        'ExcelDiscovery', 'ExcelExport', 'PowerPointDiscovery', 'PowerPointExport',
        'PdfLoad', 'PdfRender', 'Geometry', 'Fidelity', 'ExternalPdf', 'Manifest',
        'Model', 'Negative', 'CrashRecovery', 'Replay', 'Regression', 'RunnerSelfTest',
        'Completion', 'All'
    )
    if ($closedModes.Count -ne 24 -or ($closedModes | Sort-Object -Unique).Count -ne 24) {
        throw 'Runner mode allowlist is not closed and unique.'
    }
}

function Assert-ZeroMetricObject([object]$Metrics, [string]$Label) {
    foreach ($property in $Metrics.PSObject.Properties) {
        if ([int64]$property.Value -ne 0) {
            throw "$Label metric is non-zero: $($property.Name)=$($property.Value)"
        }
    }
}

function Invoke-All {
    Invoke-RunnerSelfTest
    Invoke-Contract
    Invoke-Schema
    Invoke-Regression
    Invoke-Cargo 'office500-windows-host' @('test', '--locked', '-p', 'd2i-windows-host', '--all-features')
}

function Invoke-Model {
    Assert-PinnedModel
    if ($Resume -and (Test-Path -LiteralPath $modelReportPath -PathType Leaf)) {
        $report = Get-Content -Raw -LiteralPath $modelReportPath -Encoding UTF8 | ConvertFrom-Json
        if ($report.model_artifact_sha256 -eq (Get-WorkforceFileHash $Model) -and
            $report.runtime_artifact_sha256 -eq (Get-WorkforceFileHash $Runtime) -and
            $report.complete -and $report.model_invocation_count -ge 1 -and
            $report.profile_selection_only_count -eq $report.model_invocation_count -and
            $report.raw_pdf_count -eq 0 -and $report.rendered_page_image_count -eq 0 -and
            $report.extracted_pdf_fact_count -eq 0 -and $report.export_execution_authority_count -eq 0) {
            Write-Output "Reusing verified OFFICE-500 model evidence: $modelReportPath"
            return
        }
        throw 'Refusing to resume with stale OFFICE-500 model evidence.'
    }
    if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
    Invoke-Cargo 'office500-build-model' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office500-model-e2e'
    )
    Invoke-NativeStep 'office500-model' (Join-Path $cargoTargetRoot 'release/d2i-office500-model-e2e.exe') @(
        $Runtime, $Model, $modelReportPath
    )
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated session for exact WFP and private-desktop Office export.'
    }
    $predecessor = Assert-Predecessor
    Assert-PinnedModel
    $winword = Resolve-OfficeExecutable 'WINWORD'
    $excel = Resolve-OfficeExecutable 'EXCEL'
    $powerpoint = Resolve-OfficeExecutable 'POWERPNT'
    Invoke-RunnerSelfTest
    Invoke-Contract
    Invoke-Schema
    Invoke-Regression
    Invoke-Model
    if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
    Invoke-Cargo 'office500-build-contract-verifier' @(
        'build', '--locked', '--release', '-p', 'd2i-pdf-interchange', '--bin', 'd2i-pdf-interchange'
    )
    Invoke-Cargo 'office500-build-workers' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop',
        '--bin', 'd2i-office500-word-pdf-worker', '--bin', 'd2i-office500-excel-pdf-worker',
        '--bin', 'd2i-office500-powerpoint-pdf-worker', '--bin', 'd2i-office500-pdf-render-worker',
        '--bin', 'd2i-office500-completion-e2e'
    )
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    Invoke-NativeStep 'office500-completion' (Join-Path $cargoTargetRoot 'release/d2i-office500-completion-e2e.exe') @(
        $executionRoot,
        (Join-Path $cargoTargetRoot 'release/d2i-office500-word-pdf-worker.exe'),
        (Join-Path $cargoTargetRoot 'release/d2i-office500-excel-pdf-worker.exe'),
        (Join-Path $cargoTargetRoot 'release/d2i-office500-powerpoint-pdf-worker.exe'),
        (Join-Path $cargoTargetRoot 'release/d2i-office500-pdf-render-worker.exe'),
        $winword, $excel, $powerpoint, $modelReportPath, $Office450EvidenceRoot,
        $predecessor, $sourceTree
    )
    Invoke-NativeStep 'office500-verify-completion' (Join-Path $cargoTargetRoot 'release/d2i-pdf-interchange.exe') @(
        'completion', 'verify', '--input', (Join-Path $executionRoot 'finished.json')
    )
    Invoke-NativeStep 'office500-verify-replay' (Join-Path $cargoTargetRoot 'release/d2i-pdf-interchange.exe') @(
        'replay', 'verify', '--input', (Join-Path $executionRoot 'replay-report.json')
    )
    Invoke-NativeStep 'office500-verify-certification' (Join-Path $cargoTargetRoot 'release/d2i-pdf-interchange.exe') @(
        'certification', 'verify', '--input', (Join-Path $executionRoot 'certification.json'),
        '--public-key', (Join-Path $executionRoot 'certification-public-key.hex')
    )
    $finished = Get-Content -Raw -LiteralPath (Join-Path $executionRoot 'finished.json') -Encoding UTF8 | ConvertFrom-Json
    Assert-ZeroMetricObject $finished.security 'OFFICE-500 security'
    Assert-ZeroMetricObject $finished.residual 'OFFICE-500 residual'
    if (-not $finished.complete -or $finished.source_tree_sha256 -ne $sourceTree -or
        $finished.rendered_page_count -lt 15 -or $finished.word_pdf_exports -lt 2 -or
        $finished.excel_pdf_exports -lt 2 -or $finished.powerpoint_pdf_exports -lt 2 -or
        $finished.pdf_load_count -lt 6 -or $finished.powerpoint_fidelity_comparisons -lt 5 -or
        $finished.external_pdf_render_only_cases -lt 1 -or
        $finished.external_pdf_malformed_rejections -lt 1 -or
        $finished.external_pdf_password_rejections -lt 1 -or
        $finished.external_pdf_oversize_rejections -lt 1 -or
        $finished.actual_qwen_invocation_count -lt 1 -or
        $finished.final_artifact_pair_count -lt 6 -or $finished.submission_manifest_count -lt 6 -or
        $finished.stale_pair_count -lt 1 -or $finished.superseded_pair_count -lt 1 -or
        $finished.pdfa_requested_cases -lt 1 -or $finished.pdfa_exporter_requested_cases -lt 1 -or
        $finished.pdfa_external_conformance_verified_cases -ne 0 -or
        $finished.hwpx_pdf_export_status -ne 'requires_licensed_hancom_render_backend' -or
        $finished.crash_windows_verified -lt 13 -or
        -not $finished.pdf_interchange_evidence -or -not $finished.word_pdf_export_evidence -or
        -not $finished.excel_pdf_export_evidence -or -not $finished.powerpoint_pdf_export_evidence -or
        -not $finished.independent_pdf_render_evidence -or
        -not $finished.powerpoint_visual_fidelity_evidence -or
        -not $finished.source_pdf_lineage_evidence -or -not $finished.submission_manifest_evidence -or
        -not $finished.external_pdf_render_only_evidence -or -not $finished.office450_lineage_evidence -or
        -not $finished.track_o_office500_evidence -or -not $finished.routine_human_touch_zero) {
        throw 'OFFICE-500 terminal report or residual-state gate differs.'
    }
    Copy-Item -LiteralPath (Join-Path $executionRoot 'finished.json') -Destination (Join-Path $OutputRoot 'finished.json') -Force
    Write-Output "D2I OFFICE-500 Completion complete: $OutputRoot"
}

function Invoke-ContractFilter([string]$Label, [string]$Filter) {
    Invoke-Cargo $Label @('test', '--locked', '-p', 'd2i-pdf-interchange', '--all-features', $Filter)
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'Profile' { Invoke-ContractFilter 'office500-profile' 'external_pdf_has_stricter_render_bounds' }
    'Finalization' { Invoke-ContractFilter 'office500-finalization' 'identical_input_produces_identical_pair_hash' }
    'WordDiscovery' { Resolve-OfficeExecutable 'WINWORD' | Write-Output }
    'WordExport' { Resolve-OfficeExecutable 'WINWORD' | Write-Output }
    'ExcelDiscovery' { Resolve-OfficeExecutable 'EXCEL' | Write-Output }
    'ExcelExport' { Resolve-OfficeExecutable 'EXCEL' | Write-Output }
    'PowerPointDiscovery' { Resolve-OfficeExecutable 'POWERPNT' | Write-Output }
    'PowerPointExport' { Resolve-OfficeExecutable 'POWERPNT' | Write-Output }
    'PdfLoad' { Invoke-Cargo 'office500-pdf-load' @('check', '--locked', '-p', 'd2i-windows-host', '--all-features') }
    'PdfRender' { Invoke-Cargo 'office500-pdf-render' @('check', '--locked', '-p', 'd2i-desktop', '--bin', 'd2i-office500-pdf-render-worker') }
    'Geometry' { Invoke-Contract }
    'Fidelity' { Invoke-Contract }
    'ExternalPdf' { Invoke-ContractFilter 'office500-external' 'hwpx_requires_licensed_backend_and_external_pdf_is_render_only' }
    'Manifest' { Invoke-ContractFilter 'office500-manifest' 'source_change_supersedes_pair_and_removes_submission_readiness' }
    'Model' { Invoke-Model }
    'Negative' {
        Invoke-Contract
        Invoke-Cargo 'office500-negative-windows-pdf' @(
            'test', '--locked', '-p', 'd2i-windows-host', '--all-features',
            'malformed_pdf_loader_and_password_status_fail_closed'
        )
    }
    'CrashRecovery' { Invoke-ContractFilter 'office500-recovery' 'recovery_matrix_verifies_all_thirteen_without_blind_export' }
    'Replay' { Invoke-ContractFilter 'office500-replay' 'replay_requires_exact_128_by_100' }
    'Regression' { Invoke-Regression }
    'RunnerSelfTest' { Invoke-RunnerSelfTest }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}
