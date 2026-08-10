[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Corpus', 'Features', 'PptDesignExtraction',
        'HwpxDesignExtraction', 'DocxDesignExtraction', 'FamilyDiscovery',
        'GrammarCompile', 'ExemplarIndex', 'ExemplarQuery', 'Typography',
        'Layout', 'Table', 'Chart', 'Image', 'Logo', 'HardCritic',
        'SoftCritic', 'PptRender', 'HwpxConformance', 'Refinement',
        'MultiTenant', 'Negative', 'CrashRecovery', 'Replay', 'Regression',
        'RunnerSelfTest', 'Model', 'Completion', 'All'
    )]
    [string]$Mode = 'All',
    [string]$Runtime,
    [string]$Model,
    [string]$Office400EvidenceRoot,
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
    if ([IO.Path]::IsPathRooted($env:CARGO_TARGET_DIR)) {
        [IO.Path]::GetFullPath($env:CARGO_TARGET_DIR)
    }
    else { [IO.Path]::GetFullPath((Join-Path $repoRoot $env:CARGO_TARGET_DIR)) }
}
else { $targetRoot }
Import-Module -Force (Join-Path $repoRoot 'scripts/workforce/lib/WorkforceCheckpoint.psm1')
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office450-design-intelligence' }
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
        throw "Refusing to remove a path outside OFFICE-450 OutputRoot: $resolved"
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

function Get-WithZeroHashField([object]$Value, [string]$Field) {
    $copy = [ordered]@{}
    foreach ($property in $Value.PSObject.Properties) {
        $copy[$property.Name] = if ($property.Name -eq $Field) { 'sha256:' + ('0' * 64) } else { $property.Value }
    }
    return Get-WorkforceObjectHash $copy
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-PowerPointExecutable {
    $candidates = [Collections.Generic.List[string]]::new()
    foreach ($key in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERPNT.EXE',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\POWERPNT.EXE'
    )) {
        if (Test-Path -LiteralPath $key) {
            $candidate = (Get-ItemProperty -LiteralPath $key -ErrorAction Stop).'(default)'
            if ($candidate) { $candidates.Add([string]$candidate) }
        }
    }
    $candidates.Add('C:\Program Files\Microsoft Office\Root\Office16\POWERPNT.EXE')
    $powerpoint = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $powerpoint) { throw 'Installed Microsoft PowerPoint was not found.' }
    $powerpoint = (Resolve-Path -LiteralPath $powerpoint).Path
    if ((Get-AuthenticodeSignature -LiteralPath $powerpoint).Status -ne 'Valid') {
        throw 'POWERPNT.EXE Authenticode signature is invalid.'
    }
    $excel = Join-Path (Split-Path -Parent $powerpoint) 'EXCEL.EXE'
    if (-not (Test-Path -LiteralPath $excel -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $excel).Status -ne 'Valid') {
        throw 'PowerPoint chart Excel executable is missing or unsigned.'
    }
    return $powerpoint
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
    if (-not $Office400EvidenceRoot -or -not (Test-Path -LiteralPath $Office400EvidenceRoot -PathType Container)) {
        throw 'Office400EvidenceRoot must identify sealed OFFICE-400 evidence.'
    }
    $script:Office400EvidenceRoot = (Resolve-Path -LiteralPath $Office400EvidenceRoot).Path
    $finishedPath = Join-Path $Office400EvidenceRoot 'finished.json'
    $certificationPath = Join-Path $Office400EvidenceRoot 'execution/certification.json'
    $publicKeyPath = Join-Path $Office400EvidenceRoot 'execution/certification-public-key.hex'
    foreach ($path in @($finishedPath, $certificationPath, $publicKeyPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "OFFICE-400 evidence is missing: $path" }
    }
    Invoke-Cargo 'office450-build-predecessor-verifier' @(
        'build', '--locked', '--release', '-p', 'd2i-presentation-capability', '--bin', 'd2i-presentation'
    )
    Invoke-NativeStep 'office450-verify-predecessor-completion' (Join-Path $cargoTargetRoot 'release/d2i-presentation.exe') @(
        'completion', 'verify', '--input', $finishedPath
    )
    Invoke-NativeStep 'office450-verify-predecessor-certification' (Join-Path $cargoTargetRoot 'release/d2i-presentation.exe') @(
        'certification', 'verify', '--input', $certificationPath, '--public-key', $publicKeyPath
    )
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    if (-not $finished.complete -or $finished.residual.powerpoint_processes -ne 0 -or
        $finished.residual.chart_excel_processes -ne 0 -or $finished.residual.workers -ne 0 -or
        $finished.residual.wfp_objects -ne 0 -or $finished.residual.profiles -ne 0) {
        throw 'OFFICE-400 predecessor is not a clean sealed Completion.'
    }
    return [string]$finished.finished_sha256
}

function Invoke-Contract {
    Invoke-Cargo 'office450-contract' @('test', '--locked', '-p', 'd2i-design-intelligence', '--all-features')
}

function Invoke-Schema {
    Invoke-NativeStep 'office450-schema' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-design-intelligence-schemas.ps1'), '-Check'
    )
}

function Invoke-Desktop {
    Invoke-Cargo 'office450-desktop' @('test', '--locked', '-p', 'd2i-desktop', '--test', 'design_work', '--all-features')
}

function Invoke-ContractTest([string]$Label, [string]$Filter) {
    Invoke-Cargo $Label @('test', '--locked', '-p', 'd2i-design-intelligence', '--all-features', $Filter)
}

function Invoke-DesktopTest([string]$Label, [string]$Filter) {
    Invoke-Cargo $Label @('test', '--locked', '-p', 'd2i-desktop', '--test', 'design_work', '--all-features', $Filter)
}

function Invoke-Regression {
    Invoke-Cargo 'office450-office100' @('test', '--locked', '-p', 'd2i-office-capability', '--all-features')
    Invoke-Cargo 'office450-office200' @('test', '--locked', '-p', 'd2i-document-capability', '--all-features')
    Invoke-Cargo 'office450-office300' @('test', '--locked', '-p', 'd2i-spreadsheet-capability', '--all-features')
    Invoke-Cargo 'office450-office400' @('test', '--locked', '-p', 'd2i-presentation-capability', '--all-features')
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
}

function Invoke-All {
    Invoke-RunnerSelfTest
    Invoke-Contract
    Invoke-Schema
    Invoke-Desktop
    Invoke-Regression
}

function Invoke-Model {
    Assert-PinnedModel
    if ($Resume -and (Test-Path -LiteralPath $modelReportPath -PathType Leaf)) {
        $report = Get-Content -Raw -LiteralPath $modelReportPath -Encoding UTF8 | ConvertFrom-Json
        if ($report.report_sha256 -ne (Get-WithZeroHashField $report 'report_sha256') -or
            $report.model_artifact_sha256 -ne (Get-WorkforceFileHash $Model) -or
            $report.runtime_artifact_sha256 -ne (Get-WorkforceFileHash $Runtime) -or
            -not $report.complete -or $report.model_invocation_count -lt 1 -or
            $report.model_invocation_count -ne $report.language_or_bounded_semantic_count -or
            $report.raw_corpus_count -ne 0 -or $report.raw_xml_count -ne 0 -or
            $report.raw_coordinate_count -ne 0 -or $report.raw_color_count -ne 0 -or
            $report.raw_font_count -ne 0 -or $report.raw_font_size_count -ne 0 -or
            $report.layout_execution_authority_count -ne 0) {
            throw 'Refusing to reuse stale or non-language-only Qwen evidence.'
        }
        Write-Output "Reusing verified OFFICE-450 model evidence: $modelReportPath"
        return
    }
    if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
    Invoke-Cargo 'office450-build-model' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office450-model-e2e'
    )
    Invoke-NativeStep 'office450-model' (Join-Path $cargoTargetRoot 'release/d2i-office450-model-e2e.exe') @(
        $Runtime, $Model, $modelReportPath
    )
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated session for exact WFP/private-desktop PowerPoint rendering.'
    }
    $predecessor = Assert-Predecessor
    Assert-PinnedModel
    $powerpoint = Resolve-PowerPointExecutable
    Invoke-All
    Invoke-Model
    if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
    Invoke-Cargo 'office450-build-completion' @(
        'build', '--locked', '--release', '-p', 'd2i-design-intelligence', '--bin', 'd2i-design'
    )
    Invoke-Cargo 'office450-build-e2e' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office450-design-e2e'
    )
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    Invoke-NativeStep 'office450-completion' (Join-Path $cargoTargetRoot 'release/d2i-office450-design-e2e.exe') @(
        $executionRoot, $powerpoint, $modelReportPath, $predecessor, $sourceTree
    )
    Invoke-NativeStep 'office450-verify-completion' (Join-Path $cargoTargetRoot 'release/d2i-design.exe') @(
        'completion', 'verify', '--input', (Join-Path $executionRoot 'finished.json')
    )
    Invoke-NativeStep 'office450-verify-replay' (Join-Path $cargoTargetRoot 'release/d2i-design.exe') @(
        'replay', 'verify', '--input', (Join-Path $executionRoot 'replay-report.json')
    )
    Invoke-NativeStep 'office450-verify-certification' (Join-Path $cargoTargetRoot 'release/d2i-design.exe') @(
        'certification', 'verify', '--input', (Join-Path $executionRoot 'certification.json'),
        '--public-key', (Join-Path $executionRoot 'certification-public-key.hex')
    )
    $finished = Get-Content -Raw -LiteralPath (Join-Path $executionRoot 'finished.json') -Encoding UTF8 | ConvertFrom-Json
    if (-not $finished.complete -or $finished.source_tree_sha256 -ne $sourceTree -or
        $finished.residual.powerpoint_processes -ne 0 -or $finished.residual.excel_processes -ne 0 -or
        $finished.residual.design_workers -ne 0 -or $finished.residual.model_workers -ne 0 -or
        $finished.residual.wfp_objects -ne 0 -or $finished.residual.profiles -ne 0) {
        throw 'OFFICE-450 terminal report or residual-state gate differs.'
    }
    Copy-Item -LiteralPath (Join-Path $executionRoot 'finished.json') -Destination (Join-Path $OutputRoot 'finished.json') -Force
    Write-Output "D2I OFFICE-450 Completion complete: $OutputRoot"
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'Corpus' { Invoke-ContractTest 'office450-corpus' 'same_corpus_compiles_to_same_pack_hash' }
    'Features' { Invoke-Desktop }
    'PptDesignExtraction' { Invoke-DesktopTest 'office450-ppt-features' 'pptx_snapshot_extracts_normalized_design_features' }
    'HwpxDesignExtraction' { Invoke-DesktopTest 'office450-hwpx-features' 'hwpx_snapshot_extracts_structure_without_raw_xml' }
    'DocxDesignExtraction' { Invoke-DesktopTest 'office450-docx-features' 'docx_snapshot_extracts_structure_without_raw_xml' }
    'FamilyDiscovery' { Invoke-ContractTest 'office450-family' 'same_corpus_compiles_to_same_pack_hash' }
    'GrammarCompile' { Invoke-ContractTest 'office450-grammar' 'compiled_pack_keeps_table_chart_image_and_logo_policy_closed' }
    'ExemplarIndex' { Invoke-ContractTest 'office450-exemplar-index' 'exemplar_query_is_exact_deterministic_and_content_minimized' }
    'ExemplarQuery' { Invoke-ContractTest 'office450-exemplar-query' 'exemplar_query_is_exact_deterministic_and_content_minimized' }
    'Typography' { Invoke-ContractTest 'office450-typography' 'typography_uses_only_approved_installed_fallback' }
    'Layout' { Invoke-ContractTest 'office450-layout' 'layout_solver_is_deterministic_and_exactly_pack_bound' }
    'Table' { Invoke-ContractTest 'office450-table' 'compiled_pack_keeps_table_chart_image_and_logo_policy_closed' }
    'Chart' { Invoke-ContractTest 'office450-chart' 'compiled_pack_keeps_table_chart_image_and_logo_policy_closed' }
    'Image' { Invoke-ContractTest 'office450-image' 'compiled_pack_keeps_table_chart_image_and_logo_policy_closed' }
    'Logo' { Invoke-ContractTest 'office450-logo' 'compiled_pack_keeps_table_chart_image_and_logo_policy_closed' }
    'HardCritic' { Invoke-ContractTest 'office450-hard-critic' 'critic_detects_bad_design_and_emits_bounded_closed_repairs' }
    'SoftCritic' { Invoke-ContractTest 'office450-soft-critic' 'critic_detects_bad_design_and_emits_bounded_closed_repairs' }
    'RunnerSelfTest' { Invoke-RunnerSelfTest }
    'Regression' { Invoke-Regression }
    'PptRender' { Resolve-PowerPointExecutable | Write-Output }
    'HwpxConformance' { Invoke-DesktopTest 'office450-hwpx-conformance' 'hwpx_snapshot_extracts_structure_without_raw_xml' }
    'Refinement' { Invoke-ContractTest 'office450-refinement' 'critic_detects_bad_design_and_emits_bounded_closed_repairs' }
    'MultiTenant' { Invoke-DesktopTest 'office450-multi-tenant' 'mixed_organization_features_fail_closed' }
    'Negative' { Invoke-Contract }
    'CrashRecovery' { Invoke-ContractTest 'office450-recovery' 'replay_requires_128_by_100_and_is_hash_stable' }
    'Replay' { Invoke-ContractTest 'office450-replay' 'replay_requires_128_by_100_and_is_hash_stable' }
    'Model' { Invoke-Model }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}
