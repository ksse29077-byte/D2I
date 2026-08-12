[CmdletBinding()]
param(
    [ValidateSet(
        'Contract', 'Schema', 'Disclosure', 'UrlAdmission', 'NetworkProfile', 'Fetch',
        'Redirect', 'DnsDefense', 'Discovery', 'SearchPortal', 'HtmlExtraction', 'Snapshot',
        'Evidence', 'Sufficiency', 'BrowserDiscovery', 'BrowserSnapshot', 'Download',
        'AttachmentTrust', 'FormatValidation', 'Promotion', 'Model', 'ModelFree', 'Negative',
        'PromptInjection', 'Ssrf', 'CrashRecovery', 'Replay', 'Regression', 'RunnerSelfTest',
        'Completion', 'All'
    )]
    [string]$Mode = 'All',
    [string]$Runtime,
    [string]$Model,
    [string]$Office500EvidenceRoot,
    [string]$Edge,
    [string]$EdgeDriver,
    [string]$ExternalCanaryUrl = 'https://www.microsoft.com/robots.txt',
    [string]$ExternalDownloadCanaryUrl = 'https://www.w3.org/robots.txt',
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
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office600-browser-research' }
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
        throw "Refusing to remove a path outside OFFICE-600 OutputRoot: $resolved"
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

function Resolve-EdgeArtifacts {
    if (-not $Edge) {
        $Edge = @(
            'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
            'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
        ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    }
    if (-not $EdgeDriver) {
        $driverCommand = Get-Command 'msedgedriver.exe' -ErrorAction SilentlyContinue
        if ($driverCommand) { $EdgeDriver = $driverCommand.Source }
    }
    if (-not $Edge -or -not (Test-Path -LiteralPath $Edge -PathType Leaf)) {
        throw 'Edge must identify the installed Microsoft Edge executable.'
    }
    if (-not $EdgeDriver -or -not (Test-Path -LiteralPath $EdgeDriver -PathType Leaf)) {
        throw 'EdgeDriver must identify a version-compatible msedgedriver.exe.'
    }
    $script:Edge = (Resolve-Path -LiteralPath $Edge).Path
    $script:EdgeDriver = (Resolve-Path -LiteralPath $EdgeDriver).Path
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
    if (-not $Office500EvidenceRoot -or -not (Test-Path -LiteralPath $Office500EvidenceRoot -PathType Container)) {
        throw 'Office500EvidenceRoot must identify sealed OFFICE-500 evidence.'
    }
    $script:Office500EvidenceRoot = (Resolve-Path -LiteralPath $Office500EvidenceRoot).Path
    $finishedPath = @(
        (Join-Path $Office500EvidenceRoot 'finished.json'),
        (Join-Path $Office500EvidenceRoot 'execution/finished.json')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    $certificationPath = Join-Path $Office500EvidenceRoot 'execution/certification.json'
    $publicKeyPath = Join-Path $Office500EvidenceRoot 'execution/certification-public-key.hex'
    foreach ($path in @($finishedPath, $certificationPath, $publicKeyPath)) {
        if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "OFFICE-500 evidence is missing: $path"
        }
    }
    Invoke-Cargo 'office600-build-predecessor-verifier' @(
        'build', '--locked', '--release', '-p', 'd2i-pdf-interchange', '--bin', 'd2i-pdf-interchange'
    )
    Invoke-NativeStep 'office600-verify-predecessor-completion' (Join-Path $cargoTargetRoot 'release/d2i-pdf-interchange.exe') @(
        'completion', 'verify', '--input', $finishedPath
    )
    Invoke-NativeStep 'office600-verify-predecessor-certification' (Join-Path $cargoTargetRoot 'release/d2i-pdf-interchange.exe') @(
        'certification', 'verify-archived', '--input', $certificationPath, '--public-key', $publicKeyPath
    )
    $finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
    $certification = Get-Content -Raw -LiteralPath $certificationPath -Encoding UTF8 | ConvertFrom-Json
    if (-not $finished.complete -or
        $certification.completion_report_sha256 -ne $finished.finished_sha256) {
        throw 'OFFICE-500 predecessor is not complete or its certification binding differs.'
    }
    return [string]$finished.finished_sha256
}

function Invoke-Contract([string]$Filter = '') {
    $arguments = @('test', '--locked', '-p', 'd2i-browser-research', '--all-features')
    if ($Filter) { $arguments += $Filter }
    Invoke-Cargo "office600-contract-$($Filter -replace '[^A-Za-z0-9]', '-')" $arguments
}

function Invoke-Schema {
    Invoke-NativeStep 'office600-schema' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/generate-browser-research-schemas.ps1'), '-Check'
    )
}

function Invoke-Regression {
    foreach ($package in @(
        'd2i-office-capability', 'd2i-document-capability', 'd2i-spreadsheet-capability',
        'd2i-presentation-capability', 'd2i-design-intelligence', 'd2i-pdf-interchange'
    )) {
        Invoke-Cargo "office600-regression-$package" @('test', '--locked', '-p', $package, '--all-features')
    }
}

function Invoke-RunnerSelfTest {
    $probe = Join-Path $OutputRoot '.runner-self-test'
    if (Test-Path -LiteralPath $probe) { Remove-OwnedDirectory $probe }
    New-Item -ItemType Directory -Path $probe | Out-Null
    Remove-OwnedDirectory $probe
    $outside = Join-Path $targetRoot 'd2i-office600-runner-outside-probe'
    New-Item -ItemType Directory -Path $outside -Force | Out-Null
    $rejected = $false
    try { Remove-OwnedDirectory $outside }
    catch { $rejected = $true }
    finally { Remove-Item -LiteralPath $outside -Force }
    if (-not $rejected) { throw 'Runner ownership self-test accepted an outside path.' }
    $closedModes = @(
        'Contract', 'Schema', 'Disclosure', 'UrlAdmission', 'NetworkProfile', 'Fetch',
        'Redirect', 'DnsDefense', 'Discovery', 'SearchPortal', 'HtmlExtraction', 'Snapshot',
        'Evidence', 'Sufficiency', 'BrowserDiscovery', 'BrowserSnapshot', 'Download',
        'AttachmentTrust', 'FormatValidation', 'Promotion', 'Model', 'ModelFree', 'Negative',
        'PromptInjection', 'Ssrf', 'CrashRecovery', 'Replay', 'Regression', 'RunnerSelfTest',
        'Completion', 'All'
    )
    if ($closedModes.Count -ne 31 -or ($closedModes | Sort-Object -Unique).Count -ne 31) {
        throw 'Runner mode allowlist is not closed and unique.'
    }
    Invoke-NativeStep 'office600-policy-wrapper-self-test' 'powershell' @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/invoke-office600-certified-completion.ps1'),
        '-Mode', 'SelfTest', '-OutputRoot', (Join-Path $OutputRoot '.policy-wrapper-self-test')
    )
}

function Invoke-Model {
    Assert-PinnedModel
    if ($Resume -and (Test-Path -LiteralPath $modelReportPath -PathType Leaf)) {
        $report = Get-Content -Raw -LiteralPath $modelReportPath -Encoding UTF8 | ConvertFrom-Json
        if ($report.complete -and $report.model_invocation_count -ge 2 -and
            $report.model_artifact_sha256 -eq (Get-WorkforceFileHash $Model) -and
            $report.runtime_artifact_sha256 -eq (Get-WorkforceFileHash $Runtime) -and
            $report.raw_html_count -eq 0 -and $report.raw_url_count -eq 0 -and
            $report.raw_download_count -eq 0 -and $report.network_authority_count -eq 0 -and
            $report.workspace_promotion_authority_count -eq 0 -and
            $report.provider_network_policy_denied -and
            $report.model_appcontainer_profile_removed -and
            $report.residual_model_worker_count -eq 0) {
            Write-Output "Reusing verified OFFICE-600 model evidence: $modelReportPath"
            return
        }
        throw 'Refusing to resume with stale OFFICE-600 model evidence.'
    }
    if (Test-Path -LiteralPath $modelReportPath) { Remove-Item -LiteralPath $modelReportPath -Force }
    Invoke-Cargo 'office600-build-model' @(
        'build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office600-model-e2e'
    )
    Invoke-NativeStep 'office600-model' (Join-Path $cargoTargetRoot 'release/d2i-office600-model-e2e.exe') @(
        $Runtime, $Model, $modelReportPath
    )
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
    Invoke-Cargo 'office600-windows-host' @('test', '--locked', '-p', 'd2i-windows-host', '--all-features')
    Invoke-Cargo 'office600-desktop-library' @('test', '--locked', '-p', 'd2i-desktop', '--lib', '--all-features')
}

function Invoke-Completion {
    if (-not (Test-IsAdministrator)) {
        throw 'Completion requires one elevated session for exact Edge WFP enforcement.'
    }
    Resolve-EdgeArtifacts
    Assert-PinnedModel
    $predecessor = Assert-Predecessor
    Invoke-RunnerSelfTest
    Invoke-Contract
    Invoke-Schema
    Invoke-Regression
    Invoke-Model
    if ($Resume -and (Test-Path -LiteralPath (Join-Path $executionRoot 'finished.json') -PathType Leaf)) {
        Invoke-Cargo 'office600-build-contract-verifier' @(
            'build', '--locked', '--release', '-p', 'd2i-browser-research', '--bin', 'd2i-browser-research'
        )
        Invoke-NativeStep 'office600-verify-resumed-completion' (Join-Path $cargoTargetRoot 'release/d2i-browser-research.exe') @(
            'validate-completion', (Join-Path $executionRoot 'finished.json')
        )
        Write-Output "Reused verified OFFICE-600 Completion: $executionRoot"
        return
    }
    if (Test-Path -LiteralPath $executionRoot) { Remove-OwnedDirectory $executionRoot }
    Invoke-Cargo 'office600-build-completion' @(
        'build', '--locked', '--release', '-p', 'd2i-browser-research', '--bin', 'd2i-browser-research',
        '-p', 'd2i-desktop', '--bin', 'd2i-office600-network-worker', '--bin', 'd2i-office600-completion-e2e'
    )
    $sourceTree = Get-WorkforceSourceTreeHash -RepositoryRoot $repoRoot
    Invoke-NativeStep 'office600-completion' (Join-Path $cargoTargetRoot 'release/d2i-office600-completion-e2e.exe') @(
        $executionRoot,
        (Join-Path $cargoTargetRoot 'release/d2i-office600-network-worker.exe'),
        $Edge, $EdgeDriver, $modelReportPath, $Office500EvidenceRoot,
        $predecessor, $sourceTree, $ExternalCanaryUrl, $ExternalDownloadCanaryUrl
    )
    $verifier = Join-Path $cargoTargetRoot 'release/d2i-browser-research.exe'
    Invoke-NativeStep 'office600-verify-completion' $verifier @(
        'validate-completion', (Join-Path $executionRoot 'finished.json')
    )
    Invoke-NativeStep 'office600-verify-replay' $verifier @(
        'validate-replay', (Join-Path $executionRoot 'replay-report.json')
    )
    Invoke-NativeStep 'office600-verify-certification' $verifier @(
        'validate-certification', (Join-Path $executionRoot 'certification.json'),
        (Join-Path $executionRoot 'certification-public-key.hex')
    )
    $finished = Get-Content -Raw -LiteralPath (Join-Path $executionRoot 'finished.json') -Encoding UTF8 | ConvertFrom-Json
    Assert-ZeroMetricObject $finished.security 'OFFICE-600 security'
    Assert-ZeroMetricObject $finished.residual 'OFFICE-600 residual'
    if (-not $finished.complete -or $finished.source_tree_sha256 -ne $sourceTree -or
        $finished.research_case_count -lt 24 -or $finished.routine_case_count -lt 14 -or
        $finished.security_negative_case_count -lt 10 -or $finished.external_origin_count -lt 2 -or
        $finished.snapshot_page_count -lt 5 -or $finished.actual_qwen_invocation_count -lt 2 -or
        $finished.actual_download_count -lt 1 -or $finished.promoted_artifact_count -lt 1 -or
        $finished.crash_window_count -ne 14 -or -not $finished.browser_loopback_only_evidence -or
        $finished.protected_audit_record_count -lt 16 -or
        -not $finished.network_worker_sole_egress_evidence -or -not $finished.attachment_trust_evidence -or
        -not $finished.workspace_promotion_evidence -or -not $finished.model_free_research_evidence) {
        throw 'OFFICE-600 terminal report gate differs.'
    }
    Copy-Item -LiteralPath (Join-Path $executionRoot 'finished.json') -Destination (Join-Path $OutputRoot 'finished.json') -Force
    Write-Output "D2I OFFICE-600 Completion complete: $OutputRoot"
}

switch ($Mode) {
    'Contract' { Invoke-Contract }
    'Schema' { Invoke-Schema }
    'Disclosure' { Invoke-Contract 'public_only_disclosure_gate_blocks_internal_query' }
    'UrlAdmission' { Invoke-Contract 'url_admission_rejects_scheme_userinfo_localhost_ip_and_mixed_dns' }
    'NetworkProfile' { Invoke-Contract 'public_only_disclosure_gate_blocks_internal_query' }
    'Fetch' { Invoke-Contract 'network_worker_authorization_is_one_shot_hash_and_time_bound' }
    'Redirect' { Invoke-Contract 'redirect_requires_fresh_admission_and_never_downgrades' }
    'DnsDefense' { Invoke-Contract 'connected_remote_must_equal_fresh_admitted_public_address' }
    'Discovery' { Invoke-Contract 'discovery_snippets_remain_non_evidence_hints' }
    'SearchPortal' { Invoke-Contract 'discovery_snippets_remain_non_evidence_hints' }
    'HtmlExtraction' { Invoke-Contract 'safe_snapshot_removes_active_content_and_raw_urls' }
    'Snapshot' { Invoke-Contract 'safe_snapshot_removes_active_content_and_raw_urls' }
    'Evidence' { Invoke-Contract 'evidence_synthesis_is_bounded_cited_and_number_grounded' }
    'Sufficiency' { Invoke-Contract 'evidence_synthesis_is_bounded_cited_and_number_grounded' }
    'BrowserDiscovery' { Invoke-Contract 'snapshot_server_exposes_only_closed_loopback_routes_and_records_selection' }
    'BrowserSnapshot' { Invoke-Contract 'snapshot_server_exposes_only_closed_loopback_routes_and_records_selection' }
    'Download' { Invoke-Contract 'controlled_download_rejects_filename_and_magic_attacks' }
    'AttachmentTrust' { Invoke-Cargo 'office600-attachment-trust' @('check', '--locked', '-p', 'd2i-windows-host', '--all-features') }
    'FormatValidation' { Invoke-Contract 'controlled_text_download_can_pass_parser_gate' }
    'Promotion' { Invoke-Contract 'promotion_requires_enable_trust_and_passed_validation' }
    'Model' { Invoke-Model }
    'ModelFree' { Invoke-Contract 'evidence_synthesis_is_bounded_cited_and_number_grounded' }
    'Negative' { Invoke-Contract 'controlled_download_rejects_filename_and_magic_attacks' }
    'PromptInjection' { Invoke-Contract 'prompt_injection_cannot_become_a_claim' }
    'Ssrf' { Invoke-Contract 'url_admission_rejects_private_and_special_destinations' }
    'CrashRecovery' { Invoke-Contract 'recovery_matrix_is_closed_and_side_effect_aware' }
    'Replay' { Invoke-Contract 'replay_gate_requires_exact_logical_matrix' }
    'Regression' { Invoke-Regression }
    'RunnerSelfTest' { Invoke-RunnerSelfTest }
    'Completion' { Invoke-Completion }
    'All' { Invoke-All }
}
