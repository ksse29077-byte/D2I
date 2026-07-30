[CmdletBinding()]
param(
    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$BaseSha,

    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$HeadSha = 'HEAD',

    [string[]]$ChangedFilesOverride,

    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

if ($PSBoundParameters.ContainsKey('ChangedFilesOverride')) {
    $changedFiles = @($ChangedFilesOverride)
}
else {
    if (-not $BaseSha) {
        throw 'BaseSha is required when ChangedFilesOverride is not provided'
    }
    $changedFiles = @(
        git -C $repoRoot diff --name-only --diff-filter=ACDMRTUXB "$BaseSha...$HeadSha"
    )
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot enumerate changed files'
    }
}

$changedFiles = @(
    $changedFiles |
        ForEach-Object { $_.Trim().Replace('\', '/') } |
        Where-Object { $_ } |
        Sort-Object -Unique
)
$moduleFiles = @($changedFiles | Where-Object { $_ -match '^modules/[^/]+/' })
$moduleIds = @(
    $moduleFiles |
        ForEach-Object { ($_ -split '/')[1] } |
        Sort-Object -Unique
)
$nonModuleFiles = @($changedFiles | Where-Object { $_ -notmatch '^modules/[^/]+/' })
$contractPatterns = @(
    'Cargo.toml',
    'Cargo.lock',
    'crates/d2i-module-sdk/*',
    'crates/d2i-cognitive-ir/*',
    'schemas/cognitive/*',
    'schemas/modules/*',
    'docs/modules/*',
    'scripts/modules/*',
    'templates/cognitive-module/*'
)
$contractFiles = @(
    $nonModuleFiles |
        Where-Object {
            $path = $_
            @($contractPatterns | Where-Object { $path -like $_ }).Count -gt 0
        }
)

if ($moduleFiles.Count -gt 0 -and $nonModuleFiles.Count -eq 0 -and $moduleIds.Count -eq 1) {
    $classification = 'module_only'
}
elseif ($moduleFiles.Count -gt 0) {
    $classification = 'mixed_core_migration'
}
elseif ($contractFiles.Count -gt 0) {
    $classification = 'core_contract'
}
else {
    $classification = 'core_only'
}

$result = [ordered]@{
    schema_version = 1
    classification = $classification
    changed_files = $changedFiles
    module_ids = $moduleIds
    module_files = $moduleFiles
    non_module_files = $nonModuleFiles
    core_contract_files = $contractFiles
}

if ($Json) {
    $result | ConvertTo-Json -Depth 6
}
else {
    $result.classification
}
