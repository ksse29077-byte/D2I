[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$classifier = Join-Path $PSScriptRoot 'classify-change.ps1'
$validator = Join-Path $PSScriptRoot 'validate-module-pr.ps1'
$coreValidator = Join-Path $PSScriptRoot 'validate-core-approval.ps1'
$engine = (Get-Process -Id $PID).Path
$head = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'cannot resolve repository HEAD'
}

function Assert-Classification([string]$Expected, [string[]]$Files) {
    $result = & $classifier -ChangedFilesOverride $Files -Json | ConvertFrom-Json
    if ($result.classification -ne $Expected) {
        throw "expected classification '$Expected', got '$($result.classification)'"
    }
}

Assert-Classification 'module_only' @(
    'modules/example-module/src/lib.rs',
    'modules/example-module/Cargo.lock'
)
Assert-Classification 'core_only' @('crates/d2i-core/src/lib.rs')
Assert-Classification 'core_contract' @('crates/d2i-cognitive-ir/src/lib.rs')
Assert-Classification 'core_contract' @('Cargo.toml', 'Cargo.lock')
Assert-Classification 'mixed_core_migration' @(
    'crates/d2i-cognitive-ir/src/lib.rs',
    'modules/example-module/src/lib.rs'
)

& $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'module/42-example-module' `
    -ChangedFilesOverride 'modules/example-module/README.md'
if ($LASTEXITCODE -ne 0) {
    throw 'a valid standalone module-only change must pass'
}

try {
    & $validator `
        -BaseSha $head `
        -HeadSha $head `
        -BranchName 'module/42-example-module' `
        -ChangedFilesOverride @(
            'modules/example-module/README.md',
            'Cargo.lock'
        )
    throw 'a module branch that changes root Cargo.lock must fail'
}
catch {
    if ($_.Exception.Message -notmatch 'exactly one modules/<module-id>') {
        throw "module boundary failure was not actionable: $($_.Exception.Message)"
    }
}

& $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride @(
        'crates/d2i-cognitive-ir/src/lib.rs',
        'modules/example-module/src/lib.rs'
    )
if ($LASTEXITCODE -ne 0) {
    throw 'mixed Core migration must be delegated to Core workflows'
}

& $coreValidator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'module/42-example-module' `
    -ChangedFilesOverride 'modules/example-module/README.md'
if ($LASTEXITCODE -ne 0) {
    throw 'module-only changes must not require Core approval'
}

try {
    & $coreValidator `
        -BaseSha $head `
        -HeadSha $head `
        -BranchName 'core/99-governance-test' `
        -ChangedFilesOverride '.github/workflows/module-pr.yml' `
        -PullRequestAuthorOverride 'graykavinjeo' `
        -ApprovedReviewersOverride '__no_approval__'
    throw 'a Core change without non-author CODEOWNER approval must fail'
}
catch {
    $failure = ($_.Exception.Message -replace '\s+', ' ')
    foreach ($required in @(
        '.github/workflows/module-pr.yml',
        'non-author Core CODEOWNER',
        'docs/collaboration/core-change-control.md'
    )) {
        if ($failure -notmatch [regex]::Escape($required)) {
            throw "Core approval failure is missing '$required': $failure"
        }
    }
}

& $coreValidator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride '.github/workflows/module-pr.yml' `
    -PullRequestAuthorOverride 'graykavinjeo' `
    -ApprovedReviewersOverride @('__stale__', 'ksse29077-byte')
if ($LASTEXITCODE -ne 0) {
    throw 'trusted Core governance must accept a non-author CODEOWNER approval'
}

$staleApproval = [pscustomobject]@{
    commit_id = '0000000000000000000000000000000000000000'
    state = 'APPROVED'
    submitted_at = '2026-01-01T00:00:00Z'
    user = [pscustomobject]@{ login = 'ksse29077-byte' }
}
$currentApproval = [pscustomobject]@{
    commit_id = $head
    state = 'APPROVED'
    submitted_at = '2026-01-01T00:01:00Z'
    user = [pscustomobject]@{ login = 'ksse29077-byte' }
}
& $coreValidator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride '.github/workflows/module-pr.yml' `
    -PullRequestAuthorOverride 'graykavinjeo' `
    -ReviewRecordsOverride @($staleApproval, $currentApproval)
if ($LASTEXITCODE -ne 0) {
    throw 'trusted Core governance must enumerate stale and current-head review records'
}

$currentChangeRequest = [pscustomobject]@{
    commit_id = $head
    state = 'CHANGES_REQUESTED'
    submitted_at = '2026-01-01T00:02:00Z'
    user = [pscustomobject]@{ login = 'ksse29077-byte' }
}
$ErrorActionPreference = 'Continue'
$output = & $engine `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $coreValidator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride '.github/workflows/module-pr.yml' `
    -PullRequestAuthorOverride 'graykavinjeo' `
    -ReviewRecordsOverride @($currentApproval, $currentChangeRequest) 2>&1
$status = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($status -eq 0) {
    throw 'a later current-head change request must supersede approval'
}

Write-Output 'Change classification, module scope, and Core approval governance tests passed.'
exit 0
