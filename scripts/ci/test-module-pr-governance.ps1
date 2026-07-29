[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$validator = Join-Path $PSScriptRoot 'validate-module-pr.ps1'
$coreValidator = Join-Path $PSScriptRoot 'validate-core-approval.ps1'
$head = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'cannot resolve repository HEAD'
}

& $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'docs/1-governance-test' `
    -ChangedFilesOverride 'docs/progress.md'
if ($LASTEXITCODE -ne 0) {
    throw 'non-module documentation changes should bypass module checks'
}

$goalCompilerCommit = (& git -C $repoRoot rev-parse d2b80a1).Trim()
$goalCompilerBase = (& git -C $repoRoot rev-parse "$goalCompilerCommit^").Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'cannot resolve the Goal Compiler module registration fixture'
}
& $validator `
    -BaseSha $goalCompilerBase `
    -HeadSha $goalCompilerCommit `
    -BranchName 'module/7-goal-compiler'
if ($LASTEXITCODE -ne 0) {
    throw 'a validated module-only PR must pass without human approval'
}

$engine = (Get-Process -Id $PID).Path
$ErrorActionPreference = 'Continue'
$output = & $engine `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'module/42-example-module' `
    -ChangedFilesOverride 'schemas/modules/module-manifest-v1.schema.json' 2>&1
$status = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($status -eq 0) {
    throw 'a module PR that changes a Core-owned schema must fail'
}
if (($output | Out-String) -notmatch 'Core-owned') {
    throw "Core-owned failure did not report the protected boundary: $output"
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
    -ApprovedReviewersOverride '__no_approval__' 2>&1
$status = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($status -eq 0) {
    throw 'a Core change without a current-head CODEOWNER approval must fail'
}
$coreFailure = (($output | Out-String) -replace '\s+', ' ')
foreach ($required in @(
    '.github/workflows/module-pr.yml',
    'non-author Core CODEOWNER',
    'docs/collaboration/core-change-control.md'
)) {
    if ($coreFailure -notmatch [regex]::Escape($required)) {
        throw "Core approval failure is missing '$required': $output"
    }
}

$ErrorActionPreference = 'Stop'
& $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride '.github/workflows/module-pr.yml' `
    -PullRequestAuthorOverride 'graykavinjeo' `
    -ApprovedReviewersOverride 'ksse29077-byte'
if ($LASTEXITCODE -ne 0) {
    throw 'the module workflow must accept a valid Core approval'
}

& $coreValidator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'core/99-governance-test' `
    -ChangedFilesOverride '.github/workflows/module-pr.yml' `
    -PullRequestAuthorOverride 'graykavinjeo' `
    -ApprovedReviewersOverride 'ksse29077-byte'
if ($LASTEXITCODE -ne 0) {
    throw 'trusted Core governance must accept a non-author CODEOWNER approval'
}

Write-Output 'Module-only and Core approval governance tests passed.'
exit 0
