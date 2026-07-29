[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$validator = Join-Path $PSScriptRoot 'validate-module-pr.ps1'
$head = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'cannot resolve repository HEAD'
}

& $validator `
    -BaseSha $head `
    -HeadSha $head `
    -BranchName 'docs/1-governance-test' `
    -ChangedFilesOverride 'docs/collaboration/README.md'
if ($LASTEXITCODE -ne 0) {
    throw 'non-module documentation changes should bypass module checks'
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
if (($output | Out-String) -notmatch 'Core-owned paths') {
    throw "Core-owned failure did not report the protected boundary: $output"
}

Write-Output 'Module PR governance negative test passed.'
exit 0
