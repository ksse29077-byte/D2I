param(
    [Parameter(Mandatory = $true)]
    [string]$Output
)

$ErrorActionPreference = "Stop"

$version = (& mojo --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    throw "Mojo 1.0.0b2 is required but the mojo executable is unavailable."
}
if ($version -notmatch "1\.0\.0b2") {
    throw "Mojo 1.0.0b2 is required; found '$version'."
}

& mojo build `
    --emit shared-lib `
    --optimization-level 3 `
    --Werror `
    "$PSScriptRoot\case_score.mojo" `
    -o $Output

if ($LASTEXITCODE -ne 0) {
    throw "Mojo score-kernel build failed."
}
