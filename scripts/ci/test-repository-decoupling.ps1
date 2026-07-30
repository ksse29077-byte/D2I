[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$temporaryRoot = Join-Path $env:TEMP "d2i-decoupling-concurrency-$PID"

function Invoke-Git([string[]]$Arguments) {
    & git -C $temporaryRoot @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed"
    }
}

try {
    New-Item -ItemType Directory -Path $temporaryRoot -Force | Out-Null
    Invoke-Git @('init', '--initial-branch=main')
    Invoke-Git @('config', 'user.name', 'D2I Concurrency Test')
    Invoke-Git @('config', 'user.email', 'd2i-concurrency@example.invalid')

    [IO.File]::WriteAllText(
        (Join-Path $temporaryRoot 'Cargo.toml'),
        "[workspace]`nmembers = []`nexclude = [`"modules/*`"]`n"
    )
    [IO.File]::WriteAllText((Join-Path $temporaryRoot 'Cargo.lock'), "# root lock`n")
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'modules') | Out-Null
    Invoke-Git @('add', 'Cargo.toml', 'Cargo.lock')
    Invoke-Git @('commit', '-m', 'base')
    $base = (& git -C $temporaryRoot rev-parse HEAD).Trim()
    $rootLockHash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $temporaryRoot 'Cargo.lock')).Hash

    Invoke-Git @('switch', '-c', 'module/101-alpha')
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'modules/alpha') | Out-Null
    [IO.File]::WriteAllText((Join-Path $temporaryRoot 'modules/alpha/Cargo.toml'), "[workspace]`nmembers = [`".`"]`n")
    [IO.File]::WriteAllText((Join-Path $temporaryRoot 'modules/alpha/Cargo.lock'), "# alpha lock`n")
    Invoke-Git @('add', 'modules/alpha')
    Invoke-Git @('commit', '-m', 'add alpha module')
    $alpha = (& git -C $temporaryRoot rev-parse HEAD).Trim()

    Invoke-Git @('switch', '--detach', $base)
    Invoke-Git @('switch', '-c', 'module/102-beta')
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'modules/beta') | Out-Null
    [IO.File]::WriteAllText((Join-Path $temporaryRoot 'modules/beta/Cargo.toml'), "[workspace]`nmembers = [`".`"]`n")
    [IO.File]::WriteAllText((Join-Path $temporaryRoot 'modules/beta/Cargo.lock'), "# beta lock`n")
    Invoke-Git @('add', 'modules/beta')
    Invoke-Git @('commit', '-m', 'add beta module')
    $beta = (& git -C $temporaryRoot rev-parse HEAD).Trim()

    $alphaPaths = @(git -C $temporaryRoot diff --name-only "$base...$alpha")
    $betaPaths = @(git -C $temporaryRoot diff --name-only "$base...$beta")
    $intersection = @($alphaPaths | Where-Object { $_ -in $betaPaths })
    if ($intersection.Count -ne 0) {
        throw "independent module changes overlap: $($intersection -join ', ')"
    }

    Invoke-Git @('switch', 'main')
    Invoke-Git @('merge', '--ff-only', 'module/101-alpha')
    Invoke-Git @('switch', 'module/102-beta')
    Invoke-Git @('rebase', 'main')
    Invoke-Git @('switch', 'main')
    Invoke-Git @('merge', '--ff-only', 'module/102-beta')

    if (-not (Test-Path -LiteralPath (Join-Path $temporaryRoot 'modules/alpha/Cargo.lock')) -or
        -not (Test-Path -LiteralPath (Join-Path $temporaryRoot 'modules/beta/Cargo.lock'))) {
        throw 'sequential merge lost a module-local lockfile'
    }
    if ((Get-Content -Raw -LiteralPath (Join-Path $temporaryRoot 'modules/alpha/Cargo.lock')) -eq
        (Get-Content -Raw -LiteralPath (Join-Path $temporaryRoot 'modules/beta/Cargo.lock'))) {
        throw 'synthetic module locks are not independent'
    }
    $rootLockAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $temporaryRoot 'Cargo.lock')).Hash
    if ($rootLockHash -ne $rootLockAfter) {
        throw 'independent module merges changed root Cargo.lock'
    }

    Write-Output 'Independent module path, lockfile, merge, and rebase concurrency tests passed.'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
