[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9]+(?:-[a-z0-9]+)*$')]
    [string]$ModuleId
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$templateRoot = Join-Path $repoRoot 'templates/cognitive-module'
$destination = Join-Path $repoRoot "modules/$ModuleId"
$rootLockPath = Join-Path $repoRoot 'Cargo.lock'
$rootLockBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash

if (Test-Path -LiteralPath $destination) {
    throw "module directory already exists: modules/$ModuleId"
}
if (-not (Test-Path -LiteralPath $templateRoot -PathType Container)) {
    throw 'cognitive module template is missing'
}

try {
    Copy-Item -LiteralPath $templateRoot -Destination $destination -Recurse

    $underscoreId = $ModuleId.Replace('-', '_')
    $textFiles = @(
        Get-ChildItem -LiteralPath $destination -File -Recurse |
            Where-Object {
                $_.Extension -in @(
                    '.json',
                    '.md',
                    '.ref',
                    '.rs',
                    '.toml',
                    '.yaml'
                ) -or $_.Name -eq 'Cargo.lock'
            }
    )
    foreach ($file in $textFiles) {
        $content = [IO.File]::ReadAllText($file.FullName)
        $content = $content.Replace('d2i_example_module', "d2i_$underscoreId")
        $content = $content.Replace('example-module', $ModuleId)
        [IO.File]::WriteAllText($file.FullName, $content, [Text.UTF8Encoding]::new($false))
    }

    $oldArtifactPath = Join-Path $destination 'artifacts/example-module.ref'
    $artifactPath = Join-Path $destination "artifacts/$ModuleId.ref"
    if (Test-Path -LiteralPath $oldArtifactPath) {
        Move-Item -LiteralPath $oldArtifactPath -Destination $artifactPath
    }
    elseif (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw 'template artifact was not created'
    }

    $manifestPath = Join-Path $destination 'module-manifest.yaml'
    $manifest = [IO.File]::ReadAllText($manifestPath)
    $oldArtifactHash = [regex]::Match(
        $manifest,
        '(?m)^\s*artifact_sha256:\s*(?<hash>sha256:[0-9a-f]{64})\s*$'
    ).Groups['hash'].Value
    $oldSchemaHashes = @(
        [regex]::Matches(
            $manifest,
            '(?m)^\s*sha256:\s*(?<hash>sha256:[0-9a-f]{64})\s*$'
        ) | ForEach-Object { $_.Groups['hash'].Value }
    )
    if (-not $oldArtifactHash -or $oldSchemaHashes.Count -ne 2) {
        throw 'template manifest hash fields are not in the expected form'
    }

    $artifactHash = 'sha256:' + (
        Get-FileHash -Algorithm SHA256 -LiteralPath $artifactPath
    ).Hash.ToLowerInvariant()
    $inputHash = 'sha256:' + (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath (Join-Path $destination 'schemas/input.schema.json')
    ).Hash.ToLowerInvariant()
    $outputHash = 'sha256:' + (
        Get-FileHash `
            -Algorithm SHA256 `
            -LiteralPath (Join-Path $destination 'schemas/output.schema.json')
    ).Hash.ToLowerInvariant()
    $manifest = $manifest.Replace($oldArtifactHash, $artifactHash)
    $manifest = $manifest.Replace($oldSchemaHashes[0], $inputHash)
    $manifest = $manifest.Replace($oldSchemaHashes[1], $outputHash)
    [IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($false))
    $manifestValidationOutput = @(
        cargo run `
            --locked `
            --quiet `
            --manifest-path (Join-Path $repoRoot 'Cargo.toml') `
            -p d2i-cli `
            -- module validate --json $destination
    )
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot validate the generated module manifest'
    }
    try {
        $manifestValidation = (
            $manifestValidationOutput -join [Environment]::NewLine
        ) | ConvertFrom-Json
    }
    catch {
        throw 'generated module manifest validation did not return JSON'
    }
    $manifestHash = [string]$manifestValidation.manifest_sha256
    if (
        $manifestValidation.status -ne 'pass' -or
        $manifestHash -notmatch '^sha256:[0-9a-f]{64}$'
    ) {
        throw 'generated module manifest validation did not return a canonical hash'
    }

    foreach ($fixture in Get-ChildItem -LiteralPath (Join-Path $destination 'fixtures') -Filter '*.json' -File -Recurse) {
        $content = [IO.File]::ReadAllText($fixture.FullName)
        $content = $content.Replace($oldArtifactHash, $artifactHash)
        $content = [regex]::Replace(
            $content,
            '("manifest_sha256"\s*:\s*")sha256:[0-9a-f]{64}(")',
            "`${1}$manifestHash`${2}"
        )
        [IO.File]::WriteAllText($fixture.FullName, $content, [Text.UTF8Encoding]::new($false))
    }

    $cargoManifestPath = Join-Path $destination 'Cargo.toml'
    cargo fmt --manifest-path $cargoManifestPath --all
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot format the generated standalone module'
    }

    Remove-Item -LiteralPath (Join-Path $destination 'Cargo.lock') -Force -ErrorAction SilentlyContinue
    cargo generate-lockfile --manifest-path $cargoManifestPath
    if ($LASTEXITCODE -ne 0) {
        throw 'cannot generate the module-local Cargo.lock'
    }
    $rootLockAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $rootLockPath).Hash
    if ($rootLockBefore -ne $rootLockAfter) {
        throw 'new-module modified the root Cargo.lock'
    }
}
catch {
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    throw
}

Write-Output "Created standalone module directory modules/$ModuleId."
Write-Output "Run scripts/modules/check-module.ps1 -ModulePath modules/$ModuleId."
