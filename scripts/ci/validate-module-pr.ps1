[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$BaseSha,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{7,40}$')]
    [string]$HeadSha,

    [Parameter(Mandatory = $true)]
    [string]$BranchName,

    [switch]$VerifyGitHubIssue,

    [string[]]$ChangedFilesOverride
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $repoRoot

function Fail([string]$Message) {
    throw "module-pr validation failed: $Message"
}

function Invoke-Checked([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "'$FilePath $($Arguments -join ' ')' exited with $LASTEXITCODE"
    }
}

function Test-CoreOwnedPath([string]$Path) {
    foreach ($pattern in $script:corePatterns) {
        if ($Path -like $pattern) {
            return $true
        }
    }
    return $false
}

try {
    Invoke-Checked 'git' @('cat-file', '-e', "$BaseSha^{commit}")
    Invoke-Checked 'git' @('cat-file', '-e', "$HeadSha^{commit}")

    if ($PSBoundParameters.ContainsKey('ChangedFilesOverride')) {
        $changedFiles = @(
            $ChangedFilesOverride |
                ForEach-Object { $_.Trim().Replace('\', '/') } |
                Where-Object { $_ }
        )
    }
    else {
        $changedFiles = @(
            git diff --name-only --diff-filter=ACMRTUXB "$BaseSha...$HeadSha" |
                ForEach-Object { $_.Trim().Replace('\', '/') } |
                Where-Object { $_ }
        )
        if ($LASTEXITCODE -ne 0) {
            Fail 'cannot enumerate changed files'
        }
    }

    $moduleFiles = @($changedFiles | Where-Object { $_ -like 'modules/*' })
    $isModulePr = $BranchName.StartsWith('module/', [StringComparison]::Ordinal) -or
        $moduleFiles.Count -gt 0

    if (-not $isModulePr) {
        Write-Output 'No Cognitive Module changes detected; module-specific checks are not applicable.'
        exit 0
    }

    if ($BranchName -notmatch '^module/(?<issue>[1-9][0-9]*)-(?<module>[a-z0-9]+(?:-[a-z0-9]+)*)$') {
        Fail 'module branches must match module/<issue-number>-<module-id>'
    }
    $issueNumber = $Matches.issue
    $branchModuleId = $Matches.module

    $corePatternsPath = Join-Path $repoRoot '.github/core-owned-paths.txt'
    $script:corePatterns = @(
        Get-Content -LiteralPath $corePatternsPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    )
    $coreChanges = @($changedFiles | Where-Object { Test-CoreOwnedPath $_ })
    if ($coreChanges.Count -gt 0) {
        Fail "module PR changes Core-owned paths:`n$($coreChanges -join "`n")"
    }

    $moduleRoots = @(
        $moduleFiles |
            ForEach-Object {
                $parts = $_.Split('/')
                if ($parts.Count -ge 2) { "modules/$($parts[1])" }
            } |
            Sort-Object -Unique
    )
    if ($moduleRoots.Count -ne 1) {
        Fail "one module PR must change exactly one module directory; found $($moduleRoots.Count)"
    }
    if ((Split-Path $moduleRoots[0] -Leaf) -ne $branchModuleId) {
        Fail "branch module ID '$branchModuleId' does not match changed directory '$($moduleRoots[0])'"
    }

    $moduleRoot = Join-Path $repoRoot $moduleRoots[0]
    $requiredFiles = @(
        'Cargo.toml',
        'schemas/input.schema.json',
        'schemas/output.schema.json',
        'tests/conformance.rs',
        'licenses.json',
        'model-card.md',
        'data-card.md',
        'threat-model.md'
    )
    foreach ($required in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $moduleRoot $required) -PathType Leaf)) {
            Fail "$($moduleRoots[0]) is missing required file '$required'"
        }
    }
    $manifests = @(
        'module-manifest.yaml',
        'module-manifest.json'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $moduleRoot $_) -PathType Leaf }
    if ($manifests.Count -ne 1) {
        Fail "$($moduleRoots[0]) must contain exactly one module-manifest.yaml or module-manifest.json"
    }

    $fixtureKinds = @('valid', 'invalid', 'unsupported')
    foreach ($kind in $fixtureKinds) {
        $fixtureDirectory = Join-Path $moduleRoot "fixtures/$kind"
        $fixtures = @(
            Get-ChildItem -LiteralPath $fixtureDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue
        )
        if ($fixtures.Count -eq 0) {
            Fail "$($moduleRoots[0]) requires at least one $kind JSON fixture"
        }
    }

    $fixtureFiles = @(
        Get-ChildItem -LiteralPath (Join-Path $moduleRoot 'fixtures') -Filter '*.json' -File -Recurse
    )
    $fixtureDocuments = foreach ($fixtureFile in $fixtureFiles) {
        try {
            Get-Content -Raw -LiteralPath $fixtureFile.FullName | ConvertFrom-Json
        }
        catch {
            Fail "fixture '$($fixtureFile.FullName)' is not valid JSON: $($_.Exception.Message)"
        }
    }
    $securityKinds = @('untrusted_content', 'secret_leakage')
    if (-not ($fixtureDocuments | Where-Object { $_.fixture_kind -in $securityKinds })) {
        Fail "$($moduleRoots[0]) requires an untrusted_content or secret_leakage security fixture"
    }
    if (-not ($fixtureDocuments | Where-Object { [int]$_.replay_count -ge 2 })) {
        Fail "$($moduleRoots[0]) requires a fixture with replay_count of at least 2"
    }

    $licensePath = Join-Path $moduleRoot 'licenses.json'
    try {
        $license = Get-Content -Raw -LiteralPath $licensePath | ConvertFrom-Json
    }
    catch {
        Fail "licenses.json is not valid JSON: $($_.Exception.Message)"
    }
    if ($license.schema_version -ne 1 -or
        -not $license.module_license -or
        $license.PSObject.Properties.Name -notcontains 'commercial_use' -or
        $license.PSObject.Properties.Name -notcontains 'dependencies') {
        Fail 'licenses.json must declare schema_version 1, module_license, commercial_use, and dependencies'
    }
    foreach ($dependency in @($license.dependencies)) {
        if (-not $dependency.name -or -not $dependency.version -or -not $dependency.license) {
            Fail 'every licenses.json dependency requires name, version, and license'
        }
    }

    Invoke-Checked 'cargo' @(
        'run', '-p', 'd2i-cli', '--', 'module', 'validate', $moduleRoots[0], '--json'
    )
    Invoke-Checked 'cargo' @(
        'test', '--manifest-path', "$($moduleRoots[0])/Cargo.toml",
        '--test', 'conformance', '--all-features'
    )

    if ($VerifyGitHubIssue) {
        if (-not $env:GH_TOKEN -or -not $env:GITHUB_REPOSITORY) {
            Fail 'GitHub issue verification requires GH_TOKEN and GITHUB_REPOSITORY'
        }
        $headers = @{
            Authorization = "Bearer $env:GH_TOKEN"
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $issue = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$env:GITHUB_REPOSITORY/issues/$issueNumber" `
            -Headers $headers
        if ($issue.pull_request) {
            Fail "#$issueNumber is a pull request, not a module issue"
        }
        if ($issue.state -ne 'open') {
            Fail "module issue #$issueNumber must remain open while implementation is active"
        }
        if (-not $issue.body -or $issue.body -match '_No response_') {
            Fail "module issue #$issueNumber is incomplete"
        }
        foreach ($heading in @(
            'Module name',
            'Module ID',
            'Existing contract references',
            'Execution and persistence limits',
            'Evaluation and security plan',
            'Definition of done'
        )) {
            if ($issue.body -notmatch [regex]::Escape($heading)) {
                Fail "module issue #$issueNumber does not contain required Issue Form section '$heading'"
            }
        }
    }

    Write-Output "Module PR governance checks passed for $($moduleRoots[0]) and issue #$issueNumber."
}
finally {
    Pop-Location
}
