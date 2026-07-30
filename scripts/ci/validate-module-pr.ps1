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

    [string[]]$ChangedFilesOverride,

    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$classifier = Join-Path $PSScriptRoot 'classify-change.ps1'
$moduleChecker = Join-Path $repoRoot 'scripts/modules/check-module.ps1'
Push-Location $repoRoot

function Fail([string]$Message) {
    throw "module-pr validation failed: $Message"
}

try {
    foreach ($commit in @($BaseSha, $HeadSha)) {
        git cat-file -e "$commit^{commit}"
        if ($LASTEXITCODE -ne 0) {
            Fail "cannot resolve commit $commit"
        }
    }

    $classifierArguments = @{
        BaseSha = $BaseSha
        HeadSha = $HeadSha
        Json = $true
    }
    if ($PSBoundParameters.ContainsKey('ChangedFilesOverride')) {
        $classifierArguments.ChangedFilesOverride = $ChangedFilesOverride
    }
    $classification = & $classifier @classifierArguments | ConvertFrom-Json
    $changedFiles = @($classification.changed_files)
    $isModuleBranch = $BranchName.StartsWith('module/', [StringComparison]::Ordinal)

    if ($classification.classification -ne 'module_only') {
        if ($isModuleBranch) {
            Fail @"
Module branches may change exactly one modules/<module-id> directory.
Detected classification: $($classification.classification)
Changed files:
$($changedFiles -join "`n")
Root Cargo.toml and root Cargo.lock are always Core-owned.
"@
        }
        Write-Output "Module governance reported pass for $($classification.classification); Core workflows own this change."
        return
    }

    if ($BranchName -notmatch '^module/(?<issue>[1-9][0-9]*)-(?<module>[a-z0-9]+(?:-[a-z0-9]+)*)$') {
        Fail 'module-only branches must match module/<issue-number>-<module-id>'
    }
    $issueNumber = $Matches.issue
    $branchModuleId = $Matches.module
    $moduleIds = @($classification.module_ids)
    if ($moduleIds.Count -ne 1 -or $moduleIds[0] -ne $branchModuleId) {
        Fail "branch module ID '$branchModuleId' does not match changed module '$($moduleIds -join ', ')'"
    }
    $moduleRelativePath = "modules/$branchModuleId"
    $outsideModule = @($changedFiles | Where-Object { $_ -notlike "$moduleRelativePath/*" })
    if ($outsideModule.Count -gt 0) {
        Fail "module-only PR contains paths outside ${moduleRelativePath}:`n$($outsideModule -join "`n")"
    }

    $moduleRoot = Join-Path $repoRoot $moduleRelativePath
    $requiredFiles = @(
        'Cargo.toml',
        'Cargo.lock',
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
            Fail "$moduleRelativePath is missing required file '$required'"
        }
    }
    $manifests = @(
        'module-manifest.yaml',
        'module-manifest.json'
    ) | Where-Object { Test-Path -LiteralPath (Join-Path $moduleRoot $_) -PathType Leaf }
    if ($manifests.Count -ne 1) {
        Fail "$moduleRelativePath must contain exactly one module manifest"
    }

    $fixtureFiles = @(
        Get-ChildItem `
            -LiteralPath (Join-Path $moduleRoot 'fixtures') `
            -Filter '*.json' `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    )
    if ($fixtureFiles.Count -eq 0) {
        Fail "$moduleRelativePath requires at least one JSON fixture"
    }
    $fixtureDocuments = foreach ($fixtureFile in $fixtureFiles) {
        try {
            Get-Content -Raw -LiteralPath $fixtureFile.FullName | ConvertFrom-Json
        }
        catch {
            Fail "fixture '$($fixtureFile.FullName)' is not valid JSON: $($_.Exception.Message)"
        }
    }
    if (-not ($fixtureDocuments | Where-Object { [int]$_.replay_count -ge 2 })) {
        Fail "$moduleRelativePath requires a deterministic replay fixture"
    }
    foreach ($expectedStatus in @('failed', 'unsupported')) {
        if (-not ($fixtureDocuments | Where-Object { $_.expected.status -eq $expectedStatus })) {
            Fail "$moduleRelativePath requires a fixture with expected status '$expectedStatus'"
        }
    }
    $hasUntrustedFixture = $fixtureDocuments | Where-Object {
        @($_.invocation.trust_labels | Where-Object {
                $_ -like 'untrusted_*' -or $_ -eq 'observed_ui_state'
            }).Count -gt 0
    }
    if (-not $hasUntrustedFixture) {
        Fail "$moduleRelativePath requires a fixture that treats untrusted content as data"
    }

    try {
        $license = Get-Content -Raw -LiteralPath (Join-Path $moduleRoot 'licenses.json') |
            ConvertFrom-Json
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

    $resultPath = Join-Path $env:TEMP "d2i-module-governance-$branchModuleId-$PID.json"
    & $moduleChecker `
        -ModulePath $moduleRoot `
        -OutputPath $resultPath `
        -ChangedFilesOverride $changedFiles | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "standalone module check failed; report: $resultPath"
    }
    $moduleResult = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
    if ($moduleResult.status -ne 'pass') {
        Fail "standalone module report is not pass; report: $resultPath"
    }
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction SilentlyContinue

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

    Write-Output "Module-only governance passed for $moduleRelativePath and issue #$issueNumber."
}
finally {
    Pop-Location
}
