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
    [int]$PullRequestNumber,

    [string[]]$ApprovedReviewersOverride,

    [string]$PullRequestAuthorOverride
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$script:authorOverrideProvided = $PSBoundParameters.ContainsKey('PullRequestAuthorOverride')
$script:reviewersOverrideProvided = $PSBoundParameters.ContainsKey('ApprovedReviewersOverride')
$script:pullRequestNumberProvided = $PSBoundParameters.ContainsKey('PullRequestNumber')
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

function Invoke-CheckedQuiet([string]$FilePath, [string[]]$Arguments) {
    & $FilePath @Arguments | Out-Null
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

function Test-AllowedWorkspaceRegistration(
    [string]$Base,
    [string]$Head,
    [string]$ModuleId
) {
    $diff = @(
        git diff --unified=0 "$Base...$Head" -- Cargo.toml
    )
    if ($LASTEXITCODE -ne 0) {
        Fail 'cannot inspect Cargo.toml workspace registration'
    }

    $removed = @($diff | Where-Object {
            $_.StartsWith('-') -and -not $_.StartsWith('---')
        })
    $added = @($diff | Where-Object {
            $_.StartsWith('+') -and -not $_.StartsWith('+++')
        })
    if ($removed.Count -ne 0 -or $added.Count -ne 1) {
        return $false
    }

    return $added[0] -match "^\+\s*`"modules/$([regex]::Escape($ModuleId))`",\s*$"
}

function Get-CodeOwnerLogins {
    $codeOwnersPath = Join-Path $repoRoot '.github/CODEOWNERS'
    $matches = [regex]::Matches(
        (Get-Content -Raw -LiteralPath $codeOwnersPath),
        '@(?<login>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))'
    )
    return @(
        $matches |
            ForEach-Object { $_.Groups['login'].Value } |
            Sort-Object -Unique
    )
}

function Assert-CoreApproval(
    [string[]]$CoreChanges,
    [string]$Head
) {
    $authorizedReviewers = @(Get-CodeOwnerLogins)
    if ($authorizedReviewers.Count -eq 0) {
        Fail 'CODEOWNERS does not identify any Core approver'
    }

    if ($script:authorOverrideProvided) {
        $author = $PullRequestAuthorOverride
    }
    else {
        if (-not $env:GH_TOKEN -or -not $env:GITHUB_REPOSITORY -or
            -not $script:pullRequestNumberProvided) {
            Fail "Core-owned changes require GitHub review verification. " +
                'Provide GH_TOKEN, GITHUB_REPOSITORY, and PullRequestNumber.'
        }
        $headers = @{
            Authorization = "Bearer $env:GH_TOKEN"
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $pullRequest = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$env:GITHUB_REPOSITORY/pulls/$PullRequestNumber" `
            -Headers $headers
        $author = $pullRequest.user.login
    }

    if ($script:reviewersOverrideProvided) {
        $approvedReviewers = @($ApprovedReviewersOverride)
    }
    else {
        $headers = @{
            Authorization = "Bearer $env:GH_TOKEN"
            Accept = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $reviews = @(
            Invoke-RestMethod `
                -Uri "https://api.github.com/repos/$env:GITHUB_REPOSITORY/pulls/$PullRequestNumber/reviews?per_page=100" `
                -Headers $headers
        )
        $decisionByReviewer = @{}
        foreach ($review in @($reviews | Sort-Object submitted_at)) {
            if ($review.commit_id -eq $Head -and
                $review.state -in @('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED')) {
                $decisionByReviewer[$review.user.login] = $review.state
            }
        }
        $approvedReviewers = @(
            $decisionByReviewer.GetEnumerator() |
                Where-Object { $_.Value -eq 'APPROVED' } |
                ForEach-Object { $_.Key }
        )
    }

    $validApprovers = @(
        $approvedReviewers |
            Where-Object {
                $_ -ne $author -and $_ -in $authorizedReviewers
            }
    )
    if ($validApprovers.Count -eq 0) {
        $owners = $authorizedReviewers | ForEach-Object { "@$_" }
        Fail @"
Core-owned changes require a current-head approval from a non-author Core CODEOWNER.
Detected Core-owned files:
$($CoreChanges -join "`n")
Required approver: $($owners -join ', ')
Approval method: submit a GitHub APPROVED review for commit $Head.
Policy: docs/collaboration/core-change-control.md
"@
    }
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

    $corePatternsPath = Join-Path $repoRoot '.github/core-owned-paths.txt'
    $script:corePatterns = @(
        Get-Content -LiteralPath $corePatternsPath |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    )

    $moduleFiles = @($changedFiles | Where-Object { $_ -like 'modules/*' })
    $isModulePr = $BranchName.StartsWith('module/', [StringComparison]::Ordinal) -or
        $moduleFiles.Count -gt 0

    $coreChanges = @($changedFiles | Where-Object { Test-CoreOwnedPath $_ })

    if ($isModulePr) {
        if ($BranchName -notmatch '^module/(?<issue>[1-9][0-9]*)-(?<module>[a-z0-9]+(?:-[a-z0-9]+)*)$') {
            Fail 'module branches must match module/<issue-number>-<module-id>'
        }
        $issueNumber = $Matches.issue
        $branchModuleId = $Matches.module

        $workspaceRegistrationAllowed = $false
        if ($changedFiles -contains 'Cargo.toml') {
            $workspaceRegistrationAllowed = Test-AllowedWorkspaceRegistration `
                -Base $BaseSha `
                -Head $HeadSha `
                -ModuleId $branchModuleId
            if ($workspaceRegistrationAllowed) {
                $coreChanges = @($coreChanges | Where-Object { $_ -ne 'Cargo.toml' })
            }
        }

        if ($coreChanges.Count -gt 0) {
            Fail @"
Module PRs cannot include Core-owned changes.
Detected Core-owned files:
$($coreChanges -join "`n")
Required action: move the change to a separate Core RFC and Core-only PR.
Required approver: a non-author CODEOWNER listed in .github/CODEOWNERS.
Policy: docs/collaboration/core-change-control.md
"@
        }

        $allowedOutsideModule = @('Cargo.lock')
        if ($workspaceRegistrationAllowed) {
            $allowedOutsideModule += 'Cargo.toml'
        }
        $outsideModule = @(
            $changedFiles |
                Where-Object {
                    $_ -notlike "modules/$branchModuleId/*" -and
                    $_ -notin $allowedOutsideModule
                }
        )
        if ($outsideModule.Count -gt 0) {
            Fail "module PR changes files outside its owned module and allowed workspace registration:`n$($outsideModule -join "`n")"
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

        Invoke-CheckedQuiet 'cargo' @(
            'metadata', '--locked', '--no-deps', '--format-version', '1'
        )
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

        Write-Output "Module-only PR governance checks passed for $($moduleRoots[0]) and issue #$issueNumber; human approval is not required."
    }
    elseif ($coreChanges.Count -gt 0) {
        Assert-CoreApproval -CoreChanges $coreChanges -Head $HeadSha
        Write-Output 'Core-owned change approval verified for the current PR head.'
    }
    else {
        Write-Output 'No Cognitive Module or Core-owned changes detected; specialized approval is not required.'
    }
}
finally {
    Pop-Location
}
