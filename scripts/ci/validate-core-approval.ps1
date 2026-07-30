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

    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber,

    [string[]]$ChangedFilesOverride,

    [string[]]$ApprovedReviewersOverride,

    [object[]]$ReviewRecordsOverride,

    [string]$PullRequestAuthorOverride
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$script:authorOverrideProvided = $PSBoundParameters.ContainsKey('PullRequestAuthorOverride')
$script:reviewersOverrideProvided = $PSBoundParameters.ContainsKey('ApprovedReviewersOverride')
$script:reviewRecordsOverrideProvided = $PSBoundParameters.ContainsKey('ReviewRecordsOverride')
$script:pullRequestNumberProvided = $PSBoundParameters.ContainsKey('PullRequestNumber')
Push-Location $repoRoot

function Fail([string]$Message) {
    throw "core-governance validation failed: $Message"
}

function Test-CoreOwnedPath([string]$Path) {
    foreach ($pattern in $script:corePatterns) {
        if ($Path -like $pattern) {
            return $true
        }
    }
    return $false
}

function Get-CodeOwnerLogins {
    $matches = [regex]::Matches(
        (Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.github/CODEOWNERS')),
        '@(?<login>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))'
    )
    return @(
        $matches |
            ForEach-Object { $_.Groups['login'].Value } |
            Sort-Object -Unique
    )
}

function Assert-CoreApproval([string[]]$CoreChanges) {
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
            Fail 'GitHub review verification requires GH_TOKEN, GITHUB_REPOSITORY, and PullRequestNumber'
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
        if ($script:reviewRecordsOverrideProvided) {
            $reviews = @($ReviewRecordsOverride | ForEach-Object { $_ })
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
                    -Headers $headers |
                    ForEach-Object { $_ }
            )
        }
        $decisionByReviewer = @{}
        foreach ($review in @($reviews | Sort-Object submitted_at)) {
            if ($review.commit_id -eq $HeadSha -and
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
            Where-Object { $_ -ne $author -and $_ -in $authorizedReviewers }
    )
    if ($validApprovers.Count -eq 0) {
        $owners = $authorizedReviewers | ForEach-Object { "@$_" }
        Fail @"
Core-owned changes require a current-head approval from a non-author Core CODEOWNER.
Detected Core-owned files:
$($CoreChanges -join "`n")
Required approver: $($owners -join ', ')
Approval method: submit a GitHub APPROVED review for commit $HeadSha.
Policy: docs/collaboration/core-change-control.md
"@
    }
}

try {
    foreach ($commit in @($BaseSha, $HeadSha)) {
        git cat-file -e "$commit^{commit}"
        if ($LASTEXITCODE -ne 0) {
            Fail "cannot resolve commit $commit"
        }
    }

    if ($PSBoundParameters.ContainsKey('ChangedFilesOverride')) {
        $changedFiles = @(
            $ChangedFilesOverride |
                ForEach-Object { $_.Trim().Replace('\', '/') } |
                Where-Object { $_ }
        )
    }
    else {
        $changedFiles = @(
            git diff --name-only --diff-filter=ACDMRTUXB "$BaseSha...$HeadSha" |
                ForEach-Object { $_.Trim().Replace('\', '/') } |
                Where-Object { $_ }
        )
        if ($LASTEXITCODE -ne 0) {
            Fail 'cannot enumerate changed files'
        }
    }

    $script:corePatterns = @(
        Get-Content -LiteralPath (Join-Path $repoRoot '.github/core-owned-paths.txt') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#') }
    )
    $coreChanges = @($changedFiles | Where-Object { Test-CoreOwnedPath $_ })

    $isModuleBranch = $BranchName -match '^module/[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*$'

    if ($coreChanges.Count -eq 0) {
        Write-Output 'No Core-owned changes detected; Core approval is not required.'
        return
    }
    if ($isModuleBranch) {
        Fail @"
Module PRs cannot include Core-owned changes.
Detected Core-owned files:
$($coreChanges -join "`n")
Required action: move the change to a separate Core RFC and Core-only PR.
Required approver: a non-author CODEOWNER listed in .github/CODEOWNERS.
Policy: docs/collaboration/core-change-control.md
"@
    }

    Assert-CoreApproval -CoreChanges $coreChanges
    Write-Output 'Trusted Core governance verified a non-author CODEOWNER approval for the current head.'
}
finally {
    Pop-Location
}
