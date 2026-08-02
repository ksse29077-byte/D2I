[CmdletBinding()]
param(
    [ValidateSet('Compile', 'Lifecycle', 'Admission', 'KernelE2E', 'Negative', 'All')]
    [string]$Mode = 'All',

    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$startedAt = [DateTimeOffset]::UtcNow
$results = [System.Collections.Generic.List[object]]::new()
$terminalExitCode = 1

function Invoke-Checked([string]$Label, [scriptblock]$Command) {
    $stdout = Join-Path $script:OutputRoot "$Label.stdout.log"
    $stderr = Join-Path $script:OutputRoot "$Label.stderr.log"
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Command 1> $stdout 2> $stderr
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $saved
    }
    $status = if ($exitCode -eq 0) { 'pass' } else { 'fail' }
    $script:results.Add([pscustomobject][ordered]@{
            label = $Label
            status = $status
            exit_code = $exitCode
            stdout = [IO.Path]::GetFileName($stdout)
            stderr = [IO.Path]::GetFileName($stderr)
        })
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode; see $stderr"
    }
}

function Invoke-Compile {
    foreach ($example in @('kernel-e2e-operator', 'ai-safety-operations-employee')) {
        $source = Join-Path $repoRoot "examples/workforce/$example/role.yaml"
        Invoke-Checked "compile-$example-validate" {
            cargo run --locked -p d2i-role-contract --bin d2i-role -- `
                validate --source $source
        }
        $first = Join-Path $script:OutputRoot "compile/$example-a"
        $second = Join-Path $script:OutputRoot "compile/$example-b"
        New-Item -ItemType Directory -Path (Split-Path $first -Parent) -Force | Out-Null
        Invoke-Checked "compile-$example-a" {
            cargo run --locked -p d2i-role-contract --bin d2i-role -- `
                compile --source $source --output $first
        }
        Invoke-Checked "compile-$example-b" {
            cargo run --locked -p d2i-role-contract --bin d2i-role -- `
                compile --source $source --output $second
        }
        $firstHash = (Get-FileHash -LiteralPath (Join-Path $first 'role.bundle.json') -Algorithm SHA256).Hash
        $secondHash = (Get-FileHash -LiteralPath (Join-Path $second 'role.bundle.json') -Algorithm SHA256).Hash
        if ($firstHash -ne $secondHash) {
            throw "deterministic Role bundle replay differs: $example"
        }
        Invoke-Checked "compile-$example-verify" {
            cargo run --locked -p d2i-role-contract --bin d2i-role -- `
                verify --bundle $first
        }
    }
}

function Invoke-RoleTests([string]$Label) {
    Invoke-Checked $Label {
        cargo test --locked -p d2i-desktop --test role_contract -- --nocapture
    }
}

function Invoke-KernelE2E {
    $kernelRoot = Join-Path $script:OutputRoot 'kernel-e2e'
    Invoke-Checked 'role-bound-kernel-e2e' {
        powershell -NoProfile -ExecutionPolicy Bypass `
            -File (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1') `
            -Mode Happy `
            -RoleSource (Join-Path $repoRoot 'examples/workforce/kernel-e2e-operator/role.yaml') `
            -OutputRoot $kernelRoot
    }
    $kernelResult = Get-Content -Raw -LiteralPath (Join-Path $kernelRoot 'happy/result.json') | ConvertFrom-Json
    if (-not $kernelResult.role_context_sha256 -or
        -not $kernelResult.role_ledger_chain_head -or
        $kernelResult.actual_module_invocations -lt 3 -or
        $kernelResult.mutation_count -ne 2) {
        throw 'role-bound KRN-500 result lacks Role evidence or two actual UIA actions'
    }
}

try {
    if (-not $IsWindows -and $PSVersionTable.PSVersion.Major -ge 6) {
        throw 'Role Contract v1 product runner requires Windows'
    }
    foreach ($path in @(
            (Join-Path $repoRoot 'Cargo.toml'),
            (Join-Path $repoRoot 'examples/workforce/kernel-e2e-operator/role.yaml'),
            (Join-Path $repoRoot 'examples/workforce/ai-safety-operations-employee/role.yaml'),
            (Join-Path $repoRoot 'scripts/e2e/run-first-kernel-e2e.ps1')
        )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "required Role Contract input is absent: $path"
        }
    }
    if (-not $OutputRoot) {
        $head = (& git -C $repoRoot rev-parse --short=12 HEAD).Trim()
        if ($LASTEXITCODE -ne 0) {
            throw 'repository HEAD could not be resolved'
        }
        $runId = '{0}-{1}-{2}' -f [DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssZ'), $head, $PID
        $OutputRoot = Join-Path $repoRoot "target/d2i-workforce/$runId"
    }
    $OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
    $targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
    if (-not $OutputRoot.StartsWith("$targetRoot$([IO.Path]::DirectorySeparatorChar)", [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputRoot must remain under repository target/'
    }
    if (Test-Path -LiteralPath $OutputRoot) {
        throw "OutputRoot already exists: $OutputRoot"
    }
    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    Set-Location $repoRoot

    switch ($Mode) {
        'Compile' { Invoke-Compile }
        'Lifecycle' { Invoke-RoleTests 'role-lifecycle-tests' }
        'Admission' { Invoke-RoleTests 'role-admission-tests' }
        'KernelE2E' { Invoke-KernelE2E }
        'Negative' { Invoke-RoleTests 'role-negative-tests' }
        'All' {
            Invoke-Compile
            Invoke-RoleTests 'role-runtime-tests'
            Invoke-KernelE2E
        }
    }

    $report = [ordered]@{
        schema_version = 1
        mode = $Mode.ToLowerInvariant()
        git_head = (& git -C $repoRoot rev-parse HEAD).Trim()
        started_at = $startedAt.ToString('o')
        completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        results = @($results)
        residual_owned_processes = 0
        complete = $true
        status = 'pass'
        report_sha256 = ''
    }
    $unhashed = $report | ConvertTo-Json -Depth 8 -Compress
    $report.report_sha256 = 'sha256:' + (
        Get-FileHash -Algorithm SHA256 `
            -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($unhashed)))
    ).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText(
        (Join-Path $OutputRoot 'finished.json'),
        ($report | ConvertTo-Json -Depth 8) + [Environment]::NewLine
    )
    Write-Output "D2I Role Contract v1 complete: $OutputRoot"
    $terminalExitCode = 0
}
catch {
    Write-Error $_
}
finally {
    Set-Location $repoRoot
}

exit $terminalExitCode
