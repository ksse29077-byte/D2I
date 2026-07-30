[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Worktree,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$Label,

    [Parameter(Mandatory = $true)]
    [string]$OutputRoot,

    [ValidateRange(1, 10000)]
    [int]$Runs = 1,

    [string]$TestFilter = '',

    [ValidateSet('Serial', 'Parallel')]
    [string]$Mode = 'Serial',

    [string]$CargoTargetDir = '',

    [string]$CandidateWorktree = '',

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
    [string]$CandidateLabel = 'candidate',

    [string]$CandidateCargoTargetDir = '',

    [ValidateRange(1, 86400)]
    [int]$TimeoutSeconds = 900,

    [switch]$Exact
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:CanWriteOutput = $false
$script:ResolvedOutputRoot = $null

function Get-NormalizedFullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
}

function Test-PathsOverlap {
    param(
        [Parameter(Mandatory = $true)]
        [string]$First,

        [Parameter(Mandatory = $true)]
        [string]$Second
    )

    $firstPath = Get-NormalizedFullPath -Path $First
    $secondPath = Get-NormalizedFullPath -Path $Second
    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $separator = [System.IO.Path]::DirectorySeparatorChar

    return $firstPath.Equals($secondPath, $comparison) -or
        $firstPath.StartsWith("$secondPath$separator", $comparison) -or
        $secondPath.StartsWith("$firstPath$separator", $comparison)
}

function ConvertTo-CanonicalJson {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    return $InputObject | ConvertTo-Json -Depth 20 -Compress
}

function Get-Sha256Text {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $script:Utf8NoBom.GetBytes($Text)
        $hash = $sha256.ComputeHash($bytes)
        return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
    }
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    $directory = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $temporaryPath = "$Path.tmp-$PID-$([guid]::NewGuid().ToString('N'))"
    $json = $InputObject | ConvertTo-Json -Depth 20

    try {
        [System.IO.File]::WriteAllText($temporaryPath, "$json`r`n", $script:Utf8NoBom)
        Move-Item -LiteralPath $temporaryPath -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force
        }
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $lines = @(& $FilePath @Arguments 2>&1 | ForEach-Object { "$_" })
    return [pscustomobject]@{
        exit_code = $LASTEXITCODE
        output = ($lines -join "`n").Trim()
    }
}

function ConvertTo-NativeArgument {
    param(
        [AllowEmptyString()]
        [string]$Argument
    )

    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')
    $backslashes = 0

    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
            continue
        }

        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }

        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }

    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-CommandText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $parts = @((ConvertTo-NativeArgument -Argument $FilePath))
    $parts += @($Arguments | ForEach-Object { ConvertTo-NativeArgument -Argument $_ })
    return $parts -join ' '
}

function Get-ProcessSnapshot {
    $snapshot = @{}
    $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)

    foreach ($process in $processes) {
        $creationTime = $null
        if ($null -ne $process.CreationDate) {
            try {
                $creationTime = ([datetime]$process.CreationDate).ToUniversalTime().ToString('o')
            }
            catch {
                $creationTime = "$($process.CreationDate)"
            }
        }

        $snapshot[[int]$process.ProcessId] = [pscustomobject]@{
            pid = [int]$process.ProcessId
            parent_pid = [int]$process.ParentProcessId
            name = if ($null -eq $process.Name) { '' } else { "$($process.Name)" }
            command_line = if ($null -eq $process.CommandLine) {
                ''
            }
            else {
                "$($process.CommandLine)"
            }
            creation_time = $creationTime
        }
    }

    return $snapshot
}

function Test-SameProcessIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Expected,

        [Parameter(Mandatory = $true)]
        [object]$Actual
    )

    if ([int]$Expected.pid -ne [int]$Actual.pid) {
        return $false
    }

    if ($null -eq $Expected.creation_time -or $null -eq $Actual.creation_time) {
        return $true
    }

    return "$($Expected.creation_time)" -eq "$($Actual.creation_time)"
}

function Get-ProcessClassification {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Process,

        [Parameter(Mandatory = $true)]
        [int]$CargoPid,

        [Parameter(Mandatory = $true)]
        [string]$TargetDirectory,

        [Parameter(Mandatory = $true)]
        [hashtable]$OwnedProcesses
    )

    if ([int]$Process.pid -eq $CargoPid) {
        return 'cargo'
    }

    if ($Process.name -ieq 'rustc.exe' -or $Process.name -ieq 'rustc') {
        return 'rustc'
    }

    $parent = $OwnedProcesses[[int]$Process.parent_pid]
    if ($null -ne $parent -and
        ($parent.classification -eq 'test_harness' -or
            $parent.classification -eq 'test_worker')) {
        return 'test_worker'
    }

    $commandLine = "$($Process.command_line)"
    if ($commandLine.IndexOf($TargetDirectory, [System.StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        ($Process.name -like '*.exe' -or $Process.name -notlike '*.*')) {
        return 'test_harness'
    }

    return 'tool_child'
}

function Update-OwnedProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BeforeSnapshot,

        [Parameter(Mandatory = $true)]
        [hashtable]$CurrentSnapshot,

        [Parameter(Mandatory = $true)]
        [hashtable]$OwnedProcesses,

        [Parameter(Mandatory = $true)]
        [int]$CargoPid,

        [Parameter(Mandatory = $true)]
        [string]$TargetDirectory
    )

    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($process in $CurrentSnapshot.Values) {
            $pidValue = [int]$process.pid
            if ($OwnedProcesses.ContainsKey($pidValue)) {
                continue
            }

            if ($BeforeSnapshot.ContainsKey($pidValue) -and
                (Test-SameProcessIdentity -Expected $BeforeSnapshot[$pidValue] -Actual $process)) {
                continue
            }

            if (-not $OwnedProcesses.ContainsKey([int]$process.parent_pid)) {
                continue
            }

            $classification = Get-ProcessClassification `
                -Process $process `
                -CargoPid $CargoPid `
                -TargetDirectory $TargetDirectory `
                -OwnedProcesses $OwnedProcesses
            $OwnedProcesses[$pidValue] = [pscustomobject][ordered]@{
                pid = $pidValue
                parent_pid = [int]$process.parent_pid
                name = "$($process.name)"
                command_line = "$($process.command_line)"
                creation_time = $process.creation_time
                classification = $classification
            }
            $changed = $true
        }
    }
}

function Stop-OwnedProcessTree {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BeforeSnapshot,

        [Parameter(Mandatory = $true)]
        [hashtable]$OwnedProcesses,

        [Parameter(Mandatory = $true)]
        [int]$CargoPid,

        [Parameter(Mandatory = $true)]
        [string]$TargetDirectory
    )

    $deadline = [datetime]::UtcNow.AddSeconds(5)
    do {
        $current = Get-ProcessSnapshot
        Update-OwnedProcesses `
            -BeforeSnapshot $BeforeSnapshot `
            -CurrentSnapshot $current `
            -OwnedProcesses $OwnedProcesses `
            -CargoPid $CargoPid `
            -TargetDirectory $TargetDirectory

        $running = @()
        foreach ($owned in $OwnedProcesses.Values) {
            if ([int]$owned.pid -eq $PID -or -not $current.ContainsKey([int]$owned.pid)) {
                continue
            }

            if (Test-SameProcessIdentity -Expected $owned -Actual $current[[int]$owned.pid]) {
                $running += $owned
            }
        }

        if ($running.Count -eq 0) {
            return @()
        }

        $depthByPid = @{}
        foreach ($owned in $running) {
            $depth = 0
            $cursor = $owned
            $seen = @{}
            while ($null -ne $cursor -and -not $seen.ContainsKey([int]$cursor.pid)) {
                $seen[[int]$cursor.pid] = $true
                $depth++
                $cursor = $OwnedProcesses[[int]$cursor.parent_pid]
            }
            $depthByPid[[int]$owned.pid] = $depth
        }

        foreach ($owned in @($running | Sort-Object {
                    -1 * $depthByPid[[int]$_.pid]
                })) {
            try {
                Stop-Process -Id ([int]$owned.pid) -Force -ErrorAction Stop
            }
            catch {
                if (Get-Process -Id ([int]$owned.pid) -ErrorAction SilentlyContinue) {
                    continue
                }
            }
        }

        Start-Sleep -Milliseconds 100
    } while ([datetime]::UtcNow -lt $deadline)

    $finalSnapshot = Get-ProcessSnapshot
    $residual = @()
    foreach ($owned in $OwnedProcesses.Values) {
        $pidValue = [int]$owned.pid
        if ($pidValue -eq $PID -or -not $finalSnapshot.ContainsKey($pidValue)) {
            continue
        }

        if (Test-SameProcessIdentity -Expected $owned -Actual $finalSnapshot[$pidValue]) {
            $residual += $owned
        }
    }
    return @($residual | Sort-Object pid)
}

function Get-ErrorSummary {
    param(
        [AllowEmptyString()]
        [string]$StandardOutput,

        [AllowEmptyString()]
        [string]$StandardError,

        [AllowEmptyString()]
        [string]$Fallback
    )

    $lines = @(("$StandardError`n$StandardOutput" -split "`r?`n") |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($lines.Count -eq 0) {
        return $Fallback
    }

    $start = [Math]::Max(0, $lines.Count - 8)
    $summary = ($lines[$start..($lines.Count - 1)] -join ' | ').Trim()
    if ($summary.Length -gt 2000) {
        return $summary.Substring(0, 2000)
    }
    return $summary
}

function Get-WorktreePreflight {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorktreePath,

        [Parameter(Mandatory = $true)]
        [string]$GitPath
    )

    if (-not (Test-Path -LiteralPath $WorktreePath -PathType Container)) {
        throw "Invalid worktree: directory not found at $WorktreePath"
    }

    $resolvedWorktree = (Resolve-Path -LiteralPath $WorktreePath).Path
    $manifestPath = Join-Path $resolvedWorktree 'Cargo.toml'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Invalid worktree: Cargo.toml not found at $manifestPath"
    }

    $repositoryRoot = Invoke-NativeCapture `
        -FilePath $GitPath `
        -Arguments @('-C', $resolvedWorktree, 'rev-parse', '--show-toplevel')
    if ($repositoryRoot.exit_code -ne 0) {
        throw "Invalid worktree: git repository check failed: $($repositoryRoot.output)"
    }

    $resolvedRepositoryRoot = (Resolve-Path -LiteralPath $repositoryRoot.output).Path
    if (-not $resolvedRepositoryRoot.Equals(
            $resolvedWorktree,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Invalid worktree: git root $resolvedRepositoryRoot does not match $resolvedWorktree"
    }

    $head = Invoke-NativeCapture `
        -FilePath $GitPath `
        -Arguments @('-C', $resolvedWorktree, 'rev-parse', 'HEAD')
    if ($head.exit_code -ne 0 -or $head.output -notmatch '^[0-9a-fA-F]{40}$') {
        throw "Invalid worktree: unable to collect git HEAD: $($head.output)"
    }

    $status = Invoke-NativeCapture `
        -FilePath $GitPath `
        -Arguments @('-C', $resolvedWorktree, 'status', '--short')
    if ($status.exit_code -ne 0) {
        throw "Invalid worktree: unable to collect git status: $($status.output)"
    }

    return [pscustomobject][ordered]@{
        worktree = $resolvedWorktree
        manifest_path = (Resolve-Path -LiteralPath $manifestPath).Path
        git_head = $head.output.ToLowerInvariant()
        git_status = $status.output
    }
}

function Invoke-ReproductionRun {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Cohort,

        [Parameter(Mandatory = $true)]
        [int]$RunNumber,

        [Parameter(Mandatory = $true)]
        [string]$CargoPath,

        [Parameter(Mandatory = $true)]
        [string]$IdentityName,

        [Parameter(Mandatory = $true)]
        [string]$IdentitySid,

        [Parameter(Mandatory = $true)]
        [bool]$IsAdministrator
    )

    $runId = '{0}-{1:D4}' -f $Cohort.safe_label, $RunNumber
    $runDirectory = Join-Path $script:ResolvedOutputRoot (
        Join-Path $Cohort.safe_label ('run-{0:D4}' -f $RunNumber)
    )
    New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
    $stdoutPath = Join-Path $runDirectory 'stdout.log'
    $stderrPath = Join-Path $runDirectory 'stderr.log'
    $resultPath = Join-Path $runDirectory 'result.json'
    $marker = "d2i-reproduction-$([guid]::NewGuid().ToString('N'))"
    $startedAt = [datetime]::UtcNow

    $arguments = @(
        'test',
        '--manifest-path',
        $Cohort.manifest_path,
        '--workspace',
        '--all-features'
    )
    if (-not [string]::IsNullOrWhiteSpace($TestFilter)) {
        $arguments += $TestFilter
    }
    $arguments += '--'
    if ($Exact) {
        $arguments += '--exact'
    }
    if ($Mode -eq 'Serial') {
        $arguments += '--test-threads=1'
    }

    $commandText = ConvertTo-CommandText -FilePath $CargoPath -Arguments $arguments
    $beforeSnapshot = Get-ProcessSnapshot
    $beforeSnapshotCount = $beforeSnapshot.Count
    $ownedProcesses = @{}
    $process = $null
    $processStarted = $false
    $cargoExitCode = $null
    $standardOutput = ''
    $standardError = ''
    $timedOut = $false
    $launchError = ''
    $residual = @()

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $CargoPath
        $startInfo.WorkingDirectory = $Cohort.worktree
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.EnvironmentVariables['CARGO_TARGET_DIR'] = $Cohort.target_dir
        $startInfo.EnvironmentVariables['D2I_REPRODUCTION_OWNER'] = $marker

        if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
            foreach ($argument in $arguments) {
                [void]$startInfo.ArgumentList.Add($argument)
            }
        }
        else {
            $startInfo.Arguments = (@($arguments | ForEach-Object {
                        ConvertTo-NativeArgument -Argument $_
                    }) -join ' ')
        }

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw 'System.Diagnostics.Process.Start returned false'
        }
        $processStarted = $true

        $rootSnapshot = Get-ProcessSnapshot
        if (-not $rootSnapshot.ContainsKey([int]$process.Id)) {
            $rootRecord = [pscustomobject]@{
                pid = [int]$process.Id
                parent_pid = $PID
                name = 'cargo.exe'
                command_line = $commandText
                creation_time = $null
            }
        }
        else {
            $rootRecord = $rootSnapshot[[int]$process.Id]
        }
        $ownedProcesses[[int]$process.Id] = [pscustomobject][ordered]@{
            pid = [int]$rootRecord.pid
            parent_pid = [int]$rootRecord.parent_pid
            name = "$($rootRecord.name)"
            command_line = "$($rootRecord.command_line)"
            creation_time = $rootRecord.creation_time
            classification = 'cargo'
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $deadline = $startedAt.AddSeconds($TimeoutSeconds)

        while (-not $process.HasExited -and [datetime]::UtcNow -lt $deadline) {
            $currentSnapshot = Get-ProcessSnapshot
            Update-OwnedProcesses `
                -BeforeSnapshot $beforeSnapshot `
                -CurrentSnapshot $currentSnapshot `
                -OwnedProcesses $ownedProcesses `
                -CargoPid ([int]$process.Id) `
                -TargetDirectory $Cohort.target_dir
            Start-Sleep -Milliseconds 100
            $process.Refresh()
        }

        if (-not $process.HasExited) {
            $timedOut = $true
        }
        else {
            $process.WaitForExit()
            $cargoExitCode = $process.ExitCode
        }

        $finalObservation = Get-ProcessSnapshot
        Update-OwnedProcesses `
            -BeforeSnapshot $beforeSnapshot `
            -CurrentSnapshot $finalObservation `
            -OwnedProcesses $ownedProcesses `
            -CargoPid ([int]$process.Id) `
            -TargetDirectory $Cohort.target_dir

        if ($timedOut) {
            $residual = @(Stop-OwnedProcessTree `
                    -BeforeSnapshot $beforeSnapshot `
                    -OwnedProcesses $ownedProcesses `
                    -CargoPid ([int]$process.Id) `
                    -TargetDirectory $Cohort.target_dir)
            if ($process.HasExited) {
                $process.WaitForExit()
                $cargoExitCode = $process.ExitCode
            }
        }

        $standardOutput = $stdoutTask.Result
        $standardError = $stderrTask.Result
    }
    catch {
        $launchError = $_.Exception.Message
    }
    finally {
        if ($null -ne $process -and $processStarted) {
            if (-not $process.HasExited) {
                $residual = @(Stop-OwnedProcessTree `
                        -BeforeSnapshot $beforeSnapshot `
                        -OwnedProcesses $ownedProcesses `
                        -CargoPid ([int]$process.Id) `
                        -TargetDirectory $Cohort.target_dir)
            }
            else {
                $residual = @(Stop-OwnedProcessTree `
                        -BeforeSnapshot $beforeSnapshot `
                        -OwnedProcesses $ownedProcesses `
                        -CargoPid ([int]$process.Id) `
                        -TargetDirectory $Cohort.target_dir)
            }
        }
        if ($null -ne $process) {
            $process.Dispose()
        }
    }

    [System.IO.File]::WriteAllText($stdoutPath, $standardOutput, $script:Utf8NoBom)
    [System.IO.File]::WriteAllText($stderrPath, $standardError, $script:Utf8NoBom)

    $combinedOutput = "$standardError`n$standardOutput"
    $observedTestHarness = @($ownedProcesses.Values |
            Where-Object { $_.classification -eq 'test_harness' }).Count -gt 0
    $loggedTestHarness = $combinedOutput -match '(?m)^\s*Running (?:unittests|tests?[\\/])' -or
        $combinedOutput -match '(?m)^\s*running \d+ tests?'
    $testBinaryStarted = $observedTestHarness -or $loggedTestHarness

    if (-not [string]::IsNullOrWhiteSpace($launchError)) {
        $status = 'harness_failure'
        $errorSummary = $launchError
    }
    elseif ($residual.Count -gt 0) {
        $status = 'harness_failure'
        $errorSummary = 'Runner-owned process cleanup did not reach zero residual processes.'
    }
    elseif ($timedOut) {
        $status = 'timeout'
        $errorSummary = "Cargo run exceeded the bounded timeout of $TimeoutSeconds seconds."
    }
    elseif (-not $testBinaryStarted) {
        $status = 'harness_failure'
        $errorSummary = Get-ErrorSummary `
            -StandardOutput $standardOutput `
            -StandardError $standardError `
            -Fallback 'Cargo exited before a test binary was observed.'
    }
    elseif ($cargoExitCode -eq 0) {
        $status = 'pass'
        $errorSummary = ''
    }
    else {
        $status = 'test_failure'
        $errorSummary = Get-ErrorSummary `
            -StandardOutput $standardOutput `
            -StandardError $standardError `
            -Fallback "Test binary failed with Cargo exit code $cargoExitCode."
    }

    $completedAt = [datetime]::UtcNow
    $result = [pscustomobject][ordered]@{
        schema_version = '1.0'
        label = $Cohort.label
        worktree = $Cohort.worktree
        git_head = $Cohort.git_head
        git_status = $Cohort.git_status
        command = $commandText
        command_arguments = $arguments
        working_directory = $Cohort.worktree
        manifest_path = $Cohort.manifest_path
        cargo_target_dir = $Cohort.target_dir
        run_id = $runId
        test_name = if ([string]::IsNullOrWhiteSpace($TestFilter)) {
            '*'
        }
        else {
            $TestFilter
        }
        serial_or_parallel = $Mode.ToLowerInvariant()
        cargo_exit_code = $cargoExitCode
        test_binary_started = $testBinaryStarted
        status = $status
        error_summary = $errorSummary
        ownership_marker = $marker
        runner_pid = $PID
        user_name = $IdentityName
        user_sid = $IdentitySid
        is_administrator = $IsAdministrator
        started_at = $startedAt.ToString('o')
        completed_at = $completedAt.ToString('o')
        timeout_seconds = $TimeoutSeconds
        process_snapshot_before_count = $beforeSnapshotCount
        stdout_path = $stdoutPath
        stderr_path = $stderrPath
        result_path = $resultPath
        new_processes = @($ownedProcesses.Values | Sort-Object pid)
        residual_owned_processes = @($residual)
    }
    Write-JsonAtomic -Path $resultPath -InputObject $result
    return $result
}

try {
    if ($PSVersionTable.PSEdition -eq 'Core' -and
        -not [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [System.Runtime.InteropServices.OSPlatform]::Windows
        )) {
        throw 'The Windows reproduction runner can only run on Windows.'
    }

    $resolvedOutput = Get-NormalizedFullPath -Path $OutputRoot
    $candidatePaths = @($Worktree)
    if (-not [string]::IsNullOrWhiteSpace($CandidateWorktree)) {
        $candidatePaths += $CandidateWorktree
    }
    foreach ($candidatePath in $candidatePaths) {
        if (Test-PathsOverlap -First $resolvedOutput -Second $candidatePath) {
            throw "OutputRoot and Worktree must be disjoint: $resolvedOutput and $candidatePath"
        }
    }

    New-Item -ItemType Directory -Path $resolvedOutput -Force | Out-Null
    $script:ResolvedOutputRoot = (Resolve-Path -LiteralPath $resolvedOutput).Path
    $writeProbe = Join-Path $script:ResolvedOutputRoot ".write-probe-$PID"
    [System.IO.File]::WriteAllText($writeProbe, 'ok', $script:Utf8NoBom)
    Remove-Item -LiteralPath $writeProbe -Force
    $script:CanWriteOutput = $true

    $gitCommand = @(Get-Command git -CommandType Application -ErrorAction Stop)[0]
    $cargoCommand = @(Get-Command cargo -CommandType Application -ErrorAction Stop)[0]
    $rustcCommand = @(Get-Command rustc -CommandType Application -ErrorAction Stop)[0]
    $gitPath = $gitCommand.Source
    $cargoPath = $cargoCommand.Source
    $rustcPath = $rustcCommand.Source

    $cargoVersion = Invoke-NativeCapture -FilePath $cargoPath -Arguments @('--version')
    if ($cargoVersion.exit_code -ne 0) {
        throw "Cargo is unavailable: $($cargoVersion.output)"
    }
    $rustcVersion = Invoke-NativeCapture -FilePath $rustcPath -Arguments @('--version')
    if ($rustcVersion.exit_code -ne 0) {
        throw "rustc is unavailable: $($rustcVersion.output)"
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $administratorRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $isAdministrator = $principal.IsInRole($administratorRole)
    $identitySid = $identity.User.Value
    $processSnapshotCapability = Get-ProcessSnapshot

    $basePreflight = Get-WorktreePreflight -WorktreePath $Worktree -GitPath $gitPath
    $cohortDefinitions = @(
        [pscustomobject][ordered]@{
            label = $Label
            safe_label = $Label
            worktree = $basePreflight.worktree
            manifest_path = $basePreflight.manifest_path
            git_head = $basePreflight.git_head
            git_status = $basePreflight.git_status
            target_dir = if ([string]::IsNullOrWhiteSpace($CargoTargetDir)) {
                Join-Path $script:ResolvedOutputRoot (Join-Path 'targets' $Label)
            }
            else {
                Get-NormalizedFullPath -Path $CargoTargetDir
            }
        }
    )

    if (-not [string]::IsNullOrWhiteSpace($CandidateWorktree)) {
        if ($CandidateLabel -eq $Label) {
            throw 'CandidateLabel must differ from Label.'
        }
        $candidatePreflight = Get-WorktreePreflight `
            -WorktreePath $CandidateWorktree `
            -GitPath $gitPath
        $candidateTarget = if (-not [string]::IsNullOrWhiteSpace($CandidateCargoTargetDir)) {
            Get-NormalizedFullPath -Path $CandidateCargoTargetDir
        }
        elseif (-not [string]::IsNullOrWhiteSpace($CargoTargetDir)) {
            "$(Get-NormalizedFullPath -Path $CargoTargetDir)-$CandidateLabel"
        }
        else {
            Join-Path $script:ResolvedOutputRoot (Join-Path 'targets' $CandidateLabel)
        }

        $cohortDefinitions += [pscustomobject][ordered]@{
            label = $CandidateLabel
            safe_label = $CandidateLabel
            worktree = $candidatePreflight.worktree
            manifest_path = $candidatePreflight.manifest_path
            git_head = $candidatePreflight.git_head
            git_status = $candidatePreflight.git_status
            target_dir = $candidateTarget
        }
    }

    if ($cohortDefinitions.Count -eq 2 -and
        (Test-PathsOverlap `
            -First $cohortDefinitions[0].target_dir `
            -Second $cohortDefinitions[1].target_dir)) {
        throw 'Base and Candidate CARGO_TARGET_DIR values must be disjoint.'
    }

    foreach ($cohort in $cohortDefinitions) {
        if (Test-PathsOverlap -First $cohort.target_dir -Second $cohort.worktree) {
            throw "CARGO_TARGET_DIR and Worktree must be disjoint for $($cohort.label)."
        }
        New-Item -ItemType Directory -Path $cohort.target_dir -Force | Out-Null
        $cohort.target_dir = (Resolve-Path -LiteralPath $cohort.target_dir).Path
    }

    $contractTestFilter = if ([string]::IsNullOrWhiteSpace($TestFilter)) {
        '<ALL_TESTS>'
    }
    else {
        $TestFilter
    }
    $contractExact = if ($Exact) { '--exact' } else { '<NOT_EXACT>' }
    $contractThreads = if ($Mode -eq 'Serial') {
        '--test-threads=1'
    }
    else {
        '<DEFAULT_TEST_THREADS>'
    }

    $comparisonContract = [pscustomobject][ordered]@{
        schema_version = '1.0'
        cargo_path = $cargoPath
        cargo_version = $cargoVersion.output
        rustc_path = $rustcPath
        rustc_version = $rustcVersion.output
        command_template = @(
            'cargo',
            'test',
            '--manifest-path',
            '<WORKTREE>/Cargo.toml',
            '--workspace',
            '--all-features',
            $contractTestFilter,
            '--',
            $contractExact,
            $contractThreads
        )
        test_filter = $TestFilter
        exact = [bool]$Exact
        serial_or_parallel = $Mode.ToLowerInvariant()
        timeout_seconds = $TimeoutSeconds
        user_name = $identity.Name
        user_sid = $identitySid
        is_administrator = $isAdministrator
    }
    $comparisonContractHash = Get-Sha256Text `
        -Text (ConvertTo-CanonicalJson -InputObject $comparisonContract)

    $preflight = [pscustomobject][ordered]@{
        schema_version = '1.0'
        runner_path = $MyInvocation.MyCommand.Path
        runner_pid = $PID
        output_root = $script:ResolvedOutputRoot
        current_directory = (Get-Location).Path
        user_name = $identity.Name
        user_sid = $identitySid
        is_administrator = $isAdministrator
        cargo_path = $cargoPath
        cargo_version = $cargoVersion.output
        rustc_path = $rustcPath
        rustc_version = $rustcVersion.output
        git_path = $gitPath
        comparison_contract = $comparisonContract
        comparison_contract_sha256 = $comparisonContractHash
        process_snapshot_count = $processSnapshotCapability.Count
        cohorts = $cohortDefinitions
        completed_at = [datetime]::UtcNow.ToString('o')
    }
    Write-JsonAtomic `
        -Path (Join-Path $script:ResolvedOutputRoot 'preflight.json') `
        -InputObject $preflight

    $results = @()
    foreach ($cohort in $cohortDefinitions) {
        for ($runNumber = 1; $runNumber -le $Runs; $runNumber++) {
            $results += Invoke-ReproductionRun `
                -Cohort $cohort `
                -RunNumber $runNumber `
                -CargoPath $cargoPath `
                -IdentityName $identity.Name `
                -IdentitySid $identitySid `
                -IsAdministrator $isAdministrator
        }
    }

    $requestedRuns = $Runs * $cohortDefinitions.Count
    $validResults = @($results | Where-Object {
            $_.status -eq 'pass' -or $_.status -eq 'test_failure'
        })
    $passedResults = @($results | Where-Object { $_.status -eq 'pass' })
    $testFailures = @($results | Where-Object { $_.status -eq 'test_failure' })
    $harnessFailures = @($results | Where-Object { $_.status -eq 'harness_failure' })
    $timeouts = @($results | Where-Object { $_.status -eq 'timeout' })
    $residualProcesses = @($results |
            ForEach-Object { @($_.residual_owned_processes) } |
            Sort-Object pid -Unique)
    $complete = $results.Count -eq $requestedRuns
    $allTestBinariesStarted = @($results |
            Where-Object { -not $_.test_binary_started }).Count -eq 0
    $comparisonContractsMatch = $true

    $cohortSummaries = @()
    foreach ($cohort in $cohortDefinitions) {
        $cohortResults = @($results | Where-Object { $_.label -eq $cohort.label })
        $cohortSummaries += [pscustomobject][ordered]@{
            label = $cohort.label
            worktree = $cohort.worktree
            git_head = $cohort.git_head
            git_status = $cohort.git_status
            manifest_path = $cohort.manifest_path
            working_directory = $cohort.worktree
            cargo_target_dir = $cohort.target_dir
            comparison_contract_sha256 = $comparisonContractHash
            requested_runs = $Runs
            valid_test_runs = @($cohortResults | Where-Object {
                    $_.status -eq 'pass' -or $_.status -eq 'test_failure'
                }).Count
            passed_runs = @($cohortResults | Where-Object {
                    $_.status -eq 'pass'
                }).Count
            test_failures = @($cohortResults | Where-Object {
                    $_.status -eq 'test_failure'
                }).Count
            harness_failures = @($cohortResults | Where-Object {
                    $_.status -eq 'harness_failure'
                }).Count
            timeouts = @($cohortResults | Where-Object {
                    $_.status -eq 'timeout'
                }).Count
        }
    }

    if ($cohortSummaries.Count -eq 2) {
        $comparisonContractsMatch =
            $cohortSummaries[0].comparison_contract_sha256 -eq
            $cohortSummaries[1].comparison_contract_sha256
    }

    $validForComparison = $complete -and
        $validResults.Count -eq $requestedRuns -and
        $harnessFailures.Count -eq 0 -and
        $timeouts.Count -eq 0 -and
        $residualProcesses.Count -eq 0 -and
        $allTestBinariesStarted -and
        $comparisonContractsMatch

    $finished = [pscustomobject][ordered]@{
        schema_version = '1.0'
        requested_runs = $requestedRuns
        requested_runs_per_cohort = $Runs
        valid_test_runs = $validResults.Count
        passed_runs = $passedResults.Count
        test_failures = $testFailures.Count
        harness_failures = $harnessFailures.Count
        timeouts = $timeouts.Count
        residual_owned_processes = $residualProcesses.Count
        complete = $complete
        valid_for_comparison = $validForComparison
        all_test_binaries_started = $allTestBinariesStarted
        comparison_contracts_match = $comparisonContractsMatch
        comparison_contract_sha256 = $comparisonContractHash
        comparison_kind = if ($cohortDefinitions.Count -eq 2) {
            'paired'
        }
        else {
            'single_cohort'
        }
        cohorts = $cohortSummaries
        result_files = @($results | ForEach-Object { $_.result_path })
        completed_at = [datetime]::UtcNow.ToString('o')
    }
    Write-JsonAtomic `
        -Path (Join-Path $script:ResolvedOutputRoot 'finished.json') `
        -InputObject $finished

    Write-Output ((
            "Windows reproduction complete: valid={0}/{1}, pass={2}, test_failure={3}, " +
            "harness_failure={4}, timeout={5}, comparison_valid={6}"
        ) -f @(
            $validResults.Count,
            $requestedRuns,
            $passedResults.Count,
            $testFailures.Count,
            $harnessFailures.Count,
            $timeouts.Count,
            $validForComparison
        ))

    if (-not $validForComparison) {
        exit 2
    }
    if ($testFailures.Count -gt 0) {
        exit 1
    }
    exit 0
}
catch {
    $message = $_.Exception.Message
    if ($script:CanWriteOutput) {
        $failure = [pscustomobject][ordered]@{
            schema_version = '1.0'
            requested_runs = if ([string]::IsNullOrWhiteSpace($CandidateWorktree)) {
                $Runs
            }
            else {
                $Runs * 2
            }
            valid_test_runs = 0
            passed_runs = 0
            test_failures = 0
            harness_failures = 1
            timeouts = 0
            residual_owned_processes = 0
            complete = $false
            valid_for_comparison = $false
            error_summary = $message
            completed_at = [datetime]::UtcNow.ToString('o')
        }
        try {
            Write-JsonAtomic `
                -Path (Join-Path $script:ResolvedOutputRoot 'finished.json') `
                -InputObject $failure
        }
        catch {
            [Console]::Error.WriteLine(
                "Harness failure: $message; unable to write finished.json: $($_.Exception.Message)"
            )
            exit 2
        }
    }

    [Console]::Error.WriteLine("Harness failure: $message")
    exit 2
}
