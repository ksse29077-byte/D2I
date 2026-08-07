Set-StrictMode -Version Latest

$script:ZeroHash = 'sha256:' + ('0' * 64)
$script:EmptyHash = 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
$script:SensitivePattern = '(?i)(password\s*[:=]|api[_-]?key\s*[:=]|bearer\s+[a-z0-9._-]+|authorization\s*[:=]|raw[_ -]?(ui|locator|selector|coordinate|keystroke)\s*[:=]|chain[_ -]?of[_ -]?thought\s*[:=]|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})'

function Get-WorkforceSha256Bytes {
    param([Parameter(Mandatory)][byte[]]$Bytes)

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash($Bytes)
    }
    finally {
        $hasher.Dispose()
    }
    return 'sha256:' + ([BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Get-WorkforceSha256Text {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)

    return Get-WorkforceSha256Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text))
}

function Get-WorkforceFileHash {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required hash input does not exist: $Path"
    }
    return 'sha256:' + (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function ConvertTo-WorkforceCanonicalNode {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string] -or $Value -is [char] -or $Value -is [bool] -or
        $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [int16] -or
        $Value -is [uint16] -or $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or $Value -is [single] -or
        $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [DateTime]) {
        return $Value.ToUniversalTime().ToString('o')
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $result = [ordered]@{}
        foreach ($key in @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object)) {
            $result[$key] = ConvertTo-WorkforceCanonicalNode $Value[$key]
        }
        return $result
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $result = @()
        foreach ($item in $Value) {
            $result += ,(ConvertTo-WorkforceCanonicalNode $item)
        }
        return ,$result
    }
    $properties = @($Value.PSObject.Properties | Where-Object MemberType -in @('NoteProperty', 'Property'))
    if ($properties.Count -gt 0) {
        $result = [ordered]@{}
        foreach ($property in @($properties | Sort-Object Name)) {
            $result[$property.Name] = ConvertTo-WorkforceCanonicalNode $property.Value
        }
        return $result
    }
    return [string]$Value
}

function ConvertTo-WorkforceCanonicalJson {
    param([Parameter(Mandatory)][AllowNull()][object]$Value)

    $node = ConvertTo-WorkforceCanonicalNode $Value
    return $node | ConvertTo-Json -Depth 64 -Compress
}

function Get-WorkforceObjectHash {
    param([Parameter(Mandatory)][object]$Value)

    return Get-WorkforceSha256Text (ConvertTo-WorkforceCanonicalJson $Value)
}

function Get-WorkforceJsonNativeHash {
    param([Parameter(Mandatory)][object]$Value)

    $native = (ConvertTo-WorkforceCanonicalJson $Value) | ConvertFrom-Json
    return Get-WorkforceObjectHash $native
}

function Assert-WorkforceNoSensitiveText {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [string]$Label = 'checkpoint payload'
    )

    if ($Text -match $script:SensitivePattern) {
        throw "$Label contains prohibited sensitive content."
    }
}

function Write-WorkforceAtomicJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Value,
        [switch]$Pretty
    )

    $parent = Split-Path -Parent $Path
    if (-not $parent) {
        throw 'Atomic JSON output must have a parent directory.'
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $canonical = ConvertTo-WorkforceCanonicalJson $Value
    Assert-WorkforceNoSensitiveText $canonical
    $text = if ($Pretty) {
        (ConvertTo-WorkforceCanonicalNode $Value) | ConvertTo-Json -Depth 64
    }
    else {
        $canonical
    }
    $temporary = "$Path.tmp.$PID.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText(
            $temporary,
            $text + [Environment]::NewLine,
            [System.Text.UTF8Encoding]::new($false)
        )
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-WorkforcePathSetHash {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$RelativePaths
    )

    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in @($RelativePaths | Sort-Object -Unique)) {
        if ([System.IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') {
            throw "Hash input must be a bounded relative path: $relative"
        }
        $path = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Hash input is missing: $relative"
        }
        $entries.Add([ordered]@{
            path = $relative.Replace('\\', '/')
            sha256 = Get-WorkforceFileHash $path
        })
    }
    return Get-WorkforceObjectHash @($entries)
}

function Get-WorkforceSourceTreeHash {
    param(
        [Parameter(Mandatory)][string]$RepositoryRoot,
        [string[]]$ExcludeRelativePaths = @()
    )

    $root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
    $raw = & git -C $root ls-files -co --exclude-standard -z
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate the source tree.'
    }
    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $ExcludeRelativePaths) {
        [void]$excluded.Add($item.Replace('\\', '/'))
    }
    $paths = @(
        ($raw -join "`n") -split "`0" |
            Where-Object { $_ -and -not $excluded.Contains($_.Replace('\\', '/')) } |
            Where-Object { Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf } |
            Sort-Object -Unique
    )
    return Get-WorkforcePathSetHash -Root $root -RelativePaths $paths
}

function Get-WorkforceBoundedArtifact {
    param(
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$Path
    )

    $root = [System.IO.Path]::GetFullPath($OutputRoot)
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if (-not $resolved.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Checkpoint artifact is outside OutputRoot: $resolved"
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Checkpoint artifact does not exist: $resolved"
    }
    $rootWithSeparator = $root.TrimEnd([char[]]@([char]92, [char]47)) + [System.IO.Path]::DirectorySeparatorChar
    $rootUri = [Uri]::new($rootWithSeparator)
    $pathUri = [Uri]::new($resolved)
    $relative = [Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString())
    return [ordered]@{
        path = $relative.Replace('\\', '/')
        sha256 = Get-WorkforceFileHash $resolved
    }
}

function New-WorkforceCheckpoint {
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$StepId,
        [Parameter(Mandatory)][string]$StepLabel,
        [Parameter(Mandatory)][int]$StepOrdinal,
        [Parameter(Mandatory)][string[]]$RequiredBindingFields,
        [Parameter(Mandatory)][string]$ExecutableInputSha256,
        [Parameter(Mandatory)][string]$OutputRoot,
        [string[]]$ProducedArtifactPaths = @(),
        [string]$StdoutPath,
        [string]$StderrPath,
        [int]$ExitCode = 0,
        [bool]$CleanupVerified = $true,
        [int]$ResidualProcessCount = 0,
        [int]$ResidualCredentialCount = 0,
        [int]$ResidualActivationCount = 0,
        [int]$ResidualProfileCount = 0,
        [int]$ResidualLockCount = 0,
        [string[]]$PredecessorEvidenceSha256s = @()
    )

    $artifacts = @($ProducedArtifactPaths | ForEach-Object {
        Get-WorkforceBoundedArtifact -OutputRoot $OutputRoot -Path $_
    })
    $stdout = if ($StdoutPath) { Get-WorkforceBoundedArtifact -OutputRoot $OutputRoot -Path $StdoutPath } else { $null }
    $stderr = if ($StderrPath) { Get-WorkforceBoundedArtifact -OutputRoot $OutputRoot -Path $StderrPath } else { $null }
    $checkpoint = [ordered]@{
        schema_version = 1
        step_id = $StepId
        step_label = $StepLabel
        step_ordinal = $StepOrdinal
        status = 'verified_success'
        source_tree_sha256 = $Context.source_tree_sha256
        git_sha = $Context.git_sha
        runner_sha256 = $Context.runner_sha256
        executable_input_sha256 = $ExecutableInputSha256
        mode = $Context.mode
        normalized_arguments_sha256 = $Context.normalized_arguments_sha256
        model_sha256 = $Context.model_sha256
        runtime_sha256 = $Context.runtime_sha256
        role_contract_sha256 = $Context.role_contract_sha256
        shadow_profile_sha256 = $Context.shadow_profile_sha256
        readiness_policy_sha256 = $Context.readiness_policy_sha256
        cohort_sha256 = $Context.cohort_sha256
        required_binding_fields = @($RequiredBindingFields | Sort-Object -Unique)
        predecessor_evidence_sha256s = @($PredecessorEvidenceSha256s | Sort-Object -Unique)
        produced_artifacts = $artifacts
        stdout_path = if ($stdout) { $stdout.path } else { $null }
        stdout_sha256 = if ($stdout) { $stdout.sha256 } else { $script:EmptyHash }
        stderr_path = if ($stderr) { $stderr.path } else { $null }
        stderr_sha256 = if ($stderr) { $stderr.sha256 } else { $script:EmptyHash }
        exit_code = $ExitCode
        cleanup_verified = $CleanupVerified
        residual_process_count = $ResidualProcessCount
        residual_credential_count = $ResidualCredentialCount
        residual_activation_count = $ResidualActivationCount
        residual_profile_count = $ResidualProfileCount
        residual_lock_count = $ResidualLockCount
        completed_at = [DateTimeOffset]::UtcNow.ToString('o')
        checkpoint_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $checkpoint.GetEnumerator()) {
        if ($entry.Key -ne 'checkpoint_sha256') {
            $withoutHash[$entry.Key] = $entry.Value
        }
    }
    $checkpoint.checkpoint_sha256 = Get-WorkforceJsonNativeHash $withoutHash
    Assert-WorkforceNoSensitiveText (ConvertTo-WorkforceCanonicalJson $checkpoint)
    return [pscustomobject]$checkpoint
}

function Write-WorkforceCheckpoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Checkpoint
    )

    Write-WorkforceAtomicJson -Path $Path -Value $Checkpoint -Pretty
    $verified = Read-WorkforceCheckpoint -Path $Path
    if ($verified.checkpoint_sha256 -ne $Checkpoint.checkpoint_sha256) {
        throw 'Checkpoint changed during its atomic write.'
    }
}

function Read-WorkforceCheckpoint {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Checkpoint does not exist: $Path"
    }
    $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
    Assert-WorkforceNoSensitiveText $raw
    $checkpoint = $raw | ConvertFrom-Json
    $expected = @(
        'schema_version', 'step_id', 'step_label', 'step_ordinal', 'status',
        'source_tree_sha256', 'git_sha', 'runner_sha256', 'executable_input_sha256',
        'mode', 'normalized_arguments_sha256', 'model_sha256', 'runtime_sha256',
        'role_contract_sha256', 'shadow_profile_sha256', 'readiness_policy_sha256',
        'cohort_sha256', 'required_binding_fields', 'predecessor_evidence_sha256s',
        'produced_artifacts', 'stdout_path', 'stdout_sha256', 'stderr_path',
        'stderr_sha256', 'exit_code', 'cleanup_verified', 'residual_process_count',
        'residual_credential_count', 'residual_activation_count',
        'residual_profile_count', 'residual_lock_count', 'completed_at',
        'checkpoint_sha256'
    )
    $actual = @($checkpoint.PSObject.Properties.Name)
    if (@($expected | Where-Object { $_ -notin $actual }).Count -ne 0 -or
        @($actual | Where-Object { $_ -notin $expected }).Count -ne 0) {
        throw 'Checkpoint fields differ from the closed schema.'
    }
    $withoutHash = [ordered]@{}
    foreach ($property in $checkpoint.PSObject.Properties) {
        if ($property.Name -ne 'checkpoint_sha256') {
            $withoutHash[$property.Name] = $property.Value
        }
    }
    $calculatedHash = Get-WorkforceObjectHash $withoutHash
    if ($calculatedHash -ne $checkpoint.checkpoint_sha256) {
        throw "Checkpoint canonical hash verification failed: expected $($checkpoint.checkpoint_sha256), calculated $calculatedHash."
    }
    return $checkpoint
}

function Test-WorkforceCheckpoint {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$ExecutableInputSha256,
        [Parameter(Mandatory)][string]$OutputRoot,
        [string[]]$RequiredDependencyHashes = @()
    )

    try {
        $checkpoint = Read-WorkforceCheckpoint -Path $Path
        if ($checkpoint.schema_version -ne 1 -or $checkpoint.status -ne 'verified_success' -or
            $checkpoint.exit_code -ne 0 -or -not $checkpoint.cleanup_verified -or
            $checkpoint.residual_process_count -ne 0 -or
            $checkpoint.residual_credential_count -ne 0 -or
            $checkpoint.residual_activation_count -ne 0 -or
            $checkpoint.residual_profile_count -ne 0 -or
            $checkpoint.residual_lock_count -ne 0) {
            throw 'Checkpoint is not a cleaned verified success.'
        }
        if ($checkpoint.executable_input_sha256 -ne $ExecutableInputSha256) {
            throw 'Executable input hash changed.'
        }
        foreach ($field in @($checkpoint.required_binding_fields)) {
            if (-not $Context.ContainsKey($field) -or $checkpoint.$field -ne $Context[$field]) {
                throw "Checkpoint binding changed: $field"
            }
        }
        $actualDependencies = @($checkpoint.predecessor_evidence_sha256s | Sort-Object -Unique)
        $expectedDependencies = @($RequiredDependencyHashes | Sort-Object -Unique)
        if ((ConvertTo-WorkforceCanonicalJson $actualDependencies) -ne (ConvertTo-WorkforceCanonicalJson $expectedDependencies)) {
            throw 'Checkpoint predecessor binding changed.'
        }
        foreach ($artifact in @($checkpoint.produced_artifacts)) {
            $path = [System.IO.Path]::GetFullPath((Join-Path $OutputRoot $artifact.path))
            $root = [System.IO.Path]::GetFullPath($OutputRoot)
            if (-not $path.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-Path -LiteralPath $path -PathType Leaf) -or
                (Get-WorkforceFileHash $path) -ne $artifact.sha256) {
                throw "Checkpoint artifact changed: $($artifact.path)"
            }
        }
        foreach ($log in @(
            @($checkpoint.stdout_path, $checkpoint.stdout_sha256),
            @($checkpoint.stderr_path, $checkpoint.stderr_sha256)
        )) {
            if ($null -eq $log[0]) {
                if ($log[1] -ne $script:EmptyHash) { throw 'Missing log has a non-empty hash.' }
                continue
            }
            $path = Join-Path $OutputRoot $log[0]
            if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-WorkforceFileHash $path) -ne $log[1]) {
                throw "Checkpoint log changed: $($log[0])"
            }
        }
        return [pscustomobject]@{ Valid = $true; Reason = $null; Checkpoint = $checkpoint }
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Reason = $_.Exception.Message; Checkpoint = $null }
    }
}

function New-WorkforceResumeManifest {
    param(
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$RunId,
        [string]$LastVerifiedCheckpoint,
        [string[]]$VerifiedCheckpointHashes = @(),
        [string[]]$InvalidatedCheckpointIds = @(),
        [string]$PendingStepId,
        [string]$FailedStepId,
        [int]$ResumeCount = 0
    )

    $manifest = [ordered]@{
        schema_version = 1
        run_id = $RunId
        source_tree_sha256 = $Context.source_tree_sha256
        current_git_sha = $Context.git_sha
        model_sha256 = $Context.model_sha256
        runtime_sha256 = $Context.runtime_sha256
        mode = $Context.mode
        last_verified_checkpoint = $LastVerifiedCheckpoint
        verified_checkpoint_hashes = @($VerifiedCheckpointHashes | Sort-Object -Unique)
        invalidated_checkpoint_ids = @($InvalidatedCheckpointIds | Sort-Object -Unique)
        pending_step_id = $PendingStepId
        failed_step_id = $FailedStepId
        resume_count = $ResumeCount
        manifest_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $manifest.GetEnumerator()) {
        if ($entry.Key -ne 'manifest_sha256') { $withoutHash[$entry.Key] = $entry.Value }
    }
    $manifest.manifest_sha256 = Get-WorkforceJsonNativeHash $withoutHash
    return [pscustomobject]$manifest
}

function Read-WorkforceResumeManifest {
    param([Parameter(Mandatory)][string]$Path)

    $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
    Assert-WorkforceNoSensitiveText $raw
    $manifest = $raw | ConvertFrom-Json
    $expected = @(
        'schema_version', 'run_id', 'source_tree_sha256', 'current_git_sha',
        'model_sha256', 'runtime_sha256', 'mode', 'last_verified_checkpoint',
        'verified_checkpoint_hashes', 'invalidated_checkpoint_ids',
        'pending_step_id', 'failed_step_id', 'resume_count', 'manifest_sha256'
    )
    $actual = @($manifest.PSObject.Properties.Name)
    if (@($expected | Where-Object { $_ -notin $actual }).Count -ne 0 -or
        @($actual | Where-Object { $_ -notin $expected }).Count -ne 0) {
        throw 'Resume manifest fields differ from the closed schema.'
    }
    $withoutHash = [ordered]@{}
    foreach ($property in $manifest.PSObject.Properties) {
        if ($property.Name -ne 'manifest_sha256') { $withoutHash[$property.Name] = $property.Value }
    }
    if ((Get-WorkforceObjectHash $withoutHash) -ne $manifest.manifest_sha256) {
        throw 'Resume manifest canonical hash verification failed.'
    }
    return $manifest
}

function Get-WorkforceCheckpointSetHash {
    param([Parameter(Mandatory)][object[]]$Checkpoints)

    $set = @($Checkpoints | Sort-Object step_ordinal, step_id | ForEach-Object {
        [ordered]@{ step_id = $_.step_id; checkpoint_sha256 = $_.checkpoint_sha256 }
    })
    return Get-WorkforceObjectHash $set
}

function Write-WorkforceFailureDiagnostic {
    param(
        [Parameter(Mandatory)][string]$DiagnosticRoot,
        [Parameter(Mandatory)][hashtable]$Context,
        [Parameter(Mandatory)][string]$FailedStepId,
        [Parameter(Mandatory)][int]$ExitCode,
        [Parameter(Mandatory)][string]$ExceptionClass,
        [string]$LastVerifiedCheckpointHash,
        [string]$StdoutPath,
        [string]$StderrPath,
        [bool]$CleanupVerified,
        [int]$ResidualProcessCount,
        [int]$ResidualCredentialCount,
        [int]$ResidualActivationCount,
        [int]$ResidualProfileCount,
        [int]$ResidualLockCount
    )

    New-Item -ItemType Directory -Path $DiagnosticRoot -Force | Out-Null
    function Get-BoundedDiagnostic([string]$Path, [string]$DestinationName) {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return [pscustomobject]@{ path = $null; sha256 = $script:EmptyHash; tail = '' }
        }
        $content = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
        if ($null -eq $content) { $content = '' }
        if ($content.Length -gt 8192) { $content = $content.Substring($content.Length - 8192) }
        $tail = if ($content -match $script:SensitivePattern) { '[REDACTED_BY_SECRET_SCANNER]' } else { $content }
        $destination = Join-Path $DiagnosticRoot $DestinationName
        [System.IO.File]::WriteAllText($destination, $tail, [System.Text.UTF8Encoding]::new($false))
        return [pscustomobject]@{
            path = $DestinationName
            sha256 = Get-WorkforceFileHash $Path
            tail = $tail
        }
    }
    $stdout = Get-BoundedDiagnostic $StdoutPath "$FailedStepId.stdout.tail.log"
    $stderr = Get-BoundedDiagnostic $StderrPath "$FailedStepId.stderr.tail.log"
    $failure = [ordered]@{
        schema_version = 1
        failed_step_id = $FailedStepId
        exit_code = $ExitCode
        exception_class = $ExceptionClass
        source_tree_sha256 = $Context.source_tree_sha256
        runner_sha256 = $Context.runner_sha256
        last_verified_checkpoint_sha256 = $LastVerifiedCheckpointHash
        model_sha256 = $Context.model_sha256
        runtime_sha256 = $Context.runtime_sha256
        stdout_path = $stdout.path
        stdout_sha256 = $stdout.sha256
        stderr_path = $stderr.path
        stderr_sha256 = $stderr.sha256
        bounded_stderr_tail = $stderr.tail
        cleanup_verified = $CleanupVerified
        residual_process_count = $ResidualProcessCount
        residual_credential_count = $ResidualCredentialCount
        residual_activation_count = $ResidualActivationCount
        residual_profile_count = $ResidualProfileCount
        residual_lock_count = $ResidualLockCount
        failure_sha256 = $null
    }
    $withoutHash = [ordered]@{}
    foreach ($entry in $failure.GetEnumerator()) {
        if ($entry.Key -ne 'failure_sha256') { $withoutHash[$entry.Key] = $entry.Value }
    }
    $failure.failure_sha256 = Get-WorkforceJsonNativeHash $withoutHash
    Write-WorkforceAtomicJson -Path (Join-Path $DiagnosticRoot 'failure.json') -Value $failure -Pretty
    return [pscustomobject]$failure
}

Export-ModuleMember -Function @(
    'Get-WorkforceSha256Text', 'Get-WorkforceFileHash', 'ConvertTo-WorkforceCanonicalJson',
    'Get-WorkforceObjectHash', 'Assert-WorkforceNoSensitiveText', 'Write-WorkforceAtomicJson',
    'Get-WorkforcePathSetHash', 'Get-WorkforceSourceTreeHash', 'Get-WorkforceBoundedArtifact',
    'New-WorkforceCheckpoint', 'Write-WorkforceCheckpoint', 'Read-WorkforceCheckpoint',
    'Test-WorkforceCheckpoint', 'New-WorkforceResumeManifest', 'Read-WorkforceResumeManifest',
    'Get-WorkforceCheckpointSetHash', 'Write-WorkforceFailureDiagnostic'
)
