[CmdletBinding()]
param(
    [ValidateSet('Completion', 'SelfTest')]
    [string]$Mode = 'Completion',
    [string]$Runtime,
    [string]$Model,
    [string]$Office500EvidenceRoot,
    [string]$Edge,
    [string]$EdgeDriver,
    [string]$ExternalCanaryUrl = 'https://www.microsoft.com/robots.txt',
    [string]$ExternalDownloadCanaryUrl = 'https://www.w3.org/robots.txt',
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$targetRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'target'))
if (-not $OutputRoot) { $OutputRoot = Join-Path $targetRoot 'd2i-office600-certified-closeout' }
elseif (-not [IO.Path]::IsPathRooted($OutputRoot)) { $OutputRoot = Join-Path $repoRoot $OutputRoot }
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
if (-not $OutputRoot.StartsWith($targetRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputRoot must remain inside this repository target directory.'
}

$associationKey = 'Software\Microsoft\Windows\CurrentVersion\Policies\Associations'
$attachmentsKey = 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'
$admxPath = Join-Path $env:SystemRoot 'PolicyDefinitions\AttachmentManager.admx'
$qualificationBinary = Join-Path $targetRoot 'release\d2i-office600-policy-qualification.exe'
$privatePolicyRoot = Join-Path $OutputRoot 'protected-policy-evidence'
$completionRoot = Join-Path $OutputRoot 'completion'
$maximumPolicyValueBytes = 65536
$maximumPolicyEntries = 64

if (-not ('D2I.Office600.RegistryNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace D2I.Office600 {
    public static class RegistryNative {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegOpenKeyEx(IntPtr hKey, string subKey, uint options, uint samDesired, out IntPtr result);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegCreateKeyEx(IntPtr hKey, string subKey, uint reserved, string keyClass, uint options, uint samDesired, IntPtr securityAttributes, out IntPtr result, out uint disposition);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegQueryValueEx(IntPtr hKey, string valueName, IntPtr reserved, out uint type, byte[] data, ref uint dataSize);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegSetValueEx(IntPtr hKey, string valueName, uint reserved, uint type, byte[] data, uint dataSize);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        public static extern int RegDeleteValue(IntPtr hKey, string valueName);
        [DllImport("advapi32.dll")]
        public static extern int RegCloseKey(IntPtr hKey);
    }
}
'@
}

function Get-IsElevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-NoReparsePath([string]$Path) {
    $relative = $Path.Substring($targetRoot.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
    $current = $targetRoot
    foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
        $current = Join-Path $current $segment
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Completion path cannot traverse a reparse point: $current"
            }
        }
    }
}

function Protect-EvidenceDirectory([string]$Path, [string]$UserSid) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    & icacls.exe $Path '/inheritance:r' '/grant:r' "*$($UserSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Protected evidence ACL installation failed.' }
    $acl = Get-Acl -LiteralPath $Path
    if (-not $acl.AreAccessRulesProtected) { throw 'Protected evidence ACL still inherits.' }
    $allowed = @($UserSid, 'S-1-5-18')
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin $allowed -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
            throw "Protected evidence ACL has an unexpected rule: $sid"
        }
    }
}

function Get-Sha256Bytes([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { $hash = $algorithm.ComputeHash($Bytes) }
    finally { $algorithm.Dispose() }
    return 'sha256:' + (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-Sha256File([string]$Path) {
    return Get-Sha256Bytes ([IO.File]::ReadAllBytes($Path))
}

function Get-CanonicalHash([object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 32 -Compress).Replace("`r`n", "`n")
    return Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes($json))
}

function Get-RegistryTypeName([uint32]$Type) {
    switch ($Type) {
        0 { return 'reg_none' }
        1 { return 'reg_sz' }
        2 { return 'reg_expand_sz' }
        3 { return 'reg_binary' }
        4 { return 'reg_dword' }
        7 { return 'reg_multi_sz' }
        11 { return 'reg_qword' }
        default { throw "Unsupported registry value type: $Type" }
    }
}

function Get-RawRegistryValue([string]$KeyPath, [string]$ValueName) {
    $hkcu = [IntPtr]::new(-2147483647)
    $handle = [IntPtr]::Zero
    $open = [D2I.Office600.RegistryNative]::RegOpenKeyEx($hkcu, $KeyPath, 0, 0x20019, [ref]$handle)
    if ($open -eq 2) {
        return [ordered]@{ exists = $false; type_code = 0; type = 'none'; bytes_base64 = ''; sha256 = Get-Sha256Bytes ([byte[]]@()) }
    }
    if ($open -ne 0) { throw "RegOpenKeyEx failed for $KeyPath with $open" }
    try {
        [uint32]$type = 0
        [uint32]$size = 0
        $query = [D2I.Office600.RegistryNative]::RegQueryValueEx($handle, $ValueName, [IntPtr]::Zero, [ref]$type, $null, [ref]$size)
        if ($query -eq 2) {
            return [ordered]@{ exists = $false; type_code = 0; type = 'none'; bytes_base64 = ''; sha256 = Get-Sha256Bytes ([byte[]]@()) }
        }
        if ($query -notin @(0, 234)) { throw "RegQueryValueEx size failed for $ValueName with $query" }
        if ($size -gt $maximumPolicyValueBytes) { throw "Registry policy value exceeds $maximumPolicyValueBytes bytes: $ValueName" }
        [byte[]]$bytes = [byte[]]::new($size)
        if ($size -gt 0) {
            $query = [D2I.Office600.RegistryNative]::RegQueryValueEx($handle, $ValueName, [IntPtr]::Zero, [ref]$type, $bytes, [ref]$size)
            if ($query -ne 0) { throw "RegQueryValueEx data failed for $ValueName with $query" }
            if ($bytes.Length -ne $size) { $bytes = $bytes[0..($size - 1)] }
        }
        return [ordered]@{
            exists = $true
            type_code = $type
            type = Get-RegistryTypeName $type
            bytes_base64 = [Convert]::ToBase64String($bytes)
            sha256 = Get-Sha256Bytes $bytes
        }
    }
    finally { [void][D2I.Office600.RegistryNative]::RegCloseKey($handle) }
}

function Set-RawRegistryValue([string]$KeyPath, [string]$ValueName, [uint32]$Type, [byte[]]$Bytes) {
    $hkcu = [IntPtr]::new(-2147483647)
    $handle = [IntPtr]::Zero
    [uint32]$disposition = 0
    $create = [D2I.Office600.RegistryNative]::RegCreateKeyEx($hkcu, $KeyPath, 0, $null, 0, 0x20006, [IntPtr]::Zero, [ref]$handle, [ref]$disposition)
    if ($create -ne 0) { throw "RegCreateKeyEx failed for $KeyPath with $create" }
    try {
        $set = [D2I.Office600.RegistryNative]::RegSetValueEx($handle, $ValueName, 0, $Type, $Bytes, $Bytes.Length)
        if ($set -ne 0) { throw "RegSetValueEx failed for $ValueName with $set" }
    }
    finally { [void][D2I.Office600.RegistryNative]::RegCloseKey($handle) }
}

function Remove-RawRegistryValue([string]$KeyPath, [string]$ValueName) {
    $hkcu = [IntPtr]::new(-2147483647)
    $handle = [IntPtr]::Zero
    $open = [D2I.Office600.RegistryNative]::RegOpenKeyEx($hkcu, $KeyPath, 0, 0x20006, [ref]$handle)
    if ($open -eq 2) { return }
    if ($open -ne 0) { throw "RegOpenKeyEx failed for $KeyPath with $open" }
    try {
        $delete = [D2I.Office600.RegistryNative]::RegDeleteValue($handle, $ValueName)
        if ($delete -notin @(0, 2)) { throw "RegDeleteValue failed for $ValueName with $delete" }
    }
    finally { [void][D2I.Office600.RegistryNative]::RegCloseKey($handle) }
}

function Test-RegistryKeyExists([string]$KeyPath) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($KeyPath, $false)
    if ($null -eq $key) { return $false }
    $key.Dispose()
    return $true
}

function Remove-RegistryKeyIfEmpty([string]$KeyPath) {
    $separator = $KeyPath.LastIndexOf('\')
    if ($separator -lt 1) { throw 'Registry key path is not nested.' }
    $parentPath = $KeyPath.Substring(0, $separator)
    $name = $KeyPath.Substring($separator + 1)
    $parent = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($parentPath, $true)
    if ($null -eq $parent) { return }
    try {
        $child = $parent.OpenSubKey($name, $false)
        if ($null -eq $child) { return }
        try {
            if ($child.GetValueNames().Count -ne 0 -or $child.GetSubKeyNames().Count -ne 0) {
                throw 'Refusing to remove a registry key that is not empty.'
            }
        }
        finally { $child.Dispose() }
        $parent.DeleteSubKey($name, $false)
    }
    finally { $parent.Dispose() }
}

function Get-KeyState([string]$KeyPath) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($KeyPath, $false)
    if ($null -eq $key) { return [ordered]@{ exists = $false; values = @(); subkeys = @() } }
    try {
        $valueNames = @($key.GetValueNames() | Sort-Object)
        $subkeys = @($key.GetSubKeyNames() | Sort-Object)
        if ($valueNames.Count -gt $maximumPolicyEntries -or $subkeys.Count -gt $maximumPolicyEntries) {
            throw 'Attachment policy key exceeds its bounded entry count.'
        }
        $values = @($valueNames | ForEach-Object {
            [ordered]@{ name = $_; raw = Get-RawRegistryValue $KeyPath $_ }
        })
        return [ordered]@{
            exists = $true
            values = $values
            subkeys = $subkeys
        }
    }
    finally { $key.Dispose() }
}

function Assert-AttachmentAdmx([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw 'AttachmentManager.admx is absent.' }
    if ((Get-Item -LiteralPath $Path).Length -gt 2097152) { throw 'AttachmentManager.admx exceeds its bounded size.' }
    [xml]$xml = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    $namespace = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $namespace.AddNamespace('p', $xml.DocumentElement.NamespaceURI)
    $expected = @(
        @('AM_SetLowRiskInclusion', 'LowRiskFileTypes'),
        @('AM_SetModRiskInclusion', 'ModRiskFileTypes'),
        @('AM_SetHighRiskInclusion', 'HighRiskFileTypes')
    )
    foreach ($entry in $expected) {
        $node = $xml.SelectSingleNode("//p:policy[@name='$($entry[0])']", $namespace)
        $text = if ($null -ne $node) { $node.SelectSingleNode('./p:elements/p:text', $namespace) } else { $null }
        if ($null -eq $node -or $null -eq $text -or
            $node.GetAttribute('class') -ne 'User' -or
            $node.GetAttribute('key') -ne $associationKey -or
            $text.GetAttribute('valueName') -ne $entry[1]) {
            throw "AttachmentManager ADMX mapping differs: $($entry[0])"
        }
    }
    return Get-Sha256File $Path
}

function Convert-RawRegistryText([object]$Raw, [string]$Label) {
    if (-not $Raw.exists) { return '' }
    if ($Raw.type -notin @('reg_sz', 'reg_expand_sz', 'reg_multi_sz')) {
        throw "policy_precedence_conflict: $Label has a non-text registry type"
    }
    $bytes = [Convert]::FromBase64String($Raw.bytes_base64)
    return [Text.Encoding]::Unicode.GetString($bytes).Trim([char]0)
}

function Test-ContainsTxt([object]$Raw, [string]$Label) {
    $text = Convert-RawRegistryText $Raw $Label
    return @($text -split '[;\x00]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -contains '.txt'
}

function New-RawSnapshotInput([string]$Path, [string]$UserSid, [string]$AdmxSha256) {
    $associationState = Get-KeyState $associationKey
    $attachmentsState = Get-KeyState $attachmentsKey
    $low = Get-RawRegistryValue $associationKey 'LowRiskFileTypes'
    $moderate = Get-RawRegistryValue $associationKey 'ModRiskFileTypes'
    $high = Get-RawRegistryValue $associationKey 'HighRiskFileTypes'
    $policyState = [ordered]@{ associations = $associationState; attachments = $attachmentsState }
    $attachmentsHash = if ($attachmentsState.exists) { Get-CanonicalHash $attachmentsState } else { $null }
    $value = [ordered]@{
        schema_version = 1
        user_sid = $UserSid
        admx_sha256 = $AdmxSha256
        association_key_exists = [bool]$associationState.exists
        low_risk_value_exists = [bool]$low.exists
        low_risk_value_type = [string]$low.type
        low_risk_value_bytes_base64 = [string]$low.bytes_base64
        low_risk_value_sha256 = [string]$low.sha256
        moderate_risk_value_exists = [bool]$moderate.exists
        moderate_risk_value_type = [string]$moderate.type
        moderate_risk_value_bytes_base64 = [string]$moderate.bytes_base64
        moderate_risk_value_sha256 = [string]$moderate.sha256
        high_risk_value_exists = [bool]$high.exists
        high_risk_value_type = [string]$high.type
        high_risk_value_bytes_base64 = [string]$high.bytes_base64
        high_risk_value_sha256 = [string]$high.sha256
        attachments_policy_sha256 = $attachmentsHash
        policy_state_sha256 = Get-CanonicalHash $policyState
        captured_at_unix_ms = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        snapshot_sha256 = 'sha256:' + ('0' * 64)
    }
    [IO.File]::WriteAllText($Path, (($value | ConvertTo-Json -Depth 32) + "`n"), [Text.UTF8Encoding]::new($false))
}

function Invoke-Native([string]$Command, [string[]]$Arguments) {
    Push-Location $repoRoot
    try {
        & $Command @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Command failed with exit code $LASTEXITCODE" }
    }
    finally { Pop-Location }
}

function Get-PolicySnapshot([string]$Label, [string]$UserSid, [string]$AdmxSha256) {
    Protect-EvidenceDirectory $privatePolicyRoot $UserSid
    $input = Join-Path $privatePolicyRoot "$Label.input.json"
    $output = Join-Path $privatePolicyRoot "$Label.json"
    New-RawSnapshotInput $input $UserSid $AdmxSha256
    try { Invoke-Native $qualificationBinary @('seal-snapshot', $input, $output) }
    finally { Remove-Item -LiteralPath $input -Force -ErrorAction SilentlyContinue }
    return Get-Content -Raw -LiteralPath $output -Encoding UTF8 | ConvertFrom-Json
}

function Restore-Policy([object]$Original) {
    foreach ($entry in @(
        @('LowRiskFileTypes', $Original.low_risk_value_exists, $Original.low_risk_value_type, $Original.low_risk_value_bytes_base64),
        @('ModRiskFileTypes', $Original.moderate_risk_value_exists, $Original.moderate_risk_value_type, $Original.moderate_risk_value_bytes_base64),
        @('HighRiskFileTypes', $Original.high_risk_value_exists, $Original.high_risk_value_type, $Original.high_risk_value_bytes_base64)
    )) {
        if ([bool]$entry[1]) {
            $typeCode = switch ($entry[2]) {
                'reg_none' { 0 } 'reg_sz' { 1 } 'reg_expand_sz' { 2 } 'reg_binary' { 3 }
                'reg_dword' { 4 } 'reg_multi_sz' { 7 } 'reg_qword' { 11 }
                default { throw "Unsupported restore registry type: $($entry[2])" }
            }
            Set-RawRegistryValue $associationKey $entry[0] $typeCode ([Convert]::FromBase64String($entry[3]))
        }
        else { Remove-RawRegistryValue $associationKey $entry[0] }
    }
    if (-not $Original.association_key_exists) { Remove-RegistryKeyIfEmpty $associationKey }
}

function Invoke-SelfTest {
    $selfTestRoot = Join-Path $OutputRoot 'self-test'
    if (Test-Path -LiteralPath $selfTestRoot) { Remove-Item -LiteralPath $selfTestRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $selfTestRoot -Force | Out-Null
    $admxHash = Assert-AttachmentAdmx $admxPath
    $invalidAdmx = Join-Path $selfTestRoot 'invalid.admx'
    [IO.File]::WriteAllText($invalidAdmx, '<policyDefinitions><policies /></policyDefinitions>')
    $mismatchRejected = $false
    try { [void](Assert-AttachmentAdmx $invalidAdmx) } catch { $mismatchRejected = $true }
    if (-not $mismatchRejected) { throw 'ADMX mismatch was not rejected.' }

    Invoke-Native 'cargo' @('build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office600-policy-qualification')
    $selfTestSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $snapshotA = Get-PolicySnapshot 'self-test-policy-a' $selfTestSid $admxHash
    $snapshotB = Get-PolicySnapshot 'self-test-policy-b' $selfTestSid $admxHash
    if ($snapshotA.policy_state_sha256 -ne $snapshotB.policy_state_sha256) {
        throw 'Read-only policy snapshot hash is not reproducible.'
    }
    $wrongSidRejected = $false
    try {
        Invoke-Native $qualificationBinary @(
            'probe', (Join-Path $selfTestRoot 'wrong-sid-probe.json'),
            'S-1-5-21-0-0-0-9999', $admxHash,
            (Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes('original'))),
            (Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes('staged')))
        )
    }
    catch { $wrongSidRejected = $true }
    if (-not $wrongSidRejected) { throw 'Wrong policy subject SID was not rejected.' }

    $highRiskTxt = [ordered]@{
        exists = $true
        type = 'reg_sz'
        bytes_base64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(".txt`0"))
    }
    if (-not (Test-ContainsTxt $highRiskTxt 'self-test-high-risk')) {
        throw 'Higher-precedence TXT conflict self-test failed.'
    }

    $testKey = "Software\D2I\Tests\Office600AttachmentPolicy\$([Guid]::NewGuid().ToString('N'))"
    $originalBytes = [Text.Encoding]::Unicode.GetBytes("legacy;.dat`0")
    try {
        Set-RawRegistryValue $testKey 'LowRiskFileTypes' 1 $originalBytes
        $original = Get-RawRegistryValue $testKey 'LowRiskFileTypes'
        Set-RawRegistryValue $testKey 'LowRiskFileTypes' 1 ([Text.Encoding]::Unicode.GetBytes(".txt`0"))
        Set-RawRegistryValue $testKey 'LowRiskFileTypes' ([uint32]$original.type_code) ([Convert]::FromBase64String($original.bytes_base64))
        $restored = Get-RawRegistryValue $testKey 'LowRiskFileTypes'
        if ($original.type -ne $restored.type -or $original.bytes_base64 -ne $restored.bytes_base64) {
            throw 'Snapshot/restore exact self-test failed.'
        }
        Remove-RawRegistryValue $testKey 'LowRiskFileTypes'
        Remove-RegistryKeyIfEmpty $testKey
    }
    finally {
        try { Remove-RawRegistryValue $testKey 'LowRiskFileTypes' } catch { }
        try { Remove-RegistryKeyIfEmpty $testKey } catch { }
    }
    $finished = [ordered]@{
        complete = $true
        admx_sha256 = $admxHash
        admx_mismatch_rejected = $mismatchRejected
        wrong_sid_rejected = $wrongSidRejected
        higher_precedence_txt_conflict_detected = $true
        snapshot_hash_reproducible = $true
        exact_registry_restore = $true
        elevated = Get-IsElevated
    }
    [IO.File]::WriteAllText((Join-Path $selfTestRoot 'finished.json'), (($finished | ConvertTo-Json) + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Output "OFFICE-600 policy wrapper self-test passed: $selfTestRoot"
}

if ($Mode -eq 'SelfTest') {
    Assert-NoReparsePath $OutputRoot
    Invoke-SelfTest
    exit 0
}

if (-not [Environment]::UserInteractive) { throw 'interactive_session_required' }
if (-not (Get-IsElevated)) { throw 'administrator_token_required' }
if ((git -C $repoRoot status --porcelain).Count -ne 0) { throw 'Completion requires a clean committed worktree.' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$userSid = $identity.User.Value
$head = (git -C $repoRoot rev-parse HEAD).Trim()
$tree = (git -C $repoRoot rev-parse 'HEAD^{tree}').Trim()
$admxHash = Assert-AttachmentAdmx $admxPath

Assert-NoReparsePath $OutputRoot
if (Test-Path -LiteralPath $OutputRoot) { Remove-Item -LiteralPath $OutputRoot -Recurse -Force }
New-Item -ItemType Directory -Path $OutputRoot, $privatePolicyRoot -Force | Out-Null

Invoke-Native 'cargo' @('build', '--locked', '--release', '-p', 'd2i-desktop', '--bin', 'd2i-office600-policy-qualification')
$original = Get-PolicySnapshot 'original-policy' $userSid $admxHash
$higherConflict = (Test-ContainsTxt (Get-RawRegistryValue $associationKey 'HighRiskFileTypes') 'HighRiskFileTypes') -or
    (Test-ContainsTxt (Get-RawRegistryValue $associationKey 'ModRiskFileTypes') 'ModRiskFileTypes')
if ($higherConflict) { throw 'policy_precedence_conflict' }

$policyStaged = $false
$completionSucceeded = $false
$probePath = Join-Path $OutputRoot 'attachment-policy-probe.json'
$qualificationPath = Join-Path $OutputRoot 'attachment-policy-qualification.json'
$stageMicros = [uint64]0
$restoreMicros = [uint64]0
$total = [Diagnostics.Stopwatch]::StartNew()
$completionError = $null

try {
    $stage = [Diagnostics.Stopwatch]::StartNew()
    Set-RawRegistryValue $associationKey 'LowRiskFileTypes' 1 ([Text.Encoding]::Unicode.GetBytes(".txt`0"))
    $policyStaged = $true
    $staged = Get-PolicySnapshot 'staged-policy' $userSid $admxHash
    $stage.Stop()
    $stageMicros = [uint64]($stage.Elapsed.TotalMilliseconds * 1000)
    if ($staged.low_risk_value_type -ne 'reg_sz' -or
        (Convert-RawRegistryText (Get-RawRegistryValue $associationKey 'LowRiskFileTypes') 'LowRiskFileTypes') -ne '.txt') {
        throw 'temporary completion policy did not stage exact .txt scope'
    }
    if ($original.moderate_risk_value_sha256 -ne $staged.moderate_risk_value_sha256 -or
        $original.high_risk_value_sha256 -ne $staged.high_risk_value_sha256) {
        throw 'temporary completion policy changed higher-precedence values'
    }

    Invoke-Native $qualificationBinary @(
        'probe', $probePath, $userSid, $admxHash,
        $original.policy_state_sha256, $staged.policy_state_sha256
    )

    $runnerArguments = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
        (Join-Path $repoRoot 'scripts/office/run-browser-research-v1.ps1'),
        '-Mode', 'Completion', '-Runtime', $Runtime, '-Model', $Model,
        '-Office500EvidenceRoot', $Office500EvidenceRoot,
        '-ExternalCanaryUrl', $ExternalCanaryUrl,
        '-ExternalDownloadCanaryUrl', $ExternalDownloadCanaryUrl,
        '-OutputRoot', $completionRoot, '-ReuseVerifiedPredecessorEvidence', '-Fresh'
    )
    if ($Edge) { $runnerArguments += @('-Edge', $Edge) }
    if ($EdgeDriver) { $runnerArguments += @('-EdgeDriver', $EdgeDriver) }
    Invoke-Native 'powershell' $runnerArguments
    $completionSucceeded = $true
}
catch { $completionError = $_ }
finally {
    if ($policyStaged) {
        $restore = [Diagnostics.Stopwatch]::StartNew()
        try { Restore-Policy $original }
        finally {
            $restore.Stop()
            $restoreMicros = [uint64]($restore.Elapsed.TotalMilliseconds * 1000)
        }
    }
}

$restored = Get-PolicySnapshot 'restored-policy' $userSid $admxHash
$restoredExactly = $restored.policy_state_sha256 -eq $original.policy_state_sha256
$total.Stop()
if (-not $restoredExactly) { throw 'attachment_policy_restore_mismatch' }
if ($null -ne $completionError) { throw $completionError }
if (-not $completionSucceeded) { throw 'OFFICE-600 Completion did not succeed.' }

Invoke-Native $qualificationBinary @(
    'finalize', $probePath, $restored.policy_state_sha256, 'true',
    [string]$stageMicros, [string]$restoreMicros,
    [string][uint64]($total.Elapsed.TotalMilliseconds * 1000), $qualificationPath
)

$finishedPath = Join-Path $completionRoot 'execution\finished.json'
$executionCertificationPath = Join-Path $completionRoot 'execution\certification.json'
$executionPublicKeyPath = Join-Path $completionRoot 'execution\certification-public-key.hex'
$finished = Get-Content -Raw -LiteralPath $finishedPath -Encoding UTF8 | ConvertFrom-Json
$closeoutPath = Join-Path $OutputRoot 'closeout-certification.json'
$closeoutPublicKeyPath = Join-Path $OutputRoot 'closeout-certification-public-key.hex'
Invoke-Native $qualificationBinary @(
    'certify', $finishedPath, $executionCertificationPath, $executionPublicKeyPath,
    $qualificationPath, $finished.source_tree_sha256, $closeoutPath, $closeoutPublicKeyPath
)
Invoke-Native $qualificationBinary @(
    'verify-closeout', $closeoutPath, $closeoutPublicKeyPath, $finishedPath,
    $executionCertificationPath, $executionPublicKeyPath, $qualificationPath
)

$environment = [ordered]@{
    schema_version = 1
    branch = (git -C $repoRoot branch --show-current).Trim()
    git_head = $head
    git_tree = $tree
    d2i_source_tree_sha256 = $finished.source_tree_sha256
    user_sid = $userSid
    elevated = $true
    attachment_policy_restored = $true
    original_policy_sha256 = $original.policy_state_sha256
    restored_policy_sha256 = $restored.policy_state_sha256
    closeout_certification_sha256 = (Get-Content -Raw -LiteralPath $closeoutPath | ConvertFrom-Json).certification_sha256
    complete = $true
}
[IO.File]::WriteAllText((Join-Path $OutputRoot 'finished.json'), (($environment | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "D2I OFFICE-600 certified closeout complete: $OutputRoot"
