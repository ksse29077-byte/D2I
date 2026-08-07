[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sourcePath = Join-Path $repoRoot 'crates/d2i-limited-autonomy/src/contracts.rs'
$schemaRoot = Join-Path $repoRoot 'schemas/workforce'
$source = [System.IO.File]::ReadAllText($sourcePath)
$utf8 = [System.Text.UTF8Encoding]::new($false)

$artifacts = [ordered]@{
    AutonomyReadinessBindingV1 = 'autonomy-readiness-binding-v1.schema.json'
    LimitedAutonomyProfileV1 = 'limited-autonomy-profile-v1.schema.json'
    AutonomyDeploymentApprovalV1 = 'autonomy-deployment-approval-v1.schema.json'
    AutonomyRoleRuntimeStateV1 = 'autonomy-role-runtime-state-v1.schema.json'
    AutonomyControlCommandV1 = 'autonomy-control-command-v1.schema.json'
    AutonomyCaseEligibilityV1 = 'autonomy-case-eligibility-v1.schema.json'
    AutonomyCaseAdmissionV1 = 'autonomy-case-admission-v1.schema.json'
    AutonomousCaseTaskBindingV1 = 'autonomous-case-task-binding-v1.schema.json'
    AutonomyRolloutCohortV1 = 'autonomy-rollout-cohort-v1.schema.json'
    AutonomyHealthSnapshotV1 = 'autonomy-health-snapshot-v1.schema.json'
    AutonomyHealthTripV1 = 'autonomy-health-trip-v1.schema.json'
    HumanExceptionHandoffV1 = 'human-exception-handoff-v1.schema.json'
    HumanExceptionResponseV1 = 'human-exception-response-v1.schema.json'
    AutonomousRoleDutyCycleRequestV1 = 'autonomous-role-duty-cycle-request-v1.schema.json'
    AutonomousRoleDutyCycleResultV1 = 'autonomous-role-duty-cycle-result-v1.schema.json'
    LimitedAutonomyCompletionReportV1 = 'limited-autonomy-completion-report-v1.schema.json'
    LimitedAutonomyReplayReportV1 = 'limited-autonomy-replay-report-v1.schema.json'
    LimitedAutonomyCertificationV1 = 'limited-autonomy-certification-v1.schema.json'
}

function Convert-PascalToSnake([string]$Value) {
    return ([regex]::Replace($Value, '(?<=[a-z0-9])(?=[A-Z])', '_')).ToLowerInvariant()
}

$enumValues = @{}
$enumPattern = 'pub enum (?<name>[A-Za-z0-9_]+)\s*\{(?<body>.*?)\n\}'
foreach ($match in [regex]::Matches($source, $enumPattern, 'Singleline')) {
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $match.Groups['body'].Value -split "`r?`n") {
        $candidate = ($line -replace '//.*$', '').Trim().TrimEnd(',')
        if ($candidate -match '^[A-Z][A-Za-z0-9_]*$') {
            $values.Add((Convert-PascalToSnake $candidate))
        }
    }
    $enumValues[$match.Groups['name'].Value] = @($values)
}

$structFields = @{}
$structPattern = 'pub struct (?<name>[A-Za-z0-9_]+)\s*\{(?<body>.*?)\n\}'
foreach ($match in [regex]::Matches($source, $structPattern, 'Singleline')) {
    $fields = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $match.Groups['body'].Value -split "`r?`n") {
        if ($line -match '^\s*pub\s+(?<name>[a-zA-Z0-9_]+):\s*(?<type>[^,]+),\s*$') {
            $fields.Add([pscustomobject]@{ Name = $Matches['name']; Type = $Matches['type'].Trim() })
        }
    }
    $structFields[$match.Groups['name'].Value] = @($fields)
}

function New-StringSchema([string]$FieldName) {
    if ($FieldName -eq 'signature_hex') {
        return [ordered]@{ type = 'string'; pattern = '^[0-9a-f]{128}$'; maxLength = 128 }
    }
    if ($FieldName -match '(sha256|hash)$') {
        return [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$'; maxLength = 71 }
    }
    return [ordered]@{
        type = 'string'; minLength = 1; maxLength = 512
        pattern = '^[A-Za-z0-9._:/-]+$'
    }
}

function New-TypeSchema([string]$RustType, [string]$FieldName) {
    if ($RustType -match '^Option<(.+)>$') {
        $inner = New-TypeSchema $Matches[1] $FieldName
        if ($inner.Contains('type')) {
            $inner.type = @($inner.type, 'null')
            return $inner
        }
        return [ordered]@{ anyOf = @($inner, [ordered]@{ type = 'null' }) }
    }
    if ($RustType -match '^Vec<(.+)>$') {
        $itemType = $Matches[1]
        $items = if ($itemType -eq 'String' -and $FieldName -match '(hashes|heads)$') {
            [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$'; maxLength = 71 }
        } else { New-TypeSchema $itemType ($FieldName.TrimEnd('s')) }
        return [ordered]@{ type = 'array'; maxItems = 512; uniqueItems = $true; items = $items }
    }
    if ($RustType -eq 'String') { return New-StringSchema $FieldName }
    if ($RustType -eq 'bool') { return [ordered]@{ type = 'boolean' } }
    if ($RustType -eq 'u32') {
        $maximum = if ($FieldName -match '(rate|recall|compliance)_millionths$') { 1000000 } else { 4294967295 }
        return [ordered]@{ type = 'integer'; minimum = 0; maximum = $maximum }
    }
    if ($RustType -eq 'u64') {
        return [ordered]@{ type = 'integer'; minimum = 0; maximum = 18446744073709551615 }
    }
    if ($enumValues.ContainsKey($RustType)) {
        return [ordered]@{ type = 'string'; enum = @($enumValues[$RustType]) }
    }
    if ($structFields.ContainsKey($RustType)) { return New-StructSchema $RustType $false }
    throw "Unsupported Rust schema type: $RustType for $FieldName"
}

function New-StructSchema([string]$TypeName, [bool]$TopLevel) {
    if (-not $structFields.ContainsKey($TypeName)) { throw "Missing Rust struct: $TypeName" }
    $required = [System.Collections.Generic.List[string]]::new()
    $properties = [ordered]@{}
    foreach ($field in $structFields[$TypeName]) {
        $required.Add($field.Name)
        $properties[$field.Name] = if ($field.Name -eq 'schema_version') {
            [ordered]@{ const = 1 }
        } else { New-TypeSchema $field.Type $field.Name }
    }
    $schema = [ordered]@{
        type = 'object'; additionalProperties = $false
        required = @($required); properties = $properties
    }
    if ($TopLevel) {
        return [ordered]@{
            '$schema' = 'https://json-schema.org/draft/2020-12/schema'
            '$id' = "https://d2i.local/schemas/workforce/$($artifacts[$TypeName])"
            title = $TypeName; type = $schema.type
            additionalProperties = $schema.additionalProperties
            required = $schema.required; properties = $schema.properties
        }
    }
    return $schema
}

$differences = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $artifacts.GetEnumerator()) {
    $json = ((New-StructSchema $entry.Key $true) | ConvertTo-Json -Depth 32) + "`n"
    $path = Join-Path $schemaRoot $entry.Value
    if ($Check) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            [System.IO.File]::ReadAllText($path) -ne $json) { $differences.Add($entry.Value) }
    } else { [System.IO.File]::WriteAllText($path, $json, $utf8) }
}
if ($differences.Count -ne 0) {
    throw "Limited autonomy schemas drifted from Rust contracts: $($differences -join ', ')"
}
Write-Output "Limited autonomy schemas $($artifacts.Count): $(if ($Check) { 'verified' } else { 'generated' })"
