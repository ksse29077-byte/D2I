[CmdletBinding()]
param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sourcePath = Join-Path $repoRoot 'crates/d2i-shadow-mode/src/contracts.rs'
$schemaRoot = Join-Path $repoRoot 'schemas/workforce'
$source = [System.IO.File]::ReadAllText($sourcePath)
$utf8 = [System.Text.UTF8Encoding]::new($false)

$artifacts = [ordered]@{
    ShadowModeProfileV1 = 'shadow-mode-profile-v1.schema.json'
    ShadowModeProfileApprovalV1 = 'shadow-mode-profile-approval-v1.schema.json'
    ShadowReadinessPolicyV1 = 'shadow-readiness-policy-v1.schema.json'
    ShadowReadinessPolicyApprovalV1 = 'shadow-readiness-policy-approval-v1.schema.json'
    ShadowEvaluationCohortV1 = 'shadow-evaluation-cohort-v1.schema.json'
    ShadowCohortApprovalV1 = 'shadow-cohort-approval-v1.schema.json'
    ShadowParticipationApprovalV1 = 'shadow-participation-approval-v1.schema.json'
    ReferenceOperatorAssignmentV1 = 'reference-operator-assignment-v1.schema.json'
    ReferenceOperatorAttestationV1 = 'reference-operator-attestation-v1.schema.json'
    ShadowCaseEnrollmentV1 = 'shadow-case-enrollment-v1.schema.json'
    ShadowObservationGrantV1 = 'shadow-observation-grant-v1.schema.json'
    ShadowSessionV1 = 'shadow-session-v1.schema.json'
    ShadowCycleV1 = 'shadow-cycle-v1.schema.json'
    ShadowProposalV1 = 'shadow-proposal-v1.schema.json'
    ShadowProposalCommitmentV1 = 'shadow-proposal-commitment-v1.schema.json'
    ShadowProposalRevealReceiptV1 = 'shadow-proposal-reveal-receipt-v1.schema.json'
    CounterfactualPolicyAssessmentV1 = 'counterfactual-policy-assessment-v1.schema.json'
    HumanReferenceStepV1 = 'human-reference-step-v1.schema.json'
    HumanReferenceOutcomeV1 = 'human-reference-outcome-v1.schema.json'
    ShadowStepComparisonV1 = 'shadow-step-comparison-v1.schema.json'
    ShadowAdjudicationV1 = 'shadow-adjudication-v1.schema.json'
    ShadowSessionEvaluationV1 = 'shadow-session-evaluation-v1.schema.json'
    ShadowEvidenceCoverageV1 = 'shadow-evidence-coverage-v1.schema.json'
    ShadowMetricResultV1 = 'shadow-metric-result-v1.schema.json'
    RoleShadowEvaluationSnapshotV1 = 'role-shadow-evaluation-snapshot-v1.schema.json'
    ShadowReadinessAssessmentV1 = 'shadow-readiness-assessment-v1.schema.json'
    ShadowEvaluationReportV1 = 'shadow-evaluation-report-v1.schema.json'
    ShadowEvaluationExportBundleV1 = 'shadow-evaluation-export-bundle-v1.schema.json'
    ShadowReplayReportV1 = 'shadow-replay-report-v1.schema.json'
    ShadowCycleRequestV1 = 'shadow-cycle-request-v1.schema.json'
    ShadowCycleResultV1 = 'shadow-cycle-result-v1.schema.json'
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
            $fields.Add([pscustomobject]@{
                Name = $Matches['name']
                Type = $Matches['type'].Trim()
            })
        }
    }
    $structFields[$match.Groups['name'].Value] = @($fields)
}

function New-StringSchema([string]$FieldName) {
    if ($FieldName -eq 'signature_hex') {
        return [ordered]@{ type = 'string'; pattern = '^[0-9a-f]{128}$'; maxLength = 128 }
    }
    if ($FieldName -match '(sha256|hash)$') {
        return [ordered]@{
            type = 'string'
            pattern = '^sha256:[0-9a-f]{64}$'
            maxLength = 71
        }
    }
    return [ordered]@{
        type = 'string'
        minLength = 1
        maxLength = 512
        pattern = '^[A-Za-z0-9._:/-]+$'
    }
}

function New-TypeSchema([string]$RustType, [string]$FieldName) {
    if ($RustType -match '^Option<(.+)>$') {
        $inner = New-TypeSchema $Matches[1] $FieldName
        if ($inner.Contains('type')) {
            $type = $inner.type
            $inner.type = @($type, 'null')
            return $inner
        }
        return [ordered]@{ anyOf = @($inner, [ordered]@{ type = 'null' }) }
    }
    if ($RustType -match '^Vec<(.+)>$') {
        $itemType = $Matches[1]
        $items = if ($itemType -eq 'String' -and $FieldName -match '(hashes|sha256s)$') {
            [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$'; maxLength = 71 }
        }
        else {
            New-TypeSchema $itemType ($FieldName.TrimEnd('s'))
        }
        return [ordered]@{
            type = 'array'
            maxItems = 512
            uniqueItems = $true
            items = $items
        }
    }
    if ($RustType -eq 'String') {
        return New-StringSchema $FieldName
    }
    if ($RustType -eq 'bool') {
        return [ordered]@{ type = 'boolean' }
    }
    if ($RustType -eq 'u32') {
        $maximum = if ($FieldName -match 'millionths$') { 1000000 } else { 4294967295 }
        return [ordered]@{ type = 'integer'; minimum = 0; maximum = $maximum }
    }
    if ($RustType -eq 'u64') {
        return [ordered]@{ type = 'integer'; minimum = 0; maximum = 18446744073709551615 }
    }
    if ($enumValues.ContainsKey($RustType)) {
        return [ordered]@{ type = 'string'; enum = @($enumValues[$RustType]) }
    }
    if ($structFields.ContainsKey($RustType)) {
        return New-StructSchema $RustType $false
    }
    throw "Unsupported Rust schema type: $RustType for $FieldName"
}

function New-StructSchema([string]$TypeName, [bool]$TopLevel) {
    if (-not $structFields.ContainsKey($TypeName)) {
        throw "Missing Rust struct: $TypeName"
    }
    $required = [System.Collections.Generic.List[string]]::new()
    $properties = [ordered]@{}
    foreach ($field in $structFields[$TypeName]) {
        $required.Add($field.Name)
        if ($field.Name -eq 'schema_version') {
            $properties[$field.Name] = [ordered]@{ const = 1 }
        }
        else {
            $properties[$field.Name] = New-TypeSchema $field.Type $field.Name
        }
    }
    $schema = [ordered]@{
        type = 'object'
        additionalProperties = $false
        required = @($required)
        properties = $properties
    }
    if ($TopLevel) {
        $schema = [ordered]@{
            '$schema' = 'https://json-schema.org/draft/2020-12/schema'
            '$id' = "https://d2i.local/schemas/workforce/$($artifacts[$TypeName])"
            title = $TypeName
            type = $schema.type
            additionalProperties = $schema.additionalProperties
            required = $schema.required
            properties = $schema.properties
        }
    }
    return $schema
}

$differences = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $artifacts.GetEnumerator()) {
    $schema = New-StructSchema $entry.Key $true
    $json = ($schema | ConvertTo-Json -Depth 32) + "`n"
    $path = Join-Path $schemaRoot $entry.Value
    if ($Check) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            [System.IO.File]::ReadAllText($path) -ne $json) {
            $differences.Add($entry.Value)
        }
    }
    else {
        [System.IO.File]::WriteAllText($path, $json, $utf8)
    }
}

if ($differences.Count -ne 0) {
    throw "Shadow schemas drifted from Rust contracts: $($differences -join ', ')"
}

Write-Output "Shadow schemas $($artifacts.Count): $(if ($Check) { 'verified' } else { 'generated' })"
