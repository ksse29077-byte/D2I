[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sourcePath = Join-Path $repoRoot 'crates/d2i-office-capability/src/contracts.rs'
$schemaRoot = Join-Path $repoRoot 'schemas/office'
$source = [System.IO.File]::ReadAllText($sourcePath)
$utf8 = [System.Text.UTF8Encoding]::new($false)

$artifacts = [ordered]@{
    CapabilitySourceRecordV1 = 'capability-source-record-v1.schema.json'
    McpToolCatalogSnapshotV1 = 'mcp-tool-catalog-snapshot-v1.schema.json'
    OfficeCapabilityCandidateV1 = 'office-capability-candidate-v1.schema.json'
    OfficeWorkspaceProfileV1 = 'office-workspace-profile-v1.schema.json'
    WorkspaceRootBindingV1 = 'workspace-root-binding-v1.schema.json'
    OfficeArtifactReferenceV1 = 'office-artifact-reference-v1.schema.json'
    WorkspaceObservationSnapshotV1 = 'workspace-observation-snapshot-v1.schema.json'
    WorkspaceOperationIntentV1 = 'workspace-operation-intent-v1.schema.json'
    WorkspaceOperationBindingV1 = 'workspace-operation-binding-v1.schema.json'
    WorkspaceOperationReceiptV1 = 'workspace-operation-receipt-v1.schema.json'
    OfficeArtifactProvenanceV1 = 'office-artifact-provenance-v1.schema.json'
    OfficeWorkspaceReplayReportV1 = 'office-workspace-replay-report-v1.schema.json'
    OfficeWorkspaceCompletionReportV1 = 'office-workspace-completion-report-v1.schema.json'
    OfficeWorkspaceCertificationV1 = 'office-workspace-certification-v1.schema.json'
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
    $schema = [ordered]@{ type = 'string'; minLength = 1; maxLength = 512 }
    if ($FieldName -match '(^|_)(id|ids)$' -or $FieldName -match '_id$') {
        $schema.pattern = '^[A-Za-z0-9._:/{}-]+$'
    }
    return $schema
}

function New-TypeSchema([string]$RustType, [string]$FieldName) {
    if ($RustType -match '^Option<(.+)>$') {
        return [ordered]@{ anyOf = @((New-TypeSchema $Matches[1] $FieldName), [ordered]@{ type = 'null' }) }
    }
    if ($RustType -match '^Vec<(.+)>$') {
        $itemType = $Matches[1]
        $items = if ($itemType -eq 'String' -and $FieldName -match '(hashes|sha256s)$') {
            [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$'; maxLength = 71 }
        } else { New-TypeSchema $itemType ($FieldName.TrimEnd('s')) }
        return [ordered]@{ type = 'array'; maxItems = 512; uniqueItems = $true; items = $items }
    }
    if ($RustType -eq 'String') { return New-StringSchema $FieldName }
    if ($RustType -eq 'bool') { return [ordered]@{ type = 'boolean' } }
    if ($RustType -eq 'u32') {
        return [ordered]@{ type = 'integer'; minimum = 0; maximum = 4294967295 }
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
        type = 'object'
        additionalProperties = $false
        required = @($required)
        properties = $properties
    }
    if ($TopLevel) {
        return [ordered]@{
            '$schema' = 'https://json-schema.org/draft/2020-12/schema'
            '$id' = "https://d2i.local/schemas/office/$($artifacts[$TypeName])"
            title = $TypeName
            type = $schema.type
            additionalProperties = $schema.additionalProperties
            required = $schema.required
            properties = $schema.properties
        }
    }
    return $schema
}

if (-not (Test-Path -LiteralPath $schemaRoot -PathType Container)) {
    [void](New-Item -ItemType Directory -Path $schemaRoot)
}
$differences = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $artifacts.GetEnumerator()) {
    $json = ((New-StructSchema $entry.Key $true) | ConvertTo-Json -Depth 48) + "`n"
    $path = Join-Path $schemaRoot $entry.Value
    if ($Check) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            [System.IO.File]::ReadAllText($path) -ne $json) {
            $differences.Add($entry.Value)
        }
    } else { [System.IO.File]::WriteAllText($path, $json, $utf8) }
}
if ($differences.Count -ne 0) {
    throw "Office capability schemas drifted from Rust contracts: $($differences -join ', ')"
}
Write-Output "Office capability schemas $($artifacts.Count): $(if ($Check) { 'verified' } else { 'generated' })"
