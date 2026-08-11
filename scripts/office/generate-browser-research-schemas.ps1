[CmdletBinding()]
param([switch]$Check)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$contractPath = Join-Path $repoRoot 'crates/d2i-browser-research/src/contracts.rs'
$schemaRoot = Join-Path $repoRoot 'schemas/research'
$generatedRoot = Join-Path $repoRoot 'target/browser-research-schema-generation'
$source = [IO.File]::ReadAllText($contractPath, [Text.Encoding]::UTF8)

function Convert-Kebab([string]$Value) {
    return (($Value -replace 'V1$', '') -creplace '([a-z0-9])([A-Z])', '$1-$2').ToLowerInvariant()
}

function Convert-Snake([string]$Value) {
    return ($Value -creplace '([a-z0-9])([A-Z])', '$1_$2').ToLowerInvariant()
}

$enumMatches = [regex]::Matches($source, '(?ms)pub enum (?<name>[A-Za-z0-9_]+)\s*\{(?<body>.*?)^\}')
$structMatches = [regex]::Matches($source, '(?ms)pub struct (?<name>[A-Za-z0-9_]+)\s*\{(?<body>.*?)^\}')
$enums = [ordered]@{}
$structs = [ordered]@{}

foreach ($match in $enumMatches) {
    $variants = @([regex]::Matches($match.Groups['body'].Value, '(?m)^\s*(?<name>[A-Za-z][A-Za-z0-9_]*),\s*$') |
        ForEach-Object { Convert-Snake $_.Groups['name'].Value })
    if ($variants.Count -eq 0) { throw "Closed enum has no variants: $($match.Groups['name'].Value)" }
    $enums[$match.Groups['name'].Value] = @($variants)
}

foreach ($match in $structMatches) {
    $fields = [ordered]@{}
    foreach ($field in [regex]::Matches($match.Groups['body'].Value, '(?m)^\s*pub\s+(?<name>[A-Za-z0-9_]+):\s*(?<type>[^,]+),\s*$')) {
        $fields[$field.Groups['name'].Value] = $field.Groups['type'].Value.Trim()
    }
    if ($fields.Count -eq 0) { throw "Contract struct has no fields: $($match.Groups['name'].Value)" }
    $structs[$match.Groups['name'].Value] = $fields
}

function New-StringSchema([string]$Field) {
    if ($Field.EndsWith('sha256', [StringComparison]::Ordinal)) {
        return [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$'; maxLength = 71 }
    }
    if ($Field -eq 'signature_hex') {
        return [ordered]@{ type = 'string'; pattern = '^[0-9a-f]{128}$'; maxLength = 128 }
    }
    if ($Field.EndsWith('_id', [StringComparison]::Ordinal) -or $Field.EndsWith('_ref', [StringComparison]::Ordinal)) {
        return [ordered]@{ type = 'string'; minLength = 1; maxLength = 512; pattern = '^[A-Za-z0-9._:/-]+$' }
    }
    return [ordered]@{ type = 'string'; minLength = 0; maxLength = 262144 }
}

function New-TypeSchema([string]$Type, [string]$Field) {
    if ($Type.StartsWith('Option<') -and $Type.EndsWith('>')) {
        return [ordered]@{ oneOf = @((New-TypeSchema $Type.Substring(7, $Type.Length - 8) $Field), [ordered]@{ type = 'null' }) }
    }
    if ($Type.StartsWith('Vec<') -and $Type.EndsWith('>')) {
        return [ordered]@{ type = 'array'; maxItems = 4096; items = New-TypeSchema $Type.Substring(4, $Type.Length - 5) $Field }
    }
    switch ($Type) {
        'String' { return New-StringSchema $Field }
        'bool' { return [ordered]@{ type = 'boolean' } }
        'u8' { return [ordered]@{ type = 'integer'; minimum = 0; maximum = 255 } }
        'u16' { return [ordered]@{ type = 'integer'; minimum = 0; maximum = 65535 } }
        'u32' { return [ordered]@{ type = 'integer'; minimum = 0; maximum = 4294967295 } }
        'u64' { return [ordered]@{ type = 'integer'; minimum = 0 } }
        'i64' { return [ordered]@{ type = 'integer'; minimum = -9223372036854775808; maximum = 9223372036854775807 } }
        default {
            if (-not $enums.Contains($Type) -and -not $structs.Contains($Type)) { throw "Unsupported schema type '$Type' on '$Field'" }
            return [ordered]@{ '$ref' = "#/`$defs/$Type" }
        }
    }
}

function Get-ReferencedType([string]$Type) {
    $current = $Type
    while (($current.StartsWith('Option<') -or $current.StartsWith('Vec<')) -and $current.EndsWith('>')) {
        if ($current.StartsWith('Option<')) { $current = $current.Substring(7, $current.Length - 8) }
        else { $current = $current.Substring(4, $current.Length - 5) }
    }
    return $current
}

$definitions = [ordered]@{}
foreach ($entry in $enums.GetEnumerator()) {
    $definitions[$entry.Key] = [ordered]@{ type = 'string'; enum = @($entry.Value) }
}
foreach ($entry in $structs.GetEnumerator()) {
    $properties = [ordered]@{}
    $required = [Collections.Generic.List[string]]::new()
    foreach ($field in $entry.Value.GetEnumerator()) {
        $properties[$field.Key] = New-TypeSchema $field.Value $field.Key
        if (-not $field.Value.StartsWith('Option<')) { $required.Add($field.Key) }
    }
    $definitions[$entry.Key] = [ordered]@{
        type = 'object'
        additionalProperties = $false
        required = @($required)
        properties = $properties
    }
}

if (Test-Path -LiteralPath $generatedRoot) { Remove-Item -LiteralPath $generatedRoot -Recurse -Force }
New-Item -ItemType Directory -Path $generatedRoot -Force | Out-Null
foreach ($name in $structs.Keys) {
    $reachable = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($name)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        if (-not $reachable.Add($current)) { continue }
        if (-not $structs.Contains($current)) { continue }
        foreach ($field in $structs[$current].GetEnumerator()) {
            $referenced = Get-ReferencedType $field.Value
            if (($structs.Contains($referenced) -or $enums.Contains($referenced)) -and -not $reachable.Contains($referenced)) {
                $pending.Enqueue($referenced)
            }
        }
    }
    $reachableDefinitions = [ordered]@{}
    foreach ($definitionName in $definitions.Keys) {
        if ($reachable.Contains($definitionName)) { $reachableDefinitions[$definitionName] = $definitions[$definitionName] }
    }
    $document = [ordered]@{
        '$schema' = 'https://json-schema.org/draft/2020-12/schema'
        '$id' = "https://schemas.d2i.local/research/$(Convert-Kebab $name)-v1.schema.json"
        title = $name
        '$ref' = "#/`$defs/$name"
        '$defs' = $reachableDefinitions
    }
    $path = Join-Path $generatedRoot "$(Convert-Kebab $name)-v1.schema.json"
    $json = ($document | ConvertTo-Json -Depth 100).Replace("`r`n", "`n")
    [IO.File]::WriteAllText($path, ($json + "`n"), [Text.UTF8Encoding]::new($false))
}

if ($Check) {
    if (-not (Test-Path -LiteralPath $schemaRoot)) { throw 'Browser research schema directory is absent.' }
    $expected = @(Get-ChildItem -LiteralPath $generatedRoot -File | Sort-Object Name)
    $actual = @(Get-ChildItem -LiteralPath $schemaRoot -File | Sort-Object Name)
    if (($expected.Name -join '|') -ne ($actual.Name -join '|')) { throw 'Browser research schema file set drift detected.' }
    foreach ($file in $expected) {
        $actualPath = Join-Path $schemaRoot $file.Name
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $actualPath).Hash) {
            throw "Browser research schema drift detected: $($file.Name)"
        }
    }
    Write-Output "Browser research schemas match generator: $($expected.Count)"
    exit 0
}

New-Item -ItemType Directory -Path $schemaRoot -Force | Out-Null
Get-ChildItem -LiteralPath $schemaRoot -File -ErrorAction SilentlyContinue | Remove-Item -Force
Get-ChildItem -LiteralPath $generatedRoot -File | Copy-Item -Destination $schemaRoot
Write-Output "Generated Browser Research schemas: $($structs.Count)"
