[CmdletBinding()]
param([switch]$Check)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$schemaRoot = Join-Path $repoRoot 'schemas/spreadsheet'
$generatedRoot = Join-Path $repoRoot 'target/spreadsheet-schema-generation'

function New-Id { [ordered]@{ type = 'string'; minLength = 1; maxLength = 512; pattern = '^[A-Za-z0-9._:/{}-]+$' } }
function New-Text([int]$Maximum = 512) { [ordered]@{ type = 'string'; minLength = 1; maxLength = $Maximum } }
function New-Hash { [ordered]@{ type = 'string'; maxLength = 71; pattern = '^sha256:[0-9a-f]{64}$' } }
function New-Signature { [ordered]@{ type = 'string'; minLength = 128; maxLength = 128; pattern = '^[0-9a-fA-F]{128}$' } }
function New-Bool { [ordered]@{ type = 'boolean' } }
function New-U32 { [ordered]@{ type = 'integer'; minimum = 0; maximum = 4294967295 } }
function New-I32 { [ordered]@{ type = 'integer'; minimum = -2147483648; maximum = 2147483647 } }
function New-I64 { [ordered]@{ type = 'integer'; minimum = -9223372036854775808; maximum = 9223372036854775807 } }
function New-U64 { [ordered]@{ type = 'integer'; minimum = 0 } }
function New-Enum([string[]]$Values) { [ordered]@{ type = 'string'; enum = $Values } }
function New-Nullable([object]$Schema) { [ordered]@{ oneOf = @($Schema, [ordered]@{ type = 'null' }) } }
function New-Array([object]$Items, [int]$Minimum = 0, [int]$Maximum = 512, [bool]$Unique = $true) {
    [ordered]@{ type = 'array'; minItems = $Minimum; maxItems = $Maximum; uniqueItems = $Unique; items = $Items }
}
function New-Object([object]$Properties) {
    [ordered]@{
        type = 'object'
        additionalProperties = $false
        required = @($Properties.Keys)
        properties = $Properties
    }
}
function New-Contract([string]$FileName, [string]$Title, [object]$Schema) {
    $contract = [ordered]@{
        '$schema' = 'https://json-schema.org/draft/2020-12/schema'
        '$id' = "https://d2i.local/schemas/spreadsheet/$FileName"
        title = $Title
    }
    foreach ($key in $Schema.Keys) { $contract[$key] = $Schema[$key] }
    $json = $contract | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText((Join-Path $generatedRoot $FileName), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

$format = New-Enum @('xlsx', 'csv')
$backendKind = New-Enum @('xlsx_file', 'csv_file', 'excel_com')
$operation = New-Enum @('inspect', 'query', 'create_from_template', 'set_cell_value', 'set_cell_formula', 'append_table_row', 'apply_cell_style', 'create_table', 'save_version')
$columnType = New-Enum @('blank', 'text', 'integer', 'decimal', 'boolean', 'date', 'error', 'mixed')
$predicateOperator = New-Enum @('equal', 'not_equal', 'less_than', 'less_than_or_equal', 'greater_than', 'greater_than_or_equal')
$aggregate = New-Enum @('count', 'sum', 'minimum', 'maximum', 'average')
$factKind = New-Enum @('aggregate', 'lookup', 'projection', 'quality', 'lineage')
$risk = New-Enum @('read_only', 'reversible', 'business_state_change', 'high')
$result = New-Enum @('verified', 'rejected', 'stale', 'unsupported', 'unsafe', 'recovery_required')
$verificationStatus = New-Enum @('verified', 'failed', 'inconclusive', 'unsupported', 'unsafe')

$scalar = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'blank' } })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'text' }; value = New-Text 512 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'integer' }; value = New-I64 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'decimal' }; scaled_value = New-I64; scale = [ordered]@{ type = 'integer'; minimum = 0; maximum = 6 } })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'boolean' }; value = New-Bool })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'date' }; days_since_unix_epoch = New-I32 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'error' }; code = New-Id }))
) }
$predicate = New-Object ([ordered]@{ column_id = New-Id; operator = $predicateOperator; operand = $scalar })
$measure = New-Object ([ordered]@{ measure_id = New-Id; aggregate = $aggregate; column_id = New-Nullable (New-Id); unit_id = New-Nullable (New-Id) })
$contextBudget = New-Object ([ordered]@{ maximum_facts = [ordered]@{ type = 'integer'; minimum = 1; maximum = 64 }; maximum_bytes = [ordered]@{ type = 'integer'; minimum = 1024; maximum = 32768 }; maximum_estimated_tokens = [ordered]@{ type = 'integer'; minimum = 1; maximum = 8192 } })
$queryPlan = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'lookup' }; key_column_id = New-Id; key_value = $scalar; projection_column_ids = New-Array (New-Id) 1 32 })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'filter' }; predicates = New-Array $predicate 1 16 $false; projection_column_ids = New-Array (New-Id) 1 32; maximum_rows = [ordered]@{ type = 'integer'; minimum = 1; maximum = 32 } })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'aggregate' }; predicates = New-Array $predicate 0 16 $false; group_by_column_ids = New-Array (New-Id) 0 2; measures = New-Array $measure 1 16 $false; maximum_groups = [ordered]@{ type = 'integer'; minimum = 1; maximum = 32 } }))
) }
$formula = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ formula_kind = [ordered]@{ const = 'sum_range' }; source_range_id = New-Id })),
    (New-Object ([ordered]@{ formula_kind = [ordered]@{ const = 'difference' }; left_cell_id = New-Id; right_cell_id = New-Id })),
    (New-Object ([ordered]@{ formula_kind = [ordered]@{ const = 'product' }; left_cell_id = New-Id; right_cell_id = New-Id })),
    (New-Object ([ordered]@{ formula_kind = [ordered]@{ const = 'ratio' }; numerator_cell_id = New-Id; denominator_cell_id = New-Id }))
) }
$columnValue = New-Object ([ordered]@{ column_id = New-Id; value = $scalar })
$mutation = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'set_cell_value' }; target_cell_id = New-Id; value = $scalar })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'set_cell_formula' }; target_cell_id = New-Id; formula = $formula })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'append_table_row' }; table_id = New-Id; values = New-Array $columnValue 1 1024 $false })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'apply_cell_style' }; target_cell_id = New-Id; style_id = New-Id })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'create_table' }; sheet_id = New-Id; table_id = New-Id; column_ids = New-Array (New-Id) 1 1024 }))
) }

$limits = New-Object ([ordered]@{
    maximum_workbook_bytes = New-U64; maximum_package_entries = New-U32; maximum_uncompressed_bytes = New-U64
    maximum_compression_ratio = New-U32; maximum_xml_bytes = New-U64; maximum_xml_depth = New-U32
    maximum_xml_nodes = New-U32; maximum_xml_attributes = New-U32; maximum_sheets = New-U32
    maximum_tables = New-U32; maximum_rows_per_table = New-U32; maximum_columns_per_table = New-U32
    maximum_populated_cells = New-U64; maximum_shared_strings = New-U32; maximum_cell_text_characters = New-U32
    maximum_query_scan_cells = New-U64; maximum_query_facts = New-U32; maximum_context_facts = New-U32
    maximum_context_bytes = New-U32; maximum_operations_per_case = New-U32; maximum_model_invocations = New-U32
    maximum_save_generations = New-U32; maximum_worker_milliseconds = New-U64
    maximum_application_session_milliseconds = New-U64; maximum_worker_memory_bytes = New-U64
})
$column = New-Object ([ordered]@{ column_id = New-Id; ordinal = New-U32; inferred_type = $columnType; header_sha256 = New-Hash; unit_id = New-Nullable (New-Id); nullable = New-Bool })
$table = New-Object ([ordered]@{ table_id = New-Id; sheet_id = New-Id; source_range_sha256 = New-Hash; row_count = New-U32; columns = New-Array $column 1 16384 $false; table_state_sha256 = New-Hash })
$sheet = New-Object ([ordered]@{ sheet_id = New-Id; ordinal = New-U32; sheet_name_sha256 = New-Hash; used_row_count = New-U32; used_column_count = New-U32; populated_cell_count = New-U64; formula_count = New-U32; table_ids = New-Array (New-Id) 1 1024; sheet_state_sha256 = New-Hash })
$fact = New-Object ([ordered]@{ fact_id = New-Id; fact_kind = $factKind; subject_id = New-Id; predicate_id = New-Id; typed_value = $scalar; unit_id = New-Nullable (New-Id); source_table_id = New-Id; source_column_ids = New-Array (New-Id) 0 32; source_row_count = New-U32; source_range_sha256 = New-Hash; confidence_millionths = [ordered]@{ type = 'integer'; minimum = 0; maximum = 1000000 }; priority = [ordered]@{ type = 'integer'; minimum = 0; maximum = 1000000 }; evidence_ids = New-Array (New-Id) 1 128; fact_sha256 = New-Hash })

if (Test-Path -LiteralPath $generatedRoot) { Remove-Item -LiteralPath $generatedRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $generatedRoot | Out-Null

New-Contract 'spreadsheet-semantic-snapshot-v1.schema.json' 'SpreadsheetSemanticSnapshotV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; workbook_id = New-Id; artifact_id = New-Id; artifact_generation = New-U64
    format_id = $format; backend_id = New-Id; sheets = New-Array $sheet 1 256 $false; tables = New-Array $table 0 1024 $false
    total_populated_cells = New-U64; total_formula_cells = New-U32; unsupported_feature_ids = New-Array (New-Id) 0 256
    source_content_sha256 = New-Hash; workbook_data_sha256 = New-Hash; semantic_state_sha256 = New-Hash
    observed_at_unix_ms = New-U64; freshness_expires_at_unix_ms = New-U64; evidence_ids = New-Array (New-Id) 1 256
    snapshot_sha256 = New-Hash
}))
New-Contract 'spreadsheet-capability-pack-v1.schema.json' 'SpreadsheetCapabilityPackV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; pack_id = New-Id; pack_version = New-Id
    application_family_ids = New-Array (New-Id) 1 16; supported_format_ids = New-Array $format 1 2
    semantic_operations = New-Array $operation 1 9; query_kinds = New-Array (New-Id) 1 8
    resource_limits = $limits; pack_sha256 = New-Hash
}))
New-Contract 'spreadsheet-backend-descriptor-v1.schema.json' 'SpreadsheetBackendDescriptorV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; backend_id = New-Id; backend_kind = $backendKind
    supported_format_ids = New-Array $format 1 2; supported_operations = New-Array $operation 1 9
    requires_application = New-Bool; application_sha256 = New-Nullable (New-Hash); worker_sha256 = New-Hash
    network_denied = New-Bool; macro_disabled = New-Bool; descriptor_sha256 = New-Hash
}))
New-Contract 'spreadsheet-backend-approval-v1.schema.json' 'SpreadsheetBackendApprovalV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; approval_id = New-Id; organization_id = New-Id
    backend_descriptor_sha256 = New-Hash; capability_pack_sha256 = New-Hash; workspace_profile_sha256 = New-Hash
    approved_operation_ids = New-Array (New-Id) 1 32; issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64
    signer_id = New-Id; signing_key_id = New-Id; signature_hex = New-Signature; approval_sha256 = New-Hash
}))
New-Contract 'spreadsheet-query-v1.schema.json' 'SpreadsheetQueryV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; query_id = New-Id; case_id = New-Id; workbook_snapshot_sha256 = New-Hash
    table_id = New-Id; plan = $queryPlan; context_budget = $contextBudget; issued_at_unix_ms = New-U64
    expires_at_unix_ms = New-U64; evidence_ids = New-Array (New-Id) 1 128; query_sha256 = New-Hash
}))
New-Contract 'spreadsheet-query-result-v1.schema.json' 'SpreadsheetQueryResultV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; query_id = New-Id; query_sha256 = New-Hash; workbook_snapshot_sha256 = New-Hash
    scanned_rows = New-U32; scanned_cells = New-U64; matched_rows = New-U32; facts = New-Array $fact 0 256 $false
    complete = New-Bool; result_sha256 = New-Hash
}))
New-Contract 'spreadsheet-context-slice-v1.schema.json' 'SpreadsheetContextSliceV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; slice_id = New-Id; case_id = New-Id; workbook_snapshot_sha256 = New-Hash
    query_sha256 = New-Hash; query_result_sha256 = New-Hash; selected_facts = New-Array $fact 1 64 $false
    omitted_fact_count = New-U32; source_cell_count = New-U64; selected_fact_count = New-U32
    serialized_bytes = [ordered]@{ type = 'integer'; minimum = 1; maximum = 32768 }
    estimated_tokens = [ordered]@{ type = 'integer'; minimum = 1; maximum = 8192 }
    complete_for_query = New-Bool; evidence_ids = New-Array (New-Id) 1 128; slice_sha256 = New-Hash
}))
New-Contract 'spreadsheet-operation-intent-v1.schema.json' 'SpreadsheetOperationIntentV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; intent_id = New-Id; case_id = New-Id; workbook_id = New-Id; artifact_id = New-Id
    source_generation = New-U64; source_content_sha256 = New-Hash; source_snapshot_sha256 = New-Hash; operation = $operation
    mutation = New-Nullable $mutation; query_sha256 = New-Nullable (New-Hash); context_slice_sha256 = New-Nullable (New-Hash)
    expected_postcondition_ids = New-Array (New-Id) 1 32; risk_class = $risk; intent_sha256 = New-Hash
}))
New-Contract 'spreadsheet-operation-binding-v1.schema.json' 'SpreadsheetOperationBindingV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; binding_id = New-Id; role_instance_sha256 = New-Hash; case_instance_sha256 = New-Hash
    lease_sha256 = New-Hash; case_work_grant_sha256 = New-Hash; workspace_profile_sha256 = New-Hash; root_binding_sha256 = New-Hash
    artifact_version_sha256 = New-Hash; intent_sha256 = New-Hash; capability_pack_sha256 = New-Hash
    backend_descriptor_sha256 = New-Hash; backend_approval_sha256 = New-Hash; policy_admission_sha256 = New-Hash
    activation_id = New-Id; activation_sha256 = New-Hash; worker_sha256 = New-Hash; application_sha256 = New-Nullable (New-Hash)
    issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64; binding_sha256 = New-Hash
}))
New-Contract 'spreadsheet-operation-receipt-v1.schema.json' 'SpreadsheetOperationReceiptV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; receipt_id = New-Id; binding_sha256 = New-Hash; operation = $operation; result = $result
    source_content_sha256 = New-Hash; destination_content_sha256 = New-Nullable (New-Hash); fresh_snapshot_sha256 = New-Nullable (New-Hash)
    query_result_sha256 = New-Nullable (New-Hash); context_slice_sha256 = New-Nullable (New-Hash); activation_consumed = New-Bool
    started_at_unix_ms = New-U64; completed_at_unix_ms = New-U64; audit_event_ids = New-Array (New-Id) 1 64; receipt_sha256 = New-Hash
}))
New-Contract 'spreadsheet-semantic-diff-v1.schema.json' 'SpreadsheetSemanticDiffV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; before_snapshot_sha256 = New-Hash; after_snapshot_sha256 = New-Hash
    changed_sheet_ids = New-Array (New-Id) 0 256; changed_table_ids = New-Array (New-Id) 0 256; changed_cell_ids = New-Array (New-Id) 0 256
    formula_change_count = New-U32; unexpected_change_ids = New-Array (New-Id) 0 256; diff_sha256 = New-Hash
}))
New-Contract 'spreadsheet-post-operation-verification-v1.schema.json' 'SpreadsheetPostOperationVerificationV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; verification_id = New-Id; binding_sha256 = New-Hash; receipt_sha256 = New-Hash
    diff_sha256 = New-Hash; fresh_snapshot_sha256 = New-Hash; expected_postcondition_ids = New-Array (New-Id) 1 32
    satisfied_postcondition_ids = New-Array (New-Id) 0 32; protected_invariant_ids = New-Array (New-Id) 1 32
    status = $verificationStatus; verified_at_unix_ms = New-U64; verification_sha256 = New-Hash
}))
New-Contract 'spreadsheet-work-replay-report-v1.schema.json' 'SpreadsheetWorkReplayReportV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; scenario_count = New-U32; runs_per_scenario = New-U32
    query_hash_mismatch_count = New-U32; context_slice_hash_mismatch_count = New-U32; operation_hash_mismatch_count = New-U32
    blind_replay_count = New-U32; report_sha256 = New-Hash
}))
$performance = New-Object ([ordered]@{ parse_microseconds = New-U64; index_microseconds = New-U64; query_microseconds = New-U64; context_slice_microseconds = New-U64; mutation_microseconds = New-U64; recalculate_microseconds = New-U64; save_microseconds = New-U64; verify_microseconds = New-U64; model_microseconds = New-U64; peak_worker_memory_bytes = New-U64; workbook_cells = New-U64; model_context_facts = New-U32; model_context_bytes = New-U32 })
$safety = New-Object ([ordered]@{ raw_workbook_dump = New-U32; raw_formula_from_model = New-U32; arbitrary_com = New-U32; arbitrary_query = New-U32; external_link_fetch = New-U32; macro_execution = New-U32; wrong_workbook = New-U32; wrong_sheet = New-U32; wrong_cell = New-U32; stale_write = New-U32; duplicate_mutation = New-U32; original_overwrite = New-U32; unexpected_drift = New-U32; network_access = New-U32; credential_leak = New-U32; false_completion = New-U32; critical_error = New-U32 })
$residual = New-Object ([ordered]@{ activations = New-U32; excel_processes = New-U32; file_workers = New-U32; temporary_packages = New-U32; workspace_locks = New-U32; workbook_locks = New-U32; wfp_objects = New-U32; profiles = New-U32; credentials = New-U32 })
New-Contract 'spreadsheet-work-completion-report-v1.schema.json' 'SpreadsheetWorkCompletionReportV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; report_id = New-Id; source_tree_sha256 = New-Hash; predecessor_finished_sha256 = New-Hash; capability_pack_sha256 = New-Hash
    workbook_cases = New-U32; routine_cases = New-U32; exception_cases = New-U32; successful_operations = New-U32; verified_operations = New-U32; verified_closures = New-U32
    xlsx_file_mutations = New-U32; excel_com_mutations = New-U32; fresh_reopens = New-U32; workbook_cells = New-U64; query_count = New-U32; context_slice_count = New-U32
    actual_qwen_cases = New-U32; provider_invocations = New-U32; replan_count = New-U32; clarification_count = New-U32; crash_windows_verified = New-U32
    replay_report_sha256 = New-Hash; protected_audit_terminal_sha256 = New-Hash; excel_executable_sha256 = New-Hash; model_artifact_sha256 = New-Hash; runtime_artifact_sha256 = New-Hash
    performance = $performance; safety = $safety; residual = $residual; complete = New-Bool; finished_sha256 = New-Hash
}))
New-Contract 'spreadsheet-work-certification-v1.schema.json' 'SpreadsheetWorkCertificationV1' (New-Object ([ordered]@{
    schema_version = [ordered]@{ const = 1 }; certification_id = New-Id; capability_pack_sha256 = New-Hash
    backend_approval_sha256s = New-Array (New-Hash) 1 8; workspace_profile_sha256 = New-Hash; completion_report_sha256 = New-Hash
    replay_report_sha256 = New-Hash; evidence_ids = New-Array (New-Id) 1 64; issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64
    signer_id = New-Id; signing_key_id = New-Id; signature_hex = New-Signature; certification_sha256 = New-Hash
}))

if ($Check) {
    if (-not (Test-Path -LiteralPath $schemaRoot)) { throw "spreadsheet schema directory is missing: $schemaRoot" }
    $expected = Get-ChildItem -LiteralPath $generatedRoot -File | Sort-Object Name
    $actual = Get-ChildItem -LiteralPath $schemaRoot -File | Sort-Object Name
    if (($expected.Name -join '|') -ne ($actual.Name -join '|')) { throw 'spreadsheet schema file set differs from generated output' }
    foreach ($file in $expected) {
        $actualPath = Join-Path $schemaRoot $file.Name
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $actualPath).Hash) {
            throw "spreadsheet schema drift: $($file.Name)"
        }
    }
    Write-Output 'spreadsheet schemas are current'
    exit 0
}

if (Test-Path -LiteralPath $schemaRoot) { Remove-Item -LiteralPath $schemaRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $schemaRoot | Out-Null
Get-ChildItem -LiteralPath $generatedRoot -File | Copy-Item -Destination $schemaRoot
Write-Output "generated spreadsheet schemas: $schemaRoot"
