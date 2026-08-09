[CmdletBinding()]
param([switch]$Check)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$schemaRoot = Join-Path $repoRoot 'schemas/presentation'
$generatedRoot = Join-Path $repoRoot 'target/presentation-schema-generation'

function New-Text([int]$Maximum = 2048, [int]$Minimum = 1) { [ordered]@{ type = 'string'; minLength = $Minimum; maxLength = $Maximum } }
function New-Id { [ordered]@{ type = 'string'; minLength = 1; maxLength = 512; pattern = '^[A-Za-z0-9._:/{}-]+$' } }
function New-Path { [ordered]@{ type = 'string'; minLength = 1; maxLength = 512; pattern = '^(?![A-Za-z]:)(?![/\\])(?!.+[\\/]\.\.?([\\/]|$)).+$' } }
function New-Hash { [ordered]@{ type = 'string'; pattern = '^sha256:[0-9a-f]{64}$' } }
function New-Signature { [ordered]@{ type = 'string'; pattern = '^[0-9a-fA-F]{128}$' } }
function New-Bool { [ordered]@{ type = 'boolean' } }
function New-U32([uint32]$Maximum = [uint32]::MaxValue) { [ordered]@{ type = 'integer'; minimum = 0; maximum = [uint64]$Maximum } }
function New-U64 { [ordered]@{ type = 'integer'; minimum = 0 } }
function New-I64 { [ordered]@{ type = 'integer'; minimum = -9223372036854775808; maximum = 9223372036854775807 } }
function New-Enum([string[]]$Values) { [ordered]@{ type = 'string'; enum = $Values } }
function New-Nullable([object]$Schema) { [ordered]@{ oneOf = @($Schema, [ordered]@{ type = 'null' }) } }
function New-Array([object]$Items, [int]$Minimum = 0, [int]$Maximum = 512, [bool]$Unique = $true) {
    [ordered]@{ type = 'array'; minItems = $Minimum; maxItems = $Maximum; uniqueItems = $Unique; items = $Items }
}
function New-Object([object]$Properties) {
    [ordered]@{ type = 'object'; additionalProperties = $false; required = @($Properties.Keys); properties = $Properties }
}
function New-Contract([string]$FileName, [string]$Title, [object]$Schema) {
    $contract = [ordered]@{
        '$schema' = 'https://json-schema.org/draft/2020-12/schema'
        '$id' = "https://d2i.local/schemas/presentation/$FileName"
        title = $Title
    }
    foreach ($key in $Schema.Keys) { $contract[$key] = $Schema[$key] }
    $json = $contract | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText((Join-Path $generatedRoot $FileName), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

$format = New-Enum @('pptx')
$backendKind = New-Enum @('pptx_file', 'powerpoint_com')
$shapeKind = New-Enum @('title', 'text_box', 'image', 'table', 'chart', 'simple_shape', 'placeholder')
$operation = New-Enum @('inspect', 'query', 'create_from_template', 'add_slide', 'set_title', 'set_text', 'insert_image', 'insert_table', 'set_table_cell', 'insert_chart', 'apply_layout', 'apply_style_role', 'move_resize_shape', 'save_version', 'remove_generated_slide', 'remove_generated_shape')
$slot = New-Enum @('title', 'body', 'body_left', 'body_right', 'hero', 'table_main', 'chart_main', 'footer')
$styleRole = New-Enum @('deck_title', 'slide_title', 'body', 'emphasis', 'metric', 'caption', 'table_header', 'table_body', 'chart', 'footer')
$chartKind = New-Enum @('clustered_column', 'bar', 'line')
$risk = New-Enum @('read_only', 'reversible', 'business_state_change', 'high')
$result = New-Enum @('verified', 'rejected', 'stale', 'unsupported', 'unsafe', 'recovery_required')
$verificationStatus = New-Enum @('verified', 'failed', 'inconclusive', 'unsupported', 'unsafe')
$factKind = New-Enum @('aggregate', 'lookup', 'projection', 'quality', 'lineage')

$rect = New-Object ([ordered]@{ left_millionths = New-U32 1000000; top_millionths = New-U32 1000000; width_millionths = New-U32 1000000; height_millionths = New-U32 1000000 })
$scalar = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'blank' } })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'text' }; value = New-Text 512 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'integer' }; value = New-I64 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'decimal' }; scaled_value = New-I64; scale = New-U32 6 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'boolean' }; value = New-Bool })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'date' }; days_since_unix_epoch = New-I64 })),
    (New-Object ([ordered]@{ value_type = [ordered]@{ const = 'error' }; code = New-Id }))
) }
$fact = New-Object ([ordered]@{
    fact_id = New-Id; fact_kind = $factKind; subject_id = New-Id; predicate_id = New-Id; typed_value = $scalar
    unit_id = New-Nullable (New-Id); source_table_id = New-Id; source_column_ids = New-Array (New-Id) 0 32
    source_row_count = New-U32; source_range_sha256 = New-Hash; confidence_millionths = New-U32 1000000
    priority = New-U32 1000000; evidence_ids = New-Array (New-Id) 1 128; fact_sha256 = New-Hash
})
$shapeContent = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'title' }; text_sha256 = New-Hash })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'text_box' }; text_sha256 = New-Hash })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'image' }; image_sha256 = New-Hash; embedded = New-Bool })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'table' }; rows = New-U32 256; columns = New-U32 64; table_sha256 = New-Hash })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'chart' }; chart_kind = $chartKind; fact_binding_sha256 = New-Hash })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'simple_shape' }; shape_role_id = New-Id })),
    (New-Object ([ordered]@{ content_kind = [ordered]@{ const = 'placeholder' }; placeholder_role_id = New-Id }))
) }
$shape = New-Object ([ordered]@{ shape_id = New-Id; shape_kind = $shapeKind; layout_slot = $slot; bounds = $rect; content = $shapeContent; generated = New-Bool; hidden = New-Bool; state_sha256 = New-Hash })
$slide = New-Object ([ordered]@{ slide_id = New-Id; ordinal = New-U32 500; purpose_id = New-Id; layout_id = New-Id; title_sha256 = New-Hash; shapes = New-Array $shape 0 256 $false; notes_present = New-Bool; generated = New-Bool; state_sha256 = New-Hash })
$queryPlan = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'find_slides_by_purpose' }; purpose_ids = New-Array (New-Id) 1 32 })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'find_slides_by_title' }; title_terms = New-Array (New-Text 128) 1 16 })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'find_slides_by_content_fact' }; fact_ids = New-Array (New-Id) 1 16 })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'layout_candidates' }; purpose_id = New-Id })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'template_slides' }; layout_ids = New-Array (New-Id) 1 32 })),
    (New-Object ([ordered]@{ query_kind = [ordered]@{ const = 'related_slides' }; slide_ids = New-Array (New-Id) 1 32 }))
) }
$queryMatch = New-Object ([ordered]@{ slide_id = New-Id; ordinal = New-U32 500; purpose_id = New-Id; layout_id = New-Id; relevance_millionths = New-U32 1000000; evidence_ids = New-Array (New-Id) 1 128 })
$contextSlide = New-Object ([ordered]@{ slide_id = New-Id; purpose_id = New-Id; layout_id = New-Id; title_sha256 = New-Hash; shape_kind_ids = New-Array $shapeKind 0 16; evidence_ids = New-Array (New-Id) 1 128 })
$layout = New-Object ([ordered]@{ layout_id = New-Id; required_slots = New-Array $slot 1 8; minimum_font_points = [ordered]@{ type = 'integer'; minimum = 8; maximum = 96 } })
$content = New-Object ([ordered]@{ slot = $slot; style_role = $styleRole; text = New-Text 2048; authoritative_fact_ids = New-Array (New-Id) 0 16 })
$image = New-Object ([ordered]@{ image_id = New-Id; image_sha256 = New-Hash; workspace_relative_path = New-Path; slot = $slot; fit = New-Enum @('contain', 'cover') })
$table = New-Object ([ordered]@{ table_id = New-Id; slot = $slot; column_labels = New-Array (New-Text 128) 1 32 $false; row_labels = New-Array (New-Text 128) 1 128 $false; fact_ids = New-Array (New-Id) 1 256 $false })
$chart = New-Object ([ordered]@{ chart_id = New-Id; chart_kind = $chartKind; slot = $slot; category_labels = New-Array (New-Text 128) 1 32 $false; series_label = New-Text 128; fact_ids = New-Array (New-Id) 1 32 $false })
$slidePlanItem = New-Object ([ordered]@{ planned_slide_id = New-Id; purpose_id = New-Id; title = New-Text 256; layout = $layout; contents = New-Array $content 0 16 $false; image = New-Nullable $image; table = New-Nullable $table; chart = New-Nullable $chart; required_fact_ids = New-Array (New-Id) 0 16 })
$mutation = [ordered]@{ oneOf = @(
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'add_slide' }; planned_slide_id = New-Id; purpose_id = New-Id; layout_id = New-Id })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'set_title' }; slide_id = New-Id; title = New-Text 256 })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'set_text' }; slide_id = New-Id; shape_id = New-Id; text = New-Text 2048 })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'insert_image' }; slide_id = New-Id; shape_id = New-Id; image = $image })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'insert_table' }; slide_id = New-Id; shape_id = New-Id; table = $table })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'set_table_cell' }; slide_id = New-Id; shape_id = New-Id; row = New-U32 256; column = New-U32 64; text = New-Text 512; fact_id = New-Nullable (New-Id) })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'insert_chart' }; slide_id = New-Id; shape_id = New-Id; chart = $chart })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'apply_layout' }; slide_id = New-Id; layout = $layout })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'apply_style_role' }; slide_id = New-Id; shape_id = New-Id; style_role = $styleRole })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'move_resize_shape' }; slide_id = New-Id; shape_id = New-Id; slot = $slot })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'remove_generated_slide' }; slide_id = New-Id })),
    (New-Object ([ordered]@{ mutation_kind = [ordered]@{ const = 'remove_generated_shape' }; slide_id = New-Id; shape_id = New-Id }))
) }
$limits = New-Object ([ordered]@{
    maximum_presentation_bytes = New-U64; maximum_package_entries = New-U32; maximum_uncompressed_bytes = New-U64; maximum_compression_ratio = New-U32
    maximum_xml_bytes = New-U64; maximum_xml_depth = New-U32; maximum_xml_nodes = New-U32; maximum_slides = New-U32 500
    maximum_shapes_per_slide = New-U32; maximum_text_characters = New-U32; maximum_table_rows = New-U32; maximum_table_columns = New-U32
    maximum_query_slides = New-U32 32; maximum_context_slides = New-U32 8; maximum_context_facts = New-U32 16; maximum_context_excerpts = New-U32 16
    maximum_context_bytes = New-U32 32768; maximum_model_invocations = New-U32; maximum_save_generations = New-U32; maximum_worker_milliseconds = New-U64
    maximum_application_session_milliseconds = New-U64; maximum_worker_memory_bytes = New-U64
})
$quality = New-Object ([ordered]@{ required_slides_missing = New-U32; required_titles_missing = New-U32; required_facts_missing = New-U32; empty_generated_shapes = New-U32; placeholder_generated_shapes = New-U32; off_slide_shapes = New-U32; forbidden_overlaps = New-U32; text_overflows = New-U32; below_minimum_font_shapes = New-U32; table_overflows = New-U32; incomplete_charts = New-U32; distorted_images = New-U32; hidden_generated_objects = New-U32 })
$performance = New-Object ([ordered]@{ parse_microseconds = New-U64; query_microseconds = New-U64; context_slice_microseconds = New-U64; planning_microseconds = New-U64; mutation_microseconds = New-U64; save_microseconds = New-U64; reopen_microseconds = New-U64; verify_microseconds = New-U64; render_microseconds = New-U64; model_microseconds = New-U64; peak_worker_memory_bytes = New-U64; source_slides = New-U32; context_slides = New-U32; context_facts = New-U32; context_bytes = New-U32 })
$safety = New-Object ([ordered]@{ raw_pptx_dump = New-U32; raw_xml_from_model = New-U32; arbitrary_com = New-U32; macro_execution = New-U32; external_fetch = New-U32; external_workbook_link = New-U32; dde_or_rtd = New-U32; arbitrary_process_or_command = New-U32; wrong_presentation = New-U32; wrong_slide = New-U32; wrong_shape = New-U32; stale_write = New-U32; duplicate_mutation = New-U32; original_overwrite = New-U32; unexpected_deletion = New-U32; unexpected_drift = New-U32; workspace_escape = New-U32; network_access = New-U32; credential_leak = New-U32; false_completion = New-U32; escalation_miss = New-U32; critical_error = New-U32 })
$residual = New-Object ([ordered]@{ activations = New-U32; powerpoint_processes = New-U32; chart_excel_processes = New-U32; workers = New-U32; temporary_packages = New-U32; render_files = New-U32; workspace_locks = New-U32; presentation_locks = New-U32; wfp_objects = New-U32; profiles = New-U32; credentials = New-U32 })

if (Test-Path -LiteralPath $generatedRoot) { Remove-Item -LiteralPath $generatedRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $generatedRoot | Out-Null

New-Contract 'presentation-semantic-snapshot-v1.schema.json' 'PresentationSemanticSnapshotV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; presentation_id = New-Id; artifact_id = New-Id; artifact_generation = New-U64; format_id = $format; backend_id = New-Id; slides = New-Array $slide 1 500 $false; slide_count = New-U32 500; unsupported_feature_ids = New-Array (New-Id) 0 256; source_content_sha256 = New-Hash; semantic_state_sha256 = New-Hash; observed_at_unix_ms = New-U64; freshness_expires_at_unix_ms = New-U64; evidence_ids = New-Array (New-Id) 1 256; snapshot_sha256 = New-Hash }))
New-Contract 'presentation-capability-pack-v1.schema.json' 'PresentationCapabilityPackV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; pack_id = New-Id; pack_version = New-Id; application_family_ids = New-Array (New-Id) 1 16; supported_format_ids = New-Array $format 1 1; semantic_operations = New-Array $operation 1 16; resource_limits = $limits; pack_sha256 = New-Hash }))
New-Contract 'presentation-backend-descriptor-v1.schema.json' 'PresentationBackendDescriptorV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; backend_id = New-Id; backend_kind = $backendKind; supported_operations = New-Array $operation 1 16; requires_application = New-Bool; application_sha256 = New-Nullable (New-Hash); worker_sha256 = New-Hash; network_denied = New-Bool; macro_disabled = New-Bool; descriptor_sha256 = New-Hash }))
New-Contract 'presentation-backend-approval-v1.schema.json' 'PresentationBackendApprovalV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; approval_id = New-Id; organization_id = New-Id; backend_descriptor_sha256 = New-Hash; capability_pack_sha256 = New-Hash; workspace_profile_sha256 = New-Hash; approved_operation_ids = New-Array (New-Id) 1 32; application_executable_sha256 = New-Nullable (New-Hash); issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64; signer_id = New-Id; signing_key_id = New-Id; signature_hex = New-Signature; approval_sha256 = New-Hash }))
New-Contract 'presentation-query-v1.schema.json' 'PresentationQueryV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; query_id = New-Id; case_id = New-Id; presentation_snapshot_sha256 = New-Hash; plan = $queryPlan; maximum_results = New-U32 32; issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64; evidence_ids = New-Array (New-Id) 1 128; query_sha256 = New-Hash }))
New-Contract 'presentation-query-result-v1.schema.json' 'PresentationQueryResultV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; query_id = New-Id; query_sha256 = New-Hash; presentation_snapshot_sha256 = New-Hash; scanned_slides = New-U32 500; matches = New-Array $queryMatch 0 32 $false; complete = New-Bool; result_sha256 = New-Hash }))
New-Contract 'presentation-fact-binding-v1.schema.json' 'PresentationFactBindingV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; binding_id = New-Id; spreadsheet_context_slice_sha256 = New-Hash; spreadsheet_query_result_sha256 = New-Hash; source_workbook_snapshot_sha256 = New-Hash; facts = New-Array $fact 1 16 $false; summary_fact_ids = New-Array (New-Id) 1 16; table_fact_ids = New-Array (New-Id) 1 16; chart_fact_ids = New-Array (New-Id) 1 16; binding_sha256 = New-Hash }))
New-Contract 'presentation-context-slice-v1.schema.json' 'PresentationContextSliceV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; slice_id = New-Id; case_id = New-Id; presentation_snapshot_sha256 = New-Hash; query_result_sha256 = New-Hash; fact_binding_sha256 = New-Hash; selected_slides = New-Array $contextSlide 1 8 $false; selected_fact_ids = New-Array (New-Id) 1 16; text_excerpt_sha256s = New-Array (New-Hash) 0 16; omitted_slide_count = New-U32; serialized_bytes = [ordered]@{ type = 'integer'; minimum = 1; maximum = 32768 }; estimated_tokens = [ordered]@{ type = 'integer'; minimum = 1; maximum = 8192 }; evidence_ids = New-Array (New-Id) 1 128; slice_sha256 = New-Hash }))
New-Contract 'presentation-brief-v1.schema.json' 'PresentationBriefV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; brief_id = New-Id; case_id = New-Id; objective = New-Text 2048; audience_id = New-Id; required_topic_ids = New-Array (New-Id) 1 32; required_fact_ids = New-Array (New-Id) 1 16; maximum_slides = New-U32 32; context_slice_sha256 = New-Hash; brief_sha256 = New-Hash }))
New-Contract 'presentation-layout-spec-v1.schema.json' 'PresentationLayoutSpecV1' $layout
New-Contract 'presentation-content-spec-v1.schema.json' 'PresentationContentSpecV1' $content
New-Contract 'presentation-image-spec-v1.schema.json' 'PresentationImageSpecV1' $image
New-Contract 'presentation-table-spec-v1.schema.json' 'PresentationTableSpecV1' $table
New-Contract 'presentation-chart-spec-v1.schema.json' 'PresentationChartSpecV1' $chart
New-Contract 'presentation-slide-plan-v1.schema.json' 'PresentationSlidePlanV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; plan_id = New-Id; brief_sha256 = New-Hash; context_slice_sha256 = New-Hash; fact_binding_sha256 = New-Hash; slides = New-Array $slidePlanItem 1 32 $false; covered_topic_ids = New-Array (New-Id) 1 32; covered_fact_ids = New-Array (New-Id) 1 16; model_invocation_sha256 = New-Hash; plan_sha256 = New-Hash }))
New-Contract 'presentation-operation-intent-v1.schema.json' 'PresentationOperationIntentV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; intent_id = New-Id; case_id = New-Id; presentation_id = New-Id; artifact_id = New-Id; source_generation = New-U64; source_content_sha256 = New-Hash; source_snapshot_sha256 = New-Hash; operation = $operation; mutation = New-Nullable $mutation; context_slice_sha256 = New-Hash; slide_plan_sha256 = New-Hash; fact_binding_sha256 = New-Hash; expected_postcondition_ids = New-Array (New-Id) 1 32; risk_class = $risk; intent_sha256 = New-Hash }))
New-Contract 'presentation-operation-binding-v1.schema.json' 'PresentationOperationBindingV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; binding_id = New-Id; role_instance_sha256 = New-Hash; case_instance_sha256 = New-Hash; lease_sha256 = New-Hash; case_work_grant_sha256 = New-Hash; workspace_profile_sha256 = New-Hash; root_binding_sha256 = New-Hash; artifact_version_sha256 = New-Hash; intent_sha256 = New-Hash; context_slice_sha256 = New-Hash; slide_plan_sha256 = New-Hash; fact_binding_sha256 = New-Hash; capability_pack_sha256 = New-Hash; backend_descriptor_sha256 = New-Hash; backend_approval_sha256 = New-Hash; policy_admission_sha256 = New-Hash; activation_id = New-Id; activation_sha256 = New-Hash; worker_sha256 = New-Hash; application_sha256 = New-Nullable (New-Hash); expected_source_generation = New-U64; issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64; binding_sha256 = New-Hash }))
New-Contract 'presentation-operation-receipt-v1.schema.json' 'PresentationOperationReceiptV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; receipt_id = New-Id; binding_sha256 = New-Hash; operation = $operation; result = $result; source_content_sha256 = New-Hash; destination_content_sha256 = New-Nullable (New-Hash); fresh_snapshot_sha256 = New-Nullable (New-Hash); activation_consumed = New-Bool; started_at_unix_ms = New-U64; completed_at_unix_ms = New-U64; audit_event_ids = New-Array (New-Id) 1 64; receipt_sha256 = New-Hash }))
New-Contract 'presentation-semantic-diff-v1.schema.json' 'PresentationSemanticDiffV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; before_snapshot_sha256 = New-Hash; after_snapshot_sha256 = New-Hash; added_slide_ids = New-Array (New-Id) 0 500; changed_slide_ids = New-Array (New-Id) 0 500; changed_shape_ids = New-Array (New-Id) 0 512; removed_generated_ids = New-Array (New-Id) 0 512; unexpected_change_ids = New-Array (New-Id) 0 512; diff_sha256 = New-Hash }))
New-Contract 'presentation-structural-quality-v1.schema.json' 'PresentationStructuralQualityV1' $quality
New-Contract 'presentation-post-operation-verification-v1.schema.json' 'PresentationPostOperationVerificationV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; verification_id = New-Id; binding_sha256 = New-Hash; receipt_sha256 = New-Hash; diff_sha256 = New-Hash; fresh_snapshot_sha256 = New-Hash; expected_postcondition_ids = New-Array (New-Id) 1 32; satisfied_postcondition_ids = New-Array (New-Id) 0 32; protected_invariant_ids = New-Array (New-Id) 1 32; quality = $quality; status = $verificationStatus; verified_at_unix_ms = New-U64; verification_sha256 = New-Hash }))
New-Contract 'presentation-provenance-v1.schema.json' 'PresentationProvenanceV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; artifact_id = New-Id; source_template_sha256 = New-Hash; source_workbook_snapshot_sha256 = New-Hash; fact_binding_sha256 = New-Hash; context_slice_sha256 = New-Hash; slide_plan_sha256 = New-Hash; operation_receipt_sha256s = New-Array (New-Hash) 1 128; provenance_sha256 = New-Hash }))
New-Contract 'presentation-replay-report-v1.schema.json' 'PresentationReplayReportV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; scenario_count = New-U32; runs_per_scenario = New-U32; query_hash_mismatch_count = New-U32; context_hash_mismatch_count = New-U32; plan_hash_mismatch_count = New-U32; operation_hash_mismatch_count = New-U32; blind_replay_count = New-U32; report_sha256 = New-Hash }))
New-Contract 'presentation-performance-metrics-v1.schema.json' 'PresentationPerformanceMetricsV1' $performance
New-Contract 'presentation-safety-metrics-v1.schema.json' 'PresentationSafetyMetricsV1' $safety
New-Contract 'presentation-work-completion-report-v1.schema.json' 'PresentationWorkCompletionReportV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; report_id = New-Id; source_tree_sha256 = New-Hash; predecessor_finished_sha256 = New-Hash; capability_pack_sha256 = New-Hash; presentation_cases = New-U32; routine_cases = New-U32; exception_cases = New-U32; successful_operations = New-U32; verified_operations = New-U32; verified_closures = New-U32; pptx_file_mutations = New-U32; powerpoint_com_mutations = New-U32; powerpoint_chart_mutations = New-U32; fresh_reopens = New-U32; rendered_slides = New-U32; source_slides = New-U32; context_slides = New-U32; source_workbook_cells = New-U64; context_facts = New-U32; actual_qwen_cases = New-U32; provider_invocations = New-U32; replan_count = New-U32; crash_windows_verified = New-U32; replay_report_sha256 = New-Hash; protected_audit_terminal_sha256 = New-Hash; powerpoint_executable_sha256 = New-Hash; model_artifact_sha256 = New-Hash; runtime_artifact_sha256 = New-Hash; fact_binding_sha256 = New-Hash; performance = $performance; safety = $safety; structural_quality = $quality; residual = $residual; presentation_semantic_capability_evidence = New-Bool; context_slice_evidence = New-Bool; fact_binding_evidence = New-Bool; pptx_file_work_evidence = New-Bool; powerpoint_live_work_evidence = New-Bool; chart_evidence = New-Bool; render_evidence = New-Bool; office300_lineage_evidence = New-Bool; track_o_office400_evidence = New-Bool; complete = New-Bool; finished_sha256 = New-Hash }))
New-Contract 'presentation-work-certification-v1.schema.json' 'PresentationWorkCertificationV1' (New-Object ([ordered]@{ schema_version = [ordered]@{ const = 1 }; certification_id = New-Id; capability_pack_sha256 = New-Hash; backend_approval_sha256s = New-Array (New-Hash) 1 8; workspace_profile_sha256 = New-Hash; completion_report_sha256 = New-Hash; replay_report_sha256 = New-Hash; office300_finished_sha256 = New-Hash; evidence_ids = New-Array (New-Id) 1 64; issued_at_unix_ms = New-U64; expires_at_unix_ms = New-U64; signer_id = New-Id; signing_key_id = New-Id; signature_hex = New-Signature; certification_sha256 = New-Hash }))

if ($Check) {
    if (-not (Test-Path -LiteralPath $schemaRoot)) { throw "presentation schema directory is missing: $schemaRoot" }
    $expected = Get-ChildItem -LiteralPath $generatedRoot -File | Sort-Object Name
    $actual = Get-ChildItem -LiteralPath $schemaRoot -File | Sort-Object Name
    if ($expected.Count -ne 27 -or ($expected.Name -join '|') -ne ($actual.Name -join '|')) { throw 'presentation schema file set differs from generated output' }
    foreach ($file in $expected) {
        $actualPath = Join-Path $schemaRoot $file.Name
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne (Get-FileHash -Algorithm SHA256 -LiteralPath $actualPath).Hash) { throw "presentation schema drift: $($file.Name)" }
    }
    Write-Output 'presentation schemas are current'
    exit 0
}

if (Test-Path -LiteralPath $schemaRoot) { Remove-Item -LiteralPath $schemaRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $schemaRoot | Out-Null
Get-ChildItem -LiteralPath $generatedRoot -File | Copy-Item -Destination $schemaRoot
Write-Output "generated presentation schemas: $schemaRoot"
