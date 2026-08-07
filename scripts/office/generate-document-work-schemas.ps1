[CmdletBinding()]
param([switch]$Check)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$schemaRoot = Join-Path $repoRoot 'schemas/document'
$generatedRoot = Join-Path $repoRoot 'target/document-schema-generation'

function New-Id { [ordered]@{ type = 'string'; minLength = 1; maxLength = 512; pattern = '^[A-Za-z0-9._:/{}-]+$' } }
function New-Text([int]$Maximum = 32768) { [ordered]@{ type = 'string'; minLength = 1; maxLength = $Maximum } }
function New-Hash { [ordered]@{ type = 'string'; maxLength = 71; pattern = '^sha256:[0-9a-f]{64}$' } }
function New-Bool { [ordered]@{ type = 'boolean' } }
function New-U32 { [ordered]@{ type = 'integer'; minimum = 0; maximum = 4294967295 } }
function New-U64 { [ordered]@{ type = 'integer'; minimum = 0 } }
function New-Enum([string[]]$Values) { [ordered]@{ type = 'string'; enum = $Values } }
function New-Nullable([object]$Schema) { [ordered]@{ oneOf = @($Schema, [ordered]@{ type = 'null' }) } }
function New-Array([object]$Items, [int]$Minimum = 0, [int]$Maximum = 512) {
    [ordered]@{ type = 'array'; minItems = $Minimum; maxItems = $Maximum; uniqueItems = $true; items = $Items }
}
function New-Object([object]$Properties) {
    [ordered]@{
        type = 'object'
        additionalProperties = $false
        required = @($Properties.Keys)
        properties = $Properties
    }
}
function New-Contract([string]$FileName, [string]$Title, [object]$Properties) {
    $schema = New-Object $Properties
    $schema = [ordered]@{
        '$schema' = 'https://json-schema.org/draft/2020-12/schema'
        '$id' = "https://d2i.local/schemas/document/$FileName"
        title = $Title
        type = $schema.type
        additionalProperties = $schema.additionalProperties
        required = $schema.required
        properties = $schema.properties
    }
    $json = $schema | ConvertTo-Json -Depth 100
    [IO.File]::WriteAllText((Join-Path $generatedRoot $FileName), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

$format = New-Enum @('hwpx', 'docx', 'hwp', 'doc')
$backendKind = New-Enum @('hwpx_file', 'docx_file', 'word_com', 'hancom_automation')
$operation = New-Enum @(
    'inspect', 'create_from_template', 'append_paragraph', 'insert_heading', 'replace_text',
    'apply_paragraph_style', 'insert_table', 'set_table_cell', 'insert_image', 'set_page_layout',
    'save_version', 'remove_generated_node'
)
$nodeKind = New-Enum @('paragraph', 'heading', 'table', 'image', 'page_break', 'section_break', 'header', 'footer')
$styleRole = New-Enum @('body', 'title', 'heading_1', 'heading_2', 'caption', 'table_header', 'table_body', 'emphasis')
$risk = New-Enum @('read_only', 'reversible', 'business_state_change', 'high')
$result = New-Enum @('verified', 'rejected', 'stale', 'unsupported', 'unsafe', 'recovery_required')
$verificationStatus = New-Enum @('verified', 'failed', 'inconclusive', 'unsupported', 'unsafe')

$limits = New-Object ([ordered]@{
    maximum_document_bytes = New-U64
    maximum_package_entries = New-U32
    maximum_uncompressed_bytes = New-U64
    maximum_compression_ratio = New-U32
    maximum_xml_bytes = New-U64
    maximum_xml_depth = New-U32
    maximum_xml_nodes = New-U32
    maximum_xml_attributes = New-U32
    maximum_sections = New-U32
    maximum_nodes = New-U32
    maximum_tables = New-U32
    maximum_table_rows = New-U32
    maximum_table_columns = New-U32
    maximum_table_cells = New-U32
    maximum_images = New-U32
    maximum_image_bytes = New-U64
    maximum_total_embedded_bytes = New-U64
    maximum_text_characters_per_node = New-U32
    maximum_total_observed_characters = New-U32
    maximum_generated_characters_per_case = New-U32
    maximum_operations_per_case = New-U32
    maximum_model_invocations = New-U32
    maximum_save_generations = New-U32
    maximum_worker_milliseconds = New-U64
    maximum_application_session_milliseconds = New-U64
    maximum_worker_memory_bytes = New-U64
})
$node = New-Object ([ordered]@{
    node_id = New-Id
    node_kind = $nodeKind
    section_id = New-Id
    ordinal = New-U32
    style_id = New-Nullable (New-Id)
    text_excerpt = New-Nullable (New-Text 32768)
    text_sha256 = New-Nullable (New-Hash)
    table_id = New-Nullable (New-Id)
    image_id = New-Nullable (New-Id)
    truncated = New-Bool
})

if (Test-Path -LiteralPath $generatedRoot) { Remove-Item -LiteralPath $generatedRoot -Recurse -Force }
New-Item -ItemType Directory -Force -Path $generatedRoot | Out-Null

New-Contract 'document-semantic-snapshot-v1.schema.json' 'DocumentSemanticSnapshotV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    document_id = New-Id
    artifact_id = New-Id
    artifact_generation = New-U64
    format_id = $format
    backend_id = New-Id
    document_property_ids = New-Array (New-Id) 0
    section_ids = New-Array (New-Id) 1
    ordered_nodes = New-Array $node 1
    style_catalog_sha256 = New-Hash
    image_refs = New-Array (New-Id) 0
    table_refs = New-Array (New-Id) 0
    page_layout_summary = New-Text 512
    content_summary = New-Text 32768
    unsupported_feature_ids = New-Array (New-Id) 0
    source_content_sha256 = New-Hash
    semantic_state_sha256 = New-Hash
    observed_at_unix_ms = New-U64
    freshness_expires_at_unix_ms = New-U64
    evidence_ids = New-Array (New-Id) 0
    snapshot_sha256 = New-Hash
})
New-Contract 'document-capability-pack-v1.schema.json' 'DocumentCapabilityPackV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    pack_id = New-Id
    pack_version = New-Id
    application_family_ids = New-Array (New-Id) 1
    supported_format_ids = New-Array $format 1 4
    semantic_operations = New-Array $operation 1 12
    style_policy_id = New-Id
    table_policy_id = New-Id
    image_policy_id = New-Id
    page_layout_policy_id = New-Id
    backend_descriptor_sha256s = New-Array (New-Hash) 1
    resource_limits = $limits
    evidence_ids = New-Array (New-Id) 0
    pack_sha256 = New-Hash
})
New-Contract 'document-backend-descriptor-v1.schema.json' 'DocumentBackendDescriptorV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    backend_id = New-Id
    backend_version = New-Id
    backend_kind = $backendKind
    supported_formats = New-Array $format 1 4
    supported_operations = New-Array $operation 1 12
    requires_application = New-Bool
    requires_license_evidence = New-Bool
    worker_artifact_sha256 = New-Hash
    application_binary_sha256 = New-Nullable (New-Hash)
    security_profile_id = New-Id
    resource_limits = $limits
    backend_sha256 = New-Hash
})
New-Contract 'document-backend-approval-v1.schema.json' 'DocumentBackendApprovalV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    approval_id = New-Id
    organization_id = New-Id
    backend_descriptor_sha256 = New-Hash
    capability_pack_sha256 = New-Hash
    role_ids = New-Array (New-Id) 1
    environment_ids = New-Array (New-Id) 1
    allowed_formats = New-Array $format 1 4
    allowed_operations = New-Array $operation 1 12
    application_binary_sha256s = New-Array (New-Hash) 0
    license_evidence_sha256s = New-Array (New-Hash) 0
    valid_from_unix_ms = New-U64
    valid_until_unix_ms = New-U64
    signer_id = New-Id
    signing_key_id = New-Id
    approval_sha256 = New-Hash
    signature_hex = [ordered]@{ type = 'string'; pattern = '^[0-9a-f]{128}$'; maxLength = 128 }
})
New-Contract 'document-content-payload-v1.schema.json' 'DocumentContentPayloadV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    payload_id = New-Id
    case_id = New-Id
    content_class_id = New-Id
    language_id = New-Id
    text = New-Text 32768
    character_count = New-U32
    data_class_ids = New-Array (New-Id) 1
    source_evidence_ids = New-Array (New-Id) 1
    payload_sha256 = New-Hash
})
New-Contract 'document-style-spec-v1.schema.json' 'DocumentStyleSpecV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    style_spec_id = New-Id
    style_role = $styleRole
    approved_template_style_id = New-Nullable (New-Id)
    emphasis = New-Bool
    style_spec_sha256 = New-Hash
})
New-Contract 'document-table-spec-v1.schema.json' 'DocumentTableSpecV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    table_spec_id = New-Id
    rows = [ordered]@{ type = 'integer'; minimum = 1; maximum = 256 }
    columns = [ordered]@{ type = 'integer'; minimum = 1; maximum = 64 }
    header_rows = New-U32
    column_role_ids = New-Array (New-Id) 1 64
    style_spec_id = New-Id
    maximum_width_policy_id = New-Id
    table_spec_sha256 = New-Hash
})
New-Contract 'document-image-spec-v1.schema.json' 'DocumentImageSpecV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    image_spec_id = New-Id
    artifact_id = New-Id
    content_sha256 = New-Hash
    media_type = New-Enum @('image/png', 'image/jpeg')
    placement_class_id = New-Id
    maximum_width_millimeters = [ordered]@{ type = 'integer'; minimum = 1; maximum = 1000 }
    maximum_height_millimeters = [ordered]@{ type = 'integer'; minimum = 1; maximum = 1000 }
    caption_payload_id = New-Nullable (New-Id)
    embedded = [ordered]@{ const = $true }
    image_spec_sha256 = New-Hash
})
New-Contract 'document-page-layout-spec-v1.schema.json' 'DocumentPageLayoutSpecV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    page_layout_spec_id = New-Id
    page_size_id = [ordered]@{ const = 'a4' }
    orientation = New-Enum @('portrait', 'landscape')
    top_margin_millimeters = [ordered]@{ type = 'integer'; minimum = 5; maximum = 50 }
    bottom_margin_millimeters = [ordered]@{ type = 'integer'; minimum = 5; maximum = 50 }
    left_margin_millimeters = [ordered]@{ type = 'integer'; minimum = 5; maximum = 50 }
    right_margin_millimeters = [ordered]@{ type = 'integer'; minimum = 5; maximum = 50 }
    page_layout_spec_sha256 = New-Hash
})
New-Contract 'document-operation-intent-v1.schema.json' 'DocumentOperationIntentV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    intent_id = New-Id
    case_id = New-Id
    planner_cycle_id = New-Id
    document_artifact_id = New-Id
    document_generation = New-U64
    semantic_state_sha256 = New-Hash
    operation = $operation
    target_node_ids = New-Array (New-Id) 0 1
    content_payload_ids = New-Array (New-Id) 0 1
    style_spec_ids = New-Array (New-Id) 0 1
    image_spec_ids = New-Array (New-Id) 0 1
    table_spec_id = New-Nullable (New-Id)
    page_layout_spec_id = New-Nullable (New-Id)
    required_postcondition_ids = New-Array (New-Id) 1
    risk_class = $risk
    intent_sha256 = New-Hash
})
New-Contract 'document-operation-binding-v1.schema.json' 'DocumentOperationBindingV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    binding_id = New-Id
    role_contract_sha256 = New-Hash
    role_instance_sha256 = New-Hash
    case_sha256 = New-Hash
    lease_sha256 = New-Hash
    work_grant_sha256 = New-Hash
    workspace_profile_sha256 = New-Hash
    workspace_root_binding_sha256 = New-Hash
    artifact_id = New-Id
    artifact_generation = New-U64
    artifact_content_sha256 = New-Hash
    semantic_snapshot_sha256 = New-Hash
    capability_pack_sha256 = New-Hash
    backend_descriptor_sha256 = New-Hash
    backend_approval_sha256 = New-Hash
    operation_intent_sha256 = New-Hash
    policy_decision_sha256 = New-Hash
    cognitive_activation_admission_sha256 = New-Hash
    worker_sha256 = New-Hash
    expected_output_generation = New-U64
    one_time_use_id = New-Id
    expires_at_unix_ms = New-U64
    binding_sha256 = New-Hash
})
New-Contract 'document-operation-receipt-v1.schema.json' 'DocumentOperationReceiptV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    receipt_id = New-Id
    binding_sha256 = New-Hash
    backend_id = New-Id
    worker_sha256 = New-Hash
    operation = $operation
    pre_generation = New-U64
    post_generation = New-U64
    pre_content_sha256 = New-Hash
    post_content_sha256 = New-Hash
    pre_semantic_sha256 = New-Hash
    post_semantic_sha256 = New-Hash
    bytes_written = New-U64
    application_receipt_ids = New-Array (New-Id) 0
    started_at_unix_ms = New-U64
    completed_at_unix_ms = New-U64
    result_class = $result
    receipt_sha256 = New-Hash
})
New-Contract 'document-semantic-diff-v1.schema.json' 'DocumentSemanticDiffV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    diff_id = New-Id
    added_node_ids = New-Array (New-Id) 0
    removed_node_ids = New-Array (New-Id) 0
    changed_node_ids = New-Array (New-Id) 0
    text_change_ids = New-Array (New-Id) 0
    style_change_ids = New-Array (New-Id) 0
    table_change_ids = New-Array (New-Id) 0
    image_change_ids = New-Array (New-Id) 0
    layout_change_ids = New-Array (New-Id) 0
    unexpected_change_ids = New-Array (New-Id) 0
    diff_sha256 = New-Hash
})
New-Contract 'document-post-operation-verification-v1.schema.json' 'DocumentPostOperationVerificationV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    verification_id = New-Id
    receipt_sha256 = New-Hash
    fresh_snapshot_sha256 = New-Hash
    required_postcondition_ids = New-Array (New-Id) 1
    passed_postcondition_ids = New-Array (New-Id) 0
    failed_postcondition_ids = New-Array (New-Id) 0
    semantic_diff_sha256 = New-Hash
    status = $verificationStatus
    verification_sha256 = New-Hash
})
New-Contract 'document-structural-quality-assessment-v1.schema.json' 'DocumentStructuralQualityAssessmentV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    assessment_id = New-Id
    required_section_ids = New-Array (New-Id) 0
    required_heading_ids = New-Array (New-Id) 0
    required_table_spec_ids = New-Array (New-Id) 0
    required_image_spec_ids = New-Array (New-Id) 0
    nonempty_required_node_ids = New-Array (New-Id) 0
    placeholder_text_forbidden = New-Bool
    unexpected_empty_cell_ids = New-Array (New-Id) 0
    document_structure_valid = New-Bool
    quality_status = New-Enum @('passed', 'failed', 'inconclusive')
    assessment_sha256 = New-Hash
})
New-Contract 'document-semantic-equivalence-report-v1.schema.json' 'DocumentSemanticEquivalenceReportV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    report_id = New-Id
    left_snapshot_sha256 = New-Hash
    right_snapshot_sha256 = New-Hash
    required_sections_match = New-Bool
    section_order_match = New-Bool
    textual_facts_match = New-Bool
    table_facts_match = New-Bool
    image_roles_match = New-Bool
    style_roles_match = New-Bool
    equivalent = New-Bool
    mismatch_ids = New-Array (New-Id) 0
    report_sha256 = New-Hash
})
New-Contract 'document-work-replay-report-v1.schema.json' 'DocumentWorkReplayReportV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    report_id = New-Id
    scenario_count = New-U32
    replay_runs = New-U32
    deterministic_match_count = New-U32
    deterministic_mismatch_count = New-U32
    input_set_sha256 = New-Hash
    first_output_sha256 = New-Hash
    final_output_sha256 = New-Hash
    evidence_ids = New-Array (New-Id) 1
    report_sha256 = New-Hash
})

$performance = New-Object ([ordered]@{
    workspace_discovery_microseconds = New-U64
    hwpx_parse_microseconds = New-U64
    hwpx_mutation_microseconds = New-U64
    hwpx_save_microseconds = New-U64
    hwpx_verify_microseconds = New-U64
    docx_parse_microseconds = New-U64
    docx_mutation_microseconds = New-U64
    docx_save_microseconds = New-U64
    docx_verify_microseconds = New-U64
    word_launch_microseconds = New-U64
    word_open_microseconds = New-U64
    word_operation_microseconds = New-U64
    word_save_microseconds = New-U64
    word_close_microseconds = New-U64
    qwen_inference_microseconds = New-U64
    bytes_read = New-U64
    bytes_written = New-U64
    peak_worker_memory_bytes = New-U64
    peak_word_memory_bytes = New-U64
})
$safetyProperties = [ordered]@{}
@(
    'wrong_document', 'wrong_node', 'original_overwrite', 'stale_write',
    'unexpected_document_drift', 'duplicate_mutation', 'raw_xml_from_model', 'raw_com_from_model',
    'macro_execution', 'external_link_fetch', 'arbitrary_process', 'arbitrary_command',
    'workspace_escape', 'network_access', 'credential_leak', 'mandatory_escalation_miss',
    'false_completion', 'critical_error'
) | ForEach-Object { $safetyProperties[$_] = New-U32 }
$safety = New-Object $safetyProperties
$residualProperties = [ordered]@{}
@(
    'worker_owned_word_processes', 'worker_owned_hwp_processes', 'com_workers',
    'document_file_locks', 'temporary_packages', 'activations', 'profiles', 'credentials',
    'workspace_locks'
) | ForEach-Object { $residualProperties[$_] = New-U32 }
$residual = New-Object $residualProperties

New-Contract 'document-work-completion-report-v1.schema.json' 'DocumentWorkCompletionReportV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    report_id = New-Id
    complete = New-Bool
    document_semantic_capability_evidence = New-Bool
    hwpx_document_work_evidence = New-Bool
    docx_document_work_evidence = New-Bool
    word_live_document_work_evidence = New-Bool
    office_workspace_lineage_evidence = New-Bool
    track_o_office200_evidence = New-Bool
    hancom_automation_live_evidence = New-Bool
    hancom_automation_reason_id = New-Id
    hwp_legacy_mutation_status = New-Enum @('requires_licensed_hancom_backend', 'verified_with_licensed_hancom_backend')
    source_tree_sha256 = New-Hash
    predecessor_finished_sha256 = New-Hash
    word_executable_sha256 = New-Hash
    model_artifact_sha256 = New-Hash
    runtime_artifact_sha256 = New-Hash
    document_cases = New-U32
    routine_cases = New-U32
    exception_security_cases = New-U32
    verified_closures = New-U32
    actual_qwen_cases = New-U32
    provider_invocations = New-U32
    replan_count = New-U32
    clarification_count = New-U32
    hwpx_mutations = New-U32
    docx_mutations = New-U32
    word_com_mutations = New-U32
    fresh_document_reopens = New-U32
    successful_operations = New-U32
    verified_operations = New-U32
    version_count = New-U32
    provenance_count = New-U32
    crash_windows_verified = New-U32
    replay_report_sha256 = New-Hash
    equivalence_report_sha256 = New-Hash
    protected_audit_terminal_sha256 = New-Hash
    performance = $performance
    safety = $safety
    residual = $residual
    finished_sha256 = New-Hash
})
New-Contract 'document-work-certification-v1.schema.json' 'DocumentWorkCertificationV1' ([ordered]@{
    schema_version = [ordered]@{ const = 1 }
    certification_id = New-Id
    completion_report_sha256 = New-Hash
    capability_pack_sha256 = New-Hash
    backend_approval_sha256s = New-Array (New-Hash) 1
    workspace_profile_sha256 = New-Hash
    replay_report_sha256 = New-Hash
    issued_at_unix_ms = New-U64
    expires_at_unix_ms = New-U64
    signer_id = New-Id
    signing_key_id = New-Id
    evidence_ids = New-Array (New-Id) 1
    certification_sha256 = New-Hash
    signature_hex = [ordered]@{ type = 'string'; pattern = '^[0-9a-f]{128}$'; maxLength = 128 }
})

if ($Check) {
    if (-not (Test-Path -LiteralPath $schemaRoot)) { throw 'Document schema directory is missing.' }
    $expected = @(Get-ChildItem -LiteralPath $generatedRoot -File | Sort-Object Name)
    $actual = @(Get-ChildItem -LiteralPath $schemaRoot -File | Sort-Object Name)
    if ($expected.Count -ne 19 -or $actual.Count -ne 19) { throw 'Exactly 19 document schemas are required.' }
    foreach ($file in $expected) {
        $actualPath = Join-Path $schemaRoot $file.Name
        if (-not (Test-Path -LiteralPath $actualPath) -or
            (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash -ne
            (Get-FileHash -Algorithm SHA256 -LiteralPath $actualPath).Hash) {
            throw "Document schema drift detected: $($file.Name)"
        }
    }
    Write-Output 'Document schemas match the generator.'
} else {
    New-Item -ItemType Directory -Force -Path $schemaRoot | Out-Null
    Get-ChildItem -LiteralPath $schemaRoot -File -ErrorAction SilentlyContinue | Remove-Item -Force
    Copy-Item -Path (Join-Path $generatedRoot '*') -Destination $schemaRoot -Force
    Write-Output "Generated 19 document schemas in $schemaRoot"
}
