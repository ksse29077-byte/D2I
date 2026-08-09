use d2i_spreadsheet_capability::SpreadsheetTypedFactV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationFormatV1 {
    Pptx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationBackendKindV1 {
    PptxFile,
    PowerpointCom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationShapeKindV1 {
    Title,
    TextBox,
    Image,
    Table,
    Chart,
    SimpleShape,
    Placeholder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationOperationV1 {
    Inspect,
    Query,
    CreateFromTemplate,
    AddSlide,
    SetTitle,
    SetText,
    InsertImage,
    InsertTable,
    SetTableCell,
    InsertChart,
    ApplyLayout,
    ApplyStyleRole,
    MoveResizeShape,
    SaveVersion,
    RemoveGeneratedSlide,
    RemoveGeneratedShape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationLayoutSlotV1 {
    Title,
    Body,
    BodyLeft,
    BodyRight,
    Hero,
    TableMain,
    ChartMain,
    Footer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationStyleRoleV1 {
    DeckTitle,
    SlideTitle,
    Body,
    Emphasis,
    Metric,
    Caption,
    TableHeader,
    TableBody,
    Chart,
    Footer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationChartKindV1 {
    ClusteredColumn,
    Bar,
    Line,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationRiskClassV1 {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationOperationResultV1 {
    Verified,
    Rejected,
    Stale,
    Unsupported,
    Unsafe,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationVerificationStatusV1 {
    Verified,
    Failed,
    Inconclusive,
    Unsupported,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationRectV1 {
    pub left_millionths: u32,
    pub top_millionths: u32,
    pub width_millionths: u32,
    pub height_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "content_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PresentationShapeContentV1 {
    Title {
        text_sha256: String,
    },
    TextBox {
        text_sha256: String,
    },
    Image {
        image_sha256: String,
        embedded: bool,
    },
    Table {
        rows: u32,
        columns: u32,
        table_sha256: String,
    },
    Chart {
        chart_kind: PresentationChartKindV1,
        fact_binding_sha256: String,
    },
    SimpleShape {
        shape_role_id: String,
    },
    Placeholder {
        placeholder_role_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationShapeSnapshotV1 {
    pub shape_id: String,
    pub shape_kind: PresentationShapeKindV1,
    pub layout_slot: PresentationLayoutSlotV1,
    pub bounds: PresentationRectV1,
    pub content: PresentationShapeContentV1,
    pub generated: bool,
    pub hidden: bool,
    pub state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSlideSnapshotV1 {
    pub slide_id: String,
    pub ordinal: u32,
    pub purpose_id: String,
    pub layout_id: String,
    pub title_sha256: String,
    pub shapes: Vec<PresentationShapeSnapshotV1>,
    pub notes_present: bool,
    pub generated: bool,
    pub state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSemanticSnapshotV1 {
    pub schema_version: u32,
    pub presentation_id: String,
    pub artifact_id: String,
    pub artifact_generation: u64,
    pub format_id: PresentationFormatV1,
    pub backend_id: String,
    pub slides: Vec<PresentationSlideSnapshotV1>,
    pub slide_count: u32,
    pub unsupported_feature_ids: Vec<String>,
    pub source_content_sha256: String,
    pub semantic_state_sha256: String,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "query_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PresentationQueryPlanV1 {
    FindSlidesByPurpose { purpose_ids: Vec<String> },
    FindSlidesByTitle { title_terms: Vec<String> },
    FindSlidesByContentFact { fact_ids: Vec<String> },
    LayoutCandidates { purpose_id: String },
    TemplateSlides { layout_ids: Vec<String> },
    RelatedSlides { slide_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationQueryV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub case_id: String,
    pub presentation_snapshot_sha256: String,
    pub plan: PresentationQueryPlanV1,
    pub maximum_results: u32,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationQueryMatchV1 {
    pub slide_id: String,
    pub ordinal: u32,
    pub purpose_id: String,
    pub layout_id: String,
    pub relevance_millionths: u32,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationQueryResultV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub query_sha256: String,
    pub presentation_snapshot_sha256: String,
    pub scanned_slides: u32,
    pub matches: Vec<PresentationQueryMatchV1>,
    pub complete: bool,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationFactBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub spreadsheet_context_slice_sha256: String,
    pub spreadsheet_query_result_sha256: String,
    pub source_workbook_snapshot_sha256: String,
    pub facts: Vec<SpreadsheetTypedFactV1>,
    pub summary_fact_ids: Vec<String>,
    pub table_fact_ids: Vec<String>,
    pub chart_fact_ids: Vec<String>,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationContextSlideV1 {
    pub slide_id: String,
    pub purpose_id: String,
    pub layout_id: String,
    pub title_sha256: String,
    pub shape_kind_ids: Vec<PresentationShapeKindV1>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationContextSliceV1 {
    pub schema_version: u32,
    pub slice_id: String,
    pub case_id: String,
    pub presentation_snapshot_sha256: String,
    pub query_result_sha256: String,
    pub fact_binding_sha256: String,
    pub selected_slides: Vec<PresentationContextSlideV1>,
    pub selected_fact_ids: Vec<String>,
    pub text_excerpt_sha256s: Vec<String>,
    pub omitted_slide_count: u32,
    pub serialized_bytes: u32,
    pub estimated_tokens: u32,
    pub evidence_ids: Vec<String>,
    pub slice_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationBriefV1 {
    pub schema_version: u32,
    pub brief_id: String,
    pub case_id: String,
    pub objective: String,
    pub audience_id: String,
    pub required_topic_ids: Vec<String>,
    pub required_fact_ids: Vec<String>,
    pub maximum_slides: u32,
    pub context_slice_sha256: String,
    pub brief_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationLayoutSpecV1 {
    pub layout_id: String,
    pub required_slots: Vec<PresentationLayoutSlotV1>,
    pub minimum_font_points: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationContentSpecV1 {
    pub slot: PresentationLayoutSlotV1,
    pub style_role: PresentationStyleRoleV1,
    pub text: String,
    pub authoritative_fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationImageSpecV1 {
    pub image_id: String,
    pub image_sha256: String,
    pub workspace_relative_path: String,
    pub slot: PresentationLayoutSlotV1,
    pub fit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationTableSpecV1 {
    pub table_id: String,
    pub slot: PresentationLayoutSlotV1,
    pub column_labels: Vec<String>,
    pub row_labels: Vec<String>,
    pub fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationChartSpecV1 {
    pub chart_id: String,
    pub chart_kind: PresentationChartKindV1,
    pub slot: PresentationLayoutSlotV1,
    pub category_labels: Vec<String>,
    pub series_label: String,
    pub fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSlidePlanItemV1 {
    pub planned_slide_id: String,
    pub purpose_id: String,
    pub title: String,
    pub layout: PresentationLayoutSpecV1,
    pub contents: Vec<PresentationContentSpecV1>,
    pub image: Option<PresentationImageSpecV1>,
    pub table: Option<PresentationTableSpecV1>,
    pub chart: Option<PresentationChartSpecV1>,
    pub required_fact_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSlidePlanV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub brief_sha256: String,
    pub context_slice_sha256: String,
    pub fact_binding_sha256: String,
    pub slides: Vec<PresentationSlidePlanItemV1>,
    pub covered_topic_ids: Vec<String>,
    pub covered_fact_ids: Vec<String>,
    pub model_invocation_sha256: String,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mutation_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PresentationMutationV1 {
    AddSlide {
        planned_slide_id: String,
        purpose_id: String,
        layout_id: String,
    },
    SetTitle {
        slide_id: String,
        title: String,
    },
    SetText {
        slide_id: String,
        shape_id: String,
        text: String,
    },
    InsertImage {
        slide_id: String,
        shape_id: String,
        image: PresentationImageSpecV1,
    },
    InsertTable {
        slide_id: String,
        shape_id: String,
        table: PresentationTableSpecV1,
    },
    SetTableCell {
        slide_id: String,
        shape_id: String,
        row: u32,
        column: u32,
        text: String,
        fact_id: Option<String>,
    },
    InsertChart {
        slide_id: String,
        shape_id: String,
        chart: PresentationChartSpecV1,
    },
    ApplyLayout {
        slide_id: String,
        layout: PresentationLayoutSpecV1,
    },
    ApplyStyleRole {
        slide_id: String,
        shape_id: String,
        style_role: PresentationStyleRoleV1,
    },
    MoveResizeShape {
        slide_id: String,
        shape_id: String,
        slot: PresentationLayoutSlotV1,
    },
    RemoveGeneratedSlide {
        slide_id: String,
    },
    RemoveGeneratedShape {
        slide_id: String,
        shape_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationResourceLimitsV1 {
    pub maximum_presentation_bytes: u64,
    pub maximum_package_entries: u32,
    pub maximum_uncompressed_bytes: u64,
    pub maximum_compression_ratio: u32,
    pub maximum_xml_bytes: u64,
    pub maximum_xml_depth: u32,
    pub maximum_xml_nodes: u32,
    pub maximum_slides: u32,
    pub maximum_shapes_per_slide: u32,
    pub maximum_text_characters: u32,
    pub maximum_table_rows: u32,
    pub maximum_table_columns: u32,
    pub maximum_query_slides: u32,
    pub maximum_context_slides: u32,
    pub maximum_context_facts: u32,
    pub maximum_context_excerpts: u32,
    pub maximum_context_bytes: u32,
    pub maximum_model_invocations: u32,
    pub maximum_save_generations: u32,
    pub maximum_worker_milliseconds: u64,
    pub maximum_application_session_milliseconds: u64,
    pub maximum_worker_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationCapabilityPackV1 {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub application_family_ids: Vec<String>,
    pub supported_format_ids: Vec<PresentationFormatV1>,
    pub semantic_operations: Vec<PresentationOperationV1>,
    pub resource_limits: PresentationResourceLimitsV1,
    pub pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationBackendDescriptorV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub backend_kind: PresentationBackendKindV1,
    pub supported_operations: Vec<PresentationOperationV1>,
    pub requires_application: bool,
    pub application_sha256: Option<String>,
    pub worker_sha256: String,
    pub network_denied: bool,
    pub macro_disabled: bool,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationBackendApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub backend_descriptor_sha256: String,
    pub capability_pack_sha256: String,
    pub workspace_profile_sha256: String,
    pub approved_operation_ids: Vec<String>,
    pub application_executable_sha256: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub approval_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationOperationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub case_id: String,
    pub presentation_id: String,
    pub artifact_id: String,
    pub source_generation: u64,
    pub source_content_sha256: String,
    pub source_snapshot_sha256: String,
    pub operation: PresentationOperationV1,
    pub mutation: Option<PresentationMutationV1>,
    pub context_slice_sha256: String,
    pub slide_plan_sha256: String,
    pub fact_binding_sha256: String,
    pub expected_postcondition_ids: Vec<String>,
    pub risk_class: PresentationRiskClassV1,
    pub intent_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationOperationBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub role_instance_sha256: String,
    pub case_instance_sha256: String,
    pub lease_sha256: String,
    pub case_work_grant_sha256: String,
    pub workspace_profile_sha256: String,
    pub root_binding_sha256: String,
    pub artifact_version_sha256: String,
    pub intent_sha256: String,
    pub context_slice_sha256: String,
    pub slide_plan_sha256: String,
    pub fact_binding_sha256: String,
    pub capability_pack_sha256: String,
    pub backend_descriptor_sha256: String,
    pub backend_approval_sha256: String,
    pub policy_admission_sha256: String,
    pub activation_id: String,
    pub activation_sha256: String,
    pub worker_sha256: String,
    pub application_sha256: Option<String>,
    pub expected_source_generation: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub binding_sha256: String,
    pub operation: PresentationOperationV1,
    pub result: PresentationOperationResultV1,
    pub source_content_sha256: String,
    pub destination_content_sha256: Option<String>,
    pub fresh_snapshot_sha256: Option<String>,
    pub activation_consumed: bool,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub audit_event_ids: Vec<String>,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationSemanticDiffV1 {
    pub schema_version: u32,
    pub before_snapshot_sha256: String,
    pub after_snapshot_sha256: String,
    pub added_slide_ids: Vec<String>,
    pub changed_slide_ids: Vec<String>,
    pub changed_shape_ids: Vec<String>,
    pub removed_generated_ids: Vec<String>,
    pub unexpected_change_ids: Vec<String>,
    pub diff_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PresentationStructuralQualityV1 {
    pub required_slides_missing: u32,
    pub required_titles_missing: u32,
    pub required_facts_missing: u32,
    pub empty_generated_shapes: u32,
    pub placeholder_generated_shapes: u32,
    pub off_slide_shapes: u32,
    pub forbidden_overlaps: u32,
    pub text_overflows: u32,
    pub below_minimum_font_shapes: u32,
    pub table_overflows: u32,
    pub incomplete_charts: u32,
    pub distorted_images: u32,
    pub hidden_generated_objects: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationPostOperationVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub binding_sha256: String,
    pub receipt_sha256: String,
    pub diff_sha256: String,
    pub fresh_snapshot_sha256: String,
    pub expected_postcondition_ids: Vec<String>,
    pub satisfied_postcondition_ids: Vec<String>,
    pub protected_invariant_ids: Vec<String>,
    pub quality: PresentationStructuralQualityV1,
    pub status: PresentationVerificationStatusV1,
    pub verified_at_unix_ms: u64,
    pub verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationProvenanceV1 {
    pub schema_version: u32,
    pub artifact_id: String,
    pub source_template_sha256: String,
    pub source_workbook_snapshot_sha256: String,
    pub fact_binding_sha256: String,
    pub context_slice_sha256: String,
    pub slide_plan_sha256: String,
    pub operation_receipt_sha256s: Vec<String>,
    pub provenance_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationReplayReportV1 {
    pub schema_version: u32,
    pub scenario_count: u32,
    pub runs_per_scenario: u32,
    pub query_hash_mismatch_count: u32,
    pub context_hash_mismatch_count: u32,
    pub plan_hash_mismatch_count: u32,
    pub operation_hash_mismatch_count: u32,
    pub blind_replay_count: u32,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PresentationPerformanceMetricsV1 {
    pub parse_microseconds: u64,
    pub query_microseconds: u64,
    pub context_slice_microseconds: u64,
    pub planning_microseconds: u64,
    pub mutation_microseconds: u64,
    pub save_microseconds: u64,
    pub reopen_microseconds: u64,
    pub verify_microseconds: u64,
    pub render_microseconds: u64,
    pub model_microseconds: u64,
    pub peak_worker_memory_bytes: u64,
    pub source_slides: u32,
    pub context_slides: u32,
    pub context_facts: u32,
    pub context_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PresentationSafetyMetricsV1 {
    pub raw_pptx_dump: u32,
    pub raw_xml_from_model: u32,
    pub arbitrary_com: u32,
    pub macro_execution: u32,
    pub external_fetch: u32,
    pub external_workbook_link: u32,
    pub dde_or_rtd: u32,
    pub arbitrary_process_or_command: u32,
    pub wrong_presentation: u32,
    pub wrong_slide: u32,
    pub wrong_shape: u32,
    pub stale_write: u32,
    pub duplicate_mutation: u32,
    pub original_overwrite: u32,
    pub unexpected_deletion: u32,
    pub unexpected_drift: u32,
    pub workspace_escape: u32,
    pub network_access: u32,
    pub credential_leak: u32,
    pub false_completion: u32,
    pub escalation_miss: u32,
    pub critical_error: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PresentationResidualMetricsV1 {
    pub activations: u32,
    pub powerpoint_processes: u32,
    pub chart_excel_processes: u32,
    pub workers: u32,
    pub temporary_packages: u32,
    pub render_files: u32,
    pub workspace_locks: u32,
    pub presentation_locks: u32,
    pub wfp_objects: u32,
    pub profiles: u32,
    pub credentials: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub capability_pack_sha256: String,
    pub presentation_cases: u32,
    pub routine_cases: u32,
    pub exception_cases: u32,
    pub successful_operations: u32,
    pub verified_operations: u32,
    pub verified_closures: u32,
    pub pptx_file_mutations: u32,
    pub powerpoint_com_mutations: u32,
    pub powerpoint_chart_mutations: u32,
    pub fresh_reopens: u32,
    pub rendered_slides: u32,
    pub source_slides: u32,
    pub context_slides: u32,
    pub source_workbook_cells: u64,
    pub context_facts: u32,
    pub actual_qwen_cases: u32,
    pub provider_invocations: u32,
    pub replan_count: u32,
    pub crash_windows_verified: u32,
    pub replay_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub powerpoint_executable_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub fact_binding_sha256: String,
    pub performance: PresentationPerformanceMetricsV1,
    pub safety: PresentationSafetyMetricsV1,
    pub structural_quality: PresentationStructuralQualityV1,
    pub residual: PresentationResidualMetricsV1,
    pub presentation_semantic_capability_evidence: bool,
    pub context_slice_evidence: bool,
    pub fact_binding_evidence: bool,
    pub pptx_file_work_evidence: bool,
    pub powerpoint_live_work_evidence: bool,
    pub chart_evidence: bool,
    pub render_evidence: bool,
    pub office300_lineage_evidence: bool,
    pub track_o_office400_evidence: bool,
    pub complete: bool,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub capability_pack_sha256: String,
    pub backend_approval_sha256s: Vec<String>,
    pub workspace_profile_sha256: String,
    pub completion_report_sha256: String,
    pub replay_report_sha256: String,
    pub office300_finished_sha256: String,
    pub evidence_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}
