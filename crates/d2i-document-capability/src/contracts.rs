use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentFormatV1 {
    Hwpx,
    Docx,
    Hwp,
    Doc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentBackendKindV1 {
    HwpxFile,
    DocxFile,
    WordCom,
    HancomAutomation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentOperationV1 {
    Inspect,
    CreateFromTemplate,
    AppendParagraph,
    InsertHeading,
    ReplaceText,
    ApplyParagraphStyle,
    InsertTable,
    SetTableCell,
    InsertImage,
    SetPageLayout,
    SaveVersion,
    RemoveGeneratedNode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentNodeKindV1 {
    Paragraph,
    Heading,
    Table,
    Image,
    PageBreak,
    SectionBreak,
    Header,
    Footer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStyleRoleV1 {
    Body,
    Title,
    Heading1,
    Heading2,
    Caption,
    TableHeader,
    TableBody,
    Emphasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageOrientationV1 {
    Portrait,
    Landscape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRiskClassV1 {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentOperationResultV1 {
    Verified,
    Rejected,
    Stale,
    Unsupported,
    Unsafe,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentVerificationStatusV1 {
    Verified,
    Failed,
    Inconclusive,
    Unsupported,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentQualityStatusV1 {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HwpLegacyMutationStatusV1 {
    RequiresLicensedHancomBackend,
    VerifiedWithLicensedHancomBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentResourceLimitsV1 {
    pub maximum_document_bytes: u64,
    pub maximum_package_entries: u32,
    pub maximum_uncompressed_bytes: u64,
    pub maximum_compression_ratio: u32,
    pub maximum_xml_bytes: u64,
    pub maximum_xml_depth: u32,
    pub maximum_xml_nodes: u32,
    pub maximum_xml_attributes: u32,
    pub maximum_sections: u32,
    pub maximum_nodes: u32,
    pub maximum_tables: u32,
    pub maximum_table_rows: u32,
    pub maximum_table_columns: u32,
    pub maximum_table_cells: u32,
    pub maximum_images: u32,
    pub maximum_image_bytes: u64,
    pub maximum_total_embedded_bytes: u64,
    pub maximum_text_characters_per_node: u32,
    pub maximum_total_observed_characters: u32,
    pub maximum_generated_characters_per_case: u32,
    pub maximum_operations_per_case: u32,
    pub maximum_model_invocations: u32,
    pub maximum_save_generations: u32,
    pub maximum_worker_milliseconds: u64,
    pub maximum_application_session_milliseconds: u64,
    pub maximum_worker_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSemanticNodeV1 {
    pub node_id: String,
    pub node_kind: DocumentNodeKindV1,
    pub section_id: String,
    pub ordinal: u32,
    pub style_id: Option<String>,
    pub text_excerpt: Option<String>,
    pub text_sha256: Option<String>,
    pub table_id: Option<String>,
    pub image_id: Option<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSemanticSnapshotV1 {
    pub schema_version: u32,
    pub document_id: String,
    pub artifact_id: String,
    pub artifact_generation: u64,
    pub format_id: DocumentFormatV1,
    pub backend_id: String,
    pub document_property_ids: Vec<String>,
    pub section_ids: Vec<String>,
    pub ordered_nodes: Vec<DocumentSemanticNodeV1>,
    pub style_catalog_sha256: String,
    pub image_refs: Vec<String>,
    pub table_refs: Vec<String>,
    pub page_layout_summary: String,
    pub content_summary: String,
    pub unsupported_feature_ids: Vec<String>,
    pub source_content_sha256: String,
    pub semantic_state_sha256: String,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentCapabilityPackV1 {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub application_family_ids: Vec<String>,
    pub supported_format_ids: Vec<DocumentFormatV1>,
    pub semantic_operations: Vec<DocumentOperationV1>,
    pub style_policy_id: String,
    pub table_policy_id: String,
    pub image_policy_id: String,
    pub page_layout_policy_id: String,
    pub backend_descriptor_sha256s: Vec<String>,
    pub resource_limits: DocumentResourceLimitsV1,
    pub evidence_ids: Vec<String>,
    pub pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentBackendDescriptorV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub backend_version: String,
    pub backend_kind: DocumentBackendKindV1,
    pub supported_formats: Vec<DocumentFormatV1>,
    pub supported_operations: Vec<DocumentOperationV1>,
    pub requires_application: bool,
    pub requires_license_evidence: bool,
    pub worker_artifact_sha256: String,
    pub application_binary_sha256: Option<String>,
    pub security_profile_id: String,
    pub resource_limits: DocumentResourceLimitsV1,
    pub backend_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentBackendApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub backend_descriptor_sha256: String,
    pub capability_pack_sha256: String,
    pub role_ids: Vec<String>,
    pub environment_ids: Vec<String>,
    pub allowed_formats: Vec<DocumentFormatV1>,
    pub allowed_operations: Vec<DocumentOperationV1>,
    pub application_binary_sha256s: Vec<String>,
    pub license_evidence_sha256s: Vec<String>,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentContentPayloadV1 {
    pub schema_version: u32,
    pub payload_id: String,
    pub case_id: String,
    pub content_class_id: String,
    pub language_id: String,
    pub text: String,
    pub character_count: u32,
    pub data_class_ids: Vec<String>,
    pub source_evidence_ids: Vec<String>,
    pub payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentStyleSpecV1 {
    pub schema_version: u32,
    pub style_spec_id: String,
    pub style_role: DocumentStyleRoleV1,
    pub approved_template_style_id: Option<String>,
    pub emphasis: bool,
    pub style_spec_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentTableSpecV1 {
    pub schema_version: u32,
    pub table_spec_id: String,
    pub rows: u32,
    pub columns: u32,
    pub header_rows: u32,
    pub column_role_ids: Vec<String>,
    pub style_spec_id: String,
    pub maximum_width_policy_id: String,
    pub table_spec_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentImageSpecV1 {
    pub schema_version: u32,
    pub image_spec_id: String,
    pub artifact_id: String,
    pub content_sha256: String,
    pub media_type: String,
    pub placement_class_id: String,
    pub maximum_width_millimeters: u32,
    pub maximum_height_millimeters: u32,
    pub caption_payload_id: Option<String>,
    pub embedded: bool,
    pub image_spec_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPageLayoutSpecV1 {
    pub schema_version: u32,
    pub page_layout_spec_id: String,
    pub page_size_id: String,
    pub orientation: PageOrientationV1,
    pub top_margin_millimeters: u32,
    pub bottom_margin_millimeters: u32,
    pub left_margin_millimeters: u32,
    pub right_margin_millimeters: u32,
    pub page_layout_spec_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentOperationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub case_id: String,
    pub planner_cycle_id: String,
    pub document_artifact_id: String,
    pub document_generation: u64,
    pub semantic_state_sha256: String,
    pub operation: DocumentOperationV1,
    pub target_node_ids: Vec<String>,
    pub content_payload_ids: Vec<String>,
    pub style_spec_ids: Vec<String>,
    pub image_spec_ids: Vec<String>,
    pub table_spec_id: Option<String>,
    pub page_layout_spec_id: Option<String>,
    pub required_postcondition_ids: Vec<String>,
    pub risk_class: DocumentRiskClassV1,
    pub intent_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentOperationBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub role_contract_sha256: String,
    pub role_instance_sha256: String,
    pub case_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
    pub workspace_profile_sha256: String,
    pub workspace_root_binding_sha256: String,
    pub artifact_id: String,
    pub artifact_generation: u64,
    pub artifact_content_sha256: String,
    pub semantic_snapshot_sha256: String,
    pub capability_pack_sha256: String,
    pub backend_descriptor_sha256: String,
    pub backend_approval_sha256: String,
    pub operation_intent_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_activation_admission_sha256: String,
    pub worker_sha256: String,
    pub expected_output_generation: u64,
    pub one_time_use_id: String,
    pub expires_at_unix_ms: u64,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub binding_sha256: String,
    pub backend_id: String,
    pub worker_sha256: String,
    pub operation: DocumentOperationV1,
    pub pre_generation: u64,
    pub post_generation: u64,
    pub pre_content_sha256: String,
    pub post_content_sha256: String,
    pub pre_semantic_sha256: String,
    pub post_semantic_sha256: String,
    pub bytes_written: u64,
    pub application_receipt_ids: Vec<String>,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub result_class: DocumentOperationResultV1,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSemanticDiffV1 {
    pub schema_version: u32,
    pub diff_id: String,
    pub added_node_ids: Vec<String>,
    pub removed_node_ids: Vec<String>,
    pub changed_node_ids: Vec<String>,
    pub text_change_ids: Vec<String>,
    pub style_change_ids: Vec<String>,
    pub table_change_ids: Vec<String>,
    pub image_change_ids: Vec<String>,
    pub layout_change_ids: Vec<String>,
    pub unexpected_change_ids: Vec<String>,
    pub diff_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPostOperationVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub receipt_sha256: String,
    pub fresh_snapshot_sha256: String,
    pub required_postcondition_ids: Vec<String>,
    pub passed_postcondition_ids: Vec<String>,
    pub failed_postcondition_ids: Vec<String>,
    pub semantic_diff_sha256: String,
    pub status: DocumentVerificationStatusV1,
    pub verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentStructuralQualityAssessmentV1 {
    pub schema_version: u32,
    pub assessment_id: String,
    pub required_section_ids: Vec<String>,
    pub required_heading_ids: Vec<String>,
    pub required_table_spec_ids: Vec<String>,
    pub required_image_spec_ids: Vec<String>,
    pub nonempty_required_node_ids: Vec<String>,
    pub placeholder_text_forbidden: bool,
    pub unexpected_empty_cell_ids: Vec<String>,
    pub document_structure_valid: bool,
    pub quality_status: DocumentQualityStatusV1,
    pub assessment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSemanticEquivalenceReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub left_snapshot_sha256: String,
    pub right_snapshot_sha256: String,
    pub required_sections_match: bool,
    pub section_order_match: bool,
    pub textual_facts_match: bool,
    pub table_facts_match: bool,
    pub image_roles_match: bool,
    pub style_roles_match: bool,
    pub equivalent: bool,
    pub mismatch_ids: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentWorkReplayReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub scenario_count: u32,
    pub replay_runs: u32,
    pub deterministic_match_count: u32,
    pub deterministic_mismatch_count: u32,
    pub input_set_sha256: String,
    pub first_output_sha256: String,
    pub final_output_sha256: String,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentPerformanceMetricsV1 {
    pub workspace_discovery_microseconds: u64,
    pub hwpx_parse_microseconds: u64,
    pub hwpx_mutation_microseconds: u64,
    pub hwpx_save_microseconds: u64,
    pub hwpx_verify_microseconds: u64,
    pub docx_parse_microseconds: u64,
    pub docx_mutation_microseconds: u64,
    pub docx_save_microseconds: u64,
    pub docx_verify_microseconds: u64,
    pub word_launch_microseconds: u64,
    pub word_open_microseconds: u64,
    pub word_operation_microseconds: u64,
    pub word_save_microseconds: u64,
    pub word_close_microseconds: u64,
    pub qwen_inference_microseconds: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub peak_worker_memory_bytes: u64,
    pub peak_word_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentSafetyMetricsV1 {
    pub wrong_document: u32,
    pub wrong_node: u32,
    pub original_overwrite: u32,
    pub stale_write: u32,
    pub unexpected_document_drift: u32,
    pub duplicate_mutation: u32,
    pub raw_xml_from_model: u32,
    pub raw_com_from_model: u32,
    pub macro_execution: u32,
    pub external_link_fetch: u32,
    pub arbitrary_process: u32,
    pub arbitrary_command: u32,
    pub workspace_escape: u32,
    pub network_access: u32,
    pub credential_leak: u32,
    pub mandatory_escalation_miss: u32,
    pub false_completion: u32,
    pub critical_error: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentResidualMetricsV1 {
    pub worker_owned_word_processes: u32,
    pub worker_owned_hwp_processes: u32,
    pub com_workers: u32,
    pub document_file_locks: u32,
    pub temporary_packages: u32,
    pub activations: u32,
    pub profiles: u32,
    pub credentials: u32,
    pub workspace_locks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub complete: bool,
    pub document_semantic_capability_evidence: bool,
    pub hwpx_document_work_evidence: bool,
    pub docx_document_work_evidence: bool,
    pub word_live_document_work_evidence: bool,
    pub office_workspace_lineage_evidence: bool,
    pub track_o_office200_evidence: bool,
    pub hancom_automation_live_evidence: bool,
    pub hancom_automation_reason_id: String,
    pub hwp_legacy_mutation_status: HwpLegacyMutationStatusV1,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub word_executable_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub document_cases: u32,
    pub routine_cases: u32,
    pub exception_security_cases: u32,
    pub verified_closures: u32,
    pub actual_qwen_cases: u32,
    pub provider_invocations: u32,
    pub replan_count: u32,
    pub clarification_count: u32,
    pub hwpx_mutations: u32,
    pub docx_mutations: u32,
    pub word_com_mutations: u32,
    pub fresh_document_reopens: u32,
    pub successful_operations: u32,
    pub verified_operations: u32,
    pub version_count: u32,
    pub provenance_count: u32,
    pub crash_windows_verified: u32,
    pub replay_report_sha256: String,
    pub equivalence_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub performance: DocumentPerformanceMetricsV1,
    pub safety: DocumentSafetyMetricsV1,
    pub residual: DocumentResidualMetricsV1,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub capability_pack_sha256: String,
    pub backend_approval_sha256s: Vec<String>,
    pub workspace_profile_sha256: String,
    pub replay_report_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub certification_sha256: String,
    pub signature_hex: String,
}
