use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfInterchangeProfileV1 {
    SubmissionStatic,
    InternalReview,
    ArchivePdfaRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfOriginClassV1 {
    D2iGenerated,
    ExternalUntrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfPageSelectionPolicyV1 {
    AllApproved,
    ApprovedRange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportProfileV1 {
    pub schema_version: u32,
    pub profile: PdfInterchangeProfileV1,
    pub quality_id: String,
    pub optimization_id: String,
    pub metadata_policy_id: String,
    pub structure_tag_policy_id: String,
    pub bookmark_policy_id: String,
    pub hidden_content_policy_id: String,
    pub pdfa_requested: bool,
    pub page_selection_policy: PdfPageSelectionPolicyV1,
    pub external_link_policy_id: String,
    pub font_policy_id: String,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfSourceFormatV1 {
    Docx,
    Xlsx,
    Pptx,
    Hwpx,
    ExternalPdf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfExportBackendKindV1 {
    WordFixedPdf,
    ExcelFixedPdf,
    PowerpointFixedPdf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfVerificationStatusV1 {
    Passed,
    Failed,
    RenderOnly,
    RequiresLicensedHancomRenderBackend,
    ExternalConformanceUnverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalArtifactPairStateV1 {
    Finalized,
    Superseded,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PdfFailureCodeV1 {
    None,
    StaleFinalization,
    SourceVerificationFailed,
    SourceQualityFailed,
    UnsupportedSource,
    LicensedBackendRequired,
    ExportFailed,
    OutputNotFresh,
    PdfLoadFailed,
    PasswordProtected,
    PageLimitExceeded,
    PixelBudgetExceeded,
    RenderTimeout,
    GeometryMismatch,
    VisualFidelityFailed,
    LineageMismatch,
    ExternalPdfRenderOnly,
    ExternalConformanceUnverified,
    AuditFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfFinalizationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub organization_id: String,
    pub profile: PdfInterchangeProfileV1,
    pub requested_pdfa: bool,
    pub ready_for_submission_requested: bool,
    pub intent_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub role_id: String,
    pub workspace_id: String,
    pub source_artifact_id: String,
    pub source_format: PdfSourceFormatV1,
    pub source_generation: u64,
    pub expected_source_sha256: String,
    pub expected_source_snapshot_sha256: String,
    pub expected_source_verification_sha256: String,
    pub expected_source_quality_sha256: String,
    pub expected_application_state_sha256: String,
    pub finalization_intent_sha256: String,
    pub export_profile_sha256: String,
    pub backend_approval_sha256: String,
    pub page_selection_policy: PdfPageSelectionPolicyV1,
    pub approved_sheet_ids: Vec<String>,
    pub expected_design_quality_ref: Option<String>,
    pub output_artifact_id: String,
    pub issued_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportBackendDescriptorV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub backend_kind: PdfExportBackendKindV1,
    pub executable_sha256: String,
    pub executable_version: String,
    pub authenticode_valid: bool,
    pub worker_executable_sha256: String,
    pub official_method_id: String,
    pub network_denied: bool,
    pub private_desktop: bool,
    pub mutable_operations: Vec<String>,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportBackendApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub environment_id: String,
    pub backend_descriptor_sha256: String,
    pub allowed_source_formats: Vec<PdfSourceFormatV1>,
    pub approved_profile_ids: Vec<PdfInterchangeProfileV1>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub approval_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub role_id: String,
    pub lease_sha256: String,
    pub case_work_grant_sha256: String,
    pub workspace_profile_sha256: String,
    pub root_binding_sha256: String,
    pub request_sha256: String,
    pub source_artifact_id: String,
    pub source_artifact_sha256: String,
    pub source_snapshot_sha256: String,
    pub source_verification_sha256: String,
    pub design_quality_sha256: Option<String>,
    pub source_generation: u64,
    pub export_profile_sha256: String,
    pub backend_descriptor_sha256: String,
    pub backend_approval_sha256: String,
    pub policy_decision_sha256: String,
    pub activation_id: String,
    pub activation_sha256: String,
    pub worker_executable_sha256: String,
    pub application_executable_sha256: String,
    pub expected_output_artifact_id: String,
    pub one_shot_sequence: u64,
    pub consumed: bool,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfExportReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub request_sha256: String,
    pub binding_sha256: String,
    pub backend_descriptor_sha256: String,
    pub source_artifact_sha256: String,
    pub exporter_application_sha256: String,
    pub worker_executable_sha256: String,
    pub output_pdf_sha256: String,
    pub output_pdf_bytes: u64,
    pub export_started_at_unix_ms: u64,
    pub export_completed_at_unix_ms: u64,
    pub native_export_succeeded: bool,
    pub output_fresh_and_stable: bool,
    pub pdfa_requested: bool,
    pub exporter_pdfa_flag: bool,
    pub external_pdfa_conformance_verified: bool,
    pub page_count_reported_by_source: u32,
    pub hidden_unit_count: u32,
    pub failure_code: PdfFailureCodeV1,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfPageSnapshotV1 {
    pub page_index: u32,
    pub width_millipoints: u32,
    pub height_millipoints: u32,
    pub rotation_degrees: u16,
    pub rendered_width_pixels: u32,
    pub rendered_height_pixels: u32,
    pub rendered_png_sha256: String,
    pub visual_fingerprint_sha256: String,
    pub non_white_pixel_millionths: u32,
    pub blankness_millionths: u32,
    pub page_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfDocumentSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub pdf_artifact_id: String,
    pub pdf_generation: u64,
    pub origin_class: PdfOriginClassV1,
    pub pdf_sha256: String,
    pub pdf_file_bytes: u64,
    pub page_count: u32,
    pub password_protected: bool,
    pub pages: Vec<PdfPageSnapshotV1>,
    pub export_pair_ref: Option<String>,
    pub renderer_build_id: String,
    pub renderer_executable_sha256: String,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfRenderRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub expected_pdf_sha256: String,
    pub external_untrusted: bool,
    pub maximum_pages: u32,
    pub maximum_pdf_bytes: u64,
    pub maximum_total_pixels: u64,
    pub maximum_page_width_millipoints: u32,
    pub maximum_page_height_millipoints: u32,
    pub maximum_output_png_bytes: u64,
    pub maximum_worker_memory_bytes: u64,
    pub maximum_page_render_milliseconds: u64,
    pub maximum_total_render_milliseconds: u64,
    pub destination_width_pixels: u32,
    pub issued_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfRenderResultV1 {
    pub schema_version: u32,
    pub result_id: String,
    pub request_sha256: String,
    pub pdf_sha256: String,
    pub document_snapshot_sha256: String,
    pub rendered_page_count: u32,
    pub rendered_total_pixels: u64,
    pub status: PdfVerificationStatusV1,
    pub failure_code: PdfFailureCodeV1,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfVisualFingerprintV1 {
    pub schema_version: u32,
    pub fingerprint_id: String,
    pub rendered_png_sha256: String,
    pub non_white_pixel_millionths: u32,
    pub luminance_buckets: Vec<u32>,
    pub color_buckets: Vec<u32>,
    pub edge_buckets: Vec<u32>,
    pub occupancy_buckets: Vec<u32>,
    pub perceptual_hash_sha256: String,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfVisualFidelityReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_render_sha256s: Vec<String>,
    pub pdf_render_sha256s: Vec<String>,
    pub compared_page_count: u32,
    pub maximum_distance_millionths: u32,
    pub catastrophic_drift_count: u32,
    pub threshold_profile_sha256: String,
    pub verified: bool,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfGeometryVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub source_format: PdfSourceFormatV1,
    pub expected_page_count: u32,
    pub actual_page_count: u32,
    pub dimension_mismatch_count: u32,
    pub aspect_ratio_mismatch_count: u32,
    pub rotation_mismatch_count: u32,
    pub hidden_unit_leak_count: u32,
    pub blank_page_count: u32,
    pub verified: bool,
    pub verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfPostExportVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub export_receipt_sha256: String,
    pub document_snapshot_sha256: String,
    pub geometry_verification_sha256: String,
    pub visual_fidelity_report_sha256: Option<String>,
    pub source_lineage_verified: bool,
    pub security_verified: bool,
    pub independent_load_verified: bool,
    pub independent_render_verified: bool,
    pub verified: bool,
    pub failure_code: PdfFailureCodeV1,
    pub verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalArtifactPairV1 {
    pub schema_version: u32,
    pub pair_id: String,
    pub organization_id: String,
    pub source_artifact_id: String,
    pub source_generation: u64,
    pub source_artifact_sha256: String,
    pub source_snapshot_sha256: String,
    pub pdf_artifact_id: String,
    pub pdf_generation: u64,
    pub pdf_artifact_sha256: String,
    pub export_profile_sha256: String,
    pub export_backend_sha256: String,
    pub export_receipt_sha256: String,
    pub post_export_verification_sha256: String,
    pub design_quality_ref: Option<String>,
    pub fact_lineage_refs: Vec<String>,
    pub created_at_unix_ms: u64,
    pub state: FinalArtifactPairStateV1,
    pub ready_for_submission: bool,
    pub pair_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfFinalizationSealV1 {
    pub schema_version: u32,
    pub seal_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub final_artifact_pair_sha256: String,
    pub source_artifact_sha256: String,
    pub pdf_artifact_sha256: String,
    pub export_profile_sha256: String,
    pub post_export_verification_sha256: String,
    pub pair_state: FinalArtifactPairStateV1,
    pub source_tree_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub seal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentInterchangeManifestV1 {
    pub schema_version: u32,
    pub manifest_id: String,
    pub organization_id: String,
    pub source_format: PdfSourceFormatV1,
    pub source_artifact_id: String,
    pub source_artifact_sha256: String,
    pub source_snapshot_sha256: String,
    pub pdf_artifact_sha256: String,
    pub pdf_artifact_id: String,
    pub source_filename: String,
    pub pdf_filename: String,
    pub source_mime_type: String,
    pub pdf_mime_type: String,
    pub final_artifact_pair_sha256: String,
    pub finalization_seal_sha256: String,
    pub lineage_evidence_sha256s: Vec<String>,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmissionArtifactManifestV1 {
    pub schema_version: u32,
    pub manifest_id: String,
    pub organization_id: String,
    pub interchange_manifest_sha256: String,
    pub final_artifact_pair_sha256: String,
    pub finalization_seal_sha256: String,
    pub submission_filename: String,
    pub mime_type: String,
    pub artifact_sha256: String,
    pub fact_provenance_sha256s: Vec<String>,
    pub design_quality_ref: Option<String>,
    pub ready_for_submission: bool,
    pub external_pdfa_conformance_verified: bool,
    pub created_at_unix_ms: u64,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PdfSecurityMetricsV1 {
    pub wrong_source_artifact: u32,
    pub wrong_source_generation: u32,
    pub wrong_export_profile: u32,
    pub wrong_output_artifact: u32,
    pub original_overwrite: u32,
    pub stale_export: u32,
    pub duplicate_export: u32,
    pub source_pdf_lineage_mismatch: u32,
    pub wrong_org_pack: u32,
    pub unverified_source_export: u32,
    pub raw_path_from_model: u32,
    pub shell_print: u32,
    pub send_keys: u32,
    pub pdf_printer: u32,
    pub browser_pdf: u32,
    pub external_converter: u32,
    pub arbitrary_com: u32,
    pub custom_external_exporter: u32,
    pub arbitrary_command: u32,
    pub raw_pdf_to_model: u32,
    pub raw_office_document_to_model: u32,
    pub page_image_to_model: u32,
    pub external_pdf_fact_promotion: u32,
    pub arbitrary_pdf_edit: u32,
    pub network_access: u32,
    pub arbitrary_process: u32,
    pub workspace_escape: u32,
    pub credential_leak: u32,
    pub viewer_launch: u32,
    pub password_collection: u32,
    pub macro_execution: u32,
    pub external_data_refresh: u32,
    pub hidden_content_leak: u32,
    pub false_submission_ready: u32,
    pub false_completion: u32,
    pub critical_error: u32,
    pub unloadable_pdf: u32,
    pub unexpected_page_count: u32,
    pub unexpected_page_geometry: u32,
    pub required_blank_page: u32,
    pub render_failure: u32,
    pub render_timeout: u32,
    pub visual_catastrophic_drift: u32,
    pub missing_pdf_pair: u32,
    pub stale_pdf_pair: u32,
    pub invalid_finalization_seal: u32,
    pub source_hard_design_violation: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PdfResidualMetricsV1 {
    pub word_processes: u32,
    pub excel_processes: u32,
    pub powerpoint_processes: u32,
    pub export_workers: u32,
    pub render_workers: u32,
    pub model_workers: u32,
    pub wfp_objects: u32,
    pub appcontainer_profiles: u32,
    pub temporary_render_files: u32,
    pub temporary_pdf_files: u32,
    pub temporary_png_files: u32,
    pub file_locks: u32,
    pub office_file_locks: u32,
    pub activations: u32,
    pub credentials: u32,
    pub workspace_locks: u32,
    pub viewer_processes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PdfPerformanceMetricsV1 {
    pub source_preflight_microseconds: u64,
    pub export_microseconds: u64,
    pub pdf_load_microseconds: u64,
    pub render_microseconds: u64,
    pub fidelity_microseconds: u64,
    pub finalization_microseconds: u64,
    pub model_microseconds: u64,
    pub peak_export_worker_memory_bytes: u64,
    pub peak_render_worker_memory_bytes: u64,
    pub peak_model_worker_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfWorkReplayReportV1 {
    pub schema_version: u32,
    pub scenario_count: u32,
    pub runs_per_scenario: u32,
    pub export_selection_mismatch_count: u32,
    pub geometry_mismatch_count: u32,
    pub lineage_mismatch_count: u32,
    pub manifest_mismatch_count: u32,
    pub stale_acceptance_count: u32,
    pub blind_replay_count: u32,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub word_pdf_exports: u32,
    pub excel_pdf_exports: u32,
    pub powerpoint_pdf_exports: u32,
    pub pdf_load_count: u32,
    pub rendered_page_count: u32,
    pub powerpoint_fidelity_comparisons: u32,
    pub external_pdf_render_only_cases: u32,
    pub external_pdf_malformed_rejections: u32,
    pub external_pdf_password_rejections: u32,
    pub external_pdf_oversize_rejections: u32,
    pub actual_qwen_invocation_count: u32,
    pub final_artifact_pair_count: u32,
    pub submission_manifest_count: u32,
    pub stale_pair_count: u32,
    pub superseded_pair_count: u32,
    pub pdfa_requested_cases: u32,
    pub pdfa_exporter_requested_cases: u32,
    pub pdfa_external_conformance_verified_cases: u32,
    pub hwpx_pdf_export_status: PdfVerificationStatusV1,
    pub crash_windows_verified: u32,
    pub replay_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub security: PdfSecurityMetricsV1,
    pub residual: PdfResidualMetricsV1,
    pub performance: PdfPerformanceMetricsV1,
    pub pdf_interchange_evidence: bool,
    pub word_pdf_export_evidence: bool,
    pub excel_pdf_export_evidence: bool,
    pub powerpoint_pdf_export_evidence: bool,
    pub independent_pdf_render_evidence: bool,
    pub powerpoint_visual_fidelity_evidence: bool,
    pub source_pdf_lineage_evidence: bool,
    pub submission_manifest_evidence: bool,
    pub external_pdf_render_only_evidence: bool,
    pub office450_lineage_evidence: bool,
    pub track_o_office500_evidence: bool,
    pub routine_human_touch_zero: bool,
    pub complete: bool,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub predecessor_finished_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub word_executable_sha256: String,
    pub excel_executable_sha256: String,
    pub powerpoint_executable_sha256: String,
    pub pdf_render_worker_sha256: String,
    pub evidence_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}
