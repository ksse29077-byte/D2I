use serde::{Deserialize, Serialize};

/// Public source class assessed for capability design knowledge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySourceKindV1 {
    OfficialApi,
    OfficialSdk,
    PublicMcp,
    OpenSourceLibrary,
    PublicSkill,
    ManualSemanticReference,
}

/// Terminal OFFICE-100 assessment status. Runtime approval is intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceAssessmentStatusV1 {
    ResearchOnly,
    ApprovedAsReference,
    ApprovedForOfflineConformance,
    EligibleForAdapterDesign,
    RejectedForRuntime,
}

/// Observed transport class; remote transports remain research-only in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTransportClassV1 {
    Documentation,
    FileFormat,
    Stdio,
    LocalProcess,
    ComAutomation,
    RemoteHttp,
}

/// Side-effect class assigned to a public tool without granting authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSideEffectClassV1 {
    ReadOnly,
    FileMutation,
    ApplicationMutation,
    ProcessExecution,
    ArbitraryCode,
}

/// Scope exposure observed in a third-party tool catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolScopeClassV1 {
    None,
    BoundedWorkspace,
    ApprovedApplication,
    ArbitraryLocal,
    Remote,
}

/// Risk class for a proposed D2I-owned semantic capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeCapabilityRiskClassV1 {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    High,
}

/// Working-copy lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingCopyStateV1 {
    Original,
    Working,
    Versioned,
    VerifiedFinal,
}

/// Closed semantic operation set for the v1 workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOperationClassV1 {
    ListArtifacts,
    InspectArtifact,
    CreateFolder,
    ImportArtifact,
    CreateWorkingCopy,
    CopyArtifact,
    RenameArtifact,
    MoveArtifact,
    CommitVersion,
    ExportCopy,
    RestoreVersion,
    CompareIdentity,
}

/// Result status reported by a trusted file operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceOperationStatusV1 {
    Verified,
    Rejected,
    Stale,
    Locked,
    RecoveryRequired,
}

/// Observed Office-style lock state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactLockStateV1 {
    Unlocked,
    OfficeLockPresent,
    ExternalWriteLock,
}

/// Deterministic verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceVerificationStatusV1 {
    Verified,
    Rejected,
}

/// Reproducible assessment of one official or public capability source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySourceRecordV1 {
    pub schema_version: u32,
    pub source_id: String,
    pub source_kind: CapabilitySourceKindV1,
    pub source_name: String,
    pub source_version: String,
    pub source_revision: String,
    pub source_content_sha256: String,
    pub publisher_or_owner_id: String,
    pub application_family_ids: Vec<String>,
    pub license_id: String,
    pub license_source: String,
    pub license_verified: bool,
    pub runtime_language_ids: Vec<String>,
    pub runtime_dependency_ids: Vec<String>,
    pub transport_class: CapabilityTransportClassV1,
    pub requires_network: bool,
    pub requires_local_application: bool,
    pub requires_python: bool,
    pub requires_node: bool,
    pub requires_com: bool,
    pub requires_admin: bool,
    pub exposes_arbitrary_code: bool,
    pub exposes_raw_filesystem: bool,
    pub exposes_network: bool,
    pub exposes_process_launch: bool,
    pub exposes_credentials: bool,
    pub known_security_advisory_ids: Vec<String>,
    pub tool_count: u32,
    pub tool_catalog_sha256: String,
    pub assessment_status: SourceAssessmentStatusV1,
    pub evidence_ids: Vec<String>,
    pub record_sha256: String,
}

/// Hash-only snapshot of an MCP catalog; no third-party source is embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolCatalogSnapshotV1 {
    pub schema_version: u32,
    pub source_record_sha256: String,
    pub protocol_version: String,
    pub transport_class: CapabilityTransportClassV1,
    pub server_name: String,
    pub server_version: String,
    pub tool_ids: Vec<String>,
    pub tool_input_schema_sha256s: Vec<String>,
    pub tool_output_schema_sha256s: Vec<String>,
    pub tool_side_effect_classes: Vec<ToolSideEffectClassV1>,
    pub tool_filesystem_scope_classes: Vec<ToolScopeClassV1>,
    pub tool_process_scope_classes: Vec<ToolScopeClassV1>,
    pub tool_network_scope_classes: Vec<ToolScopeClassV1>,
    pub catalog_sha256: String,
}

/// Quarantined proposal for a future D2I-owned capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeCapabilityCandidateV1 {
    pub schema_version: u32,
    pub candidate_id: String,
    pub source_record_sha256: String,
    pub source_tool_id: String,
    pub application_family_id: String,
    pub proposed_capability_id: String,
    pub proposed_semantic_operation_id: String,
    pub side_effect_class: ToolSideEffectClassV1,
    pub required_observation_class_ids: Vec<String>,
    pub required_precondition_ids: Vec<String>,
    pub required_postcondition_ids: Vec<String>,
    pub filesystem_scope: ToolScopeClassV1,
    pub application_scope: ToolScopeClassV1,
    pub risk_class: OfficeCapabilityRiskClassV1,
    pub prohibited_argument_classes: Vec<String>,
    pub reference_only: bool,
    pub evidence_ids: Vec<String>,
    pub candidate_sha256: String,
}

/// Exact, signed policy for one local approved artifact workspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeWorkspaceProfileV1 {
    pub schema_version: u32,
    pub workspace_id: String,
    pub organization_id: String,
    pub role_scope_ids: Vec<String>,
    pub workspace_root_binding_sha256: String,
    pub allowed_artifact_classes: Vec<String>,
    pub allowed_extensions: Vec<String>,
    pub maximum_total_bytes: u64,
    pub maximum_file_bytes: u64,
    pub maximum_files: u32,
    pub maximum_directories: u32,
    pub maximum_depth: u32,
    pub allowed_operations: Vec<WorkspaceOperationClassV1>,
    pub versioning_policy_id: String,
    pub backup_policy_id: String,
    pub overwrite_policy_id: String,
    pub delete_policy_id: String,
    pub retention_policy_id: String,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub signer_key_id: String,
    pub profile_sha256: String,
    pub signature_hex: String,
}

/// Runtime-only exact root binding; canonical_root never enters cognitive artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootBindingV1 {
    pub schema_version: u32,
    pub workspace_id: String,
    pub canonical_root: String,
    pub root_identity: String,
    pub volume_identity: String,
    pub security_descriptor_sha256: String,
    pub reparse_forbidden: bool,
    pub symlink_forbidden: bool,
    pub network_share_allowed: bool,
    pub removable_media_allowed: bool,
    pub valid_from_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub binding_sha256: String,
}

/// Cognitive-safe artifact reference using a relative token rather than an absolute path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeArtifactReferenceV1 {
    pub schema_version: u32,
    pub artifact_id: String,
    pub workspace_id: String,
    pub relative_path_token: String,
    pub artifact_class: String,
    pub file_format_id: String,
    pub content_sha256: String,
    pub byte_length: u64,
    pub creation_generation: u64,
    pub current_generation: u64,
    pub source_artifact_id: Option<String>,
    pub parent_version_id: Option<String>,
    pub immutable_original: bool,
    pub working_copy_state: WorkingCopyStateV1,
    pub data_class_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub artifact_sha256: String,
}

/// Fresh bounded projection of workspace state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceObservationSnapshotV1 {
    pub schema_version: u32,
    pub observation_id: String,
    pub workspace_id: String,
    pub artifact_ids: Vec<String>,
    pub artifact_generations: Vec<u64>,
    pub content_sha256s: Vec<String>,
    pub sizes: Vec<u64>,
    pub formats: Vec<String>,
    pub lock_states: Vec<ArtifactLockStateV1>,
    pub write_states: Vec<String>,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub observation_sha256: String,
}

/// Planner-owned semantic request. It contains no path or command authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOperationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub workspace_id: String,
    pub operation: WorkspaceOperationClassV1,
    pub source_artifact_id: Option<String>,
    pub destination_folder_id: Option<String>,
    pub destination_filename: Option<String>,
    pub approved_content_sha256: Option<String>,
    pub expected_source_content_sha256: Option<String>,
    pub expected_source_generation: Option<u64>,
    pub case_id: String,
    pub role_instance_id: String,
    pub evidence_ids: Vec<String>,
    pub intent_sha256: String,
}

/// Trusted join of Role, Case, Policy, activation, root, and exact artifact state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOperationBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub role_contract_sha256: String,
    pub role_instance_sha256: String,
    pub case_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
    pub workspace_profile_sha256: String,
    pub workspace_root_binding_sha256: String,
    pub source_artifact_sha256: Option<String>,
    pub source_generation: Option<u64>,
    pub operation_intent_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_activation_admission_sha256: String,
    pub expected_output_scope_token: String,
    pub one_time_use_id: String,
    pub expires_at_unix_ms: u64,
    pub binding_sha256: String,
}

/// Audit-safe outcome of one trusted workspace operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub operation_intent_sha256: String,
    pub binding_sha256: String,
    pub source_artifact_sha256: Option<String>,
    pub source_generation: Option<u64>,
    pub destination_artifact_sha256: Option<String>,
    pub destination_generation: Option<u64>,
    pub operation_class: WorkspaceOperationClassV1,
    pub status: WorkspaceOperationStatusV1,
    pub structured_result_code: String,
    pub bytes_processed: u64,
    pub atomic_commit: bool,
    pub old_identity_sha256: Option<String>,
    pub new_identity_sha256: Option<String>,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub verification_sha256: String,
    pub receipt_sha256: String,
}

/// Hash-only lineage shared by all future Office application packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeArtifactProvenanceV1 {
    pub schema_version: u32,
    pub artifact_sha256: String,
    pub source_artifact_sha256s: Vec<String>,
    pub case_sha256: String,
    pub role_instance_sha256: String,
    pub operation_receipt_sha256s: Vec<String>,
    pub application_family_id: String,
    pub created_at_unix_ms: u64,
    pub modified_at_unix_ms: u64,
    pub data_class_ids: Vec<String>,
    pub verification_sha256s: Vec<String>,
    pub provenance_sha256: String,
}

/// Deterministic contract replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeWorkspaceReplayReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub synthetic_scenario_count: u32,
    pub replay_runs: u32,
    pub deterministic_match_count: u32,
    pub deterministic_mismatch_count: u32,
    pub input_set_sha256: String,
    pub first_output_sha256: String,
    pub final_output_sha256: String,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

/// Sealed OFFICE-100 completion metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeWorkspaceCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub complete: bool,
    pub office_capability_foundation_evidence: bool,
    pub office_workspace_evidence: bool,
    pub track_o_started: bool,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub source_assessment_count: u32,
    pub excel_source_count: u32,
    pub powerpoint_source_count: u32,
    pub hwp_source_count: u32,
    pub official_source_count: u32,
    pub mcp_catalog_count: u32,
    pub rejected_runtime_source_count: u32,
    pub eligible_adapter_design_count: u32,
    pub workspace_cases: u32,
    pub routine_verified: u32,
    pub human_exceptions: u32,
    pub artifact_count: u32,
    pub operation_count: u32,
    pub version_count: u32,
    pub provenance_count: u32,
    pub stale_recoveries: u32,
    pub path_escape_count: u32,
    pub wrong_file_count: u32,
    pub original_overwrite_count: u32,
    pub duplicate_mutation_count: u32,
    pub stale_write_count: u32,
    pub reparse_escape_count: u32,
    pub symlink_escape_count: u32,
    pub raw_absolute_path_in_model_context_count: u32,
    pub arbitrary_command_count: u32,
    pub arbitrary_code_execution_count: u32,
    pub credential_leak_count: u32,
    pub network_access_count: u32,
    pub false_completion_count: u32,
    pub critical_error_count: u32,
    pub list_latency_microseconds: u64,
    pub hash_latency_microseconds: u64,
    pub copy_latency_microseconds: u64,
    pub rename_latency_microseconds: u64,
    pub move_latency_microseconds: u64,
    pub version_commit_latency_microseconds: u64,
    pub verification_latency_microseconds: u64,
    pub bytes_processed: u64,
    pub peak_memory_bytes: u64,
    pub replay_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub residual_process_count: u32,
    pub residual_profile_count: u32,
    pub residual_lock_count: u32,
    pub residual_store_count: u32,
    pub finished_sha256: String,
}

/// Signed terminal certification for one exact Completion report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeWorkspaceCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub workspace_profile_sha256: String,
    pub workspace_root_binding_sha256: String,
    pub replay_report_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub certification_sha256: String,
    pub signature_hex: String,
}
