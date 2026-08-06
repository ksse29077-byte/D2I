use d2i_role_contract::CrossCaseReusePolicyV1;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalCaseOutcomeV1 {
    VerifiedComplete,
    ExplicitRefusal,
    Escalated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeEventKindV1 {
    WorkReceived,
    IntakeAdmitted,
    CaseOpened,
    QueueEnqueued,
    OwnershipAssigned,
    LeaseClaimed,
    GoalUnderstood,
    ProviderInvoked,
    SituationModeled,
    PlanCreated,
    NextStepAdmitted,
    KernelBound,
    ActionAttempted,
    ObservationCaptured,
    VerificationPassed,
    VerificationFailed,
    RecoveryApplied,
    ClarificationRequested,
    EscalationRequested,
    RequirementSatisfied,
    CaseTerminal,
    MemoryUse,
    AuditTerminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLedgerClassV1 {
    Role,
    Intake,
    Case,
    QueueOwnership,
    Planner,
    ProtectedAudit,
    EvidenceIndex,
    TerminalCase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalTrustClassV1 {
    HistoricalNonAuthoritative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeSealStatusV1 {
    Sealed,
    ExactDuplicate,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeSealFailureCodeV1 {
    None,
    NonTerminal,
    SourceMismatch,
    StaleLedger,
    PolicyDenied,
    SensitiveData,
    IntegrityConflict,
    ResourceLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeRetentionStatusV1 {
    Active,
    Held,
    Expired,
    Tombstoned,
    Purged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeMemoryNamespaceV1 {
    pub schema_version: u32,
    pub namespace_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub role_instance_scope: Vec<String>,
    pub memory_boundary_sha256: String,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_responsibility_ids: Vec<String>,
    pub allowed_data_class_ids: Vec<String>,
    pub prohibited_data_class_ids: Vec<String>,
    pub retention_class_id: String,
    pub maximum_retention_days: u32,
    pub cross_case_reuse_policy: CrossCaseReusePolicyV1,
    pub learning_candidate_allowed: bool,
    pub maximum_episodes: u32,
    pub maximum_store_bytes: u64,
    pub maximum_query_results: u32,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub namespace_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryNamespaceApprovalV1 {
    pub schema_version: u32,
    pub namespace_sha256: String,
    pub organization_id: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeEventReferenceV1 {
    pub schema_version: u32,
    pub event_sequence: u32,
    pub event_kind: EpisodeEventKindV1,
    pub occurred_at_unix_ms: u64,
    pub source_ledger_class: SourceLedgerClassV1,
    pub source_ledger_id: String,
    pub source_ledger_sequence: u64,
    pub source_ledger_head_sha256: String,
    pub source_artifact_type: String,
    pub source_artifact_id: String,
    pub source_artifact_sha256: String,
    pub trust_class: String,
    pub evidence_ids: Vec<String>,
    pub event_reference_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequirementStateReferenceV1 {
    pub requirement_id: String,
    pub status: String,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseEpisodeV1 {
    pub schema_version: u32,
    pub episode_id: String,
    pub episode_generation: u32,
    pub organization_id: String,
    pub memory_namespace_id: String,
    pub memory_namespace_sha256: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub delegation_sha256: String,
    pub memory_boundary_sha256: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub final_case_instance_sha256: String,
    pub work_item_sha256: String,
    pub intake_receipt_sha256: String,
    pub queue_ownership_terminal_sha256: String,
    pub case_work_grant_sha256: Option<String>,
    pub terminal_outcome: TerminalCaseOutcomeV1,
    pub opened_at_unix_ms: u64,
    pub terminal_at_unix_ms: u64,
    pub priority_class: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub application_pack_ids: Vec<String>,
    pub integration_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub terminal_evidence_index_sha256: String,
    pub event_references: Vec<EpisodeEventReferenceV1>,
    pub final_requirement_states: Vec<RequirementStateReferenceV1>,
    pub blocker_class_ids: Vec<String>,
    pub clarification_reason_codes: Vec<String>,
    pub escalation_reason_codes: Vec<String>,
    pub provider_descriptor_hashes: Vec<String>,
    pub provider_invocation_hashes: Vec<String>,
    pub provider_result_hashes: Vec<String>,
    pub situation_generation_hashes: Vec<String>,
    pub plan_generation_hashes: Vec<String>,
    pub kernel_run_hashes: Vec<String>,
    pub verified_action_hashes: Vec<String>,
    pub verification_result_hashes: Vec<String>,
    pub recovery_result_hashes: Vec<String>,
    pub protected_audit_terminal_sha256: String,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub retention_record_sha256: String,
    pub approved_summary_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub canonical_episode_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritativeHeadExpectationV1 {
    pub source_ledger_class: SourceLedgerClassV1,
    pub source_ledger_id: String,
    pub expected_sequence: u64,
    pub expected_head_sha256: String,
    pub current_sequence: u64,
    pub current_head_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeSealRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub requested_at_unix_ms: u64,
    pub trusted_now_unix_ms: u64,
    pub terminal_record_present: bool,
    pub episode: CaseEpisodeV1,
    pub namespace: EpisodeMemoryNamespaceV1,
    pub namespace_approval: MemoryNamespaceApprovalV1,
    pub authoritative_heads: Vec<AuthoritativeHeadExpectationV1>,
    pub existing_episode_sha256: Option<String>,
    pub source_references_resolvable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeSealDecisionV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub status: EpisodeSealStatusV1,
    pub failure_code: EpisodeSealFailureCodeV1,
    pub episode_id: String,
    pub episode_sha256: String,
    pub authoritative_heads_sha256: String,
    pub decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeSealReceiptV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub episode_id: String,
    pub episode_sha256: String,
    pub namespace_sha256: String,
    pub decision_sha256: String,
    pub sealed_at_unix_ms: u64,
    pub source_ledger_heads_sha256: String,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedEpisodeSummaryV1 {
    pub schema_version: u32,
    pub summary_id: String,
    pub summary_generation: u32,
    pub episode_sha256: String,
    pub organization_id: String,
    pub namespace_sha256: String,
    pub role_contract_sha256: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub terminal_outcome: TerminalCaseOutcomeV1,
    pub situation_class_ids: Vec<String>,
    pub completed_subgoal_ids: Vec<String>,
    pub recovery_class_ids: Vec<String>,
    pub clarification_reason_codes: Vec<String>,
    pub escalation_reason_codes: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub verified_outcome_class_ids: Vec<String>,
    pub concise_summary: String,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub summary_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EpisodeMemoryQueryFiltersV1 {
    pub role_contract_sha256: Option<String>,
    pub work_class_id: Option<String>,
    pub responsibility_id: Option<String>,
    pub terminal_outcomes: Vec<TerminalCaseOutcomeV1>,
    pub semantic_target_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub verified_outcome_class_ids: Vec<String>,
    pub recovery_class_ids: Vec<String>,
    pub terminal_from_unix_ms: Option<u64>,
    pub terminal_to_unix_ms: Option<u64>,
    pub episode_ids: Vec<String>,
    pub episode_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeMemoryQueryV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub organization_id: String,
    pub namespace_id: String,
    pub namespace_sha256: String,
    pub current_role_contract_sha256: String,
    pub current_case_id: String,
    pub requested_policy: CrossCaseReusePolicyV1,
    pub filters: EpisodeMemoryQueryFiltersV1,
    pub maximum_results: u32,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeIndexEntryV1 {
    pub episode_id: String,
    pub episode_sha256: String,
    pub terminal_outcome: TerminalCaseOutcomeV1,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub terminal_at_unix_ms: u64,
    pub data_class_ids: Vec<String>,
    pub evidence_sha256: String,
    pub retention_status: EpisodeRetentionStatusV1,
    pub approved_summary_sha256: Option<String>,
    pub entry_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeMemoryQueryResultV1 {
    pub schema_version: u32,
    pub query_sha256: String,
    pub reuse_policy: CrossCaseReusePolicyV1,
    pub historical_trust_class: HistoricalTrustClassV1,
    pub episode_references: Vec<EpisodeIndexEntryV1>,
    pub approved_summaries: Vec<ApprovedEpisodeSummaryV1>,
    pub denied_reason_codes: Vec<String>,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeQueryReceiptV1 {
    pub schema_version: u32,
    pub query_sha256: String,
    pub result_sha256: String,
    pub namespace_sha256: String,
    pub reuse_policy: CrossCaseReusePolicyV1,
    pub returned_episode_count: u32,
    pub returned_summary_count: u32,
    pub denied: bool,
    pub completed_at_unix_ms: u64,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryAugmentedCaseContextV1 {
    pub schema_version: u32,
    pub approved_case_context_sha256: String,
    pub current_case_id: String,
    pub current_case_instance_sha256: String,
    pub current_work_grant_sha256: String,
    pub current_lease_sha256: String,
    pub current_situation_model_sha256: Option<String>,
    pub memory_namespace_sha256: String,
    pub reuse_policy: CrossCaseReusePolicyV1,
    pub retrieved_episode_hashes: Vec<String>,
    pub approved_summary_hashes: Vec<String>,
    pub query_receipt_sha256: String,
    pub memory_use_policy_sha256: String,
    pub historical_trust_class: HistoricalTrustClassV1,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub augmented_context_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUseReceiptV1 {
    pub schema_version: u32,
    pub current_case_id: String,
    pub current_case_instance_sha256: String,
    pub current_work_grant_sha256: String,
    pub planner_generation: u32,
    pub query_sha256: String,
    pub query_result_sha256: String,
    pub episode_hashes: Vec<String>,
    pub approved_summary_hashes: Vec<String>,
    pub reuse_policy: CrossCaseReusePolicyV1,
    pub namespace_sha256: String,
    pub role_memory_boundary_sha256: String,
    pub provider_invocation_sha256: Option<String>,
    pub situation_model_sha256: Option<String>,
    pub use_purpose: String,
    pub trust_class: HistoricalTrustClassV1,
    pub used_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeRetentionRecordV1 {
    pub schema_version: u32,
    pub episode_id: String,
    pub episode_sha256: String,
    pub namespace_sha256: String,
    pub retention_class_id: String,
    pub retained_from_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub maximum_retention_days: u32,
    pub status: EpisodeRetentionStatusV1,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeLegalHoldV1 {
    pub schema_version: u32,
    pub hold_id: String,
    pub episode_id: String,
    pub episode_sha256: String,
    pub organization_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeTombstoneV1 {
    pub schema_version: u32,
    pub episode_id: String,
    pub episode_sha256: String,
    pub namespace_sha256: String,
    pub tombstoned_at_unix_ms: u64,
    pub reason_code: String,
    pub protected_audit_sha256: String,
    pub tombstone_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodePurgeReceiptV1 {
    pub schema_version: u32,
    pub episode_id: String,
    pub episode_sha256: String,
    pub tombstone_sha256: String,
    pub object_removed: bool,
    pub summary_removed: bool,
    pub secure_erase_claimed: bool,
    pub completed_at_unix_ms: u64,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodicMemoryReplayReportV1 {
    pub schema_version: u32,
    pub total_episodes: u32,
    pub verified_complete: u32,
    pub explicit_refusal: u32,
    pub escalated: u32,
    pub query_matches: u32,
    pub summaries_returned: u32,
    pub hash_only_references_returned: u32,
    pub denied_reuse: u32,
    pub candidates_generated: u32,
    pub candidates_quarantined: u32,
    pub tombstones: u32,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub peak_records: u32,
    pub logical_operations: u64,
    pub critical_error_count: u32,
    pub episode_set_sha256: String,
    pub index_sha256: String,
    pub query_sha256: String,
    pub attachment_sha256: String,
    pub candidate_set_sha256: String,
    pub normalized_report_sha256: String,
}
