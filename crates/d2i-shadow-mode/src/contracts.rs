use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowRecorderModeV1 {
    InteractiveHuman,
    InstrumentedReferenceOperator,
    RecordedDeterministicFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowBlindingModeV1 {
    ProposalCommittedAndHiddenUntilReferenceDurable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowDecisionClassV1 {
    Act,
    Clarify,
    Escalate,
    DeclareComplete,
    Refuse,
    Stop,
    NoAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualDispositionV1 {
    WouldAllow,
    WouldRequireConfirmation,
    WouldDeny,
    WouldEscalate,
    InsufficientEvidence,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowResultClassV1 {
    Applied,
    ClarificationRequested,
    Escalated,
    CompletionAsserted,
    Refused,
    Stopped,
    NoAction,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowSessionStatusV1 {
    Enrolled,
    Active,
    AwaitingReferenceAction,
    AwaitingAdjudication,
    Completed,
    ClarificationTerminal,
    EscalationTerminal,
    Refused,
    Invalid,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowCycleStatusV1 {
    ProposalCommitted,
    ReferenceDurable,
    ObservationDurable,
    Verified,
    Revealed,
    Adjudicated,
    AbortedStale,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowComparisonStatusV1 {
    ExactMatch,
    ApprovedSemanticEquivalent,
    SafeAlternative,
    AiCorrectHumanIncorrect,
    HumanCorrectAiIncorrect,
    BothCorrectDifferentRoute,
    BothIncorrect,
    AiUnnecessaryAction,
    HumanUnnecessaryAction,
    AiMissedRequiredAction,
    HumanMissedRequiredAction,
    CounterfactualUnobserved,
    InsufficientEvidence,
    Incomparable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowCorrectnessV1 {
    Correct,
    Incorrect,
    InsufficientEvidence,
    CounterfactualUnobserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowEvidenceCoverageStatusV1 {
    Complete,
    Partial,
    Insufficient,
    Conflicting,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowMetricStatusV1 {
    Passed,
    Failed,
    InsufficientEvidence,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowReadinessStatusV1 {
    InsufficientEvidence,
    BlockedByCriticalError,
    NotReady,
    EligibleForWork900Design,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticEquivalenceBindingV1 {
    pub left_operation_class_id: String,
    pub right_operation_class_id: String,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowModeProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_version: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub role_instance_scope: Vec<String>,
    pub policy_set_sha256: String,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_responsibility_ids: Vec<String>,
    pub allowed_application_pack_hashes: Vec<String>,
    pub allowed_integration_ids: Vec<String>,
    pub allowed_observation_source_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub provider_descriptor_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub allowed_reference_operator_class_ids: Vec<String>,
    pub allowed_recorder_modes: Vec<ShadowRecorderModeV1>,
    pub blinding_mode: ShadowBlindingModeV1,
    pub approved_equivalence_bindings: Vec<SemanticEquivalenceBindingV1>,
    pub maximum_cases: u32,
    pub maximum_cycles_per_case: u32,
    pub maximum_proposals_per_cycle: u32,
    pub maximum_observation_bytes: u64,
    pub maximum_report_bytes: u64,
    pub maximum_store_bytes: u64,
    pub retention_class_id: String,
    pub maximum_retention_days: u32,
    pub readiness_policy_sha256: String,
    pub internal_routing_class_id: String,
    pub evidence_ids: Vec<String>,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowModeProfileApprovalV1 {
    pub schema_version: u32,
    pub profile_sha256: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReadinessPolicyV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_version: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub minimum_model_backed_cases: u32,
    pub minimum_interactive_sessions: u32,
    pub minimum_instrumented_sessions: u32,
    pub minimum_windows_sessions: u32,
    pub minimum_evidence_coverage_millionths: u32,
    pub minimum_proposal_validity_millionths: u32,
    pub minimum_decision_class_agreement_millionths: u32,
    pub minimum_policy_disposition_agreement_millionths: u32,
    pub minimum_verified_outcome_agreement_millionths: u32,
    pub minimum_mandatory_escalation_recall_millionths: u32,
    pub minimum_clarification_precision_millionths: u32,
    pub minimum_clarification_recall_millionths: u32,
    pub maximum_unnecessary_ai_action_millionths: u32,
    pub maximum_missed_required_action_millionths: u32,
    pub maximum_false_completion_count: u32,
    pub maximum_forbidden_capability_count: u32,
    pub maximum_authority_expansion_count: u32,
    pub maximum_secret_leakage_count: u32,
    pub maximum_direct_execution_attempt_count: u32,
    pub maximum_unblinded_cycle_count: u32,
    pub maximum_critical_error_count: u32,
    pub required_domain_fixture_ids: Vec<String>,
    pub required_windows_fixture_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReadinessPolicyApprovalV1 {
    pub schema_version: u32,
    pub policy_sha256: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub signer_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvaluationCohortV1 {
    pub schema_version: u32,
    pub cohort_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub readiness_policy_sha256: String,
    pub provider_descriptor_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub dataset_split_id: String,
    pub case_enrollment_ids: Vec<String>,
    pub work_class_strata: Vec<String>,
    pub scenario_class_ids: Vec<String>,
    pub domain_fixture_ids: Vec<String>,
    pub randomization_seed: u64,
    pub cohort_sealed_at_unix_ms: u64,
    pub evaluation_starts_at_unix_ms: u64,
    pub evaluation_ends_at_unix_ms: u64,
    pub exclusion_policy_id: String,
    pub allowed_exclusion_reason_codes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub cohort_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCohortApprovalV1 {
    pub schema_version: u32,
    pub cohort_sha256: String,
    pub profile_sha256: String,
    pub readiness_policy_sha256: String,
    pub organization_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowParticipationApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub actor_class_id: String,
    pub allowed_application_ids: Vec<String>,
    pub allowed_observation_classes: Vec<String>,
    pub prohibited_collection_classes: Vec<String>,
    pub retention_class_id: String,
    pub maximum_retention_days: u32,
    pub no_keylogging: bool,
    pub no_global_mouse_hook: bool,
    pub no_screen_recording: bool,
    pub no_clipboard: bool,
    pub data_class_allowlist: Vec<String>,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOperatorAssignmentV1 {
    pub schema_version: u32,
    pub assignment_id: String,
    pub organization_id: String,
    pub cohort_sha256: String,
    pub case_enrollment_id: String,
    pub actor_class_id: String,
    pub recorder_mode: ShadowRecorderModeV1,
    pub allowed_application_pack_sha256: String,
    pub allowed_semantic_target_ids: Vec<String>,
    pub allowed_reference_operation_class_ids: Vec<String>,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub participation_approval_sha256: String,
    pub evidence_ids: Vec<String>,
    pub assignment_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOperatorAttestationV1 {
    pub schema_version: u32,
    pub attestation_id: String,
    pub assignment_sha256: String,
    pub session_id: String,
    pub actor_class_id: String,
    pub recorder_mode: ShadowRecorderModeV1,
    pub interactive_session: bool,
    pub participation_approval_sha256: String,
    pub fixture_identity_sha256: String,
    pub process_identity_sha256: String,
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub attestation_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCaseEnrollmentV1 {
    pub schema_version: u32,
    pub enrollment_id: String,
    pub cohort_sha256: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub source_case_id: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub work_item_sha256: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub reference_operator_assignment_sha256: String,
    pub shadow_observation_grant_sha256: String,
    pub enrolled_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub scenario_class_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub enrollment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowObservationGrantV1 {
    pub schema_version: u32,
    pub grant_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub case_id: String,
    pub case_sha256: String,
    pub enrollment_sha256: String,
    pub allowed_observation_source_ids: Vec<String>,
    pub application_pack_hashes: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub maximum_snapshots: u32,
    pub maximum_bytes: u64,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub execution_forbidden: bool,
    pub activation_forbidden: bool,
    pub adapter_mutation_forbidden: bool,
    pub evidence_ids: Vec<String>,
    pub grant_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowSessionV1 {
    pub schema_version: u32,
    pub session_id: String,
    pub cohort_sha256: String,
    pub enrollment_sha256: String,
    pub profile_sha256: String,
    pub readiness_policy_sha256: String,
    pub provider_descriptor_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub reference_operator_assignment_sha256: String,
    pub participation_approval_sha256: String,
    pub status: ShadowSessionStatusV1,
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: Option<u64>,
    pub maximum_cycles: u32,
    pub completed_cycles: u32,
    pub current_observation_sha256: String,
    pub previous_session_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub session_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCycleV1 {
    pub schema_version: u32,
    pub session_id: String,
    pub cycle_index: u32,
    pub pre_action_observation_sha256: String,
    pub situation_model_sha256: String,
    pub shadow_proposal_sha256: String,
    pub commitment_sha256: String,
    pub human_reference_step_sha256: String,
    pub post_action_observation_sha256: String,
    pub verification_result_sha256: String,
    pub comparison_sha256: String,
    pub adjudication_sha256: String,
    pub status: ShadowCycleStatusV1,
    pub previous_cycle_sha256: String,
    pub cycle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowProposalV1 {
    pub schema_version: u32,
    pub proposal_id: String,
    pub session_id: String,
    pub cycle_index: u32,
    pub case_enrollment_sha256: String,
    pub goal_spec_sha256: String,
    pub situation_model_sha256: String,
    pub plan_generation_sha256: String,
    pub source_observation_id: String,
    pub source_observation_sha256: String,
    pub source_observation_sequence: u64,
    pub provider_invocation_sha256: String,
    pub provider_result_sha256: String,
    pub decision_class: ShadowDecisionClassV1,
    pub semantic_intent_class_id: String,
    pub capability_id: Option<String>,
    pub semantic_target_id: Option<String>,
    pub approved_argument_artifact_sha256: Option<String>,
    pub required_precondition_hashes: Vec<String>,
    pub expected_postcondition_hashes: Vec<String>,
    pub predicted_risk_class_id: String,
    pub predicted_policy_disposition: CounterfactualDispositionV1,
    pub predicted_case_progress_class_id: String,
    pub clarification_reason_codes: Vec<String>,
    pub escalation_reason_codes: Vec<String>,
    pub confidence_millionths: Option<u32>,
    pub uncertainty_class_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub proposal_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualPolicyAssessmentV1 {
    pub schema_version: u32,
    pub assessment_id: String,
    pub shadow_proposal_sha256: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub policy_set_sha256: String,
    pub case_contract_sha256: String,
    pub capability_id: Option<String>,
    pub semantic_target_id: Option<String>,
    pub risk_class_id: String,
    pub disposition: CounterfactualDispositionV1,
    pub reason_codes: Vec<String>,
    pub execution_forbidden: bool,
    pub admission_artifact_absent: bool,
    pub activation_artifact_absent: bool,
    pub evidence_ids: Vec<String>,
    pub assessment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowProposalCommitmentV1 {
    pub schema_version: u32,
    pub commitment_id: String,
    pub session_id: String,
    pub cycle_index: u32,
    pub source_observation_sha256: String,
    pub proposal_sha256: String,
    pub counterfactual_policy_assessment_sha256: String,
    pub committed_at_unix_ms: u64,
    pub reveal_allowed_after_event_class_id: String,
    pub protected_object_sha256: String,
    pub evidence_ids: Vec<String>,
    pub commitment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowProposalRevealReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub commitment_sha256: String,
    pub human_reference_step_sha256: String,
    pub post_action_observation_sha256: String,
    pub revealed_proposal_sha256: String,
    pub human_step_durable_at_unix_ms: u64,
    pub post_observation_durable_at_unix_ms: u64,
    pub revealed_at_unix_ms: u64,
    pub operator_visible_before_action: bool,
    pub evidence_ids: Vec<String>,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanReferenceStepV1 {
    pub schema_version: u32,
    pub step_id: String,
    pub session_id: String,
    pub cycle_index: u32,
    pub assignment_sha256: String,
    pub actor_class_id: String,
    pub recorder_mode: ShadowRecorderModeV1,
    pub decision_class: ShadowDecisionClassV1,
    pub reference_operation_class_id: Option<String>,
    pub capability_classification_id: Option<String>,
    pub semantic_target_id: Option<String>,
    pub approved_argument_artifact_sha256: Option<String>,
    pub pre_action_observation_id: String,
    pub pre_action_observation_sha256: String,
    pub pre_action_observation_sequence: u64,
    pub post_action_observation_id: String,
    pub post_action_observation_sha256: String,
    pub post_action_observation_sequence: u64,
    pub action_started_at_unix_ms: u64,
    pub action_completed_at_unix_ms: u64,
    pub verification_result_sha256: Option<String>,
    pub policy_assessment_sha256: String,
    pub result_class: ShadowResultClassV1,
    pub evidence_ids: Vec<String>,
    pub step_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanReferenceOutcomeV1 {
    pub schema_version: u32,
    pub session_id: String,
    pub case_enrollment_sha256: String,
    pub terminal_reference_decision: ShadowDecisionClassV1,
    pub final_observation_sha256: String,
    pub verification_result_hashes: Vec<String>,
    pub satisfied_requirement_ids: Vec<String>,
    pub unsatisfied_requirement_ids: Vec<String>,
    pub policy_compliant: bool,
    pub human_exception_status_id: String,
    pub completion_asserted: bool,
    pub independently_verified_outcome: bool,
    pub evidence_ids: Vec<String>,
    pub outcome_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowStepComparisonV1 {
    pub schema_version: u32,
    pub comparison_id: String,
    pub session_id: String,
    pub cycle_index: u32,
    pub proposal_sha256: String,
    pub human_reference_step_sha256: String,
    pub shared_pre_action_observation_sha256: String,
    pub decision_class_match: bool,
    pub capability_match: bool,
    pub semantic_target_match: bool,
    pub argument_artifact_match: bool,
    pub precondition_set_match: bool,
    pub expected_postcondition_set_match: bool,
    pub risk_class_match: bool,
    pub policy_disposition_match: bool,
    pub clarification_match: bool,
    pub escalation_match: bool,
    pub completion_match: bool,
    pub verified_outcome_effect_match: bool,
    pub status: ShadowComparisonStatusV1,
    pub equivalence_binding_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub comparison_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowAdjudicationV1 {
    pub schema_version: u32,
    pub adjudication_id: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub case_contract_sha256: String,
    pub source_observation_sha256: String,
    pub post_action_observation_sha256: String,
    pub proposal_sha256: String,
    pub counterfactual_policy_assessment_sha256: String,
    pub human_reference_step_sha256: String,
    pub actual_policy_assessment_sha256: String,
    pub verification_result_sha256: String,
    pub case_success_criteria_sha256: String,
    pub ai_proposal_correctness: ShadowCorrectnessV1,
    pub human_step_correctness: ShadowCorrectnessV1,
    pub ai_policy_compliant: bool,
    pub human_policy_compliant: bool,
    pub expected_postcondition_valid: bool,
    pub actual_postcondition_satisfied: bool,
    pub case_progress_effect_id: String,
    pub required_action_present: bool,
    pub unnecessary_ai_action: bool,
    pub unnecessary_human_action: bool,
    pub ai_missed_required_action: bool,
    pub human_missed_required_action: bool,
    pub clarification_correct: bool,
    pub escalation_correct: bool,
    pub completion_correct: bool,
    pub evidence_sufficient: bool,
    pub critical_error_codes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub adjudication_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowSessionEvaluationV1 {
    pub schema_version: u32,
    pub session_sha256: String,
    pub cycle_comparison_hashes: Vec<String>,
    pub adjudication_hashes: Vec<String>,
    pub human_outcome_sha256: String,
    pub ai_terminal_prediction: ShadowDecisionClassV1,
    pub actual_verified_terminal_outcome: bool,
    pub ai_action_count: u32,
    pub human_action_count: u32,
    pub unnecessary_ai_action_count: u32,
    pub unnecessary_human_action_count: u32,
    pub ai_missed_action_count: u32,
    pub human_missed_action_count: u32,
    pub clarification_correct: bool,
    pub escalation_correct: bool,
    pub completion_correct: bool,
    pub policy_compliant: bool,
    pub critical_error_codes: Vec<String>,
    pub metric_contribution_hashes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub evaluation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvidenceCoverageV1 {
    pub schema_version: u32,
    pub cohort_sha256: String,
    pub expected_case_count: u32,
    pub enrolled_case_count: u32,
    pub model_inference_case_count: u32,
    pub interactive_case_count: u32,
    pub instrumented_case_count: u32,
    pub completed_session_count: u32,
    pub adjudicated_session_count: u32,
    pub complete_evidence_count: u32,
    pub missing_evidence_count: u32,
    pub conflicting_evidence_count: u32,
    pub excluded_case_count: u32,
    pub exclusion_reason_codes: Vec<String>,
    pub coverage_millionths: u32,
    pub status: ShadowEvidenceCoverageStatusV1,
    pub evidence_ids: Vec<String>,
    pub coverage_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowMetricResultV1 {
    pub schema_version: u32,
    pub metric_id: String,
    pub numerator: u64,
    pub denominator: u64,
    pub value_millionths: Option<u32>,
    pub count_value: Option<u64>,
    pub status: ShadowMetricStatusV1,
    pub threshold_millionths: Option<u32>,
    pub threshold_count: Option<u64>,
    pub evidence_ids: Vec<String>,
    pub metric_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleShadowEvaluationSnapshotV1 {
    pub schema_version: u32,
    pub snapshot_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub cohort_sha256: String,
    pub readiness_policy_sha256: String,
    pub provider_descriptor_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub total_sessions: u32,
    pub completed_sessions: u32,
    pub invalid_sessions: u32,
    pub interactive_sessions: u32,
    pub instrumented_sessions: u32,
    pub model_backed_cases: u32,
    pub windows_sessions: u32,
    pub exact_matches: u32,
    pub semantic_equivalents: u32,
    pub safe_alternatives: u32,
    pub ai_correct_human_incorrect: u32,
    pub human_correct_ai_incorrect: u32,
    pub both_incorrect: u32,
    pub ai_unnecessary_actions: u32,
    pub ai_missed_actions: u32,
    pub false_completions: u32,
    pub mandatory_escalation_cases: u32,
    pub mandatory_escalation_misses: u32,
    pub forbidden_capability_count: u32,
    pub authority_expansion_count: u32,
    pub direct_execution_attempt_count: u32,
    pub secret_leakage_count: u32,
    pub unblinded_cycle_count: u32,
    pub metric_result_hashes: Vec<String>,
    pub coverage_sha256: String,
    pub critical_error_count: u32,
    pub shadow_store_head_sha256: String,
    pub protected_audit_head_sha256: String,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReadinessAssessmentV1 {
    pub schema_version: u32,
    pub assessment_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub cohort_sha256: String,
    pub readiness_policy_sha256: String,
    pub shadow_snapshot_sha256: String,
    pub evaluated_metric_hashes: Vec<String>,
    pub passed_threshold_ids: Vec<String>,
    pub failed_threshold_ids: Vec<String>,
    pub critical_blocker_codes: Vec<String>,
    pub status: ShadowReadinessStatusV1,
    pub assessed_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub assessment_sha256: String,
    pub signing_key_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvaluationReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub cohort_sha256: String,
    pub readiness_policy_sha256: String,
    pub evaluation_snapshot_sha256: String,
    pub coverage_sha256: String,
    pub metric_result_hashes: Vec<String>,
    pub readiness_assessment_sha256: String,
    pub critical_error_codes: Vec<String>,
    pub divergence_candidate_hashes: Vec<String>,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub retention_class_id: String,
    pub reporting_obligation_id: String,
    pub report_class_id: String,
    pub routing_class_id: String,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowEvaluationExportBundleV1 {
    pub schema_version: u32,
    pub bundle_id: String,
    pub profile_approval_hashes: Vec<String>,
    pub cohort_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub enrollment_hashes: Vec<String>,
    pub session_hashes: Vec<String>,
    pub proposal_commitment_hashes: Vec<String>,
    pub human_attestation_hashes: Vec<String>,
    pub comparison_hashes: Vec<String>,
    pub adjudication_hashes: Vec<String>,
    pub metric_hashes: Vec<String>,
    pub readiness_assessment_sha256: String,
    pub report_publication_hashes: Vec<String>,
    pub protected_audit_terminal_sha256: String,
    pub schema_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowReplayReportV1 {
    pub schema_version: u32,
    pub replay_id: String,
    pub session_count: u32,
    pub repetitions: u32,
    pub completed_sessions: u32,
    pub invalid_sessions: u32,
    pub interactive_sessions: u32,
    pub instrumented_sessions: u32,
    pub exact_matches: u32,
    pub semantic_equivalents: u32,
    pub safe_alternatives: u32,
    pub ai_correct_human_incorrect: u32,
    pub human_correct_ai_incorrect: u32,
    pub both_incorrect: u32,
    pub ai_unnecessary_actions: u32,
    pub ai_missed_actions: u32,
    pub false_completions: u32,
    pub mandatory_escalation_misses: u32,
    pub unblinded_cycles: u32,
    pub direct_execution_attempts: u32,
    pub critical_errors: u32,
    pub cohort_sha256: String,
    pub session_set_sha256: String,
    pub comparison_set_sha256: String,
    pub adjudication_set_sha256: String,
    pub metric_set_sha256: String,
    pub readiness_sha256: String,
    pub normalized_report_sha256: String,
    pub logical_operations: u64,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCycleRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub profile_sha256: String,
    pub cohort_sha256: String,
    pub enrollment_sha256: String,
    pub session_sha256: String,
    pub cycle_index: u32,
    pub fresh_observation_id: String,
    pub fresh_observation_sha256: String,
    pub fresh_observation_sequence: u64,
    pub case_context_sha256: String,
    pub policy_set_sha256: String,
    pub deadline_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCycleResultV1 {
    pub schema_version: u32,
    pub request_sha256: String,
    pub session_sha256: String,
    pub cycle_sha256: String,
    pub proposal_sha256: String,
    pub commitment_sha256: String,
    pub human_reference_step_sha256: String,
    pub comparison_sha256: String,
    pub adjudication_sha256: String,
    pub status: ShadowCycleStatusV1,
    pub execution_attempt_count: u32,
    pub activation_artifact_count: u32,
    pub case_mutation_count: u32,
    pub adapter_mutation_count: u32,
    pub evidence_ids: Vec<String>,
    pub result_sha256: String,
}
