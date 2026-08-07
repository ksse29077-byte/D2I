use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyReadinessStatusV1 {
    EligibleForWork900Design,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyRoleStatusV1 {
    Disabled,
    Eligible,
    Enabled,
    Paused,
    Draining,
    Suspended,
    Revoked,
    Expired,
    HealthTripped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyControlOperationV1 {
    Enable,
    Pause,
    Resume,
    Drain,
    Disable,
    Revoke,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyCaseEligibilityStatusV1 {
    Eligible,
    HumanConfirmationRequired,
    HumanExceptionRequired,
    NotEligible,
    AutonomyPaused,
    OutOfScope,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyRiskClassV1 {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    HighCriticality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyHealthStatusV1 {
    Healthy,
    Warning,
    PauseRequired,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanExceptionSeverityV1 {
    Clarification,
    Confirmation,
    MandatoryEscalation,
    TerminalEscalation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanExceptionResponseClassV1 {
    ProvideBoundedFact,
    ExistingConfirmation,
    Decline,
    ExternalHandling,
    CreateFollowupWork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DutyCycleTerminalStatusV1 {
    Idle,
    BoundedLimitReached,
    Paused,
    HealthTripped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyReadinessBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub organization_id: String,
    pub target_role_contract_id: String,
    pub target_role_contract_version: String,
    pub shadow_role_sha256: String,
    pub shadow_profile_sha256: String,
    pub shadow_cohort_sha256: String,
    pub shadow_readiness_policy_sha256: String,
    pub shadow_readiness_assessment_sha256: String,
    pub readiness_status: AutonomyReadinessStatusV1,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub provider_descriptor_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub application_pack_hashes: Vec<String>,
    pub policy_set_sha256: String,
    pub trusted_execution_compatibility_sha256: String,
    pub evidence_coverage_sha256: String,
    pub critical_error_count: u32,
    pub false_completion_count: u32,
    pub escalation_miss_count: u32,
    pub forbidden_capability_count: u32,
    pub authority_expansion_count: u32,
    pub assessed_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyHealthThresholdsV1 {
    pub maximum_verification_failures: u32,
    pub maximum_recovery_failures: u32,
    pub maximum_provider_failures: u32,
    pub maximum_sla_breaches: u32,
    pub maximum_residual_failures: u32,
    pub maximum_false_completions: u32,
    pub maximum_authority_expansions: u32,
    pub maximum_wrong_target_attempts: u32,
    pub maximum_escalation_misses: u32,
    pub maximum_secret_leakage: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedAutonomyProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub profile_version: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_version: String,
    pub role_contract_sha256: String,
    pub delegation_constraint_hashes: Vec<String>,
    pub policy_set_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub provider_descriptor_sha256: String,
    pub prompt_template_hashes: Vec<String>,
    pub application_pack_hashes: Vec<String>,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_responsibility_ids: Vec<String>,
    pub allowed_source_ids: Vec<String>,
    pub allowed_source_class_ids: Vec<String>,
    pub allowed_environment_ids: Vec<String>,
    pub autonomous_capability_ids: Vec<String>,
    pub confirmation_capability_ids: Vec<String>,
    pub prohibited_capability_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub maximum_autonomous_risk: AutonomyRiskClassV1,
    pub mandatory_human_exception_reason_codes: Vec<String>,
    pub automatic_recovery_class_ids: Vec<String>,
    pub maximum_cases_per_duty_cycle: u32,
    pub maximum_concurrent_cases: u32,
    pub maximum_actions_per_case: u32,
    pub maximum_model_invocations_per_case: u32,
    pub maximum_recovery_cycles: u32,
    pub maximum_reobservations_per_case: u32,
    pub maximum_total_autonomous_side_effects: u32,
    pub maximum_cycle_duration_ms: u64,
    pub maximum_case_duration_ms: u64,
    pub maximum_exception_pending_count: u32,
    pub maximum_exception_handoffs_per_cycle: u32,
    pub maximum_active_leases: u32,
    pub maximum_control_commands_per_cycle: u32,
    pub maximum_health_records_per_cycle: u32,
    pub maximum_store_objects: u32,
    pub maximum_store_bytes: u64,
    pub maximum_audit_records_per_cycle: u32,
    pub maximum_evidence_references: u32,
    pub maximum_report_bytes: u64,
    pub maximum_resume_checkpoints: u32,
    pub maximum_consecutive_failures: u32,
    pub maximum_verification_failures: u32,
    pub health_thresholds: AutonomyHealthThresholdsV1,
    pub rollout_maximum_cases: u32,
    pub rollout_maximum_side_effects: u32,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyDeploymentApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub target_role_sha256: String,
    pub autonomy_profile_sha256: String,
    pub readiness_binding_sha256: String,
    pub approved_environment_ids: Vec<String>,
    pub approved_work_class_ids: Vec<String>,
    pub approved_capability_ids: Vec<String>,
    pub approved_semantic_target_ids: Vec<String>,
    pub approved_maximum_risk: AutonomyRiskClassV1,
    pub rollout_maximum_cases: u32,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRoleRuntimeStateV1 {
    pub schema_version: u32,
    pub state_id: String,
    pub role_instance_sha256: String,
    pub autonomy_profile_sha256: String,
    pub deployment_approval_sha256: String,
    pub readiness_binding_sha256: String,
    pub status: AutonomyRoleStatusV1,
    pub enabled_at_unix_ms: Option<u64>,
    pub paused_at_unix_ms: Option<u64>,
    pub state_generation: u64,
    pub processed_case_count: u32,
    pub active_case_count: u32,
    pub successful_autonomous_case_count: u32,
    pub exception_count: u32,
    pub failure_count: u32,
    pub current_health_snapshot_sha256: String,
    pub current_control_command_sha256: String,
    pub previous_state_sha256: String,
    pub evidence_ids: Vec<String>,
    pub state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyControlCommandV1 {
    pub schema_version: u32,
    pub command_id: String,
    pub organization_id: String,
    pub role_instance_sha256: String,
    pub autonomy_profile_sha256: String,
    pub operation: AutonomyControlOperationV1,
    pub state_generation: u64,
    pub signer_id: String,
    pub signer_scope_id: String,
    pub signing_key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub command_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyCaseEligibilityV1 {
    pub schema_version: u32,
    pub eligibility_id: String,
    pub role_instance_sha256: String,
    pub autonomy_state_sha256: String,
    pub deployment_approval_sha256: String,
    pub autonomy_profile_sha256: String,
    pub readiness_binding_sha256: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub current_ownership_sha256: String,
    pub queue_entry_sha256: String,
    pub active_lease_sha256: String,
    pub work_item_sha256: String,
    pub source_approval_sha256: String,
    pub work_class_id: String,
    pub requested_capability_ids: Vec<String>,
    pub requested_semantic_target_ids: Vec<String>,
    pub risk_class: AutonomyRiskClassV1,
    pub policy_set_sha256: String,
    pub health_snapshot_sha256: String,
    pub evaluated_at_unix_ms: u64,
    pub status: AutonomyCaseEligibilityStatusV1,
    pub reason_codes: Vec<String>,
    pub eligibility_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyCaseAdmissionV1 {
    pub schema_version: u32,
    pub admission_id: String,
    pub role_instance_sha256: String,
    pub autonomy_state_sha256: String,
    pub deployment_approval_sha256: String,
    pub autonomy_profile_sha256: String,
    pub readiness_binding_sha256: String,
    pub case_contract_sha256: String,
    pub current_case_instance_sha256: String,
    pub current_ownership_sha256: String,
    pub active_lease_sha256: String,
    pub work_grant_sha256: String,
    pub case_eligibility_sha256: String,
    pub allowed_autonomous_capability_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub maximum_risk: AutonomyRiskClassV1,
    pub action_budget: u32,
    pub model_invocation_budget: u32,
    pub recovery_budget: u32,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub admission_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousCaseTaskBindingV1 {
    pub schema_version: u32,
    pub autonomy_case_admission_sha256: String,
    pub case_task_request_sha256: String,
    pub role_task_admission_sha256: String,
    pub current_case_instance_sha256: String,
    pub active_lease_sha256: String,
    pub work_grant_sha256: String,
    pub goal_spec_sha256: String,
    pub situation_model_sha256: String,
    pub planner_cycle_sha256: String,
    pub next_step_decision_sha256: String,
    pub policy_input_binding_sha256: String,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRolloutCohortV1 {
    pub schema_version: u32,
    pub cohort_id: String,
    pub target_role_sha256: String,
    pub autonomy_profile_sha256: String,
    pub deployment_approval_sha256: String,
    pub allowed_work_class_ids: Vec<String>,
    pub allowed_source_class_ids: Vec<String>,
    pub maximum_cases: u32,
    pub maximum_total_side_effects: u32,
    pub starts_at_unix_ms: u64,
    pub ends_at_unix_ms: u64,
    pub health_threshold_sha256: String,
    pub evidence_ids: Vec<String>,
    pub cohort_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyHealthSnapshotV1 {
    pub schema_version: u32,
    pub window_id: String,
    pub role_instance_sha256: String,
    pub autonomy_state_sha256: String,
    pub total_autonomous_cases: u32,
    pub verified_closure_cases: u32,
    pub exception_cases: u32,
    pub failed_cases: u32,
    pub false_completions: u32,
    pub unsafe_side_effects: u32,
    pub verification_failures: u32,
    pub recovery_failures: u32,
    pub policy_denials: u32,
    pub policy_bypasses: u32,
    pub activation_bypasses: u32,
    pub forbidden_proposals: u32,
    pub forbidden_executed_capabilities: u32,
    pub authority_expansions: u32,
    pub wrong_target_attempts: u32,
    pub duplicate_attempts: u32,
    pub escalation_misses: u32,
    pub secret_leakage: u32,
    pub residual_failures: u32,
    pub average_actions_per_case_millionths: u32,
    pub provider_failures: u32,
    pub sla_breaches: u32,
    pub threshold_state_ids: Vec<String>,
    pub critical_error_count: u32,
    pub health_status: AutonomyHealthStatusV1,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyHealthTripV1 {
    pub schema_version: u32,
    pub trip_id: String,
    pub role_instance_sha256: String,
    pub autonomy_state_sha256: String,
    pub health_snapshot_sha256: String,
    pub reason_codes: Vec<String>,
    pub stop_new_case_claims: bool,
    pub stop_new_actions: bool,
    pub work700_escalation_item_sha256: String,
    pub tripped_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub trip_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanExceptionHandoffV1 {
    pub schema_version: u32,
    pub handoff_id: String,
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub role_instance_sha256: String,
    pub case_id: String,
    pub case_sha256: String,
    pub autonomy_case_admission_sha256: String,
    pub source_failure_sha256: String,
    pub reason_codes: Vec<String>,
    pub severity: HumanExceptionSeverityV1,
    pub situation_model_sha256: String,
    pub current_observation_sha256: String,
    pub case_progress_class_id: String,
    pub applied_action_hashes: Vec<String>,
    pub unresolved_requirement_ids: Vec<String>,
    pub required_human_response_class_id: String,
    pub work700_escalation_item_sha256: String,
    pub internal_route_id: String,
    pub created_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub handoff_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanExceptionResponseV1 {
    pub schema_version: u32,
    pub response_id: String,
    pub handoff_sha256: String,
    pub response_class: HumanExceptionResponseClassV1,
    pub actor_class_id: String,
    pub approved_bounded_fact_sha256: Option<String>,
    pub confirmation_artifact_sha256: Option<String>,
    pub resolution_reference_sha256: Option<String>,
    pub responded_at_unix_ms: u64,
    pub valid_until_unix_ms: u64,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub response_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRoleDutyCycleRequestV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub organization_id: String,
    pub role_instance_sha256: String,
    pub autonomy_state_sha256: String,
    pub profile_sha256: String,
    pub deployment_approval_sha256: String,
    pub readiness_binding_sha256: String,
    pub trusted_time_context_sha256: String,
    pub work_radar_source_heads: Vec<String>,
    pub intake_head_sha256: String,
    pub case_ledger_head_sha256: String,
    pub queue_head_sha256: String,
    pub ownership_head_sha256: String,
    pub planner_head_hashes: Vec<String>,
    pub memory_head_sha256: String,
    pub operations_head_sha256: String,
    pub audit_head_sha256: String,
    pub maximum_cases: u32,
    pub maximum_actions: u32,
    pub maximum_provider_invocations: u32,
    pub deadline_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomousRoleDutyCycleResultV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub discovered_work: u32,
    pub admitted_work_items: u32,
    pub cases_created: u32,
    pub cases_scheduled: u32,
    pub cases_claimed: u32,
    pub autonomous_cases_started: u32,
    pub autonomous_cases_verified_complete: u32,
    pub clarification_handoffs: u32,
    pub mandatory_escalation_handoffs: u32,
    pub refusals: u32,
    pub paused_cases: u32,
    pub failures: u32,
    pub autonomous_actions: u32,
    pub provider_invocations: u32,
    pub recoveries: u32,
    pub human_touches: u32,
    pub episodes: u32,
    pub reports: u32,
    pub health_status: AutonomyHealthStatusV1,
    pub terminal_status: DutyCycleTerminalStatusV1,
    pub residual_process_count: u32,
    pub residual_profile_count: u32,
    pub residual_lock_count: u32,
    pub output_hashes: Vec<String>,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedAutonomyCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub role_contract_sha256: String,
    pub profile_sha256: String,
    pub deployment_approval_sha256: String,
    pub readiness_binding_sha256: String,
    pub total_canary_cases: u32,
    pub routine_cases: u32,
    pub routine_verified_closure: u32,
    pub routine_human_touches: u32,
    pub human_exception_cases: u32,
    pub mandatory_exception_handoff_recall_millionths: u32,
    pub actual_model_backed_cases: u32,
    pub actual_krn_side_effect_actions: u32,
    pub observations: u32,
    pub actions: u32,
    pub provider_invocations: u32,
    pub false_completions: u32,
    pub wrong_targets: u32,
    pub wrong_actions: u32,
    pub duplicate_actions: u32,
    pub duplicate_claims: u32,
    pub authority_expansions: u32,
    pub forbidden_capabilities: u32,
    pub mandatory_escalation_misses: u32,
    pub secret_leakage: u32,
    pub network_accesses: u32,
    pub critical_errors: u32,
    pub autonomous_case_completion_rate_millionths: u32,
    pub human_touches_per_case_millionths: u32,
    pub routine_human_touches_per_case_millionths: u32,
    pub exception_rate_millionths: u32,
    pub verified_closure_rate_millionths: u32,
    pub false_completion_rate_millionths: u32,
    pub sla_compliance_millionths: u32,
    pub human_supervisor_count: u32,
    pub cases_per_human_supervisor_millionths: u32,
    pub autonomy_evidence: bool,
    pub human_by_exception_evidence: bool,
    pub track_w_completion_evidence: bool,
    pub completed_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedAutonomyReplayReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub input_count: u32,
    pub iterations_per_input: u32,
    pub mismatch_count: u32,
    pub duplicate_consumption_count: u32,
    pub input_set_sha256: String,
    pub output_set_sha256: String,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitedAutonomyCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub git_head_sha256: String,
    pub completion_report_sha256: String,
    pub replay_report_sha256: String,
    pub audit_terminal_sha256: String,
    pub security_scan_sha256: String,
    pub predecessor_evidence_sha256: String,
    pub autonomy_evidence: bool,
    pub human_by_exception_evidence: bool,
    pub track_w_completion_evidence: bool,
    pub issued_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub certification_sha256: String,
}
