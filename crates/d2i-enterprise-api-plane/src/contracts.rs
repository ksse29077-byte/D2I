use serde::{Deserialize, Serialize};

/// Deployment class controlling production HTTPS versus signed loopback test transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseEnvironmentClassV1 {
    Production,
    SignedTest,
}

/// Closed HTTP methods available to signed operation descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseHttpMethodV1 {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// Separates read-only observations from business-state mutations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseOperationClassV1 {
    Observation,
    Mutation,
}

/// Side-effect class attached to one closed enterprise operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseSideEffectClassV1 {
    ReadOnly,
    ReversibleBusinessStateChange,
}

/// Idempotency requirement for one enterprise operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseIdempotencyClassV1 {
    NotApplicable,
    ClientKeyRequired,
}

/// Transport class approved for one connector deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseTransportPolicyV1 {
    HttpsOnly,
    SignedLoopbackHttpOnly,
}

/// Independent post-action verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseVerificationStatusV1 {
    Verified,
    Rejected,
    HumanExceptionRequired,
}

/// Closed worker result used by bounded recovery classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseOperationResultV1 {
    Succeeded,
    AlreadySatisfied,
    StaleConflict,
    RateLimited,
    Unauthorized,
    MalformedResponse,
    UnknownWriteOutcome,
    Rejected,
}

/// Current health state of an approved connector binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseConnectorHealthStatusV1 {
    Healthy,
    Degraded,
    Unavailable,
}

/// Fail-closed recovery disposition for one worker result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnterpriseRecoveryDispositionV1 {
    None,
    FreshObservationAndReplan,
    BoundedRetry,
    VerifyUnknownOutcome,
    HumanException,
}

/// Finite byte, depth, item, page, and duration limits for one connector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseResourceLimitsV1 {
    pub maximum_request_bytes: u32,
    pub maximum_response_bytes: u32,
    pub maximum_response_depth: u32,
    pub maximum_response_items: u32,
    pub maximum_pages: u32,
    pub maximum_duration_ms: u64,
}

/// TLS verification and optional organization pinning policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseTlsPolicyV1 {
    pub verify_os_trust_chain: bool,
    pub verify_hostname: bool,
    pub verify_expiry: bool,
    pub reject_weak_protocols: bool,
    pub pin_class: String,
    pub pin_sha256: Option<String>,
}

/// Model-neutral description of one bounded execution plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPlaneDescriptorV1 {
    pub schema_version: u32,
    pub execution_plane_id: String,
    pub descriptor_version: String,
    pub adapter_class_id: String,
    pub supported_capability_ids: Vec<String>,
    pub supported_observation_class_ids: Vec<String>,
    pub supported_action_class_ids: Vec<String>,
    pub verification_class_ids: Vec<String>,
    pub security_profile_id: String,
    pub resource_limits: EnterpriseResourceLimitsV1,
    pub adapter_artifact_sha256: String,
    pub evidence_ids: Vec<String>,
    pub descriptor_sha256: String,
}

/// Signed-pack operation definition from semantic intent to fixed transport behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseOperationDescriptorV1 {
    pub schema_version: u32,
    pub operation_id: String,
    pub capability_id: String,
    pub semantic_target_id: String,
    pub resource_class_id: String,
    pub operation_class: EnterpriseOperationClassV1,
    pub http_method: EnterpriseHttpMethodV1,
    pub fixed_path_template: String,
    pub allowed_path_parameter_ids: Vec<String>,
    pub allowed_query_parameter_ids: Vec<String>,
    pub request_schema_sha256: String,
    pub response_schema_sha256: String,
    pub success_status_codes: Vec<u32>,
    pub side_effect_class: EnterpriseSideEffectClassV1,
    pub idempotency_class: EnterpriseIdempotencyClassV1,
    pub optimistic_concurrency_required: bool,
    pub resource_version_field_id: String,
    pub verification_operation_id: String,
    pub retry_policy_id: String,
    pub rate_budget_class_id: String,
    pub maximum_request_bytes: u32,
    pub maximum_response_bytes: u32,
    pub data_class_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub descriptor_sha256: String,
}

/// Signed immutable connector package containing the complete allowed operation surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseConnectorPackV1 {
    pub schema_version: u32,
    pub connector_pack_id: String,
    pub connector_pack_version: String,
    pub display_name: String,
    pub system_family_id: String,
    pub organization_scope_id: String,
    pub environment_ids: Vec<String>,
    pub base_origin: String,
    pub transport_profile_id: String,
    pub credential_profile_id: String,
    pub credential_reference_class_id: String,
    pub operation_descriptors: Vec<EnterpriseOperationDescriptorV1>,
    pub allowed_observation_operation_ids: Vec<String>,
    pub allowed_mutation_operation_ids: Vec<String>,
    pub request_schema_sha256s: Vec<String>,
    pub response_schema_sha256s: Vec<String>,
    pub resource_class_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub capability_ids: Vec<String>,
    pub rate_limit_per_minute: u32,
    pub retry_limit: u32,
    pub resource_limits: EnterpriseResourceLimitsV1,
    pub redaction_policy_id: String,
    pub tls_policy: EnterpriseTlsPolicyV1,
    pub redirect_policy_id: String,
    pub proxy_policy_id: String,
    pub idempotency_policy_id: String,
    pub concurrency_policy_id: String,
    pub verification_policy_id: String,
    pub signer_key_id: String,
    pub evidence_ids: Vec<String>,
    pub pack_sha256: String,
    pub signature_hex: String,
}

/// Organization approval that narrows one signed connector pack deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseConnectorApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub connector_pack_sha256: String,
    pub approved_environment_id: String,
    pub approved_role_ids: Vec<String>,
    pub approved_operation_ids: Vec<String>,
    pub approved_capability_ids: Vec<String>,
    pub approved_origins: Vec<String>,
    pub approved_ports: Vec<u32>,
    pub transport_policy: EnterpriseTransportPolicyV1,
    pub credential_profile_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub nonce: String,
    pub evidence_ids: Vec<String>,
    pub approval_sha256: String,
    pub signature_hex: String,
}

/// Runtime binding to one exact endpoint, worker, credential reference, and policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseEndpointBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub connector_pack_sha256: String,
    pub connector_approval_sha256: String,
    pub exact_origin: String,
    pub scheme: String,
    pub hostname: String,
    pub port: u32,
    pub environment_id: String,
    pub environment_class: EnterpriseEnvironmentClassV1,
    pub resolved_endpoint_identity: String,
    pub tls_profile_sha256: String,
    pub network_policy_sha256: String,
    pub credential_reference_id: String,
    pub worker_executable_sha256: String,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub binding_sha256: String,
}

/// Opaque non-secret reference to worker-only credential material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseCredentialReferenceV1 {
    pub schema_version: u32,
    pub credential_reference_id: String,
    pub organization_id: String,
    pub connector_pack_id: String,
    pub auth_scheme_class_id: String,
    pub allowed_origin: String,
    pub allowed_operation_class_ids: Vec<String>,
    pub secret_present: bool,
    pub secret_source_class_id: String,
    pub expires_at_unix_ms: u64,
    pub generation: u64,
    pub credential_policy_sha256: String,
    pub evidence_ids: Vec<String>,
    pub reference_sha256: String,
}

/// Bounded read-only request for one approved resource observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseObservationRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub connector_binding_sha256: String,
    pub operation_id: String,
    pub resource_reference_id: String,
    pub case_sha256: String,
    pub role_instance_sha256: String,
    pub observation_sequence: u64,
    pub requested_field_class_ids: Vec<String>,
    pub maximum_bytes: u32,
    pub maximum_items: u32,
    pub trusted_time_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

/// Normalized, redacted, fresh snapshot from an approved enterprise operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseObservationSnapshotV1 {
    pub schema_version: u32,
    pub observation_id: String,
    pub sequence: u64,
    pub connector_sha256: String,
    pub operation_sha256: String,
    pub resource_identity: String,
    pub resource_version: String,
    pub normalized_approved_field_ids: Vec<String>,
    pub normalized_approved_values: Vec<String>,
    pub redacted_field_ids: Vec<String>,
    pub data_class_ids: Vec<String>,
    pub response_status_class_id: String,
    pub response_schema_sha256: String,
    pub raw_response_sha256: String,
    pub normalized_state_sha256: String,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub provenance_id: String,
    pub evidence_ids: Vec<String>,
    pub observation_sha256: String,
}

/// Planner-owned semantic proposal without raw transport or credential fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseOperationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub case_sha256: String,
    pub planner_cycle_sha256: String,
    pub connector_pack_id: String,
    pub connector_pack_sha256: String,
    pub operation_id: String,
    pub capability_id: String,
    pub semantic_target_id: String,
    pub resource_reference_id: String,
    pub approved_argument_reference_hashes: Vec<String>,
    pub expected_state_transition_id: String,
    pub expected_postcondition_id: String,
    pub predicted_risk_class_id: String,
    pub evidence_ids: Vec<String>,
    pub intent_sha256: String,
}

/// Exact trusted join of Case, authority, observation, connector, Policy, and activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseOperationBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub case_sha256: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub ownership_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
    pub autonomy_admission_sha256: String,
    pub planner_intent_sha256: String,
    pub current_observation_sha256: String,
    pub resource_version: String,
    pub connector_pack_sha256: String,
    pub connector_approval_sha256: String,
    pub endpoint_binding_sha256: String,
    pub credential_reference_sha256: String,
    pub operation_descriptor_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_activation_admission_sha256: String,
    pub activation_one_time_use_id: String,
    pub approved_argument_artifact_hashes: Vec<String>,
    pub idempotency_key_sha256: String,
    pub timeout_ms: u64,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

/// Bounded transport result that remains non-terminal until fresh verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub operation_binding_sha256: String,
    pub activation_one_time_use_id: String,
    pub request_sha256: String,
    pub response_sha256: Option<String>,
    pub result: EnterpriseOperationResultV1,
    pub http_status: Option<u32>,
    pub bytes_sent: u32,
    pub bytes_received: u32,
    pub server_mutation_sequence: Option<u64>,
    pub idempotency_key_sha256: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub receipt_sha256: String,
}

/// Independent comparison of a fresh remote snapshot to the expected postcondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterprisePostActionVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub case_sha256: String,
    pub operation_receipt_sha256: String,
    pub fresh_observation_sha256: String,
    pub expected_postcondition_id: String,
    pub status: EnterpriseVerificationStatusV1,
    pub compared_field_ids: Vec<String>,
    pub failure_reason_code: Option<String>,
    pub verified_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub verification_sha256: String,
}

/// Exact destination and fail-closed network behavior for one worker executable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseNetworkPolicyV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub worker_executable_sha256: String,
    pub exact_scheme: String,
    pub exact_hostname: String,
    pub exact_port: u32,
    pub exact_origin: String,
    pub allow_loopback_test: bool,
    pub deny_redirects: bool,
    pub deny_ambient_proxy: bool,
    pub deny_other_hosts: bool,
    pub deny_other_ports: bool,
    pub deny_external_network: bool,
    pub valid_from_unix_ms: u64,
    pub valid_to_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub policy_sha256: String,
}

/// Durable logical-mutation record preventing blind or conflicting replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseIdempotencyRecordV1 {
    pub schema_version: u32,
    pub record_id: String,
    pub case_sha256: String,
    pub operation_descriptor_sha256: String,
    pub resource_reference_sha256: String,
    pub idempotency_key_sha256: String,
    pub first_request_sha256: String,
    pub resolved_receipt_sha256: Option<String>,
    pub server_mutation_sequence: Option<u64>,
    pub unknown_outcome: bool,
    pub blind_replay_count: u32,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

/// Bounded connector health projection derived from receipts and observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseConnectorHealthV1 {
    pub schema_version: u32,
    pub health_id: String,
    pub connector_pack_sha256: String,
    pub endpoint_binding_sha256: String,
    pub status: EnterpriseConnectorHealthStatusV1,
    pub successful_observations: u32,
    pub successful_mutations: u32,
    pub consecutive_failures: u32,
    pub rate_limit_events: u32,
    pub authentication_failures: u32,
    pub malformed_response_count: u32,
    pub measured_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub health_sha256: String,
}

/// Deterministic synthetic replay evidence for operation and recovery decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseReplayReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub synthetic_case_count: u32,
    pub replay_runs: u32,
    pub deterministic_match_count: u32,
    pub deterministic_mismatch_count: u32,
    pub input_set_sha256: String,
    pub first_output_sha256: String,
    pub final_output_sha256: String,
    pub evidence_ids: Vec<String>,
    pub report_sha256: String,
}

/// Terminal EDGE-100 product-gate metrics and cleanup evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseApiCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub complete: bool,
    pub enterprise_api_plane_evidence: bool,
    pub track_x_edge100_evidence: bool,
    pub source_tree_sha256: String,
    pub connector_pack_sha256: String,
    pub connector_approval_sha256: String,
    pub endpoint_binding_sha256: String,
    pub reference_server_sha256: String,
    pub connector_worker_sha256: String,
    pub model_sha256: String,
    pub runtime_sha256: String,
    pub total_cases: u32,
    pub routine_cases: u32,
    pub verified_closures: u32,
    pub human_exceptions: u32,
    pub work_source_observations: u32,
    pub work_signals: u32,
    pub work_items: u32,
    pub persistent_cases: u32,
    pub queue_claims: u32,
    pub actual_model_invocations: u32,
    pub model_elapsed_milliseconds: u64,
    pub routine_human_touches: u32,
    pub actions_after_handoff: u32,
    pub api_requests: u32,
    pub api_reads: u32,
    pub api_writes: u32,
    pub verified_writes: u32,
    pub api_bytes_sent: u64,
    pub api_bytes_received: u64,
    pub api_2xx_responses: u32,
    pub api_4xx_responses: u32,
    pub api_5xx_responses: u32,
    pub api_no_response: u32,
    pub actual_connection_count: u32,
    pub allowed_connection_count: u32,
    pub denied_connection_count: u32,
    pub fresh_observations: u32,
    pub stale_conflicts: u32,
    pub rate_limit_events: u32,
    pub idempotency_resolutions: u32,
    pub unknown_write_outcomes: u32,
    pub blind_write_replays: u32,
    pub timeout_events: u32,
    pub retry_attempts: u32,
    pub duplicate_server_mutations: u32,
    pub network_policy_denials: u32,
    pub ssrf_attempts: u32,
    pub redirect_attempts: u32,
    pub proxy_use: u32,
    pub schema_failures: u32,
    pub wrong_endpoint: u32,
    pub wrong_operation: u32,
    pub wrong_resource: u32,
    pub forbidden_operation: u32,
    pub credential_leak: u32,
    pub external_network: u32,
    pub false_completion: u32,
    pub escalation_miss: u32,
    pub critical_errors: u32,
    pub checkpoint_set_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub residual_process: u32,
    pub residual_credential: u32,
    pub residual_network_policy: u32,
    pub residual_profile: u32,
    pub residual_store: u32,
    pub residual_lock: u32,
    pub evidence_ids: Vec<String>,
    pub finished_sha256: String,
}

/// Signed certification binding Completion to connector and compatibility hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseApiCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub connector_pack_sha256: String,
    pub connector_approval_sha256: String,
    pub endpoint_binding_sha256: String,
    pub replay_report_sha256: String,
    pub policy_admission_compatibility_sha256: String,
    pub trusted_execution_compatibility_sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub evidence_ids: Vec<String>,
    pub certification_sha256: String,
    pub signature_hex: String,
}

/// Deterministic recovery decision produced without model or network authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseRecoveryDecisionV1 {
    pub disposition: EnterpriseRecoveryDispositionV1,
    pub maximum_retry_count: u32,
    pub require_fresh_observation: bool,
    pub reason_code: String,
}
