//! Evidence-grounded Role operations contracts and deterministic evaluation.
//!
//! This platform-neutral crate reads no clock, filesystem, environment,
//! network, model, credential, adapter, or activation state. Reports,
//! acknowledgements, and escalations are non-executable evidence artifacts.

mod contracts;

pub use contracts::*;

use d2i_role_contract::{KpiDirectionV1, RoleContractV1, RoleReportingTriggerV1, RoleSlaProfileV1};
use d2i_work_case::CaseSlaBindingV1;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

pub const ROLE_OPERATIONS_SCHEMA_VERSION: u32 = 1;
pub const MAX_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STRING_BYTES: usize = 512;
pub const MAX_CASES_PER_CYCLE: u32 = 10_000;
pub const MAX_ROLE_INSTANCES: usize = 128;
pub const MAX_SLA_STATES: usize = 10_000;
pub const MAX_MILESTONES_PER_CASE: usize = 8;
pub const MAX_PAUSE_INTERVALS: usize = 64;
pub const MAX_CUMULATIVE_PAUSE_SECONDS: u64 = 31_536_000;
pub const MAX_BREACHES: usize = 40_000;
pub const MAX_METRIC_BINDINGS: usize = 128;
pub const MAX_METRIC_RESULTS: usize = 128;
pub const MAX_MEASUREMENT_WINDOW_SECONDS: u64 = 31_536_000;
pub const MAX_REPORTS_PER_CYCLE: u32 = 10_000;
pub const MAX_REPORT_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_REPORT_EVIDENCE_REFS: usize = 512;
pub const MAX_ROUTING_CLASSES: usize = 128;
pub const MAX_INTERNAL_INBOXES: usize = 128;
pub const MAX_ESCALATIONS: usize = 10_000;
pub const MAX_ACKNOWLEDGEMENTS: usize = 10_000;
pub const MAX_RESOLUTIONS: usize = 10_000;
pub const MAX_RESOLUTION_SECONDS: u64 = 31_536_000;
pub const MAX_LEDGER_RECORDS: usize = 100_000;
pub const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_REPLAY_RECORDS: usize = 100_000;
pub const MAX_LOGICAL_OPERATIONS: u64 = 100_000_000;
pub const MAX_CONCURRENT_COORDINATORS: usize = 1;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub const ROLE_OPERATIONS_PROFILE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-profile-v1.schema.json");
pub const ROLE_OPERATIONS_PROFILE_APPROVAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-profile-approval-v1.schema.json");
pub const TRUSTED_ROLE_OPERATIONS_TIME_CONTEXT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/trusted-role-operations-time-context-v1.schema.json");
pub const ROLE_MEASUREMENT_WINDOW_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-measurement-window-v1.schema.json");
pub const SLA_MILESTONE_MAPPING_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/sla-milestone-mapping-v1.schema.json");
pub const SLA_MILESTONE_EVENT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/sla-milestone-event-v1.schema.json");
pub const SLA_PAUSE_CONDITION_BINDING_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/sla-pause-condition-binding-v1.schema.json");
pub const SLA_PAUSE_INTERVAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/sla-pause-interval-v1.schema.json");
pub const CASE_SLA_RUNTIME_STATE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-sla-runtime-state-v1.schema.json");
pub const SLA_BREACH_RECORD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/sla-breach-record-v1.schema.json");
pub const KPI_METRIC_BINDING_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/kpi-metric-binding-v1.schema.json");
pub const METRIC_EVIDENCE_COVERAGE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/metric-evidence-coverage-v1.schema.json");
pub const ROLE_METRIC_RESULT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-metric-result-v1.schema.json");
pub const HUMAN_INTERACTION_EVENT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/human-interaction-event-v1.schema.json");
pub const FALSE_COMPLETION_REVIEW_RECORD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/false-completion-review-record-v1.schema.json");
pub const ROLE_OPERATIONS_SNAPSHOT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-snapshot-v1.schema.json");
pub const REPORTING_TRIGGER_EVENT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/reporting-trigger-event-v1.schema.json");
pub const REPORT_EVIDENCE_EVALUATION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/report-evidence-evaluation-v1.schema.json");
pub const ROLE_OPERATIONS_REPORT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-report-v1.schema.json");
pub const ROLE_ROUTING_REGISTRY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-routing-registry-v1.schema.json");
pub const ROLE_ROUTING_REGISTRY_APPROVAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-routing-registry-approval-v1.schema.json");
pub const REPORT_PUBLICATION_ENVELOPE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/report-publication-envelope-v1.schema.json");
pub const REPORT_PUBLICATION_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/report-publication-receipt-v1.schema.json");
pub const ROLE_ESCALATION_TRIGGER_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-escalation-trigger-v1.schema.json");
pub const ROLE_ESCALATION_ITEM_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-escalation-item-v1.schema.json");
pub const ESCALATION_ACKNOWLEDGEMENT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/escalation-acknowledgement-v1.schema.json");
pub const ESCALATION_RESOLUTION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/escalation-resolution-v1.schema.json");
pub const ROLE_OPERATIONS_CYCLE_REQUEST_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-cycle-request-v1.schema.json");
pub const ROLE_OPERATIONS_CYCLE_RESULT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-cycle-result-v1.schema.json");
pub const ROLE_OPERATIONS_REPLAY_REPORT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/role-operations-replay-report-v1.schema.json");

/// Validation, integrity, resource, signature, or strict JSON failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleOperationsError {
    Invalid(String),
    Integrity(String),
    ResourceLimit(String),
    Signature(String),
    Json(String),
}

impl Display for RoleOperationsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity: {message}"),
            Self::ResourceLimit(message) => write!(formatter, "resource_limit: {message}"),
            Self::Signature(message) => write!(formatter, "signature: {message}"),
            Self::Json(message) => write!(formatter, "json: {message}"),
        }
    }
}

impl std::error::Error for RoleOperationsError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, RoleOperationsError> {
    Err(RoleOperationsError::Invalid(message.into()))
}
fn integrity<T>(message: impl Into<String>) -> Result<T, RoleOperationsError> {
    Err(RoleOperationsError::Integrity(message.into()))
}
fn resource<T>(message: impl Into<String>) -> Result<T, RoleOperationsError> {
    Err(RoleOperationsError::ResourceLimit(message.into()))
}

/// Parses bounded JSON while rejecting duplicate object keys.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RoleOperationsError> {
    if bytes.len() > MAX_JSON_BYTES {
        return resource("JSON exceeds the operations byte limit");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| RoleOperationsError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| RoleOperationsError::Json(error.to_string()))?;
    serde_json::from_value(strict.0).map_err(|error| RoleOperationsError::Json(error.to_string()))
}

/// Returns canonical key-sorted JSON bytes.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, RoleOperationsError> {
    let value = serde_json::to_value(value)
        .map_err(|error| RoleOperationsError::Json(error.to_string()))?;
    let normalized = normalize_json(value);
    serde_json::to_vec(&normalized).map_err(|error| RoleOperationsError::Json(error.to_string()))
}

/// Returns the lowercase SHA-256 identity of canonical JSON.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, RoleOperationsError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

/// Hashes canonical JSON after removing top-level self-referential fields.
pub fn hash_without<T: Serialize>(
    value: &T,
    fields: &[&str],
) -> Result<String, RoleOperationsError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| RoleOperationsError::Json(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| RoleOperationsError::Invalid("artifact is not an object".to_owned()))?;
    for field in fields {
        object.remove(*field);
    }
    canonical_sha256(&value)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered = Map::new();
            let mut entries = map.into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in entries {
                ordered.insert(key, normalize_json(value));
            }
            Value::Object(ordered)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_json).collect()),
        other => other,
    }
}

fn validate_hash(value: &str, label: &str) -> Result<(), RoleOperationsError> {
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        invalid(format!("{label} is not lowercase SHA-256"))
    }
}

fn validate_id(value: &str, label: &str) -> Result<(), RoleOperationsError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        || value.contains('*')
        || value.contains("..")
    {
        invalid(format!("{label} is empty, unbounded, wildcard, or unsafe"))
    } else {
        Ok(())
    }
}

fn validate_sorted_unique(values: &[String], label: &str) -> Result<(), RoleOperationsError> {
    if values.len() > MAX_REPORT_EVIDENCE_REFS {
        return resource(format!("{label} exceeds its collection limit"));
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} must be sorted and unique"));
    }
    for value in values {
        validate_id(value, label)?;
    }
    Ok(())
}

fn validate_hash_set(values: &[String], label: &str) -> Result<(), RoleOperationsError> {
    if values.len() > MAX_REPORT_EVIDENCE_REFS || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} must be bounded, sorted, and unique"));
    }
    for value in values {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn reject_forbidden<T: Serialize>(value: &T, label: &str) -> Result<(), RoleOperationsError> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "password",
        "credential",
        "api_key",
        "bearer",
        "authorization",
        "private_key",
        "recipient_email",
        "email_address",
        "phone_number",
        "personal_name",
        "raw_ui",
        "raw_instruction",
        "raw_prompt",
        "locator",
        "selector",
        "coordinate",
        "command",
        "chain_of_thought",
        "activation_token",
        "webhook",
    ];
    let json = serde_json::to_value(value)
        .map_err(|error| RoleOperationsError::Json(error.to_string()))?;
    fn scan(value: &Value, path: &str) -> Result<(), RoleOperationsError> {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    let lower = key.to_ascii_lowercase();
                    if FORBIDDEN_KEYS.iter().any(|item| lower.contains(item)) {
                        return invalid(format!("forbidden field in {path}: {key}"));
                    }
                    scan(value, key)?;
                }
            }
            Value::Array(values) => {
                if values.len() > MAX_REPORT_EVIDENCE_REFS {
                    return resource(format!("collection in {path} exceeds limit"));
                }
                for value in values {
                    scan(value, path)?;
                }
            }
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                if text.len() > MAX_STRING_BYTES
                    || text.contains('*')
                    || text.contains('@')
                    || lower.contains("http://")
                    || lower.contains("https://")
                    || lower.contains("bearer ")
                    || lower.contains("api_key=")
                    || lower.contains("password=")
                {
                    return invalid(format!("forbidden or unbounded content in {path}"));
                }
            }
            Value::Number(number) if number.is_f64() => {
                return invalid(format!("floating-point value in {path} is forbidden"));
            }
            _ => {}
        }
        Ok(())
    }
    scan(&json, label)
}

fn validate_hashed<T: Serialize>(
    value: &T,
    declared: &str,
    hash_field: &str,
    extra_omissions: &[&str],
) -> Result<(), RoleOperationsError> {
    validate_hash(declared, hash_field)?;
    reject_forbidden(value, hash_field)?;
    let mut omissions = vec![hash_field];
    omissions.extend_from_slice(extra_omissions);
    if hash_without(value, &omissions)? != declared {
        return integrity(format!("{hash_field} differs from canonical content"));
    }
    Ok(())
}

macro_rules! impl_hashed_artifact {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, RoleOperationsError> {
                self.$field = ZERO_HASH.to_owned();
                self.$field = hash_without(&self, &[stringify!($field)])?;
                self.validate()?;
                Ok(self)
            }

            pub fn validate(&self) -> Result<(), RoleOperationsError> {
                validate_hashed(self, &self.$field, stringify!($field), &[])
            }
        }
    };
}

impl_hashed_artifact!(RoleOperationsProfileV1, profile_sha256);
impl_hashed_artifact!(TrustedRoleOperationsTimeContextV1, context_sha256);
impl_hashed_artifact!(RoleMeasurementWindowV1, window_sha256);
impl_hashed_artifact!(SlaMilestoneMappingV1, mapping_sha256);
impl_hashed_artifact!(SlaMilestoneEventV1, event_sha256);
impl_hashed_artifact!(SlaPauseConditionBindingV1, binding_sha256);
impl_hashed_artifact!(SlaPauseIntervalV1, pause_sha256);
impl_hashed_artifact!(CaseSlaRuntimeStateV1, state_sha256);
impl_hashed_artifact!(SlaBreachRecordV1, breach_sha256);
impl_hashed_artifact!(KpiMetricBindingV1, binding_sha256);
impl_hashed_artifact!(MetricEvidenceCoverageV1, coverage_sha256);
impl_hashed_artifact!(FalseCompletionReviewRecordV1, record_sha256);
impl_hashed_artifact!(HumanInteractionEventV1, interaction_sha256);
impl_hashed_artifact!(RoleMetricResultV1, result_sha256);
impl_hashed_artifact!(RoleOperationsSnapshotV1, snapshot_sha256);
impl_hashed_artifact!(ReportingTriggerEventV1, trigger_sha256);
impl_hashed_artifact!(ReportEvidenceEvaluationV1, evaluation_sha256);
impl_hashed_artifact!(RoleOperationsReportV1, report_sha256);
impl_hashed_artifact!(RoleRoutingRegistryV1, registry_sha256);
impl_hashed_artifact!(ReportPublicationEnvelopeV1, publication_sha256);
impl_hashed_artifact!(ReportPublicationReceiptV1, receipt_sha256);
impl_hashed_artifact!(RoleEscalationTriggerV1, trigger_sha256);
impl_hashed_artifact!(RoleEscalationItemV1, item_sha256);
impl_hashed_artifact!(RoleOperationsCycleRequestV1, request_sha256);
impl_hashed_artifact!(RoleOperationsCycleResultV1, cycle_sha256);
impl_hashed_artifact!(RoleOperationsReplayReportV1, normalized_replay_sha256);

/// Validates that a profile only narrows declarations in an immutable Role Contract.
pub fn validate_profile_against_role(
    profile: &RoleOperationsProfileV1,
    contract: &RoleContractV1,
    expected_delegation_sha256: &str,
) -> Result<(), RoleOperationsError> {
    profile.validate()?;
    contract
        .validate()
        .map_err(|error| RoleOperationsError::Integrity(error.to_string()))?;
    if profile.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || profile.organization_id != contract.organization_scope.organization_id
        || profile.role_contract_id != contract.role_contract_id
        || profile.role_contract_version != contract.role_version
        || profile.role_contract_sha256 != contract.contract_sha256
        || profile.policy_set_sha256 != contract.policy_set_sha256
        || profile.working_calendar_sha256 != contract.working_calendar.calendar_sha256
        || profile.delegation_sha256 != expected_delegation_sha256
    {
        return integrity("operations profile differs from Role/organization/delegation binding");
    }
    validate_hash(expected_delegation_sha256, "delegation SHA-256")?;
    validate_sorted_unique(&profile.role_instance_scope, "Role Instance scope")?;
    validate_sorted_unique(
        &profile.report_frequency_profile_ids,
        "report frequency profiles",
    )?;
    validate_sorted_unique(&profile.routing_class_allowlist, "routing class allowlist")?;
    if profile.maximum_cases_per_cycle == 0
        || profile.maximum_cases_per_cycle > MAX_CASES_PER_CYCLE
        || profile.maximum_reports_per_cycle == 0
        || profile.maximum_reports_per_cycle > MAX_REPORTS_PER_CYCLE
        || profile.maximum_escalations_per_cycle == 0
        || profile.maximum_escalations_per_cycle as usize > MAX_ESCALATIONS
        || profile.maximum_report_bytes == 0
        || profile.maximum_report_bytes > MAX_REPORT_BYTES
        || profile.maximum_store_bytes == 0
        || profile.maximum_store_bytes > MAX_STORE_BYTES
        || profile.maximum_pending_escalation_seconds == 0
        || profile.maximum_pending_escalation_seconds
            > contract.escalation_policy.maximum_pending_seconds
        || profile.maximum_resolution_seconds == 0
        || profile.maximum_resolution_seconds > MAX_RESOLUTION_SECONDS
        || profile.logical_operation_budget == 0
        || profile.logical_operation_budget > MAX_LOGICAL_OPERATIONS
        || profile.warning_remaining_millionths > 1_000_000
    {
        return resource("operations profile bounds are zero, excessive, or expand the Role");
    }
    if profile.kpi_metric_bindings.len() > MAX_METRIC_BINDINGS
        || profile.measurement_window_profiles.len() > MAX_METRIC_BINDINGS
        || profile.sla_pause_condition_bindings.len() > MAX_PAUSE_INTERVALS
        || profile.internal_route_bindings.len() > MAX_INTERNAL_INBOXES
    {
        return resource("operations profile collection exceeds a fixed bound");
    }
    profile.sla_milestone_mapping.validate()?;
    validate_milestone_mapping(&profile.sla_milestone_mapping)?;

    let enabled_kpis = contract
        .kpi_definitions
        .iter()
        .filter(|definition| definition.enabled)
        .map(|definition| (definition.kpi_id.as_str(), definition))
        .collect::<BTreeMap<_, _>>();
    if enabled_kpis.len() != profile.kpi_metric_bindings.len() {
        return integrity("every enabled Role KPI must have exactly one metric binding");
    }
    let mut seen_kpis = BTreeSet::new();
    for binding in &profile.kpi_metric_bindings {
        binding.validate()?;
        let definition = enabled_kpis
            .get(binding.kpi_id.as_str())
            .copied()
            .ok_or_else(|| {
                RoleOperationsError::Integrity("profile adds an undeclared KPI".to_owned())
            })?;
        if !seen_kpis.insert(&binding.kpi_id)
            || binding.metric_id != definition.metric_id
            || binding.direction != definition.direction
            || binding.target_millionths != definition.target_millionths
            || binding.target_integer != definition.target_integer
            || binding.warning_threshold != definition.warning_threshold
            || binding.breach_behavior != definition.breach_behavior
            || binding.required_evidence_class_ids != definition.evidence_class_ids
        {
            return integrity("metric binding changes or duplicates a Role KPI declaration");
        }
    }

    let declared_pause_ids = contract
        .sla_profiles
        .iter()
        .flat_map(|sla| sla.pause_conditions.iter())
        .collect::<BTreeSet<_>>();
    let mut bound_pause_ids = BTreeSet::new();
    for binding in &profile.sla_pause_condition_bindings {
        binding.validate()?;
        if !declared_pause_ids.contains(&binding.pause_condition_id)
            || !bound_pause_ids.insert(&binding.pause_condition_id)
            || binding.maximum_single_pause_seconds == 0
            || binding.maximum_single_pause_seconds > binding.maximum_cumulative_pause_seconds
            || binding.maximum_cumulative_pause_seconds > MAX_CUMULATIVE_PAUSE_SECONDS
        {
            return integrity("pause binding is undeclared, duplicated, or unbounded");
        }
    }
    if declared_pause_ids != bound_pause_ids {
        return integrity("every declared Role SLA pause condition must be explicitly bound");
    }

    let declared_routes = contract
        .reporting_obligations
        .iter()
        .filter(|obligation| obligation.enabled)
        .map(|obligation| obligation.routing_class_id.as_str())
        .chain(
            contract
                .escalation_policy
                .routing_class_by_severity
                .values()
                .map(String::as_str),
        )
        .chain([
            contract
                .escalation_policy
                .authority_exceeded_route_class
                .as_str(),
            contract.escalation_policy.unsafe_route_class.as_str(),
            contract.escalation_policy.legal_review_route_class.as_str(),
            contract
                .escalation_policy
                .policy_conflict_route_class
                .as_str(),
        ])
        .collect::<BTreeSet<_>>();
    for route in declared_routes {
        if !profile
            .routing_class_allowlist
            .iter()
            .any(|allowed| allowed == route)
        {
            return integrity("profile omits a routing class required by the Role");
        }
    }
    let mut bound_routes = BTreeSet::new();
    for binding in &profile.internal_route_bindings {
        validate_id(&binding.routing_class_id, "routing class")?;
        validate_id(&binding.internal_inbox_id, "internal inbox")?;
        if !profile
            .routing_class_allowlist
            .contains(&binding.routing_class_id)
            || !binding.internal_inbox_id.starts_with("protected-inbox-")
            || !bound_routes.insert(&binding.routing_class_id)
        {
            return integrity("internal route is outside or duplicates the profile allowlist");
        }
    }
    if bound_routes
        != profile
            .routing_class_allowlist
            .iter()
            .collect::<BTreeSet<_>>()
    {
        return integrity("every allowed routing class must bind exactly one protected inbox");
    }
    Ok(())
}

fn validate_milestone_mapping(mapping: &SlaMilestoneMappingV1) -> Result<(), RoleOperationsError> {
    if mapping.received_source != SlaMilestoneSourceV1::WorkItemReceived
        || !matches!(
            mapping.acknowledged_source,
            SlaMilestoneSourceV1::FirstExclusiveLeaseClaim
                | SlaMilestoneSourceV1::ExplicitCaseAcknowledgement
        )
        || !matches!(
            mapping.begun_source,
            SlaMilestoneSourceV1::FirstAcceptedCaseTask
                | SlaMilestoneSourceV1::FirstPlannerStepAdmitted
                | SlaMilestoneSourceV1::FirstKernelBinding
        )
        || mapping.resolved_source != SlaMilestoneSourceV1::TerminalCaseTimestamp
        || mapping.escalated_source != SlaMilestoneSourceV1::DurableEscalationItem
    {
        return invalid("SLA milestone mapping selects a non-authoritative source");
    }
    Ok(())
}

/// Seals and signs an exact profile approval.
pub fn sign_profile_approval(
    mut approval: RoleOperationsProfileApprovalV1,
    profile: &RoleOperationsProfileV1,
    signing_key: &SigningKey,
) -> Result<RoleOperationsProfileApprovalV1, RoleOperationsError> {
    profile.validate()?;
    approval.signature_hex = "00".repeat(64);
    approval.approval_sha256 = ZERO_HASH.to_owned();
    validate_profile_approval_fields(&approval, profile)?;
    approval.approval_sha256 = hash_without(&approval, &["approval_sha256", "signature_hex"])?;
    let signing_bytes = canonical_json_bytes(&approval)?;
    approval.signature_hex = hex_encode(&signing_key.sign(&signing_bytes).to_bytes());
    validate_profile_approval_shape(&approval, profile)?;
    Ok(approval)
}

/// Verifies profile approval identity, lifetime, signature, and exact hashes.
pub fn verify_profile_approval(
    approval: &RoleOperationsProfileApprovalV1,
    profile: &RoleOperationsProfileV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<(), RoleOperationsError> {
    validate_profile_approval_shape(approval, profile)?;
    if approval.signing_key_id != expected_signer_key_id
        || now_unix_seconds < approval.issued_at_unix_seconds
        || now_unix_seconds >= approval.expires_at_unix_seconds
    {
        return invalid("profile approval signer or validity window differs");
    }
    let mut unsigned = approval.clone();
    let signature = decode_signature(&unsigned.signature_hex)?;
    unsigned.signature_hex = "00".repeat(64);
    verifying_key
        .verify(&canonical_json_bytes(&unsigned)?, &signature)
        .map_err(|error| RoleOperationsError::Signature(error.to_string()))
}

fn validate_profile_approval_shape(
    approval: &RoleOperationsProfileApprovalV1,
    profile: &RoleOperationsProfileV1,
) -> Result<(), RoleOperationsError> {
    validate_profile_approval_fields(approval, profile)?;
    validate_hash(&approval.approval_sha256, "approval_sha256")?;
    if approval.approval_sha256 != hash_without(approval, &["approval_sha256", "signature_hex"])? {
        return integrity("profile approval hash differs");
    }
    Ok(())
}

fn validate_profile_approval_fields(
    approval: &RoleOperationsProfileApprovalV1,
    profile: &RoleOperationsProfileV1,
) -> Result<(), RoleOperationsError> {
    if approval.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || approval.profile_sha256 != profile.profile_sha256
        || approval.organization_id != profile.organization_id
        || approval.role_contract_sha256 != profile.role_contract_sha256
        || approval.issued_at_unix_seconds == 0
        || approval.issued_at_unix_seconds >= approval.expires_at_unix_seconds
    {
        return integrity("profile approval differs from profile or has invalid lifetime");
    }
    validate_id(&approval.signer_id, "profile approval signer")?;
    validate_id(&approval.signing_key_id, "profile approval signing key")?;
    validate_id(&approval.nonce, "profile approval nonce")?;
    validate_sorted_unique(&approval.evidence_ids, "profile approval evidence")?;
    reject_forbidden(approval, "profile approval")
}

/// Validates trusted time monotonicity and caller-projected interval bounds.
pub fn validate_time_context(
    current: &TrustedRoleOperationsTimeContextV1,
    prior: Option<&TrustedRoleOperationsTimeContextV1>,
) -> Result<(), RoleOperationsError> {
    validate_time_context_shape(current)?;
    if let Some(prior) = prior {
        validate_time_context_shape(prior)?;
        if current.tick_sequence
            != prior.tick_sequence.checked_add(1).ok_or_else(|| {
                RoleOperationsError::ResourceLimit("trusted tick overflow".to_owned())
            })?
            || current.trusted_now_unix_seconds < prior.trusted_now_unix_seconds
            || current.prior_tick_sha256.as_ref() != Some(&prior.context_sha256)
            || current.timezone_id != prior.timezone_id
            || current.timezone_projection_sha256 != prior.timezone_projection_sha256
            || current.window_start_unix_seconds < prior.window_start_unix_seconds
        {
            return integrity("trusted time rollback, replay, overlap, or projection drift");
        }
    } else if current.prior_tick_sha256.is_some() {
        return invalid("initial trusted time cannot claim a prior tick");
    }
    Ok(())
}

fn validate_time_context_shape(
    current: &TrustedRoleOperationsTimeContextV1,
) -> Result<(), RoleOperationsError> {
    current.validate()?;
    if current.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || current.trusted_now_unix_seconds == 0
        || current.window_start_unix_seconds >= current.window_end_unix_seconds
        || current.trusted_now_unix_seconds < current.window_start_unix_seconds
        || current.trusted_now_unix_seconds > current.window_end_unix_seconds
        || current.tick_sequence == 0
    {
        return invalid("trusted operations time has an invalid now/window/tick shape");
    }
    validate_hash(&current.timezone_projection_sha256, "timezone projection")?;
    Ok(())
}

/// Validates one caller-supplied fixed measurement window.
pub fn validate_measurement_window(
    window: &RoleMeasurementWindowV1,
    time: &TrustedRoleOperationsTimeContextV1,
    prior: Option<&RoleMeasurementWindowV1>,
) -> Result<(), RoleOperationsError> {
    window.validate()?;
    validate_time_context(time, None)?;
    let duration = window
        .end_unix_seconds
        .checked_sub(window.start_unix_seconds)
        .ok_or_else(|| RoleOperationsError::Invalid("measurement window is reversed".to_owned()))?;
    if duration == 0
        || duration > MAX_MEASUREMENT_WINDOW_SECONDS
        || window.timezone_projection_sha256 != time.timezone_projection_sha256
        || window.source_tick_sha256 != time.context_sha256
    {
        return invalid("measurement window is zero, excessive, or stale");
    }
    if let Some(prior) = prior {
        if window.start_unix_seconds < prior.end_unix_seconds
            || window.previous_window_sha256.as_ref() != Some(&prior.window_sha256)
        {
            return integrity("measurement windows overlap or break their chain");
        }
    } else if window.previous_window_sha256.is_some() {
        return invalid("initial measurement window cannot claim a predecessor");
    }
    Ok(())
}

/// Calculates one additive, pause-aware SLA runtime projection.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_case_sla(
    evidence: &CaseOperationsEvidenceV1,
    role_sla_profile: &RoleSlaProfileV1,
    profile: &RoleOperationsProfileV1,
    time: &TrustedRoleOperationsTimeContextV1,
    previous_state_sha256: Option<String>,
) -> Result<CaseSlaRuntimeStateV1, RoleOperationsError> {
    profile.validate()?;
    validate_time_context_shape(time)?;
    evidence
        .sla_binding
        .validate_against(role_sla_profile)
        .map_err(|error| RoleOperationsError::Integrity(error.to_string()))?;
    if evidence.case_id != evidence.sla_binding.case_id
        || evidence.role_contract_sha256 != profile.role_contract_sha256
        || evidence.milestone_events.len() > MAX_MILESTONES_PER_CASE
        || evidence.pause_intervals.len() > MAX_PAUSE_INTERVALS
    {
        return integrity("SLA evidence differs from its Case, Role, or resource boundary");
    }
    for hash in [
        &evidence.case_contract_sha256,
        &evidence.current_case_instance_sha256,
        &evidence.case_ledger_head_sha256,
        &evidence.queue_ledger_head_sha256,
        &evidence.planner_ledger_head_sha256,
    ] {
        validate_hash(hash, "authoritative SLA source")?;
    }
    let event_times = validate_milestone_events(
        &evidence.milestone_events,
        &evidence.case_id,
        &evidence.sla_binding.binding_sha256,
        &profile.sla_milestone_mapping,
        time.trusted_now_unix_seconds,
    )?;
    let terminal_at = event_times.get(&SlaMilestoneV1::Resolved).copied();
    let (pauses, total_pause, active_pause) = validate_pauses(
        &evidence.pause_intervals,
        &evidence.case_id,
        &evidence.sla_binding,
        role_sla_profile,
        profile,
        terminal_at,
        time.trusted_now_unix_seconds,
    )?;
    let effective_ack = checked_deadline(
        evidence.sla_binding.acknowledge_due_at_unix_seconds,
        total_pause,
    )?;
    let effective_begin =
        checked_deadline(evidence.sla_binding.begin_due_at_unix_seconds, total_pause)?;
    let effective_resolve = checked_deadline(
        evidence.sla_binding.resolve_due_at_unix_seconds,
        total_pause,
    )?;
    let effective_escalate = checked_deadline(
        evidence.sla_binding.escalation_due_at_unix_seconds,
        total_pause,
    )?;
    let acknowledged = event_times.get(&SlaMilestoneV1::Acknowledged).copied();
    let begun = event_times.get(&SlaMilestoneV1::Begun).copied();
    let escalated = event_times.get(&SlaMilestoneV1::Escalated).copied();
    let ack_status = milestone_status(
        acknowledged,
        effective_ack,
        time.trusted_now_unix_seconds,
        active_pause,
    );
    let begin_status = milestone_status(
        begun,
        effective_begin,
        time.trusted_now_unix_seconds,
        active_pause,
    );
    let resolve_status = milestone_status(
        terminal_at,
        effective_resolve,
        time.trusted_now_unix_seconds,
        active_pause,
    );
    let escalation_status = milestone_status(
        escalated,
        effective_escalate,
        time.trusted_now_unix_seconds,
        active_pause,
    );
    let risk_band = risk_band(
        time.trusted_now_unix_seconds,
        effective_resolve,
        evidence.sla_binding.received_at_unix_seconds,
        profile.warning_remaining_millionths,
        profile.critical_remaining_seconds,
    )?;
    let statuses = [ack_status, begin_status, resolve_status];
    let overall = if active_pause {
        OverallSlaStatusV1::Paused
    } else if terminal_at.is_some() {
        if statuses
            .iter()
            .all(|status| *status == SlaMilestoneStatusV1::MetOnTime)
        {
            OverallSlaStatusV1::Compliant
        } else {
            OverallSlaStatusV1::TerminalNoncompliant
        }
    } else if statuses.iter().any(|status| {
        matches!(
            status,
            SlaMilestoneStatusV1::BreachedUnmet | SlaMilestoneStatusV1::MetLate
        )
    }) {
        OverallSlaStatusV1::Breached
    } else if matches!(risk_band, SlaRiskBandV1::Warning | SlaRiskBandV1::Critical) {
        OverallSlaStatusV1::AtRisk
    } else {
        OverallSlaStatusV1::Pending
    };
    let mut evidence_ids = evidence.evidence_class_ids.clone();
    evidence_ids.sort();
    evidence_ids.dedup();
    let state = CaseSlaRuntimeStateV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        sla_state_id: format!("sla-state:{}", evidence.case_id),
        case_id: evidence.case_id.clone(),
        case_contract_sha256: evidence.case_contract_sha256.clone(),
        current_case_instance_sha256: evidence.current_case_instance_sha256.clone(),
        role_contract_sha256: evidence.role_contract_sha256.clone(),
        sla_binding_sha256: evidence.sla_binding.binding_sha256.clone(),
        sla_profile_id: evidence.sla_binding.role_sla_profile_id.clone(),
        priority_class: format!("{:?}", evidence.sla_binding.priority_class).to_ascii_lowercase(),
        received_at_unix_seconds: evidence.sla_binding.received_at_unix_seconds,
        baseline_acknowledge_due_at_unix_seconds: evidence
            .sla_binding
            .acknowledge_due_at_unix_seconds,
        baseline_begin_due_at_unix_seconds: evidence.sla_binding.begin_due_at_unix_seconds,
        baseline_resolve_due_at_unix_seconds: evidence.sla_binding.resolve_due_at_unix_seconds,
        baseline_escalation_due_at_unix_seconds: evidence
            .sla_binding
            .escalation_due_at_unix_seconds,
        acknowledged_at_unix_seconds: acknowledged,
        begun_at_unix_seconds: begun,
        resolved_at_unix_seconds: terminal_at,
        escalated_at_unix_seconds: escalated,
        approved_pause_intervals: pauses,
        total_approved_pause_seconds: total_pause,
        effective_acknowledge_due_at_unix_seconds: effective_ack,
        effective_begin_due_at_unix_seconds: effective_begin,
        effective_resolve_due_at_unix_seconds: effective_resolve,
        effective_escalation_due_at_unix_seconds: effective_escalate,
        acknowledge_status: ack_status,
        begin_status,
        resolve_status,
        escalation_status,
        overall_sla_status: overall,
        risk_band,
        current_clock_context_sha256: time.context_sha256.clone(),
        case_ledger_head_sha256: evidence.case_ledger_head_sha256.clone(),
        queue_ledger_head_sha256: evidence.queue_ledger_head_sha256.clone(),
        planner_ledger_head_sha256: evidence.planner_ledger_head_sha256.clone(),
        evidence_ids,
        previous_state_sha256,
        state_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_sla_state_baseline(&state, &evidence.sla_binding)?;
    Ok(state)
}

fn validate_milestone_events(
    events: &[SlaMilestoneEventV1],
    case_id: &str,
    binding_sha256: &str,
    mapping: &SlaMilestoneMappingV1,
    now: u64,
) -> Result<BTreeMap<SlaMilestoneV1, u64>, RoleOperationsError> {
    let mut output = BTreeMap::new();
    for event in events {
        event.validate()?;
        let expected_source = match event.milestone {
            SlaMilestoneV1::Received => mapping.received_source,
            SlaMilestoneV1::Acknowledged => mapping.acknowledged_source,
            SlaMilestoneV1::Begun => mapping.begun_source,
            SlaMilestoneV1::Resolved => mapping.resolved_source,
            SlaMilestoneV1::Escalated => mapping.escalated_source,
        };
        if event.case_id != case_id
            || event.sla_binding_sha256 != binding_sha256
            || event.source != expected_source
            || event.occurred_at_unix_seconds == 0
            || event.occurred_at_unix_seconds > now
            || output
                .insert(event.milestone, event.occurred_at_unix_seconds)
                .is_some()
        {
            return integrity(
                "SLA milestone is stale, duplicated, future-dated, or incorrectly mapped",
            );
        }
    }
    if let (Some(received), Some(acknowledged)) = (
        output.get(&SlaMilestoneV1::Received),
        output.get(&SlaMilestoneV1::Acknowledged),
    ) {
        if acknowledged < received {
            return integrity("acknowledgement precedes receipt");
        }
    }
    if let (Some(acknowledged), Some(begun)) = (
        output.get(&SlaMilestoneV1::Acknowledged),
        output.get(&SlaMilestoneV1::Begun),
    ) {
        if begun < acknowledged {
            return integrity("begin precedes acknowledgement");
        }
    }
    if let (Some(begun), Some(resolved)) = (
        output.get(&SlaMilestoneV1::Begun),
        output.get(&SlaMilestoneV1::Resolved),
    ) {
        if resolved < begun {
            return integrity("resolution precedes begin");
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn validate_pauses(
    pauses: &[SlaPauseIntervalV1],
    case_id: &str,
    sla_binding: &CaseSlaBindingV1,
    role_sla_profile: &RoleSlaProfileV1,
    profile: &RoleOperationsProfileV1,
    terminal_at: Option<u64>,
    now: u64,
) -> Result<(Vec<SlaPauseIntervalV1>, u64, bool), RoleOperationsError> {
    let bindings = profile
        .sla_pause_condition_bindings
        .iter()
        .map(|binding| (binding.pause_condition_id.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut ordered = pauses.to_vec();
    ordered.sort_by(|left, right| {
        left.started_at_unix_seconds
            .cmp(&right.started_at_unix_seconds)
            .then_with(|| left.pause_id.cmp(&right.pause_id))
    });
    let mut total = 0_u64;
    let mut previous_end = None;
    let mut previous_hash: Option<&str> = None;
    let mut active = false;
    for pause in &ordered {
        pause.validate()?;
        let binding = bindings
            .get(pause.pause_condition_id.as_str())
            .ok_or_else(|| {
                RoleOperationsError::Integrity("pause condition is not profile-bound".to_owned())
            })?;
        if pause.case_id != case_id
            || pause.sla_binding_sha256 != sla_binding.binding_sha256
            || !role_sla_profile
                .pause_conditions
                .contains(&pause.pause_condition_id)
            || !binding
                .allowed_source_event_classes
                .contains(&pause.source_event_class_id)
            || pause
                .case_block_class_id
                .as_ref()
                .is_some_and(|class| !binding.allowed_case_block_classes.contains(class))
            || pause
                .clarification_reason_code
                .as_ref()
                .is_some_and(|reason| !binding.allowed_clarification_reason_codes.contains(reason))
            || pause.started_at_unix_seconds < sla_binding.received_at_unix_seconds
            || pause.started_at_unix_seconds > now
            || terminal_at.is_some_and(|terminal| pause.started_at_unix_seconds >= terminal)
            || binding.approval_required != pause.approval_sha256.is_some()
            || binding.required_evidence_class_ids.iter().any(|required| {
                !pause
                    .evidence_ids
                    .iter()
                    .any(|evidence| evidence == required)
            })
            || pause.previous_pause_sha256.as_deref() != previous_hash
        {
            return integrity(
                "pause is unauthorized, stale, post-terminal, or lacks exact evidence",
            );
        }
        let end = pause.ended_at_unix_seconds.unwrap_or(now);
        if end < pause.started_at_unix_seconds || end > now {
            return invalid("pause interval rolls time backward or is future-dated");
        }
        if previous_end.is_some_and(|previous| pause.started_at_unix_seconds < previous) {
            return integrity("SLA pause intervals overlap");
        }
        let duration = end
            .checked_sub(pause.started_at_unix_seconds)
            .ok_or_else(|| RoleOperationsError::Invalid("pause duration underflow".to_owned()))?;
        if duration == 0 || duration > binding.maximum_single_pause_seconds {
            return resource("pause duration is zero, indefinite, or exceeds its single bound");
        }
        total = total
            .checked_add(duration)
            .ok_or_else(|| RoleOperationsError::ResourceLimit("pause total overflow".to_owned()))?;
        if total > binding.maximum_cumulative_pause_seconds || total > MAX_CUMULATIVE_PAUSE_SECONDS
        {
            return resource("cumulative pause exceeds its approved bound");
        }
        active |= pause.ended_at_unix_seconds.is_none();
        previous_end = Some(end);
        previous_hash = Some(&pause.pause_sha256);
    }
    Ok((ordered, total, active))
}

fn checked_deadline(baseline: u64, pause: u64) -> Result<u64, RoleOperationsError> {
    baseline
        .checked_add(pause)
        .ok_or_else(|| RoleOperationsError::ResourceLimit("effective deadline overflow".to_owned()))
}

fn milestone_status(
    actual: Option<u64>,
    deadline: u64,
    now: u64,
    active_pause: bool,
) -> SlaMilestoneStatusV1 {
    if let Some(actual) = actual {
        if actual <= deadline {
            SlaMilestoneStatusV1::MetOnTime
        } else {
            SlaMilestoneStatusV1::MetLate
        }
    } else if active_pause {
        SlaMilestoneStatusV1::Paused
    } else if now > deadline {
        SlaMilestoneStatusV1::BreachedUnmet
    } else {
        SlaMilestoneStatusV1::Pending
    }
}

fn risk_band(
    now: u64,
    deadline: u64,
    received: u64,
    warning_remaining_millionths: u32,
    critical_remaining_seconds: u64,
) -> Result<SlaRiskBandV1, RoleOperationsError> {
    if now > deadline {
        return Ok(SlaRiskBandV1::Breached);
    }
    let remaining = deadline
        .checked_sub(now)
        .ok_or_else(|| RoleOperationsError::Invalid("SLA remaining time underflow".to_owned()))?;
    if remaining <= critical_remaining_seconds {
        return Ok(SlaRiskBandV1::Critical);
    }
    let total = deadline
        .checked_sub(received)
        .ok_or_else(|| RoleOperationsError::Invalid("SLA total time underflow".to_owned()))?;
    if total == 0 {
        return invalid("SLA deadline interval is zero");
    }
    let ratio = remaining
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_div(total))
        .ok_or_else(|| {
            RoleOperationsError::ResourceLimit("SLA risk arithmetic overflow".to_owned())
        })?;
    if ratio <= u64::from(warning_remaining_millionths) {
        Ok(SlaRiskBandV1::Warning)
    } else {
        Ok(SlaRiskBandV1::Healthy)
    }
}

fn validate_sla_state_baseline(
    state: &CaseSlaRuntimeStateV1,
    binding: &CaseSlaBindingV1,
) -> Result<(), RoleOperationsError> {
    if state.case_id != binding.case_id
        || state.sla_binding_sha256 != binding.binding_sha256
        || state.received_at_unix_seconds != binding.received_at_unix_seconds
        || state.baseline_acknowledge_due_at_unix_seconds != binding.acknowledge_due_at_unix_seconds
        || state.baseline_begin_due_at_unix_seconds != binding.begin_due_at_unix_seconds
        || state.baseline_resolve_due_at_unix_seconds != binding.resolve_due_at_unix_seconds
        || state.baseline_escalation_due_at_unix_seconds != binding.escalation_due_at_unix_seconds
    {
        return integrity("SLA runtime overlay mutates its immutable baseline binding");
    }
    Ok(())
}

/// Produces immutable exactly-once breach records absent from `existing_breach_keys`.
pub fn detect_sla_breaches(
    state: &CaseSlaRuntimeStateV1,
    time: &TrustedRoleOperationsTimeContextV1,
    existing_breach_keys: &BTreeSet<(String, String, SlaMilestoneV1)>,
) -> Result<Vec<SlaBreachRecordV1>, RoleOperationsError> {
    state.validate()?;
    validate_time_context_shape(time)?;
    if state.current_clock_context_sha256 != time.context_sha256 {
        return integrity("stale clock context cannot create an SLA breach");
    }
    let milestones = [
        (
            SlaMilestoneV1::Acknowledged,
            state.acknowledge_status,
            state.baseline_acknowledge_due_at_unix_seconds,
            state.effective_acknowledge_due_at_unix_seconds,
            state.acknowledged_at_unix_seconds,
        ),
        (
            SlaMilestoneV1::Begun,
            state.begin_status,
            state.baseline_begin_due_at_unix_seconds,
            state.effective_begin_due_at_unix_seconds,
            state.begun_at_unix_seconds,
        ),
        (
            SlaMilestoneV1::Resolved,
            state.resolve_status,
            state.baseline_resolve_due_at_unix_seconds,
            state.effective_resolve_due_at_unix_seconds,
            state.resolved_at_unix_seconds,
        ),
        (
            SlaMilestoneV1::Escalated,
            state.escalation_status,
            state.baseline_escalation_due_at_unix_seconds,
            state.effective_escalation_due_at_unix_seconds,
            state.escalated_at_unix_seconds,
        ),
    ];
    let mut records = Vec::new();
    for (milestone, status, baseline, effective, actual) in milestones {
        if !matches!(
            status,
            SlaMilestoneStatusV1::MetLate | SlaMilestoneStatusV1::BreachedUnmet
        ) || existing_breach_keys.contains(&(
            state.case_id.clone(),
            state.sla_binding_sha256.clone(),
            milestone,
        )) {
            continue;
        }
        let endpoint = actual.unwrap_or(time.trusted_now_unix_seconds);
        let duration = endpoint.checked_sub(effective).ok_or_else(|| {
            RoleOperationsError::Integrity("breach duration cannot be negative".to_owned())
        })?;
        let severity = if matches!(
            milestone,
            SlaMilestoneV1::Resolved | SlaMilestoneV1::Escalated
        ) {
            RoleEscalationSeverityV1::High
        } else {
            RoleEscalationSeverityV1::Elevated
        };
        let mut heads = vec![
            state.case_ledger_head_sha256.clone(),
            state.queue_ledger_head_sha256.clone(),
            state.planner_ledger_head_sha256.clone(),
        ];
        heads.sort();
        heads.dedup();
        let record = SlaBreachRecordV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            breach_id: format!("sla-breach:{}:{milestone:?}", state.case_id).to_ascii_lowercase(),
            case_id: state.case_id.clone(),
            sla_state_sha256: state.state_sha256.clone(),
            sla_binding_sha256: state.sla_binding_sha256.clone(),
            milestone,
            baseline_deadline_unix_seconds: baseline,
            effective_deadline_unix_seconds: effective,
            detected_at_unix_seconds: time.trusted_now_unix_seconds,
            actual_milestone_at_unix_seconds: actual,
            breach_duration_seconds: duration,
            severity,
            reason_codes: vec![format!("sla_{milestone:?}_deadline_exceeded").to_ascii_lowercase()],
            mandatory_escalation: matches!(severity, RoleEscalationSeverityV1::High),
            source_ledger_heads: heads,
            evidence_ids: vec!["authoritative-sla-runtime-state".to_owned()],
            breach_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        records.push(record);
    }
    records.sort_by(|left, right| left.breach_id.cmp(&right.breach_id));
    Ok(records)
}

/// Computes evidence coverage without treating missing or zero populations as success.
pub fn evaluate_metric(
    binding: &KpiMetricBindingV1,
    population: &RoleMetricPopulationV1,
    window: &RoleMeasurementWindowV1,
    evidence_ids: Vec<String>,
) -> Result<(MetricEvidenceCoverageV1, RoleMetricResultV1), RoleOperationsError> {
    binding.validate()?;
    window.validate()?;
    validate_metric_population(population)?;
    let (numerator, denominator, integer_value, millionths_value, expected) =
        metric_values(binding.formula_kind, population)?;
    let formula_missing = if binding.formula_kind == KpiFormulaKindV1::FalseCompletionRate {
        population
            .false_completion_review_population
            .saturating_sub(population.false_completion_review_covered)
    } else {
        0
    };
    let missing_evidence = population.missing_evidence_count.max(formula_missing);
    let (coverage_status, coverage_millionths) = if population.conflicting_evidence_count > 0 {
        (MetricCoverageStatusV1::Conflicting, None)
    } else if expected == 0 {
        (MetricCoverageStatusV1::NotApplicable, None)
    } else if missing_evidence > 0 {
        let covered = expected.saturating_sub(missing_evidence);
        (
            MetricCoverageStatusV1::Insufficient,
            Some(millionths(covered, expected)? as u32),
        )
    } else {
        (MetricCoverageStatusV1::Complete, Some(1_000_000))
    };
    let mut evidence = evidence_ids;
    evidence.sort();
    evidence.dedup();
    let coverage = MetricEvidenceCoverageV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        metric_binding_sha256: binding.binding_sha256.clone(),
        measurement_window_sha256: window.window_sha256.clone(),
        expected_population_count: expected,
        observed_population_count: expected.saturating_sub(missing_evidence),
        covered_population_count: expected.saturating_sub(missing_evidence),
        missing_evidence_count: missing_evidence,
        conflicting_evidence_count: population.conflicting_evidence_count,
        coverage_millionths,
        evidence_class_ids: evidence.clone(),
        status: coverage_status,
        coverage_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let result_status = match coverage.status {
        MetricCoverageStatusV1::Conflicting => RoleMetricResultStatusV1::ConflictingEvidence,
        MetricCoverageStatusV1::Insufficient | MetricCoverageStatusV1::Partial => {
            RoleMetricResultStatusV1::InsufficientEvidence
        }
        MetricCoverageStatusV1::NotApplicable => RoleMetricResultStatusV1::NotApplicable,
        MetricCoverageStatusV1::Complete => {
            metric_result_status(binding, integer_value, millionths_value)?
        }
    };
    let expose_value = coverage.status == MetricCoverageStatusV1::Complete;
    let result = RoleMetricResultV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        kpi_id: binding.kpi_id.clone(),
        metric_id: binding.metric_id.clone(),
        metric_binding_sha256: binding.binding_sha256.clone(),
        measurement_window_sha256: window.window_sha256.clone(),
        formula_kind: binding.formula_kind,
        numerator: expose_value.then_some(numerator).flatten(),
        denominator: expose_value.then_some(denominator).flatten(),
        integer_value: expose_value.then_some(integer_value).flatten(),
        millionths_value: expose_value.then_some(millionths_value).flatten(),
        unit: binding.unit.clone(),
        direction: binding.direction,
        target_millionths: binding.target_millionths,
        target_integer: binding.target_integer,
        warning_threshold: binding.warning_threshold,
        result_status,
        evidence_coverage_sha256: coverage.coverage_sha256.clone(),
        evidence_ids: evidence,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    Ok((coverage, result))
}

fn validate_metric_population(
    population: &RoleMetricPopulationV1,
) -> Result<(), RoleOperationsError> {
    if population.terminal_cases > population.admitted_cases
        || population.verified_complete_cases > population.terminal_cases
        || population.explicit_refusal_cases > population.terminal_cases
        || population.autonomous_completed_cases > population.verified_complete_cases
        || population.escalated_cases > population.admitted_cases
        || population.sla_applicable_cases > population.admitted_cases
        || population.sla_compliant_cases > population.sla_applicable_cases
        || population.clarified_cases > population.admitted_cases
        || population.unsupported_cases > population.admitted_cases
        || population.recovery_successes > population.recovery_attempts
        || population.acknowledge_duration_count > population.admitted_cases
        || population.begin_duration_count > population.admitted_cases
        || population.resolve_duration_count > population.terminal_cases
        || population.human_duration_covered_count > population.human_interaction_count
        || population.false_completion_review_population > population.terminal_cases
        || population.false_completion_review_covered
            > population.false_completion_review_population
        || population.false_completion_count > population.false_completion_review_covered
        || population.missing_evidence_count > population.admitted_cases
        || population.conflicting_evidence_count > population.admitted_cases
    {
        return integrity("metric population contains impossible authoritative counts");
    }
    Ok(())
}

type MetricValues = (Option<i64>, Option<i64>, Option<i64>, Option<i64>, u64);

fn metric_values(
    formula: KpiFormulaKindV1,
    population: &RoleMetricPopulationV1,
) -> Result<MetricValues, RoleOperationsError> {
    let count = |value: u64| -> Result<MetricValues, RoleOperationsError> {
        let value = i64::try_from(value)
            .map_err(|_| RoleOperationsError::ResourceLimit("metric count overflow".to_owned()))?;
        Ok((
            Some(value),
            None,
            Some(value),
            None,
            population.admitted_cases,
        ))
    };
    let rate = |numerator: u64, denominator: u64| -> Result<MetricValues, RoleOperationsError> {
        if denominator == 0 {
            return Ok((None, None, None, None, 0));
        }
        Ok((
            Some(i64::try_from(numerator).map_err(|_| {
                RoleOperationsError::ResourceLimit("metric numerator overflow".to_owned())
            })?),
            Some(i64::try_from(denominator).map_err(|_| {
                RoleOperationsError::ResourceLimit("metric denominator overflow".to_owned())
            })?),
            None,
            Some(
                i64::try_from(millionths(numerator, denominator)?).map_err(|_| {
                    RoleOperationsError::ResourceLimit("metric millionths overflow".to_owned())
                })?,
            ),
            denominator,
        ))
    };
    match formula {
        KpiFormulaKindV1::AdmittedCaseCount => count(population.admitted_cases),
        KpiFormulaKindV1::TerminalCaseCount => count(population.terminal_cases),
        KpiFormulaKindV1::VerifiedCompleteCount => count(population.verified_complete_cases),
        KpiFormulaKindV1::ExplicitRefusalCount => count(population.explicit_refusal_cases),
        KpiFormulaKindV1::EscalatedCaseCount => count(population.escalated_cases),
        KpiFormulaKindV1::AutonomousCaseCompletionRate => rate(
            population.autonomous_completed_cases,
            population.admitted_cases,
        ),
        KpiFormulaKindV1::VerifiedClosureRate => rate(
            population.verified_complete_cases,
            population.terminal_cases,
        ),
        KpiFormulaKindV1::SlaComplianceRate => rate(
            population.sla_compliant_cases,
            population.sla_applicable_cases,
        ),
        KpiFormulaKindV1::EscalationRate => {
            rate(population.escalated_cases, population.admitted_cases)
        }
        KpiFormulaKindV1::ClarificationRate => {
            rate(population.clarified_cases, population.admitted_cases)
        }
        KpiFormulaKindV1::RecoverySuccessRate => {
            rate(population.recovery_successes, population.recovery_attempts)
        }
        KpiFormulaKindV1::HumanTouchesPerCase => rate(
            population.human_interaction_count,
            population.admitted_cases,
        ),
        KpiFormulaKindV1::HumanMinutesPerCase => rate(
            population.human_interaction_seconds / 60,
            population.admitted_cases,
        ),
        KpiFormulaKindV1::AverageTimeToAcknowledge => rate(
            population.acknowledge_seconds_total,
            population.acknowledge_duration_count,
        ),
        KpiFormulaKindV1::AverageTimeToBegin => rate(
            population.begin_seconds_total,
            population.begin_duration_count,
        ),
        KpiFormulaKindV1::AverageTimeToResolve => rate(
            population.resolve_seconds_total,
            population.resolve_duration_count,
        ),
        KpiFormulaKindV1::FalseCompletionRate => {
            if population.false_completion_review_population == 0
                || population.false_completion_review_covered
                    != population.false_completion_review_population
            {
                Ok((
                    None,
                    None,
                    None,
                    None,
                    population.false_completion_review_population,
                ))
            } else {
                rate(
                    population.false_completion_count,
                    population.false_completion_review_population,
                )
            }
        }
        KpiFormulaKindV1::UnsupportedCaseRate => {
            rate(population.unsupported_cases, population.admitted_cases)
        }
    }
}

fn millionths(numerator: u64, denominator: u64) -> Result<u64, RoleOperationsError> {
    if denominator == 0 {
        return invalid("metric denominator is zero");
    }
    numerator
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_div(denominator))
        .ok_or_else(|| RoleOperationsError::ResourceLimit("metric arithmetic overflow".to_owned()))
}

fn metric_result_status(
    binding: &KpiMetricBindingV1,
    integer: Option<i64>,
    millionths_value: Option<i64>,
) -> Result<RoleMetricResultStatusV1, RoleOperationsError> {
    let value = integer.or(millionths_value).ok_or_else(|| {
        RoleOperationsError::Invalid("complete metric lacks a typed value".to_owned())
    })?;
    let target = binding
        .target_integer
        .or(binding.target_millionths)
        .ok_or_else(|| {
            RoleOperationsError::Integrity("metric binding lacks its Role target".to_owned())
        })?;
    let met = match binding.direction {
        KpiDirectionV1::Maximize | KpiDirectionV1::AtLeast => value >= target,
        KpiDirectionV1::Minimize | KpiDirectionV1::AtMost => value <= target,
    };
    if met {
        return Ok(RoleMetricResultStatusV1::Met);
    }
    let warning = binding
        .warning_threshold
        .is_some_and(|threshold| match binding.direction {
            KpiDirectionV1::Maximize | KpiDirectionV1::AtLeast => value >= threshold,
            KpiDirectionV1::Minimize | KpiDirectionV1::AtMost => value <= threshold,
        });
    Ok(if warning {
        RoleMetricResultStatusV1::Warning
    } else {
        RoleMetricResultStatusV1::Breached
    })
}

/// Evaluates required report evidence exactly as declared by the Role.
pub fn evaluate_report_evidence(
    obligation_id: String,
    required: Vec<String>,
    present: Vec<String>,
    conflicting: Vec<String>,
) -> Result<ReportEvidenceEvaluationV1, RoleOperationsError> {
    let mut required = required;
    let mut present = present;
    let mut conflicting = conflicting;
    for values in [&mut required, &mut present, &mut conflicting] {
        values.sort();
        values.dedup();
    }
    let missing = required
        .iter()
        .filter(|item| !present.contains(item))
        .cloned()
        .collect::<Vec<_>>();
    let status = if !conflicting.is_empty() {
        ReportEvidenceStatusV1::Conflicting
    } else if !missing.is_empty() {
        ReportEvidenceStatusV1::Incomplete
    } else {
        ReportEvidenceStatusV1::Complete
    };
    ReportEvidenceEvaluationV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        obligation_id,
        required_evidence_class_ids: required,
        present_evidence_class_ids: present,
        missing_evidence_class_ids: missing,
        conflicting_evidence_ids: conflicting,
        status,
        evaluation_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Validates an exact report trigger against one immutable Role obligation.
pub fn validate_report_trigger(
    trigger: &ReportingTriggerEventV1,
    contract: &RoleContractV1,
) -> Result<(), RoleOperationsError> {
    trigger.validate()?;
    if trigger.role_contract_sha256 != contract.contract_sha256 {
        return integrity("report trigger Role hash differs");
    }
    let obligation = contract
        .reporting_obligations
        .iter()
        .find(|item| item.obligation_id == trigger.obligation_id && item.enabled)
        .ok_or_else(|| {
            RoleOperationsError::Invalid("report obligation is disabled or absent".to_owned())
        })?;
    if trigger.trigger_kind != reporting_trigger(obligation.trigger) {
        return integrity("report trigger kind differs from Role obligation");
    }
    if matches!(trigger.trigger_kind, ReportingTriggerKindV1::Periodic)
        && trigger.source_case_id.is_some()
    {
        return invalid("periodic trigger cannot claim a Case source");
    }
    if !matches!(
        trigger.trigger_kind,
        ReportingTriggerKindV1::Periodic | ReportingTriggerKindV1::OnRoleSuspend
    ) && trigger.source_case_id.is_none()
    {
        return invalid("Case-scoped report trigger lacks its Case ID");
    }
    validate_hash_set(
        &trigger.source_artifact_hashes,
        "report trigger source hashes",
    )
}

fn reporting_trigger(trigger: RoleReportingTriggerV1) -> ReportingTriggerKindV1 {
    match trigger {
        RoleReportingTriggerV1::OnTaskComplete => ReportingTriggerKindV1::OnTaskComplete,
        RoleReportingTriggerV1::OnTaskFailed => ReportingTriggerKindV1::OnTaskFailed,
        RoleReportingTriggerV1::OnEscalation => ReportingTriggerKindV1::OnEscalation,
        RoleReportingTriggerV1::OnRoleSuspend => ReportingTriggerKindV1::OnRoleSuspend,
        RoleReportingTriggerV1::Periodic => ReportingTriggerKindV1::Periodic,
        RoleReportingTriggerV1::SlaBreach => ReportingTriggerKindV1::SlaBreach,
    }
}

/// Builds a non-executable report only when all required evidence is complete.
#[allow(clippy::too_many_arguments)]
pub fn build_role_report(
    contract: &RoleContractV1,
    trigger: &ReportingTriggerEventV1,
    snapshot: &RoleOperationsSnapshotV1,
    evaluation: &ReportEvidenceEvaluationV1,
    report_generation: u64,
    included_escalation_hashes: Vec<String>,
    human_interaction_count: u32,
) -> Result<RoleOperationsReportV1, RoleOperationsError> {
    validate_report_trigger(trigger, contract)?;
    snapshot.validate()?;
    evaluation.validate()?;
    if evaluation.status != ReportEvidenceStatusV1::Complete
        || evaluation.obligation_id != trigger.obligation_id
        || snapshot.role_contract_sha256 != contract.contract_sha256
        || report_generation == 0
    {
        return integrity("incomplete or cross-bound evidence cannot create a Role report");
    }
    let obligation = contract
        .reporting_obligations
        .iter()
        .find(|item| item.obligation_id == trigger.obligation_id && item.enabled)
        .ok_or_else(|| RoleOperationsError::Invalid("report obligation absent".to_owned()))?;
    if evaluation.required_evidence_class_ids != obligation.required_evidence_class_ids {
        return integrity("report evidence requirements differ from the immutable Role obligation");
    }
    let mut escalation_hashes = included_escalation_hashes;
    escalation_hashes.sort();
    escalation_hashes.dedup();
    RoleOperationsReportV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        report_id: format!("report:{}:{}", trigger.obligation_id, trigger.trigger_id),
        report_generation,
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_version: contract.role_version.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        report_class_id: obligation.report_class_id.clone(),
        reporting_obligation_id: obligation.obligation_id.clone(),
        trigger_sha256: trigger.trigger_sha256.clone(),
        measurement_window_sha256: Some(snapshot.measurement_window_sha256.clone()),
        role_operations_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        included_metric_result_hashes: snapshot.metric_result_hashes.clone(),
        included_sla_state_hashes: snapshot.case_sla_state_hashes.clone(),
        included_breach_hashes: snapshot.breach_hashes.clone(),
        included_escalation_hashes: escalation_hashes,
        included_episode_hashes: snapshot.terminal_episode_hashes.clone(),
        summary_counts: RoleReportSummaryCountsV1 {
            total_cases: snapshot.total_cases,
            verified_complete_cases: snapshot.verified_complete_cases,
            explicit_refusal_cases: snapshot.explicit_refusal_cases,
            escalated_cases: snapshot.escalated_cases,
            sla_compliant_cases: snapshot.sla_compliant_cases,
            sla_breached_cases: snapshot.sla_breached_cases,
            human_interaction_count,
        },
        data_class_ids: vec!["hash-reference".to_owned(), "structured-count".to_owned()],
        redaction_proof_ids: vec!["operations-report-redaction-v1".to_owned()],
        retention_class_id: obligation.retention_class_id.clone(),
        routing_class_id: obligation.routing_class_id.clone(),
        evidence_completeness_status: evaluation.status,
        evidence_ids: vec![
            evaluation.evaluation_sha256.clone(),
            snapshot.snapshot_sha256.clone(),
        ],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Seals and signs an internal routing registry approval.
pub fn sign_routing_registry_approval(
    mut approval: RoleRoutingRegistryApprovalV1,
    registry: &RoleRoutingRegistryV1,
    signing_key: &SigningKey,
) -> Result<RoleRoutingRegistryApprovalV1, RoleOperationsError> {
    validate_routing_registry(registry)?;
    approval.signature_hex = "00".repeat(64);
    approval.approval_sha256 = ZERO_HASH.to_owned();
    validate_registry_approval_fields(&approval, registry)?;
    approval.approval_sha256 = hash_without(&approval, &["approval_sha256", "signature_hex"])?;
    approval.signature_hex = hex_encode(
        &signing_key
            .sign(&canonical_json_bytes(&approval)?)
            .to_bytes(),
    );
    validate_registry_approval_shape(&approval, registry)?;
    Ok(approval)
}

/// Verifies routing approval, expiry, and exact signer identity.
pub fn verify_routing_registry_approval(
    approval: &RoleRoutingRegistryApprovalV1,
    registry: &RoleRoutingRegistryV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    now: u64,
) -> Result<(), RoleOperationsError> {
    validate_routing_registry(registry)?;
    validate_registry_approval_shape(approval, registry)?;
    if approval.signing_key_id != expected_signer_key_id
        || now < approval.issued_at_unix_seconds
        || now >= approval.expires_at_unix_seconds
    {
        return invalid("routing approval signer or validity differs");
    }
    let mut unsigned = approval.clone();
    let signature = decode_signature(&unsigned.signature_hex)?;
    unsigned.signature_hex = "00".repeat(64);
    verifying_key
        .verify(&canonical_json_bytes(&unsigned)?, &signature)
        .map_err(|error| RoleOperationsError::Signature(error.to_string()))
}

fn validate_registry_approval_shape(
    approval: &RoleRoutingRegistryApprovalV1,
    registry: &RoleRoutingRegistryV1,
) -> Result<(), RoleOperationsError> {
    validate_registry_approval_fields(approval, registry)?;
    validate_hash(&approval.approval_sha256, "routing approval hash")?;
    if approval.approval_sha256 != hash_without(approval, &["approval_sha256", "signature_hex"])? {
        return integrity("routing approval hash differs");
    }
    Ok(())
}

fn validate_registry_approval_fields(
    approval: &RoleRoutingRegistryApprovalV1,
    registry: &RoleRoutingRegistryV1,
) -> Result<(), RoleOperationsError> {
    if approval.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || approval.registry_sha256 != registry.registry_sha256
        || approval.organization_id != registry.organization_id
        || approval.role_contract_sha256 != registry.role_contract_sha256
        || approval.issued_at_unix_seconds == 0
        || approval.issued_at_unix_seconds >= approval.expires_at_unix_seconds
    {
        return integrity("routing approval differs from registry or its lifetime");
    }
    validate_id(&approval.signer_id, "routing approval signer")?;
    validate_id(&approval.signing_key_id, "routing approval key")?;
    validate_id(&approval.nonce, "routing approval nonce")?;
    validate_sorted_unique(&approval.evidence_ids, "routing approval evidence")?;
    reject_forbidden(approval, "routing registry approval")
}

/// Validates a bounded internal-only routing registry before it can be approved or used.
pub fn validate_routing_registry(
    registry: &RoleRoutingRegistryV1,
) -> Result<(), RoleOperationsError> {
    registry.validate()?;
    if registry.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || registry.valid_from_unix_seconds == 0
        || registry.valid_from_unix_seconds >= registry.valid_to_unix_seconds
        || registry.allowed_routing_class_ids.len() > MAX_ROUTING_CLASSES
        || registry.route_bindings.len() > MAX_INTERNAL_INBOXES
        || registry.escalation_severity_allowlist.is_empty()
    {
        return invalid("routing registry version, lifetime, or bounds are invalid");
    }
    validate_id(&registry.registry_id, "routing registry ID")?;
    validate_id(&registry.registry_version, "routing registry version")?;
    validate_id(&registry.organization_id, "routing registry organization")?;
    validate_hash(&registry.role_contract_sha256, "routing registry Role hash")?;
    validate_sorted_unique(
        &registry.allowed_routing_class_ids,
        "routing registry allowlist",
    )?;
    validate_sorted_unique(&registry.report_class_allowlist, "report class allowlist")?;
    validate_sorted_unique(&registry.evidence_ids, "routing registry evidence")?;
    if registry
        .escalation_severity_allowlist
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return invalid("routing severity allowlist must be sorted and unique");
    }
    let mut bound_routes = BTreeSet::new();
    let mut inboxes = BTreeSet::new();
    for binding in &registry.route_bindings {
        validate_id(&binding.routing_class_id, "routing class")?;
        validate_id(&binding.internal_inbox_id, "internal inbox")?;
        if !registry
            .allowed_routing_class_ids
            .contains(&binding.routing_class_id)
            || !binding.internal_inbox_id.starts_with("protected-inbox-")
            || !bound_routes.insert(&binding.routing_class_id)
            || !inboxes.insert(&binding.internal_inbox_id)
        {
            return integrity(
                "routing registry has an unapproved, duplicate, or non-internal route",
            );
        }
    }
    if bound_routes
        != registry
            .allowed_routing_class_ids
            .iter()
            .collect::<BTreeSet<_>>()
    {
        return integrity("routing registry must bind every allowed class exactly once");
    }
    Ok(())
}

/// Exact signed routing material required by every route resolution.
pub struct ApprovedRoutingContext<'a> {
    /// Immutable internal routing registry.
    pub registry: &'a RoleRoutingRegistryV1,
    /// Signature approval for the exact registry hash.
    pub approval: &'a RoleRoutingRegistryApprovalV1,
    /// Key identifier pinned by the organization runtime.
    pub expected_signer_key_id: &'a str,
    /// Verification key pinned by the organization runtime.
    pub verifying_key: &'a VerifyingKey,
    /// Trusted caller time used for registry and approval expiry.
    pub trusted_now_unix_seconds: u64,
}

/// Bounded, non-persistent query for one approved internal route.
pub struct InternalRouteQuery<'a> {
    /// Organization expected by the caller.
    pub organization_id: &'a str,
    /// Immutable Role Contract digest expected by the caller.
    pub role_contract_sha256: &'a str,
    /// Opaque routing class declared by the Role.
    pub routing_class_id: &'a str,
    /// Optional report class that must be allowlisted.
    pub report_class_id: Option<&'a str>,
    /// Optional escalation severity that must be allowlisted.
    pub severity: Option<RoleEscalationSeverityV1>,
}

/// Resolves one approved routing class to a protected internal inbox.
pub fn resolve_internal_route(
    routing: &ApprovedRoutingContext<'_>,
    query: &InternalRouteQuery<'_>,
) -> Result<String, RoleOperationsError> {
    verify_routing_registry_approval(
        routing.approval,
        routing.registry,
        routing.expected_signer_key_id,
        routing.verifying_key,
        routing.trusted_now_unix_seconds,
    )?;
    if routing.registry.organization_id != query.organization_id
        || routing.registry.role_contract_sha256 != query.role_contract_sha256
        || routing.trusted_now_unix_seconds < routing.registry.valid_from_unix_seconds
        || routing.trusted_now_unix_seconds >= routing.registry.valid_to_unix_seconds
        || !routing
            .registry
            .allowed_routing_class_ids
            .iter()
            .any(|item| item == query.routing_class_id)
        || query.report_class_id.is_some_and(|class| {
            !routing
                .registry
                .report_class_allowlist
                .iter()
                .any(|item| item == class)
        })
        || query.severity.is_some_and(|value| {
            !routing
                .registry
                .escalation_severity_allowlist
                .contains(&value)
        })
    {
        return integrity(
            "routing registry is stale, cross-organization, or outside its allowlist",
        );
    }
    let matches = routing
        .registry
        .route_bindings
        .iter()
        .filter(|binding| binding.routing_class_id == query.routing_class_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return invalid("routing class does not resolve to exactly one internal inbox");
    }
    Ok(matches[0].internal_inbox_id.clone())
}

/// Builds one exact internal-only publication from a verified report and signed route.
pub fn build_report_publication(
    publication_id: String,
    report: &RoleOperationsReportV1,
    routing: &ApprovedRoutingContext<'_>,
) -> Result<ReportPublicationEnvelopeV1, RoleOperationsError> {
    report.validate()?;
    let inbox = resolve_internal_route(
        routing,
        &InternalRouteQuery {
            organization_id: &report.organization_id,
            role_contract_sha256: &report.role_contract_sha256,
            routing_class_id: &report.routing_class_id,
            report_class_id: Some(&report.report_class_id),
            severity: None,
        },
    )?;
    let publication = ReportPublicationEnvelopeV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        publication_id,
        report_sha256: report.report_sha256.clone(),
        reporting_obligation_id: report.reporting_obligation_id.clone(),
        report_class_id: report.report_class_id.clone(),
        routing_class_id: report.routing_class_id.clone(),
        internal_inbox_id: inbox,
        registry_sha256: routing.registry.registry_sha256.clone(),
        published_at_unix_seconds: routing.trusted_now_unix_seconds,
        retention_class_id: report.retention_class_id.clone(),
        evidence_ids: vec![report.report_sha256.clone()],
        publication_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_report_publication(&publication, report, routing)?;
    Ok(publication)
}

/// Revalidates every report, registry, signer, route, and retention binding in a publication.
pub fn validate_report_publication(
    publication: &ReportPublicationEnvelopeV1,
    report: &RoleOperationsReportV1,
    routing: &ApprovedRoutingContext<'_>,
) -> Result<(), RoleOperationsError> {
    publication.validate()?;
    report.validate()?;
    let expected_inbox = resolve_internal_route(
        routing,
        &InternalRouteQuery {
            organization_id: &report.organization_id,
            role_contract_sha256: &report.role_contract_sha256,
            routing_class_id: &report.routing_class_id,
            report_class_id: Some(&report.report_class_id),
            severity: None,
        },
    )?;
    if publication.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || publication.report_sha256 != report.report_sha256
        || publication.reporting_obligation_id != report.reporting_obligation_id
        || publication.report_class_id != report.report_class_id
        || publication.routing_class_id != report.routing_class_id
        || publication.internal_inbox_id != expected_inbox
        || publication.registry_sha256 != routing.registry.registry_sha256
        || publication.published_at_unix_seconds != routing.trusted_now_unix_seconds
        || publication.retention_class_id != report.retention_class_id
        || publication.evidence_ids != vec![report.report_sha256.clone()]
    {
        return integrity("publication differs from its report or signed internal route");
    }
    Ok(())
}

/// Creates one durable receipt for an exact internal publication object.
pub fn build_report_publication_receipt(
    publication: &ReportPublicationEnvelopeV1,
    internal_inbox_ledger_head_sha256: String,
    publication_sequence: u64,
    recorded_at_unix_seconds: u64,
) -> Result<ReportPublicationReceiptV1, RoleOperationsError> {
    publication.validate()?;
    let receipt = ReportPublicationReceiptV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        publication_sha256: publication.publication_sha256.clone(),
        internal_inbox_ledger_head_sha256,
        durable_object_sha256: publication.publication_sha256.clone(),
        publication_sequence,
        status: ReportPublicationStatusV1::PublishedToInternalRoute,
        recorded_at_unix_seconds,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_report_publication_receipt(&receipt, publication)?;
    Ok(receipt)
}

/// Validates that an internal receipt cannot claim external or substituted delivery.
pub fn validate_report_publication_receipt(
    receipt: &ReportPublicationReceiptV1,
    publication: &ReportPublicationEnvelopeV1,
) -> Result<(), RoleOperationsError> {
    receipt.validate()?;
    publication.validate()?;
    validate_hash(
        &receipt.internal_inbox_ledger_head_sha256,
        "internal inbox ledger head",
    )?;
    if receipt.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || receipt.publication_sha256 != publication.publication_sha256
        || receipt.durable_object_sha256 != publication.publication_sha256
        || receipt.publication_sequence == 0
        || receipt.status != ReportPublicationStatusV1::PublishedToInternalRoute
        || receipt.recorded_at_unix_seconds < publication.published_at_unix_seconds
    {
        return integrity("publication receipt differs from the durable internal publication");
    }
    Ok(())
}

/// Selects Role escalation route precedence without suppressing the trigger.
pub fn select_escalation_route(
    contract: &RoleContractV1,
    trigger: &RoleEscalationTriggerV1,
) -> Option<String> {
    let reasons = trigger
        .reason_codes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if reasons.contains("unsafe_verification")
        || trigger.safety_severity == RoleEscalationSeverityV1::Unsafe
    {
        Some(contract.escalation_policy.unsafe_route_class.clone())
    } else if reasons.contains("legal_approval") {
        Some(contract.escalation_policy.legal_review_route_class.clone())
    } else if reasons.contains("policy_unknown") {
        Some(
            contract
                .escalation_policy
                .policy_conflict_route_class
                .clone(),
        )
    } else if reasons.contains("authority_exceeded") {
        Some(
            contract
                .escalation_policy
                .authority_exceeded_route_class
                .clone(),
        )
    } else {
        let key = match trigger.safety_severity {
            RoleEscalationSeverityV1::Routine => "routine",
            RoleEscalationSeverityV1::Elevated => "elevated",
            RoleEscalationSeverityV1::High => "high",
            RoleEscalationSeverityV1::Unsafe => "unsafe",
        };
        contract
            .escalation_policy
            .routing_class_by_severity
            .get(key)
            .cloned()
    }
}

/// Validates the exact source binding and mandatory human-exception semantics of a trigger.
pub fn validate_escalation_trigger(
    trigger: &RoleEscalationTriggerV1,
    contract: &RoleContractV1,
) -> Result<(), RoleOperationsError> {
    trigger.validate()?;
    if trigger.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || trigger.organization_id != contract.organization_scope.organization_id
        || trigger.role_contract_sha256 != contract.contract_sha256
        || trigger.detected_at_unix_seconds == 0
        || trigger.reason_codes.is_empty()
    {
        return integrity("escalation trigger differs from its Role or lacks a reason");
    }
    validate_sorted_unique(&trigger.reason_codes, "escalation reasons")?;
    validate_hash(&trigger.source_artifact_sha256, "escalation source")?;
    for hash in [
        trigger.sla_breach_sha256.as_deref(),
        trigger.kpi_breach_sha256.as_deref(),
        trigger.case_escalation_request_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_hash(hash, "escalation source binding")?;
    }
    let source_shape_valid = match trigger.trigger_source_kind {
        EscalationTriggerSourceKindV1::CaseMandatoryEscalation
        | EscalationTriggerSourceKindV1::RecoveryEscalation => {
            trigger.case_id.is_some()
                && trigger.case_escalation_request_sha256.is_some()
                && trigger.sla_breach_sha256.is_none()
                && trigger.kpi_breach_sha256.is_none()
        }
        EscalationTriggerSourceKindV1::SlaBreach => {
            trigger.case_id.is_some()
                && trigger.sla_breach_sha256.is_some()
                && trigger.kpi_breach_sha256.is_none()
                && trigger.case_escalation_request_sha256.is_none()
        }
        EscalationTriggerSourceKindV1::KpiBreach => {
            trigger.kpi_breach_sha256.is_some()
                && trigger.sla_breach_sha256.is_none()
                && trigger.case_escalation_request_sha256.is_none()
        }
        _ => {
            trigger.sla_breach_sha256.is_none()
                && trigger.kpi_breach_sha256.is_none()
                && trigger.case_escalation_request_sha256.is_none()
        }
    };
    if !source_shape_valid {
        return integrity("escalation source kind and exact source hashes differ");
    }
    let expected_reason = match trigger.trigger_source_kind {
        EscalationTriggerSourceKindV1::AuthorityExceeded => Some("authority_exceeded"),
        EscalationTriggerSourceKindV1::PolicyUnknown => Some("policy_unknown"),
        EscalationTriggerSourceKindV1::UnsafeVerification => Some("unsafe_verification"),
        EscalationTriggerSourceKindV1::LegalApproval => Some("legal_approval"),
        EscalationTriggerSourceKindV1::HighCriticality => Some("high_criticality"),
        EscalationTriggerSourceKindV1::SensitiveInput => Some("sensitive_input"),
        _ => None,
    };
    if expected_reason.is_some_and(|reason| !trigger.reason_codes.iter().any(|item| item == reason))
    {
        return integrity("escalation trigger suppresses its mandatory reason code");
    }
    let mandatory_human = trigger.reason_codes.iter().any(|reason| {
        contract
            .human_exception_policy
            .mandatory_escalation_reason_codes
            .contains(reason)
            || contract
                .escalation_policy
                .mandatory_reason_codes
                .contains(reason)
    });
    if mandatory_human
        && trigger.authority_impact != EscalationAuthorityImpactV1::RequiresAuthorizedHuman
    {
        return integrity("mandatory escalation cannot be downgraded to operational attention");
    }
    Ok(())
}

/// Creates one non-executable internal escalation item from a mandatory trigger.
#[allow(clippy::too_many_arguments)]
pub fn build_escalation_item(
    trigger: &RoleEscalationTriggerV1,
    contract: &RoleContractV1,
    profile: &RoleOperationsProfileV1,
    routing: &ApprovedRoutingContext<'_>,
    case_ledger_head_sha256: String,
    role_ledger_head_sha256: String,
    queue_ledger_head_sha256: String,
) -> Result<RoleEscalationItemV1, RoleOperationsError> {
    validate_escalation_trigger(trigger, contract)?;
    validate_profile_against_role(profile, contract, &profile.delegation_sha256)?;
    let route = select_escalation_route(contract, trigger);
    let internal_inbox_id = route
        .as_deref()
        .map(|routing_class_id| {
            resolve_internal_route(
                routing,
                &InternalRouteQuery {
                    organization_id: &trigger.organization_id,
                    role_contract_sha256: &trigger.role_contract_sha256,
                    routing_class_id,
                    report_class_id: None,
                    severity: Some(trigger.safety_severity),
                },
            )
        })
        .transpose()?;
    let acknowledge_due = trigger
        .detected_at_unix_seconds
        .checked_add(profile.maximum_pending_escalation_seconds)
        .ok_or_else(|| RoleOperationsError::ResourceLimit("ack deadline overflow".to_owned()))?;
    let resolution_due = acknowledge_due
        .checked_add(profile.maximum_resolution_seconds)
        .ok_or_else(|| {
            RoleOperationsError::ResourceLimit("resolution deadline overflow".to_owned())
        })?;
    RoleEscalationItemV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        escalation_item_id: format!("escalation-item:{}", trigger.trigger_id),
        organization_id: trigger.organization_id.clone(),
        role_contract_sha256: trigger.role_contract_sha256.clone(),
        case_id: trigger.case_id.clone(),
        escalation_kind: if trigger.authority_impact
            == EscalationAuthorityImpactV1::RequiresAuthorizedHuman
        {
            EscalationKindV1::HumanExceptionHandoff
        } else {
            EscalationKindV1::OperationalAttention
        },
        source_trigger_sha256: trigger.trigger_sha256.clone(),
        reason_codes: trigger.reason_codes.clone(),
        severity: trigger.safety_severity,
        routing_class_id: route,
        internal_inbox_id,
        created_at_unix_seconds: trigger.detected_at_unix_seconds,
        acknowledge_due_at_unix_seconds: acknowledge_due,
        resolution_due_at_unix_seconds: resolution_due,
        status: if select_escalation_route(contract, trigger).is_some() {
            EscalationItemStatusV1::Routed
        } else {
            EscalationItemStatusV1::RouteUnavailable
        },
        source_case_ledger_head_sha256: case_ledger_head_sha256,
        source_role_ledger_head_sha256: role_ledger_head_sha256,
        source_queue_ledger_head_sha256: queue_ledger_head_sha256,
        evidence_ids: vec![trigger.trigger_sha256.clone()],
        previous_escalation_sha256: None,
        item_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Seals and signs an acknowledgement that cannot be interpreted as approval.
pub fn sign_escalation_acknowledgement(
    mut acknowledgement: EscalationAcknowledgementV1,
    item: &RoleEscalationItemV1,
    signing_key: &SigningKey,
) -> Result<EscalationAcknowledgementV1, RoleOperationsError> {
    item.validate()?;
    if acknowledgement.escalation_item_sha256 != item.item_sha256
        || item.status != EscalationItemStatusV1::Routed
        || item.routing_class_id.is_none()
        || item.internal_inbox_id.is_none()
        || acknowledgement.acknowledged_at_unix_seconds < item.created_at_unix_seconds
        || acknowledgement.acknowledged_at_unix_seconds > item.acknowledge_due_at_unix_seconds
    {
        return integrity("acknowledgement differs from item or its deadline");
    }
    acknowledgement.signature_hex = "00".repeat(64);
    acknowledgement.acknowledgement_sha256 = ZERO_HASH.to_owned();
    acknowledgement.acknowledgement_sha256 = hash_without(
        &acknowledgement,
        &["acknowledgement_sha256", "signature_hex"],
    )?;
    acknowledgement.signature_hex = hex_encode(
        &signing_key
            .sign(&canonical_json_bytes(&acknowledgement)?)
            .to_bytes(),
    );
    validate_signed_acknowledgement(&acknowledgement, item)?;
    Ok(acknowledgement)
}

/// Verifies an acknowledgement signature and exact item binding.
pub fn verify_escalation_acknowledgement(
    acknowledgement: &EscalationAcknowledgementV1,
    item: &RoleEscalationItemV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), RoleOperationsError> {
    validate_signed_acknowledgement(acknowledgement, item)?;
    if acknowledgement.signer_key_id != expected_signer_key_id {
        return integrity("acknowledgement signer differs");
    }
    let mut unsigned = acknowledgement.clone();
    let signature = decode_signature(&unsigned.signature_hex)?;
    unsigned.signature_hex = "00".repeat(64);
    verifying_key
        .verify(&canonical_json_bytes(&unsigned)?, &signature)
        .map_err(|error| RoleOperationsError::Signature(error.to_string()))
}

fn validate_signed_acknowledgement(
    acknowledgement: &EscalationAcknowledgementV1,
    item: &RoleEscalationItemV1,
) -> Result<(), RoleOperationsError> {
    if acknowledgement.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || acknowledgement.escalation_item_sha256 != item.item_sha256
        || item.status != EscalationItemStatusV1::Routed
        || item.routing_class_id.is_none()
        || item.internal_inbox_id.is_none()
        || acknowledgement.acknowledgement_sha256
            != hash_without(
                acknowledgement,
                &["acknowledgement_sha256", "signature_hex"],
            )?
    {
        return integrity("acknowledgement hash or item binding differs");
    }
    validate_id(&acknowledgement.acknowledgement_id, "acknowledgement ID")?;
    validate_id(
        &acknowledgement.authenticated_actor_class_id,
        "acknowledgement actor class",
    )?;
    validate_id(&acknowledgement.signer_key_id, "acknowledgement signer")?;
    validate_sorted_unique(&acknowledgement.evidence_ids, "acknowledgement evidence")?;
    if acknowledgement.acknowledged_at_unix_seconds < item.created_at_unix_seconds
        || acknowledgement.acknowledged_at_unix_seconds > item.acknowledge_due_at_unix_seconds
    {
        return integrity("acknowledgement is outside the bounded item lifetime");
    }
    reject_forbidden(acknowledgement, "escalation acknowledgement")
}

/// Seals and signs a resolution that cannot reopen the source Case.
pub fn sign_escalation_resolution(
    mut resolution: EscalationResolutionV1,
    item: &RoleEscalationItemV1,
    acknowledgement: &EscalationAcknowledgementV1,
    signing_key: &SigningKey,
) -> Result<EscalationResolutionV1, RoleOperationsError> {
    verify_escalation_acknowledgement(
        acknowledgement,
        item,
        &acknowledgement.signer_key_id,
        &signing_key.verifying_key(),
    )?;
    if resolution.escalation_item_sha256 != item.item_sha256
        || resolution.latest_acknowledgement_sha256 != acknowledgement.acknowledgement_sha256
        || acknowledgement.escalation_item_sha256 != item.item_sha256
        || resolution.signer_key_id != acknowledgement.signer_key_id
        || resolution.resolved_at_unix_seconds < acknowledgement.acknowledged_at_unix_seconds
        || resolution.resolved_at_unix_seconds > item.resolution_due_at_unix_seconds
    {
        return integrity("resolution differs from item, acknowledgement, or deadline");
    }
    if matches!(
        resolution.resolution_disposition,
        EscalationResolutionDispositionV1::FollowUpWorkCreated
    ) != resolution.follow_up_work_item_reference.is_some()
    {
        return invalid("follow-up disposition and Work Item reference differ");
    }
    resolution.signature_hex = "00".repeat(64);
    resolution.resolution_sha256 = ZERO_HASH.to_owned();
    resolution.resolution_sha256 =
        hash_without(&resolution, &["resolution_sha256", "signature_hex"])?;
    resolution.signature_hex = hex_encode(
        &signing_key
            .sign(&canonical_json_bytes(&resolution)?)
            .to_bytes(),
    );
    validate_signed_resolution(&resolution, item, acknowledgement)?;
    Ok(resolution)
}

/// Verifies a resolution signature and exact acknowledgement chain.
pub fn verify_escalation_resolution(
    resolution: &EscalationResolutionV1,
    item: &RoleEscalationItemV1,
    acknowledgement: &EscalationAcknowledgementV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), RoleOperationsError> {
    verify_escalation_acknowledgement(
        acknowledgement,
        item,
        expected_signer_key_id,
        verifying_key,
    )?;
    validate_signed_resolution(resolution, item, acknowledgement)?;
    if resolution.signer_key_id != expected_signer_key_id {
        return integrity("resolution signer differs");
    }
    let mut unsigned = resolution.clone();
    let signature = decode_signature(&unsigned.signature_hex)?;
    unsigned.signature_hex = "00".repeat(64);
    verifying_key
        .verify(&canonical_json_bytes(&unsigned)?, &signature)
        .map_err(|error| RoleOperationsError::Signature(error.to_string()))
}

fn validate_signed_resolution(
    resolution: &EscalationResolutionV1,
    item: &RoleEscalationItemV1,
    acknowledgement: &EscalationAcknowledgementV1,
) -> Result<(), RoleOperationsError> {
    if resolution.schema_version != ROLE_OPERATIONS_SCHEMA_VERSION
        || resolution.escalation_item_sha256 != item.item_sha256
        || resolution.latest_acknowledgement_sha256 != acknowledgement.acknowledgement_sha256
        || resolution.signer_key_id != acknowledgement.signer_key_id
        || resolution.resolution_sha256
            != hash_without(resolution, &["resolution_sha256", "signature_hex"])?
    {
        return integrity("resolution hash or acknowledgement chain differs");
    }
    validate_id(&resolution.resolution_id, "resolution ID")?;
    validate_id(&resolution.signer_key_id, "resolution signer")?;
    validate_sorted_unique(&resolution.evidence_ids, "resolution evidence")?;
    if resolution.resolved_at_unix_seconds < acknowledgement.acknowledged_at_unix_seconds
        || resolution.resolved_at_unix_seconds > item.resolution_due_at_unix_seconds
        || matches!(
            resolution.resolution_disposition,
            EscalationResolutionDispositionV1::FollowUpWorkCreated
        ) != resolution.follow_up_work_item_reference.is_some()
    {
        return integrity("resolution is outside the acknowledged item lifetime");
    }
    reject_forbidden(resolution, "escalation resolution")
}

/// Creates a deterministic Role operations snapshot from evaluated evidence.
#[allow(clippy::too_many_arguments)]
pub fn build_role_snapshot(
    profile: &RoleOperationsProfileV1,
    contract: &RoleContractV1,
    window: &RoleMeasurementWindowV1,
    cases: &[CaseOperationsEvidenceV1],
    states: &[CaseSlaRuntimeStateV1],
    breaches: &[SlaBreachRecordV1],
    metric_results: &[RoleMetricResultV1],
    escalations: &[RoleEscalationItemV1],
    role_ledger_head_sha256: String,
    memory_store_head_sha256: String,
    audit_ledger_head_sha256: String,
) -> Result<RoleOperationsSnapshotV1, RoleOperationsError> {
    validate_profile_against_role(profile, contract, &profile.delegation_sha256)?;
    window.validate()?;
    for hash in [
        &role_ledger_head_sha256,
        &memory_store_head_sha256,
        &audit_ledger_head_sha256,
    ] {
        validate_hash(hash, "snapshot source head")?;
    }
    if cases.len() != states.len()
        || cases.len() > profile.maximum_cases_per_cycle as usize
        || states.len() > MAX_SLA_STATES
        || breaches.len() > MAX_BREACHES
        || metric_results.len() > MAX_METRIC_RESULTS
        || metric_results.len() != profile.kpi_metric_bindings.len()
        || escalations.len() > profile.maximum_escalations_per_cycle as usize
        || escalations.len() > MAX_ESCALATIONS
    {
        return integrity("snapshot Case/SLA population differs or exceeds profile");
    }
    let mut cases_by_id = BTreeMap::new();
    for case in cases {
        validate_id(&case.case_id, "snapshot Case ID")?;
        validate_id(&case.role_instance_id, "snapshot Role Instance ID")?;
        validate_sorted_unique(&case.evidence_class_ids, "snapshot Case evidence classes")?;
        for hash in [
            &case.case_contract_sha256,
            &case.current_case_instance_sha256,
            &case.case_ledger_head_sha256,
            &case.queue_ledger_head_sha256,
            &case.planner_ledger_head_sha256,
        ] {
            validate_hash(hash, "snapshot Case source")?;
        }
        if case.role_contract_sha256 != contract.contract_sha256
            || !profile.role_instance_scope.contains(&case.role_instance_id)
            || case.sla_binding.case_id != case.case_id
            || (case.verified_complete && case.explicit_refusal)
            || ((case.verified_complete || case.explicit_refusal)
                && case.terminal_outcome.is_none())
            || (case.autonomous_completion && !case.verified_complete)
            || case.recovery_success_count > case.recovery_attempt_count
            || cases_by_id.insert(&case.case_id, case).is_some()
        {
            return integrity("snapshot Case evidence is cross-bound, duplicated, or inconsistent");
        }
        if let Some(outcome) = &case.terminal_outcome {
            validate_id(outcome, "terminal outcome")?;
        }
        if let Some(episode) = &case.terminal_episode_sha256 {
            validate_hash(episode, "terminal Episode")?;
        }
    }
    let mut states_by_case = BTreeMap::new();
    for state in states {
        state.validate()?;
        let case = cases_by_id.get(&state.case_id).ok_or_else(|| {
            RoleOperationsError::Integrity("SLA state has no exact snapshot Case".to_owned())
        })?;
        if state.role_contract_sha256 != contract.contract_sha256
            || state.case_contract_sha256 != case.case_contract_sha256
            || state.current_case_instance_sha256 != case.current_case_instance_sha256
            || state.sla_binding_sha256 != case.sla_binding.binding_sha256
            || state.case_ledger_head_sha256 != case.case_ledger_head_sha256
            || state.queue_ledger_head_sha256 != case.queue_ledger_head_sha256
            || state.planner_ledger_head_sha256 != case.planner_ledger_head_sha256
            || states_by_case.insert(&state.case_id, state).is_some()
        {
            return integrity("snapshot SLA state differs from its authoritative Case evidence");
        }
    }
    for breach in breaches {
        breach.validate()?;
        let state = states_by_case.get(&breach.case_id).ok_or_else(|| {
            RoleOperationsError::Integrity("breach has no exact snapshot SLA state".to_owned())
        })?;
        if breach.sla_state_sha256 != state.state_sha256
            || breach.sla_binding_sha256 != state.sla_binding_sha256
        {
            return integrity("breach differs from its exact snapshot SLA state");
        }
    }
    let bindings = profile
        .kpi_metric_bindings
        .iter()
        .map(|binding| (binding.binding_sha256.as_str(), binding))
        .collect::<BTreeMap<_, _>>();
    let mut result_bindings = BTreeSet::new();
    for result in metric_results {
        result.validate()?;
        let binding = bindings
            .get(result.metric_binding_sha256.as_str())
            .copied()
            .ok_or_else(|| {
                RoleOperationsError::Integrity(
                    "metric result is not bound by the Role Operations profile".to_owned(),
                )
            })?;
        if result.measurement_window_sha256 != window.window_sha256
            || result.kpi_id != binding.kpi_id
            || result.metric_id != binding.metric_id
            || result.formula_kind != binding.formula_kind
            || result.unit != binding.unit
            || result.direction != binding.direction
            || result.target_millionths != binding.target_millionths
            || result.target_integer != binding.target_integer
            || result.warning_threshold != binding.warning_threshold
            || !result_bindings.insert(&result.metric_binding_sha256)
        {
            return integrity("metric result changes or duplicates its exact profile binding");
        }
    }
    for escalation in escalations {
        escalation.validate()?;
        if escalation.organization_id != contract.organization_scope.organization_id
            || escalation.role_contract_sha256 != contract.contract_sha256
            || escalation
                .case_id
                .as_ref()
                .is_some_and(|case_id| !cases_by_id.contains_key(case_id))
        {
            return integrity("snapshot escalation differs from its Role or Case population");
        }
    }
    let mut state_hashes = states
        .iter()
        .map(|state| state.state_sha256.clone())
        .collect::<Vec<_>>();
    let mut breach_hashes = breaches
        .iter()
        .map(|record| record.breach_sha256.clone())
        .collect::<Vec<_>>();
    let mut metric_hashes = metric_results
        .iter()
        .map(|result| result.result_sha256.clone())
        .collect::<Vec<_>>();
    let mut episodes = cases
        .iter()
        .filter_map(|case| case.terminal_episode_sha256.clone())
        .collect::<Vec<_>>();
    for values in [
        &mut state_hashes,
        &mut breach_hashes,
        &mut metric_hashes,
        &mut episodes,
    ] {
        values.sort();
        values.dedup();
    }
    let role_instances = cases
        .iter()
        .map(|case| case.role_instance_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let total_cases = u32::try_from(cases.len())
        .map_err(|_| RoleOperationsError::ResourceLimit("Case count overflow".to_owned()))?;
    let count = |predicate: &dyn Fn(&CaseOperationsEvidenceV1) -> bool| -> u32 {
        cases.iter().filter(|case| predicate(case)).count() as u32
    };
    let state_count = |status: OverallSlaStatusV1| -> u32 {
        states
            .iter()
            .filter(|state| state.overall_sla_status == status)
            .count() as u32
    };
    RoleOperationsSnapshotV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        snapshot_id: format!("operations-snapshot:{}", window.window_id),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_version: contract.role_version.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        role_instance_ids: role_instances,
        measurement_window_sha256: window.window_sha256.clone(),
        operations_profile_sha256: profile.profile_sha256.clone(),
        total_cases,
        active_cases: count(&|case| case.terminal_outcome.is_none()),
        blocked_cases: count(&|case| case.blocked),
        awaiting_clarification_cases: count(&|case| case.awaiting_clarification),
        awaiting_verification_cases: count(&|case| case.awaiting_verification),
        escalation_pending_cases: count(&|case| case.escalation_pending),
        terminal_cases: count(&|case| case.terminal_outcome.is_some()),
        verified_complete_cases: count(&|case| case.verified_complete),
        explicit_refusal_cases: count(&|case| case.explicit_refusal),
        escalated_cases: count(&|case| case.escalated),
        sla_compliant_cases: state_count(OverallSlaStatusV1::Compliant),
        sla_at_risk_cases: state_count(OverallSlaStatusV1::AtRisk),
        sla_paused_cases: state_count(OverallSlaStatusV1::Paused),
        sla_breached_cases: states
            .iter()
            .filter(|state| {
                matches!(
                    state.overall_sla_status,
                    OverallSlaStatusV1::Breached | OverallSlaStatusV1::TerminalNoncompliant
                )
            })
            .count() as u32,
        open_escalation_count: escalations
            .iter()
            .filter(|item| {
                !matches!(
                    item.status,
                    EscalationItemStatusV1::Resolved | EscalationItemStatusV1::Superseded
                )
            })
            .count() as u32,
        acknowledged_escalation_count: escalations
            .iter()
            .filter(|item| item.status == EscalationItemStatusV1::Acknowledged)
            .count() as u32,
        overdue_escalation_count: escalations
            .iter()
            .filter(|item| item.status == EscalationItemStatusV1::Overdue)
            .count() as u32,
        metric_result_hashes: metric_hashes,
        case_sla_state_hashes: state_hashes,
        breach_hashes,
        terminal_episode_hashes: episodes,
        role_ledger_head_sha256,
        case_ledger_head_sha256: first_identical_head(
            cases,
            |case| &case.case_ledger_head_sha256,
            "Case",
        )?,
        queue_ledger_head_sha256: first_identical_head(
            cases,
            |case| &case.queue_ledger_head_sha256,
            "Queue",
        )?,
        planner_ledger_head_sha256: hash_set(
            cases
                .iter()
                .map(|case| case.planner_ledger_head_sha256.clone())
                .collect(),
        )?,
        memory_store_head_sha256,
        audit_ledger_head_sha256,
        evidence_ids: vec!["authoritative-role-operations-cycle".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn first_identical_head<'a>(
    cases: &'a [CaseOperationsEvidenceV1],
    selector: impl Fn(&'a CaseOperationsEvidenceV1) -> &'a String,
    label: &str,
) -> Result<String, RoleOperationsError> {
    let heads = cases.iter().map(selector).collect::<BTreeSet<_>>();
    if heads.len() != 1 {
        return integrity(format!(
            "{label} ledger heads conflict across snapshot inputs"
        ));
    }
    heads
        .into_iter()
        .next()
        .cloned()
        .ok_or_else(|| RoleOperationsError::Invalid(format!("{label} ledger head absent")))
}

fn hash_set(mut hashes: Vec<String>) -> Result<String, RoleOperationsError> {
    hashes.sort();
    hashes.dedup();
    validate_hash_set(&hashes, "hash set")?;
    canonical_sha256(&hashes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn decode_signature(value: &str) -> Result<Signature, RoleOperationsError> {
    if value.len() != 128 {
        return invalid("signature hex length is invalid");
    }
    let mut bytes = [0_u8; 64];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|error| RoleOperationsError::Signature(error.to_string()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|error| RoleOperationsError::Signature(error.to_string()))?;
    }
    Ok(Signature::from_bytes(&bytes))
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }
    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("floating-point JSON is forbidden"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX_STRING_BYTES {
            return Err(E::custom("JSON string exceeds bound"));
        }
        Ok(StrictValue(Value::String(value.to_owned())))
    }
    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            if values.len() >= MAX_REPORT_EVIDENCE_REFS {
                return Err(serde::de::Error::custom("JSON array exceeds bound"));
            }
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }
    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if map.len() >= MAX_REPORT_EVIDENCE_REFS {
                return Err(serde::de::Error::custom("JSON object exceeds bound"));
            }
            if map.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key: {key}"
                )));
            }
            map.insert(key, access.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(map)))
    }
}

#[cfg(test)]
mod tests;
