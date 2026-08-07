//! Bounded governance contracts for limited autonomous Role operation.

mod contracts;

pub use contracts::*;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

pub const LIMITED_AUTONOMY_SCHEMA_VERSION: u32 = 1;
pub const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_COLLECTION_ITEMS: usize = 512;
pub const MAX_STRING_BYTES: usize = 512;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub fn public_schema(name: &str) -> Option<&'static str> {
    match name {
        "autonomy-readiness-binding-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-readiness-binding-v1.schema.json"
        )),
        "limited-autonomy-profile-v1" => Some(include_str!(
            "../../../schemas/workforce/limited-autonomy-profile-v1.schema.json"
        )),
        "autonomy-deployment-approval-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-deployment-approval-v1.schema.json"
        )),
        "autonomy-role-runtime-state-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-role-runtime-state-v1.schema.json"
        )),
        "autonomy-control-command-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-control-command-v1.schema.json"
        )),
        "autonomy-case-eligibility-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-case-eligibility-v1.schema.json"
        )),
        "autonomy-case-admission-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-case-admission-v1.schema.json"
        )),
        "autonomous-case-task-binding-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomous-case-task-binding-v1.schema.json"
        )),
        "autonomy-rollout-cohort-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-rollout-cohort-v1.schema.json"
        )),
        "autonomy-health-snapshot-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-health-snapshot-v1.schema.json"
        )),
        "autonomy-health-trip-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomy-health-trip-v1.schema.json"
        )),
        "human-exception-handoff-v1" => Some(include_str!(
            "../../../schemas/workforce/human-exception-handoff-v1.schema.json"
        )),
        "human-exception-response-v1" => Some(include_str!(
            "../../../schemas/workforce/human-exception-response-v1.schema.json"
        )),
        "autonomous-role-duty-cycle-request-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomous-role-duty-cycle-request-v1.schema.json"
        )),
        "autonomous-role-duty-cycle-result-v1" => Some(include_str!(
            "../../../schemas/workforce/autonomous-role-duty-cycle-result-v1.schema.json"
        )),
        "limited-autonomy-completion-report-v1" => Some(include_str!(
            "../../../schemas/workforce/limited-autonomy-completion-report-v1.schema.json"
        )),
        "limited-autonomy-replay-report-v1" => Some(include_str!(
            "../../../schemas/workforce/limited-autonomy-replay-report-v1.schema.json"
        )),
        "limited-autonomy-certification-v1" => Some(include_str!(
            "../../../schemas/workforce/limited-autonomy-certification-v1.schema.json"
        )),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LimitedAutonomyError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    Resource(String),
    Signature(String),
}

impl Display for LimitedAutonomyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::Replay(message) => ("replay", message),
            Self::Resource(message) => ("resource", message),
            Self::Signature(message) => ("signature", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for LimitedAutonomyError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, LimitedAutonomyError> {
    Err(LimitedAutonomyError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, LimitedAutonomyError> {
    Err(LimitedAutonomyError::Integrity(message.into()))
}

fn stale<T>(message: impl Into<String>) -> Result<T, LimitedAutonomyError> {
    Err(LimitedAutonomyError::Stale(message.into()))
}

fn unauthorized<T>(message: impl Into<String>) -> Result<T, LimitedAutonomyError> {
    Err(LimitedAutonomyError::Unauthorized(message.into()))
}

pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, LimitedAutonomyError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(LimitedAutonomyError::Resource(
            "JSON input exceeds byte limit".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))?;
    validate_bounded_value(&strict.0, 0)?;
    reject_sensitive_payload(&strict.0)?;
    serde_json::from_value(strict.0)
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, LimitedAutonomyError> {
    let value = serde_json::to_value(value)
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))?;
    serde_json::to_vec(&normalize_json(value))
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, LimitedAutonomyError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

pub fn hash_without<T: Serialize>(
    value: &T,
    fields: &[&str],
) -> Result<String, LimitedAutonomyError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| LimitedAutonomyError::Invalid("artifact must be an object".to_owned()))?;
    for field in fields {
        object.remove(*field);
    }
    canonical_sha256(&value)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, normalize_json(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_json).collect()),
        value => value,
    }
}

pub fn validate_hash(value: &str, label: &str) -> Result<(), LimitedAutonomyError> {
    let bytes = value.as_bytes();
    if bytes.len() != 71
        || !value.starts_with("sha256:")
        || !bytes[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return invalid(format!("{label} is not a lowercase SHA-256"));
    }
    Ok(())
}

pub fn validate_id(value: &str, label: &str) -> Result<(), LimitedAutonomyError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || value == "*"
        || value.contains("**")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return invalid(format!("{label} is not a bounded identifier"));
    }
    Ok(())
}

fn validate_artifact<T: Serialize>(
    value: &T,
    hash_field: &str,
    signature_field: Option<&str>,
) -> Result<(), LimitedAutonomyError> {
    let serialized = serde_json::to_value(value)
        .map_err(|error| LimitedAutonomyError::Invalid(error.to_string()))?;
    validate_bounded_value(&serialized, 0)?;
    reject_sensitive_payload(&serialized)?;
    let object = serialized
        .as_object()
        .ok_or_else(|| LimitedAutonomyError::Invalid("artifact must be an object".to_owned()))?;
    if object.get("schema_version") != Some(&Value::from(LIMITED_AUTONOMY_SCHEMA_VERSION)) {
        return invalid("unsupported limited autonomy schema version");
    }
    let actual = object
        .get(hash_field)
        .and_then(Value::as_str)
        .ok_or_else(|| LimitedAutonomyError::Invalid(format!("{hash_field} is absent")))?;
    validate_hash(actual, hash_field)?;
    let expected = match signature_field {
        Some(signature) => hash_without(value, &[hash_field, signature])?,
        None => hash_without(value, &[hash_field])?,
    };
    if actual != expected {
        return integrity(format!("{hash_field} mismatch"));
    }
    Ok(())
}

fn validate_bounded_value(value: &Value, depth: usize) -> Result<(), LimitedAutonomyError> {
    if depth > 32 {
        return Err(LimitedAutonomyError::Resource(
            "JSON nesting exceeds limit".to_owned(),
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => Err(
            LimitedAutonomyError::Resource("string exceeds byte limit".to_owned()),
        ),
        Value::Array(values) => {
            if values.len() > MAX_COLLECTION_ITEMS {
                return Err(LimitedAutonomyError::Resource(
                    "collection exceeds item limit".to_owned(),
                ));
            }
            for value in values {
                validate_bounded_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(object) => {
            if object.len() > MAX_COLLECTION_ITEMS {
                return Err(LimitedAutonomyError::Resource(
                    "object exceeds field limit".to_owned(),
                ));
            }
            for (key, value) in object {
                if key.len() > 128 {
                    return Err(LimitedAutonomyError::Resource(
                        "field name exceeds limit".to_owned(),
                    ));
                }
                validate_bounded_value(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_sensitive_payload(value: &Value) -> Result<(), LimitedAutonomyError> {
    const DENIED: &[&str] = &[
        "password",
        "raw_secret",
        "secret_value",
        "credential_value",
        "clipboard",
        "raw_prompt",
        "raw_ui",
        "locator",
        "command_line",
        "access_token",
    ];
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let lowered = key.to_ascii_lowercase();
                if DENIED.iter().any(|denied| lowered.contains(denied)) {
                    return invalid(format!("sensitive field {key} is forbidden"));
                }
                reject_sensitive_payload(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_sensitive_payload(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_ids(values: &[String], label: &str) -> Result<(), LimitedAutonomyError> {
    if values.len() > MAX_COLLECTION_ITEMS {
        return Err(LimitedAutonomyError::Resource(format!(
            "{label} exceeds item limit"
        )));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_id(value, label)?;
        if previous.is_some_and(|prior| prior >= value.as_str()) {
            return invalid(format!("{label} must be sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_hashes(values: &[String], label: &str) -> Result<(), LimitedAutonomyError> {
    let mut previous: Option<&str> = None;
    for value in values {
        validate_hash(value, label)?;
        if previous.is_some_and(|prior| prior >= value.as_str()) {
            return invalid(format!("{label} must be sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_interval(start: u64, end: u64, label: &str) -> Result<(), LimitedAutonomyError> {
    if start >= end {
        return invalid(format!("{label} must be finite and increasing"));
    }
    Ok(())
}

macro_rules! impl_sealed_artifact {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, LimitedAutonomyError> {
                self.$field = ZERO_HASH.to_owned();
                self.$field = hash_without(&self, &[stringify!($field)])?;
                Ok(self)
            }

            pub fn validate_integrity(&self) -> Result<(), LimitedAutonomyError> {
                validate_artifact(self, stringify!($field), None)
            }
        }
    };
}

macro_rules! impl_signed_artifact {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal_and_sign(mut self, key: &SigningKey) -> Result<Self, LimitedAutonomyError> {
                self.$field = ZERO_HASH.to_owned();
                self.signature_hex.clear();
                self.$field = hash_without(&self, &[stringify!($field), "signature_hex"])?;
                self.signature_hex = hex_encode(&key.sign(self.$field.as_bytes()).to_bytes());
                Ok(self)
            }

            pub fn validate_integrity(&self) -> Result<(), LimitedAutonomyError> {
                validate_artifact(self, stringify!($field), Some("signature_hex"))?;
                validate_signature_hex(&self.signature_hex)
            }

            pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), LimitedAutonomyError> {
                self.validate_integrity()?;
                let signature =
                    Signature::from_slice(&hex_decode(&self.signature_hex)?).map_err(|_| {
                        LimitedAutonomyError::Signature("invalid signature encoding".to_owned())
                    })?;
                key.verify(self.$field.as_bytes(), &signature).map_err(|_| {
                    LimitedAutonomyError::Signature("signature verification failed".to_owned())
                })
            }
        }
    };
}

impl_sealed_artifact!(AutonomyReadinessBindingV1, binding_sha256);
impl_sealed_artifact!(LimitedAutonomyProfileV1, profile_sha256);
impl_signed_artifact!(AutonomyDeploymentApprovalV1, approval_sha256);
impl_sealed_artifact!(AutonomyRoleRuntimeStateV1, state_sha256);
impl_signed_artifact!(AutonomyControlCommandV1, command_sha256);
impl_sealed_artifact!(AutonomyCaseEligibilityV1, eligibility_sha256);
impl_sealed_artifact!(AutonomyCaseAdmissionV1, admission_sha256);
impl_sealed_artifact!(AutonomousCaseTaskBindingV1, binding_sha256);
impl_sealed_artifact!(AutonomyRolloutCohortV1, cohort_sha256);
impl_sealed_artifact!(AutonomyHealthSnapshotV1, snapshot_sha256);
impl_sealed_artifact!(AutonomyHealthTripV1, trip_sha256);
impl_sealed_artifact!(HumanExceptionHandoffV1, handoff_sha256);
impl_signed_artifact!(HumanExceptionResponseV1, response_sha256);
impl_sealed_artifact!(AutonomousRoleDutyCycleRequestV1, request_sha256);
impl_sealed_artifact!(AutonomousRoleDutyCycleResultV1, result_sha256);
impl_sealed_artifact!(LimitedAutonomyCompletionReportV1, report_sha256);
impl_sealed_artifact!(LimitedAutonomyReplayReportV1, report_sha256);
impl_sealed_artifact!(LimitedAutonomyCertificationV1, certification_sha256);

impl AutonomyReadinessBindingV1 {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), LimitedAutonomyError> {
        self.validate_integrity()?;
        validate_id(&self.binding_id, "binding_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_hashes(&self.prompt_template_hashes, "prompt_template_hashes")?;
        validate_hashes(&self.application_pack_hashes, "application_pack_hashes")?;
        if now_unix_ms > self.valid_until_unix_ms
            || self.assessed_at_unix_ms >= self.valid_until_unix_ms
        {
            return stale("readiness binding expired or has an invalid interval");
        }
        if self.critical_error_count != 0
            || self.false_completion_count != 0
            || self.escalation_miss_count != 0
            || self.forbidden_capability_count != 0
            || self.authority_expansion_count != 0
        {
            return unauthorized("readiness contains a critical safety count");
        }
        Ok(())
    }
}

impl LimitedAutonomyProfileV1 {
    pub fn validate(&self, now_unix_ms: u64) -> Result<(), LimitedAutonomyError> {
        self.validate_integrity()?;
        validate_interval(
            self.valid_from_unix_ms,
            self.valid_to_unix_ms,
            "profile validity",
        )?;
        if now_unix_ms < self.valid_from_unix_ms || now_unix_ms > self.valid_to_unix_ms {
            return stale("limited autonomy profile is outside its validity interval");
        }
        for (values, label) in [
            (&self.allowed_work_class_ids, "allowed_work_class_ids"),
            (
                &self.allowed_responsibility_ids,
                "allowed_responsibility_ids",
            ),
            (&self.allowed_source_ids, "allowed_source_ids"),
            (&self.allowed_source_class_ids, "allowed_source_class_ids"),
            (&self.allowed_environment_ids, "allowed_environment_ids"),
            (&self.autonomous_capability_ids, "autonomous_capability_ids"),
            (
                &self.confirmation_capability_ids,
                "confirmation_capability_ids",
            ),
            (&self.prohibited_capability_ids, "prohibited_capability_ids"),
            (
                &self.allowed_semantic_target_ids,
                "allowed_semantic_target_ids",
            ),
        ] {
            validate_ids(values, label)?;
        }
        validate_hashes(&self.application_pack_hashes, "application_pack_hashes")?;
        validate_hashes(&self.prompt_template_hashes, "prompt_template_hashes")?;
        if self.maximum_cases_per_duty_cycle == 0
            || self.maximum_concurrent_cases != 1
            || self.maximum_actions_per_case == 0
            || self.maximum_model_invocations_per_case == 0
            || self.maximum_reobservations_per_case == 0
            || self.maximum_cycle_duration_ms == 0
            || self.maximum_case_duration_ms == 0
            || self.maximum_exception_handoffs_per_cycle == 0
            || self.maximum_active_leases != 1
            || self.maximum_control_commands_per_cycle == 0
            || self.maximum_health_records_per_cycle == 0
            || self.maximum_store_objects == 0
            || self.maximum_store_bytes == 0
            || self.maximum_audit_records_per_cycle == 0
            || self.maximum_evidence_references == 0
            || self.maximum_report_bytes == 0
            || self.maximum_resume_checkpoints == 0
            || self.rollout_maximum_cases == 0
            || self.rollout_maximum_side_effects == 0
        {
            return invalid("limited autonomy limits must be finite and concurrency must be one");
        }
        if self.health_thresholds.maximum_false_completions != 0
            || self.health_thresholds.maximum_authority_expansions != 0
            || self.health_thresholds.maximum_wrong_target_attempts != 0
            || self.health_thresholds.maximum_escalation_misses != 0
            || self.health_thresholds.maximum_secret_leakage != 0
        {
            return invalid("critical health thresholds must be zero");
        }
        if self
            .autonomous_capability_ids
            .iter()
            .any(|id| self.prohibited_capability_ids.contains(id))
        {
            return invalid("autonomous and prohibited capabilities overlap");
        }
        Ok(())
    }
}

pub fn validate_case_admission(
    admission: &AutonomyCaseAdmissionV1,
    eligibility: &AutonomyCaseEligibilityV1,
    state: &AutonomyRoleRuntimeStateV1,
    profile: &LimitedAutonomyProfileV1,
    now_unix_ms: u64,
) -> Result<(), LimitedAutonomyError> {
    admission.validate_integrity()?;
    eligibility.validate_integrity()?;
    state.validate_integrity()?;
    profile.validate(now_unix_ms)?;
    if eligibility.status != AutonomyCaseEligibilityStatusV1::Eligible
        || state.status != AutonomyRoleStatusV1::Enabled
        || admission.role_instance_sha256 != eligibility.role_instance_sha256
        || admission.role_instance_sha256 != state.role_instance_sha256
        || admission.autonomy_state_sha256 != eligibility.autonomy_state_sha256
        || admission.autonomy_state_sha256 != state.state_sha256
        || admission.deployment_approval_sha256 != eligibility.deployment_approval_sha256
        || admission.autonomy_profile_sha256 != profile.profile_sha256
        || admission.readiness_binding_sha256 != eligibility.readiness_binding_sha256
        || admission.case_contract_sha256 != eligibility.case_contract_sha256
        || admission.current_case_instance_sha256 != eligibility.current_case_instance_sha256
        || admission.current_ownership_sha256 != eligibility.current_ownership_sha256
        || admission.active_lease_sha256 != eligibility.active_lease_sha256
        || admission.case_eligibility_sha256 != eligibility.eligibility_sha256
        || !is_subset(
            &admission.allowed_autonomous_capability_ids,
            &profile.autonomous_capability_ids,
        )
        || !is_subset(
            &admission.allowed_semantic_target_ids,
            &profile.allowed_semantic_target_ids,
        )
        || admission.maximum_risk > profile.maximum_autonomous_risk
        || admission.action_budget == 0
        || admission.action_budget > profile.maximum_actions_per_case
        || admission.model_invocation_budget == 0
        || admission.model_invocation_budget > profile.maximum_model_invocations_per_case
        || admission.recovery_budget > profile.maximum_recovery_cycles
        || admission.issued_at_unix_ms > now_unix_ms
        || now_unix_ms > admission.expires_at_unix_ms
        || admission.issued_at_unix_ms >= admission.expires_at_unix_ms
    {
        return unauthorized("Case admission is stale, expanded, or not exactly bound");
    }
    Ok(())
}

pub fn validate_case_task_binding(
    binding: &AutonomousCaseTaskBindingV1,
    admission: &AutonomyCaseAdmissionV1,
) -> Result<(), LimitedAutonomyError> {
    binding.validate_integrity()?;
    admission.validate_integrity()?;
    if binding.autonomy_case_admission_sha256 != admission.admission_sha256
        || binding.current_case_instance_sha256 != admission.current_case_instance_sha256
        || binding.active_lease_sha256 != admission.active_lease_sha256
        || binding.work_grant_sha256 != admission.work_grant_sha256
    {
        return unauthorized("Case Task binding does not match the current admission");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashWindowV1 {
    RadarBeforeCheckpoint,
    IntakeBeforeCase,
    QueueBeforeLease,
    ModelBeforeActionAdmission,
    ActivationBeforeOutcome,
    ActionBeforeVerification,
    VerificationBeforeCaseLedger,
    TerminalCaseBeforeEpisode,
    HandoffBeforeRoutePublication,
    PauseBeforeRuntimeState,
    HealthTripBeforeIndex,
    ClosureBeforeReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashRecoveryDirectiveV1 {
    RescanFromDurableCursor,
    RepairFromIntakeReceipt,
    RequeueWithoutLease,
    ReobserveAndReplan,
    ReobserveAndVerifyNoReplay,
    RepairCaseFromVerifiedResult,
    PublishExactlyOnce,
    RestorePausedNoAction,
}

pub const fn crash_recovery_directive(window: CrashWindowV1) -> CrashRecoveryDirectiveV1 {
    match window {
        CrashWindowV1::RadarBeforeCheckpoint => CrashRecoveryDirectiveV1::RescanFromDurableCursor,
        CrashWindowV1::IntakeBeforeCase => CrashRecoveryDirectiveV1::RepairFromIntakeReceipt,
        CrashWindowV1::QueueBeforeLease => CrashRecoveryDirectiveV1::RequeueWithoutLease,
        CrashWindowV1::ModelBeforeActionAdmission => CrashRecoveryDirectiveV1::ReobserveAndReplan,
        CrashWindowV1::ActivationBeforeOutcome | CrashWindowV1::ActionBeforeVerification => {
            CrashRecoveryDirectiveV1::ReobserveAndVerifyNoReplay
        }
        CrashWindowV1::VerificationBeforeCaseLedger => {
            CrashRecoveryDirectiveV1::RepairCaseFromVerifiedResult
        }
        CrashWindowV1::TerminalCaseBeforeEpisode
        | CrashWindowV1::HandoffBeforeRoutePublication
        | CrashWindowV1::ClosureBeforeReport => CrashRecoveryDirectiveV1::PublishExactlyOnce,
        CrashWindowV1::PauseBeforeRuntimeState | CrashWindowV1::HealthTripBeforeIndex => {
            CrashRecoveryDirectiveV1::RestorePausedNoAction
        }
    }
}

pub fn verify_deployment_approval(
    approval: &AutonomyDeploymentApprovalV1,
    profile: &LimitedAutonomyProfileV1,
    readiness: &AutonomyReadinessBindingV1,
    key: &VerifyingKey,
    now_unix_ms: u64,
) -> Result<(), LimitedAutonomyError> {
    approval.verify_signature(key)?;
    profile.validate(now_unix_ms)?;
    readiness.validate(now_unix_ms)?;
    validate_interval(
        approval.issued_at_unix_ms,
        approval.expires_at_unix_ms,
        "approval",
    )?;
    if now_unix_ms < approval.issued_at_unix_ms || now_unix_ms > approval.expires_at_unix_ms {
        return stale("deployment approval is outside its validity interval");
    }
    if approval.organization_id != profile.organization_id
        || approval.autonomy_profile_sha256 != profile.profile_sha256
        || approval.readiness_binding_sha256 != readiness.binding_sha256
        || approval.target_role_sha256 != profile.role_contract_sha256
    {
        return unauthorized("deployment approval binding mismatch");
    }
    if !is_subset(
        &approval.approved_environment_ids,
        &profile.allowed_environment_ids,
    ) || !is_subset(
        &approval.approved_work_class_ids,
        &profile.allowed_work_class_ids,
    ) || !is_subset(
        &approval.approved_capability_ids,
        &profile.autonomous_capability_ids,
    ) || !is_subset(
        &approval.approved_semantic_target_ids,
        &profile.allowed_semantic_target_ids,
    ) || approval.approved_maximum_risk > profile.maximum_autonomous_risk
        || approval.rollout_maximum_cases > profile.rollout_maximum_cases
    {
        return unauthorized("deployment approval expands the autonomy profile");
    }
    Ok(())
}

fn is_subset(left: &[String], right: &[String]) -> bool {
    left.iter().all(|value| right.binary_search(value).is_ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseEligibilityInputV1<'a> {
    pub role_active: bool,
    pub delegation_active: bool,
    pub source_approved: bool,
    pub case_non_terminal: bool,
    pub ownership_current: bool,
    pub lease_current: bool,
    pub work_grant_current: bool,
    pub policy_known: bool,
    pub confirmation_required: bool,
    pub mandatory_exception: bool,
    pub work_class_id: &'a str,
    pub capability_ids: &'a [String],
    pub semantic_target_ids: &'a [String],
    pub risk_class: AutonomyRiskClassV1,
    pub now_unix_ms: u64,
}

pub fn evaluate_case_eligibility(
    mut result: AutonomyCaseEligibilityV1,
    input: &CaseEligibilityInputV1<'_>,
    state: &AutonomyRoleRuntimeStateV1,
    profile: &LimitedAutonomyProfileV1,
) -> Result<AutonomyCaseEligibilityV1, LimitedAutonomyError> {
    state.validate_integrity()?;
    profile.validate(input.now_unix_ms)?;
    result.reason_codes.clear();
    result.status = if input.now_unix_ms > result.evaluated_at_unix_ms.saturating_add(60_000) {
        result
            .reason_codes
            .push("eligibility_evidence_stale".to_owned());
        AutonomyCaseEligibilityStatusV1::Expired
    } else if !matches!(state.status, AutonomyRoleStatusV1::Enabled) {
        result.reason_codes.push("autonomy_not_enabled".to_owned());
        AutonomyCaseEligibilityStatusV1::AutonomyPaused
    } else if !input.role_active
        || !input.delegation_active
        || !input.source_approved
        || !input.case_non_terminal
        || !input.ownership_current
        || !input.lease_current
        || !input.work_grant_current
    {
        result
            .reason_codes
            .push("required_authority_binding_absent".to_owned());
        AutonomyCaseEligibilityStatusV1::NotEligible
    } else if !profile
        .allowed_work_class_ids
        .iter()
        .any(|id| id == input.work_class_id)
        || !is_subset(input.capability_ids, &profile.autonomous_capability_ids)
        || !is_subset(
            input.semantic_target_ids,
            &profile.allowed_semantic_target_ids,
        )
        || input.risk_class > profile.maximum_autonomous_risk
    {
        result
            .reason_codes
            .push("case_outside_autonomy_scope".to_owned());
        AutonomyCaseEligibilityStatusV1::OutOfScope
    } else if input.mandatory_exception || !input.policy_known {
        result
            .reason_codes
            .push("mandatory_human_exception".to_owned());
        AutonomyCaseEligibilityStatusV1::HumanExceptionRequired
    } else if input.confirmation_required {
        result
            .reason_codes
            .push("human_confirmation_required".to_owned());
        AutonomyCaseEligibilityStatusV1::HumanConfirmationRequired
    } else {
        result
            .reason_codes
            .push("bounded_autonomy_eligible".to_owned());
        AutonomyCaseEligibilityStatusV1::Eligible
    };
    result.reason_codes.sort();
    result.seal()
}

pub fn apply_control_command(
    state: &AutonomyRoleRuntimeStateV1,
    command: &AutonomyControlCommandV1,
    key: &VerifyingKey,
    now_unix_ms: u64,
    resume_bindings_valid: bool,
) -> Result<AutonomyRoleRuntimeStateV1, LimitedAutonomyError> {
    state.validate_integrity()?;
    command.verify_signature(key)?;
    if now_unix_ms < command.issued_at_unix_ms || now_unix_ms > command.expires_at_unix_ms {
        return stale("autonomy control command expired");
    }
    if command.role_instance_sha256 != state.role_instance_sha256
        || command.autonomy_profile_sha256 != state.autonomy_profile_sha256
        || command.state_generation != state.state_generation.saturating_add(1)
    {
        return unauthorized("control command binding or generation mismatch");
    }
    let next = match (state.status, command.operation) {
        (AutonomyRoleStatusV1::Eligible, AutonomyControlOperationV1::Enable)
        | (AutonomyRoleStatusV1::Disabled, AutonomyControlOperationV1::Enable) => {
            AutonomyRoleStatusV1::Enabled
        }
        (AutonomyRoleStatusV1::Enabled, AutonomyControlOperationV1::Pause) => {
            AutonomyRoleStatusV1::Paused
        }
        (AutonomyRoleStatusV1::Paused, AutonomyControlOperationV1::Resume)
            if resume_bindings_valid =>
        {
            AutonomyRoleStatusV1::Enabled
        }
        (AutonomyRoleStatusV1::Enabled, AutonomyControlOperationV1::Drain) => {
            AutonomyRoleStatusV1::Draining
        }
        (_, AutonomyControlOperationV1::Disable) => AutonomyRoleStatusV1::Disabled,
        (_, AutonomyControlOperationV1::Revoke) => AutonomyRoleStatusV1::Revoked,
        (AutonomyRoleStatusV1::Paused, AutonomyControlOperationV1::Resume) => {
            return unauthorized("resume requires fresh exact binding validation");
        }
        _ => return invalid("control transition is not allowed"),
    };
    let mut updated = state.clone();
    updated.state_id = format!("{}-g{}", state.state_id, command.state_generation);
    updated.status = next;
    updated.state_generation = command.state_generation;
    updated.current_control_command_sha256 = command.command_sha256.clone();
    updated.previous_state_sha256 = state.state_sha256.clone();
    if next == AutonomyRoleStatusV1::Enabled && updated.enabled_at_unix_ms.is_none() {
        updated.enabled_at_unix_ms = Some(now_unix_ms);
    }
    if next == AutonomyRoleStatusV1::Paused {
        updated.paused_at_unix_ms = Some(now_unix_ms);
    } else if next == AutonomyRoleStatusV1::Enabled {
        updated.paused_at_unix_ms = None;
    }
    updated.seal()
}

pub fn evaluate_health(
    mut snapshot: AutonomyHealthSnapshotV1,
    thresholds: &AutonomyHealthThresholdsV1,
) -> Result<AutonomyHealthSnapshotV1, LimitedAutonomyError> {
    let critical = snapshot.false_completions
        + snapshot.unsafe_side_effects
        + snapshot.escalation_misses
        + snapshot.authority_expansions
        + snapshot.forbidden_executed_capabilities
        + snapshot.wrong_target_attempts
        + snapshot.secret_leakage
        + snapshot.policy_bypasses
        + snapshot.activation_bypasses;
    snapshot.critical_error_count = critical;
    snapshot.health_status = if critical > 0 {
        AutonomyHealthStatusV1::Critical
    } else if snapshot.verification_failures > thresholds.maximum_verification_failures
        || snapshot.recovery_failures > thresholds.maximum_recovery_failures
    {
        AutonomyHealthStatusV1::PauseRequired
    } else if snapshot.provider_failures > thresholds.maximum_provider_failures
        || snapshot.sla_breaches > thresholds.maximum_sla_breaches
        || snapshot.residual_failures > thresholds.maximum_residual_failures
    {
        AutonomyHealthStatusV1::Warning
    } else {
        AutonomyHealthStatusV1::Healthy
    };
    snapshot.seal()
}

pub fn validate_health_trip(trip: &AutonomyHealthTripV1) -> Result<(), LimitedAutonomyError> {
    trip.validate_integrity()?;
    validate_ids(&trip.reason_codes, "reason_codes")?;
    if !trip.stop_new_case_claims || !trip.stop_new_actions || trip.reason_codes.is_empty() {
        return invalid("health trip must synchronously stop claims and actions");
    }
    Ok(())
}

pub fn validate_handoff(handoff: &HumanExceptionHandoffV1) -> Result<(), LimitedAutonomyError> {
    handoff.validate_integrity()?;
    validate_ids(&handoff.reason_codes, "reason_codes")?;
    validate_hashes(&handoff.applied_action_hashes, "applied_action_hashes")?;
    if handoff.reason_codes.is_empty() || handoff.unresolved_requirement_ids.is_empty() {
        return invalid("human exception handoff lacks bounded resolution context");
    }
    Ok(())
}

pub fn verify_human_response(
    response: &HumanExceptionResponseV1,
    expected_handoff_sha256: &str,
    key: &VerifyingKey,
    now_unix_ms: u64,
) -> Result<(), LimitedAutonomyError> {
    response.verify_signature(key)?;
    if response.handoff_sha256 != expected_handoff_sha256 {
        return unauthorized("human response targets another handoff");
    }
    if now_unix_ms < response.responded_at_unix_ms || now_unix_ms > response.valid_until_unix_ms {
        return stale("human exception response is outside its validity interval");
    }
    match response.response_class {
        HumanExceptionResponseClassV1::ProvideBoundedFact
            if response.approved_bounded_fact_sha256.is_some()
                && response.confirmation_artifact_sha256.is_none() => {}
        HumanExceptionResponseClassV1::ExistingConfirmation
            if response.confirmation_artifact_sha256.is_some()
                && response.approved_bounded_fact_sha256.is_none() => {}
        HumanExceptionResponseClassV1::Decline
        | HumanExceptionResponseClassV1::ExternalHandling
        | HumanExceptionResponseClassV1::CreateFollowupWork
            if response.approved_bounded_fact_sha256.is_none()
                && response.confirmation_artifact_sha256.is_none() => {}
        _ => return invalid("human response payload does not match its response class"),
    }
    Ok(())
}

pub fn validate_duty_cycle_request(
    request: &AutonomousRoleDutyCycleRequestV1,
    profile: &LimitedAutonomyProfileV1,
    now_unix_ms: u64,
) -> Result<(), LimitedAutonomyError> {
    request.validate_integrity()?;
    if request.maximum_cases == 0
        || request.maximum_cases > profile.maximum_cases_per_duty_cycle
        || request.maximum_actions == 0
        || request.maximum_actions
            > profile
                .maximum_actions_per_case
                .saturating_mul(request.maximum_cases)
        || request.maximum_provider_invocations == 0
        || request.maximum_provider_invocations
            > profile
                .maximum_model_invocations_per_case
                .saturating_mul(request.maximum_cases)
        || request.deadline_unix_ms <= now_unix_ms
    {
        return invalid("duty cycle request exceeds a finite profile bound");
    }
    Ok(())
}

pub fn validate_duty_cycle_result(
    result: &AutonomousRoleDutyCycleResultV1,
    request: &AutonomousRoleDutyCycleRequestV1,
) -> Result<(), LimitedAutonomyError> {
    result.validate_integrity()?;
    if result.cases_claimed > request.maximum_cases
        || result.autonomous_actions > request.maximum_actions
        || result.provider_invocations > request.maximum_provider_invocations
        || result.autonomous_cases_verified_complete > result.autonomous_cases_started
        || result.residual_process_count != 0
        || result.residual_profile_count != 0
        || result.residual_lock_count != 0
    {
        return integrity("duty cycle result violates request or cleanup bounds");
    }
    Ok(())
}

pub fn validate_completion_report(
    report: &LimitedAutonomyCompletionReportV1,
) -> Result<(), LimitedAutonomyError> {
    report.validate_integrity()?;
    if report.total_canary_cases != 8
        || report.routine_cases < 5
        || report.routine_verified_closure != report.routine_cases
        || report.routine_human_touches != 0
        || report.human_exception_cases < 3
        || report.mandatory_exception_handoff_recall_millionths != 1_000_000
        || report.actual_model_backed_cases < 5
        || report.actual_krn_side_effect_actions < 8
        || report.observations <= report.actions
        || report.provider_invocations < 8
        || [
            report.false_completions,
            report.wrong_targets,
            report.wrong_actions,
            report.duplicate_actions,
            report.duplicate_claims,
            report.authority_expansions,
            report.forbidden_capabilities,
            report.mandatory_escalation_misses,
            report.secret_leakage,
            report.network_accesses,
            report.critical_errors,
        ]
        .iter()
        .any(|count| *count != 0)
        || !report.autonomy_evidence
        || !report.human_by_exception_evidence
        || !report.track_w_completion_evidence
    {
        return integrity("completion report does not satisfy the WORK-900 gate");
    }
    Ok(())
}

pub fn validate_replay_report(
    report: &LimitedAutonomyReplayReportV1,
) -> Result<(), LimitedAutonomyError> {
    report.validate_integrity()?;
    if report.input_count != 128
        || report.iterations_per_input != 100
        || report.mismatch_count != 0
        || report.duplicate_consumption_count != 0
    {
        return integrity("deterministic replay report is incomplete");
    }
    Ok(())
}

#[derive(Debug, Default)]
pub struct ReplayLedgerV1 {
    command_ids: BTreeSet<String>,
    command_nonces: BTreeSet<String>,
    response_hashes: BTreeSet<String>,
    handoff_hashes: BTreeSet<String>,
}

impl ReplayLedgerV1 {
    pub fn consume_command(
        &mut self,
        command: &AutonomyControlCommandV1,
    ) -> Result<(), LimitedAutonomyError> {
        if !self.command_ids.insert(command.command_id.clone())
            || !self.command_nonces.insert(command.nonce.clone())
        {
            return Err(LimitedAutonomyError::Replay(
                "control command ID or nonce was already consumed".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn consume_handoff(
        &mut self,
        handoff: &HumanExceptionHandoffV1,
    ) -> Result<(), LimitedAutonomyError> {
        if !self.handoff_hashes.insert(handoff.handoff_sha256.clone()) {
            return Err(LimitedAutonomyError::Replay(
                "human exception handoff was already published".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn consume_response(
        &mut self,
        response: &HumanExceptionResponseV1,
    ) -> Result<(), LimitedAutonomyError> {
        if !self
            .response_hashes
            .insert(response.response_sha256.clone())
        {
            return Err(LimitedAutonomyError::Replay(
                "human exception response was already consumed".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_signature_hex(value: &str) -> Result<(), LimitedAutonomyError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LimitedAutonomyError::Signature(
            "signature is not lowercase Ed25519 hex".to_owned(),
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode(value: &str) -> Result<Vec<u8>, LimitedAutonomyError> {
    validate_signature_hex(value)?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, LimitedAutonomyError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(LimitedAutonomyError::Signature(
            "signature contains non-lowercase hex".to_owned(),
        )),
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor).map(Self)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate fields or floating point numbers")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("floating point numbers are forbidden"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("collection exceeds item limit"));
            }
            values.push(value.0);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
            if object.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON field: {key}")));
            }
            if object.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("object exceeds field limit"));
            }
            object.insert(key, value.0);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests;
