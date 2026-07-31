//! Deterministic, side-effect-free cognitive recovery contracts.
//!
//! This crate classifies failures and materializes bounded recovery handoffs.
//! It deliberately owns no adapter, filesystem, process, network, or model
//! authority.

use d2i_cognitive_ir::{
    CognitiveRecoveryKind, CognitiveRiskClass, GoalProgress, PlanGraph, RecoveryDecision,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Recovery contract schema version.
pub const RECOVERY_SCHEMA_VERSION: u32 = 1;
/// Repository-relative Draft 2020-12 recovery control schema.
pub const COGNITIVE_RECOVERY_CONTROL_V1_SCHEMA: &str =
    "schemas/cognitive/cognitive-recovery-control-v1.schema.json";
/// Maximum number of recovery cycles retained in one history.
pub const MAX_RECOVERY_CYCLES: usize = 64;
const MAX_ITEMS: usize = 64;
const MAX_TEXT_BYTES: usize = 1024;
const MAX_ID_BYTES: usize = 128;
const MAX_TOTAL_CYCLES: u32 = 64;

/// Pure recovery contract failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// A field, bound, enum combination, or graph is invalid.
    Invalid(String),
    /// A hash or exact lifecycle binding differs.
    Integrity(String),
    /// The requested automatic behavior is outside the safe recovery boundary.
    AccessDenied(String),
    /// A legacy projection cannot preserve the decision meaning.
    Unsupported(String),
    /// Strict JSON processing failed.
    Json(String),
}

impl Display for RecoveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid recovery artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "recovery integrity failure: {message}"),
            Self::AccessDenied(message) => write!(formatter, "recovery denied: {message}"),
            Self::Unsupported(message) => {
                write!(formatter, "unsupported recovery projection: {message}")
            }
            Self::Json(message) => write!(formatter, "recovery JSON failure: {message}"),
        }
    }
}

impl Error for RecoveryError {}

/// Parses strict JSON and rejects duplicate or unknown fields.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, RecoveryError> {
    d2i_trusted_action_execution::parse_json_strict(bytes)
        .map_err(|error| RecoveryError::Json(error.to_string()))
}

/// Computes the repository canonical SHA-256 representation.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, RecoveryError> {
    d2i_trusted_action_execution::canonical_sha256(value)
        .map_err(|error| RecoveryError::Json(error.to_string()))
}

fn hash_without<T: Serialize>(value: &T, field: &str) -> Result<String, RecoveryError> {
    let mut value = serde_json::to_value(value).map_err(json_error)?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| RecoveryError::Json("self-hashed artifact is not an object".to_owned()))?;
    if object.remove(field).is_none() {
        return Err(RecoveryError::Json(format!(
            "self-hash field {field} is absent"
        )));
    }
    canonical_sha256(&value)
}

fn empty_hash() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

/// Closed stage at which recovery was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStageV1 {
    Observation,
    Grounding,
    CandidateGeneration,
    Ranking,
    Policy,
    Confirmation,
    Activation,
    TargetResolution,
    Preparation,
    Execution,
    Verification,
}

/// Closed, trusted machine reason used for recovery classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReasonCodeV1 {
    NoFailure,
    ObservationUnavailable,
    StaleBinding,
    AmbiguousTarget,
    NoCandidate,
    NoEligibleCandidate,
    UnsupportedCapability,
    PolicyDenied,
    PolicyUnknown,
    AuthorityExceeded,
    ConfirmationMissing,
    ActivationUnavailable,
    TargetResolutionFailed,
    PreparationFailed,
    ExecutionFailed,
    ExecutionTimeoutOrUnknown,
    ExecutionAbortedAfterCommit,
    PostconditionFailed,
    ExpectedChangeMissing,
    VerificationInconclusive,
    VerificationUnsupported,
    UnsafeSideEffect,
    ProtectedInvariantViolation,
    ClarificationRequired,
    EvidenceConflict,
    BudgetExhausted,
    Unrecoverable,
}

/// Strict multi-stage recovery trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTriggerV1 {
    pub schema_version: u32,
    pub trigger_id: String,
    pub stage: RecoveryStageV1,
    pub goal_id: String,
    pub plan_generation_id: Option<String>,
    pub proposal_id: Option<String>,
    pub proposal_sha256: Option<String>,
    pub capability_id: Option<String>,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub fresh_observation_id: Option<String>,
    pub fresh_observation_hash: Option<String>,
    pub fresh_observation_sequence: Option<u64>,
    pub execution_receipt_sha256: Option<String>,
    pub verified_action_result_sha256: Option<String>,
    pub policy_decision_sha256: Option<String>,
    pub activation_admission_sha256: Option<String>,
    pub reason_codes: Vec<RecoveryReasonCodeV1>,
    pub evidence_ids: Vec<String>,
    pub detected_at_unix_ms: u64,
    pub trigger_sha256: String,
}

impl RecoveryTriggerV1 {
    /// Canonically seals and validates a trigger.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_set(&mut self.reason_codes, "trigger reason_codes", false)?;
        canonicalize_strings(&mut self.evidence_ids, "trigger evidence_ids", false)?;
        self.trigger_sha256 = hash_without(&self, "trigger_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates stage-specific lifecycle fields and the canonical hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery trigger")?;
        validate_id(&self.trigger_id, "trigger_id")?;
        validate_id(&self.goal_id, "trigger goal_id")?;
        validate_id(&self.source_observation_id, "source_observation_id")?;
        validate_hash(&self.source_observation_hash, "source_observation_hash")?;
        validate_optional_id(&self.plan_generation_id, "plan_generation_id")?;
        validate_optional_id(&self.proposal_id, "proposal_id")?;
        validate_optional_hash(&self.proposal_sha256, "proposal_sha256")?;
        validate_optional_id(&self.capability_id, "capability_id")?;
        validate_optional_id(&self.fresh_observation_id, "fresh_observation_id")?;
        validate_optional_hash(&self.fresh_observation_hash, "fresh_observation_hash")?;
        for (value, label) in [
            (&self.execution_receipt_sha256, "execution_receipt_sha256"),
            (
                &self.verified_action_result_sha256,
                "verified_action_result_sha256",
            ),
            (&self.policy_decision_sha256, "policy_decision_sha256"),
            (
                &self.activation_admission_sha256,
                "activation_admission_sha256",
            ),
        ] {
            validate_optional_hash(value, label)?;
        }
        if self.detected_at_unix_ms == 0 {
            return invalid("trigger detected_at_unix_ms must be positive");
        }
        validate_sorted_set(&self.reason_codes, "trigger reason_codes", false)?;
        validate_sorted_strings(&self.evidence_ids, "trigger evidence_ids", false)?;
        let proposal_shape = self.proposal_id.is_some()
            && self.proposal_sha256.is_some()
            && self.capability_id.is_some();
        if self.proposal_id.is_some() != self.proposal_sha256.is_some()
            || self.proposal_id.is_some() != self.capability_id.is_some()
        {
            return invalid("proposal ID, hash, and capability must appear together");
        }
        let fresh_shape = self.fresh_observation_id.is_some()
            && self.fresh_observation_hash.is_some()
            && self.fresh_observation_sequence.is_some();
        if self.fresh_observation_id.is_some() != self.fresh_observation_hash.is_some()
            || self.fresh_observation_id.is_some() != self.fresh_observation_sequence.is_some()
        {
            return invalid("fresh observation ID, hash, and sequence must appear together");
        }
        if fresh_shape
            && (self.fresh_observation_id.as_ref() == Some(&self.source_observation_id)
                || self.fresh_observation_hash.as_ref() == Some(&self.source_observation_hash)
                || self.fresh_observation_sequence <= Some(self.source_observation_sequence))
        {
            return integrity("fresh observation is not newer than the source observation");
        }
        let plan = self.plan_generation_id.is_some();
        let policy = self.policy_decision_sha256.is_some();
        let activation = self.activation_admission_sha256.is_some();
        let receipt = self.execution_receipt_sha256.is_some();
        let verified = self.verified_action_result_sha256.is_some();
        let valid_shape = match self.stage {
            RecoveryStageV1::Observation => {
                !plan && !proposal_shape && !policy && !activation && !receipt && !verified
            }
            RecoveryStageV1::Grounding
            | RecoveryStageV1::CandidateGeneration
            | RecoveryStageV1::Ranking => {
                plan && !proposal_shape && !policy && !activation && !receipt && !verified
            }
            RecoveryStageV1::Policy | RecoveryStageV1::Confirmation => {
                plan && proposal_shape && !activation && !receipt && !verified
            }
            RecoveryStageV1::Activation => {
                plan && proposal_shape && policy && !receipt && !verified
            }
            RecoveryStageV1::TargetResolution | RecoveryStageV1::Preparation => {
                plan && proposal_shape && policy && activation && !receipt && !verified
            }
            RecoveryStageV1::Execution => {
                plan && proposal_shape && policy && activation && !verified
            }
            RecoveryStageV1::Verification => {
                plan && proposal_shape && policy && activation && receipt && verified && fresh_shape
            }
        };
        if !valid_shape {
            return invalid("trigger contains an impossible stage/lifecycle field combination");
        }
        validate_hash(&self.trigger_sha256, "trigger_sha256")?;
        if hash_without(self, "trigger_sha256")? != self.trigger_sha256 {
            return integrity("trigger_sha256 differs from canonical trigger");
        }
        reject_forbidden_json(self, "recovery trigger")
    }
}

/// Closed normalized recovery failure class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryFailureClassV1 {
    NoFailure,
    TransientObservationFailure,
    StaleBinding,
    AmbiguousTarget,
    NoCandidate,
    NoEligibleCandidate,
    UnsupportedCapability,
    PolicyDenied,
    PolicyUnknown,
    AuthorityExceeded,
    ConfirmationMissing,
    ActivationUnavailable,
    TargetResolutionFailed,
    PreparationFailed,
    ExecutionFailed,
    ExecutionTimeoutOrUnknown,
    PostconditionFailed,
    ExpectedChangeMissing,
    VerificationInconclusive,
    VerificationUnsupported,
    UnsafeSideEffect,
    ProtectedInvariantViolation,
    ClarificationRequired,
    BudgetExhausted,
    Unrecoverable,
}

/// Whether and how a class may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRetryabilityV1 {
    None,
    ReobserveOnly,
    FreshCycle,
    AlternateOrReplan,
}

/// Safety severity of a normalized failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverySafetySeverityV1 {
    None,
    Operational,
    Elevated,
    Unsafe,
}

/// Effect of a failure on delegated authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAuthorityImpactV1 {
    None,
    WithinAuthority,
    RequiresEscalation,
}

/// Information gap remaining after classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryInformationGapV1 {
    None,
    BoundedUserFact,
    AmbiguousTarget,
    ConflictingEvidence,
}

/// Deterministic normalized classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClassificationV1 {
    pub schema_version: u32,
    pub trigger_sha256: String,
    pub primary_class: RecoveryFailureClassV1,
    pub secondary_classes: Vec<RecoveryFailureClassV1>,
    pub retryability: RecoveryRetryabilityV1,
    pub safety_severity: RecoverySafetySeverityV1,
    pub authority_impact: RecoveryAuthorityImpactV1,
    pub information_gap: RecoveryInformationGapV1,
    pub reason_codes: Vec<RecoveryReasonCodeV1>,
    pub classification_sha256: String,
}

impl RecoveryClassificationV1 {
    /// Validates binding, class priority, bounds, and canonical hash.
    pub fn validate_against(&self, trigger: &RecoveryTriggerV1) -> Result<(), RecoveryError> {
        trigger.validate()?;
        validate_schema(self.schema_version, "recovery classification")?;
        validate_hash(&self.trigger_sha256, "classification trigger_sha256")?;
        validate_sorted_set(
            &self.secondary_classes,
            "classification secondary_classes",
            true,
        )?;
        validate_sorted_set(&self.reason_codes, "classification reason_codes", false)?;
        if self.trigger_sha256 != trigger.trigger_sha256
            || self.reason_codes != trigger.reason_codes
            || self.secondary_classes.contains(&self.primary_class)
        {
            return integrity("classification differs from its exact trigger or class set");
        }
        let expected = classify_recovery_trigger(trigger)?;
        if self != &expected {
            return integrity("classification differs from deterministic classification");
        }
        Ok(())
    }
}

/// Classifies a trusted trigger with unsafe and authority failures taking priority.
pub fn classify_recovery_trigger(
    trigger: &RecoveryTriggerV1,
) -> Result<RecoveryClassificationV1, RecoveryError> {
    trigger.validate()?;
    let mut classes = trigger
        .reason_codes
        .iter()
        .copied()
        .map(class_for_reason)
        .collect::<Vec<_>>();
    classes.sort_by_key(|class| failure_priority(*class));
    classes.dedup();
    let primary_class = *classes
        .first()
        .ok_or_else(|| RecoveryError::Invalid("classification has no failure class".to_owned()))?;
    let secondary_classes = classes.into_iter().skip(1).collect::<Vec<_>>();
    let (retryability, safety_severity, authority_impact, information_gap) =
        classification_attributes(primary_class, &trigger.reason_codes);
    let mut classification = RecoveryClassificationV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        trigger_sha256: trigger.trigger_sha256.clone(),
        primary_class,
        secondary_classes,
        retryability,
        safety_severity,
        authority_impact,
        information_gap,
        reason_codes: trigger.reason_codes.clone(),
        classification_sha256: empty_hash(),
    };
    classification.classification_sha256 = hash_without(&classification, "classification_sha256")?;
    Ok(classification)
}

fn class_for_reason(reason: RecoveryReasonCodeV1) -> RecoveryFailureClassV1 {
    match reason {
        RecoveryReasonCodeV1::NoFailure => RecoveryFailureClassV1::NoFailure,
        RecoveryReasonCodeV1::ObservationUnavailable => {
            RecoveryFailureClassV1::TransientObservationFailure
        }
        RecoveryReasonCodeV1::StaleBinding => RecoveryFailureClassV1::StaleBinding,
        RecoveryReasonCodeV1::AmbiguousTarget => RecoveryFailureClassV1::AmbiguousTarget,
        RecoveryReasonCodeV1::NoCandidate => RecoveryFailureClassV1::NoCandidate,
        RecoveryReasonCodeV1::NoEligibleCandidate => RecoveryFailureClassV1::NoEligibleCandidate,
        RecoveryReasonCodeV1::UnsupportedCapability => {
            RecoveryFailureClassV1::UnsupportedCapability
        }
        RecoveryReasonCodeV1::PolicyDenied => RecoveryFailureClassV1::PolicyDenied,
        RecoveryReasonCodeV1::PolicyUnknown => RecoveryFailureClassV1::PolicyUnknown,
        RecoveryReasonCodeV1::AuthorityExceeded => RecoveryFailureClassV1::AuthorityExceeded,
        RecoveryReasonCodeV1::ConfirmationMissing => RecoveryFailureClassV1::ConfirmationMissing,
        RecoveryReasonCodeV1::ActivationUnavailable => {
            RecoveryFailureClassV1::ActivationUnavailable
        }
        RecoveryReasonCodeV1::TargetResolutionFailed => {
            RecoveryFailureClassV1::TargetResolutionFailed
        }
        RecoveryReasonCodeV1::PreparationFailed => RecoveryFailureClassV1::PreparationFailed,
        RecoveryReasonCodeV1::ExecutionFailed => RecoveryFailureClassV1::ExecutionFailed,
        RecoveryReasonCodeV1::ExecutionTimeoutOrUnknown
        | RecoveryReasonCodeV1::ExecutionAbortedAfterCommit => {
            RecoveryFailureClassV1::ExecutionTimeoutOrUnknown
        }
        RecoveryReasonCodeV1::PostconditionFailed => RecoveryFailureClassV1::PostconditionFailed,
        RecoveryReasonCodeV1::ExpectedChangeMissing => {
            RecoveryFailureClassV1::ExpectedChangeMissing
        }
        RecoveryReasonCodeV1::VerificationInconclusive | RecoveryReasonCodeV1::EvidenceConflict => {
            RecoveryFailureClassV1::VerificationInconclusive
        }
        RecoveryReasonCodeV1::VerificationUnsupported => {
            RecoveryFailureClassV1::VerificationUnsupported
        }
        RecoveryReasonCodeV1::UnsafeSideEffect => RecoveryFailureClassV1::UnsafeSideEffect,
        RecoveryReasonCodeV1::ProtectedInvariantViolation => {
            RecoveryFailureClassV1::ProtectedInvariantViolation
        }
        RecoveryReasonCodeV1::ClarificationRequired => {
            RecoveryFailureClassV1::ClarificationRequired
        }
        RecoveryReasonCodeV1::BudgetExhausted => RecoveryFailureClassV1::BudgetExhausted,
        RecoveryReasonCodeV1::Unrecoverable => RecoveryFailureClassV1::Unrecoverable,
    }
}

fn failure_priority(class: RecoveryFailureClassV1) -> u8 {
    match class {
        RecoveryFailureClassV1::ProtectedInvariantViolation => 0,
        RecoveryFailureClassV1::UnsafeSideEffect => 1,
        RecoveryFailureClassV1::AuthorityExceeded => 2,
        RecoveryFailureClassV1::PolicyUnknown => 3,
        RecoveryFailureClassV1::PolicyDenied => 4,
        RecoveryFailureClassV1::BudgetExhausted => 5,
        RecoveryFailureClassV1::Unrecoverable => 6,
        RecoveryFailureClassV1::ExecutionTimeoutOrUnknown => 7,
        RecoveryFailureClassV1::VerificationInconclusive => 8,
        RecoveryFailureClassV1::VerificationUnsupported => 9,
        RecoveryFailureClassV1::ClarificationRequired => 10,
        RecoveryFailureClassV1::StaleBinding => 11,
        RecoveryFailureClassV1::AmbiguousTarget => 12,
        RecoveryFailureClassV1::NoEligibleCandidate => 13,
        RecoveryFailureClassV1::NoCandidate => 14,
        RecoveryFailureClassV1::UnsupportedCapability => 15,
        RecoveryFailureClassV1::ActivationUnavailable => 16,
        RecoveryFailureClassV1::TargetResolutionFailed => 17,
        RecoveryFailureClassV1::PreparationFailed => 18,
        RecoveryFailureClassV1::ExecutionFailed => 19,
        RecoveryFailureClassV1::PostconditionFailed => 20,
        RecoveryFailureClassV1::ExpectedChangeMissing => 21,
        RecoveryFailureClassV1::TransientObservationFailure => 22,
        RecoveryFailureClassV1::ConfirmationMissing => 23,
        RecoveryFailureClassV1::NoFailure => 24,
    }
}

fn classification_attributes(
    class: RecoveryFailureClassV1,
    reasons: &[RecoveryReasonCodeV1],
) -> (
    RecoveryRetryabilityV1,
    RecoverySafetySeverityV1,
    RecoveryAuthorityImpactV1,
    RecoveryInformationGapV1,
) {
    let information = if reasons.contains(&RecoveryReasonCodeV1::EvidenceConflict) {
        RecoveryInformationGapV1::ConflictingEvidence
    } else {
        match class {
            RecoveryFailureClassV1::AmbiguousTarget => RecoveryInformationGapV1::AmbiguousTarget,
            RecoveryFailureClassV1::ClarificationRequired => {
                RecoveryInformationGapV1::BoundedUserFact
            }
            _ => RecoveryInformationGapV1::None,
        }
    };
    match class {
        RecoveryFailureClassV1::UnsafeSideEffect
        | RecoveryFailureClassV1::ProtectedInvariantViolation => (
            RecoveryRetryabilityV1::None,
            RecoverySafetySeverityV1::Unsafe,
            RecoveryAuthorityImpactV1::RequiresEscalation,
            information,
        ),
        RecoveryFailureClassV1::AuthorityExceeded | RecoveryFailureClassV1::PolicyUnknown => (
            RecoveryRetryabilityV1::None,
            RecoverySafetySeverityV1::Elevated,
            RecoveryAuthorityImpactV1::RequiresEscalation,
            information,
        ),
        RecoveryFailureClassV1::StaleBinding
        | RecoveryFailureClassV1::TransientObservationFailure
        | RecoveryFailureClassV1::ActivationUnavailable
        | RecoveryFailureClassV1::ExecutionTimeoutOrUnknown
        | RecoveryFailureClassV1::VerificationInconclusive
        | RecoveryFailureClassV1::AmbiguousTarget => (
            RecoveryRetryabilityV1::ReobserveOnly,
            RecoverySafetySeverityV1::Operational,
            RecoveryAuthorityImpactV1::WithinAuthority,
            information,
        ),
        RecoveryFailureClassV1::NoCandidate
        | RecoveryFailureClassV1::NoEligibleCandidate
        | RecoveryFailureClassV1::UnsupportedCapability
        | RecoveryFailureClassV1::VerificationUnsupported => (
            RecoveryRetryabilityV1::AlternateOrReplan,
            RecoverySafetySeverityV1::Operational,
            RecoveryAuthorityImpactV1::WithinAuthority,
            information,
        ),
        RecoveryFailureClassV1::ExecutionFailed
        | RecoveryFailureClassV1::PostconditionFailed
        | RecoveryFailureClassV1::ExpectedChangeMissing
        | RecoveryFailureClassV1::TargetResolutionFailed
        | RecoveryFailureClassV1::PreparationFailed => (
            RecoveryRetryabilityV1::FreshCycle,
            RecoverySafetySeverityV1::Operational,
            RecoveryAuthorityImpactV1::WithinAuthority,
            information,
        ),
        _ => (
            RecoveryRetryabilityV1::None,
            RecoverySafetySeverityV1::None,
            RecoveryAuthorityImpactV1::None,
            information,
        ),
    }
}

/// Bounded immutable recovery budget snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBudgetV1 {
    pub schema_version: u32,
    pub budget_id: String,
    pub goal_id: String,
    pub maximum_total_cycles: u32,
    pub remaining_total_cycles: u32,
    pub maximum_reobservations: u32,
    pub remaining_reobservations: u32,
    pub maximum_fresh_retries: u32,
    pub remaining_fresh_retries: u32,
    pub maximum_alternate_capability_attempts: u32,
    pub remaining_alternate_capability_attempts: u32,
    pub maximum_replans: u32,
    pub remaining_replans: u32,
    pub maximum_clarifications: u32,
    pub remaining_clarifications: u32,
    pub started_at_unix_ms: u64,
    pub deadline_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub budget_sha256: String,
}

impl RecoveryBudgetV1 {
    /// Canonically seals and validates a budget.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(&mut self.evidence_ids, "budget evidence_ids", false)?;
        self.budget_sha256 = hash_without(&self, "budget_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates all bounds and the canonical hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery budget")?;
        validate_id(&self.budget_id, "budget_id")?;
        validate_id(&self.goal_id, "budget goal_id")?;
        if self.maximum_total_cycles == 0
            || self.maximum_total_cycles > MAX_TOTAL_CYCLES
            || self.maximum_reobservations > MAX_TOTAL_CYCLES
            || self.maximum_fresh_retries > MAX_TOTAL_CYCLES
            || self.maximum_alternate_capability_attempts > MAX_TOTAL_CYCLES
            || self.maximum_replans > MAX_TOTAL_CYCLES
            || self.maximum_clarifications > MAX_TOTAL_CYCLES
            || self.remaining_total_cycles > self.maximum_total_cycles
            || self.remaining_reobservations > self.maximum_reobservations
            || self.remaining_fresh_retries > self.maximum_fresh_retries
            || self.remaining_alternate_capability_attempts
                > self.maximum_alternate_capability_attempts
            || self.remaining_replans > self.maximum_replans
            || self.remaining_clarifications > self.maximum_clarifications
            || self.started_at_unix_ms == 0
            || self.started_at_unix_ms >= self.deadline_unix_ms
        {
            return invalid("recovery budget bounds or remaining counters are invalid");
        }
        validate_sorted_strings(&self.evidence_ids, "budget evidence_ids", false)?;
        validate_hash(&self.budget_sha256, "budget_sha256")?;
        if hash_without(self, "budget_sha256")? != self.budget_sha256 {
            return integrity("budget_sha256 differs from canonical budget");
        }
        reject_forbidden_json(self, "recovery budget")
    }

    /// Returns a single atomic decision transition without increasing any counter.
    pub fn consume_for(
        &self,
        kind: RecoveryDecisionKindV1,
        decided_at_unix_ms: u64,
    ) -> Result<Self, RecoveryError> {
        self.validate()?;
        if decided_at_unix_ms < self.started_at_unix_ms {
            return invalid("decision predates the recovery budget");
        }
        if decided_at_unix_ms >= self.deadline_unix_ms
            && !matches!(
                kind,
                RecoveryDecisionKindV1::Escalate
                    | RecoveryDecisionKindV1::Stop
                    | RecoveryDecisionKindV1::NoRecoveryComplete
            )
        {
            return Err(RecoveryError::AccessDenied(
                "recovery deadline is exhausted".to_owned(),
            ));
        }
        let consumes_cycle = matches!(
            kind,
            RecoveryDecisionKindV1::Reobserve
                | RecoveryDecisionKindV1::RetryFreshCycle
                | RecoveryDecisionKindV1::SelectAlternateCapability
                | RecoveryDecisionKindV1::Replan
                | RecoveryDecisionKindV1::RequestClarification
        );
        let mut after = self.clone();
        if consumes_cycle {
            after.remaining_total_cycles = decrement(after.remaining_total_cycles, "total cycle")?;
        }
        match kind {
            RecoveryDecisionKindV1::Reobserve => {
                after.remaining_reobservations =
                    decrement(after.remaining_reobservations, "reobservation")?;
            }
            RecoveryDecisionKindV1::RetryFreshCycle => {
                after.remaining_fresh_retries =
                    decrement(after.remaining_fresh_retries, "fresh retry")?;
            }
            RecoveryDecisionKindV1::SelectAlternateCapability => {
                after.remaining_alternate_capability_attempts = decrement(
                    after.remaining_alternate_capability_attempts,
                    "alternate capability",
                )?;
            }
            RecoveryDecisionKindV1::Replan => {
                after.remaining_replans = decrement(after.remaining_replans, "replan")?;
            }
            RecoveryDecisionKindV1::RequestClarification => {
                after.remaining_clarifications =
                    decrement(after.remaining_clarifications, "clarification")?;
            }
            _ => {}
        }
        after.budget_sha256 = hash_without(&after, "budget_sha256")?;
        after.validate()?;
        after.validate_transition_from(self, kind)?;
        Ok(after)
    }

    /// Verifies that exactly the selected strategy and total-cycle counters changed.
    pub fn validate_transition_from(
        &self,
        before: &Self,
        kind: RecoveryDecisionKindV1,
    ) -> Result<(), RecoveryError> {
        before.validate()?;
        self.validate()?;
        let expected = before.consume_for_unchecked(kind)?;
        if self != &expected {
            return integrity("budget transition increased or consumed the wrong counter");
        }
        Ok(())
    }

    fn consume_for_unchecked(&self, kind: RecoveryDecisionKindV1) -> Result<Self, RecoveryError> {
        let mut after = self.clone();
        if matches!(
            kind,
            RecoveryDecisionKindV1::Reobserve
                | RecoveryDecisionKindV1::RetryFreshCycle
                | RecoveryDecisionKindV1::SelectAlternateCapability
                | RecoveryDecisionKindV1::Replan
                | RecoveryDecisionKindV1::RequestClarification
        ) {
            after.remaining_total_cycles = decrement(after.remaining_total_cycles, "total cycle")?;
        }
        match kind {
            RecoveryDecisionKindV1::Reobserve => {
                after.remaining_reobservations =
                    decrement(after.remaining_reobservations, "reobservation")?;
            }
            RecoveryDecisionKindV1::RetryFreshCycle => {
                after.remaining_fresh_retries =
                    decrement(after.remaining_fresh_retries, "fresh retry")?;
            }
            RecoveryDecisionKindV1::SelectAlternateCapability => {
                after.remaining_alternate_capability_attempts = decrement(
                    after.remaining_alternate_capability_attempts,
                    "alternate capability",
                )?;
            }
            RecoveryDecisionKindV1::Replan => {
                after.remaining_replans = decrement(after.remaining_replans, "replan")?;
            }
            RecoveryDecisionKindV1::RequestClarification => {
                after.remaining_clarifications =
                    decrement(after.remaining_clarifications, "clarification")?;
            }
            _ => {}
        }
        after.budget_sha256 = hash_without(&after, "budget_sha256")?;
        Ok(after)
    }
}

fn decrement(value: u32, label: &str) -> Result<u32, RecoveryError> {
    value
        .checked_sub(1)
        .ok_or_else(|| RecoveryError::AccessDenied(format!("{label} recovery budget is exhausted")))
}

/// Terminal outcome retained for one recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHistoryOutcomeV1 {
    Passed,
    Failed,
    Inconclusive,
    Unsupported,
    Unsafe,
    ClarificationPending,
    Escalated,
    Stopped,
}

/// Canonical record for one attempted recovery cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHistoryEntryV1 {
    pub schema_version: u32,
    pub cycle_index: u32,
    pub trigger_sha256: String,
    pub classification_sha256: String,
    pub decision_sha256: String,
    pub plan_generation_id: Option<String>,
    pub proposal_id: Option<String>,
    pub proposal_sha256: Option<String>,
    pub capability_id: Option<String>,
    pub input_sha256: Option<String>,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub fresh_observation_hash: Option<String>,
    pub fresh_observation_sequence: Option<u64>,
    pub policy_decision_sha256: Option<String>,
    pub cognitive_admission_sha256: Option<String>,
    pub activation_record_hash: Option<String>,
    pub execution_receipt_sha256: Option<String>,
    pub verified_action_result_sha256: Option<String>,
    pub terminal_outcome: RecoveryHistoryOutcomeV1,
    pub evidence_ids: Vec<String>,
    pub entry_sha256: String,
}

impl RecoveryHistoryEntryV1 {
    /// Canonically seals one bounded history entry.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(&mut self.evidence_ids, "history evidence_ids", false)?;
        self.entry_sha256 = hash_without(&self, "entry_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates entry shape and canonical identity.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery history entry")?;
        if self.cycle_index == 0 || self.cycle_index > MAX_RECOVERY_CYCLES as u32 {
            return invalid("history cycle_index is outside 1..=64");
        }
        for (hash, label) in [
            (&self.trigger_sha256, "history trigger_sha256"),
            (&self.classification_sha256, "history classification_sha256"),
            (&self.decision_sha256, "history decision_sha256"),
            (
                &self.source_observation_hash,
                "history source_observation_hash",
            ),
        ] {
            validate_hash(hash, label)?;
        }
        validate_optional_id(&self.plan_generation_id, "history plan_generation_id")?;
        validate_optional_id(&self.proposal_id, "history proposal_id")?;
        validate_optional_hash(&self.proposal_sha256, "history proposal_sha256")?;
        validate_optional_id(&self.capability_id, "history capability_id")?;
        validate_optional_hash(&self.input_sha256, "history input_sha256")?;
        for (value, label) in [
            (
                &self.fresh_observation_hash,
                "history fresh_observation_hash",
            ),
            (
                &self.policy_decision_sha256,
                "history policy_decision_sha256",
            ),
            (
                &self.cognitive_admission_sha256,
                "history cognitive_admission_sha256",
            ),
            (
                &self.activation_record_hash,
                "history activation_record_hash",
            ),
            (
                &self.execution_receipt_sha256,
                "history execution_receipt_sha256",
            ),
            (
                &self.verified_action_result_sha256,
                "history verified_action_result_sha256",
            ),
        ] {
            validate_optional_hash(value, label)?;
        }
        if self.proposal_id.is_some() != self.proposal_sha256.is_some()
            || self.proposal_id.is_some() != self.capability_id.is_some()
            || self.fresh_observation_hash.is_some() != self.fresh_observation_sequence.is_some()
        {
            return invalid("history proposal or fresh observation fields are incomplete");
        }
        if self
            .fresh_observation_sequence
            .is_some_and(|sequence| sequence <= self.source_observation_sequence)
        {
            return integrity("history fresh observation sequence is not newer");
        }
        validate_sorted_strings(&self.evidence_ids, "history evidence_ids", false)?;
        validate_hash(&self.entry_sha256, "entry_sha256")?;
        if hash_without(self, "entry_sha256")? != self.entry_sha256 {
            return integrity("entry_sha256 differs from canonical history entry");
        }
        reject_forbidden_json(self, "recovery history entry")
    }

    fn failure_fingerprint(&self) -> Option<(String, String, String)> {
        Some((
            self.source_observation_hash.clone(),
            self.capability_id.clone()?,
            self.input_sha256.clone()?,
        ))
    }
}

/// Canonical bounded history and all one-shot identities consumed by recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHistoryV1 {
    pub schema_version: u32,
    pub history_id: String,
    pub goal_id: String,
    pub entries: Vec<RecoveryHistoryEntryV1>,
    pub consumed_proposal_ids: Vec<String>,
    pub consumed_proposal_hashes: Vec<String>,
    pub consumed_admission_hashes: Vec<String>,
    pub consumed_activation_record_hashes: Vec<String>,
    pub consumed_execution_receipt_hashes: Vec<String>,
    pub history_sha256: String,
}

impl RecoveryHistoryV1 {
    /// Creates an empty canonical history.
    pub fn empty(history_id: String, goal_id: String) -> Result<Self, RecoveryError> {
        let mut history = Self {
            schema_version: RECOVERY_SCHEMA_VERSION,
            history_id,
            goal_id,
            entries: Vec::new(),
            consumed_proposal_ids: Vec::new(),
            consumed_proposal_hashes: Vec::new(),
            consumed_admission_hashes: Vec::new(),
            consumed_activation_record_hashes: Vec::new(),
            consumed_execution_receipt_hashes: Vec::new(),
            history_sha256: empty_hash(),
        };
        history.history_sha256 = hash_without(&history, "history_sha256")?;
        history.validate()?;
        Ok(history)
    }

    /// Appends one cycle and rejects replay, non-monotonic observation, and blind loops.
    pub fn append(&self, entry: RecoveryHistoryEntryV1) -> Result<Self, RecoveryError> {
        self.validate()?;
        entry.validate()?;
        if self.entries.len() >= MAX_RECOVERY_CYCLES
            || entry.cycle_index as usize != self.entries.len().saturating_add(1)
        {
            return invalid("history cycle is non-sequential or exceeds 64 entries");
        }
        if self.entries.last().is_some_and(|last| {
            entry.source_observation_sequence <= last.source_observation_sequence
        }) {
            return integrity("history observation sequence is not monotonic");
        }
        if let Some(fingerprint) = entry.failure_fingerprint() {
            if self
                .entries
                .iter()
                .filter_map(RecoveryHistoryEntryV1::failure_fingerprint)
                .any(|existing| existing == fingerprint)
            {
                return Err(RecoveryError::AccessDenied(
                    "same state, capability, and input failure fingerprint was repeated".to_owned(),
                ));
            }
        }
        let mut next = self.clone();
        push_optional_unique(
            &mut next.consumed_proposal_ids,
            &entry.proposal_id,
            "proposal ID",
        )?;
        push_optional_unique(
            &mut next.consumed_proposal_hashes,
            &entry.proposal_sha256,
            "proposal hash",
        )?;
        push_optional_unique(
            &mut next.consumed_admission_hashes,
            &entry.cognitive_admission_sha256,
            "admission hash",
        )?;
        push_optional_unique(
            &mut next.consumed_activation_record_hashes,
            &entry.activation_record_hash,
            "activation record hash",
        )?;
        push_optional_unique(
            &mut next.consumed_execution_receipt_hashes,
            &entry.execution_receipt_sha256,
            "execution receipt hash",
        )?;
        next.entries.push(entry);
        next.history_sha256 = hash_without(&next, "history_sha256")?;
        next.validate()?;
        Ok(next)
    }

    /// Fully verifies entries, consumed sets, sequence, replay, and canonical hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery history")?;
        validate_id(&self.history_id, "history_id")?;
        validate_id(&self.goal_id, "history goal_id")?;
        if self.entries.len() > MAX_RECOVERY_CYCLES {
            return invalid("recovery history exceeds 64 entries");
        }
        let mut prior_sequence = None;
        let mut proposal_ids = BTreeSet::new();
        let mut proposal_hashes = BTreeSet::new();
        let mut admissions = BTreeSet::new();
        let mut activations = BTreeSet::new();
        let mut receipts = BTreeSet::new();
        let mut fingerprints = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            entry.validate()?;
            if entry.cycle_index as usize != index.saturating_add(1)
                || prior_sequence.is_some_and(|value| entry.source_observation_sequence <= value)
            {
                return integrity("history cycle index or observation sequence is not monotonic");
            }
            prior_sequence = Some(entry.source_observation_sequence);
            insert_optional(&mut proposal_ids, &entry.proposal_id, "proposal ID")?;
            insert_optional(
                &mut proposal_hashes,
                &entry.proposal_sha256,
                "proposal hash",
            )?;
            insert_optional(
                &mut admissions,
                &entry.cognitive_admission_sha256,
                "admission hash",
            )?;
            insert_optional(
                &mut activations,
                &entry.activation_record_hash,
                "activation record hash",
            )?;
            insert_optional(
                &mut receipts,
                &entry.execution_receipt_sha256,
                "execution receipt hash",
            )?;
            if entry
                .failure_fingerprint()
                .is_some_and(|value| !fingerprints.insert(value))
            {
                return Err(RecoveryError::AccessDenied(
                    "history repeats an identical failure fingerprint".to_owned(),
                ));
            }
        }
        compare_set(&proposal_ids, &self.consumed_proposal_ids, "proposal IDs")?;
        compare_set(
            &proposal_hashes,
            &self.consumed_proposal_hashes,
            "proposal hashes",
        )?;
        compare_set(
            &admissions,
            &self.consumed_admission_hashes,
            "admission hashes",
        )?;
        compare_set(
            &activations,
            &self.consumed_activation_record_hashes,
            "activation hashes",
        )?;
        compare_set(
            &receipts,
            &self.consumed_execution_receipt_hashes,
            "receipt hashes",
        )?;
        validate_hash(&self.history_sha256, "history_sha256")?;
        if hash_without(self, "history_sha256")? != self.history_sha256 {
            return integrity("history_sha256 differs from canonical history");
        }
        reject_forbidden_json(self, "recovery history")
    }
}

fn push_optional_unique(
    values: &mut Vec<String>,
    value: &Option<String>,
    label: &str,
) -> Result<(), RecoveryError> {
    if let Some(value) = value {
        if values.binary_search(value).is_ok() {
            return Err(RecoveryError::AccessDenied(format!(
                "recovery reused consumed {label}"
            )));
        }
        values.push(value.clone());
        values.sort();
    }
    Ok(())
}

fn insert_optional(
    values: &mut BTreeSet<String>,
    value: &Option<String>,
    label: &str,
) -> Result<(), RecoveryError> {
    if value
        .as_ref()
        .is_some_and(|value| !values.insert(value.clone()))
    {
        return Err(RecoveryError::AccessDenied(format!(
            "recovery history reused {label}"
        )));
    }
    Ok(())
}

fn compare_set(
    expected: &BTreeSet<String>,
    actual: &[String],
    label: &str,
) -> Result<(), RecoveryError> {
    validate_sorted_strings(actual, label, true)?;
    if expected.iter().cloned().collect::<Vec<_>>() != actual {
        return integrity(&format!("history consumed {label} set differs"));
    }
    Ok(())
}

/// One policy-approved group of interchangeable capabilities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateCapabilityGroupV1 {
    pub group_id: String,
    pub capability_ids: Vec<String>,
}

impl AlternateCapabilityGroupV1 {
    fn validate(&self) -> Result<(), RecoveryError> {
        validate_id(&self.group_id, "alternate capability group_id")?;
        validate_sorted_strings(&self.capability_ids, "alternate capability IDs", false)
    }
}

/// Trusted, policy- and authority-bound recovery strategy profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub policy_set_sha256: String,
    pub authority_sha256: String,
    pub retryable_failure_classes: Vec<RecoveryFailureClassV1>,
    pub reobservable_failure_classes: Vec<RecoveryFailureClassV1>,
    pub alternate_capability_failure_classes: Vec<RecoveryFailureClassV1>,
    pub replannable_failure_classes: Vec<RecoveryFailureClassV1>,
    pub clarifiable_failure_classes: Vec<RecoveryFailureClassV1>,
    pub mandatory_escalation_failure_classes: Vec<RecoveryFailureClassV1>,
    pub forbidden_automatic_failure_classes: Vec<RecoveryFailureClassV1>,
    pub retryable_capability_ids: Vec<String>,
    pub alternate_capability_groups: Vec<AlternateCapabilityGroupV1>,
    pub maximum_same_capability_attempts: u32,
    pub allow_replan: bool,
    pub allow_clarification: bool,
    pub escalation_risk_threshold: CognitiveRiskClass,
    pub evidence_ids: Vec<String>,
    pub profile_sha256: String,
}

impl RecoveryPolicyProfileV1 {
    /// Canonically seals set-like profile collections.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        for (values, label) in [
            (
                &mut self.retryable_failure_classes,
                "retryable failure classes",
            ),
            (
                &mut self.reobservable_failure_classes,
                "reobservable failure classes",
            ),
            (
                &mut self.alternate_capability_failure_classes,
                "alternate failure classes",
            ),
            (
                &mut self.replannable_failure_classes,
                "replannable failure classes",
            ),
            (
                &mut self.clarifiable_failure_classes,
                "clarifiable failure classes",
            ),
            (
                &mut self.mandatory_escalation_failure_classes,
                "mandatory escalation classes",
            ),
            (
                &mut self.forbidden_automatic_failure_classes,
                "forbidden automatic classes",
            ),
        ] {
            canonicalize_set(values, label, true)?;
        }
        canonicalize_strings(
            &mut self.retryable_capability_ids,
            "retryable capability IDs",
            true,
        )?;
        for group in &mut self.alternate_capability_groups {
            canonicalize_strings(&mut group.capability_ids, "alternate capability IDs", false)?;
        }
        self.alternate_capability_groups.sort();
        canonicalize_strings(&mut self.evidence_ids, "profile evidence_ids", false)?;
        self.profile_sha256 = hash_without(&self, "profile_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates mandatory safety classes, bounds, and canonical profile hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery policy profile")?;
        validate_id(&self.profile_id, "recovery profile_id")?;
        validate_hash(&self.policy_set_sha256, "profile policy_set_sha256")?;
        validate_hash(&self.authority_sha256, "profile authority_sha256")?;
        for (values, label) in [
            (&self.retryable_failure_classes, "retryable failure classes"),
            (
                &self.reobservable_failure_classes,
                "reobservable failure classes",
            ),
            (
                &self.alternate_capability_failure_classes,
                "alternate failure classes",
            ),
            (
                &self.replannable_failure_classes,
                "replannable failure classes",
            ),
            (
                &self.clarifiable_failure_classes,
                "clarifiable failure classes",
            ),
            (
                &self.mandatory_escalation_failure_classes,
                "mandatory escalation classes",
            ),
            (
                &self.forbidden_automatic_failure_classes,
                "forbidden automatic classes",
            ),
        ] {
            validate_sorted_set(values, label, true)?;
        }
        validate_sorted_strings(
            &self.retryable_capability_ids,
            "retryable capability IDs",
            true,
        )?;
        if self.alternate_capability_groups.len() > MAX_ITEMS
            || !self
                .alternate_capability_groups
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            || self.maximum_same_capability_attempts == 0
            || self.maximum_same_capability_attempts > MAX_TOTAL_CYCLES
        {
            return invalid("recovery profile group or attempt bounds are invalid");
        }
        let mut alternate_ids = BTreeSet::new();
        for group in &self.alternate_capability_groups {
            group.validate()?;
            for capability in &group.capability_ids {
                if !alternate_ids.insert(capability) {
                    return invalid("capability appears in multiple alternate groups");
                }
            }
        }
        for mandatory in [
            RecoveryFailureClassV1::UnsafeSideEffect,
            RecoveryFailureClassV1::ProtectedInvariantViolation,
        ] {
            if !self
                .mandatory_escalation_failure_classes
                .contains(&mandatory)
                || !self
                    .forbidden_automatic_failure_classes
                    .contains(&mandatory)
            {
                return invalid("unsafe classes must require escalation and forbid automation");
            }
        }
        for denied in [
            RecoveryFailureClassV1::PolicyDenied,
            RecoveryFailureClassV1::PolicyUnknown,
            RecoveryFailureClassV1::AuthorityExceeded,
        ] {
            if self.retryable_failure_classes.contains(&denied) {
                return invalid("policy or authority failures cannot be retryable");
            }
        }
        validate_sorted_strings(&self.evidence_ids, "profile evidence_ids", false)?;
        validate_hash(&self.profile_sha256, "profile_sha256")?;
        if hash_without(self, "profile_sha256")? != self.profile_sha256 {
            return integrity("profile_sha256 differs from canonical profile");
        }
        reject_forbidden_json(self, "recovery policy profile")
    }

    /// Verifies exact trusted-policy/authority binding and capability scope.
    pub fn validate_against(
        &self,
        policy_set_sha256: &str,
        authority_sha256: &str,
        authorized_capability_ids: &BTreeSet<String>,
    ) -> Result<(), RecoveryError> {
        self.validate()?;
        validate_hash(policy_set_sha256, "trusted policy set hash")?;
        validate_hash(authority_sha256, "delegated authority hash")?;
        if self.policy_set_sha256 != policy_set_sha256
            || self.authority_sha256 != authority_sha256
            || self
                .retryable_capability_ids
                .iter()
                .any(|capability| !authorized_capability_ids.contains(capability))
            || self.alternate_capability_groups.iter().any(|group| {
                group
                    .capability_ids
                    .iter()
                    .any(|capability| !authorized_capability_ids.contains(capability))
            })
        {
            return Err(RecoveryError::AccessDenied(
                "recovery profile exceeds trusted policy or delegated authority".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Additive KRN-400 recovery decision kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDecisionKindV1 {
    ContinueExecution,
    NoRecoveryComplete,
    Reobserve,
    RetryFreshCycle,
    SelectAlternateCapability,
    Replan,
    RequestClarification,
    Escalate,
    Stop,
}

/// Existing-verification verdict normalized for pure recovery policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryVerificationVerdictV1 {
    Passed,
    Failed,
    Inconclusive,
    Unsupported,
    Unsafe,
}

/// Explicit deterministic inputs not derived from model or UI text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryDecisionContextV1 {
    pub verification_verdict: Option<RecoveryVerificationVerdictV1>,
    pub goal_progress: GoalProgress,
    pub latest_observation_trusted: bool,
    pub bounded_user_fact_missing: bool,
    pub same_failure_count: u32,
    pub same_capability_attempts: u32,
    pub current_proposal_id: Option<String>,
    pub current_proposal_sha256: Option<String>,
    pub current_capability_id: Option<String>,
    pub current_risk: CognitiveRiskClass,
    pub alternate_capability_ids: Vec<String>,
    pub replan_available: bool,
}

impl RecoveryDecisionContextV1 {
    fn validate(&self) -> Result<(), RecoveryError> {
        validate_optional_id(&self.current_proposal_id, "context proposal_id")?;
        validate_optional_hash(&self.current_proposal_sha256, "context proposal_sha256")?;
        validate_optional_id(&self.current_capability_id, "context capability_id")?;
        if self.current_proposal_id.is_some() != self.current_proposal_sha256.is_some()
            || self.current_proposal_id.is_some() != self.current_capability_id.is_some()
            || self.same_failure_count > MAX_TOTAL_CYCLES
            || self.same_capability_attempts > MAX_TOTAL_CYCLES
        {
            return invalid("recovery decision context lifecycle or attempt count is invalid");
        }
        validate_sorted_strings(
            &self.alternate_capability_ids,
            "context alternate capabilities",
            true,
        )
    }
}

/// Deterministic recovery decision that carries no execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecisionV1 {
    pub schema_version: u32,
    pub recovery_id: String,
    pub trigger_sha256: String,
    pub classification_sha256: String,
    pub budget_before_sha256: String,
    pub budget_after: RecoveryBudgetV1,
    pub history_sha256: String,
    pub decision_kind: RecoveryDecisionKindV1,
    pub reason_codes: Vec<RecoveryReasonCodeV1>,
    pub excluded_proposal_ids: Vec<String>,
    pub excluded_proposal_hashes: Vec<String>,
    pub excluded_capability_ids: Vec<String>,
    pub required_new_observation: bool,
    pub required_new_selection: bool,
    pub required_new_policy_admission: bool,
    pub required_new_platform_activation: bool,
    pub required_new_plan_generation: bool,
    pub clarification_request_sha256: Option<String>,
    pub escalation_request_sha256: Option<String>,
    pub replan_request_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub decided_at_unix_ms: u64,
    pub decision_sha256: String,
}

impl RecoveryDecisionV1 {
    /// Validates exact trigger/classification/budget/history binding and strategy shape.
    pub fn validate_against(
        &self,
        trigger: &RecoveryTriggerV1,
        classification: &RecoveryClassificationV1,
        budget_before: &RecoveryBudgetV1,
        history: &RecoveryHistoryV1,
    ) -> Result<(), RecoveryError> {
        trigger.validate()?;
        classification.validate_against(trigger)?;
        budget_before.validate()?;
        history.validate()?;
        validate_schema(self.schema_version, "recovery decision")?;
        validate_id(&self.recovery_id, "recovery_id")?;
        for (hash, label) in [
            (&self.trigger_sha256, "decision trigger_sha256"),
            (
                &self.classification_sha256,
                "decision classification_sha256",
            ),
            (&self.budget_before_sha256, "decision budget_before_sha256"),
            (&self.history_sha256, "decision history_sha256"),
        ] {
            validate_hash(hash, label)?;
        }
        if self.trigger_sha256 != trigger.trigger_sha256
            || self.classification_sha256 != classification.classification_sha256
            || self.budget_before_sha256 != budget_before.budget_sha256
            || self.history_sha256 != history.history_sha256
            || self.reason_codes != classification.reason_codes
            || self.budget_after.goal_id != trigger.goal_id
            || history.goal_id != trigger.goal_id
        {
            return integrity("recovery decision exact context binding differs");
        }
        self.budget_after
            .validate_transition_from(budget_before, self.decision_kind)?;
        validate_sorted_set(&self.reason_codes, "decision reason_codes", false)?;
        validate_sorted_strings(&self.excluded_proposal_ids, "excluded proposal IDs", true)?;
        validate_hash_vec(
            &self.excluded_proposal_hashes,
            "excluded proposal hashes",
            true,
        )?;
        validate_sorted_strings(
            &self.excluded_capability_ids,
            "excluded capability IDs",
            true,
        )?;
        validate_sorted_strings(&self.evidence_ids, "decision evidence_ids", false)?;
        for (value, label) in [
            (
                &self.clarification_request_sha256,
                "clarification_request_sha256",
            ),
            (&self.escalation_request_sha256, "escalation_request_sha256"),
            (&self.replan_request_sha256, "replan_request_sha256"),
        ] {
            validate_optional_hash(value, label)?;
        }
        if self.decided_at_unix_ms < trigger.detected_at_unix_ms {
            return invalid("decision predates its trigger");
        }
        let expected_requirements = decision_requirements(self.decision_kind);
        if (
            self.required_new_observation,
            self.required_new_selection,
            self.required_new_policy_admission,
            self.required_new_platform_activation,
            self.required_new_plan_generation,
        ) != expected_requirements
        {
            return integrity("decision fresh-cycle requirements differ from its strategy");
        }
        if matches!(
            classification.primary_class,
            RecoveryFailureClassV1::UnsafeSideEffect
                | RecoveryFailureClassV1::ProtectedInvariantViolation
        ) && !matches!(
            self.decision_kind,
            RecoveryDecisionKindV1::Escalate | RecoveryDecisionKindV1::Stop
        ) {
            return Err(RecoveryError::AccessDenied(
                "unsafe recovery may only escalate or stop".to_owned(),
            ));
        }
        if self.decision_kind == RecoveryDecisionKindV1::SelectAlternateCapability
            && self.excluded_capability_ids.is_empty()
        {
            return invalid("alternate capability decision must exclude the failed capability");
        }
        validate_hash(&self.decision_sha256, "decision_sha256")?;
        if hash_without(self, "decision_sha256")? != self.decision_sha256 {
            return integrity("decision_sha256 differs from canonical decision");
        }
        reject_forbidden_json(self, "recovery decision")
    }
}

fn decision_requirements(kind: RecoveryDecisionKindV1) -> (bool, bool, bool, bool, bool) {
    match kind {
        RecoveryDecisionKindV1::Reobserve => (true, false, false, false, false),
        RecoveryDecisionKindV1::RetryFreshCycle
        | RecoveryDecisionKindV1::SelectAlternateCapability => (true, true, true, true, false),
        RecoveryDecisionKindV1::Replan => (true, true, true, true, true),
        _ => (false, false, false, false, false),
    }
}

/// Deterministically chooses one bounded recovery strategy.
#[allow(clippy::too_many_arguments)]
pub fn decide_recovery(
    recovery_id: String,
    trigger: &RecoveryTriggerV1,
    classification: &RecoveryClassificationV1,
    budget: &RecoveryBudgetV1,
    history: &RecoveryHistoryV1,
    profile: &RecoveryPolicyProfileV1,
    context: &RecoveryDecisionContextV1,
    decided_at_unix_ms: u64,
    evidence_ids: Vec<String>,
) -> Result<RecoveryDecisionV1, RecoveryError> {
    trigger.validate()?;
    classification.validate_against(trigger)?;
    budget.validate()?;
    history.validate()?;
    profile.validate()?;
    context.validate()?;
    if trigger.goal_id != budget.goal_id || trigger.goal_id != history.goal_id {
        return integrity("recovery decision goal binding differs");
    }
    let class = classification.primary_class;
    let risk_escalates =
        risk_rank(context.current_risk) >= risk_rank(profile.escalation_risk_threshold);
    let mandatory_escalation = profile
        .mandatory_escalation_failure_classes
        .contains(&class)
        || class == RecoveryFailureClassV1::PolicyUnknown
        || class == RecoveryFailureClassV1::AuthorityExceeded
        || risk_escalates;
    let forbidden_automatic = profile.forbidden_automatic_failure_classes.contains(&class);
    let has_alternate = context
        .current_capability_id
        .as_ref()
        .is_some_and(|failed| {
            context
                .alternate_capability_ids
                .iter()
                .any(|candidate| candidate != failed)
        });
    let can_reobserve = profile.reobservable_failure_classes.contains(&class)
        && budget.remaining_reobservations > 0
        && context.latest_observation_trusted;
    let can_retry = profile.retryable_failure_classes.contains(&class)
        && context
            .current_capability_id
            .as_ref()
            .is_some_and(|capability| profile.retryable_capability_ids.contains(capability))
        && budget.remaining_fresh_retries > 0
        && context.same_capability_attempts < profile.maximum_same_capability_attempts
        && context.latest_observation_trusted;
    let can_alternate = profile
        .alternate_capability_failure_classes
        .contains(&class)
        && budget.remaining_alternate_capability_attempts > 0
        && has_alternate
        && context.latest_observation_trusted;
    let can_replan = profile.allow_replan
        && profile.replannable_failure_classes.contains(&class)
        && budget.remaining_replans > 0
        && context.replan_available;
    let can_clarify = profile.allow_clarification
        && profile.clarifiable_failure_classes.contains(&class)
        && budget.remaining_clarifications > 0
        && context.bounded_user_fact_missing;

    let kind = if context.verification_verdict == Some(RecoveryVerificationVerdictV1::Passed)
        && context.goal_progress == GoalProgress::Complete
    {
        RecoveryDecisionKindV1::NoRecoveryComplete
    } else if context.verification_verdict == Some(RecoveryVerificationVerdictV1::Passed)
        && context.goal_progress == GoalProgress::InProgress
    {
        RecoveryDecisionKindV1::ContinueExecution
    } else if mandatory_escalation {
        RecoveryDecisionKindV1::Escalate
    } else if matches!(
        class,
        RecoveryFailureClassV1::PolicyDenied | RecoveryFailureClassV1::BudgetExhausted
    ) || budget.remaining_total_cycles == 0
    {
        RecoveryDecisionKindV1::Stop
    } else if forbidden_automatic {
        RecoveryDecisionKindV1::Escalate
    } else {
        match class {
            RecoveryFailureClassV1::StaleBinding
            | RecoveryFailureClassV1::ActivationUnavailable
            | RecoveryFailureClassV1::ExecutionTimeoutOrUnknown
                if can_reobserve =>
            {
                RecoveryDecisionKindV1::Reobserve
            }
            RecoveryFailureClassV1::VerificationInconclusive
            | RecoveryFailureClassV1::TransientObservationFailure
                if can_reobserve =>
            {
                RecoveryDecisionKindV1::Reobserve
            }
            RecoveryFailureClassV1::AmbiguousTarget
                if context.same_failure_count == 0 && can_reobserve =>
            {
                RecoveryDecisionKindV1::Reobserve
            }
            RecoveryFailureClassV1::AmbiguousTarget
            | RecoveryFailureClassV1::ClarificationRequired
                if can_clarify =>
            {
                RecoveryDecisionKindV1::RequestClarification
            }
            RecoveryFailureClassV1::ExecutionFailed
            | RecoveryFailureClassV1::PostconditionFailed
            | RecoveryFailureClassV1::ExpectedChangeMissing
            | RecoveryFailureClassV1::TargetResolutionFailed
            | RecoveryFailureClassV1::PreparationFailed
                if can_retry =>
            {
                RecoveryDecisionKindV1::RetryFreshCycle
            }
            RecoveryFailureClassV1::UnsupportedCapability
            | RecoveryFailureClassV1::VerificationUnsupported
            | RecoveryFailureClassV1::NoCandidate
            | RecoveryFailureClassV1::NoEligibleCandidate
                if can_alternate =>
            {
                RecoveryDecisionKindV1::SelectAlternateCapability
            }
            RecoveryFailureClassV1::ExecutionFailed
            | RecoveryFailureClassV1::PostconditionFailed
            | RecoveryFailureClassV1::ExpectedChangeMissing
                if context.same_capability_attempts >= profile.maximum_same_capability_attempts
                    && can_alternate =>
            {
                RecoveryDecisionKindV1::SelectAlternateCapability
            }
            _ if can_replan => RecoveryDecisionKindV1::Replan,
            _ if can_clarify => RecoveryDecisionKindV1::RequestClarification,
            RecoveryFailureClassV1::PolicyUnknown
            | RecoveryFailureClassV1::AuthorityExceeded
            | RecoveryFailureClassV1::VerificationInconclusive => RecoveryDecisionKindV1::Escalate,
            _ => RecoveryDecisionKindV1::Stop,
        }
    };
    let budget_after = budget.consume_for(kind, decided_at_unix_ms)?;
    let mut excluded_proposal_ids = Vec::new();
    let mut excluded_proposal_hashes = Vec::new();
    let mut excluded_capability_ids = Vec::new();
    if matches!(
        kind,
        RecoveryDecisionKindV1::RetryFreshCycle
            | RecoveryDecisionKindV1::SelectAlternateCapability
            | RecoveryDecisionKindV1::Replan
    ) {
        if let Some(value) = &context.current_proposal_id {
            excluded_proposal_ids.push(value.clone());
        }
        if let Some(value) = &context.current_proposal_sha256 {
            excluded_proposal_hashes.push(value.clone());
        }
    }
    if matches!(
        kind,
        RecoveryDecisionKindV1::SelectAlternateCapability | RecoveryDecisionKindV1::Replan
    ) {
        if let Some(value) = &context.current_capability_id {
            excluded_capability_ids.push(value.clone());
        }
    }
    let requirements = decision_requirements(kind);
    let mut evidence_ids = evidence_ids;
    canonicalize_strings(&mut evidence_ids, "decision evidence_ids", false)?;
    let mut decision = RecoveryDecisionV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        recovery_id,
        trigger_sha256: trigger.trigger_sha256.clone(),
        classification_sha256: classification.classification_sha256.clone(),
        budget_before_sha256: budget.budget_sha256.clone(),
        budget_after,
        history_sha256: history.history_sha256.clone(),
        decision_kind: kind,
        reason_codes: classification.reason_codes.clone(),
        excluded_proposal_ids,
        excluded_proposal_hashes,
        excluded_capability_ids,
        required_new_observation: requirements.0,
        required_new_selection: requirements.1,
        required_new_policy_admission: requirements.2,
        required_new_platform_activation: requirements.3,
        required_new_plan_generation: requirements.4,
        clarification_request_sha256: None,
        escalation_request_sha256: None,
        replan_request_sha256: None,
        evidence_ids,
        decided_at_unix_ms,
        decision_sha256: empty_hash(),
    };
    decision.decision_sha256 = hash_without(&decision, "decision_sha256")?;
    decision.validate_against(trigger, classification, budget, history)?;
    Ok(decision)
}

fn risk_rank(risk: CognitiveRiskClass) -> u8 {
    match risk {
        CognitiveRiskClass::ReadOnly => 0,
        CognitiveRiskClass::Reversible => 1,
        CognitiveRiskClass::BusinessStateChange => 2,
        CognitiveRiskClass::HighCriticality => 3,
    }
}

/// Strategy requested from a wholly fresh trust cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshRecoveryStrategyV1 {
    RetrySameCapability,
    AlternateCapability,
    Replan,
}

/// Request proving that automatic retry cannot reuse stale authority or execution material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshRecoveryCycleRequestV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub parent_recovery_decision_sha256: String,
    pub goal_id: String,
    pub previous_plan_generation_id: String,
    pub previous_proposal_sha256: Option<String>,
    pub previous_capability_id: Option<String>,
    pub latest_observation_id: String,
    pub latest_observation_hash: String,
    pub latest_observation_sequence: u64,
    pub excluded_proposal_ids: Vec<String>,
    pub excluded_proposal_hashes: Vec<String>,
    pub excluded_capability_ids: Vec<String>,
    pub required_strategy: FreshRecoveryStrategyV1,
    pub budget_sha256: String,
    pub history_sha256: String,
    pub authority_sha256: String,
    pub policy_snapshot_sha256: String,
    pub requested_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub cycle_request_sha256: String,
}

impl FreshRecoveryCycleRequestV1 {
    /// Materializes a strict fresh-cycle request from a retry, alternate, or replan decision.
    #[allow(clippy::too_many_arguments)]
    pub fn from_decision(
        cycle_id: String,
        decision: &RecoveryDecisionV1,
        goal_id: String,
        previous_plan_generation_id: String,
        previous_proposal_sha256: Option<String>,
        previous_capability_id: Option<String>,
        latest_observation_id: String,
        latest_observation_hash: String,
        latest_observation_sequence: u64,
        history: &RecoveryHistoryV1,
        authority_sha256: String,
        policy_snapshot_sha256: String,
        requested_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        evidence_ids: Vec<String>,
    ) -> Result<Self, RecoveryError> {
        let required_strategy = match decision.decision_kind {
            RecoveryDecisionKindV1::RetryFreshCycle => FreshRecoveryStrategyV1::RetrySameCapability,
            RecoveryDecisionKindV1::SelectAlternateCapability => {
                FreshRecoveryStrategyV1::AlternateCapability
            }
            RecoveryDecisionKindV1::Replan => FreshRecoveryStrategyV1::Replan,
            _ => return invalid("decision does not authorize a fresh recovery cycle"),
        };
        let mut request = Self {
            schema_version: RECOVERY_SCHEMA_VERSION,
            cycle_id,
            parent_recovery_decision_sha256: decision.decision_sha256.clone(),
            goal_id,
            previous_plan_generation_id,
            previous_proposal_sha256,
            previous_capability_id,
            latest_observation_id,
            latest_observation_hash,
            latest_observation_sequence,
            excluded_proposal_ids: decision.excluded_proposal_ids.clone(),
            excluded_proposal_hashes: decision.excluded_proposal_hashes.clone(),
            excluded_capability_ids: decision.excluded_capability_ids.clone(),
            required_strategy,
            budget_sha256: decision.budget_after.budget_sha256.clone(),
            history_sha256: history.history_sha256.clone(),
            authority_sha256,
            policy_snapshot_sha256,
            requested_at_unix_ms,
            expires_at_unix_ms,
            evidence_ids,
            cycle_request_sha256: empty_hash(),
        };
        canonicalize_strings(&mut request.evidence_ids, "cycle evidence_ids", false)?;
        request.cycle_request_sha256 = hash_without(&request, "cycle_request_sha256")?;
        request.validate_against(decision, history, requested_at_unix_ms)?;
        Ok(request)
    }

    /// Validates decision, history, TTL, and excluded identity binding.
    pub fn validate_against(
        &self,
        decision: &RecoveryDecisionV1,
        history: &RecoveryHistoryV1,
        now_unix_ms: u64,
    ) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "fresh recovery cycle request")?;
        validate_id(&self.cycle_id, "cycle_id")?;
        validate_hash(
            &self.parent_recovery_decision_sha256,
            "parent_recovery_decision_sha256",
        )?;
        validate_id(&self.goal_id, "cycle goal_id")?;
        validate_id(
            &self.previous_plan_generation_id,
            "previous_plan_generation_id",
        )?;
        validate_optional_hash(&self.previous_proposal_sha256, "previous_proposal_sha256")?;
        validate_optional_id(&self.previous_capability_id, "previous_capability_id")?;
        validate_id(&self.latest_observation_id, "latest_observation_id")?;
        validate_hash(&self.latest_observation_hash, "latest_observation_hash")?;
        validate_sorted_strings(
            &self.excluded_proposal_ids,
            "cycle excluded proposal IDs",
            true,
        )?;
        validate_hash_vec(
            &self.excluded_proposal_hashes,
            "cycle excluded proposal hashes",
            true,
        )?;
        validate_sorted_strings(
            &self.excluded_capability_ids,
            "cycle excluded capability IDs",
            true,
        )?;
        for (hash, label) in [
            (&self.budget_sha256, "cycle budget_sha256"),
            (&self.history_sha256, "cycle history_sha256"),
            (&self.authority_sha256, "cycle authority_sha256"),
            (&self.policy_snapshot_sha256, "cycle policy_snapshot_sha256"),
        ] {
            validate_hash(hash, label)?;
        }
        if self.parent_recovery_decision_sha256 != decision.decision_sha256
            || self.goal_id != history.goal_id
            || self.budget_sha256 != decision.budget_after.budget_sha256
            || self.history_sha256 != history.history_sha256
            || self.excluded_proposal_ids != decision.excluded_proposal_ids
            || self.excluded_proposal_hashes != decision.excluded_proposal_hashes
            || self.excluded_capability_ids != decision.excluded_capability_ids
            || self.requested_at_unix_ms == 0
            || self.requested_at_unix_ms >= self.expires_at_unix_ms
            || now_unix_ms < self.requested_at_unix_ms
            || now_unix_ms >= self.expires_at_unix_ms
        {
            return integrity("fresh cycle request binding or lifetime differs");
        }
        validate_sorted_strings(&self.evidence_ids, "cycle evidence_ids", false)?;
        validate_hash(&self.cycle_request_sha256, "cycle_request_sha256")?;
        if hash_without(self, "cycle_request_sha256")? != self.cycle_request_sha256 {
            return integrity("cycle_request_sha256 differs from canonical request");
        }
        reject_forbidden_json(self, "fresh recovery cycle request")
    }
}

/// Evidence returned only after a completely fresh KRN-100 through KRN-300 cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshRecoveryCycleEvidenceV1 {
    pub schema_version: u32,
    pub cycle_request_sha256: String,
    pub observation_id: String,
    pub observation_hash: String,
    pub observation_sequence: u64,
    pub plan_generation_id: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub capability_id: String,
    pub input_sha256: String,
    pub policy_decision_sha256: String,
    pub cognitive_admission_sha256: String,
    pub activation_record_hash: String,
    pub execution_receipt_sha256: String,
    pub verified_action_result_sha256: String,
    pub verification_verdict: RecoveryVerificationVerdictV1,
}

impl FreshRecoveryCycleEvidenceV1 {
    /// Rejects stale observation and every consumed or excluded one-shot identity.
    pub fn validate_against(
        &self,
        request: &FreshRecoveryCycleRequestV1,
        history: &RecoveryHistoryV1,
    ) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "fresh cycle evidence")?;
        for (id, label) in [
            (&self.observation_id, "fresh evidence observation_id"),
            (
                &self.plan_generation_id,
                "fresh evidence plan_generation_id",
            ),
            (&self.proposal_id, "fresh evidence proposal_id"),
            (&self.capability_id, "fresh evidence capability_id"),
        ] {
            validate_id(id, label)?;
        }
        for (hash, label) in [
            (&self.cycle_request_sha256, "fresh evidence request hash"),
            (&self.observation_hash, "fresh evidence observation hash"),
            (&self.proposal_sha256, "fresh evidence proposal hash"),
            (&self.input_sha256, "fresh evidence input hash"),
            (
                &self.policy_decision_sha256,
                "fresh evidence policy decision hash",
            ),
            (
                &self.cognitive_admission_sha256,
                "fresh evidence admission hash",
            ),
            (
                &self.activation_record_hash,
                "fresh evidence activation hash",
            ),
            (
                &self.execution_receipt_sha256,
                "fresh evidence receipt hash",
            ),
            (
                &self.verified_action_result_sha256,
                "fresh evidence verified result hash",
            ),
        ] {
            validate_hash(hash, label)?;
        }
        if self.cycle_request_sha256 != request.cycle_request_sha256
            || self.observation_id == request.latest_observation_id
            || self.observation_hash == request.latest_observation_hash
            || self.observation_sequence <= request.latest_observation_sequence
            || request.excluded_proposal_ids.contains(&self.proposal_id)
            || request
                .excluded_proposal_hashes
                .contains(&self.proposal_sha256)
            || request
                .excluded_capability_ids
                .contains(&self.capability_id)
            || history.consumed_proposal_ids.contains(&self.proposal_id)
            || history
                .consumed_proposal_hashes
                .contains(&self.proposal_sha256)
            || history
                .consumed_admission_hashes
                .contains(&self.cognitive_admission_sha256)
            || history
                .consumed_activation_record_hashes
                .contains(&self.activation_record_hash)
            || history
                .consumed_execution_receipt_hashes
                .contains(&self.execution_receipt_sha256)
        {
            return Err(RecoveryError::AccessDenied(
                "fresh cycle reused stale, excluded, or consumed trust-chain material".to_owned(),
            ));
        }
        reject_forbidden_json(self, "fresh recovery cycle evidence")
    }
}

/// Closed, non-text replan constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplanConstraintCodeV1 {
    PreserveGoal,
    StayWithinAuthority,
    ExcludeFailedProposal,
    ExcludeFailedCapability,
    ReversibleOnly,
    BoundedLoopsOnly,
}

/// Strict request for a full replacement plan graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplanRequestV1 {
    pub schema_version: u32,
    pub replan_id: String,
    pub recovery_decision_sha256: String,
    pub goal_id: String,
    pub old_plan_generation_id: String,
    pub old_plan_sha256: String,
    pub latest_observation_id: String,
    pub latest_observation_hash: String,
    pub latest_observation_sequence: u64,
    pub failure_class: RecoveryFailureClassV1,
    pub excluded_proposal_ids: Vec<String>,
    pub excluded_capability_ids: Vec<String>,
    pub authority_sha256: String,
    pub policy_snapshot_sha256: String,
    pub constraints: Vec<ReplanConstraintCodeV1>,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl ReplanRequestV1 {
    /// Canonically seals a full-plan request.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(
            &mut self.excluded_proposal_ids,
            "replan excluded proposal IDs",
            true,
        )?;
        canonicalize_strings(
            &mut self.excluded_capability_ids,
            "replan excluded capability IDs",
            true,
        )?;
        canonicalize_set(&mut self.constraints, "replan constraints", false)?;
        canonicalize_strings(&mut self.evidence_ids, "replan evidence_ids", false)?;
        self.request_sha256 = hash_without(&self, "request_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates strict identifiers, constraints, and request hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "replan request")?;
        for (id, label) in [
            (&self.replan_id, "replan_id"),
            (&self.goal_id, "replan goal_id"),
            (&self.old_plan_generation_id, "old_plan_generation_id"),
            (&self.latest_observation_id, "replan observation_id"),
        ] {
            validate_id(id, label)?;
        }
        for (hash, label) in [
            (
                &self.recovery_decision_sha256,
                "replan recovery decision hash",
            ),
            (&self.old_plan_sha256, "old_plan_sha256"),
            (&self.latest_observation_hash, "replan observation hash"),
            (&self.authority_sha256, "replan authority hash"),
            (&self.policy_snapshot_sha256, "replan policy hash"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_sorted_strings(
            &self.excluded_proposal_ids,
            "replan excluded proposal IDs",
            true,
        )?;
        validate_sorted_strings(
            &self.excluded_capability_ids,
            "replan excluded capability IDs",
            true,
        )?;
        validate_sorted_set(&self.constraints, "replan constraints", false)?;
        for required in [
            ReplanConstraintCodeV1::PreserveGoal,
            ReplanConstraintCodeV1::StayWithinAuthority,
            ReplanConstraintCodeV1::ReversibleOnly,
            ReplanConstraintCodeV1::BoundedLoopsOnly,
        ] {
            if !self.constraints.contains(&required) {
                return invalid("replan request omits a mandatory safety constraint");
            }
        }
        validate_sorted_strings(&self.evidence_ids, "replan evidence_ids", false)?;
        validate_hash(&self.request_sha256, "replan request_sha256")?;
        if hash_without(self, "request_sha256")? != self.request_sha256 {
            return integrity("replan request_sha256 differs from canonical request");
        }
        reject_forbidden_json(self, "replan request")
    }
}

/// Closed reason for a deterministic replacement plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplanRationaleCodeV1 {
    RemoveFailedCapability,
    ReplaceUnavailableStep,
    ResolveNoEligibleCandidate,
    PreserveSafeGoalPath,
}

/// Strict adapter result containing a complete new plan graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplanResultV1 {
    pub schema_version: u32,
    pub replan_id: String,
    pub request_sha256: String,
    pub new_plan_generation_id: String,
    pub new_plan: PlanGraph,
    pub new_plan_sha256: String,
    pub planner_id: String,
    pub planner_contract_version: String,
    pub rationale_code: ReplanRationaleCodeV1,
    pub evidence_ids: Vec<String>,
    pub result_sha256: String,
}

impl ReplanResultV1 {
    /// Seals a strict replacement plan result.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(&mut self.evidence_ids, "replan result evidence_ids", false)?;
        self.new_plan_sha256 = canonical_sha256(&self.new_plan)?;
        self.result_sha256 = hash_without(&self, "result_sha256")?;
        Ok(self)
    }

    /// Validates a full new DAG, generation change, exclusions, and authority scope.
    pub fn validate_against(
        &self,
        request: &ReplanRequestV1,
        authorized_capability_ids: &BTreeSet<String>,
    ) -> Result<(), RecoveryError> {
        request.validate()?;
        validate_schema(self.schema_version, "replan result")?;
        validate_id(&self.replan_id, "result replan_id")?;
        validate_hash(&self.request_sha256, "result request_sha256")?;
        validate_id(&self.new_plan_generation_id, "new_plan_generation_id")?;
        validate_id(&self.planner_id, "planner_id")?;
        validate_id(&self.planner_contract_version, "planner_contract_version")?;
        if self.replan_id != request.replan_id
            || self.request_sha256 != request.request_sha256
            || self.new_plan_generation_id == request.old_plan_generation_id
            || self.new_plan_generation_id != self.new_plan.plan_generation_id
        {
            return integrity("replan result request or generation binding differs");
        }
        self.new_plan
            .validate()
            .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
        for node in &self.new_plan.nodes {
            if node.capability_id.as_ref().is_some_and(|capability| {
                request.excluded_capability_ids.contains(capability)
                    || !authorized_capability_ids.contains(capability)
            }) {
                return Err(RecoveryError::AccessDenied(
                    "replan reintroduced an excluded or unauthorized capability".to_owned(),
                ));
            }
        }
        validate_hash(&self.new_plan_sha256, "new_plan_sha256")?;
        if canonical_sha256(&self.new_plan)? != self.new_plan_sha256 {
            return integrity("new_plan_sha256 differs from the complete PlanGraph");
        }
        validate_sorted_strings(&self.evidence_ids, "replan result evidence_ids", false)?;
        validate_hash(&self.result_sha256, "replan result_sha256")?;
        if hash_without(self, "result_sha256")? != self.result_sha256 {
            return integrity("replan result_sha256 differs from canonical result");
        }
        reject_forbidden_json(self, "replan result")
    }
}

/// Deterministic test replanner and future strict external-planner boundary.
pub struct DeterministicFixtureReplanner;

impl DeterministicFixtureReplanner {
    /// Accepts only a complete caller-supplied graph satisfying the exact replan request.
    pub fn replan(
        request: &ReplanRequestV1,
        new_plan: PlanGraph,
        planner_id: String,
        rationale_code: ReplanRationaleCodeV1,
        authorized_capability_ids: &BTreeSet<String>,
    ) -> Result<ReplanResultV1, RecoveryError> {
        request.validate()?;
        let result = ReplanResultV1 {
            schema_version: RECOVERY_SCHEMA_VERSION,
            replan_id: request.replan_id.clone(),
            request_sha256: request.request_sha256.clone(),
            new_plan_generation_id: new_plan.plan_generation_id.clone(),
            new_plan,
            new_plan_sha256: empty_hash(),
            planner_id,
            planner_contract_version: "fixture-replanner-v1".to_owned(),
            rationale_code,
            evidence_ids: vec!["deterministic-fixture-replanner".to_owned()],
            result_sha256: empty_hash(),
        }
        .seal()?;
        result.validate_against(request, authorized_capability_ids)?;
        Ok(result)
    }
}

/// Closed clarification question code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationQuestionCodeV1 {
    ConfirmTargetExists,
    ChooseSemanticTarget,
    ProvideBoundedNonSecretValue,
    ConfirmGoalConstraint,
}

/// Strict answer shape requested from an authenticated user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationQuestionKindV1 {
    Boolean,
    ChooseOne,
    BoundedNonSecretText,
}

/// One minimal, non-authority clarification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationRequestV1 {
    pub schema_version: u32,
    pub clarification_id: String,
    pub recovery_decision_sha256: String,
    pub goal_id: String,
    pub question_code: ClarificationQuestionCodeV1,
    pub question_kind: ClarificationQuestionKindV1,
    pub prompt_template_id: String,
    pub allowed_options: Vec<String>,
    pub value_schema_id: String,
    pub maximum_text_bytes: u32,
    pub sensitive_input_allowed: bool,
    pub blocks_capability_ids: Vec<String>,
    pub requested_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl ClarificationRequestV1 {
    /// Canonically seals one minimal clarification question.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(&mut self.allowed_options, "clarification options", true)?;
        canonicalize_strings(
            &mut self.blocks_capability_ids,
            "clarification blocked capabilities",
            false,
        )?;
        canonicalize_strings(&mut self.evidence_ids, "clarification evidence_ids", false)?;
        self.request_sha256 = hash_without(&self, "request_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates answer kind, bounded options, non-secret policy, TTL, and hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "clarification request")?;
        for (id, label) in [
            (&self.clarification_id, "clarification_id"),
            (&self.goal_id, "clarification goal_id"),
            (&self.prompt_template_id, "prompt_template_id"),
            (&self.value_schema_id, "value_schema_id"),
        ] {
            validate_id(id, label)?;
        }
        validate_hash(
            &self.recovery_decision_sha256,
            "clarification decision hash",
        )?;
        if self.sensitive_input_allowed
            || self.maximum_text_bytes == 0
            || self.maximum_text_bytes as usize > MAX_TEXT_BYTES
            || self.requested_at_unix_ms == 0
            || self.requested_at_unix_ms >= self.expires_at_unix_ms
        {
            return invalid("clarification sensitivity, size, or lifetime is invalid");
        }
        validate_sorted_strings(&self.allowed_options, "clarification options", true)?;
        match self.question_kind {
            ClarificationQuestionKindV1::Boolean if !self.allowed_options.is_empty() => {
                return invalid("boolean clarification cannot carry options");
            }
            ClarificationQuestionKindV1::ChooseOne
                if self.allowed_options.len() < 2 || self.allowed_options.len() > 16 =>
            {
                return invalid("choose-one clarification requires 2..=16 options");
            }
            ClarificationQuestionKindV1::BoundedNonSecretText
                if !self.allowed_options.is_empty() =>
            {
                return invalid("bounded text clarification cannot carry options");
            }
            _ => {}
        }
        validate_sorted_strings(
            &self.blocks_capability_ids,
            "clarification blocked capabilities",
            false,
        )?;
        validate_sorted_strings(&self.evidence_ids, "clarification evidence_ids", false)?;
        validate_hash(&self.request_sha256, "clarification request_sha256")?;
        if hash_without(self, "request_sha256")? != self.request_sha256 {
            return integrity("clarification request hash differs");
        }
        reject_forbidden_json(self, "clarification request")
    }
}

/// Strict clarification answer payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClarificationAnswerV1 {
    Boolean(bool),
    ChooseOne(String),
    BoundedNonSecretText(String),
}

/// One-time authenticated response to an exact clarification request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClarificationResponseV1 {
    pub schema_version: u32,
    pub response_id: String,
    pub clarification_request_sha256: String,
    pub goal_id: String,
    pub authenticated_instruction_provenance_sha256: String,
    pub answer: ClarificationAnswerV1,
    pub responded_at_unix_ms: u64,
    pub response_sha256: String,
}

impl ClarificationResponseV1 {
    /// Seals and validates an exact non-secret clarification response.
    pub fn seal(mut self, request: &ClarificationRequestV1) -> Result<Self, RecoveryError> {
        self.response_sha256 = hash_without(&self, "response_sha256")?;
        self.validate_against(request, self.responded_at_unix_ms)?;
        Ok(self)
    }

    /// Validates one-time response binding, answer type/value, TTL, and hash.
    pub fn validate_against(
        &self,
        request: &ClarificationRequestV1,
        now_unix_ms: u64,
    ) -> Result<(), RecoveryError> {
        request.validate()?;
        validate_schema(self.schema_version, "clarification response")?;
        validate_id(&self.response_id, "clarification response_id")?;
        validate_hash(
            &self.clarification_request_sha256,
            "clarification request binding",
        )?;
        validate_id(&self.goal_id, "clarification response goal_id")?;
        validate_hash(
            &self.authenticated_instruction_provenance_sha256,
            "clarification provenance hash",
        )?;
        if self.clarification_request_sha256 != request.request_sha256
            || self.goal_id != request.goal_id
            || self.responded_at_unix_ms < request.requested_at_unix_ms
            || self.responded_at_unix_ms >= request.expires_at_unix_ms
            || now_unix_ms < self.responded_at_unix_ms
            || now_unix_ms >= request.expires_at_unix_ms
        {
            return integrity("clarification response binding or lifetime differs");
        }
        match (&request.question_kind, &self.answer) {
            (ClarificationQuestionKindV1::Boolean, ClarificationAnswerV1::Boolean(_)) => {}
            (ClarificationQuestionKindV1::ChooseOne, ClarificationAnswerV1::ChooseOne(value))
                if request.allowed_options.contains(value) => {}
            (
                ClarificationQuestionKindV1::BoundedNonSecretText,
                ClarificationAnswerV1::BoundedNonSecretText(value),
            ) if !value.is_empty()
                && value.len() <= request.maximum_text_bytes as usize
                && !contains_secret_marker(value) => {}
            _ => return invalid("clarification answer type or value is not allowed"),
        }
        validate_hash(&self.response_sha256, "clarification response_sha256")?;
        if hash_without(self, "response_sha256")? != self.response_sha256 {
            return integrity("clarification response hash differs");
        }
        reject_forbidden_json(self, "clarification response")
    }
}

/// Escalation severity without a recipient-routing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationSeverityV1 {
    Operational,
    Elevated,
    High,
    Critical,
}

/// Required authority class for an escalation handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAuthorityClassV1 {
    OperationalOwner,
    PolicyOwner,
    SecurityOwner,
    LegalOrOrganizationalOwner,
}

/// Closed safe-state summary code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeStateSummaryCodeV1 {
    AutomaticMutationBlocked,
    LastObservationRetained,
    ProtectedInvariantViolated,
    StateUnknownAfterCommit,
}

/// Closed recommended next-action code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedNextActionCodeV1 {
    InspectProtectedEvidence,
    ResolvePolicyConflict,
    ReviewAuthorityScope,
    DetermineSafeManualDisposition,
}

/// Non-executable escalation handoff containing only IDs, hashes, counts, and codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationRequestV1 {
    pub schema_version: u32,
    pub escalation_id: String,
    pub recovery_decision_sha256: String,
    pub goal_id: String,
    pub severity: EscalationSeverityV1,
    pub reason_codes: Vec<RecoveryReasonCodeV1>,
    pub originating_stage: RecoveryStageV1,
    pub required_authority_class: RequiredAuthorityClassV1,
    pub blocked_capability_ids: Vec<String>,
    pub policy_set_sha256: String,
    pub authority_sha256: String,
    pub latest_observation_hash: String,
    pub verified_action_result_sha256: Option<String>,
    pub protected_violation_count: u32,
    pub unexpected_change_count: u32,
    pub safe_state_summary_codes: Vec<SafeStateSummaryCodeV1>,
    pub recommended_next_action_codes: Vec<RecommendedNextActionCodeV1>,
    pub evidence_ids: Vec<String>,
    pub raised_at_unix_ms: u64,
    pub escalation_sha256: String,
}

impl EscalationRequestV1 {
    /// Canonically seals an escalation request.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_set(&mut self.reason_codes, "escalation reason_codes", false)?;
        canonicalize_strings(
            &mut self.blocked_capability_ids,
            "escalation blocked capabilities",
            true,
        )?;
        canonicalize_set(
            &mut self.safe_state_summary_codes,
            "safe-state summary codes",
            false,
        )?;
        canonicalize_set(
            &mut self.recommended_next_action_codes,
            "recommended action codes",
            false,
        )?;
        canonicalize_strings(&mut self.evidence_ids, "escalation evidence_ids", false)?;
        self.escalation_sha256 = hash_without(&self, "escalation_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates bounded hash-only escalation evidence and canonical identity.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "escalation request")?;
        validate_id(&self.escalation_id, "escalation_id")?;
        validate_id(&self.goal_id, "escalation goal_id")?;
        for (hash, label) in [
            (&self.recovery_decision_sha256, "escalation decision hash"),
            (&self.policy_set_sha256, "escalation policy hash"),
            (&self.authority_sha256, "escalation authority hash"),
            (&self.latest_observation_hash, "escalation observation hash"),
        ] {
            validate_hash(hash, label)?;
        }
        validate_optional_hash(
            &self.verified_action_result_sha256,
            "escalation verified result hash",
        )?;
        validate_sorted_set(&self.reason_codes, "escalation reason_codes", false)?;
        validate_sorted_strings(
            &self.blocked_capability_ids,
            "escalation blocked capabilities",
            true,
        )?;
        validate_sorted_set(
            &self.safe_state_summary_codes,
            "safe-state summary codes",
            false,
        )?;
        validate_sorted_set(
            &self.recommended_next_action_codes,
            "recommended action codes",
            false,
        )?;
        validate_sorted_strings(&self.evidence_ids, "escalation evidence_ids", false)?;
        if self.raised_at_unix_ms == 0
            || matches!(
                self.severity,
                EscalationSeverityV1::High | EscalationSeverityV1::Critical
            ) && !self
                .safe_state_summary_codes
                .contains(&SafeStateSummaryCodeV1::AutomaticMutationBlocked)
        {
            return invalid("escalation time or high-risk safe-state shape is invalid");
        }
        validate_hash(&self.escalation_sha256, "escalation_sha256")?;
        if hash_without(self, "escalation_sha256")? != self.escalation_sha256 {
            return integrity("escalation hash differs from canonical request");
        }
        reject_forbidden_json(self, "escalation request")
    }
}

/// Recovery cycle terminal or handoff outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCycleOutcomeV1 {
    Completed,
    ContinuePlan,
    Recovered,
    ClarificationPending,
    Escalated,
    Stopped,
    BudgetExhausted,
    Failed,
}

/// Immutable result of one bounded recovery decision/cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCycleResultV1 {
    pub schema_version: u32,
    pub recovery_id: String,
    pub outcome: RecoveryCycleOutcomeV1,
    pub trigger_sha256: String,
    pub classification_sha256: String,
    pub decision_sha256: String,
    pub budget_before_sha256: String,
    pub budget_after_sha256: String,
    pub history_before_sha256: String,
    pub history_after_sha256: String,
    pub fresh_cycle_request_sha256: Option<String>,
    pub replan_result_sha256: Option<String>,
    pub clarification_sha256: Option<String>,
    pub escalation_sha256: Option<String>,
    pub new_proposal_sha256: Option<String>,
    pub new_admission_sha256: Option<String>,
    pub new_activation_record_hash: Option<String>,
    pub new_execution_receipt_sha256: Option<String>,
    pub new_verification_result_sha256: Option<String>,
    pub terminal_verified_result_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub result_sha256: String,
}

impl RecoveryCycleResultV1 {
    /// Canonically seals and validates a recovery cycle result.
    pub fn seal(mut self) -> Result<Self, RecoveryError> {
        canonicalize_strings(&mut self.evidence_ids, "cycle result evidence_ids", false)?;
        self.result_sha256 = hash_without(&self, "result_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates outcome-specific proof fields and canonical result hash.
    pub fn validate(&self) -> Result<(), RecoveryError> {
        validate_schema(self.schema_version, "recovery cycle result")?;
        validate_id(&self.recovery_id, "cycle result recovery_id")?;
        for (hash, label) in [
            (&self.trigger_sha256, "cycle trigger hash"),
            (&self.classification_sha256, "cycle classification hash"),
            (&self.decision_sha256, "cycle decision hash"),
            (&self.budget_before_sha256, "cycle budget before hash"),
            (&self.budget_after_sha256, "cycle budget after hash"),
            (&self.history_before_sha256, "cycle history before hash"),
            (&self.history_after_sha256, "cycle history after hash"),
        ] {
            validate_hash(hash, label)?;
        }
        for (value, label) in [
            (&self.fresh_cycle_request_sha256, "fresh cycle request hash"),
            (&self.replan_result_sha256, "replan result hash"),
            (&self.clarification_sha256, "clarification hash"),
            (&self.escalation_sha256, "escalation hash"),
            (&self.new_proposal_sha256, "new proposal hash"),
            (&self.new_admission_sha256, "new admission hash"),
            (
                &self.new_activation_record_hash,
                "new activation record hash",
            ),
            (
                &self.new_execution_receipt_sha256,
                "new execution receipt hash",
            ),
            (
                &self.new_verification_result_sha256,
                "new verification result hash",
            ),
            (
                &self.terminal_verified_result_sha256,
                "terminal verified result hash",
            ),
        ] {
            validate_optional_hash(value, label)?;
        }
        let fresh_complete = [
            self.fresh_cycle_request_sha256.is_some(),
            self.new_proposal_sha256.is_some(),
            self.new_admission_sha256.is_some(),
            self.new_activation_record_hash.is_some(),
            self.new_execution_receipt_sha256.is_some(),
            self.new_verification_result_sha256.is_some(),
            self.terminal_verified_result_sha256.is_some(),
        ]
        .into_iter()
        .all(|value| value);
        match self.outcome {
            RecoveryCycleOutcomeV1::Recovered if !fresh_complete => {
                return integrity("recovered/completed result lacks a fully verified fresh cycle");
            }
            RecoveryCycleOutcomeV1::Completed if self.terminal_verified_result_sha256.is_none() => {
                return integrity("completed result lacks a terminal verified result");
            }
            RecoveryCycleOutcomeV1::ClarificationPending if self.clarification_sha256.is_none() => {
                return invalid("clarification_pending result lacks a clarification hash");
            }
            RecoveryCycleOutcomeV1::Escalated if self.escalation_sha256.is_none() => {
                return invalid("escalated result lacks an escalation hash");
            }
            _ => {}
        }
        validate_sorted_strings(&self.evidence_ids, "cycle result evidence_ids", false)?;
        validate_hash(&self.result_sha256, "cycle result_sha256")?;
        if hash_without(self, "result_sha256")? != self.result_sha256 {
            return integrity("cycle result hash differs from canonical result");
        }
        reject_forbidden_json(self, "recovery cycle result")
    }
}

/// Projects only meaning-preserving KRN-400 decisions into the frozen legacy contract.
pub fn project_legacy_decision(
    decision: &RecoveryDecisionV1,
) -> Result<RecoveryDecision, RecoveryError> {
    let kind = match decision.decision_kind {
        RecoveryDecisionKindV1::RetryFreshCycle => CognitiveRecoveryKind::Retry,
        RecoveryDecisionKindV1::Reobserve => CognitiveRecoveryKind::Reobserve,
        RecoveryDecisionKindV1::Replan => CognitiveRecoveryKind::Replan,
        RecoveryDecisionKindV1::SelectAlternateCapability => CognitiveRecoveryKind::Fallback,
        RecoveryDecisionKindV1::RequestClarification => CognitiveRecoveryKind::RequestUserInput,
        RecoveryDecisionKindV1::Stop => CognitiveRecoveryKind::Stop,
        RecoveryDecisionKindV1::Escalate
        | RecoveryDecisionKindV1::NoRecoveryComplete
        | RecoveryDecisionKindV1::ContinueExecution => {
            return Err(RecoveryError::Unsupported(
                "decision meaning cannot be preserved by legacy RecoveryDecision".to_owned(),
            ));
        }
    };
    let replacement_plan_generation_id = (kind == CognitiveRecoveryKind::Replan)
        .then(|| format!("replan-for-{}", decision.recovery_id));
    let legacy = RecoveryDecision {
        schema_version: 1,
        kind,
        reason: format!("bounded recovery decision {}", decision.recovery_id),
        remaining_retry_budget: decision.budget_after.remaining_fresh_retries,
        evidence: vec![decision.decision_sha256.clone()],
        replacement_plan_generation_id,
    };
    legacy
        .validate()
        .map_err(|error| RecoveryError::Invalid(error.to_string()))?;
    Ok(legacy)
}

fn validate_schema(version: u32, label: &str) -> Result<(), RecoveryError> {
    if version != RECOVERY_SCHEMA_VERSION {
        return invalid(&format!(
            "{label} schema_version must be {RECOVERY_SCHEMA_VERSION}"
        ));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), RecoveryError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
        || value.contains("..")
    {
        return invalid(&format!("{label} is empty, oversized, or malformed"));
    }
    Ok(())
}

fn validate_hash(value: &str, label: &str) -> Result<(), RecoveryError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(&format!("{label} must use lowercase sha256:<hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(&format!("{label} has invalid lowercase SHA-256 syntax"));
    }
    Ok(())
}

fn validate_optional_id(value: &Option<String>, label: &str) -> Result<(), RecoveryError> {
    if let Some(value) = value {
        validate_id(value, label)?;
    }
    Ok(())
}

fn validate_optional_hash(value: &Option<String>, label: &str) -> Result<(), RecoveryError> {
    if let Some(value) = value {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_sorted_strings(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), RecoveryError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_ITEMS
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(&format!(
            "{label} is empty, duplicated, unsorted, or oversized"
        ));
    }
    for value in values {
        validate_id(value, label)?;
    }
    Ok(())
}

fn validate_hash_vec(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), RecoveryError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_ITEMS
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(&format!(
            "{label} is empty, duplicated, unsorted, or oversized"
        ));
    }
    for value in values {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_sorted_set<T: Ord>(
    values: &[T],
    label: &str,
    allow_empty: bool,
) -> Result<(), RecoveryError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_ITEMS
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(&format!(
            "{label} is empty, duplicated, unsorted, or oversized"
        ));
    }
    Ok(())
}

fn canonicalize_strings(
    values: &mut Vec<String>,
    label: &str,
    allow_empty: bool,
) -> Result<(), RecoveryError> {
    values.sort();
    values.dedup();
    validate_sorted_strings(values, label, allow_empty)
}

fn canonicalize_set<T: Ord>(
    values: &mut Vec<T>,
    label: &str,
    allow_empty: bool,
) -> Result<(), RecoveryError> {
    values.sort();
    values.dedup();
    validate_sorted_set(values, label, allow_empty)
}

fn reject_forbidden_json<T: Serialize>(value: &T, label: &str) -> Result<(), RecoveryError> {
    fn walk(value: &Value) -> bool {
        match value {
            Value::String(value) => {
                contains_secret_marker(value)
                    || value.contains(":\\")
                    || value.starts_with('/')
                    || value.starts_with("file:")
            }
            Value::Array(values) => values.iter().any(walk),
            Value::Object(values) => values.iter().any(|(key, value)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "raw_locator" | "raw_payload" | "credential" | "secret" | "token"
                ) || walk(value)
            }),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    let value = serde_json::to_value(value).map_err(json_error)?;
    if walk(&value) {
        return Err(RecoveryError::AccessDenied(format!(
            "{label} contains a secret, credential, locator, payload, or absolute path"
        )));
    }
    Ok(())
}

fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "credential",
        "bearer ",
        "api_key",
        "api-key",
        "access_token",
        "secret_value",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn invalid<T>(message: &str) -> Result<T, RecoveryError> {
    Err(RecoveryError::Invalid(message.to_owned()))
}

fn integrity<T>(message: &str) -> Result<T, RecoveryError> {
    Err(RecoveryError::Integrity(message.to_owned()))
}

fn json_error(error: serde_json::Error) -> RecoveryError {
    RecoveryError::Json(error.to_string())
}
