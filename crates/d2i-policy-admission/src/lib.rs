//! Deterministic, side-effect-free Cognitive Policy Admission v1.
//!
//! Policy admission resolves delegated authority, trusted policy, confirmation,
//! and activation eligibility around an exact `PolicyReadyActionV1`. None of
//! the artifacts in this crate is an adapter handle, Windows activation token,
//! credential, locator, or execution permit.

use d2i_action_selection::{canonical_sha256 as action_sha256, PolicyReadyActionV1};
use d2i_cognitive_ir::{
    CognitiveRiskClass, ConfirmationPolicy, ConfirmationRequirement, GoalSpec, Reversibility,
};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Cognitive Policy Admission schema version.
pub const POLICY_ADMISSION_SCHEMA_VERSION: u32 = 1;
/// Embedded Core-owned JSON Schema.
pub const COGNITIVE_POLICY_ADMISSION_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/cognitive-policy-admission-v1.schema.json");

const MAX_IDS: usize = 64;
const MAX_EVIDENCE_IDS: usize = 64;
const MAX_CONSUMED_GRANTS: usize = 1024;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 100_000;
const MAX_ID_LEN: usize = 128;
const MAX_CONFIRMATION_TTL_SECONDS: u64 = 300;
const MAX_ADMISSION_TTL_SECONDS: u64 = 300;

/// Fail-closed policy admission error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAdmissionError {
    /// A bounded contract field is malformed.
    Invalid(String),
    /// A sealed identity, lifecycle value, or digest was substituted.
    Integrity(String),
    /// The current decision cannot produce an admission.
    NotAdmissible(String),
    /// A one-time confirmation was already consumed.
    Replay(String),
    /// Strict JSON parsing or canonical serialization failed.
    Json(String),
}

impl Display for PolicyAdmissionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => {
                write!(formatter, "invalid policy admission input: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "policy admission integrity failure: {message}")
            }
            Self::NotAdmissible(message) => {
                write!(formatter, "policy admission denied: {message}")
            }
            Self::Replay(message) => write!(formatter, "confirmation replay rejected: {message}"),
            Self::Json(message) => write!(formatter, "policy admission JSON failure: {message}"),
        }
    }
}

impl Error for PolicyAdmissionError {}

/// Strict authority scope projection supplied by a future Role Contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScopeConstraintsV1 {
    pub application_pack_sha256: String,
    pub integration_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
}

impl AuthorityScopeConstraintsV1 {
    fn sort_sets(&mut self) {
        self.integration_ids.sort();
        self.semantic_target_ids.sort();
    }

    fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_hash(
            &self.application_pack_sha256,
            "scope application_pack_sha256",
        )?;
        validate_sorted_ids(
            &self.integration_ids,
            "scope integration_ids",
            MAX_IDS,
            false,
        )?;
        validate_sorted_ids(
            &self.semantic_target_ids,
            "scope semantic_target_ids",
            MAX_IDS,
            false,
        )
    }
}

/// Minimal delegated authority projection; it is never an execution permit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedAuthorityContextV1 {
    pub schema_version: u32,
    pub authority_id: String,
    pub organization_id: String,
    pub actor_id: String,
    pub role_id: String,
    pub policy_set_id: String,
    pub policy_set_version: String,
    pub policy_set_sha256: String,
    pub allowed_capability_ids: Vec<String>,
    pub forbidden_capability_ids: Vec<String>,
    pub autonomous_capability_ids: Vec<String>,
    pub confirmation_capability_ids: Vec<String>,
    pub maximum_autonomous_risk: CognitiveRiskClass,
    pub maximum_confirmable_risk: CognitiveRiskClass,
    pub allowed_application_pack_sha256: String,
    pub allowed_integration_ids: Vec<String>,
    pub scope_constraints: AuthorityScopeConstraintsV1,
    pub valid_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub authority_sha256: String,
}

impl DelegatedAuthorityContextV1 {
    /// Canonically sorts set-like arrays and seals the authority.
    pub fn seal(mut self) -> Result<Self, PolicyAdmissionError> {
        self.allowed_capability_ids.sort();
        self.forbidden_capability_ids.sort();
        self.autonomous_capability_ids.sort();
        self.confirmation_capability_ids.sort();
        self.allowed_integration_ids.sort();
        self.evidence_ids.sort();
        self.scope_constraints.sort_sets();
        self.authority_sha256 = self.compute_authority_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical authority digest without the self-hash.
    pub fn compute_authority_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "authority_sha256")
    }

    /// Validates shape, set relations, validity interval, and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "delegated authority")?;
        validate_id(&self.authority_id, "authority_id")?;
        validate_id(&self.organization_id, "authority organization_id")?;
        validate_id(&self.actor_id, "authority actor_id")?;
        validate_id(&self.role_id, "authority role_id")?;
        validate_id(&self.policy_set_id, "authority policy_set_id")?;
        validate_id(&self.policy_set_version, "authority policy_set_version")?;
        validate_hash(&self.policy_set_sha256, "authority policy_set_sha256")?;
        validate_sorted_ids(
            &self.allowed_capability_ids,
            "allowed_capability_ids",
            MAX_IDS,
            false,
        )?;
        validate_sorted_ids(
            &self.forbidden_capability_ids,
            "forbidden_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.autonomous_capability_ids,
            "autonomous_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.confirmation_capability_ids,
            "confirmation_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.allowed_integration_ids,
            "allowed_integration_ids",
            MAX_IDS,
            false,
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "authority evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        self.scope_constraints.validate()?;
        validate_interval(
            self.valid_from_unix_seconds,
            self.expires_at_unix_seconds,
            "authority",
        )?;
        if self.maximum_autonomous_risk > self.maximum_confirmable_risk {
            return invalid("maximum_autonomous_risk exceeds maximum_confirmable_risk");
        }
        let allowed = id_set(&self.allowed_capability_ids);
        let forbidden = id_set(&self.forbidden_capability_ids);
        let autonomous = id_set(&self.autonomous_capability_ids);
        let confirmation = id_set(&self.confirmation_capability_ids);
        if !allowed.is_disjoint(&forbidden) {
            return invalid("allowed and forbidden capability sets overlap");
        }
        if !autonomous.is_subset(&allowed) {
            return invalid("autonomous capabilities are not a subset of allowed capabilities");
        }
        if !confirmation.is_subset(&allowed) {
            return invalid("confirmation capabilities are not a subset of allowed capabilities");
        }
        if !autonomous.is_disjoint(&forbidden) || !confirmation.is_disjoint(&forbidden) {
            return invalid("delegated capability sets overlap forbidden capabilities");
        }
        if self.allowed_application_pack_sha256 != self.scope_constraints.application_pack_sha256 {
            return invalid("authority application pack differs from scope constraints");
        }
        let allowed_integrations = id_set(&self.allowed_integration_ids);
        let scoped_integrations = id_set(&self.scope_constraints.integration_ids);
        if !scoped_integrations.is_subset(&allowed_integrations) {
            return invalid("scope integrations exceed delegated integrations");
        }
        validate_hash(
            &self.allowed_application_pack_sha256,
            "allowed_application_pack_sha256",
        )?;
        validate_hash(&self.authority_sha256, "authority_sha256")?;
        if self.compute_authority_sha256()? != self.authority_sha256 {
            return integrity("authority_sha256 differs from canonical authority");
        }
        reject_forbidden_json(self, "delegated authority")
    }

    fn active_at(&self, now: u64) -> bool {
        self.valid_from_unix_seconds <= now && now < self.expires_at_unix_seconds
    }
}

/// Whether trusted policy facts are complete for an autonomous decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedPolicyStateV1 {
    Effective,
    Unknown,
}

/// Read-only trusted policy fixture boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedPolicySnapshotV1 {
    pub schema_version: u32,
    pub policy_set_id: String,
    pub policy_set_version: String,
    pub policy_set_sha256: String,
    pub organization_id: String,
    pub policy_state: TrustedPolicyStateV1,
    pub allowed_risk_classes: Vec<CognitiveRiskClass>,
    pub denied_capability_ids: Vec<String>,
    pub mandatory_confirmation_capability_ids: Vec<String>,
    pub mandatory_escalation_capability_ids: Vec<String>,
    pub forbidden_semantic_targets: Vec<String>,
    pub effective_from_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

impl TrustedPolicySnapshotV1 {
    /// Canonically sorts set-like arrays and seals the snapshot.
    pub fn seal(mut self) -> Result<Self, PolicyAdmissionError> {
        self.allowed_risk_classes.sort();
        self.denied_capability_ids.sort();
        self.mandatory_confirmation_capability_ids.sort();
        self.mandatory_escalation_capability_ids.sort();
        self.forbidden_semantic_targets.sort();
        self.evidence_ids.sort();
        self.snapshot_sha256 = self.compute_snapshot_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical snapshot digest without its self-hash.
    pub fn compute_snapshot_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "snapshot_sha256")
    }

    /// Validates bounded policy facts, disjoint decision sets, and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "trusted policy snapshot")?;
        validate_id(&self.policy_set_id, "policy policy_set_id")?;
        validate_id(&self.policy_set_version, "policy policy_set_version")?;
        validate_hash(&self.policy_set_sha256, "policy policy_set_sha256")?;
        validate_id(&self.organization_id, "policy organization_id")?;
        validate_sorted_unique(&self.allowed_risk_classes, "allowed_risk_classes", 4, false)?;
        validate_sorted_ids(
            &self.denied_capability_ids,
            "denied_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.mandatory_confirmation_capability_ids,
            "mandatory_confirmation_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.mandatory_escalation_capability_ids,
            "mandatory_escalation_capability_ids",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.forbidden_semantic_targets,
            "forbidden_semantic_targets",
            MAX_IDS,
            true,
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "policy evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_interval(
            self.effective_from_unix_seconds,
            self.expires_at_unix_seconds,
            "policy snapshot",
        )?;
        let denied = id_set(&self.denied_capability_ids);
        if !denied.is_disjoint(&id_set(&self.mandatory_confirmation_capability_ids))
            || !denied.is_disjoint(&id_set(&self.mandatory_escalation_capability_ids))
        {
            return invalid("denied capabilities overlap mandatory policy sets");
        }
        validate_hash(&self.snapshot_sha256, "snapshot_sha256")?;
        if self.compute_snapshot_sha256()? != self.snapshot_sha256 {
            return integrity("snapshot_sha256 differs from canonical policy snapshot");
        }
        reject_forbidden_json(self, "trusted policy snapshot")
    }

    fn active_at(&self, now: u64) -> bool {
        self.effective_from_unix_seconds <= now && now < self.expires_at_unix_seconds
    }
}

/// Caller-requested autonomy preference. Policy remains authoritative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedAutonomyModeV1 {
    AutonomousPreferred,
    ConfirmationAllowed,
}

/// Exact, sealed input to deterministic policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationRequestV1 {
    pub schema_version: u32,
    pub policy_ready_action: PolicyReadyActionV1,
    pub goal: GoalSpec,
    pub delegated_authority: DelegatedAuthorityContextV1,
    pub trusted_policy_snapshot: TrustedPolicySnapshotV1,
    pub evaluated_at_unix_seconds: u64,
    pub requested_autonomy_mode: RequestedAutonomyModeV1,
    pub expected_policy_ready_sha256: String,
    pub expected_selection_sha256: String,
    pub expected_proposal_sha256: String,
    pub expected_goal_id: String,
    pub expected_plan_generation_id: String,
    pub expected_source_observation_hash: String,
    pub expected_source_observation_sequence: u64,
    pub expected_capability_id: String,
    pub expected_application_pack_sha256: String,
    pub expected_semantic_target_id: String,
    pub expected_capability_binding_sha256: String,
    pub expected_risk: CognitiveRiskClass,
    pub expected_confirmation_requirement: ConfirmationRequirement,
    pub goal_sha256: String,
    pub request_sha256: String,
}

impl PolicyEvaluationRequestV1 {
    /// Builds and seals all duplicate exact-binding fields.
    pub fn new(
        policy_ready_action: PolicyReadyActionV1,
        goal: GoalSpec,
        delegated_authority: DelegatedAuthorityContextV1,
        trusted_policy_snapshot: TrustedPolicySnapshotV1,
        evaluated_at_unix_seconds: u64,
        requested_autonomy_mode: RequestedAutonomyModeV1,
    ) -> Result<Self, PolicyAdmissionError> {
        let proposal_sha256 = action_sha256(&policy_ready_action.proposal)
            .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
        let goal_sha256 = action_sha256(&goal)
            .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
        let mut request = Self {
            schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
            expected_policy_ready_sha256: policy_ready_action.policy_ready_sha256.clone(),
            expected_selection_sha256: policy_ready_action.selection_sha256.clone(),
            expected_proposal_sha256: proposal_sha256,
            expected_goal_id: policy_ready_action.goal_id.clone(),
            expected_plan_generation_id: policy_ready_action.plan_generation_id.clone(),
            expected_source_observation_hash: policy_ready_action.source_observation_hash.clone(),
            expected_source_observation_sequence: policy_ready_action.source_observation_sequence,
            expected_capability_id: policy_ready_action.capability_id.clone(),
            expected_application_pack_sha256: policy_ready_action.application_pack_sha256.clone(),
            expected_semantic_target_id: policy_ready_action.semantic_target_id.clone(),
            expected_capability_binding_sha256: policy_ready_action
                .capability_binding_sha256
                .clone(),
            expected_risk: policy_ready_action.risk,
            expected_confirmation_requirement: policy_ready_action.confirmation_requirement,
            policy_ready_action,
            goal,
            delegated_authority,
            trusted_policy_snapshot,
            evaluated_at_unix_seconds,
            requested_autonomy_mode,
            goal_sha256,
            request_sha256: empty_hash(),
        };
        request.request_sha256 = request.compute_request_sha256()?;
        request.validate()?;
        Ok(request)
    }

    /// Computes the canonical request digest without its self-hash.
    pub fn compute_request_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "request_sha256")
    }

    /// Validates seals and every duplicate exact-binding field.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        self.validate_seals()?;
        if !self.binding_mismatches()?.is_empty() {
            return integrity("policy evaluation request exact bindings differ");
        }
        Ok(())
    }

    fn validate_seals(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "policy evaluation request")?;
        validate_policy_ready_action(&self.policy_ready_action)?;
        self.goal
            .validate()
            .map_err(|error| PolicyAdmissionError::Invalid(error.to_string()))?;
        self.delegated_authority.validate()?;
        self.trusted_policy_snapshot.validate()?;
        validate_hash(
            &self.expected_policy_ready_sha256,
            "expected_policy_ready_sha256",
        )?;
        validate_hash(&self.expected_selection_sha256, "expected_selection_sha256")?;
        validate_hash(&self.expected_proposal_sha256, "expected_proposal_sha256")?;
        validate_id(&self.expected_goal_id, "expected_goal_id")?;
        validate_id(
            &self.expected_plan_generation_id,
            "expected_plan_generation_id",
        )?;
        validate_hash(
            &self.expected_source_observation_hash,
            "expected_source_observation_hash",
        )?;
        validate_id(&self.expected_capability_id, "expected_capability_id")?;
        validate_hash(
            &self.expected_application_pack_sha256,
            "expected_application_pack_sha256",
        )?;
        validate_id(
            &self.expected_semantic_target_id,
            "expected_semantic_target_id",
        )?;
        validate_hash(
            &self.expected_capability_binding_sha256,
            "expected_capability_binding_sha256",
        )?;
        validate_hash(&self.goal_sha256, "goal_sha256")?;
        validate_hash(&self.request_sha256, "request_sha256")?;
        if self.compute_request_sha256()? != self.request_sha256 {
            return integrity("request_sha256 differs from canonical request");
        }
        reject_forbidden_json(self, "policy evaluation request")
    }

    fn binding_mismatches(&self) -> Result<Vec<PolicyReasonCodeV1>, PolicyAdmissionError> {
        let ready = &self.policy_ready_action;
        let proposal_sha256 = action_sha256(&ready.proposal)
            .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
        let goal_sha256 = action_sha256(&self.goal)
            .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
        let mut reasons = Vec::new();
        if self.expected_policy_ready_sha256 != ready.policy_ready_sha256
            || self.expected_selection_sha256 != ready.selection_sha256
            || self.expected_proposal_sha256 != proposal_sha256
            || self.expected_goal_id != ready.goal_id
            || self.expected_plan_generation_id != ready.plan_generation_id
            || self.expected_source_observation_hash != ready.source_observation_hash
            || self.expected_source_observation_sequence != ready.source_observation_sequence
            || self.expected_capability_id != ready.capability_id
            || self.expected_application_pack_sha256 != ready.application_pack_sha256
            || self.expected_semantic_target_id != ready.semantic_target_id
            || self.expected_capability_binding_sha256 != ready.capability_binding_sha256
            || self.expected_risk != ready.risk
            || self.expected_confirmation_requirement != ready.confirmation_requirement
            || goal_sha256 != self.goal_sha256
            || self.goal.goal_id != ready.goal_id
            || ready.proposal.goal_id != ready.goal_id
            || ready.proposal.plan_generation_id != ready.plan_generation_id
            || ready.proposal.source_observation_hash != ready.source_observation_hash
            || ready.proposal.capability_id != ready.capability_id
            || ready.proposal.semantic_target != ready.semantic_target_id
            || ready.proposal.valid_until_sequence != ready.source_observation_sequence
            || ready.proposal.risk != ready.risk
            || ready.proposal.reversibility != ready.reversibility
            || ready.proposal.confirmation_requirement != ready.confirmation_requirement
        {
            reasons.push(PolicyReasonCodeV1::ExactBindingMismatch);
        }
        Ok(reasons)
    }
}

/// Closed policy outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOutcomeV1 {
    AllowAutonomous,
    RequireConfirmation,
    Deny,
    Escalate,
}

/// Closed machine-readable policy reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCodeV1 {
    DelegatedAutonomous,
    ConfirmationCapability,
    GoalAlwaysConfirmation,
    GoalRiskConfirmation,
    ProposalConfirmationRequired,
    PolicyMandatoryConfirmation,
    RiskRequiresConfirmation,
    ForbiddenCapability,
    PolicyDeniedCapability,
    ForbiddenSemanticTarget,
    ExpiredAuthority,
    ExpiredPolicy,
    AuthorityPolicyMismatch,
    OrganizationMismatch,
    ApplicationScopeMismatch,
    IntegrationScopeMismatch,
    SemanticScopeMismatch,
    CapabilityOutsideAuthority,
    RiskAboveConfirmable,
    HighCriticality,
    PolicyUnknown,
    PolicyRiskUnknown,
    UnsupportedIrreversible,
    ExactBindingMismatch,
    MandatoryEscalation,
}

/// Confirmation result resolved by policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedConfirmationRequirementV1 {
    NotRequired,
    Required,
    NotApplicable,
}

/// Deterministic policy decision, not adapter execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub outcome: PolicyOutcomeV1,
    pub policy_ready_sha256: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub capability_id: String,
    pub authority_sha256: String,
    pub policy_snapshot_sha256: String,
    pub resolved_confirmation_requirement: ResolvedConfirmationRequirementV1,
    pub reason_codes: Vec<PolicyReasonCodeV1>,
    pub evidence_ids: Vec<String>,
    pub evaluated_at_unix_seconds: u64,
    pub decision_sha256: String,
}

impl PolicyDecisionV1 {
    /// Computes the canonical decision digest without its self-hash.
    pub fn compute_decision_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "decision_sha256")
    }

    /// Validates bounded decision fields, outcome shape, and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "policy decision")?;
        validate_id(&self.decision_id, "decision_id")?;
        validate_hash(&self.policy_ready_sha256, "decision policy_ready_sha256")?;
        validate_id(&self.proposal_id, "decision proposal_id")?;
        validate_hash(&self.proposal_sha256, "decision proposal_sha256")?;
        validate_id(&self.goal_id, "decision goal_id")?;
        validate_id(&self.plan_generation_id, "decision plan_generation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "decision source_observation_hash",
        )?;
        validate_id(&self.capability_id, "decision capability_id")?;
        validate_hash(&self.authority_sha256, "decision authority_sha256")?;
        validate_hash(
            &self.policy_snapshot_sha256,
            "decision policy_snapshot_sha256",
        )?;
        validate_sorted_unique(&self.reason_codes, "reason_codes", 32, false)?;
        validate_sorted_ids(
            &self.evidence_ids,
            "decision evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        match self.outcome {
            PolicyOutcomeV1::AllowAutonomous
                if self.resolved_confirmation_requirement
                    != ResolvedConfirmationRequirementV1::NotRequired =>
            {
                return invalid("autonomous decision cannot require confirmation");
            }
            PolicyOutcomeV1::RequireConfirmation
                if self.resolved_confirmation_requirement
                    != ResolvedConfirmationRequirementV1::Required =>
            {
                return invalid("confirmation decision must require confirmation");
            }
            PolicyOutcomeV1::Deny | PolicyOutcomeV1::Escalate
                if self.resolved_confirmation_requirement
                    != ResolvedConfirmationRequirementV1::NotApplicable =>
            {
                return invalid("terminal policy outcome must mark confirmation not applicable");
            }
            _ => {}
        }
        validate_hash(&self.decision_sha256, "decision_sha256")?;
        if self.compute_decision_sha256()? != self.decision_sha256 {
            return integrity("decision_sha256 differs from canonical policy decision");
        }
        reject_forbidden_json(self, "policy decision")
    }
}

/// Evaluates trusted policy and delegated authority without side effects.
pub fn evaluate_policy(
    request: &PolicyEvaluationRequestV1,
) -> Result<PolicyDecisionV1, PolicyAdmissionError> {
    request.validate_seals()?;
    let ready = &request.policy_ready_action;
    let authority = &request.delegated_authority;
    let policy = &request.trusted_policy_snapshot;
    let now = request.evaluated_at_unix_seconds;

    let mut outcome = PolicyOutcomeV1::AllowAutonomous;
    let mut reasons = request.binding_mismatches()?;

    if !reasons.is_empty() {
        outcome = PolicyOutcomeV1::Deny;
    } else if !authority.active_at(now) {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::ExpiredAuthority);
    } else if !policy.active_at(now) {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::ExpiredPolicy);
    } else if authority.organization_id != policy.organization_id {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::OrganizationMismatch);
    } else if authority.policy_set_id != policy.policy_set_id
        || authority.policy_set_version != policy.policy_set_version
        || authority.policy_set_sha256 != policy.policy_set_sha256
    {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::AuthorityPolicyMismatch);
    } else if authority
        .forbidden_capability_ids
        .contains(&ready.capability_id)
    {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::ForbiddenCapability);
    } else if policy.denied_capability_ids.contains(&ready.capability_id) {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::PolicyDeniedCapability);
    } else if policy
        .forbidden_semantic_targets
        .contains(&ready.semantic_target_id)
    {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::ForbiddenSemanticTarget);
    } else if ready.reversibility == Reversibility::Irreversible
        || ready.confirmation_requirement == ConfirmationRequirement::UnsupportedIrreversible
    {
        outcome = PolicyOutcomeV1::Deny;
        reasons.push(PolicyReasonCodeV1::UnsupportedIrreversible);
    } else if ready.risk == CognitiveRiskClass::HighCriticality {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::HighCriticality);
    } else if policy
        .mandatory_escalation_capability_ids
        .contains(&ready.capability_id)
    {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::MandatoryEscalation);
    } else if policy.policy_state == TrustedPolicyStateV1::Unknown {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::PolicyUnknown);
    } else if !policy.allowed_risk_classes.contains(&ready.risk) {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::PolicyRiskUnknown);
    } else if authority.allowed_application_pack_sha256 != ready.application_pack_sha256 {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::ApplicationScopeMismatch);
    } else if !authority
        .scope_constraints
        .semantic_target_ids
        .contains(&ready.semantic_target_id)
    {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::SemanticScopeMismatch);
    } else if !authority
        .allowed_capability_ids
        .contains(&ready.capability_id)
    {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::CapabilityOutsideAuthority);
    } else if ready.risk > authority.maximum_confirmable_risk {
        outcome = PolicyOutcomeV1::Escalate;
        reasons.push(PolicyReasonCodeV1::RiskAboveConfirmable);
    } else {
        let confirmation_reasons = confirmation_reasons(request);
        if !confirmation_reasons.is_empty() {
            outcome = PolicyOutcomeV1::RequireConfirmation;
            reasons.extend(confirmation_reasons);
        } else if authority
            .autonomous_capability_ids
            .contains(&ready.capability_id)
            && ready.risk <= authority.maximum_autonomous_risk
        {
            reasons.push(PolicyReasonCodeV1::DelegatedAutonomous);
        } else if authority
            .confirmation_capability_ids
            .contains(&ready.capability_id)
            || ready.risk <= authority.maximum_confirmable_risk
        {
            outcome = PolicyOutcomeV1::RequireConfirmation;
            reasons.push(if ready.risk > authority.maximum_autonomous_risk {
                PolicyReasonCodeV1::RiskRequiresConfirmation
            } else {
                PolicyReasonCodeV1::ConfirmationCapability
            });
        } else {
            outcome = PolicyOutcomeV1::Escalate;
            reasons.push(PolicyReasonCodeV1::CapabilityOutsideAuthority);
        }
    }

    reasons.sort();
    reasons.dedup();
    let mut evidence_ids = authority
        .evidence_ids
        .iter()
        .chain(policy.evidence_ids.iter())
        .chain(ready.evidence_ids.iter())
        .cloned()
        .collect::<Vec<_>>();
    evidence_ids.sort();
    evidence_ids.dedup();
    let proposal_sha256 = action_sha256(&ready.proposal)
        .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
    let mut decision = PolicyDecisionV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        decision_id: derive_id("decision", &request.request_sha256)?,
        outcome,
        policy_ready_sha256: ready.policy_ready_sha256.clone(),
        proposal_id: ready.proposal.proposal_id.clone(),
        proposal_sha256,
        goal_id: ready.goal_id.clone(),
        plan_generation_id: ready.plan_generation_id.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        capability_id: ready.capability_id.clone(),
        authority_sha256: authority.authority_sha256.clone(),
        policy_snapshot_sha256: policy.snapshot_sha256.clone(),
        resolved_confirmation_requirement: match outcome {
            PolicyOutcomeV1::AllowAutonomous => ResolvedConfirmationRequirementV1::NotRequired,
            PolicyOutcomeV1::RequireConfirmation => ResolvedConfirmationRequirementV1::Required,
            PolicyOutcomeV1::Deny | PolicyOutcomeV1::Escalate => {
                ResolvedConfirmationRequirementV1::NotApplicable
            }
        },
        reason_codes: reasons,
        evidence_ids,
        evaluated_at_unix_seconds: now,
        decision_sha256: empty_hash(),
    };
    decision.decision_sha256 = decision.compute_decision_sha256()?;
    decision.validate()?;
    Ok(decision)
}

fn confirmation_reasons(request: &PolicyEvaluationRequestV1) -> Vec<PolicyReasonCodeV1> {
    let ready = &request.policy_ready_action;
    let authority = &request.delegated_authority;
    let policy = &request.trusted_policy_snapshot;
    let mut reasons = Vec::new();
    if request.goal.confirmation_policy == ConfirmationPolicy::Always {
        reasons.push(PolicyReasonCodeV1::GoalAlwaysConfirmation);
    }
    if request.goal.confirmation_policy == ConfirmationPolicy::BeforeRiskyAction
        && ready.risk >= CognitiveRiskClass::BusinessStateChange
    {
        reasons.push(PolicyReasonCodeV1::GoalRiskConfirmation);
    }
    if ready.confirmation_requirement == ConfirmationRequirement::Required {
        reasons.push(PolicyReasonCodeV1::ProposalConfirmationRequired);
    }
    if authority
        .confirmation_capability_ids
        .contains(&ready.capability_id)
    {
        reasons.push(PolicyReasonCodeV1::ConfirmationCapability);
    }
    if policy
        .mandatory_confirmation_capability_ids
        .contains(&ready.capability_id)
    {
        reasons.push(PolicyReasonCodeV1::PolicyMandatoryConfirmation);
    }
    if ready.risk > authority.maximum_autonomous_risk {
        reasons.push(PolicyReasonCodeV1::RiskRequiresConfirmation);
    }
    reasons
}

/// One-time challenge emitted only for a confirmation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationChallengeV1 {
    pub schema_version: u32,
    pub challenge_id: String,
    pub decision_sha256: String,
    pub policy_ready_sha256: String,
    pub proposal_sha256: String,
    pub actor_id: String,
    pub role_id: String,
    pub organization_id: String,
    pub capability_id: String,
    pub semantic_target_id: String,
    pub risk: CognitiveRiskClass,
    pub confirmation_reason_codes: Vec<PolicyReasonCodeV1>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub challenge_nonce_sha256: String,
    pub evidence_ids: Vec<String>,
    pub challenge_sha256: String,
}

impl ConfirmationChallengeV1 {
    /// Computes the canonical challenge digest without its self-hash.
    pub fn compute_challenge_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "challenge_sha256")
    }

    /// Validates bounded, short-lived challenge content and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "confirmation challenge")?;
        validate_id(&self.challenge_id, "challenge_id")?;
        validate_hash(&self.decision_sha256, "challenge decision_sha256")?;
        validate_hash(&self.policy_ready_sha256, "challenge policy_ready_sha256")?;
        validate_hash(&self.proposal_sha256, "challenge proposal_sha256")?;
        validate_id(&self.actor_id, "challenge actor_id")?;
        validate_id(&self.role_id, "challenge role_id")?;
        validate_id(&self.organization_id, "challenge organization_id")?;
        validate_id(&self.capability_id, "challenge capability_id")?;
        validate_id(&self.semantic_target_id, "challenge semantic_target_id")?;
        validate_sorted_unique(
            &self.confirmation_reason_codes,
            "confirmation_reason_codes",
            16,
            false,
        )?;
        validate_short_interval(
            self.issued_at_unix_seconds,
            self.expires_at_unix_seconds,
            MAX_CONFIRMATION_TTL_SECONDS,
            "challenge",
        )?;
        validate_hash(&self.challenge_nonce_sha256, "challenge_nonce_sha256")?;
        validate_sorted_ids(
            &self.evidence_ids,
            "challenge evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.challenge_sha256, "challenge_sha256")?;
        if self.compute_challenge_sha256()? != self.challenge_sha256 {
            return integrity("challenge_sha256 differs from canonical challenge");
        }
        reject_forbidden_json(self, "confirmation challenge")
    }
}

/// Creates a challenge from a confirmation-only policy decision.
pub fn create_confirmation_challenge(
    request: &PolicyEvaluationRequestV1,
    decision: &PolicyDecisionV1,
    challenge_id: String,
    challenge_nonce_sha256: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> Result<ConfirmationChallengeV1, PolicyAdmissionError> {
    request.validate()?;
    validate_decision_binding(request, decision)?;
    if decision.outcome != PolicyOutcomeV1::RequireConfirmation {
        return Err(PolicyAdmissionError::NotAdmissible(
            "challenge requires a require_confirmation decision".to_owned(),
        ));
    }
    let mut evidence_ids = decision.evidence_ids.clone();
    evidence_ids.push("confirmation-challenge".to_owned());
    evidence_ids.sort();
    evidence_ids.dedup();
    let mut challenge = ConfirmationChallengeV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        challenge_id,
        decision_sha256: decision.decision_sha256.clone(),
        policy_ready_sha256: decision.policy_ready_sha256.clone(),
        proposal_sha256: decision.proposal_sha256.clone(),
        actor_id: request.delegated_authority.actor_id.clone(),
        role_id: request.delegated_authority.role_id.clone(),
        organization_id: request.delegated_authority.organization_id.clone(),
        capability_id: request.policy_ready_action.capability_id.clone(),
        semantic_target_id: request.policy_ready_action.semantic_target_id.clone(),
        risk: request.policy_ready_action.risk,
        confirmation_reason_codes: decision.reason_codes.clone(),
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        challenge_nonce_sha256,
        evidence_ids,
        challenge_sha256: empty_hash(),
    };
    challenge.challenge_sha256 = challenge.compute_challenge_sha256()?;
    challenge.validate()?;
    Ok(challenge)
}

/// Trusted confirmation fixture validated against an exact challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationGrantV1 {
    pub schema_version: u32,
    pub grant_id: String,
    pub challenge_id: String,
    pub challenge_sha256: String,
    pub decision_sha256: String,
    pub policy_ready_sha256: String,
    pub proposal_sha256: String,
    pub confirming_actor_id: String,
    pub confirming_role_id: String,
    pub organization_id: String,
    pub granted_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub confirmation_proof_sha256: String,
    pub one_time_use_id: String,
    pub evidence_ids: Vec<String>,
    pub grant_sha256: String,
}

impl ConfirmationGrantV1 {
    /// Canonically sorts evidence and seals a trusted grant fixture.
    pub fn seal(mut self) -> Result<Self, PolicyAdmissionError> {
        self.evidence_ids.sort();
        self.grant_sha256 = self.compute_grant_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical grant digest without its self-hash.
    pub fn compute_grant_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "grant_sha256")
    }

    /// Validates bounded grant content and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "confirmation grant")?;
        validate_id(&self.grant_id, "grant_id")?;
        validate_id(&self.challenge_id, "grant challenge_id")?;
        validate_hash(&self.challenge_sha256, "grant challenge_sha256")?;
        validate_hash(&self.decision_sha256, "grant decision_sha256")?;
        validate_hash(&self.policy_ready_sha256, "grant policy_ready_sha256")?;
        validate_hash(&self.proposal_sha256, "grant proposal_sha256")?;
        validate_id(&self.confirming_actor_id, "confirming_actor_id")?;
        validate_id(&self.confirming_role_id, "confirming_role_id")?;
        validate_id(&self.organization_id, "grant organization_id")?;
        validate_short_interval(
            self.granted_at_unix_seconds,
            self.expires_at_unix_seconds,
            MAX_CONFIRMATION_TTL_SECONDS,
            "grant",
        )?;
        validate_hash(&self.confirmation_proof_sha256, "confirmation_proof_sha256")?;
        validate_id(&self.one_time_use_id, "one_time_use_id")?;
        validate_sorted_ids(
            &self.evidence_ids,
            "grant evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.grant_sha256, "grant_sha256")?;
        if self.compute_grant_sha256()? != self.grant_sha256 {
            return integrity("grant_sha256 differs from canonical grant");
        }
        reject_forbidden_json(self, "confirmation grant")
    }

    /// Validates exact challenge, identity, action, and time bindings.
    pub fn validate_against(
        &self,
        request: &PolicyEvaluationRequestV1,
        decision: &PolicyDecisionV1,
        challenge: &ConfirmationChallengeV1,
        at_unix_seconds: u64,
    ) -> Result<(), PolicyAdmissionError> {
        self.validate()?;
        request.validate()?;
        validate_decision_binding(request, decision)?;
        challenge.validate()?;
        if decision.outcome != PolicyOutcomeV1::RequireConfirmation {
            return Err(PolicyAdmissionError::NotAdmissible(
                "grant cannot override deny, escalate, or autonomous decisions".to_owned(),
            ));
        }
        if challenge.decision_sha256 != decision.decision_sha256
            || challenge.policy_ready_sha256 != decision.policy_ready_sha256
            || challenge.proposal_sha256 != decision.proposal_sha256
            || self.challenge_id != challenge.challenge_id
            || self.challenge_sha256 != challenge.challenge_sha256
            || self.decision_sha256 != challenge.decision_sha256
            || self.policy_ready_sha256 != challenge.policy_ready_sha256
            || self.proposal_sha256 != challenge.proposal_sha256
        {
            return integrity("grant action or challenge binding differs");
        }
        if self.confirming_actor_id != challenge.actor_id
            || self.confirming_role_id != challenge.role_id
            || self.organization_id != challenge.organization_id
        {
            return integrity("grant actor, role, or organization differs");
        }
        if at_unix_seconds < self.granted_at_unix_seconds
            || at_unix_seconds >= self.expires_at_unix_seconds
            || at_unix_seconds >= challenge.expires_at_unix_seconds
        {
            return invalid("confirmation grant or challenge is not active");
        }
        Ok(())
    }
}

/// Bounded in-memory one-time grant ledger.
///
/// Durable cross-process consumption is deliberately deferred to the trusted
/// execution binding. This ledger prevents reuse within one admission
/// artifact lifecycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConsumptionLedgerV1 {
    consumed_one_time_use_ids: BTreeSet<String>,
}

impl GrantConsumptionLedgerV1 {
    /// Creates an empty bounded ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a one-time identifier has already been consumed.
    #[must_use]
    pub fn contains(&self, one_time_use_id: &str) -> bool {
        self.consumed_one_time_use_ids.contains(one_time_use_id)
    }

    fn consume(&mut self, one_time_use_id: &str) -> Result<(), PolicyAdmissionError> {
        validate_id(one_time_use_id, "consumed one_time_use_id")?;
        if self.consumed_one_time_use_ids.len() >= MAX_CONSUMED_GRANTS {
            return invalid("grant consumption ledger exceeds 1024 entries");
        }
        if !self
            .consumed_one_time_use_ids
            .insert(one_time_use_id.to_owned())
        {
            return Err(PolicyAdmissionError::Replay(
                "one_time_use_id was already consumed".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Narrow adapter family eligible for the next trusted execution stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKindV1 {
    Uia,
    WebDriver,
}

/// Read-only projection of an existing activation binding and ledger state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEligibilityContextV1 {
    pub schema_version: u32,
    pub eligibility_id: String,
    pub organization_id: String,
    pub integration_id: String,
    pub application_pack_sha256: String,
    pub runtime_binding_id: String,
    pub runtime_binding_sha256: String,
    pub adapter_kind: AdapterKindV1,
    pub activation_scope_id: String,
    pub activation_ledger_id: String,
    pub activation_ledger_chain_head: String,
    pub eligible_capability_ids: Vec<String>,
    pub capability_binding_sha256: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub eligibility_sha256: String,
}

impl ActivationEligibilityContextV1 {
    /// Canonically sorts set-like arrays and seals eligibility.
    pub fn seal(mut self) -> Result<Self, PolicyAdmissionError> {
        self.eligible_capability_ids.sort();
        self.evidence_ids.sort();
        self.eligibility_sha256 = self.compute_eligibility_sha256()?;
        self.validate()?;
        Ok(self)
    }

    /// Computes the canonical eligibility digest without its self-hash.
    pub fn compute_eligibility_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "eligibility_sha256")
    }

    /// Validates the read-only binding projection and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "activation eligibility")?;
        validate_id(&self.eligibility_id, "eligibility_id")?;
        validate_id(&self.organization_id, "eligibility organization_id")?;
        validate_id(&self.integration_id, "eligibility integration_id")?;
        validate_hash(
            &self.application_pack_sha256,
            "eligibility application_pack_sha256",
        )?;
        validate_id(&self.runtime_binding_id, "runtime_binding_id")?;
        validate_hash(&self.runtime_binding_sha256, "runtime_binding_sha256")?;
        validate_id(&self.activation_scope_id, "activation_scope_id")?;
        validate_id(&self.activation_ledger_id, "activation_ledger_id")?;
        validate_hash(
            &self.activation_ledger_chain_head,
            "activation_ledger_chain_head",
        )?;
        validate_sorted_ids(
            &self.eligible_capability_ids,
            "eligible_capability_ids",
            MAX_IDS,
            false,
        )?;
        validate_hash(
            &self.capability_binding_sha256,
            "eligibility capability_binding_sha256",
        )?;
        validate_hash(
            &self.source_observation_hash,
            "eligibility source_observation_hash",
        )?;
        validate_short_interval(
            self.observed_at_unix_seconds,
            self.expires_at_unix_seconds,
            MAX_ADMISSION_TTL_SECONDS,
            "activation eligibility",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "eligibility evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        validate_hash(&self.eligibility_sha256, "eligibility_sha256")?;
        if self.compute_eligibility_sha256()? != self.eligibility_sha256 {
            return integrity("eligibility_sha256 differs from canonical eligibility");
        }
        reject_forbidden_json(self, "activation eligibility")
    }

    fn active_at(&self, now: u64) -> bool {
        self.observed_at_unix_seconds <= now && now < self.expires_at_unix_seconds
    }
}

/// Admission mode resolved before one-shot Windows activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionModeV1 {
    DelegatedAutonomous,
    ConfirmedException,
}

/// Exact admission artifact consumed by the next trusted execution binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveActivationAdmissionV1 {
    pub schema_version: u32,
    pub admission_id: String,
    pub admission_mode: AdmissionModeV1,
    pub policy_ready_sha256: String,
    pub selection_sha256: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub capability_id: String,
    pub semantic_target_id: String,
    pub application_pack_sha256: String,
    pub capability_binding_sha256: String,
    pub authority_sha256: String,
    pub policy_snapshot_sha256: String,
    pub policy_decision_sha256: String,
    pub confirmation_challenge_sha256: Option<String>,
    pub confirmation_grant_sha256: Option<String>,
    pub activation_eligibility_sha256: String,
    pub integration_id: String,
    pub runtime_binding_sha256: String,
    pub adapter_kind: AdapterKindV1,
    pub admitted_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub admission_sha256: String,
}

impl CognitiveActivationAdmissionV1 {
    /// Computes the canonical admission digest without its self-hash.
    pub fn compute_admission_sha256(&self) -> Result<String, PolicyAdmissionError> {
        hash_without_field(self, "admission_sha256")
    }

    /// Validates admission shape and self-hash.
    pub fn validate(&self) -> Result<(), PolicyAdmissionError> {
        validate_version(self.schema_version, "activation admission")?;
        validate_id(&self.admission_id, "admission_id")?;
        validate_hash(&self.policy_ready_sha256, "admission policy_ready_sha256")?;
        validate_hash(&self.selection_sha256, "admission selection_sha256")?;
        validate_id(&self.proposal_id, "admission proposal_id")?;
        validate_hash(&self.proposal_sha256, "admission proposal_sha256")?;
        validate_id(&self.goal_id, "admission goal_id")?;
        validate_id(&self.plan_generation_id, "admission plan_generation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "admission source_observation_hash",
        )?;
        validate_id(&self.capability_id, "admission capability_id")?;
        validate_id(&self.semantic_target_id, "admission semantic_target_id")?;
        validate_hash(
            &self.application_pack_sha256,
            "admission application_pack_sha256",
        )?;
        validate_hash(
            &self.capability_binding_sha256,
            "admission capability_binding_sha256",
        )?;
        validate_hash(&self.authority_sha256, "admission authority_sha256")?;
        validate_hash(
            &self.policy_snapshot_sha256,
            "admission policy_snapshot_sha256",
        )?;
        validate_hash(
            &self.policy_decision_sha256,
            "admission policy_decision_sha256",
        )?;
        validate_optional_hash(
            &self.confirmation_challenge_sha256,
            "confirmation_challenge_sha256",
        )?;
        validate_optional_hash(&self.confirmation_grant_sha256, "confirmation_grant_sha256")?;
        validate_hash(
            &self.activation_eligibility_sha256,
            "activation_eligibility_sha256",
        )?;
        validate_id(&self.integration_id, "admission integration_id")?;
        validate_hash(
            &self.runtime_binding_sha256,
            "admission runtime_binding_sha256",
        )?;
        validate_short_interval(
            self.admitted_at_unix_seconds,
            self.expires_at_unix_seconds,
            MAX_ADMISSION_TTL_SECONDS,
            "activation admission",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "admission evidence_ids",
            MAX_EVIDENCE_IDS,
            false,
        )?;
        match self.admission_mode {
            AdmissionModeV1::DelegatedAutonomous
                if self.confirmation_challenge_sha256.is_some()
                    || self.confirmation_grant_sha256.is_some() =>
            {
                return invalid("delegated admission cannot contain confirmation hashes");
            }
            AdmissionModeV1::ConfirmedException
                if self.confirmation_challenge_sha256.is_none()
                    || self.confirmation_grant_sha256.is_none() =>
            {
                return invalid("confirmed admission requires challenge and grant hashes");
            }
            _ => {}
        }
        validate_hash(&self.admission_sha256, "admission_sha256")?;
        if self.compute_admission_sha256()? != self.admission_sha256 {
            return integrity("admission_sha256 differs from canonical admission");
        }
        reject_forbidden_json(self, "activation admission")
    }
}

/// Explicit deterministic inputs for admission creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionIssuanceV1 {
    pub admission_id: String,
    pub admitted_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub expected_runtime_binding_sha256: String,
    pub expected_activation_ledger_chain_head: String,
    pub expected_adapter_kind: AdapterKindV1,
}

/// Produces an activation admission without creating a token or invoking an adapter.
#[allow(clippy::too_many_arguments)]
pub fn admit_action(
    request: &PolicyEvaluationRequestV1,
    decision: &PolicyDecisionV1,
    challenge: Option<&ConfirmationChallengeV1>,
    grant: Option<&ConfirmationGrantV1>,
    eligibility: &ActivationEligibilityContextV1,
    ledger: &mut GrantConsumptionLedgerV1,
    issuance: AdmissionIssuanceV1,
) -> Result<CognitiveActivationAdmissionV1, PolicyAdmissionError> {
    request.validate()?;
    validate_decision_binding(request, decision)?;
    eligibility.validate()?;
    validate_hash(
        &issuance.expected_runtime_binding_sha256,
        "expected_runtime_binding_sha256",
    )?;
    validate_hash(
        &issuance.expected_activation_ledger_chain_head,
        "expected_activation_ledger_chain_head",
    )?;
    let ready = &request.policy_ready_action;
    if !eligibility.active_at(issuance.admitted_at_unix_seconds) {
        return Err(PolicyAdmissionError::NotAdmissible(
            "activation eligibility is stale".to_owned(),
        ));
    }
    if eligibility.organization_id != request.delegated_authority.organization_id
        || !request
            .delegated_authority
            .allowed_integration_ids
            .contains(&eligibility.integration_id)
        || !request
            .delegated_authority
            .scope_constraints
            .integration_ids
            .contains(&eligibility.integration_id)
    {
        return Err(PolicyAdmissionError::NotAdmissible(
            "integration or organization scope differs".to_owned(),
        ));
    }
    if eligibility.application_pack_sha256 != ready.application_pack_sha256
        || !eligibility
            .eligible_capability_ids
            .contains(&ready.capability_id)
        || eligibility.capability_binding_sha256 != ready.capability_binding_sha256
        || eligibility.source_observation_hash != ready.source_observation_hash
        || eligibility.source_observation_sequence != ready.source_observation_sequence
        || eligibility.runtime_binding_sha256 != issuance.expected_runtime_binding_sha256
        || eligibility.activation_ledger_chain_head
            != issuance.expected_activation_ledger_chain_head
        || eligibility.adapter_kind != issuance.expected_adapter_kind
        || !adapter_matches_capability(eligibility.adapter_kind, &ready.capability_id)
    {
        return integrity("activation eligibility exact binding differs");
    }
    if issuance.admitted_at_unix_seconds < decision.evaluated_at_unix_seconds
        || issuance.expires_at_unix_seconds > eligibility.expires_at_unix_seconds
    {
        return invalid("admission time exceeds decision or eligibility bounds");
    }

    let (mode, challenge_hash, grant_hash) = match decision.outcome {
        PolicyOutcomeV1::AllowAutonomous => {
            if challenge.is_some() || grant.is_some() {
                return Err(PolicyAdmissionError::NotAdmissible(
                    "confirmation is not applicable to autonomous admission".to_owned(),
                ));
            }
            (AdmissionModeV1::DelegatedAutonomous, None, None)
        }
        PolicyOutcomeV1::RequireConfirmation => {
            let challenge = challenge.ok_or_else(|| {
                PolicyAdmissionError::NotAdmissible("confirmation challenge is required".to_owned())
            })?;
            let grant = grant.ok_or_else(|| {
                PolicyAdmissionError::NotAdmissible("confirmation grant is required".to_owned())
            })?;
            grant.validate_against(
                request,
                decision,
                challenge,
                issuance.admitted_at_unix_seconds,
            )?;
            ledger.consume(&grant.one_time_use_id)?;
            (
                AdmissionModeV1::ConfirmedException,
                Some(challenge.challenge_sha256.clone()),
                Some(grant.grant_sha256.clone()),
            )
        }
        PolicyOutcomeV1::Deny | PolicyOutcomeV1::Escalate => {
            return Err(PolicyAdmissionError::NotAdmissible(
                "deny or escalate decision cannot produce admission".to_owned(),
            ));
        }
    };

    let mut evidence_ids = decision
        .evidence_ids
        .iter()
        .chain(eligibility.evidence_ids.iter())
        .cloned()
        .collect::<Vec<_>>();
    if let Some(challenge) = challenge {
        evidence_ids.extend(challenge.evidence_ids.iter().cloned());
    }
    if let Some(grant) = grant {
        evidence_ids.extend(grant.evidence_ids.iter().cloned());
    }
    evidence_ids.sort();
    evidence_ids.dedup();
    let mut admission = CognitiveActivationAdmissionV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        admission_id: issuance.admission_id,
        admission_mode: mode,
        policy_ready_sha256: ready.policy_ready_sha256.clone(),
        selection_sha256: ready.selection_sha256.clone(),
        proposal_id: ready.proposal.proposal_id.clone(),
        proposal_sha256: decision.proposal_sha256.clone(),
        goal_id: ready.goal_id.clone(),
        plan_generation_id: ready.plan_generation_id.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        capability_id: ready.capability_id.clone(),
        semantic_target_id: ready.semantic_target_id.clone(),
        application_pack_sha256: ready.application_pack_sha256.clone(),
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
        authority_sha256: decision.authority_sha256.clone(),
        policy_snapshot_sha256: decision.policy_snapshot_sha256.clone(),
        policy_decision_sha256: decision.decision_sha256.clone(),
        confirmation_challenge_sha256: challenge_hash,
        confirmation_grant_sha256: grant_hash,
        activation_eligibility_sha256: eligibility.eligibility_sha256.clone(),
        integration_id: eligibility.integration_id.clone(),
        runtime_binding_sha256: eligibility.runtime_binding_sha256.clone(),
        adapter_kind: eligibility.adapter_kind,
        admitted_at_unix_seconds: issuance.admitted_at_unix_seconds,
        expires_at_unix_seconds: issuance.expires_at_unix_seconds,
        evidence_ids,
        admission_sha256: empty_hash(),
    };
    admission.admission_sha256 = admission.compute_admission_sha256()?;
    admission.validate()?;
    Ok(admission)
}

/// JSON-compatible projection for the existing Desktop `AuditOutcome`.
///
/// This projection is audit compatibility only. `allowed` does not create an
/// adapter permit and this crate never connects it to `CognitiveExecutor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOutcomeProjectionV1 {
    pub allowed: bool,
    pub reason: String,
    pub evidence: Vec<String>,
}

impl From<&PolicyDecisionV1> for AuditOutcomeProjectionV1 {
    fn from(decision: &PolicyDecisionV1) -> Self {
        Self {
            allowed: decision.outcome == PolicyOutcomeV1::AllowAutonomous,
            reason: format!(
                "policy_decision:{}",
                match decision.outcome {
                    PolicyOutcomeV1::AllowAutonomous => "allow_autonomous",
                    PolicyOutcomeV1::RequireConfirmation => "require_confirmation",
                    PolicyOutcomeV1::Deny => "deny",
                    PolicyOutcomeV1::Escalate => "escalate",
                }
            ),
            evidence: decision.evidence_ids.clone(),
        }
    }
}

impl From<&CognitiveActivationAdmissionV1> for AuditOutcomeProjectionV1 {
    fn from(admission: &CognitiveActivationAdmissionV1) -> Self {
        Self {
            allowed: true,
            reason: format!(
                "activation_admission:{}",
                match admission.admission_mode {
                    AdmissionModeV1::DelegatedAutonomous => "delegated_autonomous",
                    AdmissionModeV1::ConfirmedException => "confirmed_exception",
                }
            ),
            evidence: admission.evidence_ids.clone(),
        }
    }
}

/// Strictly parses JSON with duplicate-key, size, depth, and node limits.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, PolicyAdmissionError> {
    if bytes.len() > MAX_JSON_BYTES {
        return invalid("JSON exceeds 8 MiB");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| json_error("parse strict JSON", error))?
        .0;
    deserializer
        .end()
        .map_err(|error| json_error("parse trailing JSON", error))?;
    validate_json_limits(&value)?;
    serde_json::from_value(value).map_err(|error| json_error("decode strict JSON", error))
}

/// Computes recursive-key-sorted JSON SHA-256 using the D2I hash format.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, PolicyAdmissionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| json_error("serialize canonical JSON", error))?;
    hash_value(&value)
}

fn validate_policy_ready_action(ready: &PolicyReadyActionV1) -> Result<(), PolicyAdmissionError> {
    validate_version(ready.schema_version, "policy-ready action")?;
    validate_id(&ready.selection_id, "policy-ready selection_id")?;
    validate_hash(&ready.selection_sha256, "policy-ready selection_sha256")?;
    validate_hash(
        &ready.candidate_set_sha256,
        "policy-ready candidate_set_sha256",
    )?;
    validate_id(&ready.goal_id, "policy-ready goal_id")?;
    validate_id(&ready.world_state_id, "policy-ready world_state_id")?;
    validate_id(&ready.plan_generation_id, "policy-ready plan_generation_id")?;
    validate_id(&ready.observation_id, "policy-ready observation_id")?;
    validate_hash(
        &ready.source_observation_hash,
        "policy-ready source_observation_hash",
    )?;
    validate_hash(
        &ready.application_pack_sha256,
        "policy-ready application_pack_sha256",
    )?;
    validate_hash(
        &ready.grounding_result_sha256,
        "policy-ready grounding_result_sha256",
    )?;
    validate_id(&ready.semantic_target_id, "policy-ready semantic_target_id")?;
    validate_id(
        &ready.selected_element_id,
        "policy-ready selected_element_id",
    )?;
    validate_id(
        &ready.selected_element_kind,
        "policy-ready selected_element_kind",
    )?;
    validate_id(&ready.capability_id, "policy-ready capability_id")?;
    validate_hash(
        &ready.capability_binding_sha256,
        "policy-ready capability_binding_sha256",
    )?;
    let mut proposal_for_shape = ready.proposal.clone();
    if proposal_for_shape.reversibility == Reversibility::Irreversible {
        proposal_for_shape.reversibility = Reversibility::Reversible;
    }
    proposal_for_shape
        .validate()
        .map_err(|error| PolicyAdmissionError::Invalid(error.to_string()))?;
    validate_sorted_ids(
        &ready.evidence_ids,
        "policy-ready evidence_ids",
        MAX_EVIDENCE_IDS,
        false,
    )?;
    validate_hash(
        &ready.policy_input_sha256,
        "policy-ready policy_input_sha256",
    )?;
    validate_hash(
        &ready.policy_ready_sha256,
        "policy-ready policy_ready_sha256",
    )?;
    let computed = ready
        .compute_policy_ready_sha256()
        .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
    if computed != ready.policy_ready_sha256 {
        return integrity("policy_ready_sha256 differs from canonical action");
    }
    reject_forbidden_json(ready, "policy-ready action")
}

fn validate_decision_binding(
    request: &PolicyEvaluationRequestV1,
    decision: &PolicyDecisionV1,
) -> Result<(), PolicyAdmissionError> {
    decision.validate()?;
    let ready = &request.policy_ready_action;
    let proposal_sha256 = action_sha256(&ready.proposal)
        .map_err(|error| PolicyAdmissionError::Integrity(error.to_string()))?;
    if decision.policy_ready_sha256 != ready.policy_ready_sha256
        || decision.proposal_id != ready.proposal.proposal_id
        || decision.proposal_sha256 != proposal_sha256
        || decision.goal_id != ready.goal_id
        || decision.plan_generation_id != ready.plan_generation_id
        || decision.source_observation_hash != ready.source_observation_hash
        || decision.source_observation_sequence != ready.source_observation_sequence
        || decision.capability_id != ready.capability_id
        || decision.authority_sha256 != request.delegated_authority.authority_sha256
        || decision.policy_snapshot_sha256 != request.trusted_policy_snapshot.snapshot_sha256
        || decision.evaluated_at_unix_seconds != request.evaluated_at_unix_seconds
    {
        return integrity("policy decision differs from exact request binding");
    }
    Ok(())
}

fn adapter_matches_capability(kind: AdapterKindV1, capability_id: &str) -> bool {
    match kind {
        AdapterKindV1::Uia => capability_id.starts_with("uia."),
        AdapterKindV1::WebDriver => capability_id.starts_with("webdriver."),
    }
}

fn validate_version(version: u32, label: &str) -> Result<(), PolicyAdmissionError> {
    if version != POLICY_ADMISSION_SCHEMA_VERSION {
        return invalid(format!("{label} schema_version must be 1"));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), PolicyAdmissionError> {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return invalid(format!("{label} must be a bounded identifier"));
    }
    Ok(())
}

fn validate_hash(value: &str, label: &str) -> Result<(), PolicyAdmissionError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return invalid(format!("{label} must be lowercase canonical sha256"));
    }
    Ok(())
}

fn validate_optional_hash(value: &Option<String>, label: &str) -> Result<(), PolicyAdmissionError> {
    if let Some(value) = value {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_sorted_ids(
    values: &[String],
    label: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), PolicyAdmissionError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return invalid(format!("{label} has invalid collection bounds"));
    }
    for value in values {
        validate_id(value, label)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} must be sorted and duplicate-free"));
    }
    Ok(())
}

fn validate_sorted_unique<T: Ord>(
    values: &[T],
    label: &str,
    maximum: usize,
    allow_empty: bool,
) -> Result<(), PolicyAdmissionError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return invalid(format!("{label} has invalid collection bounds"));
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{label} must be sorted and duplicate-free"));
    }
    Ok(())
}

fn validate_interval(start: u64, expires: u64, label: &str) -> Result<(), PolicyAdmissionError> {
    if start >= expires {
        return invalid(format!("{label} validity interval is empty"));
    }
    Ok(())
}

fn validate_short_interval(
    start: u64,
    expires: u64,
    maximum_ttl: u64,
    label: &str,
) -> Result<(), PolicyAdmissionError> {
    validate_interval(start, expires, label)?;
    if expires.saturating_sub(start) > maximum_ttl {
        return invalid(format!("{label} TTL exceeds {maximum_ttl} seconds"));
    }
    Ok(())
}

fn id_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

fn derive_id(prefix: &str, hash: &str) -> Result<String, PolicyAdmissionError> {
    validate_hash(hash, "derived ID source hash")?;
    Ok(format!("{prefix}-{}", &hash[7..31]))
}

fn empty_hash() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

fn hash_without_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, PolicyAdmissionError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| json_error("serialize self-hash", error))?;
    let object = value.as_object_mut().ok_or_else(|| {
        PolicyAdmissionError::Json("self-hashed artifact is not an object".to_owned())
    })?;
    object.remove(field);
    hash_value(&value)
}

fn hash_value(value: &Value) -> Result<String, PolicyAdmissionError> {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| json_error("serialize canonical value", error))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                if let Some(value) = object.get(key) {
                    canonical.insert(key.clone(), canonicalize(value));
                }
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn reject_forbidden_json<T: Serialize>(value: &T, label: &str) -> Result<(), PolicyAdmissionError> {
    let value =
        serde_json::to_value(value).map_err(|error| json_error("inspect forbidden JSON", error))?;
    fn walk(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                let key = key.to_ascii_lowercase();
                let forbidden_key = [
                    "password",
                    "credential",
                    "raw_input",
                    "selector",
                    "locator",
                    "coordinate",
                    "adapter_handle",
                    "activation_token",
                ]
                .iter()
                .any(|needle| key.contains(needle));
                forbidden_key || walk(value)
            }),
            Value::Array(values) => values.iter().any(walk),
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                let raw_secret = ["password=", "token=", "secret=", "bearer "]
                    .iter()
                    .any(|needle| lower.contains(needle));
                let absolute_path = text.starts_with('/')
                    || text.starts_with("\\\\")
                    || (text.len() > 2
                        && text.as_bytes()[1] == b':'
                        && matches!(text.as_bytes()[2], b'\\' | b'/'));
                raw_secret || absolute_path
            }
            _ => false,
        }
    }
    if walk(&value) {
        return invalid(format!(
            "{label} contains forbidden raw authority or locator data"
        ));
    }
    Ok(())
}

fn validate_json_limits(value: &Value) -> Result<(), PolicyAdmissionError> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), PolicyAdmissionError> {
        if depth > MAX_JSON_DEPTH {
            return invalid("JSON nesting exceeds 64");
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_JSON_NODES {
            return invalid("JSON node count exceeds 100000");
        }
        match value {
            Value::Object(object) => {
                for value in object.values() {
                    walk(value, depth.saturating_add(1), nodes)?;
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, depth.saturating_add(1), nodes)?;
                }
            }
            Value::Number(number) if number.as_f64().is_some_and(|value| !value.is_finite()) => {
                return invalid("JSON contains non-finite number");
            }
            _ => {}
        }
        Ok(())
    }
    let mut nodes = 0;
    walk(value, 0, &mut nodes)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
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

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if !value.is_finite() {
                    return Err(E::custom("non-finite JSON number"));
                }
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if object.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {key}"
                        )));
                    }
                }
                Ok(StrictValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn invalid<T>(message: impl Into<String>) -> Result<T, PolicyAdmissionError> {
    Err(PolicyAdmissionError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, PolicyAdmissionError> {
    Err(PolicyAdmissionError::Integrity(message.into()))
}

fn json_error(context: &str, error: impl Display) -> PolicyAdmissionError {
    PolicyAdmissionError::Json(format!("{context}: {error}"))
}
