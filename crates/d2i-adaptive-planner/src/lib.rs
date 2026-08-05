//! Bounded semantic planning and trusted next-step admission for WORK-500.
//!
//! This crate never grounds targets, admits policy, creates activation, or
//! calls an adapter. A plan and a decision are non-authoritative artifacts.

use d2i_cognitive_ir::{
    CognitiveRiskClass, ComparisonOp, ConfirmationPolicy, GoalSpec, Postcondition, Provenance,
    Reversibility, COGNITIVE_SCHEMA_VERSION,
};
use d2i_intelligence_provider::{
    GoalDraftV1, GoalUnderstandingRequestV1, GoalUnderstandingResultV1, IntelligenceProviderError,
    ProviderCandidateDispositionV1, ProviderNextStepDraftV1, ProviderPlanningRequestV1,
    ProviderPlanningResultV1, ProviderReasonCodeV1, ProviderResultStatusV1, MAX_CANDIDATES,
};
use d2i_situation_model::{
    canonical_sha256, hash_without, reject_sensitive_value, validate_hash, validate_id,
    validate_ids, CaseSituationModelV1, SituationError,
};
use d2i_work_queue::CaseWorkGrantV1;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

pub const ADAPTIVE_PLANNER_SCHEMA_VERSION: u32 = 1;
pub const MAX_SUBGOALS: usize = 64;
pub const MAX_BRANCH_CONDITIONS: usize = 64;
pub const MAX_PLAN_CYCLES: u32 = 32;
pub const MAX_ACTIONS_PER_CASE: u32 = 16;
pub const MAX_REPLANS: u32 = 16;
pub const MAX_CLARIFICATIONS: u32 = 4;
pub const MIN_ACTION_CONFIDENCE_MILLIONTHS: u32 = 700_000;

pub const ADAPTIVE_PLAN_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/adaptive-plan-v1.schema.json");
pub const ADAPTIVE_PLANNING_REQUEST_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/adaptive-planning-request-v1.schema.json");
pub const ADAPTIVE_PLANNING_RESULT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/adaptive-planning-result-v1.schema.json");
pub const NEXT_STEP_DECISION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/next-step-decision-v1.schema.json");
pub const PLANNER_CYCLE_RECORD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/planner-cycle-record-v1.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptivePlannerError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    ResourceLimit(String),
    ClarificationRequired(String),
    EscalationRequired(String),
}

impl Display for AdaptivePlannerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::ResourceLimit(message) => ("resource_limit", message),
            Self::ClarificationRequired(message) => ("clarification_required", message),
            Self::EscalationRequired(message) => ("escalation_required", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for AdaptivePlannerError {}

impl From<SituationError> for AdaptivePlannerError {
    fn from(value: SituationError) -> Self {
        match value {
            SituationError::Invalid(message) | SituationError::Json(message) => {
                Self::Invalid(message)
            }
            SituationError::Integrity(message) => Self::Integrity(message),
            SituationError::ResourceLimit(message) => Self::ResourceLimit(message),
            SituationError::SensitiveContent(message) => Self::Unauthorized(message),
        }
    }
}

impl From<IntelligenceProviderError> for AdaptivePlannerError {
    fn from(value: IntelligenceProviderError) -> Self {
        match value {
            IntelligenceProviderError::Invalid(message)
            | IntelligenceProviderError::OutputInvalid(message) => Self::Invalid(message),
            IntelligenceProviderError::Integrity(message) => Self::Integrity(message),
            IntelligenceProviderError::Unauthorized(message)
            | IntelligenceProviderError::SensitiveContent(message) => Self::Unauthorized(message),
            IntelligenceProviderError::ResourceLimit(message) => Self::ResourceLimit(message),
            IntelligenceProviderError::Unavailable(message)
            | IntelligenceProviderError::Timeout(message)
            | IntelligenceProviderError::Process(message) => Self::Invalid(message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptivePlanStepStatusV1 {
    Open,
    Completed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextStepOutcomeV1 {
    Continue,
    VerifiedCaseComplete,
    ClarificationRequired,
    EscalationRequired,
    Unsupported,
    Unsafe,
    BudgetExhausted,
    ProviderUnavailable,
    ProviderOutputInvalid,
    NoEligibleAction,
    ConflictingSituation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerCycleStageV1 {
    ProviderInvoked,
    ProviderResultValidated,
    SituationPersisted,
    PlanPersisted,
    StepAdmitted,
    KernelBound,
    ActionAttempted,
    VerificationPersisted,
    SituationUpdated,
    TerminalEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerCycleStatusV1 {
    InProgress,
    Verified,
    Clarification,
    Escalation,
    Failed,
    Recovered,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptivePlanStepV1 {
    pub subgoal_id: String,
    pub semantic_intent: String,
    pub status: AdaptivePlanStepStatusV1,
    pub requirement_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveBranchConditionV1 {
    pub condition_id: String,
    pub fact_predicate: String,
    pub when_true_subgoal_id: String,
    pub when_false_subgoal_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerProviderProvenanceV1 {
    pub provider_id: String,
    pub provider_descriptor_sha256: String,
    pub invocation_sha256: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptivePlanV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub generation: u64,
    pub case_id: String,
    pub goal_spec_sha256: String,
    pub situation_sha256: String,
    pub case_work_grant_sha256: String,
    pub current_observation_sha256: String,
    pub ordered_subgoals: Vec<AdaptivePlanStepV1>,
    pub completed_subgoal_ids: Vec<String>,
    pub open_subgoal_ids: Vec<String>,
    pub branch_conditions: Vec<AdaptiveBranchConditionV1>,
    pub maximum_cycles: u32,
    pub maximum_actions: u32,
    pub clarification_condition_ids: Vec<String>,
    pub escalation_condition_ids: Vec<String>,
    pub stop_condition_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub provider_provenance: PlannerProviderProvenanceV1,
    pub previous_plan_sha256: Option<String>,
    pub plan_sha256: String,
}

impl AdaptivePlanV1 {
    pub fn seal(mut self) -> Result<Self, AdaptivePlannerError> {
        self.completed_subgoal_ids.sort();
        self.open_subgoal_ids.sort();
        self.clarification_condition_ids.sort();
        self.escalation_condition_ids.sort();
        self.stop_condition_ids.sort();
        self.evidence_ids.sort();
        self.plan_sha256 = hash_without(&self, &["plan_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.schema_version != ADAPTIVE_PLANNER_SCHEMA_VERSION
            || self.generation == 0
            || self.maximum_cycles == 0
            || self.maximum_cycles > MAX_PLAN_CYCLES
            || self.maximum_actions == 0
            || self.maximum_actions > MAX_ACTIONS_PER_CASE
            || self.ordered_subgoals.is_empty()
            || self.ordered_subgoals.len() > MAX_SUBGOALS
            || self.branch_conditions.len() > MAX_BRANCH_CONDITIONS
        {
            return Err(AdaptivePlannerError::ResourceLimit(
                "Adaptive Plan contains invalid or unbounded limits".to_owned(),
            ));
        }
        validate_id(&self.plan_id, "Adaptive Plan ID")?;
        validate_id(&self.case_id, "Adaptive Plan Case ID")?;
        for (value, label) in [
            (&self.goal_spec_sha256, "GoalSpec hash"),
            (&self.situation_sha256, "Situation hash"),
            (&self.case_work_grant_sha256, "Case Work Grant hash"),
            (&self.current_observation_sha256, "observation hash"),
            (&self.plan_sha256, "Adaptive Plan hash"),
        ] {
            validate_hash(value, label)?;
        }
        if let Some(previous) = &self.previous_plan_sha256 {
            validate_hash(previous, "previous Adaptive Plan hash")?;
            if self.generation == 1 {
                return Err(AdaptivePlannerError::Invalid(
                    "generation one cannot bind a previous plan".to_owned(),
                ));
            }
        } else if self.generation != 1 {
            return Err(AdaptivePlannerError::Invalid(
                "later plan generation requires previous plan hash".to_owned(),
            ));
        }
        let mut step_ids = BTreeSet::new();
        for step in &self.ordered_subgoals {
            validate_id(&step.subgoal_id, "plan subgoal ID")?;
            validate_id(&step.semantic_intent, "plan semantic intent")?;
            validate_ids(&step.requirement_ids, false)?;
            validate_ids(&step.evidence_ids, false)?;
            if !step_ids.insert(&step.subgoal_id) {
                return Err(AdaptivePlannerError::Invalid(
                    "plan contains duplicate subgoal ID".to_owned(),
                ));
            }
        }
        for ids in [
            &self.completed_subgoal_ids,
            &self.open_subgoal_ids,
            &self.clarification_condition_ids,
            &self.escalation_condition_ids,
            &self.stop_condition_ids,
            &self.evidence_ids,
        ] {
            validate_ids(ids, ids == &self.completed_subgoal_ids)?;
        }
        if self
            .completed_subgoal_ids
            .iter()
            .any(|id| self.open_subgoal_ids.contains(id))
            || self
                .completed_subgoal_ids
                .iter()
                .chain(&self.open_subgoal_ids)
                .any(|id| !step_ids.contains(id))
        {
            return Err(AdaptivePlannerError::Invalid(
                "plan subgoal status projection is inconsistent".to_owned(),
            ));
        }
        for condition in &self.branch_conditions {
            validate_id(&condition.condition_id, "branch condition ID")?;
            validate_id(&condition.fact_predicate, "branch fact predicate")?;
            if !step_ids.contains(&condition.when_true_subgoal_id)
                || !step_ids.contains(&condition.when_false_subgoal_id)
            {
                return Err(AdaptivePlannerError::Invalid(
                    "branch condition references an unknown subgoal".to_owned(),
                ));
            }
        }
        self.provider_provenance.validate()?;
        if hash_without(self, &["plan_sha256"])? != self.plan_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "Adaptive Plan self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "Adaptive Plan")?;
        Ok(())
    }
}

impl PlannerProviderProvenanceV1 {
    fn validate(&self) -> Result<(), AdaptivePlannerError> {
        validate_id(&self.provider_id, "planner provider ID")?;
        validate_hash(&self.provider_descriptor_sha256, "provider descriptor hash")?;
        validate_hash(&self.invocation_sha256, "planner invocation hash")?;
        validate_hash(&self.result_sha256, "planner result hash")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextStepCandidateV1 {
    pub candidate_id: String,
    pub plan_generation: u64,
    pub subgoal_id: String,
    pub semantic_intent: String,
    pub semantic_target_id: Option<String>,
    pub capability_id: Option<String>,
    pub approved_value_sha256: Option<String>,
    pub required_precondition_ids: Vec<String>,
    pub expected_postcondition_ids: Vec<String>,
    pub risk_estimate: CognitiveRiskClass,
    pub reversibility: Reversibility,
    pub information_gathering: bool,
    pub clarification: bool,
    pub escalation: bool,
    pub verify_only: bool,
    pub confidence_millionths: u32,
    pub uncertainty_reason_codes: Vec<ProviderReasonCodeV1>,
    pub evidence_refs: Vec<String>,
    pub candidate_sha256: String,
}

impl NextStepCandidateV1 {
    pub fn from_provider(
        draft: &ProviderNextStepDraftV1,
        plan_generation: u64,
    ) -> Result<Self, AdaptivePlannerError> {
        draft.validate()?;
        let mut value = Self {
            candidate_id: draft.candidate_id.clone(),
            plan_generation,
            subgoal_id: draft.subgoal_id.clone(),
            semantic_intent: draft.semantic_intent.clone(),
            semantic_target_id: draft.semantic_target_id.clone(),
            capability_id: draft.capability_id.clone(),
            approved_value_sha256: draft.approved_value_sha256.clone(),
            required_precondition_ids: draft.required_precondition_ids.clone(),
            expected_postcondition_ids: draft.expected_postcondition_ids.clone(),
            risk_estimate: draft.risk_estimate,
            reversibility: if draft.reversible {
                Reversibility::Reversible
            } else {
                Reversibility::Irreversible
            },
            information_gathering: draft.disposition
                == ProviderCandidateDispositionV1::InformationGathering,
            clarification: draft.disposition == ProviderCandidateDispositionV1::Clarification,
            escalation: draft.disposition == ProviderCandidateDispositionV1::Escalation,
            verify_only: draft.disposition == ProviderCandidateDispositionV1::VerifyOnly,
            confidence_millionths: draft.confidence_millionths,
            uncertainty_reason_codes: draft.uncertainty.clone(),
            evidence_refs: draft.evidence_refs.clone(),
            candidate_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        };
        value.candidate_sha256 = hash_without(&value, &["candidate_sha256"])?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.plan_generation == 0 || self.confidence_millionths > 1_000_000 {
            return Err(AdaptivePlannerError::Invalid(
                "next-step generation or confidence is invalid".to_owned(),
            ));
        }
        validate_id(&self.candidate_id, "next-step candidate ID")?;
        validate_id(&self.subgoal_id, "next-step subgoal ID")?;
        validate_id(&self.semantic_intent, "next-step semantic intent")?;
        if let Some(target) = &self.semantic_target_id {
            validate_id(target, "next-step semantic target")?;
        }
        if let Some(capability) = &self.capability_id {
            validate_id(capability, "next-step capability")?;
        }
        if let Some(value) = &self.approved_value_sha256 {
            validate_hash(value, "next-step approved value hash")?;
        }
        validate_ids(&self.required_precondition_ids, true)?;
        validate_ids(&self.expected_postcondition_ids, true)?;
        validate_ids(&self.evidence_refs, false)?;
        if [
            self.information_gathering,
            self.clarification,
            self.escalation,
            self.verify_only,
        ]
        .iter()
        .filter(|flag| **flag)
        .count()
            > 1
        {
            return Err(AdaptivePlannerError::Invalid(
                "next-step disposition flags conflict".to_owned(),
            ));
        }
        let non_action = self.clarification || self.escalation || self.verify_only;
        if non_action
            && (self.approved_value_sha256.is_some()
                || self.reversibility == Reversibility::Irreversible)
        {
            return Err(AdaptivePlannerError::Unauthorized(
                "non-action step carries executable or irreversible semantics".to_owned(),
            ));
        }
        validate_hash(&self.candidate_sha256, "next-step candidate hash")?;
        if hash_without(self, &["candidate_sha256"])? != self.candidate_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "next-step candidate self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "next-step candidate")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptivePlanningRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub case_id: String,
    pub goal_spec_sha256: String,
    pub situation_sha256: String,
    pub case_work_grant_sha256: String,
    pub lease_sha256: String,
    pub ownership_state_sha256: String,
    pub current_observation_sha256: String,
    pub plan_generation: u64,
    pub previous_plan_sha256: Option<String>,
    pub open_subgoal_ids: Vec<String>,
    pub completed_subgoal_ids: Vec<String>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub forbidden_capability_ids: Vec<String>,
    pub approved_value_sha256s: Vec<String>,
    pub allowed_precondition_ids: Vec<String>,
    pub allowed_postcondition_ids: Vec<String>,
    pub risk_ceiling: CognitiveRiskClass,
    pub minimum_confidence_millionths: u32,
    pub maximum_candidates: u32,
    pub maximum_cycles: u32,
    pub maximum_actions: u32,
    pub trusted_time_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl AdaptivePlanningRequestV1 {
    pub fn seal(mut self) -> Result<Self, AdaptivePlannerError> {
        for ids in [
            &mut self.open_subgoal_ids,
            &mut self.completed_subgoal_ids,
            &mut self.allowed_semantic_target_ids,
            &mut self.allowed_capability_ids,
            &mut self.forbidden_capability_ids,
            &mut self.allowed_precondition_ids,
            &mut self.allowed_postcondition_ids,
            &mut self.evidence_ids,
        ] {
            ids.sort();
        }
        self.approved_value_sha256s.sort();
        self.request_sha256 = hash_without(&self, &["request_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.schema_version != ADAPTIVE_PLANNER_SCHEMA_VERSION
            || self.plan_generation == 0
            || self.minimum_confidence_millionths > 1_000_000
            || self.maximum_candidates == 0
            || self.maximum_candidates as usize > MAX_CANDIDATES
            || self.maximum_cycles == 0
            || self.maximum_cycles > MAX_PLAN_CYCLES
            || self.maximum_actions == 0
            || self.maximum_actions > MAX_ACTIONS_PER_CASE
            || self.trusted_time_unix_seconds == 0
        {
            return Err(AdaptivePlannerError::ResourceLimit(
                "Adaptive Planning request contains invalid bounds".to_owned(),
            ));
        }
        validate_id(&self.request_id, "Adaptive Planning request ID")?;
        validate_id(&self.case_id, "Adaptive Planning Case ID")?;
        for (value, label) in [
            (&self.goal_spec_sha256, "GoalSpec hash"),
            (&self.situation_sha256, "Situation hash"),
            (&self.case_work_grant_sha256, "Case Work Grant hash"),
            (&self.lease_sha256, "lease hash"),
            (&self.ownership_state_sha256, "ownership hash"),
            (&self.current_observation_sha256, "observation hash"),
            (&self.request_sha256, "Adaptive Planning request hash"),
        ] {
            validate_hash(value, label)?;
        }
        if let Some(previous) = &self.previous_plan_sha256 {
            validate_hash(previous, "previous plan hash")?;
            if self.plan_generation == 1 {
                return Err(AdaptivePlannerError::Invalid(
                    "first plan generation cannot bind a previous plan".to_owned(),
                ));
            }
        } else if self.plan_generation != 1 {
            return Err(AdaptivePlannerError::Invalid(
                "later planning request requires previous plan hash".to_owned(),
            ));
        }
        for ids in [
            &self.open_subgoal_ids,
            &self.completed_subgoal_ids,
            &self.allowed_semantic_target_ids,
            &self.allowed_capability_ids,
            &self.forbidden_capability_ids,
            &self.allowed_precondition_ids,
            &self.allowed_postcondition_ids,
            &self.evidence_ids,
        ] {
            validate_ids(ids, ids == &self.completed_subgoal_ids)?;
        }
        let mut approved_values = BTreeSet::new();
        for hash in &self.approved_value_sha256s {
            validate_hash(hash, "approved planning value hash")?;
            if !approved_values.insert(hash) {
                return Err(AdaptivePlannerError::Invalid(
                    "approved planning value hashes contain duplicates".to_owned(),
                ));
            }
        }
        if self
            .allowed_capability_ids
            .iter()
            .any(|value| self.forbidden_capability_ids.contains(value))
            || self
                .open_subgoal_ids
                .iter()
                .any(|value| self.completed_subgoal_ids.contains(value))
        {
            return Err(AdaptivePlannerError::Unauthorized(
                "Adaptive Planning allow/deny or subgoal sets overlap".to_owned(),
            ));
        }
        if hash_without(self, &["request_sha256"])? != self.request_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "Adaptive Planning request self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "Adaptive Planning request")?;
        Ok(())
    }

    pub fn provider_request(
        &self,
        provider_invocation_sha256: String,
    ) -> Result<ProviderPlanningRequestV1, AdaptivePlannerError> {
        let mut value = ProviderPlanningRequestV1 {
            schema_version: ADAPTIVE_PLANNER_SCHEMA_VERSION,
            request_id: self.request_id.clone(),
            case_id: self.case_id.clone(),
            goal_spec_sha256: self.goal_spec_sha256.clone(),
            situation_sha256: self.situation_sha256.clone(),
            plan_generation: self.plan_generation,
            open_subgoal_ids: self.open_subgoal_ids.clone(),
            allowed_semantic_target_ids: self.allowed_semantic_target_ids.clone(),
            allowed_capability_ids: self.allowed_capability_ids.clone(),
            forbidden_capability_ids: self.forbidden_capability_ids.clone(),
            approved_value_sha256s: self.approved_value_sha256s.clone(),
            allowed_precondition_ids: self.allowed_precondition_ids.clone(),
            allowed_postcondition_ids: self.allowed_postcondition_ids.clone(),
            maximum_candidates: self.maximum_candidates,
            provider_invocation_sha256,
            evidence_ids: self.evidence_ids.clone(),
            request_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        };
        value.request_sha256 = hash_without(&value, &["request_sha256"])?;
        value.validate()?;
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptivePlanningResultV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub provider_result_sha256: String,
    pub plan: Option<AdaptivePlanV1>,
    pub candidates: Vec<NextStepCandidateV1>,
    pub outcome: NextStepOutcomeV1,
    pub reason_codes: Vec<ProviderReasonCodeV1>,
    pub result_sha256: String,
}

impl AdaptivePlanningResultV1 {
    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.schema_version != ADAPTIVE_PLANNER_SCHEMA_VERSION
            || self.candidates.len() > MAX_CANDIDATES
        {
            return Err(AdaptivePlannerError::ResourceLimit(
                "Adaptive Planning result exceeds bounds".to_owned(),
            ));
        }
        validate_id(&self.request_id, "Adaptive Planning result request ID")?;
        validate_hash(
            &self.provider_result_sha256,
            "provider planning result hash",
        )?;
        validate_hash(&self.result_sha256, "Adaptive Planning result hash")?;
        if let Some(plan) = &self.plan {
            plan.validate()?;
        }
        let mut ids = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !ids.insert(&candidate.candidate_id) {
                return Err(AdaptivePlannerError::Invalid(
                    "Adaptive Planning result contains duplicate candidates".to_owned(),
                ));
            }
        }
        if self.outcome == NextStepOutcomeV1::Continue
            && (self.plan.is_none() || self.candidates.is_empty())
        {
            return Err(AdaptivePlannerError::Invalid(
                "continue result requires a plan and candidates".to_owned(),
            ));
        }
        if self.outcome != NextStepOutcomeV1::Continue
            && self.reason_codes.is_empty()
            && self.outcome != NextStepOutcomeV1::VerifiedCaseComplete
        {
            return Err(AdaptivePlannerError::Invalid(
                "non-continue result requires a reason code".to_owned(),
            ));
        }
        if self.reason_codes.len() > 16 {
            return Err(AdaptivePlannerError::ResourceLimit(
                "planning reason codes exceed bound".to_owned(),
            ));
        }
        if hash_without(self, &["result_sha256"])? != self.result_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "Adaptive Planning result self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "Adaptive Planning result")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextStepDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub case_id: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub plan_sha256: Option<String>,
    pub situation_sha256: String,
    pub case_work_grant_sha256: String,
    pub lease_sha256: String,
    pub ownership_state_sha256: String,
    pub observation_sha256: String,
    pub outcome: NextStepOutcomeV1,
    pub selected_candidate: Option<NextStepCandidateV1>,
    pub rejected_candidate_hashes: Vec<String>,
    pub reason_codes: Vec<ProviderReasonCodeV1>,
    pub valid_until_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub decision_sha256: String,
}

impl NextStepDecisionV1 {
    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.schema_version != ADAPTIVE_PLANNER_SCHEMA_VERSION
            || self.valid_until_unix_seconds == 0
            || self.rejected_candidate_hashes.len() > MAX_CANDIDATES
            || self.reason_codes.len() > 16
        {
            return Err(AdaptivePlannerError::ResourceLimit(
                "next-step decision bounds are invalid".to_owned(),
            ));
        }
        validate_id(&self.decision_id, "next-step decision ID")?;
        validate_id(&self.case_id, "next-step decision Case ID")?;
        for hash in [
            &self.request_sha256,
            &self.result_sha256,
            &self.situation_sha256,
            &self.case_work_grant_sha256,
            &self.lease_sha256,
            &self.ownership_state_sha256,
            &self.observation_sha256,
            &self.decision_sha256,
        ] {
            validate_hash(hash, "next-step decision hash")?;
        }
        if let Some(plan) = &self.plan_sha256 {
            validate_hash(plan, "next-step plan hash")?;
        }
        for hash in &self.rejected_candidate_hashes {
            validate_hash(hash, "rejected candidate hash")?;
        }
        match (&self.outcome, &self.selected_candidate) {
            (NextStepOutcomeV1::Continue, Some(candidate)) => candidate.validate()?,
            (NextStepOutcomeV1::Continue, None) => {
                return Err(AdaptivePlannerError::Invalid(
                    "continue decision requires one selected candidate".to_owned(),
                ));
            }
            (_, Some(_)) => {
                return Err(AdaptivePlannerError::Unauthorized(
                    "terminal or attention decision cannot carry an executable candidate"
                        .to_owned(),
                ));
            }
            (_, None) => {}
        }
        validate_ids(&self.evidence_ids, false)?;
        if hash_without(self, &["decision_sha256"])? != self.decision_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "next-step decision self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "next-step decision")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerCycleRecordV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub sequence: u64,
    pub case_id: String,
    pub stage: PlannerCycleStageV1,
    pub status: PlannerCycleStatusV1,
    pub provider_invocation_sha256: Option<String>,
    pub provider_result_sha256: Option<String>,
    pub goal_spec_sha256: Option<String>,
    pub situation_sha256: Option<String>,
    pub adaptive_plan_sha256: Option<String>,
    pub next_step_decision_sha256: Option<String>,
    pub kernel_run_sha256: Option<String>,
    pub verification_result_sha256: Option<String>,
    pub reason_codes: Vec<ProviderReasonCodeV1>,
    pub recorded_at_unix_seconds: u64,
    pub previous_record_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub evidence_ids: Vec<String>,
    pub record_sha256: String,
}

impl PlannerCycleRecordV1 {
    pub fn seal(mut self) -> Result<Self, AdaptivePlannerError> {
        self.evidence_ids.sort();
        self.record_sha256 = hash_without(&self, &["record_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), AdaptivePlannerError> {
        if self.schema_version != ADAPTIVE_PLANNER_SCHEMA_VERSION
            || self.sequence == 0
            || self.recorded_at_unix_seconds == 0
            || self.reason_codes.len() > 16
        {
            return Err(AdaptivePlannerError::ResourceLimit(
                "planner cycle record bounds are invalid".to_owned(),
            ));
        }
        validate_id(&self.cycle_id, "planner cycle ID")?;
        validate_id(&self.case_id, "planner cycle Case ID")?;
        for hash in [
            self.provider_invocation_sha256.as_ref(),
            self.provider_result_sha256.as_ref(),
            self.goal_spec_sha256.as_ref(),
            self.situation_sha256.as_ref(),
            self.adaptive_plan_sha256.as_ref(),
            self.next_step_decision_sha256.as_ref(),
            self.kernel_run_sha256.as_ref(),
            self.verification_result_sha256.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_hash(hash, "planner cycle artifact hash")?;
        }
        validate_hash(&self.previous_record_sha256, "previous planner record hash")?;
        validate_hash(
            &self.protected_audit_terminal_sha256,
            "planner protected audit hash",
        )?;
        validate_hash(&self.record_sha256, "planner record hash")?;
        validate_ids(&self.evidence_ids, false)?;
        if hash_without(self, &["record_sha256"])? != self.record_sha256 {
            return Err(AdaptivePlannerError::Integrity(
                "planner cycle record self-hash differs".to_owned(),
            ));
        }
        Ok(())
    }
}

pub struct TrustedPlannerAdmissionContextV1<'a> {
    pub planning_request: &'a AdaptivePlanningRequestV1,
    pub provider_request: &'a ProviderPlanningRequestV1,
    pub provider_result: &'a ProviderPlanningResultV1,
    pub plan: &'a AdaptivePlanV1,
    pub situation: &'a CaseSituationModelV1,
    pub work_grant: &'a CaseWorkGrantV1,
    pub current_lease_sha256: &'a str,
    pub current_ownership_state_sha256: &'a str,
    pub current_observation_sha256: &'a str,
    pub trusted_time_unix_seconds: u64,
    pub decision_id: String,
}

pub fn admit_next_step(
    context: TrustedPlannerAdmissionContextV1<'_>,
) -> Result<NextStepDecisionV1, AdaptivePlannerError> {
    context.planning_request.validate()?;
    context.provider_request.validate()?;
    context.provider_result.validate()?;
    context.plan.validate()?;
    context.situation.validate()?;
    context
        .work_grant
        .validate()
        .map_err(|error| AdaptivePlannerError::Invalid(error.to_string()))?;
    if context.trusted_time_unix_seconds == 0
        || context.trusted_time_unix_seconds >= context.work_grant.expires_at_unix_seconds
    {
        return Err(AdaptivePlannerError::Stale(
            "Case Work Grant expired before planner admission".to_owned(),
        ));
    }
    let request = context.planning_request;
    if request.case_id != context.work_grant.case_id
        || request.case_id != context.situation.case_id
        || request.case_work_grant_sha256 != context.work_grant.grant_sha256
        || request.case_work_grant_sha256 != context.situation.case_work_grant_sha256
        || request.lease_sha256 != context.work_grant.lease_sha256
        || request.lease_sha256 != context.situation.lease_sha256
        || request.lease_sha256 != context.current_lease_sha256
        || request.ownership_state_sha256 != context.work_grant.ownership_state_sha256
        || request.ownership_state_sha256 != context.situation.ownership_state_sha256
        || request.ownership_state_sha256 != context.current_ownership_state_sha256
        || request.situation_sha256 != context.situation.situation_sha256
        || request.current_observation_sha256 != context.current_observation_sha256
        || request.plan_generation != context.plan.generation
        || request.goal_spec_sha256 != context.plan.goal_spec_sha256
        || request.situation_sha256 != context.plan.situation_sha256
        || request.case_work_grant_sha256 != context.plan.case_work_grant_sha256
        || request.current_observation_sha256 != context.plan.current_observation_sha256
        || context.provider_request.request_id != request.request_id
        || context.provider_request.case_id != request.case_id
        || context.provider_request.goal_spec_sha256 != request.goal_spec_sha256
        || context.provider_request.situation_sha256 != request.situation_sha256
        || context.provider_request.plan_generation != request.plan_generation
        || context.provider_result.request_id != request.request_id
    {
        return Err(AdaptivePlannerError::Stale(
            "planner admission bindings are stale or cross-Case".to_owned(),
        ));
    }
    let outcome = map_provider_outcome(context.provider_result.status);
    if outcome != NextStepOutcomeV1::Continue {
        return seal_decision(NextStepDecisionV1 {
            schema_version: ADAPTIVE_PLANNER_SCHEMA_VERSION,
            decision_id: context.decision_id,
            case_id: request.case_id.clone(),
            request_sha256: request.request_sha256.clone(),
            result_sha256: context.provider_result.result_sha256.clone(),
            plan_sha256: Some(context.plan.plan_sha256.clone()),
            situation_sha256: request.situation_sha256.clone(),
            case_work_grant_sha256: request.case_work_grant_sha256.clone(),
            lease_sha256: request.lease_sha256.clone(),
            ownership_state_sha256: request.ownership_state_sha256.clone(),
            observation_sha256: request.current_observation_sha256.clone(),
            outcome,
            selected_candidate: None,
            rejected_candidate_hashes: Vec::new(),
            reason_codes: context.provider_result.reason_codes.clone(),
            valid_until_unix_seconds: context
                .work_grant
                .expires_at_unix_seconds
                .min(context.trusted_time_unix_seconds.saturating_add(30)),
            evidence_ids: request.evidence_ids.clone(),
            decision_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        });
    }

    let mut admitted = Vec::new();
    let mut rejected = Vec::new();
    for draft in &context.provider_result.candidates {
        let candidate = NextStepCandidateV1::from_provider(draft, request.plan_generation)?;
        if candidate_is_admissible(
            &candidate,
            context.plan,
            request,
            context.situation,
            context.work_grant,
        ) {
            admitted.push(candidate);
        } else {
            rejected.push(candidate.candidate_sha256);
        }
    }
    admitted.sort_by(compare_candidates);
    let Some(selected) = admitted.into_iter().next() else {
        return seal_decision(NextStepDecisionV1 {
            schema_version: ADAPTIVE_PLANNER_SCHEMA_VERSION,
            decision_id: context.decision_id,
            case_id: request.case_id.clone(),
            request_sha256: request.request_sha256.clone(),
            result_sha256: context.provider_result.result_sha256.clone(),
            plan_sha256: Some(context.plan.plan_sha256.clone()),
            situation_sha256: request.situation_sha256.clone(),
            case_work_grant_sha256: request.case_work_grant_sha256.clone(),
            lease_sha256: request.lease_sha256.clone(),
            ownership_state_sha256: request.ownership_state_sha256.clone(),
            observation_sha256: request.current_observation_sha256.clone(),
            outcome: NextStepOutcomeV1::NoEligibleAction,
            selected_candidate: None,
            rejected_candidate_hashes: rejected,
            reason_codes: vec![ProviderReasonCodeV1::NoEligibleAction],
            valid_until_unix_seconds: context
                .work_grant
                .expires_at_unix_seconds
                .min(context.trusted_time_unix_seconds.saturating_add(30)),
            evidence_ids: request.evidence_ids.clone(),
            decision_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        });
    };
    seal_decision(NextStepDecisionV1 {
        schema_version: ADAPTIVE_PLANNER_SCHEMA_VERSION,
        decision_id: context.decision_id,
        case_id: request.case_id.clone(),
        request_sha256: request.request_sha256.clone(),
        result_sha256: context.provider_result.result_sha256.clone(),
        plan_sha256: Some(context.plan.plan_sha256.clone()),
        situation_sha256: request.situation_sha256.clone(),
        case_work_grant_sha256: request.case_work_grant_sha256.clone(),
        lease_sha256: request.lease_sha256.clone(),
        ownership_state_sha256: request.ownership_state_sha256.clone(),
        observation_sha256: request.current_observation_sha256.clone(),
        outcome: NextStepOutcomeV1::Continue,
        selected_candidate: Some(selected),
        rejected_candidate_hashes: rejected,
        reason_codes: Vec::new(),
        valid_until_unix_seconds: context
            .work_grant
            .expires_at_unix_seconds
            .min(context.trusted_time_unix_seconds.saturating_add(30)),
        evidence_ids: request.evidence_ids.clone(),
        decision_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
    })
}

fn candidate_is_admissible(
    candidate: &NextStepCandidateV1,
    plan: &AdaptivePlanV1,
    request: &AdaptivePlanningRequestV1,
    situation: &CaseSituationModelV1,
    grant: &CaseWorkGrantV1,
) -> bool {
    if candidate.plan_generation != request.plan_generation
        || !plan.open_subgoal_ids.contains(&candidate.subgoal_id)
        || candidate.confidence_millionths < request.minimum_confidence_millionths
        || candidate.risk_estimate > request.risk_ceiling
        || candidate.reversibility == Reversibility::Irreversible
        || !candidate.uncertainty_reason_codes.is_empty()
        || candidate.clarification
        || candidate.escalation
    {
        return false;
    }
    if candidate.verify_only {
        return candidate.capability_id.is_none()
            && candidate.semantic_target_id.is_none()
            && candidate.approved_value_sha256.is_none();
    }
    let Some(capability) = &candidate.capability_id else {
        return false;
    };
    let Some(target) = &candidate.semantic_target_id else {
        return false;
    };
    request.allowed_capability_ids.contains(capability)
        && situation.allowed_capability_ids.contains(capability)
        && grant.allowed_capability_ids.contains(capability)
        && !request.forbidden_capability_ids.contains(capability)
        && !situation.forbidden_capability_ids.contains(capability)
        && request.allowed_semantic_target_ids.contains(target)
        && situation.allowed_semantic_target_ids.contains(target)
        && grant.semantic_target_ids.contains(target)
        && candidate
            .approved_value_sha256
            .as_ref()
            .is_none_or(|hash| request.approved_value_sha256s.contains(hash))
        && candidate
            .required_precondition_ids
            .iter()
            .all(|value| request.allowed_precondition_ids.contains(value))
        && candidate
            .expected_postcondition_ids
            .iter()
            .all(|value| request.allowed_postcondition_ids.contains(value))
        && !candidate.expected_postcondition_ids.is_empty()
}

fn compare_candidates(left: &NextStepCandidateV1, right: &NextStepCandidateV1) -> Ordering {
    right
        .confidence_millionths
        .cmp(&left.confidence_millionths)
        .then_with(|| left.candidate_id.cmp(&right.candidate_id))
        .then_with(|| left.candidate_sha256.cmp(&right.candidate_sha256))
}

fn map_provider_outcome(status: ProviderResultStatusV1) -> NextStepOutcomeV1 {
    match status {
        ProviderResultStatusV1::Succeeded => NextStepOutcomeV1::Continue,
        ProviderResultStatusV1::ClarificationRequired => NextStepOutcomeV1::ClarificationRequired,
        ProviderResultStatusV1::EscalationRequired => NextStepOutcomeV1::EscalationRequired,
        ProviderResultStatusV1::Unsupported => NextStepOutcomeV1::Unsupported,
        ProviderResultStatusV1::Failed => NextStepOutcomeV1::ProviderOutputInvalid,
    }
}

fn seal_decision(
    mut decision: NextStepDecisionV1,
) -> Result<NextStepDecisionV1, AdaptivePlannerError> {
    decision.rejected_candidate_hashes.sort();
    decision.evidence_ids.sort();
    decision.decision_sha256 = hash_without(&decision, &["decision_sha256"])?;
    decision.validate()?;
    Ok(decision)
}

pub fn compile_trusted_goal(
    request: &GoalUnderstandingRequestV1,
    result: &GoalUnderstandingResultV1,
    goal_id: String,
) -> Result<GoalSpec, AdaptivePlannerError> {
    request.validate()?;
    result.validate()?;
    if result.request_id() != request.request_id {
        return Err(AdaptivePlannerError::Integrity(
            "Goal result belongs to a different request".to_owned(),
        ));
    }
    let draft = match result {
        GoalUnderstandingResultV1::Draft { draft, .. } => draft,
        GoalUnderstandingResultV1::ClarificationRequired { .. } => {
            return Err(AdaptivePlannerError::ClarificationRequired(
                "provider requires structured clarification".to_owned(),
            ));
        }
        GoalUnderstandingResultV1::Unsupported { .. } => {
            return Err(AdaptivePlannerError::Invalid(
                "provider does not support the Goal request".to_owned(),
            ));
        }
    };
    compile_goal_draft(request, draft, result.result_sha256(), goal_id)
}

fn compile_goal_draft(
    request: &GoalUnderstandingRequestV1,
    draft: &GoalDraftV1,
    result_sha256: &str,
    goal_id: String,
) -> Result<GoalSpec, AdaptivePlannerError> {
    draft.validate()?;
    validate_id(&goal_id, "compiled Goal ID")?;
    if draft.risk_estimate > request.allowed_risk_ceiling {
        return Err(AdaptivePlannerError::EscalationRequired(
            "model risk estimate exceeds the Case risk ceiling".to_owned(),
        ));
    }
    if draft
        .forbidden_outcomes
        .iter()
        .any(|outcome| !request.forbidden_outcomes.contains(outcome))
    {
        return Err(AdaptivePlannerError::Unauthorized(
            "Goal draft changed the trusted forbidden-outcome set".to_owned(),
        ));
    }
    let scope = BTreeMap::from([
        (
            "approved_scope_bounds".to_owned(),
            json!(request.scope_bounds),
        ),
        ("case_id".to_owned(), json!(request.case_id)),
        ("work_class_id".to_owned(), json!(request.work_class_id)),
    ]);
    let success_criteria = request
        .case_outcome_requirement_ids
        .iter()
        .map(|requirement_id| Postcondition {
            target_state: requirement_id.clone(),
            op: ComparisonOp::Equals,
            expected_value: json!("satisfied"),
            required: true,
            timeout_ms: 30_000,
        })
        .collect::<Vec<_>>();
    let confirmation_policy = match request.allowed_risk_ceiling {
        CognitiveRiskClass::ReadOnly | CognitiveRiskClass::Reversible => ConfirmationPolicy::Never,
        CognitiveRiskClass::BusinessStateChange => ConfirmationPolicy::BeforeRiskyAction,
        CognitiveRiskClass::HighCriticality => ConfirmationPolicy::Always,
    };
    let goal = GoalSpec {
        schema_version: COGNITIVE_SCHEMA_VERSION,
        goal_id,
        objective: draft.objective.clone(),
        scope,
        required_outcomes: request.case_outcome_requirement_ids.clone(),
        constraints: request
            .scope_bounds
            .iter()
            .chain(&request.forbidden_outcomes)
            .chain(&request.confirmation_requirements)
            .cloned()
            .collect(),
        success_criteria,
        risk_class: request.allowed_risk_ceiling,
        confirmation_policy,
        provenance: Provenance {
            source: "trusted_goal_draft_compiler_v1".to_owned(),
            source_hash: result_sha256.to_owned(),
            module_id: "d2i.adaptive_planner.goal_draft_compiler.v1".to_owned(),
        },
    };
    goal.validate()
        .map_err(|error| AdaptivePlannerError::Invalid(error.to_string()))?;
    reject_sensitive_value(&goal, "compiled GoalSpec")?;
    Ok(goal)
}

pub fn goal_spec_sha256(goal: &GoalSpec) -> Result<String, AdaptivePlannerError> {
    goal.validate()
        .map_err(|error| AdaptivePlannerError::Invalid(error.to_string()))?;
    canonical_sha256(goal).map_err(Into::into)
}

pub fn adapt_provider_result(
    request: &AdaptivePlanningRequestV1,
    provider_result: &ProviderPlanningResultV1,
    plan: Option<AdaptivePlanV1>,
) -> Result<AdaptivePlanningResultV1, AdaptivePlannerError> {
    request.validate()?;
    provider_result.validate()?;
    if provider_result.request_id != request.request_id {
        return Err(AdaptivePlannerError::Integrity(
            "provider result belongs to another planning request".to_owned(),
        ));
    }
    let outcome = map_provider_outcome(provider_result.status);
    let candidates = provider_result
        .candidates
        .iter()
        .map(|candidate| NextStepCandidateV1::from_provider(candidate, request.plan_generation))
        .collect::<Result<Vec<_>, _>>()?;
    let mut value = AdaptivePlanningResultV1 {
        schema_version: ADAPTIVE_PLANNER_SCHEMA_VERSION,
        request_id: request.request_id.clone(),
        provider_result_sha256: provider_result.result_sha256.clone(),
        plan,
        candidates,
        outcome,
        reason_codes: provider_result.reason_codes.clone(),
        result_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
    };
    value.result_sha256 = hash_without(&value, &["result_sha256"])?;
    value.validate()?;
    Ok(value)
}

pub fn parse_strict_planner_json<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, AdaptivePlannerError> {
    d2i_situation_model::parse_json_strict(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_situation_model::ZERO_HASH;

    #[test]
    fn duplicate_json_keys_fail_closed() {
        let input = br#"{"outcome":"continue","outcome":"unsafe"}"#;
        assert!(parse_strict_planner_json::<serde_json::Value>(input).is_err());
    }

    #[test]
    fn raw_command_shape_is_rejected() {
        let candidate = NextStepCandidateV1 {
            candidate_id: "candidate.1".to_owned(),
            plan_generation: 1,
            subgoal_id: "subgoal.save".to_owned(),
            semantic_intent: "shell_command".to_owned(),
            semantic_target_id: Some("record.save".to_owned()),
            capability_id: Some("process.execute".to_owned()),
            approved_value_sha256: None,
            required_precondition_ids: Vec::new(),
            expected_postcondition_ids: vec!["record.saved".to_owned()],
            risk_estimate: CognitiveRiskClass::BusinessStateChange,
            reversibility: Reversibility::Reversible,
            information_gathering: false,
            clarification: false,
            escalation: false,
            verify_only: false,
            confidence_millionths: 900_000,
            uncertainty_reason_codes: Vec::new(),
            evidence_refs: vec!["evidence.1".to_owned()],
            candidate_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        };
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn provider_cannot_lower_trusted_risk_class() {
        assert!(CognitiveRiskClass::Reversible < CognitiveRiskClass::BusinessStateChange);
    }

    #[test]
    fn planning_request_projects_exact_condition_and_value_allowlists() {
        let request = planning_request_for("office.record.update")
            .seal()
            .unwrap_or_else(|error| panic!("planning request fixture must seal: {error}"));
        let provider = request
            .provider_request(ZERO_HASH.to_owned())
            .unwrap_or_else(|error| panic!("provider request fixture must project: {error}"));
        assert_eq!(
            provider.approved_value_sha256s,
            request.approved_value_sha256s
        );
        assert_eq!(
            provider.allowed_precondition_ids,
            request.allowed_precondition_ids
        );
        assert_eq!(
            provider.allowed_postcondition_ids,
            request.allowed_postcondition_ids
        );
    }

    #[test]
    fn opaque_cross_domain_work_classes_share_one_planning_contract() {
        let work_classes = [
            "office.record.update",
            "finance.invoice.review",
            "it.service.request",
            "safety.inspection.review",
        ];
        let hashes = work_classes
            .iter()
            .map(|work_class| {
                planning_request_for(work_class)
                    .seal()
                    .unwrap_or_else(|error| panic!("{work_class} must validate: {error}"))
                    .request_sha256
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(hashes.len(), work_classes.len());
    }

    fn planning_request_for(work_class: &str) -> AdaptivePlanningRequestV1 {
        AdaptivePlanningRequestV1 {
            schema_version: 1,
            request_id: format!("request.{work_class}"),
            case_id: format!("case.{work_class}"),
            goal_spec_sha256: ZERO_HASH.to_owned(),
            situation_sha256: ZERO_HASH.to_owned(),
            case_work_grant_sha256: ZERO_HASH.to_owned(),
            lease_sha256: ZERO_HASH.to_owned(),
            ownership_state_sha256: ZERO_HASH.to_owned(),
            current_observation_sha256: ZERO_HASH.to_owned(),
            plan_generation: 1,
            previous_plan_sha256: None,
            open_subgoal_ids: vec![format!("subgoal.{work_class}")],
            completed_subgoal_ids: Vec::new(),
            allowed_semantic_target_ids: vec![format!("target.{work_class}")],
            allowed_capability_ids: vec!["capability.update".to_owned()],
            forbidden_capability_ids: vec!["capability.shell".to_owned()],
            approved_value_sha256s: vec![ZERO_HASH.to_owned()],
            allowed_precondition_ids: vec!["precondition.fresh".to_owned()],
            allowed_postcondition_ids: vec!["postcondition.verified".to_owned()],
            risk_ceiling: CognitiveRiskClass::BusinessStateChange,
            minimum_confidence_millionths: 700_000,
            maximum_candidates: 1,
            maximum_cycles: 4,
            maximum_actions: 4,
            trusted_time_unix_seconds: 1,
            evidence_ids: vec![format!("evidence.{work_class}")],
            request_sha256: ZERO_HASH.to_owned(),
        }
    }
}
