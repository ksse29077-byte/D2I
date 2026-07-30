use crate::{
    hash_value, validate_hash, validate_text, validate_token, CognitiveRiskClass, ComparisonOp,
    ConfirmationPolicy, ConfirmationRequirement, DesktopError, ExecutionStatus, GoalProgress,
    ObservationSnapshot, Provenance, Reversibility,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const VERIFICATION_SCHEMA_VERSION: u32 = 2;
const MAX_POSTCONDITIONS: usize = 256;
const MAX_EVIDENCE_ITEMS: usize = 256;
const MAX_WARNING_ITEMS: usize = 128;
const MAX_UNEXPECTED_CHANGES: usize = 128;

/// Observation field that a v2 verifier may compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiableObservationFieldV2 {
    /// Whether the referenced element exists in the fresh snapshot.
    ElementExists,
    /// The typed `ObservableElement.value` field.
    ElementValue,
    /// The normalized `ObservableElement.kind` field.
    ElementKind,
}

/// Typed reference to a fact exposed by an `ObservationSnapshot`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationTargetV2 {
    /// Snapshot-local semantic element identifier.
    pub element_id: String,
    /// Bounded observable field.
    pub field: VerifiableObservationFieldV2,
}

impl VerificationTargetV2 {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.element_id, "verification target element_id")
    }
}

/// Typed postcondition whose truth can be determined from a supplied snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiablePostconditionV2 {
    /// Stable identifier used to bind a result to this criterion.
    pub criterion_id: String,
    /// Observable fact to compare.
    pub target: VerificationTargetV2,
    /// Comparison operator.
    pub op: ComparisonOp,
    /// Expected typed value.
    pub expected_value: Value,
    /// Whether failure prevents action success or goal completion.
    pub required: bool,
}

impl VerifiablePostconditionV2 {
    /// Validates the target and operator/value combination.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.criterion_id, "verification criterion_id")?;
        self.target.validate()?;
        match self.target.field {
            VerifiableObservationFieldV2::ElementExists => {
                if self.op != ComparisonOp::Equals || !self.expected_value.is_boolean() {
                    return Err(DesktopError::Invalid(
                        "element_exists requires equals with a boolean expected_value".to_owned(),
                    ));
                }
            }
            VerifiableObservationFieldV2::ElementKind => {
                if !matches!(self.op, ComparisonOp::Equals | ComparisonOp::NotEquals)
                    || !self.expected_value.is_string()
                {
                    return Err(DesktopError::Invalid(
                        "element_kind requires equals or not_equals with a string expected_value"
                            .to_owned(),
                    ));
                }
            }
            VerifiableObservationFieldV2::ElementValue => match self.op {
                ComparisonOp::Contains if !self.expected_value.is_string() => {
                    return Err(DesktopError::Invalid(
                        "contains requires a string expected_value".to_owned(),
                    ));
                }
                ComparisonOp::Exists if !self.expected_value.is_boolean() => {
                    return Err(DesktopError::Invalid(
                        "exists requires a boolean expected_value".to_owned(),
                    ));
                }
                ComparisonOp::GreaterOrEqual | ComparisonOp::LessOrEqual
                    if !self.expected_value.is_number() =>
                {
                    return Err(DesktopError::Invalid(
                        "ordered comparison requires a numeric expected_value".to_owned(),
                    ));
                }
                _ => {}
            },
        }
        Ok(())
    }
}

/// Goal contract used by Cognitive Verification Contract v2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationGoalSpecV2 {
    /// Contract schema version. Must be `2`.
    pub schema_version: u32,
    /// Goal lifecycle identifier.
    pub goal_id: String,
    /// Human-authored objective retained as data.
    pub objective: String,
    /// Bounded goal scope.
    pub scope: BTreeMap<String, Value>,
    /// Required business outcomes.
    pub required_outcomes: Vec<String>,
    /// Goal constraints.
    pub constraints: Vec<String>,
    /// Criteria required to determine overall goal progress.
    pub success_criteria: Vec<VerifiablePostconditionV2>,
    /// Goal risk classification.
    pub risk_class: CognitiveRiskClass,
    /// Goal confirmation policy.
    pub confirmation_policy: ConfirmationPolicy,
    /// Goal provenance.
    pub provenance: Provenance,
}

impl VerificationGoalSpecV2 {
    /// Validates bounds, identifiers, provenance, and typed success criteria.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_v2(self.schema_version, "verification goal")?;
        validate_token(&self.goal_id, "verification goal_id")?;
        validate_text(&self.objective, "verification objective")?;
        validate_text_collection(&self.required_outcomes, "required_outcomes", 64)?;
        validate_text_collection(&self.constraints, "constraints", 128)?;
        validate_postconditions(&self.success_criteria, "goal success_criteria", true)?;
        validate_provenance(&self.provenance)?;
        let _ = hash_value(self)?;
        Ok(())
    }
}

/// Action proposal bound to the observation from which it was produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationActionProposalV2 {
    /// Contract schema version. Must be `2`.
    pub schema_version: u32,
    /// Proposal lifecycle identifier.
    pub proposal_id: String,
    /// Goal lifecycle identifier.
    pub goal_id: String,
    /// Plan generation that produced this proposal.
    pub plan_generation_id: String,
    /// Exact source observation identifier.
    pub source_observation_id: String,
    /// Exact source observation stable state hash.
    pub source_observation_hash: String,
    /// Exact source observation logical sequence.
    pub source_observation_sequence: u64,
    /// Declared capability.
    pub capability_id: String,
    /// Semantic target description retained as data.
    pub semantic_target: String,
    /// Typed action arguments.
    pub arguments: Value,
    /// Preconditions checked before execution.
    pub preconditions: Vec<VerifiablePostconditionV2>,
    /// Postconditions checked after execution.
    pub expected_postconditions: Vec<VerifiablePostconditionV2>,
    /// Action risk.
    pub risk: CognitiveRiskClass,
    /// Reversibility declaration.
    pub reversibility: Reversibility,
    /// Confirmation declaration.
    pub confirmation_requirement: ConfirmationRequirement,
    /// Proposal confidence.
    pub confidence: f64,
    /// Proposal evidence.
    pub evidence: Vec<String>,
    /// Last source-observation sequence for which the proposal is valid.
    pub valid_until_sequence: u64,
}

impl VerificationActionProposalV2 {
    /// Validates the proposal and its exact source-observation binding.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_v2(self.schema_version, "verification action proposal")?;
        validate_token(&self.proposal_id, "verification proposal_id")?;
        validate_token(&self.goal_id, "verification proposal goal_id")?;
        validate_token(
            &self.plan_generation_id,
            "verification proposal plan_generation_id",
        )?;
        validate_token(
            &self.source_observation_id,
            "verification proposal source_observation_id",
        )?;
        validate_hash(
            &self.source_observation_hash,
            "verification proposal source_observation_hash",
        )?;
        validate_token(&self.capability_id, "verification capability_id")?;
        validate_text(&self.semantic_target, "verification semantic_target")?;
        validate_postconditions(&self.preconditions, "proposal preconditions", false)?;
        validate_postconditions(
            &self.expected_postconditions,
            "proposal expected_postconditions",
            true,
        )?;
        if self.reversibility == Reversibility::Irreversible {
            return Err(DesktopError::AccessDenied(
                "irreversible proposals are unsupported by verification contract v2".to_owned(),
            ));
        }
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return Err(DesktopError::Invalid(
                "verification proposal confidence must be finite and within 0..1".to_owned(),
            ));
        }
        validate_text_collection(&self.evidence, "proposal evidence", MAX_EVIDENCE_ITEMS)?;
        if self.valid_until_sequence < self.source_observation_sequence {
            return Err(DesktopError::Replay(
                "proposal validity precedes its source observation".to_owned(),
            ));
        }
        let _ = hash_value(self)?;
        Ok(())
    }
}

/// Execution record cryptographically and logically bound to one proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundActionExecutionV2 {
    /// Contract schema version. Must be `2`.
    pub schema_version: u32,
    /// Stable execution-attempt identifier.
    pub execution_id: String,
    /// Exact executed proposal.
    pub proposal_id: String,
    /// Exact goal.
    pub goal_id: String,
    /// Exact plan generation.
    pub plan_generation_id: String,
    /// Exact pre-execution observation identifier.
    pub source_observation_id: String,
    /// Exact pre-execution observation state hash.
    pub source_observation_hash: String,
    /// Exact pre-execution observation sequence.
    pub source_observation_sequence: u64,
    /// Executor-reported status. This is not a verification verdict.
    pub status: ExecutionStatus,
    /// Executor evidence.
    pub evidence: Vec<String>,
    /// Executor warnings.
    pub warnings: Vec<String>,
}

impl BoundActionExecutionV2 {
    /// Validates execution identity and bounded diagnostic collections.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_v2(self.schema_version, "bound action execution")?;
        validate_token(&self.execution_id, "execution_id")?;
        validate_token(&self.proposal_id, "execution proposal_id")?;
        validate_token(&self.goal_id, "execution goal_id")?;
        validate_token(&self.plan_generation_id, "execution plan_generation_id")?;
        validate_token(
            &self.source_observation_id,
            "execution source_observation_id",
        )?;
        validate_hash(
            &self.source_observation_hash,
            "execution source_observation_hash",
        )?;
        validate_text_collection(&self.evidence, "execution evidence", MAX_EVIDENCE_ITEMS)?;
        validate_text_collection(&self.warnings, "execution warnings", MAX_WARNING_ITEMS)
    }
}

/// Complete side-effect-free verifier input with pre/post observation evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationRequestV2 {
    /// Contract schema version. Must be `2`.
    pub schema_version: u32,
    /// Stable request identifier used for result binding.
    pub verification_id: String,
    /// Original typed goal contract.
    pub goal: VerificationGoalSpecV2,
    /// Original typed action proposal.
    pub proposal: VerificationActionProposalV2,
    /// Bound execution result.
    pub execution: BoundActionExecutionV2,
    /// Snapshot from which the proposal was produced.
    pub source_observation: ObservationSnapshot,
    /// Snapshot freshly collected after the execution attempt.
    pub fresh_observation: ObservationSnapshot,
}

impl VerificationRequestV2 {
    /// Validates all lifecycle, freshness, target, and hash bindings.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_v2(self.schema_version, "verification request")?;
        validate_token(&self.verification_id, "verification_id")?;
        self.goal.validate()?;
        self.proposal.validate()?;
        self.execution.validate()?;
        self.source_observation.validate()?;
        self.fresh_observation.validate()?;

        if self.goal.goal_id != self.proposal.goal_id || self.goal.goal_id != self.execution.goal_id
        {
            return Err(DesktopError::Integrity(
                "verification goal lifecycle binding mismatch".to_owned(),
            ));
        }
        if self.proposal.proposal_id != self.execution.proposal_id {
            return Err(DesktopError::Integrity(
                "execution is not bound to the supplied proposal".to_owned(),
            ));
        }
        if self.proposal.plan_generation_id != self.execution.plan_generation_id {
            return Err(DesktopError::Replay(
                "execution plan generation does not match proposal".to_owned(),
            ));
        }
        if self.proposal.source_observation_id != self.source_observation.observation_id
            || self.execution.source_observation_id != self.source_observation.observation_id
        {
            return Err(DesktopError::Replay(
                "source observation identifier binding mismatch".to_owned(),
            ));
        }
        if self.proposal.source_observation_hash != self.source_observation.state_hash
            || self.execution.source_observation_hash != self.source_observation.state_hash
        {
            return Err(DesktopError::Replay(
                "source observation hash binding mismatch".to_owned(),
            ));
        }
        if self.proposal.source_observation_sequence != self.source_observation.sequence
            || self.execution.source_observation_sequence != self.source_observation.sequence
        {
            return Err(DesktopError::Replay(
                "source observation sequence binding mismatch".to_owned(),
            ));
        }
        if self.proposal.valid_until_sequence < self.source_observation.sequence {
            return Err(DesktopError::Replay(
                "proposal expired before its bound source observation".to_owned(),
            ));
        }
        if self.fresh_observation.sequence <= self.source_observation.sequence {
            return Err(DesktopError::Replay(
                "post-execution observation sequence is not fresh".to_owned(),
            ));
        }
        if self.fresh_observation.observation_id == self.source_observation.observation_id {
            return Err(DesktopError::Replay(
                "post-execution observation reused the source observation identifier".to_owned(),
            ));
        }
        if self.fresh_observation.source_kind != self.source_observation.source_kind
            || self.fresh_observation.target_binding != self.source_observation.target_binding
        {
            return Err(DesktopError::Integrity(
                "post-execution observation target binding changed".to_owned(),
            ));
        }
        let _ = hash_value(self)?;
        Ok(())
    }

    /// Computes the stable canonical request hash used by replay adapters.
    pub fn canonical_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Terminal verification verdict, independent of executor status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdictV2 {
    /// All required observable criteria passed.
    Passed,
    /// At least one required observable criterion failed.
    Failed,
    /// Evidence is insufficient or conflicting.
    Inconclusive,
    /// The requested criterion is outside the frozen verifier capability.
    Unsupported,
    /// Verification observed an unsafe or unexpected state change.
    Unsafe,
}

/// Confidence declaration for deterministic rule verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationConfidenceV2 {
    /// Numeric confidence is intentionally not used by this contract.
    NotApplicable,
}

/// Result for one exact action or goal postcondition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostconditionResultV2 {
    /// Exact criterion identifier.
    pub criterion_id: String,
    /// Exact typed target.
    pub target: VerificationTargetV2,
    /// Terminal criterion verdict.
    pub verdict: VerificationVerdictV2,
    /// Whether this criterion is required.
    pub required: bool,
    /// Observed typed value, or `None` when unavailable.
    pub observed_value: Option<Value>,
    /// Deterministic reason.
    pub reason: String,
    /// Bounded evidence references.
    pub evidence: Vec<String>,
}

impl PostconditionResultV2 {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.criterion_id, "postcondition result criterion_id")?;
        self.target.validate()?;
        validate_text(&self.reason, "postcondition result reason")?;
        validate_text_collection(
            &self.evidence,
            "postcondition result evidence",
            MAX_EVIDENCE_ITEMS,
        )
    }
}

/// Verification result bound to one request, execution, and fresh observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResultV2 {
    /// Contract schema version. Must be `2`.
    pub schema_version: u32,
    /// Exact verification request identifier.
    pub verification_id: String,
    /// Exact goal identifier.
    pub goal_id: String,
    /// Exact plan generation.
    pub plan_generation_id: String,
    /// Exact proposal identifier.
    pub proposal_id: String,
    /// Exact execution identifier.
    pub execution_id: String,
    /// Executor status copied without promoting it to verified success.
    pub execution_status: ExecutionStatus,
    /// Independent action verification verdict.
    pub action_verdict: VerificationVerdictV2,
    /// Results for the proposal's expected postconditions.
    pub action_postcondition_results: Vec<PostconditionResultV2>,
    /// Results for the goal's success criteria.
    pub goal_postcondition_results: Vec<PostconditionResultV2>,
    /// Stable state hash of the fresh observation.
    pub observed_state_hash: String,
    /// Overall goal progress after this verification.
    pub goal_progress: GoalProgress,
    /// Unexpected observable changes that prevent an unqualified pass.
    pub unexpected_changes: Vec<String>,
    /// Bounded warnings.
    pub warnings: Vec<String>,
    /// Bounded evidence references.
    pub evidence: Vec<String>,
    /// Deterministic result reason.
    pub reason: String,
    /// Result provenance.
    pub provenance: Provenance,
    /// Explicit deterministic confidence semantics.
    pub confidence: VerificationConfidenceV2,
}

impl VerificationResultV2 {
    /// Validates result fields without trusting a caller-supplied request.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_v2(self.schema_version, "verification result")?;
        validate_token(&self.verification_id, "result verification_id")?;
        validate_token(&self.goal_id, "result goal_id")?;
        validate_token(&self.plan_generation_id, "result plan_generation_id")?;
        validate_token(&self.proposal_id, "result proposal_id")?;
        validate_token(&self.execution_id, "result execution_id")?;
        validate_hash(&self.observed_state_hash, "result observed_state_hash")?;
        validate_result_collection(
            &self.action_postcondition_results,
            "action postcondition results",
        )?;
        validate_result_collection(
            &self.goal_postcondition_results,
            "goal postcondition results",
        )?;
        validate_text_collection(
            &self.unexpected_changes,
            "unexpected_changes",
            MAX_UNEXPECTED_CHANGES,
        )?;
        validate_text_collection(&self.warnings, "verification warnings", MAX_WARNING_ITEMS)?;
        validate_text_collection(&self.evidence, "verification evidence", MAX_EVIDENCE_ITEMS)?;
        validate_text(&self.reason, "verification reason")?;
        validate_provenance(&self.provenance)?;
        let _ = hash_value(self)?;
        Ok(())
    }

    /// Validates exact request/result binding and fail-closed verdict semantics.
    pub fn validate_against(&self, request: &VerificationRequestV2) -> Result<(), DesktopError> {
        request.validate()?;
        self.validate()?;
        if self.verification_id != request.verification_id
            || self.goal_id != request.goal.goal_id
            || self.plan_generation_id != request.proposal.plan_generation_id
            || self.proposal_id != request.proposal.proposal_id
            || self.execution_id != request.execution.execution_id
        {
            return Err(DesktopError::Integrity(
                "verification result lifecycle binding mismatch".to_owned(),
            ));
        }
        if self.execution_status != request.execution.status {
            return Err(DesktopError::Integrity(
                "verification result changed executor status".to_owned(),
            ));
        }
        if self.observed_state_hash != request.fresh_observation.state_hash {
            return Err(DesktopError::Replay(
                "verification result is bound to another observation".to_owned(),
            ));
        }
        validate_result_bindings(
            &request.proposal.expected_postconditions,
            &self.action_postcondition_results,
            "action",
        )?;
        validate_result_bindings(
            &request.goal.success_criteria,
            &self.goal_postcondition_results,
            "goal",
        )?;
        validate_observed_results(
            &request.proposal.expected_postconditions,
            &self.action_postcondition_results,
            &request.fresh_observation,
            "action",
        )?;
        validate_observed_results(
            &request.goal.success_criteria,
            &self.goal_postcondition_results,
            &request.fresh_observation,
            "goal",
        )?;

        let expected_action_verdict = expected_action_verdict(
            request.execution.status,
            &self.action_postcondition_results,
            &self.unexpected_changes,
        );
        if self.action_verdict != expected_action_verdict {
            return Err(DesktopError::Invalid(
                "action verdict does not match execution and required postconditions".to_owned(),
            ));
        }

        let expected_goal_progress =
            expected_goal_progress(self.action_verdict, &self.goal_postcondition_results);
        if self.goal_progress != expected_goal_progress {
            return Err(DesktopError::Invalid(
                "goal progress does not match action and goal postcondition results".to_owned(),
            ));
        }
        Ok(())
    }

    /// Computes the stable canonical result hash after request binding checks.
    pub fn canonical_hash_against(
        &self,
        request: &VerificationRequestV2,
    ) -> Result<String, DesktopError> {
        self.validate_against(request)?;
        hash_value(self)
    }
}

/// Side-effect-free v2 verifier boundary.
///
/// Implementations receive typed data only. They do not receive adapter,
/// policy, activation, audit, filesystem, process, secret, or network
/// authority.
pub trait PostconditionVerifierV2 {
    /// Verifies one bound execution against a caller-supplied fresh observation.
    fn verify(
        &mut self,
        request: &VerificationRequestV2,
    ) -> Result<VerificationResultV2, DesktopError>;
}

fn validate_v2(version: u32, label: &str) -> Result<(), DesktopError> {
    if version != VERIFICATION_SCHEMA_VERSION {
        return Err(DesktopError::Invalid(format!(
            "{label} schema_version must be {VERIFICATION_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn validate_provenance(value: &Provenance) -> Result<(), DesktopError> {
    validate_text(&value.source, "verification provenance source")?;
    validate_hash(&value.source_hash, "verification provenance source_hash")?;
    validate_token(&value.module_id, "verification provenance module_id")
}

fn validate_text_collection(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), DesktopError> {
    if values.len() > maximum {
        return Err(DesktopError::Invalid(format!(
            "{field} exceeds {maximum} entries"
        )));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_postconditions(
    values: &[VerifiablePostconditionV2],
    field: &str,
    require_nonempty: bool,
) -> Result<(), DesktopError> {
    if (require_nonempty && values.is_empty()) || values.len() > MAX_POSTCONDITIONS {
        return Err(DesktopError::Invalid(format!(
            "{field} exceeds its allowed entry count"
        )));
    }
    let mut identifiers = BTreeSet::new();
    for value in values {
        value.validate()?;
        if !identifiers.insert(value.criterion_id.as_str()) {
            return Err(DesktopError::Invalid(format!(
                "{field} contains duplicate criterion_id '{}'",
                value.criterion_id
            )));
        }
    }
    Ok(())
}

fn validate_result_collection(
    values: &[PostconditionResultV2],
    field: &str,
) -> Result<(), DesktopError> {
    if values.is_empty() || values.len() > MAX_POSTCONDITIONS {
        return Err(DesktopError::Invalid(format!(
            "{field} must contain 1..={MAX_POSTCONDITIONS} entries"
        )));
    }
    let mut identifiers = BTreeSet::new();
    for value in values {
        value.validate()?;
        if !identifiers.insert(value.criterion_id.as_str()) {
            return Err(DesktopError::Invalid(format!(
                "{field} contains duplicate criterion_id '{}'",
                value.criterion_id
            )));
        }
    }
    Ok(())
}

fn validate_result_bindings(
    expected: &[VerifiablePostconditionV2],
    actual: &[PostconditionResultV2],
    label: &str,
) -> Result<(), DesktopError> {
    if expected.len() != actual.len() {
        return Err(DesktopError::Integrity(format!(
            "{label} postcondition result count mismatch"
        )));
    }
    let expected_by_id = expected
        .iter()
        .map(|criterion| (criterion.criterion_id.as_str(), criterion))
        .collect::<BTreeMap<_, _>>();
    for result in actual {
        let Some(criterion) = expected_by_id.get(result.criterion_id.as_str()) else {
            return Err(DesktopError::Integrity(format!(
                "{label} result references an undeclared criterion"
            )));
        };
        if result.target != criterion.target || result.required != criterion.required {
            return Err(DesktopError::Integrity(format!(
                "{label} result changed criterion target or required status"
            )));
        }
    }
    Ok(())
}

fn required_results_passed(values: &[PostconditionResultV2]) -> bool {
    values
        .iter()
        .all(|result| !result.required || result.verdict == VerificationVerdictV2::Passed)
}

fn validate_observed_results(
    expected: &[VerifiablePostconditionV2],
    actual: &[PostconditionResultV2],
    observation: &ObservationSnapshot,
    label: &str,
) -> Result<(), DesktopError> {
    let expected_by_id = expected
        .iter()
        .map(|criterion| (criterion.criterion_id.as_str(), criterion))
        .collect::<BTreeMap<_, _>>();
    for result in actual {
        let Some(criterion) = expected_by_id.get(result.criterion_id.as_str()) else {
            return Err(DesktopError::Integrity(format!(
                "{label} result references an undeclared criterion"
            )));
        };
        let (verdict, observed_value) = evaluate_criterion(criterion, observation);
        if result.verdict != verdict || result.observed_value != observed_value {
            return Err(DesktopError::Integrity(format!(
                "{label} result does not match the fresh observation"
            )));
        }
    }
    Ok(())
}

fn evaluate_criterion(
    criterion: &VerifiablePostconditionV2,
    observation: &ObservationSnapshot,
) -> (VerificationVerdictV2, Option<Value>) {
    let matching = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == criterion.target.element_id)
        .collect::<Vec<_>>();
    if matching.len() > 1 {
        return (VerificationVerdictV2::Inconclusive, None);
    }

    let observed = match criterion.target.field {
        VerifiableObservationFieldV2::ElementExists => Some(Value::Bool(!matching.is_empty())),
        VerifiableObservationFieldV2::ElementValue => {
            matching.first().map(|element| element.value.clone())
        }
        VerifiableObservationFieldV2::ElementKind => matching
            .first()
            .map(|element| Value::String(element.kind.clone())),
    };

    compare_observed(criterion.op, observed, &criterion.expected_value)
}

fn compare_observed(
    op: ComparisonOp,
    observed: Option<Value>,
    expected: &Value,
) -> (VerificationVerdictV2, Option<Value>) {
    let verdict = match op {
        ComparisonOp::Equals => match observed.as_ref() {
            Some(actual) => verdict_from_bool(actual == expected),
            None => VerificationVerdictV2::Inconclusive,
        },
        ComparisonOp::NotEquals => match observed.as_ref() {
            Some(actual) => verdict_from_bool(actual != expected),
            None => VerificationVerdictV2::Inconclusive,
        },
        ComparisonOp::Contains => match observed.as_ref() {
            None => VerificationVerdictV2::Inconclusive,
            Some(actual) => match (actual.as_str(), expected.as_str()) {
                (Some(actual), Some(needle)) => verdict_from_bool(actual.contains(needle)),
                _ => VerificationVerdictV2::Unsupported,
            },
        },
        ComparisonOp::Exists => match expected.as_bool() {
            Some(expected_exists) => {
                let exists = observed.as_ref().is_some_and(|value| !value.is_null());
                verdict_from_bool(exists == expected_exists)
            }
            None => VerificationVerdictV2::Unsupported,
        },
        ComparisonOp::GreaterOrEqual | ComparisonOp::LessOrEqual => {
            let actual_integer = observed.as_ref().and_then(json_integer);
            let expected_integer = json_integer(expected);
            match (actual_integer, expected_integer) {
                (Some(actual), Some(target)) => verdict_from_bool(match op {
                    ComparisonOp::GreaterOrEqual => actual >= target,
                    ComparisonOp::LessOrEqual => actual <= target,
                    _ => false,
                }),
                (None, _) if observed.is_none() => VerificationVerdictV2::Inconclusive,
                _ => VerificationVerdictV2::Unsupported,
            }
        }
    };
    (verdict, observed)
}

fn json_integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn verdict_from_bool(value: bool) -> VerificationVerdictV2 {
    if value {
        VerificationVerdictV2::Passed
    } else {
        VerificationVerdictV2::Failed
    }
}

fn expected_action_verdict(
    execution_status: ExecutionStatus,
    results: &[PostconditionResultV2],
    unexpected_changes: &[String],
) -> VerificationVerdictV2 {
    if execution_status == ExecutionStatus::Unsupported {
        return VerificationVerdictV2::Unsupported;
    }
    if execution_status != ExecutionStatus::Succeeded {
        return VerificationVerdictV2::Failed;
    }
    if !unexpected_changes.is_empty()
        || results
            .iter()
            .any(|result| result.required && result.verdict == VerificationVerdictV2::Unsafe)
    {
        return VerificationVerdictV2::Unsafe;
    }
    for verdict in [
        VerificationVerdictV2::Unsupported,
        VerificationVerdictV2::Inconclusive,
        VerificationVerdictV2::Failed,
    ] {
        if results
            .iter()
            .any(|result| result.required && result.verdict == verdict)
        {
            return verdict;
        }
    }
    VerificationVerdictV2::Passed
}

fn expected_goal_progress(
    action_verdict: VerificationVerdictV2,
    results: &[PostconditionResultV2],
) -> GoalProgress {
    if action_verdict != VerificationVerdictV2::Passed {
        return GoalProgress::Blocked;
    }
    if required_results_passed(results) {
        return GoalProgress::Complete;
    }
    if results.iter().any(|result| {
        result.required
            && matches!(
                result.verdict,
                VerificationVerdictV2::Inconclusive
                    | VerificationVerdictV2::Unsupported
                    | VerificationVerdictV2::Unsafe
            )
    }) {
        return GoalProgress::Blocked;
    }
    GoalProgress::InProgress
}
