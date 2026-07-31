//! Deterministic, side-effect-free Cognitive Action Selection Pipeline v1.
//!
//! The crate validates module-owned data but does not link module
//! implementations. Its terminal `PolicyReadyActionV1` is data for a future
//! policy boundary, never approval or execution authority.

use d2i_action_candidates::{ActionCapabilityBinding, CandidateActionInput, CandidateActionKind};
use d2i_application_semantics::{ApplicationPack, ApplicationSemanticTarget};
use d2i_cognitive_ir::{
    ActionProposal, CognitiveRiskClass, ConfirmationRequirement, GoalSpec, ObservationSnapshot,
    ObservationSourceKind, PlanGraph, PlanNodeKind, Postcondition, Reversibility, TrustLabel,
    WorldState,
};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Action Selection Pipeline schema version.
pub const ACTION_SELECTION_SCHEMA_VERSION: u32 = 1;
/// Embedded Core-owned JSON Schema.
pub const ACTION_SELECTION_PIPELINE_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/action-selection-pipeline-v1.schema.json");

const MAX_CANDIDATES: usize = 64;
const MAX_EVIDENCE_IDS: usize = 32;
const MAX_TEXT: usize = 4096;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 100_000;

/// Fail-closed pipeline error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionSelectionError {
    /// A value violates a bounded input contract.
    Invalid(String),
    /// A sealed identity, lifecycle value, or hash was substituted.
    Integrity(String),
    /// A well-formed candidate uses a capability unavailable in this context.
    Unsupported(String),
    /// No eligible candidate was returned by the ranker.
    NoEligibleCandidate,
    /// JSON parsing or canonical serialization failed.
    Json(String),
}

impl Display for ActionSelectionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => {
                write!(formatter, "invalid action selection input: {message}")
            }
            Self::Integrity(message) => {
                write!(formatter, "action selection integrity failure: {message}")
            }
            Self::Unsupported(message) => {
                write!(
                    formatter,
                    "unsupported action selection candidate: {message}"
                )
            }
            Self::NoEligibleCandidate => formatter.write_str("no eligible action candidate"),
            Self::Json(message) => write!(formatter, "action selection JSON failure: {message}"),
        }
    }
}

impl Error for ActionSelectionError {}

impl From<d2i_cognitive_ir::CognitiveIrError> for ActionSelectionError {
    fn from(error: d2i_cognitive_ir::CognitiveIrError) -> Self {
        Self::Integrity(error.to_string())
    }
}

impl From<d2i_application_semantics::ApplicationSemanticsError> for ActionSelectionError {
    fn from(error: d2i_application_semantics::ApplicationSemanticsError) -> Self {
        Self::Integrity(error.to_string())
    }
}

impl From<d2i_action_candidates::ActionCandidateError> for ActionSelectionError {
    fn from(error: d2i_action_candidates::ActionCandidateError) -> Self {
        Self::Integrity(error.to_string())
    }
}

/// Exact Element Grounder v1 terminal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingStatusV1 {
    UniqueMatch,
    Ambiguous,
    NotFound,
    Unsupported,
}

/// Strict mirror of one Element Grounder v1 candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGroundingCandidateV1 {
    pub element_id: String,
    pub kind: String,
    pub label: String,
    pub score: f64,
    pub matched_features: Vec<String>,
    pub evidence: Vec<String>,
    pub trust_labels: BTreeSet<TrustLabel>,
}

/// Strict mirror of the module-owned Element Grounder v1 output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGroundingResultV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub source_observation_hash: String,
    pub plan_generation_id: String,
    pub target_text: String,
    pub status: GroundingStatusV1,
    pub selected_element_id: Option<String>,
    pub candidates: Vec<ElementGroundingCandidateV1>,
    pub ambiguity_reason: Option<String>,
    pub user_confirmation_required: bool,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
}

/// Stable, non-executable binding from a unique grounding result to an observed element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedTargetBindingV1 {
    pub schema_version: u32,
    pub application_pack_sha256: String,
    pub observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub grounding_result_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub semantic_target_id: String,
    pub selected_element_id: String,
    pub selected_element_kind: String,
    pub source_kind: ObservationSourceKind,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

impl GroundedTargetBindingV1 {
    /// Computes the binding hash with `binding_sha256` omitted.
    pub fn compute_binding_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "binding_sha256")
    }

    /// Validates identifiers, bounded evidence, source kind, and the self-hash.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "grounded target binding")?;
        validate_hash(
            &self.application_pack_sha256,
            "grounded application_pack_sha256",
        )?;
        validate_id(&self.observation_id, "grounded observation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "grounded source_observation_hash",
        )?;
        validate_hash(
            &self.grounding_result_sha256,
            "grounded grounding_result_sha256",
        )?;
        validate_id(&self.goal_id, "grounded goal_id")?;
        validate_id(&self.plan_generation_id, "grounded plan_generation_id")?;
        validate_id(&self.semantic_target_id, "grounded semantic_target_id")?;
        validate_id(&self.selected_element_id, "grounded selected_element_id")?;
        validate_id(
            &self.selected_element_kind,
            "grounded selected_element_kind",
        )?;
        if !matches!(
            self.source_kind,
            ObservationSourceKind::Uia | ObservationSourceKind::WebDriver
        ) {
            return invalid("grounded source_kind must be uia or web_driver");
        }
        if self.trust_labels.is_empty() {
            return invalid("grounded trust_labels must not be empty");
        }
        validate_sorted_ids(
            &self.evidence_ids,
            "grounded evidence_ids",
            MAX_EVIDENCE_IDS,
        )?;
        validate_hash(&self.binding_sha256, "grounded binding_sha256")?;
        if self.compute_binding_sha256()? != self.binding_sha256 {
            return integrity("grounded binding_sha256 does not match canonical content");
        }
        Ok(())
    }
}

/// A unique grounding selection validated against the trusted pack and observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedGroundingSelectionV1 {
    pub schema_version: u32,
    pub grounding_result_sha256: String,
    pub grounded_target: GroundedTargetBindingV1,
}

impl ValidatedGroundingSelectionV1 {
    /// Revalidates the selection's internal duplicated hashes.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "validated grounding selection")?;
        validate_hash(
            &self.grounding_result_sha256,
            "selection grounding_result_sha256",
        )?;
        self.grounded_target.validate()?;
        if self.grounding_result_sha256 != self.grounded_target.grounding_result_sha256 {
            return integrity("selection grounding result hash differs from target binding");
        }
        Ok(())
    }
}

/// Parses Element Grounder output with duplicate-key and unknown-field rejection.
pub fn parse_element_grounding_result_strict(
    bytes: &[u8],
) -> Result<ElementGroundingResultV1, ActionSelectionError> {
    parse_json_strict(bytes)
}

/// Validates actual Element Grounder output.
///
/// Non-unique terminal statuses return `Ok(None)` and therefore cannot produce
/// action candidates.
pub fn validate_element_grounding_result(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    semantic_target_id: &str,
    expected_goal_id: &str,
    expected_plan_generation_id: &str,
    result: &ElementGroundingResultV1,
) -> Result<Option<ValidatedGroundingSelectionV1>, ActionSelectionError> {
    pack.validate()?;
    observation.validate()?;
    validate_id(semantic_target_id, "semantic_target_id")?;
    validate_id(expected_goal_id, "expected_goal_id")?;
    validate_id(expected_plan_generation_id, "expected_plan_generation_id")?;
    validate_grounding_result_shape(result)?;

    if result.goal_id != expected_goal_id
        || result.plan_generation_id != expected_plan_generation_id
        || result.source_observation_hash != observation.state_hash
    {
        return integrity("Grounder result lifecycle binding differs from trusted context");
    }

    let target = unique_semantic_target(pack, semantic_target_id)?;
    if result.target_text != target.canonical_label && !target.aliases.contains(&result.target_text)
    {
        return integrity("Grounder target_text is not declared by the semantic target");
    }
    let grounding_result_sha256 = canonical_sha256(result)?;

    if result.status != GroundingStatusV1::UniqueMatch {
        return Ok(None);
    }
    if result.user_confirmation_required {
        return integrity("confirmation-required grounding cannot produce an action candidate");
    }
    let selected_id = result.selected_element_id.as_deref().ok_or_else(|| {
        ActionSelectionError::Invalid("unique_match requires selection".to_owned())
    })?;
    let element = unique_observed_element(observation, selected_id)?;
    let candidate = unique_grounding_candidate(&result.candidates, selected_id)?;

    if candidate.kind != element.kind || candidate.trust_labels != element.trust_labels {
        return integrity("selected Grounder candidate differs from the observed element");
    }
    if !target.expected_kinds.contains(&element.kind) {
        return integrity("selected observed kind is not admitted by the semantic target");
    }
    reject_forbidden_selected_element(observation, element, candidate)?;

    let mut evidence_ids = vec![
        "grounding-result".to_owned(),
        "observation-state".to_owned(),
        "semantic-target".to_owned(),
    ];
    evidence_ids.sort();
    let mut grounded_target = GroundedTargetBindingV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        application_pack_sha256: pack.pack_sha256.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        grounding_result_sha256: grounding_result_sha256.clone(),
        goal_id: result.goal_id.clone(),
        plan_generation_id: result.plan_generation_id.clone(),
        semantic_target_id: semantic_target_id.to_owned(),
        selected_element_id: element.element_id.clone(),
        selected_element_kind: element.kind.clone(),
        source_kind: observation.source_kind,
        trust_labels: element.trust_labels.clone(),
        evidence_ids,
        binding_sha256: empty_hash(),
    };
    grounded_target.binding_sha256 = grounded_target.compute_binding_sha256()?;
    grounded_target.validate()?;
    Ok(Some(ValidatedGroundingSelectionV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        grounding_result_sha256,
        grounded_target,
    }))
}

/// Additive context for selecting among multiple capabilities at a
/// `SelectCapability` plan node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSelectionContextV1 {
    pub schema_version: u32,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub current_step: String,
    pub allowed_capability_ids: Vec<String>,
    pub context_sha256: String,
}

impl ActionSelectionContextV1 {
    /// Sorts capability IDs and seals the context.
    pub fn seal(mut self) -> Result<Self, ActionSelectionError> {
        self.allowed_capability_ids.sort();
        self.context_sha256 = self.compute_context_sha256()?;
        Ok(self)
    }

    /// Computes the context hash with `context_sha256` omitted.
    pub fn compute_context_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "context_sha256")
    }

    /// Validates exact goal/world/plan lifecycle and `SelectCapability` shape.
    pub fn validate_context(
        &self,
        goal: &GoalSpec,
        world: &WorldState,
        plan: &PlanGraph,
    ) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "action selection context")?;
        goal.validate()?;
        world.validate()?;
        plan.validate()?;
        validate_id(&self.goal_id, "selection context goal_id")?;
        validate_id(
            &self.plan_generation_id,
            "selection context plan_generation_id",
        )?;
        validate_id(&self.current_step, "selection context current_step")?;
        validate_sorted_ids(
            &self.allowed_capability_ids,
            "allowed_capability_ids",
            MAX_CANDIDATES,
        )?;
        validate_hash(&self.context_sha256, "selection context_sha256")?;
        if self.compute_context_sha256()? != self.context_sha256 {
            return integrity("selection context hash differs from canonical content");
        }
        if self.goal_id != goal.goal_id
            || self.goal_id != world.goal_id
            || self.plan_generation_id != plan.plan_generation_id
            || self.plan_generation_id != world.plan_generation_id
            || self.current_step != world.current_step
        {
            return integrity("selection context lifecycle differs from goal/world/plan");
        }
        let node = unique_plan_node(plan, &self.current_step)?;
        if node.kind != PlanNodeKind::SelectCapability || node.capability_id.is_some() {
            return integrity(
                "selection context current step must be an unbound SelectCapability node",
            );
        }
        Ok(())
    }
}

/// Plan Ranker hard-gate status mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatusV1 {
    Passed,
    Failed,
    Unknown,
}

/// Plan Ranker hard-gate name mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateNameV1 {
    Policy,
    Activation,
    Binding,
    InputSchema,
    OutputSchema,
    Risk,
    SideEffect,
    Network,
    Credential,
    Capability,
    Quality,
}

/// Exact Plan Ranker v1 gate set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGateResultsV1 {
    pub policy: GateStatusV1,
    pub activation: GateStatusV1,
    pub binding: GateStatusV1,
    pub input_schema: GateStatusV1,
    pub output_schema: GateStatusV1,
    pub risk: GateStatusV1,
    pub side_effect: GateStatusV1,
    pub network: GateStatusV1,
    pub credential: GateStatusV1,
    pub capability: GateStatusV1,
    pub quality: GateStatusV1,
}

impl CandidateGateResultsV1 {
    fn ordered(&self) -> [(GateNameV1, GateStatusV1); 11] {
        [
            (GateNameV1::Policy, self.policy),
            (GateNameV1::Activation, self.activation),
            (GateNameV1::Binding, self.binding),
            (GateNameV1::InputSchema, self.input_schema),
            (GateNameV1::OutputSchema, self.output_schema),
            (GateNameV1::Risk, self.risk),
            (GateNameV1::SideEffect, self.side_effect),
            (GateNameV1::Network, self.network),
            (GateNameV1::Credential, self.credential),
            (GateNameV1::Capability, self.capability),
            (GateNameV1::Quality, self.quality),
        ]
    }
}

/// Evidence IDs for every supplied admission gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGateEvidenceV1 {
    pub policy: Vec<String>,
    pub activation: Vec<String>,
    pub binding: Vec<String>,
    pub input_schema: Vec<String>,
    pub output_schema: Vec<String>,
    pub risk: Vec<String>,
    pub side_effect: Vec<String>,
    pub network: Vec<String>,
    pub credential: Vec<String>,
    pub capability: Vec<String>,
    pub quality: Vec<String>,
}

impl CandidateGateEvidenceV1 {
    fn collections(&self) -> [(&str, &[String]); 11] {
        [
            ("policy", &self.policy),
            ("activation", &self.activation),
            ("binding", &self.binding),
            ("input_schema", &self.input_schema),
            ("output_schema", &self.output_schema),
            ("risk", &self.risk),
            ("side_effect", &self.side_effect),
            ("network", &self.network),
            ("credential", &self.credential),
            ("capability", &self.capability),
            ("quality", &self.quality),
        ]
    }

    fn sort(&mut self) {
        self.policy.sort();
        self.activation.sort();
        self.binding.sort();
        self.input_schema.sort();
        self.output_schema.sort();
        self.risk.sort();
        self.side_effect.sort();
        self.network.sort();
        self.credential.sort();
        self.capability.sort();
        self.quality.sort();
    }

    fn validate(&self) -> Result<(), ActionSelectionError> {
        for (name, values) in self.collections() {
            validate_sorted_ids(
                values,
                &format!("admission gate evidence {name}"),
                MAX_EVIDENCE_IDS,
            )?;
        }
        Ok(())
    }

    fn flattened(&self) -> Vec<String> {
        let mut values = self
            .collections()
            .into_iter()
            .flat_map(|(_, values)| values.iter().cloned())
            .collect::<Vec<_>>();
        values.sort();
        values.dedup();
        values
    }
}

/// Sealed ranking metadata absent from frozen Cognitive IR v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRankingProfileV1 {
    pub schema_version: u32,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub capability_id: String,
    pub capability_binding_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_hash: String,
    pub capability_version: String,
    pub input_schema_id: String,
    pub input_schema_version: u32,
    pub output_schema_id: String,
    pub output_schema_version: u32,
    pub normalized_cost_millionths: u32,
    pub success_likelihood_millionths: u32,
    pub ranking_profile_sha256: String,
}

impl CandidateRankingProfileV1 {
    /// Computes the profile hash with its self-hash omitted.
    pub fn compute_profile_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "ranking_profile_sha256")
    }

    /// Seals the profile without changing ranking metadata.
    pub fn seal(mut self) -> Result<Self, ActionSelectionError> {
        self.ranking_profile_sha256 = self.compute_profile_sha256()?;
        Ok(self)
    }

    /// Validates all bounded fields and the self-hash.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "candidate ranking profile")?;
        validate_id(&self.proposal_id, "ranking proposal_id")?;
        validate_hash(&self.proposal_sha256, "ranking proposal_sha256")?;
        validate_id(&self.capability_id, "ranking capability_id")?;
        validate_hash(
            &self.capability_binding_sha256,
            "ranking capability_binding_sha256",
        )?;
        validate_id(&self.goal_id, "ranking goal_id")?;
        validate_id(&self.plan_generation_id, "ranking plan_generation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "ranking source_observation_hash",
        )?;
        validate_semver(&self.capability_version)?;
        validate_ranker_id(&self.input_schema_id, "ranking input_schema_id")?;
        validate_ranker_id(&self.output_schema_id, "ranking output_schema_id")?;
        if self.input_schema_version == 0 || self.output_schema_version == 0 {
            return invalid("ranking schema versions must be greater than zero");
        }
        if self.normalized_cost_millionths > 1_000_000
            || self.success_likelihood_millionths > 1_000_000
        {
            return invalid("ranking millionths must be within 0..=1000000");
        }
        validate_hash(&self.ranking_profile_sha256, "ranking_profile_sha256")?;
        if self.compute_profile_sha256()? != self.ranking_profile_sha256 {
            return integrity("ranking profile hash differs from canonical content");
        }
        Ok(())
    }
}

/// Trusted pre-admission metadata. This is not a policy decision, activation
/// permit, approval, or execution authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateAdmissionProfileV1 {
    pub schema_version: u32,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub capability_id: String,
    pub capability_binding_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_hash: String,
    pub trusted_source_id: String,
    pub trusted_source_sha256: String,
    pub gate_results: CandidateGateResultsV1,
    pub gate_evidence: CandidateGateEvidenceV1,
    pub admission_profile_sha256: String,
}

impl CandidateAdmissionProfileV1 {
    /// Computes the profile hash with its self-hash omitted.
    pub fn compute_profile_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "admission_profile_sha256")
    }

    /// Sorts evidence IDs and seals the profile without upgrading any gate.
    pub fn seal(mut self) -> Result<Self, ActionSelectionError> {
        self.gate_evidence.sort();
        self.admission_profile_sha256 = self.compute_profile_sha256()?;
        Ok(self)
    }

    /// Validates source evidence, bindings, gate evidence, and self-hash.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "candidate admission profile")?;
        validate_id(&self.proposal_id, "admission proposal_id")?;
        validate_hash(&self.proposal_sha256, "admission proposal_sha256")?;
        validate_id(&self.capability_id, "admission capability_id")?;
        validate_hash(
            &self.capability_binding_sha256,
            "admission capability_binding_sha256",
        )?;
        validate_id(&self.goal_id, "admission goal_id")?;
        validate_id(&self.plan_generation_id, "admission plan_generation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "admission source_observation_hash",
        )?;
        validate_id(&self.trusted_source_id, "admission trusted_source_id")?;
        validate_hash(
            &self.trusted_source_sha256,
            "admission trusted_source_sha256",
        )?;
        self.gate_evidence.validate()?;
        validate_hash(&self.admission_profile_sha256, "admission_profile_sha256")?;
        if self.compute_profile_sha256()? != self.admission_profile_sha256 {
            return integrity("admission profile hash differs from canonical content");
        }
        Ok(())
    }
}

/// Proposal fields used before ranking/admission profiles are bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedActionProposalSpecV1 {
    pub candidate_id: String,
    pub capability_binding_sha256: String,
    pub input: CandidateActionInput,
    pub preconditions: Vec<Postcondition>,
    pub expected_postconditions: Vec<Postcondition>,
    pub confidence: f64,
}

/// Complete specification for one candidate build.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateGenerationSpecV1 {
    pub proposal: GroundedActionProposalSpecV1,
    pub ranking_profile: CandidateRankingProfileV1,
    pub admission_profile: CandidateAdmissionProfileV1,
}

/// Strict arguments for a non-fixture grounded proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedActionArgumentsV1 {
    pub schema_version: u32,
    pub operation: String,
    pub target: GroundedTargetBindingV1,
    pub input: CandidateActionInput,
}

/// One sealed candidate record retaining the exact original proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCandidateRecordV1 {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub capability_binding_sha256: String,
    pub ranking_profile_sha256: String,
    pub admission_profile_sha256: String,
    pub capability_binding: ActionCapabilityBinding,
    pub ranking_profile: CandidateRankingProfileV1,
    pub admission_profile: CandidateAdmissionProfileV1,
    pub proposal: ActionProposal,
    pub evidence_ids: Vec<String>,
}

impl ActionCandidateRecordV1 {
    /// Computes `candidate_hash` with that field omitted.
    pub fn compute_candidate_hash(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "candidate_hash")
    }

    /// Validates exact duplicated profile, binding, and proposal identities.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_ranker_id(&self.candidate_id, "candidate_id")?;
        validate_hash(&self.candidate_hash, "candidate_hash")?;
        validate_id(&self.proposal_id, "candidate proposal_id")?;
        validate_hash(&self.proposal_sha256, "candidate proposal_sha256")?;
        validate_hash(
            &self.capability_binding_sha256,
            "candidate capability_binding_sha256",
        )?;
        validate_hash(
            &self.ranking_profile_sha256,
            "candidate ranking_profile_sha256",
        )?;
        validate_hash(
            &self.admission_profile_sha256,
            "candidate admission_profile_sha256",
        )?;
        validate_sorted_ids(
            &self.evidence_ids,
            "candidate evidence_ids",
            MAX_EVIDENCE_IDS,
        )?;
        self.capability_binding.validate()?;
        self.ranking_profile.validate()?;
        self.admission_profile.validate()?;
        self.proposal.validate()?;
        if !self.proposal.confidence.is_finite() {
            return invalid("candidate proposal confidence must be finite");
        }
        if self.proposal_id != self.proposal.proposal_id
            || self.proposal_sha256 != canonical_sha256(&self.proposal)?
            || self.capability_binding_sha256 != self.capability_binding.binding_sha256
            || self.ranking_profile_sha256 != self.ranking_profile.ranking_profile_sha256
            || self.admission_profile_sha256 != self.admission_profile.admission_profile_sha256
        {
            return integrity("candidate duplicated identity fields differ from sealed records");
        }
        validate_profile_bindings(
            &self.proposal,
            &self.capability_binding,
            &self.ranking_profile,
            &self.admission_profile,
        )?;
        if self.compute_candidate_hash()? != self.candidate_hash {
            return integrity("candidate_hash does not match canonical candidate");
        }
        Ok(())
    }
}

/// Structured exclusion for a well-formed but unavailable capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedCandidateBuildV1 {
    pub candidate_id: String,
    pub capability_binding_sha256: String,
    pub reason_code: CandidateBuildRejectionCodeV1,
    pub evidence_ids: Vec<String>,
}

/// Bounded reasons that may exclude a candidate without hiding malformed data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateBuildRejectionCodeV1 {
    CapabilityNotAllowed,
    CapabilityUnavailable,
}

/// Deterministic set of one or more generated candidates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCandidateSetV1 {
    pub schema_version: u32,
    pub candidate_set_id: String,
    pub goal_id: String,
    pub world_state_id: String,
    pub plan_generation_id: String,
    pub observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub application_pack_sha256: String,
    pub grounding_result_sha256: String,
    pub semantic_target_id: String,
    pub grounded_target_binding_sha256: String,
    pub candidates: Vec<ActionCandidateRecordV1>,
    pub rejected_builds: Vec<RejectedCandidateBuildV1>,
    pub set_sha256: String,
}

impl ActionCandidateSetV1 {
    /// Computes `set_sha256` with that field omitted.
    pub fn compute_set_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "set_sha256")
    }

    /// Validates canonical candidate order, uniqueness, bounds, and self-hash.
    pub fn validate(&self) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "action candidate set")?;
        validate_ranker_id(&self.candidate_set_id, "candidate_set_id")?;
        validate_id(&self.goal_id, "candidate set goal_id")?;
        validate_id(&self.world_state_id, "candidate set world_state_id")?;
        validate_id(&self.plan_generation_id, "candidate set plan_generation_id")?;
        validate_id(&self.observation_id, "candidate set observation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "candidate set source_observation_hash",
        )?;
        validate_hash(
            &self.application_pack_sha256,
            "candidate set application_pack_sha256",
        )?;
        validate_hash(
            &self.grounding_result_sha256,
            "candidate set grounding_result_sha256",
        )?;
        validate_id(&self.semantic_target_id, "candidate set semantic_target_id")?;
        validate_hash(
            &self.grounded_target_binding_sha256,
            "candidate set grounded_target_binding_sha256",
        )?;
        if self.candidates.is_empty() || self.candidates.len() > MAX_CANDIDATES {
            return invalid("candidate set must contain 1..=64 candidates");
        }
        if self.rejected_builds.len() > MAX_CANDIDATES {
            return invalid("candidate set rejected_builds exceeds 64");
        }
        let mut previous: Option<(&str, &str)> = None;
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            let key = (
                candidate.candidate_hash.as_str(),
                candidate.candidate_id.as_str(),
            );
            if previous.is_some_and(|prior| prior >= key) {
                return invalid("candidate records must be strictly ordered by hash then ID");
            }
            previous = Some(key);
            if !ids.insert(candidate.candidate_id.as_str())
                || !hashes.insert(candidate.candidate_hash.as_str())
            {
                return invalid("candidate IDs and hashes must be unique");
            }
        }
        validate_hash(&self.set_sha256, "candidate set_sha256")?;
        if self.compute_set_sha256()? != self.set_sha256 {
            return integrity("candidate set hash differs from canonical content");
        }
        Ok(())
    }
}

/// Candidate generation returns either a nonempty set or a structured
/// capability-only exclusion result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionCandidateBuildOutcomeV1 {
    Candidates {
        candidate_set: Box<ActionCandidateSetV1>,
    },
    NoCandidates {
        rejected_builds: Vec<RejectedCandidateBuildV1>,
    },
}

/// Builds the deterministic proposal before sealed profiles are supplied.
#[allow(clippy::too_many_arguments)]
pub fn build_grounded_action_proposal(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    selection: &ValidatedGroundingSelectionV1,
    context: &ActionSelectionContextV1,
    capability_binding: &ActionCapabilityBinding,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    spec: &GroundedActionProposalSpecV1,
) -> Result<ActionProposal, ActionSelectionError> {
    validate_candidate_context(
        pack,
        observation,
        selection,
        context,
        capability_binding,
        goal,
        world,
        plan,
        spec,
    )?;
    let target = selection.grounded_target.clone();
    let arguments = GroundedActionArgumentsV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        operation: capability_binding.capability.operation.clone(),
        target,
        input: spec.input.clone(),
    };
    reject_forbidden_json(
        &serde_json::to_value(&arguments)
            .map_err(|error| json_error("serialize grounded arguments", error))?,
        "grounded arguments",
    )?;
    let proposal_material = serde_json::json!({
        "schema_version": 1,
        "candidate_id": spec.candidate_id,
        "goal_id": goal.goal_id,
        "plan_generation_id": plan.plan_generation_id,
        "source_observation_hash": observation.state_hash,
        "capability_binding_sha256": capability_binding.binding_sha256,
        "arguments": arguments,
        "preconditions": spec.preconditions,
        "expected_postconditions": spec.expected_postconditions,
        "confidence": spec.confidence,
    });
    let digest = canonical_sha256(&proposal_material)?;
    let suffix = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| ActionSelectionError::Json("proposal digest prefix missing".to_owned()))?;
    let evidence = vec![
        format!("application-pack:{}", pack.pack_sha256),
        format!("capability-binding:{}", capability_binding.binding_sha256),
        format!(
            "grounded-target:{}",
            selection.grounded_target.binding_sha256
        ),
        format!("grounding-result:{}", selection.grounding_result_sha256),
        format!("observation:{}", observation.state_hash),
        format!("selection-context:{}", context.context_sha256),
    ];
    let proposal = ActionProposal {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        proposal_id: format!("asp1-{suffix}"),
        goal_id: goal.goal_id.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        capability_id: capability_binding.capability.capability_id.clone(),
        semantic_target: selection.grounded_target.semantic_target_id.clone(),
        arguments: serde_json::to_value(arguments)
            .map_err(|error| json_error("serialize proposal arguments", error))?,
        preconditions: spec.preconditions.clone(),
        expected_postconditions: spec.expected_postconditions.clone(),
        risk: capability_binding.capability.risk_class,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: capability_binding.capability.confirmation_requirement,
        confidence: spec.confidence,
        evidence,
        valid_until_sequence: observation.sequence,
    };
    proposal.validate()?;
    if !proposal.confidence.is_finite() {
        return invalid("proposal confidence must be finite");
    }
    Ok(proposal)
}

/// Builds one exact candidate from a unique grounding selection.
#[allow(clippy::too_many_arguments)]
pub fn build_grounded_action_candidate(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    selection: &ValidatedGroundingSelectionV1,
    context: &ActionSelectionContextV1,
    capability_binding: &ActionCapabilityBinding,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    spec: &CandidateGenerationSpecV1,
) -> Result<ActionCandidateRecordV1, ActionSelectionError> {
    let proposal = build_grounded_action_proposal(
        pack,
        observation,
        selection,
        context,
        capability_binding,
        goal,
        world,
        plan,
        &spec.proposal,
    )?;
    let proposal_sha256 = canonical_sha256(&proposal)?;
    spec.ranking_profile.validate()?;
    spec.admission_profile.validate()?;
    validate_profile_bindings(
        &proposal,
        capability_binding,
        &spec.ranking_profile,
        &spec.admission_profile,
    )?;
    let mut evidence_ids = spec.admission_profile.gate_evidence.flattened();
    if evidence_ids.len() > MAX_EVIDENCE_IDS {
        return invalid("candidate aggregate evidence exceeds 32 unique IDs");
    }
    evidence_ids.sort();
    let mut record = ActionCandidateRecordV1 {
        candidate_id: spec.proposal.candidate_id.clone(),
        candidate_hash: empty_hash(),
        proposal_id: proposal.proposal_id.clone(),
        proposal_sha256,
        capability_binding_sha256: capability_binding.binding_sha256.clone(),
        ranking_profile_sha256: spec.ranking_profile.ranking_profile_sha256.clone(),
        admission_profile_sha256: spec.admission_profile.admission_profile_sha256.clone(),
        capability_binding: capability_binding.clone(),
        ranking_profile: spec.ranking_profile.clone(),
        admission_profile: spec.admission_profile.clone(),
        proposal,
        evidence_ids,
    };
    record.candidate_hash = record.compute_candidate_hash()?;
    record.validate()?;
    Ok(record)
}

/// Builds a canonical multi-candidate set. Only explicit capability
/// availability failures become structured exclusions.
#[allow(clippy::too_many_arguments)]
pub fn build_grounded_action_candidates(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    selection: &ValidatedGroundingSelectionV1,
    context: &ActionSelectionContextV1,
    capability_bindings: &[ActionCapabilityBinding],
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    specs: &[CandidateGenerationSpecV1],
) -> Result<ActionCandidateBuildOutcomeV1, ActionSelectionError> {
    if specs.is_empty() || specs.len() > MAX_CANDIDATES {
        return invalid("candidate generation specs must contain 1..=64 entries");
    }
    if capability_bindings.is_empty() || capability_bindings.len() > MAX_CANDIDATES {
        return invalid("capability bindings must contain 1..=64 entries");
    }
    validate_lifecycle(pack, observation, selection, context, goal, world, plan)?;
    let mut binding_hashes = BTreeSet::new();
    for binding in capability_bindings {
        binding.validate()?;
        if !binding_hashes.insert(binding.binding_sha256.as_str()) {
            return invalid("capability binding hashes must be unique");
        }
    }
    let mut candidates = Vec::new();
    let mut rejected_builds = Vec::new();
    for spec in specs {
        validate_ranker_id(&spec.proposal.candidate_id, "candidate_id")?;
        let binding = unique_capability_binding(
            capability_bindings,
            &spec.proposal.capability_binding_sha256,
        )?;
        if !context
            .allowed_capability_ids
            .contains(&binding.capability.capability_id)
        {
            rejected_builds.push(rejected_build(
                spec,
                CandidateBuildRejectionCodeV1::CapabilityNotAllowed,
            )?);
            continue;
        }
        if !world
            .capabilities
            .contains(&binding.capability.capability_id)
        {
            rejected_builds.push(rejected_build(
                spec,
                CandidateBuildRejectionCodeV1::CapabilityUnavailable,
            )?);
            continue;
        }
        candidates.push(build_grounded_action_candidate(
            pack,
            observation,
            selection,
            context,
            binding,
            goal,
            world,
            plan,
            spec,
        )?);
    }
    candidates.sort_by(|left, right| {
        left.candidate_hash
            .cmp(&right.candidate_hash)
            .then_with(|| left.candidate_id.cmp(&right.candidate_id))
    });
    rejected_builds.sort_by(|left, right| {
        left.candidate_id.cmp(&right.candidate_id).then_with(|| {
            left.capability_binding_sha256
                .cmp(&right.capability_binding_sha256)
        })
    });
    validate_candidate_uniqueness(&candidates)?;
    if candidates.is_empty() {
        return Ok(ActionCandidateBuildOutcomeV1::NoCandidates { rejected_builds });
    }
    let identity_material = serde_json::json!({
        "schema_version": 1,
        "goal_id": goal.goal_id,
        "world_state_id": world.world_state_id,
        "plan_generation_id": plan.plan_generation_id,
        "observation_id": observation.observation_id,
        "source_observation_hash": observation.state_hash,
        "source_observation_sequence": observation.sequence,
        "application_pack_sha256": pack.pack_sha256,
        "grounding_result_sha256": selection.grounding_result_sha256,
        "semantic_target_id": selection.grounded_target.semantic_target_id,
        "grounded_target_binding_sha256": selection.grounded_target.binding_sha256,
        "candidate_hashes": candidates.iter().map(|candidate| &candidate.candidate_hash).collect::<Vec<_>>(),
    });
    let digest = canonical_sha256(&identity_material)?;
    let suffix = digest.strip_prefix("sha256:").ok_or_else(|| {
        ActionSelectionError::Json("candidate set digest prefix missing".to_owned())
    })?;
    let mut candidate_set = ActionCandidateSetV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        candidate_set_id: format!("candidate-set-{suffix}"),
        goal_id: goal.goal_id.clone(),
        world_state_id: world.world_state_id.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        application_pack_sha256: pack.pack_sha256.clone(),
        grounding_result_sha256: selection.grounding_result_sha256.clone(),
        semantic_target_id: selection.grounded_target.semantic_target_id.clone(),
        grounded_target_binding_sha256: selection.grounded_target.binding_sha256.clone(),
        candidates,
        rejected_builds,
        set_sha256: empty_hash(),
    };
    candidate_set.set_sha256 = candidate_set.compute_set_sha256()?;
    candidate_set.validate()?;
    Ok(ActionCandidateBuildOutcomeV1::Candidates {
        candidate_set: Box::new(candidate_set),
    })
}

/// Exact Plan Ranker v1 input candidate mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerCandidateV1 {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub capability_id: String,
    pub capability_version: String,
    pub input_schema_id: String,
    pub input_schema_version: u32,
    pub output_schema_id: String,
    pub output_schema_version: u32,
    pub normalized_cost_millionths: u32,
    pub success_likelihood_millionths: u32,
    pub gate_results: CandidateGateResultsV1,
    pub evidence_ids: Vec<String>,
}

/// Exact Plan Ranker v1 input payload mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerInputPayloadV1 {
    pub schema_version: u32,
    pub candidates: Vec<PlanRankerCandidateV1>,
}

/// Out-of-payload index back to the original proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerCandidateIndexV1 {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub capability_binding_sha256: String,
    pub ranking_profile_sha256: String,
    pub admission_profile_sha256: String,
}

/// Schema-pinned Plan Ranker input and exact proposal index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerInputBridgeV1 {
    pub schema_version: u32,
    pub candidate_set_sha256: String,
    pub payload: PlanRankerInputPayloadV1,
    pub payload_sha256: String,
    pub candidate_index: Vec<PlanRankerCandidateIndexV1>,
    pub bridge_sha256: String,
}

impl PlanRankerInputBridgeV1 {
    /// Computes the bridge hash with its self-hash omitted.
    pub fn compute_bridge_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "bridge_sha256")
    }

    /// Validates payload/index coverage and canonical hashes.
    pub fn validate(
        &self,
        candidate_set: &ActionCandidateSetV1,
    ) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "Plan Ranker input bridge")?;
        candidate_set.validate()?;
        if self.candidate_set_sha256 != candidate_set.set_sha256 {
            return integrity("Plan Ranker bridge candidate set hash differs");
        }
        if self.payload.schema_version != ACTION_SELECTION_SCHEMA_VERSION
            || self.payload.candidates.len() != candidate_set.candidates.len()
            || self.candidate_index.len() != candidate_set.candidates.len()
        {
            return integrity("Plan Ranker payload/index coverage differs from candidate set");
        }
        for ((payload, index), source) in self
            .payload
            .candidates
            .iter()
            .zip(&self.candidate_index)
            .zip(&candidate_set.candidates)
        {
            if payload.candidate_id != source.candidate_id
                || payload.candidate_hash != source.candidate_hash
                || payload.capability_id != source.proposal.capability_id
                || payload.capability_version != source.ranking_profile.capability_version
                || payload.input_schema_id != source.ranking_profile.input_schema_id
                || payload.input_schema_version != source.ranking_profile.input_schema_version
                || payload.output_schema_id != source.ranking_profile.output_schema_id
                || payload.output_schema_version != source.ranking_profile.output_schema_version
                || payload.normalized_cost_millionths
                    != source.ranking_profile.normalized_cost_millionths
                || payload.success_likelihood_millionths
                    != source.ranking_profile.success_likelihood_millionths
                || payload.gate_results != source.admission_profile.gate_results
                || payload.evidence_ids != source.evidence_ids
            {
                return integrity("Plan Ranker payload candidate differs from sealed source");
            }
            if index.candidate_id != source.candidate_id
                || index.candidate_hash != source.candidate_hash
                || index.proposal_id != source.proposal_id
                || index.proposal_sha256 != source.proposal_sha256
                || index.capability_binding_sha256 != source.capability_binding_sha256
                || index.ranking_profile_sha256 != source.ranking_profile_sha256
                || index.admission_profile_sha256 != source.admission_profile_sha256
            {
                return integrity("Plan Ranker candidate index differs from sealed source");
            }
        }
        validate_hash(&self.payload_sha256, "Plan Ranker payload_sha256")?;
        if canonical_sha256(&self.payload)? != self.payload_sha256 {
            return integrity("Plan Ranker payload hash differs from canonical payload");
        }
        validate_hash(&self.bridge_sha256, "Plan Ranker bridge_sha256")?;
        if self.compute_bridge_sha256()? != self.bridge_sha256 {
            return integrity("Plan Ranker bridge hash differs from canonical bridge");
        }
        Ok(())
    }
}

/// Builds a metadata-only Plan Ranker input bridge.
pub fn build_plan_ranker_input_bridge(
    candidate_set: &ActionCandidateSetV1,
) -> Result<PlanRankerInputBridgeV1, ActionSelectionError> {
    candidate_set.validate()?;
    let payload = PlanRankerInputPayloadV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        candidates: candidate_set
            .candidates
            .iter()
            .map(|candidate| PlanRankerCandidateV1 {
                candidate_id: candidate.candidate_id.clone(),
                candidate_hash: candidate.candidate_hash.clone(),
                capability_id: candidate.proposal.capability_id.clone(),
                capability_version: candidate.ranking_profile.capability_version.clone(),
                input_schema_id: candidate.ranking_profile.input_schema_id.clone(),
                input_schema_version: candidate.ranking_profile.input_schema_version,
                output_schema_id: candidate.ranking_profile.output_schema_id.clone(),
                output_schema_version: candidate.ranking_profile.output_schema_version,
                normalized_cost_millionths: candidate.ranking_profile.normalized_cost_millionths,
                success_likelihood_millionths: candidate
                    .ranking_profile
                    .success_likelihood_millionths,
                gate_results: candidate.admission_profile.gate_results.clone(),
                evidence_ids: candidate.evidence_ids.clone(),
            })
            .collect(),
    };
    let payload_sha256 = canonical_sha256(&payload)?;
    let candidate_index = candidate_set
        .candidates
        .iter()
        .map(|candidate| PlanRankerCandidateIndexV1 {
            candidate_id: candidate.candidate_id.clone(),
            candidate_hash: candidate.candidate_hash.clone(),
            proposal_id: candidate.proposal_id.clone(),
            proposal_sha256: candidate.proposal_sha256.clone(),
            capability_binding_sha256: candidate.capability_binding_sha256.clone(),
            ranking_profile_sha256: candidate.ranking_profile_sha256.clone(),
            admission_profile_sha256: candidate.admission_profile_sha256.clone(),
        })
        .collect();
    let mut bridge = PlanRankerInputBridgeV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        candidate_set_sha256: candidate_set.set_sha256.clone(),
        payload,
        payload_sha256,
        candidate_index,
        bridge_sha256: empty_hash(),
    };
    bridge.bridge_sha256 = bridge.compute_bridge_sha256()?;
    bridge.validate(candidate_set)?;
    Ok(bridge)
}

/// One Plan Ranker v1 gate rejection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankingGateRejectionV1 {
    pub gate: GateNameV1,
    pub status: GateStatusV1,
}

/// One Plan Ranker v1 ranked candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankingCandidateV1 {
    pub rank: u32,
    pub candidate_id: String,
    pub candidate_hash: String,
    pub normalized_cost_millionths: u32,
    pub success_likelihood_millionths: u32,
}

/// One Plan Ranker v1 rejected candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankingRejectedCandidateV1 {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub reasons: Vec<PlanRankingGateRejectionV1>,
}

/// Exact Plan Ranker v1 terminal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanRankingOutcomeV1 {
    Ranked,
    NoEligibleCandidate,
}

/// Strict mirror of Plan Ranker v1 output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankingOutputV1 {
    pub schema_version: u32,
    pub ranking_policy_version: u32,
    pub outcome: PlanRankingOutcomeV1,
    pub selected_candidate_id: Option<String>,
    pub selected_candidate_hash: Option<String>,
    pub ranked_candidates: Vec<PlanRankingCandidateV1>,
    pub rejected_candidates: Vec<PlanRankingRejectedCandidateV1>,
}

/// Validated Plan Ranker output bound to its exact input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedPlanRankingV1 {
    pub schema_version: u32,
    pub candidate_set_sha256: String,
    pub plan_ranker_input_sha256: String,
    pub plan_ranker_output_sha256: String,
    pub output: PlanRankingOutputV1,
    pub validation_sha256: String,
}

impl ValidatedPlanRankingV1 {
    /// Computes the validation artifact hash with its self-hash omitted.
    pub fn compute_validation_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "validation_sha256")
    }

    /// Revalidates the sealed validation artifact against the original input.
    pub fn validate(
        &self,
        candidate_set: &ActionCandidateSetV1,
        bridge: &PlanRankerInputBridgeV1,
    ) -> Result<(), ActionSelectionError> {
        validate_version(self.schema_version, "validated Plan Ranker result")?;
        bridge.validate(candidate_set)?;
        if self.candidate_set_sha256 != candidate_set.set_sha256
            || self.plan_ranker_input_sha256 != bridge.payload_sha256
            || self.plan_ranker_output_sha256 != canonical_sha256(&self.output)?
        {
            return integrity("validated ranking bindings differ from source artifacts");
        }
        validate_plan_ranking_shape(candidate_set, &self.output)?;
        validate_hash(&self.validation_sha256, "ranking validation_sha256")?;
        if self.compute_validation_sha256()? != self.validation_sha256 {
            return integrity("ranking validation hash differs from canonical content");
        }
        Ok(())
    }
}

/// Parses Plan Ranker output with duplicate-key and unknown-field rejection.
pub fn parse_plan_ranking_output_strict(
    bytes: &[u8],
) -> Result<PlanRankingOutputV1, ActionSelectionError> {
    parse_json_strict(bytes)
}

/// Validates a Plan Ranker result without invoking the standalone module.
pub fn validate_plan_ranking_output(
    candidate_set: &ActionCandidateSetV1,
    bridge: &PlanRankerInputBridgeV1,
    output: &PlanRankingOutputV1,
) -> Result<ValidatedPlanRankingV1, ActionSelectionError> {
    bridge.validate(candidate_set)?;
    validate_plan_ranking_shape(candidate_set, output)?;
    let mut validated = ValidatedPlanRankingV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        candidate_set_sha256: candidate_set.set_sha256.clone(),
        plan_ranker_input_sha256: bridge.payload_sha256.clone(),
        plan_ranker_output_sha256: canonical_sha256(output)?,
        output: output.clone(),
        validation_sha256: empty_hash(),
    };
    validated.validation_sha256 = validated.compute_validation_sha256()?;
    validated.validate(candidate_set, bridge)?;
    Ok(validated)
}

/// Selected proposal rebound to every trusted lifecycle and profile identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundSelectedActionV1 {
    pub schema_version: u32,
    pub selection_id: String,
    pub candidate_set_sha256: String,
    pub plan_ranker_input_sha256: String,
    pub plan_ranker_output_sha256: String,
    pub selected_candidate_id: String,
    pub selected_candidate_hash: String,
    pub selected_proposal_id: String,
    pub selected_proposal_sha256: String,
    pub goal_id: String,
    pub world_state_id: String,
    pub plan_generation_id: String,
    pub observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub application_pack_sha256: String,
    pub grounding_result_sha256: String,
    pub semantic_target_id: String,
    pub selected_element_id: String,
    pub selected_element_kind: String,
    pub capability_binding_sha256: String,
    pub ranking_profile_sha256: String,
    pub admission_profile_sha256: String,
    pub proposal: ActionProposal,
    pub evidence_ids: Vec<String>,
    pub selection_sha256: String,
}

impl BoundSelectedActionV1 {
    /// Computes the selection hash with `selection_sha256` omitted.
    pub fn compute_selection_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "selection_sha256")
    }
}

/// Reconnects the rank-1 ID/hash pair to the immutable original proposal.
#[allow(clippy::too_many_arguments)]
pub fn bind_selected_action(
    candidate_set: &ActionCandidateSetV1,
    bridge: &PlanRankerInputBridgeV1,
    ranking: &ValidatedPlanRankingV1,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    observation: &ObservationSnapshot,
    grounding: &ValidatedGroundingSelectionV1,
) -> Result<BoundSelectedActionV1, ActionSelectionError> {
    candidate_set.validate()?;
    ranking.validate(candidate_set, bridge)?;
    goal.validate()?;
    world.validate()?;
    plan.validate()?;
    observation.validate()?;
    grounding.validate()?;
    if ranking.output.outcome != PlanRankingOutcomeV1::Ranked {
        return Err(ActionSelectionError::NoEligibleCandidate);
    }
    let selected_id = ranking
        .output
        .selected_candidate_id
        .as_deref()
        .ok_or(ActionSelectionError::NoEligibleCandidate)?;
    let selected_hash = ranking
        .output
        .selected_candidate_hash
        .as_deref()
        .ok_or(ActionSelectionError::NoEligibleCandidate)?;
    let candidate = unique_candidate(candidate_set, selected_id, selected_hash)?;
    if candidate_set.goal_id != goal.goal_id
        || candidate_set.world_state_id != world.world_state_id
        || candidate_set.plan_generation_id != plan.plan_generation_id
        || candidate_set.plan_generation_id != world.plan_generation_id
        || candidate_set.observation_id != observation.observation_id
        || candidate_set.source_observation_hash != observation.state_hash
        || candidate_set.source_observation_sequence != observation.sequence
        || candidate_set.grounding_result_sha256 != grounding.grounding_result_sha256
        || candidate_set.grounded_target_binding_sha256 != grounding.grounded_target.binding_sha256
        || candidate.proposal.valid_until_sequence != observation.sequence
    {
        return integrity("selected candidate lifecycle is stale or substituted");
    }
    if candidate.proposal.goal_id != goal.goal_id
        || candidate.proposal.plan_generation_id != plan.plan_generation_id
        || candidate.proposal.source_observation_hash != observation.state_hash
        || candidate.proposal.semantic_target != grounding.grounded_target.semantic_target_id
        || candidate.capability_binding.semantic_target_id
            != grounding.grounded_target.semantic_target_id
        || !candidate
            .capability_binding
            .allowed_element_kinds
            .contains(&grounding.grounded_target.selected_element_kind)
    {
        return integrity("selected proposal binding differs from trusted context");
    }
    let identity = serde_json::json!({
        "candidate_set_sha256": candidate_set.set_sha256,
        "plan_ranker_input_sha256": bridge.payload_sha256,
        "plan_ranker_output_sha256": ranking.plan_ranker_output_sha256,
        "selected_candidate_id": candidate.candidate_id,
        "selected_candidate_hash": candidate.candidate_hash,
        "selected_proposal_sha256": candidate.proposal_sha256,
    });
    let digest = canonical_sha256(&identity)?;
    let suffix = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| ActionSelectionError::Json("selection digest prefix missing".to_owned()))?;
    let mut evidence_ids = candidate.evidence_ids.clone();
    evidence_ids.sort();
    let mut selected = BoundSelectedActionV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        selection_id: format!("selected-action-{suffix}"),
        candidate_set_sha256: candidate_set.set_sha256.clone(),
        plan_ranker_input_sha256: bridge.payload_sha256.clone(),
        plan_ranker_output_sha256: ranking.plan_ranker_output_sha256.clone(),
        selected_candidate_id: candidate.candidate_id.clone(),
        selected_candidate_hash: candidate.candidate_hash.clone(),
        selected_proposal_id: candidate.proposal_id.clone(),
        selected_proposal_sha256: candidate.proposal_sha256.clone(),
        goal_id: goal.goal_id.clone(),
        world_state_id: world.world_state_id.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        application_pack_sha256: candidate_set.application_pack_sha256.clone(),
        grounding_result_sha256: grounding.grounding_result_sha256.clone(),
        semantic_target_id: grounding.grounded_target.semantic_target_id.clone(),
        selected_element_id: grounding.grounded_target.selected_element_id.clone(),
        selected_element_kind: grounding.grounded_target.selected_element_kind.clone(),
        capability_binding_sha256: candidate.capability_binding_sha256.clone(),
        ranking_profile_sha256: candidate.ranking_profile_sha256.clone(),
        admission_profile_sha256: candidate.admission_profile_sha256.clone(),
        proposal: candidate.proposal.clone(),
        evidence_ids,
        selection_sha256: empty_hash(),
    };
    selected.selection_sha256 = selected.compute_selection_sha256()?;
    validate_hash(&selected.selection_sha256, "selection_sha256")?;
    Ok(selected)
}

/// Read-only input for a future policy boundary. It contains no decision,
/// approval, activation permit, adapter handle, or execution authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReadyActionV1 {
    pub schema_version: u32,
    pub selection_id: String,
    pub selection_sha256: String,
    pub candidate_set_sha256: String,
    pub goal_id: String,
    pub world_state_id: String,
    pub plan_generation_id: String,
    pub observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub application_pack_sha256: String,
    pub grounding_result_sha256: String,
    pub semantic_target_id: String,
    pub selected_element_id: String,
    pub selected_element_kind: String,
    pub capability_id: String,
    pub capability_binding_sha256: String,
    pub proposal: ActionProposal,
    pub risk: CognitiveRiskClass,
    pub reversibility: Reversibility,
    pub confirmation_requirement: ConfirmationRequirement,
    pub expected_postconditions: Vec<Postcondition>,
    pub evidence_ids: Vec<String>,
    pub policy_input_sha256: String,
    pub policy_ready_sha256: String,
}

impl PolicyReadyActionV1 {
    /// Computes the terminal artifact hash with its self-hash omitted.
    pub fn compute_policy_ready_sha256(&self) -> Result<String, ActionSelectionError> {
        hash_without_field(self, "policy_ready_sha256")
    }
}

/// Projects a selected action into a non-authoritative policy input.
pub fn build_policy_ready_action(
    selected: &BoundSelectedActionV1,
) -> Result<PolicyReadyActionV1, ActionSelectionError> {
    validate_hash(&selected.selection_sha256, "selected selection_sha256")?;
    if selected.compute_selection_sha256()? != selected.selection_sha256 {
        return integrity("selected action hash differs from canonical content");
    }
    selected.proposal.validate()?;
    if selected.selected_proposal_id != selected.proposal.proposal_id
        || selected.selected_proposal_sha256 != canonical_sha256(&selected.proposal)?
        || selected.goal_id != selected.proposal.goal_id
        || selected.plan_generation_id != selected.proposal.plan_generation_id
        || selected.source_observation_hash != selected.proposal.source_observation_hash
        || selected.semantic_target_id != selected.proposal.semantic_target
        || selected.source_observation_sequence != selected.proposal.valid_until_sequence
    {
        return integrity("selected action proposal differs from lifecycle bindings");
    }
    let policy_input = serde_json::json!({
        "selection_sha256": selected.selection_sha256,
        "proposal_sha256": selected.selected_proposal_sha256,
        "goal_id": selected.goal_id,
        "world_state_id": selected.world_state_id,
        "plan_generation_id": selected.plan_generation_id,
        "source_observation_hash": selected.source_observation_hash,
        "source_observation_sequence": selected.source_observation_sequence,
        "capability_id": selected.proposal.capability_id,
        "capability_binding_sha256": selected.capability_binding_sha256,
        "risk": selected.proposal.risk,
        "reversibility": selected.proposal.reversibility,
        "confirmation_requirement": selected.proposal.confirmation_requirement,
        "expected_postconditions": selected.proposal.expected_postconditions,
    });
    let policy_input_sha256 = canonical_sha256(&policy_input)?;
    let mut ready = PolicyReadyActionV1 {
        schema_version: ACTION_SELECTION_SCHEMA_VERSION,
        selection_id: selected.selection_id.clone(),
        selection_sha256: selected.selection_sha256.clone(),
        candidate_set_sha256: selected.candidate_set_sha256.clone(),
        goal_id: selected.goal_id.clone(),
        world_state_id: selected.world_state_id.clone(),
        plan_generation_id: selected.plan_generation_id.clone(),
        observation_id: selected.observation_id.clone(),
        source_observation_hash: selected.source_observation_hash.clone(),
        source_observation_sequence: selected.source_observation_sequence,
        application_pack_sha256: selected.application_pack_sha256.clone(),
        grounding_result_sha256: selected.grounding_result_sha256.clone(),
        semantic_target_id: selected.semantic_target_id.clone(),
        selected_element_id: selected.selected_element_id.clone(),
        selected_element_kind: selected.selected_element_kind.clone(),
        capability_id: selected.proposal.capability_id.clone(),
        capability_binding_sha256: selected.capability_binding_sha256.clone(),
        proposal: selected.proposal.clone(),
        risk: selected.proposal.risk,
        reversibility: selected.proposal.reversibility,
        confirmation_requirement: selected.proposal.confirmation_requirement,
        expected_postconditions: selected.proposal.expected_postconditions.clone(),
        evidence_ids: selected.evidence_ids.clone(),
        policy_input_sha256,
        policy_ready_sha256: empty_hash(),
    };
    reject_forbidden_json(
        &serde_json::to_value(&ready)
            .map_err(|error| json_error("serialize policy-ready action", error))?,
        "policy-ready action",
    )?;
    ready.policy_ready_sha256 = ready.compute_policy_ready_sha256()?;
    validate_hash(&ready.policy_ready_sha256, "policy_ready_sha256")?;
    Ok(ready)
}

fn validate_grounding_result_shape(
    result: &ElementGroundingResultV1,
) -> Result<(), ActionSelectionError> {
    validate_version(result.schema_version, "Element Grounder result")?;
    validate_id(&result.goal_id, "Grounder goal_id")?;
    validate_hash(
        &result.source_observation_hash,
        "Grounder source_observation_hash",
    )?;
    validate_id(&result.plan_generation_id, "Grounder plan_generation_id")?;
    validate_text(&result.target_text, "Grounder target_text")?;
    if result.candidates.len() > MAX_CANDIDATES {
        return invalid("Grounder candidates exceeds 64");
    }
    validate_texts(&result.evidence, "Grounder evidence", 256, false)?;
    validate_texts(&result.warnings, "Grounder warnings", 256, false)?;
    if let Some(reason) = &result.ambiguity_reason {
        validate_text(reason, "Grounder ambiguity_reason")?;
    }
    let mut ids = BTreeSet::new();
    for candidate in &result.candidates {
        validate_id(&candidate.element_id, "Grounder candidate element_id")?;
        validate_id(&candidate.kind, "Grounder candidate kind")?;
        validate_text(&candidate.label, "Grounder candidate label")?;
        if !candidate.score.is_finite() || !(0.0..=1.0).contains(&candidate.score) {
            return invalid("Grounder candidate score must be finite within 0..=1");
        }
        validate_texts(
            &candidate.matched_features,
            "Grounder matched_features",
            256,
            false,
        )?;
        validate_texts(
            &candidate.evidence,
            "Grounder candidate evidence",
            256,
            false,
        )?;
        if candidate.trust_labels.is_empty() {
            return invalid("Grounder candidate trust_labels must not be empty");
        }
        if !ids.insert(candidate.element_id.as_str()) {
            return invalid("Grounder candidate element IDs must be unique");
        }
    }
    match (result.status, result.selected_element_id.as_deref()) {
        (GroundingStatusV1::UniqueMatch, Some(selected)) => {
            validate_id(selected, "Grounder selected_element_id")?;
        }
        (GroundingStatusV1::UniqueMatch, None) => {
            return invalid("unique_match requires selected_element_id");
        }
        (_, None) => {}
        (_, Some(_)) => return invalid("non-unique Grounder status cannot select an element"),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_candidate_context(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    selection: &ValidatedGroundingSelectionV1,
    context: &ActionSelectionContextV1,
    binding: &ActionCapabilityBinding,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    spec: &GroundedActionProposalSpecV1,
) -> Result<(), ActionSelectionError> {
    validate_lifecycle(pack, observation, selection, context, goal, world, plan)?;
    binding.validate()?;
    validate_ranker_id(&spec.candidate_id, "candidate_id")?;
    validate_hash(
        &spec.capability_binding_sha256,
        "spec capability_binding_sha256",
    )?;
    if spec.capability_binding_sha256 != binding.binding_sha256 {
        return integrity("candidate spec binding hash differs from the supplied binding");
    }
    if !context
        .allowed_capability_ids
        .contains(&binding.capability.capability_id)
        || !world
            .capabilities
            .contains(&binding.capability.capability_id)
    {
        return Err(ActionSelectionError::Unsupported(
            "capability is unavailable in selection context or WorldState".to_owned(),
        ));
    }
    let target = unique_semantic_target(pack, &selection.grounded_target.semantic_target_id)?;
    if binding.application_pack_sha256 != pack.pack_sha256
        || binding.semantic_target_id != target.target_id
        || binding.source_kind != observation.source_kind
        || binding.source_kind != selection.grounded_target.source_kind
        || !binding
            .allowed_element_kinds
            .contains(&selection.grounded_target.selected_element_kind)
        || !target
            .expected_kinds
            .contains(&selection.grounded_target.selected_element_kind)
        || binding.capability.operation != action_input_kind(&spec.input).operation()
        || binding.action_kind != action_input_kind(&spec.input)
    {
        return integrity("candidate source, target, kind, action, or capability binding differs");
    }
    if !binding.capability.reversible
        || binding.capability.confirmation_requirement
            == ConfirmationRequirement::UnsupportedIrreversible
    {
        return invalid("irreversible or unsupported-irreversible candidate is forbidden");
    }
    if spec.expected_postconditions.is_empty() {
        return invalid("candidate requires at least one expected postcondition");
    }
    if spec.preconditions.len() > 256 || spec.expected_postconditions.len() > 256 {
        return invalid("candidate condition count exceeds 256");
    }
    if !spec.confidence.is_finite() || !(0.0..=1.0).contains(&spec.confidence) {
        return invalid("candidate confidence must be finite within 0..=1");
    }
    reject_forbidden_json(
        &serde_json::to_value(&spec.preconditions)
            .map_err(|error| json_error("serialize preconditions", error))?,
        "candidate preconditions",
    )?;
    reject_forbidden_json(
        &serde_json::to_value(&spec.expected_postconditions)
            .map_err(|error| json_error("serialize postconditions", error))?,
        "candidate expected_postconditions",
    )?;
    validate_action_input(&spec.input)
}

fn validate_lifecycle(
    pack: &ApplicationPack,
    observation: &ObservationSnapshot,
    selection: &ValidatedGroundingSelectionV1,
    context: &ActionSelectionContextV1,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
) -> Result<(), ActionSelectionError> {
    pack.validate()?;
    observation.validate()?;
    selection.validate()?;
    context.validate_context(goal, world, plan)?;
    if selection.grounded_target.application_pack_sha256 != pack.pack_sha256
        || selection.grounded_target.observation_id != observation.observation_id
        || selection.grounded_target.source_observation_hash != observation.state_hash
        || selection.grounded_target.source_observation_sequence != observation.sequence
        || selection.grounded_target.goal_id != goal.goal_id
        || selection.grounded_target.plan_generation_id != plan.plan_generation_id
        || world.current_observation_hash != observation.state_hash
    {
        return integrity("grounded selection differs from pack/observation/goal/world/plan");
    }
    reject_forbidden_json(
        &serde_json::to_value(goal)
            .map_err(|error| json_error("serialize goal for trust validation", error))?,
        "goal",
    )
}

fn validate_profile_bindings(
    proposal: &ActionProposal,
    binding: &ActionCapabilityBinding,
    ranking: &CandidateRankingProfileV1,
    admission: &CandidateAdmissionProfileV1,
) -> Result<(), ActionSelectionError> {
    let proposal_hash = canonical_sha256(proposal)?;
    let exact = |proposal_id: &str,
                 proposal_sha256: &str,
                 capability_id: &str,
                 binding_sha256: &str,
                 goal_id: &str,
                 generation_id: &str,
                 observation_hash: &str| {
        proposal_id == proposal.proposal_id
            && proposal_sha256 == proposal_hash
            && capability_id == proposal.capability_id
            && binding_sha256 == binding.binding_sha256
            && goal_id == proposal.goal_id
            && generation_id == proposal.plan_generation_id
            && observation_hash == proposal.source_observation_hash
    };
    if !exact(
        &ranking.proposal_id,
        &ranking.proposal_sha256,
        &ranking.capability_id,
        &ranking.capability_binding_sha256,
        &ranking.goal_id,
        &ranking.plan_generation_id,
        &ranking.source_observation_hash,
    ) || !exact(
        &admission.proposal_id,
        &admission.proposal_sha256,
        &admission.capability_id,
        &admission.capability_binding_sha256,
        &admission.goal_id,
        &admission.plan_generation_id,
        &admission.source_observation_hash,
    ) {
        return integrity("ranking or admission profile binding differs from proposal");
    }
    Ok(())
}

fn validate_plan_ranking_shape(
    candidate_set: &ActionCandidateSetV1,
    output: &PlanRankingOutputV1,
) -> Result<(), ActionSelectionError> {
    if output.schema_version != ACTION_SELECTION_SCHEMA_VERSION
        || output.ranking_policy_version != 1
    {
        return invalid("Plan Ranker output schema or policy version must be 1");
    }
    if output.ranked_candidates.len() > MAX_CANDIDATES
        || output.rejected_candidates.len() > MAX_CANDIDATES
    {
        return invalid("Plan Ranker output candidate count exceeds 64");
    }
    match (
        output.outcome,
        output.selected_candidate_id.as_deref(),
        output.selected_candidate_hash.as_deref(),
        output.ranked_candidates.is_empty(),
    ) {
        (PlanRankingOutcomeV1::Ranked, Some(_), Some(_), false) => {}
        (PlanRankingOutcomeV1::NoEligibleCandidate, None, None, true) => {}
        _ => return invalid("Plan Ranker selected/null/outcome rules are inconsistent"),
    }
    let source = candidate_set
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.candidate_id.as_str(),
                candidate.candidate_hash.as_str(),
                candidate,
            )
        })
        .collect::<Vec<_>>();
    let mut covered = BTreeSet::new();
    for (index, ranked) in output.ranked_candidates.iter().enumerate() {
        let expected_rank = u32::try_from(index.saturating_add(1))
            .map_err(|_| ActionSelectionError::Invalid("rank is not representable".to_owned()))?;
        if ranked.rank != expected_rank {
            return invalid("Plan Ranker ranks must be contiguous from 1");
        }
        let candidate = source_candidate(&source, &ranked.candidate_id, &ranked.candidate_hash)?;
        if ranked.normalized_cost_millionths != candidate.ranking_profile.normalized_cost_millionths
            || ranked.success_likelihood_millionths
                != candidate.ranking_profile.success_likelihood_millionths
        {
            return integrity("ranked cost or likelihood differs from sealed profile");
        }
        if candidate
            .admission_profile
            .gate_results
            .ordered()
            .iter()
            .any(|(_, status)| *status != GateStatusV1::Passed)
        {
            return integrity("candidate with a non-passed gate cannot be ranked");
        }
        if !covered.insert(candidate.candidate_id.as_str()) {
            return invalid("Plan Ranker output contains a duplicate candidate");
        }
    }
    for rejected in &output.rejected_candidates {
        let candidate =
            source_candidate(&source, &rejected.candidate_id, &rejected.candidate_hash)?;
        let expected = candidate
            .admission_profile
            .gate_results
            .ordered()
            .into_iter()
            .filter(|(_, status)| *status != GateStatusV1::Passed)
            .map(|(gate, status)| PlanRankingGateRejectionV1 { gate, status })
            .collect::<Vec<_>>();
        if expected.is_empty() || rejected.reasons != expected {
            return integrity("Plan Ranker rejection reasons differ from supplied gates");
        }
        if !covered.insert(candidate.candidate_id.as_str()) {
            return invalid("candidate appears more than once or in ranked and rejected output");
        }
    }
    if covered.len() != candidate_set.candidates.len() {
        return integrity("Plan Ranker output omitted an input candidate");
    }
    if let Some(first) = output.ranked_candidates.first() {
        if output.selected_candidate_id.as_deref() != Some(first.candidate_id.as_str())
            || output.selected_candidate_hash.as_deref() != Some(first.candidate_hash.as_str())
        {
            return integrity("Plan Ranker selection must equal rank 1 ID/hash");
        }
    }
    Ok(())
}

fn source_candidate<'a>(
    source: &[(&str, &str, &'a ActionCandidateRecordV1)],
    candidate_id: &str,
    candidate_hash: &str,
) -> Result<&'a ActionCandidateRecordV1, ActionSelectionError> {
    let id_matches = source
        .iter()
        .filter(|(id, _, _)| *id == candidate_id)
        .collect::<Vec<_>>();
    if id_matches.len() != 1 {
        return integrity("Plan Ranker output candidate ID is missing or ambiguous");
    }
    if id_matches[0].1 != candidate_hash {
        return integrity("Plan Ranker output substituted an ID/hash pair");
    }
    Ok(id_matches[0].2)
}

fn unique_candidate<'a>(
    set: &'a ActionCandidateSetV1,
    candidate_id: &str,
    candidate_hash: &str,
) -> Result<&'a ActionCandidateRecordV1, ActionSelectionError> {
    let mut matches = set
        .candidates
        .iter()
        .filter(|candidate| candidate.candidate_id == candidate_id);
    let candidate = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity("selected candidate is absent".to_owned())
    })?;
    if matches.next().is_some() || candidate.candidate_hash != candidate_hash {
        return integrity("selected candidate is duplicated or hash-substituted");
    }
    Ok(candidate)
}

fn unique_semantic_target<'a>(
    pack: &'a ApplicationPack,
    target_id: &str,
) -> Result<&'a ApplicationSemanticTarget, ActionSelectionError> {
    let mut matches = pack
        .targets
        .iter()
        .filter(|target| target.target_id == target_id);
    let target = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity(
            "semantic target is absent from application pack".to_owned(),
        )
    })?;
    if matches.next().is_some() {
        return integrity("semantic target is duplicated in application pack");
    }
    Ok(target)
}

fn unique_observed_element<'a>(
    observation: &'a ObservationSnapshot,
    element_id: &str,
) -> Result<&'a d2i_cognitive_ir::ObservableElement, ActionSelectionError> {
    let mut matches = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == element_id);
    let element = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity("selected element is absent from observation".to_owned())
    })?;
    if matches.next().is_some() {
        return integrity("selected element is duplicated in observation");
    }
    Ok(element)
}

fn unique_grounding_candidate<'a>(
    candidates: &'a [ElementGroundingCandidateV1],
    element_id: &str,
) -> Result<&'a ElementGroundingCandidateV1, ActionSelectionError> {
    let mut matches = candidates
        .iter()
        .filter(|candidate| candidate.element_id == element_id);
    let candidate = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity(
            "selected element is absent from Grounder candidates".to_owned(),
        )
    })?;
    if matches.next().is_some() {
        return integrity("selected element is duplicated in Grounder candidates");
    }
    Ok(candidate)
}

fn unique_plan_node<'a>(
    plan: &'a PlanGraph,
    node_id: &str,
) -> Result<&'a d2i_cognitive_ir::PlanNode, ActionSelectionError> {
    let mut matches = plan.nodes.iter().filter(|node| node.node_id == node_id);
    let node = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity("selection plan node is absent".to_owned())
    })?;
    if matches.next().is_some() {
        return integrity("selection plan node is duplicated");
    }
    Ok(node)
}

fn unique_capability_binding<'a>(
    bindings: &'a [ActionCapabilityBinding],
    binding_sha256: &str,
) -> Result<&'a ActionCapabilityBinding, ActionSelectionError> {
    validate_hash(binding_sha256, "requested capability binding hash")?;
    let mut matches = bindings
        .iter()
        .filter(|binding| binding.binding_sha256 == binding_sha256);
    let binding = matches.next().ok_or_else(|| {
        ActionSelectionError::Integrity("requested capability binding is absent".to_owned())
    })?;
    if matches.next().is_some() {
        return integrity("requested capability binding is duplicated");
    }
    Ok(binding)
}

fn reject_forbidden_selected_element(
    observation: &ObservationSnapshot,
    element: &d2i_cognitive_ir::ObservableElement,
    candidate: &ElementGroundingCandidateV1,
) -> Result<(), ActionSelectionError> {
    if element.element_id == "observation.status" || element.kind == "observation.status" {
        return invalid("observation.status cannot be selected");
    }
    if observation
        .redactions
        .iter()
        .any(|redaction| redaction.field.contains(&element.element_id))
    {
        return invalid("redacted observed element cannot be selected");
    }
    if secret_like(&element.label)
        || secret_like(&element.kind)
        || secret_like(&candidate.label)
        || json_contains_secret(&element.value)
    {
        return invalid("credential or secret-like observed element cannot be selected");
    }
    Ok(())
}

fn validate_candidate_uniqueness(
    candidates: &[ActionCandidateRecordV1],
) -> Result<(), ActionSelectionError> {
    let mut ids = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for candidate in candidates {
        if !ids.insert(candidate.candidate_id.as_str()) {
            return invalid("candidate IDs must be unique");
        }
        if !hashes.insert(candidate.candidate_hash.as_str()) {
            return invalid("candidate hashes must be unique");
        }
    }
    Ok(())
}

fn rejected_build(
    spec: &CandidateGenerationSpecV1,
    reason_code: CandidateBuildRejectionCodeV1,
) -> Result<RejectedCandidateBuildV1, ActionSelectionError> {
    validate_ranker_id(&spec.proposal.candidate_id, "rejected candidate_id")?;
    validate_hash(
        &spec.proposal.capability_binding_sha256,
        "rejected capability binding hash",
    )?;
    Ok(RejectedCandidateBuildV1 {
        candidate_id: spec.proposal.candidate_id.clone(),
        capability_binding_sha256: spec.proposal.capability_binding_sha256.clone(),
        reason_code,
        evidence_ids: vec!["capability-admission".to_owned()],
    })
}

fn action_input_kind(input: &CandidateActionInput) -> CandidateActionKind {
    match input {
        CandidateActionInput::Invoke => CandidateActionKind::Invoke,
        CandidateActionInput::SetText { .. } => CandidateActionKind::SetText,
        CandidateActionInput::Toggle { .. } => CandidateActionKind::Toggle,
        CandidateActionInput::Click => CandidateActionKind::Click,
        CandidateActionInput::TypeText { .. } => CandidateActionKind::TypeText,
        CandidateActionInput::Select { .. } => CandidateActionKind::Select,
    }
}

fn validate_action_input(input: &CandidateActionInput) -> Result<(), ActionSelectionError> {
    match input {
        CandidateActionInput::SetText { text_hash }
        | CandidateActionInput::TypeText { text_hash } => {
            validate_hash(text_hash, "candidate text_hash")
        }
        CandidateActionInput::Select { value_hash } => {
            validate_hash(value_hash, "candidate value_hash")
        }
        CandidateActionInput::Invoke
        | CandidateActionInput::Toggle { .. }
        | CandidateActionInput::Click => Ok(()),
    }
}

fn validate_version(version: u32, label: &str) -> Result<(), ActionSelectionError> {
    if version != ACTION_SELECTION_SCHEMA_VERSION {
        return invalid(&format!("{label} schema_version must be 1"));
    }
    Ok(())
}

fn validate_id(value: &str, field: &str) -> Result<(), ActionSelectionError> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric()
                || (index > 0 && matches!(character, '_' | '-' | '.' | ':' | '/'))
        })
    {
        return invalid(&format!("{field} is not a bounded identifier"));
    }
    Ok(())
}

fn validate_ranker_id(value: &str, field: &str) -> Result<(), ActionSelectionError> {
    if value.is_empty()
        || value.len() > 128
        || !value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric() || (index > 0 && matches!(character, '_' | '-' | '.'))
        })
    {
        return invalid(&format!("{field} is not a Plan Ranker identifier"));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), ActionSelectionError> {
    if value.is_empty()
        || value.len() > MAX_TEXT
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return invalid(&format!("{field} is not bounded text"));
    }
    Ok(())
}

fn validate_texts(
    values: &[String],
    field: &str,
    maximum: usize,
    require_nonempty: bool,
) -> Result<(), ActionSelectionError> {
    if values.len() > maximum || (require_nonempty && values.is_empty()) {
        return invalid(&format!("{field} has an invalid collection length"));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_sorted_ids(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), ActionSelectionError> {
    if values.is_empty() || values.len() > maximum {
        return invalid(&format!("{field} must contain 1..={maximum} values"));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_id(value, field)?;
        if previous.is_some_and(|prior| prior >= value.as_str()) {
            return invalid(&format!("{field} must be strictly sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), ActionSelectionError> {
    let suffix = value
        .strip_prefix("sha256:")
        .ok_or_else(|| ActionSelectionError::Invalid(format!("{field} must use sha256:")))?;
    if suffix.len() != 64
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(&format!("{field} must be lowercase SHA-256"));
    }
    Ok(())
}

fn validate_semver(value: &str) -> Result<(), ActionSelectionError> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return invalid("capability_version must be MAJOR.MINOR.PATCH");
    }
    Ok(())
}

fn reject_forbidden_json(value: &Value, field: &str) -> Result<(), ActionSelectionError> {
    fn walk(value: &Value, path: &str) -> Result<(), ActionSelectionError> {
        match value {
            Value::Object(object) => {
                for (key, child) in object {
                    let normalized = key.to_ascii_lowercase();
                    if forbidden_key(&normalized) {
                        return invalid(&format!("{path} contains forbidden field '{key}'"));
                    }
                    walk(child, &format!("{path}.{key}"))?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, path)?;
                }
            }
            Value::String(text) if secret_like(text) => {
                return invalid(&format!("{path} contains raw secret-like text"));
            }
            Value::Number(number) if number.as_f64().is_some_and(|number| !number.is_finite()) => {
                return invalid(&format!("{path} contains a non-finite number"));
            }
            _ => {}
        }
        Ok(())
    }
    walk(value, field)
}

fn forbidden_key(key: &str) -> bool {
    [
        "password",
        "passwd",
        "secret",
        "credential",
        "token",
        "cookie",
        "authorization",
        "locator",
        "selector",
        "xpath",
        "automationid",
        "runtimeid",
        "coordinates",
        "webdriver_element",
        "com_handle",
        "adapter_handle",
        "policy_decision",
        "activation_permit",
        "approval_signature",
        "executable_locator",
        "url",
    ]
    .iter()
    .any(|marker| key.contains(marker))
}

fn secret_like(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "api key",
        "apikey",
        "secret",
        "access token",
        "refresh token",
        "authorization:",
        "cookie:",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn json_contains_secret(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            forbidden_key(&key.to_ascii_lowercase()) || json_contains_secret(child)
        }),
        Value::Array(values) => values.iter().any(json_contains_secret),
        Value::String(text) => secret_like(text),
        _ => false,
    }
}

fn invalid<T>(message: &str) -> Result<T, ActionSelectionError> {
    Err(ActionSelectionError::Invalid(message.to_owned()))
}

fn integrity<T>(message: &str) -> Result<T, ActionSelectionError> {
    Err(ActionSelectionError::Integrity(message.to_owned()))
}

fn json_error(context: &str, error: impl Display) -> ActionSelectionError {
    ActionSelectionError::Json(format!("{context}: {error}"))
}

fn empty_hash() -> String {
    format!("sha256:{}", "0".repeat(64))
}

fn hash_without_field<T: Serialize>(
    value: &T,
    field: &str,
) -> Result<String, ActionSelectionError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| json_error("serialize self-hash", error))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ActionSelectionError::Json("self-hashed artifact is not an object".to_owned())
    })?;
    object.remove(field);
    canonical_sha256(&value)
}

/// Computes SHA-256 over compact JSON with recursively sorted object keys.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ActionSelectionError> {
    let value = serde_json::to_value(value)
        .map_err(|error| json_error("convert canonical JSON value", error))?;
    validate_json_limits(&value)?;
    let bytes = serde_json::to_vec(&canonicalize_value(value))
        .map_err(|error| json_error("serialize canonical JSON", error))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

/// Parses strict bounded JSON, rejecting duplicate keys and trailing content.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ActionSelectionError> {
    if bytes.len() > MAX_JSON_BYTES {
        return invalid("JSON input exceeds 8 MiB");
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer
        .deserialize_any(StrictValueVisitor)
        .map_err(|error| json_error("parse strict JSON", error))?;
    deserializer
        .end()
        .map_err(|error| json_error("reject trailing JSON", error))?;
    validate_json_limits(&value)?;
    serde_json::from_value(value).map_err(|error| json_error("decode strict contract", error))
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let ordered = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
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
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key '{key}'"
                )));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StrictValueSeed;

impl<'de> serde::de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

fn validate_json_limits(value: &Value) -> Result<(), ActionSelectionError> {
    fn walk(value: &Value, depth: usize, count: &mut usize) -> Result<(), ActionSelectionError> {
        if depth > MAX_JSON_DEPTH {
            return invalid("JSON nesting exceeds 64");
        }
        *count = count.saturating_add(1);
        if *count > MAX_JSON_NODES {
            return invalid("JSON node count exceeds 100000");
        }
        match value {
            Value::Object(object) => {
                for child in object.values() {
                    walk(child, depth.saturating_add(1), count)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    walk(child, depth.saturating_add(1), count)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut count = 0;
    walk(value, 0, &mut count)
}
