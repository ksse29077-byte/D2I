//! Action Candidate Provider Contract v1 and deterministic fixture bridge.
//!
//! This crate binds one application semantic target and one fixture grounding
//! oracle to an already declared Cognitive IR v1 capability. It emits only an
//! `ActionProposal` data record. It owns no adapter, policy, activation,
//! approval, audit, module loader, network, filesystem, process, UI, or browser
//! execution authority.

use d2i_application_semantics::{
    ApplicationPack, ApplicationSemanticTarget, ObservationFixtureBridge,
};
use d2i_cognitive_ir::{
    ActionProposal, CapabilityDescriptor, ConfirmationRequirement, GoalSpec, ObservationSourceKind,
    PlanGraph, PlanNodeKind, Postcondition, Reversibility, WorldState,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Action Candidate Provider fixture contract version.
pub const ACTION_CANDIDATE_SCHEMA_VERSION: u32 = 1;
/// Authoritative Action Candidate Provider v1 JSON Schema.
pub const ACTION_CANDIDATE_PROVIDER_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/action-candidate-provider-v1.schema.json");

const MAX_ID_BYTES: usize = 128;
const MAX_ELEMENT_KINDS: usize = 32;
const MAX_CONDITIONS: usize = 32;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Structured Action Candidate Provider bridge failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionCandidateError {
    /// A field, collection, or version is malformed or outside its bound.
    Invalid(String),
    /// A lifecycle, hash, target, capability, or fixture binding differs.
    Integrity(String),
    /// A referenced semantic target, grounding case, element, or plan node is absent.
    NotFound(String),
    /// A supposedly unique record has more than one match.
    Ambiguous(String),
    /// The requested capability/action combination is not supported by v1.
    Unsupported(String),
    /// Canonical JSON conversion or serialization failed.
    Json(String),
}

impl Display for ActionCandidateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid action candidate: {message}"),
            Self::Integrity(message) => {
                write!(formatter, "action candidate integrity failure: {message}")
            }
            Self::NotFound(message) => {
                write!(formatter, "action candidate target absent: {message}")
            }
            Self::Ambiguous(message) => {
                write!(formatter, "ambiguous action candidate binding: {message}")
            }
            Self::Unsupported(message) => {
                write!(formatter, "unsupported action candidate: {message}")
            }
            Self::Json(message) => write!(formatter, "action candidate JSON failure: {message}"),
        }
    }
}

impl Error for ActionCandidateError {}

impl From<d2i_cognitive_ir::CognitiveIrError> for ActionCandidateError {
    fn from(error: d2i_cognitive_ir::CognitiveIrError) -> Self {
        Self::Integrity(error.to_string())
    }
}

impl From<d2i_application_semantics::ApplicationSemanticsError> for ActionCandidateError {
    fn from(error: d2i_application_semantics::ApplicationSemanticsError) -> Self {
        Self::Integrity(error.to_string())
    }
}

/// Closed action argument shape supported by the v1 fixture bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateActionInput {
    /// Invoke one UI Automation element.
    Invoke,
    /// Set UI Automation text by content hash only.
    SetText { text_hash: String },
    /// Set a UI Automation toggle to the requested boolean state.
    Toggle { desired: bool },
    /// Click one WebDriver element.
    Click,
    /// Type WebDriver text by content hash only.
    TypeText { text_hash: String },
    /// Select a WebDriver value by content hash only.
    Select { value_hash: String },
}

impl CandidateActionInput {
    fn kind(&self) -> CandidateActionKind {
        match self {
            Self::Invoke => CandidateActionKind::Invoke,
            Self::SetText { .. } => CandidateActionKind::SetText,
            Self::Toggle { .. } => CandidateActionKind::Toggle,
            Self::Click => CandidateActionKind::Click,
            Self::TypeText { .. } => CandidateActionKind::TypeText,
            Self::Select { .. } => CandidateActionKind::Select,
        }
    }

    fn validate(&self) -> Result<(), ActionCandidateError> {
        match self {
            Self::SetText { text_hash } | Self::TypeText { text_hash } => {
                validate_hash(text_hash, "candidate text_hash")
            }
            Self::Select { value_hash } => validate_hash(value_hash, "candidate value_hash"),
            Self::Invoke | Self::Toggle { .. } | Self::Click => Ok(()),
        }
    }
}

/// Closed operation family used to cross-check a capability descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateActionKind {
    Invoke,
    SetText,
    Toggle,
    Click,
    TypeText,
    Select,
}

impl CandidateActionKind {
    /// Returns the exact Cognitive capability operation token for this action.
    #[must_use]
    pub fn operation(self) -> &'static str {
        match self {
            Self::Invoke => "uia.invoke",
            Self::SetText => "uia.set_value",
            Self::Toggle => "uia.toggle",
            Self::Click => "webdriver.click",
            Self::TypeText => "webdriver.type",
            Self::Select => "webdriver.select",
        }
    }

    /// Returns the observation source required by this action.
    #[must_use]
    pub fn source_kind(self) -> ObservationSourceKind {
        match self {
            Self::Invoke | Self::SetText | Self::Toggle => ObservationSourceKind::Uia,
            Self::Click | Self::TypeText | Self::Select => ObservationSourceKind::WebDriver,
        }
    }
}

/// Immutable mapping from one semantic target to one declared capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCapabilityBinding {
    pub schema_version: u32,
    pub binding_id: String,
    pub application_pack_sha256: String,
    pub semantic_target_id: String,
    pub source_kind: ObservationSourceKind,
    pub allowed_element_kinds: Vec<String>,
    pub action_kind: CandidateActionKind,
    pub capability: CapabilityDescriptor,
    pub binding_sha256: String,
}

impl ActionCapabilityBinding {
    /// Computes the canonical binding hash with `binding_sha256` omitted.
    pub fn compute_binding_sha256(&self) -> Result<String, ActionCandidateError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| json_error("serialize binding", error))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ActionCandidateError::Json(
                "action capability binding did not serialize as an object".to_owned(),
            )
        })?;
        object.remove("binding_sha256");
        hash_value(&value)
    }

    /// Sorts set-like fields and replaces `binding_sha256`.
    pub fn seal(mut self) -> Result<Self, ActionCandidateError> {
        self.allowed_element_kinds.sort();
        self.binding_sha256 = self.compute_binding_sha256()?;
        Ok(self)
    }

    /// Validates bounds, operation/source compatibility, and the binding hash.
    pub fn validate(&self) -> Result<(), ActionCandidateError> {
        if self.schema_version != ACTION_CANDIDATE_SCHEMA_VERSION {
            return invalid("action capability binding schema_version must be 1");
        }
        validate_id(&self.binding_id, "binding_id")?;
        validate_hash(
            &self.application_pack_sha256,
            "binding application_pack_sha256",
        )?;
        validate_id(&self.semantic_target_id, "binding semantic_target_id")?;
        validate_hash(&self.binding_sha256, "binding_sha256")?;
        self.capability.validate()?;
        if self.source_kind != self.action_kind.source_kind() {
            return Err(ActionCandidateError::Integrity(
                "binding source kind differs from its action kind".to_owned(),
            ));
        }
        if self.capability.operation != self.action_kind.operation() {
            return Err(ActionCandidateError::Integrity(
                "capability operation differs from the bound action kind".to_owned(),
            ));
        }
        if !self.capability.reversible
            || self.capability.confirmation_requirement
                == ConfirmationRequirement::UnsupportedIrreversible
        {
            return Err(ActionCandidateError::Unsupported(
                "v1 fixture bridge supports only reversible capabilities".to_owned(),
            ));
        }
        validate_sorted_ids(
            &self.allowed_element_kinds,
            "allowed_element_kinds",
            MAX_ELEMENT_KINDS,
        )?;
        if self.compute_binding_sha256()? != self.binding_sha256 {
            return Err(ActionCandidateError::Integrity(
                "binding_sha256 does not match the canonical capability binding".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Bounded request to create one capability-bound fixture proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCandidateBridgeRequest {
    pub schema_version: u32,
    pub application_pack_sha256: String,
    pub observation_bridge_sha256: String,
    pub grounding_case_id: String,
    pub capability_binding_sha256: String,
    pub goal_id: String,
    pub world_state_id: String,
    pub plan_generation_id: String,
    pub input: CandidateActionInput,
    pub preconditions: Vec<Postcondition>,
    pub expected_postconditions: Vec<Postcondition>,
    pub confidence: f64,
}

impl ActionCandidateBridgeRequest {
    fn validate(&self) -> Result<(), ActionCandidateError> {
        if self.schema_version != ACTION_CANDIDATE_SCHEMA_VERSION {
            return invalid("action candidate bridge request schema_version must be 1");
        }
        validate_hash(
            &self.application_pack_sha256,
            "request application_pack_sha256",
        )?;
        validate_hash(
            &self.observation_bridge_sha256,
            "request observation_bridge_sha256",
        )?;
        validate_id(&self.grounding_case_id, "request grounding_case_id")?;
        validate_hash(
            &self.capability_binding_sha256,
            "request capability_binding_sha256",
        )?;
        validate_id(&self.goal_id, "request goal_id")?;
        validate_id(&self.world_state_id, "request world_state_id")?;
        validate_id(&self.plan_generation_id, "request plan_generation_id")?;
        self.input.validate()?;
        validate_conditions(&self.preconditions, "request preconditions", false)?;
        validate_conditions(
            &self.expected_postconditions,
            "request expected_postconditions",
            true,
        )?;
        if !self.confidence.is_finite() || !(0.0..=1.0).contains(&self.confidence) {
            return invalid("request confidence must be finite and within 0.0..=1.0");
        }
        Ok(())
    }
}

/// Exact non-executable target binding embedded in proposal arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateTargetBinding {
    pub application_pack_sha256: String,
    pub observation_bridge_sha256: String,
    pub observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub grounding_case_id: String,
    pub semantic_target_id: String,
    pub element_id: String,
    pub element_kind: String,
    pub capability_binding_sha256: String,
}

impl CandidateTargetBinding {
    fn validate(&self) -> Result<(), ActionCandidateError> {
        validate_hash(
            &self.application_pack_sha256,
            "target application_pack_sha256",
        )?;
        validate_hash(
            &self.observation_bridge_sha256,
            "target observation_bridge_sha256",
        )?;
        validate_id(&self.observation_id, "target observation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "target source_observation_hash",
        )?;
        validate_id(&self.grounding_case_id, "target grounding_case_id")?;
        validate_id(&self.semantic_target_id, "target semantic_target_id")?;
        validate_id(&self.element_id, "target element_id")?;
        validate_id(&self.element_kind, "target element_kind")?;
        validate_hash(
            &self.capability_binding_sha256,
            "target capability_binding_sha256",
        )
    }
}

/// Strict typed JSON stored in `ActionProposal.arguments`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateActionArguments {
    pub schema_version: u32,
    pub operation: String,
    pub target: CandidateTargetBinding,
    pub input: CandidateActionInput,
}

impl CandidateActionArguments {
    /// Validates the closed argument shape without granting execution authority.
    pub fn validate(&self) -> Result<(), ActionCandidateError> {
        if self.schema_version != ACTION_CANDIDATE_SCHEMA_VERSION {
            return invalid("candidate arguments schema_version must be 1");
        }
        validate_id(&self.operation, "candidate arguments operation")?;
        self.target.validate()?;
        self.input.validate()
    }
}

/// Self-hashed fixture artifact containing one capability-bound proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBoundActionProposal {
    pub schema_version: u32,
    pub application_pack_sha256: String,
    pub observation_bridge_sha256: String,
    pub observation_id: String,
    pub source_observation_sequence: u64,
    pub grounding_case_id: String,
    pub semantic_target_id: String,
    pub selected_element_id: String,
    pub world_state_id: String,
    pub capability_binding: ActionCapabilityBinding,
    pub proposal: ActionProposal,
    pub proposal_sha256: String,
    pub bridge_sha256: String,
}

impl CapabilityBoundActionProposal {
    /// Computes the canonical artifact hash with `bridge_sha256` omitted.
    pub fn compute_bridge_sha256(&self) -> Result<String, ActionCandidateError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| json_error("serialize bridge", error))?;
        let object = value.as_object_mut().ok_or_else(|| {
            ActionCandidateError::Json(
                "capability-bound proposal did not serialize as an object".to_owned(),
            )
        })?;
        object.remove("bridge_sha256");
        hash_value(&value)
    }

    /// Validates all internal hashes and exact duplicated bindings.
    pub fn validate(&self) -> Result<(), ActionCandidateError> {
        if self.schema_version != ACTION_CANDIDATE_SCHEMA_VERSION {
            return invalid("capability-bound proposal schema_version must be 1");
        }
        validate_hash(
            &self.application_pack_sha256,
            "proposal bridge application_pack_sha256",
        )?;
        validate_hash(
            &self.observation_bridge_sha256,
            "proposal bridge observation_bridge_sha256",
        )?;
        validate_id(&self.observation_id, "proposal bridge observation_id")?;
        validate_id(&self.grounding_case_id, "proposal bridge grounding_case_id")?;
        validate_id(
            &self.semantic_target_id,
            "proposal bridge semantic_target_id",
        )?;
        validate_id(
            &self.selected_element_id,
            "proposal bridge selected_element_id",
        )?;
        validate_id(&self.world_state_id, "proposal bridge world_state_id")?;
        validate_hash(&self.proposal_sha256, "proposal_sha256")?;
        validate_hash(&self.bridge_sha256, "bridge_sha256")?;
        self.capability_binding.validate()?;
        self.proposal.validate()?;

        if self.application_pack_sha256 != self.capability_binding.application_pack_sha256
            || self.semantic_target_id != self.capability_binding.semantic_target_id
        {
            return Err(ActionCandidateError::Integrity(
                "capability binding differs from proposal bridge metadata".to_owned(),
            ));
        }
        if self.proposal.capability_id != self.capability_binding.capability.capability_id
            || self.proposal.risk != self.capability_binding.capability.risk_class
            || self.proposal.confirmation_requirement
                != self.capability_binding.capability.confirmation_requirement
            || self.proposal.reversibility != Reversibility::Reversible
        {
            return Err(ActionCandidateError::Integrity(
                "proposal authority fields differ from the capability descriptor".to_owned(),
            ));
        }
        if self.proposal.semantic_target != self.semantic_target_id
            || self.proposal.valid_until_sequence != self.source_observation_sequence
        {
            return Err(ActionCandidateError::Integrity(
                "proposal semantic target or validity differs from bridge metadata".to_owned(),
            ));
        }

        let arguments: CandidateActionArguments =
            serde_json::from_value(self.proposal.arguments.clone())
                .map_err(|error| json_error("decode candidate arguments", error))?;
        arguments.validate()?;
        self.verify_arguments(&arguments)?;

        let expected_evidence = expected_evidence(
            &self.application_pack_sha256,
            &self.observation_bridge_sha256,
            &self.proposal.source_observation_hash,
            &self.semantic_target_id,
            &self.selected_element_id,
            &self.capability_binding,
            &self.world_state_id,
            &self.proposal.plan_generation_id,
        );
        if self.proposal.evidence != expected_evidence {
            return Err(ActionCandidateError::Integrity(
                "proposal evidence differs from its bound identities".to_owned(),
            ));
        }
        if hash_value(&self.proposal)? != self.proposal_sha256 {
            return Err(ActionCandidateError::Integrity(
                "proposal_sha256 does not match the canonical ActionProposal".to_owned(),
            ));
        }
        if self.compute_bridge_sha256()? != self.bridge_sha256 {
            return Err(ActionCandidateError::Integrity(
                "bridge_sha256 does not match the canonical proposal bridge".to_owned(),
            ));
        }
        Ok(())
    }

    /// Revalidates the artifact against its original trusted Core context.
    pub fn validate_context(
        &self,
        pack: &ApplicationPack,
        observation_bridge: &ObservationFixtureBridge,
        goal: &GoalSpec,
        world: &WorldState,
        plan: &PlanGraph,
    ) -> Result<(), ActionCandidateError> {
        self.validate()?;
        pack.validate()?;
        observation_bridge.validate()?;
        goal.validate()?;
        world.validate()?;
        plan.validate()?;
        validate_lifecycle(goal, world, plan, observation_bridge)?;

        if self.application_pack_sha256 != pack.pack_sha256
            || self.observation_bridge_sha256 != observation_bridge.bridge_sha256
            || self.observation_id != observation_bridge.observation_snapshot.observation_id
            || self.proposal.source_observation_hash
                != observation_bridge.observation_snapshot.state_hash
            || self.source_observation_sequence != observation_bridge.observation_snapshot.sequence
            || self.proposal.goal_id != goal.goal_id
            || self.world_state_id != world.world_state_id
            || self.proposal.plan_generation_id != plan.plan_generation_id
        {
            return Err(ActionCandidateError::Integrity(
                "proposal bridge differs from its trusted lifecycle context".to_owned(),
            ));
        }
        let target = unique_target(pack, &self.semantic_target_id)?;
        let case = unique_case(observation_bridge, &self.grounding_case_id)?;
        let element = unique_element(
            observation_bridge,
            &case.expected_element_id,
            "context selected element",
        )?;
        validate_target_and_element(
            target,
            case.element_grounder.semantic_target_id.as_str(),
            element.kind.as_str(),
            &self.capability_binding,
            observation_bridge.observation_snapshot.source_kind,
        )?;
        if case.expected_element_id != self.selected_element_id {
            return Err(ActionCandidateError::Integrity(
                "proposal bridge selected element differs from the grounding oracle".to_owned(),
            ));
        }
        validate_capability_admission(world, plan, &self.capability_binding)
    }

    fn verify_arguments(
        &self,
        arguments: &CandidateActionArguments,
    ) -> Result<(), ActionCandidateError> {
        let target = &arguments.target;
        if arguments.operation != self.capability_binding.capability.operation
            || arguments.input.kind() != self.capability_binding.action_kind
            || target.application_pack_sha256 != self.application_pack_sha256
            || target.observation_bridge_sha256 != self.observation_bridge_sha256
            || target.observation_id != self.observation_id
            || target.source_observation_hash != self.proposal.source_observation_hash
            || target.source_observation_sequence != self.source_observation_sequence
            || target.grounding_case_id != self.grounding_case_id
            || target.semantic_target_id != self.semantic_target_id
            || target.element_id != self.selected_element_id
            || target.capability_binding_sha256 != self.capability_binding.binding_sha256
            || !self
                .capability_binding
                .allowed_element_kinds
                .contains(&target.element_kind)
        {
            return Err(ActionCandidateError::Integrity(
                "proposal arguments differ from their bridge bindings".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Builds one deterministic, capability-bound `ActionProposal` fixture.
#[allow(clippy::too_many_arguments)]
pub fn bridge_fixture_action_candidate(
    pack: &ApplicationPack,
    observation_bridge: &ObservationFixtureBridge,
    capability_binding: &ActionCapabilityBinding,
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    request: &ActionCandidateBridgeRequest,
) -> Result<CapabilityBoundActionProposal, ActionCandidateError> {
    pack.validate()?;
    observation_bridge.validate()?;
    capability_binding.validate()?;
    goal.validate()?;
    world.validate()?;
    plan.validate()?;
    request.validate()?;
    validate_lifecycle(goal, world, plan, observation_bridge)?;

    if observation_bridge.application_pack_sha256 != pack.pack_sha256
        || request.application_pack_sha256 != pack.pack_sha256
        || capability_binding.application_pack_sha256 != pack.pack_sha256
    {
        return Err(ActionCandidateError::Integrity(
            "application pack hash differs across candidate inputs".to_owned(),
        ));
    }
    if request.observation_bridge_sha256 != observation_bridge.bridge_sha256
        || request.capability_binding_sha256 != capability_binding.binding_sha256
        || request.goal_id != goal.goal_id
        || request.world_state_id != world.world_state_id
        || request.plan_generation_id != plan.plan_generation_id
    {
        return Err(ActionCandidateError::Integrity(
            "candidate request differs from its lifecycle or sealed bindings".to_owned(),
        ));
    }
    if request.input.kind() != capability_binding.action_kind {
        return Err(ActionCandidateError::Integrity(
            "candidate input kind differs from the capability binding".to_owned(),
        ));
    }

    let target = unique_target(pack, &capability_binding.semantic_target_id)?;
    let case = unique_case(observation_bridge, &request.grounding_case_id)?;
    let element = unique_element(
        observation_bridge,
        &case.expected_element_id,
        "grounding oracle element",
    )?;
    validate_target_and_element(
        target,
        case.element_grounder.semantic_target_id.as_str(),
        element.kind.as_str(),
        capability_binding,
        observation_bridge.observation_snapshot.source_kind,
    )?;
    validate_capability_admission(world, plan, capability_binding)?;

    let arguments = CandidateActionArguments {
        schema_version: 1,
        operation: capability_binding.capability.operation.clone(),
        target: CandidateTargetBinding {
            application_pack_sha256: pack.pack_sha256.clone(),
            observation_bridge_sha256: observation_bridge.bridge_sha256.clone(),
            observation_id: observation_bridge
                .observation_snapshot
                .observation_id
                .clone(),
            source_observation_hash: observation_bridge.observation_snapshot.state_hash.clone(),
            source_observation_sequence: observation_bridge.observation_snapshot.sequence,
            grounding_case_id: request.grounding_case_id.clone(),
            semantic_target_id: target.target_id.clone(),
            element_id: element.element_id.clone(),
            element_kind: element.kind.clone(),
            capability_binding_sha256: capability_binding.binding_sha256.clone(),
        },
        input: request.input.clone(),
    };
    arguments.validate()?;
    let arguments_value = serde_json::to_value(&arguments)
        .map_err(|error| json_error("serialize candidate arguments", error))?;
    reject_raw_secret_value(&arguments_value, "candidate arguments")?;

    let proposal_id = proposal_id(
        goal,
        world,
        plan,
        observation_bridge,
        capability_binding,
        request,
        &arguments,
    )?;
    let evidence = expected_evidence(
        &pack.pack_sha256,
        &observation_bridge.bridge_sha256,
        &observation_bridge.observation_snapshot.state_hash,
        &target.target_id,
        &element.element_id,
        capability_binding,
        &world.world_state_id,
        &plan.plan_generation_id,
    );
    let proposal = ActionProposal {
        schema_version: 1,
        proposal_id,
        goal_id: goal.goal_id.clone(),
        plan_generation_id: plan.plan_generation_id.clone(),
        source_observation_hash: observation_bridge.observation_snapshot.state_hash.clone(),
        capability_id: capability_binding.capability.capability_id.clone(),
        semantic_target: target.target_id.clone(),
        arguments: arguments_value,
        preconditions: request.preconditions.clone(),
        expected_postconditions: request.expected_postconditions.clone(),
        risk: capability_binding.capability.risk_class,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: capability_binding.capability.confirmation_requirement,
        confidence: request.confidence,
        evidence,
        valid_until_sequence: observation_bridge.observation_snapshot.sequence,
    };
    proposal.validate()?;
    let proposal_sha256 = hash_value(&proposal)?;

    let mut result = CapabilityBoundActionProposal {
        schema_version: 1,
        application_pack_sha256: pack.pack_sha256.clone(),
        observation_bridge_sha256: observation_bridge.bridge_sha256.clone(),
        observation_id: observation_bridge
            .observation_snapshot
            .observation_id
            .clone(),
        source_observation_sequence: observation_bridge.observation_snapshot.sequence,
        grounding_case_id: request.grounding_case_id.clone(),
        semantic_target_id: target.target_id.clone(),
        selected_element_id: element.element_id.clone(),
        world_state_id: world.world_state_id.clone(),
        capability_binding: capability_binding.clone(),
        proposal,
        proposal_sha256,
        bridge_sha256: empty_sha256(),
    };
    result.bridge_sha256 = result.compute_bridge_sha256()?;
    result.validate_context(pack, observation_bridge, goal, world, plan)?;
    Ok(result)
}

fn validate_lifecycle(
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    observation_bridge: &ObservationFixtureBridge,
) -> Result<(), ActionCandidateError> {
    if world.goal_id != goal.goal_id
        || world.current_observation_hash != observation_bridge.observation_snapshot.state_hash
        || world.plan_generation_id != plan.plan_generation_id
    {
        return Err(ActionCandidateError::Integrity(
            "goal, world, observation, and plan lifecycle bindings differ".to_owned(),
        ));
    }
    reject_raw_secret_value(
        &serde_json::to_value(goal)
            .map_err(|error| json_error("serialize goal for secret check", error))?,
        "goal",
    )
}

fn validate_capability_admission(
    world: &WorldState,
    plan: &PlanGraph,
    binding: &ActionCapabilityBinding,
) -> Result<(), ActionCandidateError> {
    if !world
        .capabilities
        .contains(&binding.capability.capability_id)
    {
        return Err(ActionCandidateError::Unsupported(format!(
            "capability '{}' is absent from WorldState",
            binding.capability.capability_id
        )));
    }
    let mut nodes = plan
        .nodes
        .iter()
        .filter(|node| node.node_id == world.current_step);
    let node = nodes.next().ok_or_else(|| {
        ActionCandidateError::NotFound(format!(
            "current plan node '{}' is absent",
            world.current_step
        ))
    })?;
    if nodes.next().is_some() {
        return Err(ActionCandidateError::Ambiguous(format!(
            "current plan node '{}' is duplicated",
            world.current_step
        )));
    }
    if node.kind != PlanNodeKind::ProposeAction
        || node.capability_id.as_deref() != Some(binding.capability.capability_id.as_str())
    {
        return Err(ActionCandidateError::Integrity(
            "current plan node is not bound to the requested capability".to_owned(),
        ));
    }
    Ok(())
}

fn validate_target_and_element(
    target: &ApplicationSemanticTarget,
    grounded_target_id: &str,
    element_kind: &str,
    binding: &ActionCapabilityBinding,
    source_kind: ObservationSourceKind,
) -> Result<(), ActionCandidateError> {
    if grounded_target_id != target.target_id
        || binding.semantic_target_id != target.target_id
        || binding.source_kind != source_kind
        || !binding
            .allowed_element_kinds
            .iter()
            .any(|kind| kind == element_kind)
        || !target
            .expected_kinds
            .iter()
            .any(|kind| kind == element_kind)
    {
        return Err(ActionCandidateError::Integrity(
            "semantic target, grounded element, source, and capability binding differ".to_owned(),
        ));
    }
    for allowed_kind in &binding.allowed_element_kinds {
        if !target.expected_kinds.contains(allowed_kind) {
            return Err(ActionCandidateError::Integrity(
                "capability binding admits an element kind outside the semantic target".to_owned(),
            ));
        }
    }
    Ok(())
}

fn unique_target<'a>(
    pack: &'a ApplicationPack,
    target_id: &str,
) -> Result<&'a ApplicationSemanticTarget, ActionCandidateError> {
    let mut matches = pack
        .targets
        .iter()
        .filter(|target| target.target_id == target_id);
    let target = matches.next().ok_or_else(|| {
        ActionCandidateError::NotFound(format!("semantic target '{target_id}' is absent"))
    })?;
    if matches.next().is_some() {
        return Err(ActionCandidateError::Ambiguous(format!(
            "semantic target '{target_id}' is duplicated"
        )));
    }
    Ok(target)
}

fn unique_case<'a>(
    bridge: &'a ObservationFixtureBridge,
    case_id: &str,
) -> Result<&'a d2i_application_semantics::BridgedGroundingCase, ActionCandidateError> {
    let mut matches = bridge.cases.iter().filter(|case| case.case_id == case_id);
    let case = matches.next().ok_or_else(|| {
        ActionCandidateError::NotFound(format!("grounding case '{case_id}' is absent"))
    })?;
    if matches.next().is_some() {
        return Err(ActionCandidateError::Ambiguous(format!(
            "grounding case '{case_id}' is duplicated"
        )));
    }
    Ok(case)
}

fn unique_element<'a>(
    bridge: &'a ObservationFixtureBridge,
    element_id: &str,
    label: &str,
) -> Result<&'a d2i_cognitive_ir::ObservableElement, ActionCandidateError> {
    let mut matches = bridge
        .observation_snapshot
        .observable_elements
        .iter()
        .filter(|element| element.element_id == element_id);
    let element = matches.next().ok_or_else(|| {
        ActionCandidateError::NotFound(format!("{label} '{element_id}' is absent"))
    })?;
    if matches.next().is_some() {
        return Err(ActionCandidateError::Ambiguous(format!(
            "{label} '{element_id}' is duplicated"
        )));
    }
    Ok(element)
}

#[allow(clippy::too_many_arguments)]
fn expected_evidence(
    application_pack_sha256: &str,
    observation_bridge_sha256: &str,
    observation_hash: &str,
    semantic_target_id: &str,
    element_id: &str,
    capability_binding: &ActionCapabilityBinding,
    world_state_id: &str,
    plan_generation_id: &str,
) -> Vec<String> {
    vec![
        format!("application-pack:{application_pack_sha256}"),
        format!("observation-bridge:{observation_bridge_sha256}"),
        format!("observation:{observation_hash}"),
        format!("semantic-target:{semantic_target_id}"),
        format!("grounded-element:{element_id}"),
        format!("capability-binding:{}", capability_binding.binding_sha256),
        format!("capability:{}", capability_binding.capability.capability_id),
        format!("world-state:{world_state_id}"),
        format!("plan-generation:{plan_generation_id}"),
    ]
}

#[allow(clippy::too_many_arguments)]
fn proposal_id(
    goal: &GoalSpec,
    world: &WorldState,
    plan: &PlanGraph,
    observation_bridge: &ObservationFixtureBridge,
    capability_binding: &ActionCapabilityBinding,
    request: &ActionCandidateBridgeRequest,
    arguments: &CandidateActionArguments,
) -> Result<String, ActionCandidateError> {
    let material = serde_json::json!({
        "schema_version": 1,
        "goal_id": goal.goal_id,
        "world_state_id": world.world_state_id,
        "plan_generation_id": plan.plan_generation_id,
        "source_observation_hash": observation_bridge.observation_snapshot.state_hash,
        "grounding_case_id": request.grounding_case_id,
        "capability_binding_sha256": capability_binding.binding_sha256,
        "arguments": arguments,
        "preconditions": request.preconditions,
        "expected_postconditions": request.expected_postconditions,
        "confidence": request.confidence,
    });
    let digest = hash_value(&material)?;
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        ActionCandidateError::Json("canonical proposal digest lost its prefix".to_owned())
    })?;
    Ok(format!("acp1:{hex}"))
}

fn validate_conditions(
    conditions: &[Postcondition],
    field: &str,
    require_nonempty: bool,
) -> Result<(), ActionCandidateError> {
    if conditions.len() > MAX_CONDITIONS || (require_nonempty && conditions.is_empty()) {
        return invalid(format!(
            "{field} must contain {} to {MAX_CONDITIONS} entries",
            usize::from(require_nonempty)
        ));
    }
    let mut identities = Vec::with_capacity(conditions.len());
    for condition in conditions {
        validate_id(&condition.target_state, field)?;
        if condition.timeout_ms == 0 || condition.timeout_ms > 60_000 {
            return invalid(format!("{field} timeout_ms must be 1..=60000"));
        }
        let identity = (
            condition.target_state.as_str(),
            condition.op,
            condition.required,
        );
        if identities.contains(&identity) {
            return invalid(format!("{field} contains a duplicate condition"));
        }
        identities.push(identity);
        reject_raw_secret_value(&condition.expected_value, field)?;
    }
    Ok(())
}

fn validate_sorted_ids(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), ActionCandidateError> {
    if values.is_empty() || values.len() > maximum {
        return invalid(format!(
            "{field} must contain between 1 and {maximum} entries"
        ));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_id(value, field)?;
        if previous.is_some_and(|prior| prior >= value.as_str()) {
            return invalid(format!("{field} must be strictly sorted and unique"));
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_id(value: &str, field: &str) -> Result<(), ActionCandidateError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return invalid(format!("{field} is not a bounded stable identifier"));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), ActionCandidateError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(format!("{field} must use sha256:<lowercase hex>"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} has invalid SHA-256 syntax"));
    }
    Ok(())
}

fn reject_raw_secret_value(value: &Value, field: &str) -> Result<(), ActionCandidateError> {
    match value {
        Value::String(text) => {
            if raw_secret_marker(text) {
                return Err(ActionCandidateError::Integrity(format!(
                    "{field} contains raw secret-like material"
                )));
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_raw_secret_value(item, field)?;
            }
        }
        Value::Object(object) => {
            for (key, item) in object {
                if raw_secret_marker(key) {
                    return Err(ActionCandidateError::Integrity(format!(
                        "{field} contains a raw secret-like field name"
                    )));
                }
                reject_raw_secret_value(item, field)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn raw_secret_marker(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "password=",
        "password:",
        "token=",
        "token:",
        "api_key=",
        "api-key=",
        "authorization:",
        "bearer ",
        "cookie:",
        "secret=",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn hash_value<T: Serialize>(value: &T) -> Result<String, ActionCandidateError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ActionCandidateError> {
    let value = serde_json::to_value(value)
        .map_err(|error| json_error("convert canonical value", error))?;
    let canonical = canonicalize_value(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| json_error("serialize canonical value", error))?;
    if bytes.len() > MAX_JSON_BYTES {
        return invalid("canonical action candidate artifact exceeds 2 MiB");
    }
    Ok(bytes)
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
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn empty_sha256() -> String {
    sha256_bytes(&[])
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ActionCandidateError> {
    Err(ActionCandidateError::Invalid(message.into()))
}

fn json_error(context: &str, error: serde_json::Error) -> ActionCandidateError {
    ActionCandidateError::Json(format!("{context}: {error}"))
}
