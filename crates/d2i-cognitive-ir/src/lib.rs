//! Pure Cognitive IR v1 data contracts, validation, and canonical hashing.
//!
//! This crate intentionally contains no executor, adapter, policy, audit, I/O,
//! activation, or platform implementation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Cognitive IR v1 schema version.
pub const COGNITIVE_SCHEMA_VERSION: u32 = 1;
/// Authoritative Cognitive IR v1 JSON Schema.
pub const COGNITIVE_IR_V1_SCHEMA: &str =
    include_str!("../../../schemas/cognitive/cognitive-ir-v1.schema.json");
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLAN_LOOP_ITERATIONS: u32 = 1_000;

/// Source and build trace attached to Cognitive IR records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source: String,
    pub source_hash: String,
    pub module_id: String,
}

impl Provenance {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_text(&self.source, "provenance source")?;
        validate_hash(&self.source_hash, "provenance source_hash")?;
        validate_token(&self.module_id, "provenance module_id")
    }
}

/// Risk class for cognitive planning. Irreversible work is unsupported here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRiskClass {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    HighCriticality,
}

/// Goal-level confirmation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationPolicy {
    Never,
    BeforeRiskyAction,
    BeforeIrreversibleAction,
    Always,
}

/// Action-level confirmation requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationRequirement {
    None,
    Required,
    UnsupportedIrreversible,
}

/// Whether an action can be rolled back by the capability contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    Reversible,
    Irreversible,
}

/// Top-level task goal normalized before planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalSpec {
    pub schema_version: u32,
    pub goal_id: String,
    pub objective: String,
    pub scope: BTreeMap<String, Value>,
    pub required_outcomes: Vec<String>,
    pub constraints: Vec<String>,
    pub success_criteria: Vec<Postcondition>,
    pub risk_class: CognitiveRiskClass,
    pub confirmation_policy: ConfirmationPolicy,
    pub provenance: Provenance,
}

impl GoalSpec {
    /// Validates version, bounded text, and success criteria.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "goal")?;
        validate_token(&self.goal_id, "goal_id")?;
        validate_text(&self.objective, "objective")?;
        validate_text_vec(&self.required_outcomes, "required_outcomes", 64)?;
        validate_text_vec(&self.constraints, "constraints", 128)?;
        if self.success_criteria.is_empty() {
            return Err(CognitiveIrError::Invalid(
                "goal requires at least one success criterion".to_owned(),
            ));
        }
        for criterion in &self.success_criteria {
            criterion.validate()?;
        }
        self.provenance.validate()
    }
}

/// Label describing whether observation content can be trusted as instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabel {
    AuthenticatedUserInstruction,
    ApprovedPolicy,
    ApprovedProcedure,
    VerifiedOperationalState,
    ObservedUiState,
    UntrustedWebContent,
    UntrustedDocumentContent,
    Fixture,
}

/// Deterministic observation source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSourceKind {
    Fixture,
    Uia,
    WebDriver,
    FileMetadata,
    Process,
}

/// One bounded state element visible to the cognitive plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableElement {
    pub element_id: String,
    pub kind: String,
    pub label: String,
    pub value: Value,
    pub trust_labels: BTreeSet<TrustLabel>,
}

impl ObservableElement {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.element_id, "observable element_id")?;
        validate_token(&self.kind, "observable kind")?;
        validate_text(&self.label, "observable label")?;
        if self.trust_labels.is_empty() {
            return Err(CognitiveIrError::Invalid(
                "observable element requires at least one trust label".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Redaction marker proving sensitive content was not retained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionMetadata {
    pub field: String,
    pub reason: String,
    pub replacement_hash: String,
}

impl RedactionMetadata {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.field, "redaction field")?;
        validate_text(&self.reason, "redaction reason")?;
        validate_hash(&self.replacement_hash, "redaction replacement_hash")
    }
}

/// Read-only snapshot. Baseline snapshots are generated by fixtures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    pub schema_version: u32,
    pub observation_id: String,
    pub source_kind: ObservationSourceKind,
    pub target_binding: BTreeMap<String, String>,
    pub state_hash: String,
    pub sequence: u64,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub observable_elements: Vec<ObservableElement>,
    pub redactions: Vec<RedactionMetadata>,
    pub provenance: Provenance,
}

impl ObservationSnapshot {
    /// Validates bounds and verifies the declared stable state hash.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "observation")?;
        validate_token(&self.observation_id, "observation_id")?;
        for (key, value) in &self.target_binding {
            validate_token(key, "target binding key")?;
            validate_text(value, "target binding value")?;
        }
        if self.trust_labels.is_empty() {
            return Err(CognitiveIrError::Invalid(
                "observation requires at least one trust label".to_owned(),
            ));
        }
        if self.observable_elements.len() > 10_000 {
            return Err(CognitiveIrError::Invalid(
                "observable element count exceeds 10000".to_owned(),
            ));
        }
        for element in &self.observable_elements {
            element.validate()?;
        }
        for redaction in &self.redactions {
            redaction.validate()?;
        }
        let expected = self.compute_state_hash()?;
        if self.state_hash != expected {
            return Err(CognitiveIrError::Integrity(
                "observation state_hash does not match observable state".to_owned(),
            ));
        }
        self.provenance.validate()
    }

    /// Computes a stable hash that ignores snapshot identity and sequence.
    pub fn compute_state_hash(&self) -> Result<String, CognitiveIrError> {
        let canonical = serde_json::json!({
            "source_kind": self.source_kind,
            "target_binding": self.target_binding,
            "trust_labels": self.trust_labels,
            "observable_elements": self.observable_elements,
            "redactions": self.redactions,
        });
        hash_value(&canonical)
    }
}

/// Source type for a normalized world-state fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldFactKind {
    ObservedFact,
    InferredState,
    UserAssertion,
    PolicyFact,
    UntrustedContent,
}

/// One fact relevant to the current goal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFact {
    pub fact_id: String,
    pub kind: WorldFactKind,
    pub subject: String,
    pub predicate: String,
    pub object: Value,
    pub evidence: Vec<String>,
}

impl WorldFact {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.fact_id, "world fact_id")?;
        validate_text(&self.subject, "world fact subject")?;
        validate_text(&self.predicate, "world fact predicate")?;
        validate_text_vec(&self.evidence, "world fact evidence", 64)
    }
}

/// Goal-scoped normalized state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldState {
    pub schema_version: u32,
    pub world_state_id: String,
    pub goal_id: String,
    pub normalized_facts: Vec<WorldFact>,
    pub known_state: BTreeMap<String, Value>,
    pub uncertain_state: BTreeMap<String, Value>,
    pub conflicts: Vec<String>,
    pub capabilities: BTreeSet<String>,
    pub current_step: String,
    pub current_observation_hash: String,
    pub plan_generation_id: String,
    pub provenance: Provenance,
}

impl WorldState {
    /// Validates world state and its observation hash binding.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "world_state")?;
        validate_token(&self.world_state_id, "world_state_id")?;
        validate_token(&self.goal_id, "world_state goal_id")?;
        for fact in &self.normalized_facts {
            fact.validate()?;
        }
        validate_text_vec(&self.conflicts, "world_state conflicts", 128)?;
        for capability in &self.capabilities {
            validate_token(capability, "world_state capability")?;
        }
        validate_token(&self.current_step, "world_state current_step")?;
        validate_hash(
            &self.current_observation_hash,
            "world_state current_observation_hash",
        )?;
        validate_token(&self.plan_generation_id, "world_state plan_generation_id")?;
        self.provenance.validate()
    }
}

/// Cognitive plan node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNodeKind {
    Observe,
    Interpret,
    SelectCapability,
    ProposeAction,
    PolicyGate,
    ActivationGate,
    Execute,
    Verify,
    Branch,
    LoopBounded,
    Recover,
    HumanReview,
    Return,
}

/// Typed plan node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanNode {
    pub node_id: String,
    pub kind: PlanNodeKind,
    pub capability_id: Option<String>,
    pub loop_bound: Option<u32>,
}

impl PlanNode {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.node_id, "plan node_id")?;
        if let Some(capability) = &self.capability_id {
            validate_token(capability, "plan node capability_id")?;
        }
        match (self.kind, self.loop_bound) {
            (PlanNodeKind::LoopBounded, Some(bound))
                if bound > 0 && bound <= MAX_PLAN_LOOP_ITERATIONS =>
            {
                Ok(())
            }
            (PlanNodeKind::LoopBounded, _) => Err(CognitiveIrError::Invalid(format!(
                "loop_bounded node '{}' must declare loop_bound 1..={MAX_PLAN_LOOP_ITERATIONS}",
                self.node_id
            ))),
            (_, Some(_)) => Err(CognitiveIrError::Invalid(format!(
                "non-loop node '{}' cannot declare loop_bound",
                self.node_id
            ))),
            _ => Ok(()),
        }
    }
}

/// Typed plan edge kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanEdgeKind {
    Sequence,
    BranchTrue,
    BranchFalse,
    Recovery,
    HumanReview,
}

/// Directed plan edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEdge {
    pub from: String,
    pub to: String,
    pub kind: PlanEdgeKind,
    pub condition: Option<String>,
}

/// Versioned cognitive plan graph. Loops are represented by bounded nodes, not cycles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanGraph {
    pub schema_version: u32,
    pub plan_generation_id: String,
    pub entry_node: String,
    pub nodes: Vec<PlanNode>,
    pub edges: Vec<PlanEdge>,
}

impl PlanGraph {
    /// Validates unique nodes, bounded loops, references, and DAG shape.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "plan_graph")?;
        validate_token(&self.plan_generation_id, "plan_generation_id")?;
        validate_token(&self.entry_node, "plan entry_node")?;
        let mut nodes = BTreeSet::new();
        for node in &self.nodes {
            node.validate()?;
            if !nodes.insert(node.node_id.as_str()) {
                return Err(CognitiveIrError::Invalid(format!(
                    "duplicate plan node '{}'",
                    node.node_id
                )));
            }
        }
        if !nodes.contains(self.entry_node.as_str()) {
            return Err(CognitiveIrError::Invalid(
                "plan entry_node is not declared".to_owned(),
            ));
        }
        let mut indegree = nodes
            .iter()
            .map(|id| (*id, 0_usize))
            .collect::<BTreeMap<_, _>>();
        let mut adjacency = BTreeMap::<&str, Vec<&str>>::new();
        for edge in &self.edges {
            validate_token(&edge.from, "plan edge from")?;
            validate_token(&edge.to, "plan edge to")?;
            if !nodes.contains(edge.from.as_str()) || !nodes.contains(edge.to.as_str()) {
                return Err(CognitiveIrError::Invalid(
                    "plan edge references a missing node".to_owned(),
                ));
            }
            adjacency
                .entry(edge.from.as_str())
                .or_default()
                .push(edge.to.as_str());
            if let Some(value) = indegree.get_mut(edge.to.as_str()) {
                *value = value.saturating_add(1);
            }
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
            .collect::<VecDeque<_>>();
        let mut visited = 0_usize;
        while let Some(node) = ready.pop_front() {
            visited = visited.saturating_add(1);
            if let Some(targets) = adjacency.get(node) {
                for target in targets {
                    if let Some(degree) = indegree.get_mut(target) {
                        *degree = degree.saturating_sub(1);
                        if *degree == 0 {
                            ready.push_back(target);
                        }
                    }
                }
            }
        }
        if visited != nodes.len() {
            return Err(CognitiveIrError::Invalid(
                "plan graph contains a cycle".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Capability exposed to the cognitive planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDescriptor {
    pub capability_id: String,
    pub operation: String,
    pub risk_class: CognitiveRiskClass,
    pub reversible: bool,
    pub confirmation_requirement: ConfirmationRequirement,
    pub retry_limit: u32,
}

impl CapabilityDescriptor {
    /// Validates the capability identifier, operation, and retry bound.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.capability_id, "capability_id")?;
        validate_token(&self.operation, "capability operation")?;
        if self.retry_limit > 100 {
            return Err(CognitiveIrError::Invalid(
                "capability retry_limit exceeds 100".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Comparison operator used by postcondition checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOp {
    Equals,
    NotEquals,
    Contains,
    Exists,
    GreaterOrEqual,
    LessOrEqual,
}

/// Expected target state after execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Postcondition {
    pub target_state: String,
    pub op: ComparisonOp,
    pub expected_value: Value,
    pub required: bool,
    pub timeout_ms: u64,
}

impl Postcondition {
    fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_token(&self.target_state, "postcondition target_state")?;
        if self.timeout_ms == 0 || self.timeout_ms > 60_000 {
            return Err(CognitiveIrError::Invalid(
                "postcondition timeout_ms must be 1..=60000".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One action proposed from a specific observation and plan generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProposal {
    pub schema_version: u32,
    pub proposal_id: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_hash: String,
    pub capability_id: String,
    pub semantic_target: String,
    pub arguments: Value,
    pub preconditions: Vec<Postcondition>,
    pub expected_postconditions: Vec<Postcondition>,
    pub risk: CognitiveRiskClass,
    pub reversibility: Reversibility,
    pub confirmation_requirement: ConfirmationRequirement,
    pub confidence: f64,
    pub evidence: Vec<String>,
    pub valid_until_sequence: u64,
}

impl ActionProposal {
    /// Validates proposal bounds and fail-closed baseline constraints.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "action_proposal")?;
        validate_token(&self.proposal_id, "proposal_id")?;
        validate_token(&self.goal_id, "proposal goal_id")?;
        validate_token(&self.plan_generation_id, "proposal plan_generation_id")?;
        validate_hash(
            &self.source_observation_hash,
            "proposal source_observation_hash",
        )?;
        validate_token(&self.capability_id, "proposal capability_id")?;
        validate_text(&self.semantic_target, "proposal semantic_target")?;
        for precondition in &self.preconditions {
            precondition.validate()?;
        }
        if self.expected_postconditions.is_empty() {
            return Err(CognitiveIrError::Invalid(
                "action proposal requires at least one expected postcondition".to_owned(),
            ));
        }
        for postcondition in &self.expected_postconditions {
            postcondition.validate()?;
        }
        if self.reversibility == Reversibility::Irreversible {
            return Err(CognitiveIrError::AccessDenied(
                "irreversible actions are unsupported by the cognitive baseline".to_owned(),
            ));
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err(CognitiveIrError::Invalid(
                "proposal confidence must be within 0.0..=1.0".to_owned(),
            ));
        }
        validate_text_vec(&self.evidence, "proposal evidence", 256)
    }
}

/// Status returned by an action executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Denied,
    Unsupported,
    Timeout,
}

/// Mockable execution result. The baseline carries no payload bytes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionExecution {
    pub status: ExecutionStatus,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
}

/// Progress toward the goal after verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalProgress {
    NotStarted,
    InProgress,
    Complete,
    Blocked,
}

/// Per-postcondition outcome.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostconditionResult {
    pub target_state: String,
    pub passed: bool,
    pub required: bool,
    pub observed_value: Option<Value>,
    pub reason: String,
}

/// Verification result for one executed action and fresh observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationResult {
    pub schema_version: u32,
    pub execution_status: ExecutionStatus,
    pub postcondition_results: Vec<PostconditionResult>,
    pub observed_state_hash: String,
    pub goal_progress: GoalProgress,
    pub warnings: Vec<String>,
    pub evidence: Vec<String>,
    pub reason: String,
}

impl VerificationResult {
    /// Validates version and observation binding.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "verification_result")?;
        validate_hash(
            &self.observed_state_hash,
            "verification observed_state_hash",
        )?;
        validate_text_vec(&self.warnings, "verification warnings", 128)?;
        validate_text_vec(&self.evidence, "verification evidence", 256)?;
        validate_text(&self.reason, "verification reason")?;
        Ok(())
    }

    /// Returns true when execution and every required postcondition succeeded.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.execution_status == ExecutionStatus::Succeeded
            && self
                .postcondition_results
                .iter()
                .all(|result| !result.required || result.passed)
    }
}

/// Recovery action chosen after a failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRecoveryKind {
    Retry,
    Reobserve,
    Replan,
    Fallback,
    RequestUserInput,
    Stop,
}

/// Bounded recovery decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecision {
    pub schema_version: u32,
    pub kind: CognitiveRecoveryKind,
    pub reason: String,
    pub remaining_retry_budget: u32,
    pub evidence: Vec<String>,
    pub replacement_plan_generation_id: Option<String>,
}

impl RecoveryDecision {
    /// Validates recovery metadata.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "recovery_decision")?;
        validate_text(&self.reason, "recovery reason")?;
        validate_text_vec(&self.evidence, "recovery evidence", 128)?;
        if let Some(id) = &self.replacement_plan_generation_id {
            validate_token(id, "replacement_plan_generation_id")?;
        }
        Ok(())
    }
}

/// Deterministic logical timing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveTiming {
    pub step: String,
    pub logical_tick: u64,
}

/// User-facing structured work report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkReport {
    pub schema_version: u32,
    pub confirmed_facts: Vec<String>,
    pub completed_actions: Vec<String>,
    pub incomplete_items: Vec<String>,
    pub opinions: Vec<String>,
    pub opinion_basis: Vec<String>,
    pub uncertainties: Vec<String>,
    pub user_decision_required: bool,
    pub build_id: String,
    pub module_ids: Vec<String>,
    pub timings: Vec<CognitiveTiming>,
    pub warnings: Vec<String>,
}

impl WorkReport {
    /// Validates report shape.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        validate_version(self.schema_version, "work_report")?;
        validate_text_vec(&self.confirmed_facts, "report confirmed_facts", 512)?;
        validate_text_vec(&self.completed_actions, "report completed_actions", 512)?;
        validate_text_vec(&self.incomplete_items, "report incomplete_items", 512)?;
        validate_text_vec(&self.opinions, "report opinions", 128)?;
        validate_text_vec(&self.opinion_basis, "report opinion_basis", 256)?;
        validate_text_vec(&self.uncertainties, "report uncertainties", 256)?;
        validate_token(&self.build_id, "report build_id")?;
        validate_text_vec(&self.module_ids, "report module_ids", 128)?;
        validate_text_vec(&self.warnings, "report warnings", 256)
    }

    /// Computes a stable report hash for deterministic replay tests.
    pub fn report_hash(&self) -> Result<String, CognitiveIrError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Bundle used by schema and round-trip tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveIrBundle {
    pub goal_spec: GoalSpec,
    pub observation_snapshot: ObservationSnapshot,
    pub world_state: WorldState,
    pub plan_graph: PlanGraph,
    pub action_proposal: ActionProposal,
    pub verification_result: VerificationResult,
    pub recovery_decision: RecoveryDecision,
    pub work_report: WorkReport,
}

impl CognitiveIrBundle {
    /// Validates all Cognitive IR v1 members.
    pub fn validate(&self) -> Result<(), CognitiveIrError> {
        self.goal_spec.validate()?;
        self.observation_snapshot.validate()?;
        self.world_state.validate()?;
        self.plan_graph.validate()?;
        self.action_proposal.validate()?;
        self.verification_result.validate()?;
        self.recovery_decision.validate()?;
        self.work_report.validate()
    }
}
/// Pure Cognitive IR contract failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CognitiveIrError {
    /// A field, bound, graph, or schema version is invalid.
    Invalid(String),
    /// A declared digest does not match canonical content.
    Integrity(String),
    /// A contract requests an unsupported or forbidden action.
    AccessDenied(String),
    /// Canonical JSON serialization failed.
    Json(String),
}

impl Display for CognitiveIrError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid desktop artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity failure: {message}"),
            Self::AccessDenied(message) => write!(formatter, "access denied: {message}"),
            Self::Json(message) => write!(formatter, "JSON failure: {message}"),
        }
    }
}

impl Error for CognitiveIrError {}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CognitiveIrError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| CognitiveIrError::Json(error.to_string()))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(CognitiveIrError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn hash_value<T: Serialize>(value: &T) -> Result<String, CognitiveIrError> {
    Ok(format!("sha256:{:x}", Sha256::digest(json_bytes(value)?)))
}

fn validate_text(value: &str, field: &str) -> Result<(), CognitiveIrError> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(CognitiveIrError::Invalid(format!(
            "{field} is empty, contains NUL, or exceeds bounds"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<(), CognitiveIrError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(CognitiveIrError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), CognitiveIrError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CognitiveIrError::Invalid(format!(
            "{field} must use sha256:<hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CognitiveIrError::Invalid(format!(
            "{field} has invalid SHA-256 syntax"
        )));
    }
    Ok(())
}

fn validate_version(version: u32, label: &str) -> Result<(), CognitiveIrError> {
    if version != COGNITIVE_SCHEMA_VERSION {
        return Err(CognitiveIrError::Invalid(format!(
            "{label} schema_version must be {COGNITIVE_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn validate_text_vec(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), CognitiveIrError> {
    if values.len() > maximum {
        return Err(CognitiveIrError::Invalid(format!(
            "{field} exceeds {maximum} entries"
        )));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}
