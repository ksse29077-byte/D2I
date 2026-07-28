use crate::{
    Diagnostic, DomainId, ExecutorId, NodeId, ProvenanceId, Severity, SkillId, SourceLocation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_LOOP_ITERATIONS: u32 = 10_000;

/// Stable link from an IR element to one source location and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub id: ProvenanceId,
    pub source_path: String,
    pub line: Option<u32>,
    pub field: Option<String>,
    pub content_hash: String,
}

/// Typed entity instance lowered from a structured source record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub entity_type: String,
    pub attributes: BTreeMap<String, String>,
    pub provenance_id: ProvenanceId,
}

/// Typed relation between two entity identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relation {
    pub id: String,
    pub relation_type: String,
    pub source: String,
    pub target: String,
    pub provenance_id: ProvenanceId,
}

/// Canonical terminology entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Term {
    pub id: String,
    pub canonical: String,
    pub aliases: Vec<String>,
    pub provenance_id: ProvenanceId,
}

/// Subject-predicate-object fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact {
    pub id: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    pub provenance_id: ProvenanceId,
}

/// Text document retained as a source-addressed semantic record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub path: String,
    pub title: Option<String>,
    pub provenance_id: ProvenanceId,
}

/// Typed procedure and its ordered source steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Procedure {
    pub id: String,
    pub version: String,
    pub steps: Vec<ProcedureStep>,
    pub provenance_id: ProvenanceId,
}

/// One procedure step before it is lowered into an execution node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcedureStep {
    pub id: String,
    pub kind: String,
    pub next: Option<String>,
    pub failure: Option<String>,
    pub max_iterations: Option<u32>,
    pub provenance_id: ProvenanceId,
}

/// Typed rule with canonical condition and action values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub condition: Value,
    pub action: Value,
    pub exception: bool,
    pub provenance_id: ProvenanceId,
}

/// Positive or negative source example.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Example {
    pub id: String,
    pub skill_id: SkillId,
    pub positive: bool,
    pub request: Value,
    pub provenance_id: ProvenanceId,
}

/// Expected outcome derived from evaluation data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    pub id: String,
    pub expected: Value,
    pub provenance_id: ProvenanceId,
}

/// Typed semantic IR for one domain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainIr {
    pub domain_id: DomainId,
    pub version: String,
    pub name: String,
    pub languages: Vec<String>,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub terms: Vec<Term>,
    pub facts: Vec<Fact>,
    pub documents: Vec<Document>,
    pub procedures: Vec<Procedure>,
    pub rules: Vec<Rule>,
    pub examples: Vec<Example>,
    pub outcomes: Vec<Outcome>,
}

/// Business criticality used by skill, policy, and evaluation gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

/// Typed skill contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillIr {
    pub id: SkillId,
    pub version: String,
    pub input_schema: String,
    pub output_schema: String,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
    pub criticality: Criticality,
    pub fallback: Option<String>,
    pub evidence_required: bool,
    pub evaluation_dataset: String,
    pub evaluation_thresholds: String,
    pub candidate_executors: Vec<ExecutorId>,
    pub provenance_id: ProvenanceId,
}

/// Complete execution node kind set required by the Phase 2 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    ReadInput,
    Normalize,
    Lookup,
    Retrieve,
    RuleEval,
    NativeCall,
    ModelCall,
    Parallel,
    Join,
    Branch,
    LoopBounded,
    Validate,
    PolicyGate,
    HumanReview,
    Return,
}

/// Retry policy attached to each execution node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub limit: u32,
}

/// Cache policy attached to each execution node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePolicy {
    pub cacheable: bool,
}

/// Typed execution node with resource, failure, and evidence contracts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionNode {
    pub id: NodeId,
    pub kind: NodeKind,
    pub input_type: String,
    pub output_type: String,
    pub timeout_ms: u32,
    pub expected_memory_bytes: u64,
    pub executor_id: Option<ExecutorId>,
    pub min_confidence: f64,
    pub failure_target: Option<NodeId>,
    pub retry: RetryPolicy,
    pub cache: CachePolicy,
    pub side_effect: bool,
    pub parallel_group: Option<String>,
    pub evidence_required: bool,
    pub loop_max_iterations: Option<u32>,
    pub provenance_id: ProvenanceId,
}

/// Typed directed edge kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Success,
    Failure,
    BranchTrue,
    BranchFalse,
    Parallel,
    Join,
}

/// Directed execution graph edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
    pub condition: Option<String>,
    pub provenance_id: ProvenanceId,
}

/// Acyclic execution graph for one skill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionGraph {
    pub skill_id: SkillId,
    pub entry_node: NodeId,
    pub nodes: Vec<ExecutionNode>,
    pub edges: Vec<ExecutionEdge>,
}

impl ExecutionGraph {
    /// Validates identifiers, bounded loops, references, and acyclicity.
    #[must_use]
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        let mut nodes = BTreeMap::new();
        for node in &self.nodes {
            if nodes.insert(node.id.as_str(), node).is_some() {
                diagnostics.push(graph_error(
                    "D2I2100",
                    format!("duplicate execution node '{}'", node.id),
                    "give every execution node a unique id",
                ));
            }
            match (node.kind, node.loop_max_iterations) {
                (NodeKind::LoopBounded, Some(limit))
                    if limit > 0 && limit <= MAX_LOOP_ITERATIONS => {}
                (NodeKind::LoopBounded, _) => diagnostics.push(graph_error(
                    "D2I2101",
                    format!("bounded loop '{}' has an invalid iteration limit", node.id),
                    format!("set loop_max_iterations to 1..={MAX_LOOP_ITERATIONS}"),
                )),
                (_, Some(_)) => diagnostics.push(graph_error(
                    "D2I2102",
                    format!("non-loop node '{}' declares an iteration limit", node.id),
                    "remove loop_max_iterations or use loop_bounded",
                )),
                _ => {}
            }
            if matches!(node.kind, NodeKind::Parallel | NodeKind::Join)
                && node.parallel_group.as_deref().is_none_or(str::is_empty)
            {
                diagnostics.push(graph_error(
                    "D2I2103",
                    format!("parallel node '{}' requires a parallel_group", node.id),
                    "assign a stable parallel group id",
                ));
            }
        }

        if !nodes.contains_key(self.entry_node.as_str()) {
            diagnostics.push(graph_error(
                "D2I2104",
                format!("entry node '{}' does not exist", self.entry_node),
                "set entry_node to a declared node id",
            ));
        }

        let mut indegree = nodes
            .keys()
            .map(|id| (*id, 0_usize))
            .collect::<BTreeMap<_, _>>();
        let mut adjacency = BTreeMap::<&str, Vec<&str>>::new();
        for edge in &self.edges {
            let from = edge.from.as_str();
            let to = edge.to.as_str();
            if !nodes.contains_key(from) || !nodes.contains_key(to) {
                diagnostics.push(graph_error(
                    "D2I2105",
                    format!("edge '{from}' -> '{to}' references a missing node"),
                    "reference only declared execution nodes",
                ));
                continue;
            }
            adjacency.entry(from).or_default().push(to);
            if let Some(value) = indegree.get_mut(to) {
                *value += 1;
            }
        }
        for node in &self.nodes {
            if let Some(target) = &node.failure_target {
                if !nodes.contains_key(target.as_str()) {
                    diagnostics.push(graph_error(
                        "D2I2106",
                        format!(
                            "failure target '{}' from '{}' does not exist",
                            target, node.id
                        ),
                        "set failure_target to a declared node",
                    ));
                }
            }
        }

        let mut ready = indegree
            .iter()
            .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
            .collect::<VecDeque<_>>();
        let mut visited = 0_usize;
        while let Some(node) = ready.pop_front() {
            visited += 1;
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
            diagnostics.push(graph_error(
                "D2I2107",
                "execution graph contains a cycle",
                "represent repeated work with one loop_bounded node instead of a back edge",
            ));
        }

        diagnostics
    }
}

/// Execution graphs for every compiled skill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExecutionIr {
    pub graphs: Vec<ExecutionGraph>,
}

/// Data access label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessLabel {
    pub resource: String,
    pub label: String,
    pub provenance_id: ProvenanceId,
}

/// Minimum confidence and fallback policy for one skill.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceThreshold {
    pub skill_id: SkillId,
    pub minimum: f64,
    pub fallback: String,
    pub provenance_id: ProvenanceId,
}

/// Permission for an action or side effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPermission {
    pub action: String,
    pub allowed: bool,
    pub requires_human_review: bool,
    pub provenance_id: ProvenanceId,
}

/// Typed policy bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyIr {
    pub default_action: String,
    pub network_allowed: bool,
    pub access_labels: Vec<AccessLabel>,
    pub confidence_thresholds: Vec<ConfidenceThreshold>,
    pub action_permissions: Vec<ActionPermission>,
    pub allowed_executors: Vec<ExecutorId>,
}

/// One evaluation case.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationCase {
    pub id: String,
    pub skill_id: SkillId,
    pub request: Value,
    pub expected: Value,
    pub provenance_id: ProvenanceId,
}

/// Metric threshold contract.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSpec {
    pub id: String,
    pub threshold: f64,
    pub higher_is_better: bool,
    pub provenance_id: ProvenanceId,
}

/// Condition that marks an evaluation result as critically unsafe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticalErrorCondition {
    pub id: String,
    pub expression: String,
    pub maximum_rate: f64,
    pub provenance_id: ProvenanceId,
}

/// Typed evaluation bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvaluationIr {
    pub cases: Vec<EvaluationCase>,
    pub metrics: Vec<MetricSpec>,
    pub critical_errors: Vec<CriticalErrorCondition>,
}

/// Complete typed Phase 2 compiler IR.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledIr {
    pub domain: DomainIr,
    pub skills: Vec<SkillIr>,
    pub execution: ExecutionIr,
    pub policy: PolicyIr,
    pub evaluation: EvaluationIr,
    pub provenance: Vec<EvidenceRef>,
}

impl CompiledIr {
    /// Validates every execution graph and all provenance references.
    #[must_use]
    pub fn validate(&self) -> Vec<Diagnostic> {
        let mut diagnostics = self
            .execution
            .graphs
            .iter()
            .flat_map(ExecutionGraph::validate)
            .collect::<Vec<_>>();
        let provenance = self
            .provenance
            .iter()
            .map(|item| item.id.as_str())
            .collect::<BTreeSet<_>>();
        let mut referenced = Vec::new();
        referenced.extend(self.domain.entities.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.relations.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.terms.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.facts.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.documents.iter().map(|item| &item.provenance_id));
        referenced.extend(
            self.domain
                .procedures
                .iter()
                .map(|item| &item.provenance_id),
        );
        referenced.extend(self.domain.rules.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.examples.iter().map(|item| &item.provenance_id));
        referenced.extend(self.domain.outcomes.iter().map(|item| &item.provenance_id));
        referenced.extend(self.skills.iter().map(|item| &item.provenance_id));
        for graph in &self.execution.graphs {
            referenced.extend(graph.nodes.iter().map(|item| &item.provenance_id));
            referenced.extend(graph.edges.iter().map(|item| &item.provenance_id));
        }
        referenced.extend(
            self.policy
                .access_labels
                .iter()
                .map(|item| &item.provenance_id),
        );
        referenced.extend(
            self.policy
                .confidence_thresholds
                .iter()
                .map(|item| &item.provenance_id),
        );
        referenced.extend(
            self.policy
                .action_permissions
                .iter()
                .map(|item| &item.provenance_id),
        );
        referenced.extend(self.evaluation.cases.iter().map(|item| &item.provenance_id));
        referenced.extend(
            self.evaluation
                .metrics
                .iter()
                .map(|item| &item.provenance_id),
        );
        referenced.extend(
            self.evaluation
                .critical_errors
                .iter()
                .map(|item| &item.provenance_id),
        );
        for reference in referenced {
            if !provenance.contains(reference.as_str()) {
                diagnostics.push(graph_error(
                    "D2I2108",
                    format!("IR references missing provenance '{reference}'"),
                    "attach every IR element to a declared provenance record",
                ));
            }
        }
        diagnostics
    }
}

fn graph_error(code: &str, message: impl Into<String>, help: impl Into<String>) -> Diagnostic {
    Diagnostic::new(Severity::Error, code, message)
        .with_location(SourceLocation::new("<execution-ir>", None, None))
        .with_help(help)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, kind: NodeKind, provenance_id: &ProvenanceId) -> ExecutionNode {
        ExecutionNode {
            id: match NodeId::new(id) {
                Ok(id) => id,
                Err(error) => panic!("invalid test node id: {error}"),
            },
            kind,
            input_type: "record".to_owned(),
            output_type: "record".to_owned(),
            timeout_ms: 10,
            expected_memory_bytes: 1024,
            executor_id: None,
            min_confidence: 0.0,
            failure_target: None,
            retry: RetryPolicy { limit: 0 },
            cache: CachePolicy { cacheable: false },
            side_effect: false,
            parallel_group: None,
            evidence_required: false,
            loop_max_iterations: (kind == NodeKind::LoopBounded).then_some(3),
            provenance_id: provenance_id.clone(),
        }
    }

    fn edge(from: &str, to: &str, provenance_id: &ProvenanceId) -> ExecutionEdge {
        ExecutionEdge {
            from: match NodeId::new(from) {
                Ok(id) => id,
                Err(error) => panic!("invalid test edge source: {error}"),
            },
            to: match NodeId::new(to) {
                Ok(id) => id,
                Err(error) => panic!("invalid test edge target: {error}"),
            },
            kind: EdgeKind::Success,
            condition: None,
            provenance_id: provenance_id.clone(),
        }
    }

    #[test]
    fn execution_graph_rejects_cycles() {
        let provenance = match ProvenanceId::new("p000001") {
            Ok(id) => id,
            Err(error) => panic!("invalid test provenance id: {error}"),
        };
        let graph = ExecutionGraph {
            skill_id: match SkillId::new("cycle") {
                Ok(id) => id,
                Err(error) => panic!("invalid test skill id: {error}"),
            },
            entry_node: match NodeId::new("a") {
                Ok(id) => id,
                Err(error) => panic!("invalid entry id: {error}"),
            },
            nodes: vec![
                node("a", NodeKind::ReadInput, &provenance),
                node("b", NodeKind::Return, &provenance),
            ],
            edges: vec![edge("a", "b", &provenance), edge("b", "a", &provenance)],
        };
        assert!(graph
            .validate()
            .iter()
            .any(|diagnostic| diagnostic.code() == "D2I2107"));
    }

    #[test]
    fn bounded_loop_is_acyclic_and_requires_a_positive_limit() {
        let provenance = match ProvenanceId::new("p000001") {
            Ok(id) => id,
            Err(error) => panic!("invalid test provenance id: {error}"),
        };
        let mut loop_node = node("loop", NodeKind::LoopBounded, &provenance);
        let graph = ExecutionGraph {
            skill_id: match SkillId::new("bounded") {
                Ok(id) => id,
                Err(error) => panic!("invalid test skill id: {error}"),
            },
            entry_node: loop_node.id.clone(),
            nodes: vec![
                loop_node.clone(),
                node("return", NodeKind::Return, &provenance),
            ],
            edges: vec![edge("loop", "return", &provenance)],
        };
        assert!(graph.validate().is_empty());
        loop_node.loop_max_iterations = Some(0);
        let invalid = ExecutionGraph {
            nodes: vec![loop_node],
            ..graph
        };
        assert!(invalid
            .validate()
            .iter()
            .any(|diagnostic| diagnostic.code() == "D2I2101"));
    }
}
