use d2i_compiler::{load_verified_package, PackageSummary, VerifiedPackage};
use d2i_eval::{BenchmarkCase, ExecutorDescriptor};
use d2i_runtime_api::{Evidence, ExecutorRegistry, PackageLoader, RuntimeError};
use d2i_schema::d2i::package as fb;
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

const MAX_GRAPH_NODES: usize = 4_096;
const MAX_GRAPH_EDGES: usize = 16_384;
const MAX_RETRY_LIMIT: u32 = 16;
const MAX_NODE_TIMEOUT_MS: u32 = 60_000;
const MAX_LOOP_ITERATIONS: u32 = 10_000;
const REQUIRED_EXECUTOR_ABI: &str = "d2i-rust-executor-v1";

#[derive(Debug, Clone)]
pub(crate) struct CaseRecord {
    pub id: String,
    pub attributes: BTreeMap<String, String>,
    pub evidence: Evidence,
}

#[derive(Debug, Default)]
pub(crate) struct KnowledgeIndex {
    pub aliases: BTreeMap<String, (String, Evidence)>,
    pub cases: Vec<CaseRecord>,
}

/// Verified package image and deterministic runtime indexes.
pub struct RuntimePackage {
    verified: VerifiedPackage,
    skills: BTreeMap<String, fb::Skill>,
    graphs: BTreeMap<String, fb::ExecutionGraph>,
    input_schemas: BTreeMap<String, JSONSchema>,
    output_schemas: BTreeMap<String, JSONSchema>,
    provenance: BTreeMap<String, Evidence>,
    descriptors: BTreeMap<String, ExecutorDescriptor>,
    pub(crate) knowledge: Arc<KnowledgeIndex>,
}

impl RuntimePackage {
    /// Returns verified package identity and section counts.
    #[must_use]
    pub fn summary(&self) -> &PackageSummary {
        &self.verified.summary
    }

    /// Returns the compiled execution graph for one skill.
    #[must_use]
    pub fn graph(&self, skill_id: &str) -> Option<&fb::ExecutionGraph> {
        self.graphs.get(skill_id)
    }

    /// Returns one compiled skill contract.
    #[must_use]
    pub fn skill(&self, skill_id: &str) -> Option<&fb::Skill> {
        self.skills.get(skill_id)
    }

    /// Returns skill identifiers in deterministic order.
    pub fn skill_ids(&self) -> impl Iterator<Item = &str> {
        self.skills.keys().map(String::as_str)
    }

    /// Returns the verified package policy bundle.
    #[must_use]
    pub fn policies(&self) -> &fb::PolicyBundle {
        &self.verified.policies
    }

    /// Resolves one provenance identifier to runtime evidence.
    #[must_use]
    pub fn provenance(&self, id: &str) -> Option<&Evidence> {
        self.provenance.get(id)
    }

    /// Validates a request against the skill's bundled input schema.
    pub fn validate_request(&self, skill_id: &str, request: &Value) -> Result<(), RuntimeError> {
        let schema = self
            .input_schemas
            .get(skill_id)
            .ok_or_else(|| RuntimeError::UnsupportedSkill(skill_id.to_owned()))?;
        if let Err(errors) = schema.validate(request) {
            let messages = errors
                .take(8)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(RuntimeError::InvalidRequest(messages));
        }
        Ok(())
    }

    /// Validates a decision result against the skill's bundled output schema.
    pub fn validate_result(&self, skill_id: &str, result: &Value) -> Result<(), RuntimeError> {
        let schema = self
            .output_schemas
            .get(skill_id)
            .ok_or_else(|| RuntimeError::UnsupportedSkill(skill_id.to_owned()))?;
        if let Err(errors) = schema.validate(result) {
            let messages = errors
                .take(8)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(RuntimeError::AdapterProtocol(format!(
                "result schema validation failed: {messages}"
            )));
        }
        Ok(())
    }

    /// Iterates bundled evaluation request values.
    pub fn evaluation_cases(&self) -> impl Iterator<Item = (&str, Value)> + '_ {
        self.verified.evaluation.cases.iter().filter_map(|case| {
            serde_json::from_str(&case.request_json)
                .ok()
                .map(|request| (case.id.as_str(), request))
        })
    }

    /// Decodes bundled evaluation requests and expected values for benchmarking.
    pub fn benchmark_cases(&self) -> Result<Vec<BenchmarkCase>, RuntimeError> {
        self.verified
            .evaluation
            .cases
            .iter()
            .map(|case| {
                let request = serde_json::from_str(&case.request_json).map_err(|error| {
                    RuntimeError::Package(format!(
                        "evaluation case '{}' has invalid request JSON: {error}",
                        case.id
                    ))
                })?;
                let expected = serde_json::from_str(&case.expected_json).map_err(|error| {
                    RuntimeError::Package(format!(
                        "evaluation case '{}' has invalid expected JSON: {error}",
                        case.id
                    ))
                })?;
                Ok(BenchmarkCase {
                    id: case.id.clone(),
                    skill_id: case.skill_id.clone(),
                    request,
                    expected,
                })
            })
            .collect()
    }

    /// Returns the source path and content hash of the bundled evaluation dataset.
    #[must_use]
    pub fn evaluation_dataset_identity(&self) -> Option<(&str, &str)> {
        self.verified
            .evaluation
            .cases
            .first()
            .and_then(|case| self.provenance.get(&case.provenance_id))
            .map(|evidence| (evidence.source.as_str(), evidence.content_hash.as_str()))
    }

    /// Returns one compiled evaluation threshold.
    #[must_use]
    pub fn evaluation_threshold(&self, id: &str) -> Option<(f64, bool)> {
        self.verified
            .evaluation
            .metrics
            .iter()
            .find(|metric| metric.id == id)
            .map(|metric| (metric.threshold, metric.higher_is_better))
    }
}

/// Strict local package loader for the Rust reference runtime.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReferencePackageLoader;

impl PackageLoader for ReferencePackageLoader {
    type Package = RuntimePackage;

    fn load(&self, path: &Path) -> Result<Self::Package, RuntimeError> {
        let verified = load_verified_package(path)
            .map_err(|error| RuntimeError::Package(error.to_string()))?;
        validate_target(&verified)?;
        validate_graphs(&verified)?;
        let descriptors = load_descriptors(&verified)?;

        let provenance = build_provenance(&verified);
        let skills = verified
            .skills
            .skills
            .iter()
            .cloned()
            .map(|skill| (skill.id.clone(), skill))
            .collect::<BTreeMap<_, _>>();
        let graphs = verified
            .execution
            .graphs
            .iter()
            .cloned()
            .map(|graph| (graph.skill_id.clone(), graph))
            .collect::<BTreeMap<_, _>>();
        if skills.keys().collect::<BTreeSet<_>>() != graphs.keys().collect::<BTreeSet<_>>() {
            return Err(RuntimeError::Graph(
                "skill and execution graph identifiers do not match".to_owned(),
            ));
        }
        let input_schemas = compile_schemas(&verified, &skills, |skill| &skill.input_schema)?;
        let output_schemas = compile_schemas(&verified, &skills, |skill| &skill.output_schema)?;
        let knowledge = Arc::new(build_knowledge(&verified, &provenance)?);

        Ok(RuntimePackage {
            verified,
            skills,
            graphs,
            input_schemas,
            output_schemas,
            provenance,
            descriptors,
            knowledge,
        })
    }
}

pub(crate) fn validate_bindings(
    package: &RuntimePackage,
    registry: &ExecutorRegistry,
) -> Result<(), RuntimeError> {
    let allowed = package
        .policies()
        .allowed_executors
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for graph in package.graphs.values() {
        for node in &graph.nodes {
            let Some(id) = node.executor_id.as_deref() else {
                continue;
            };
            if !allowed.contains(id) {
                return Err(RuntimeError::MissingExecutor(format!(
                    "{id} is not allowed by package policy"
                )));
            }
            if !package.descriptors.contains_key(id) {
                return Err(RuntimeError::MissingExecutor(format!(
                    "{id} has no verified executor descriptor"
                )));
            }
            let typed = d2i_core::ExecutorId::new(id.to_owned())
                .map_err(|error| RuntimeError::MissingExecutor(error.to_string()))?;
            if registry.get(&typed).is_none() {
                return Err(RuntimeError::MissingExecutor(id.to_owned()));
            }
        }
    }
    Ok(())
}

fn load_descriptors(
    package: &VerifiedPackage,
) -> Result<BTreeMap<String, ExecutorDescriptor>, RuntimeError> {
    let bytes = package
        .artifact("executors/descriptors.json")
        .ok_or_else(|| {
            RuntimeError::Package("executor descriptor registry is missing".to_owned())
        })?;
    let descriptors = serde_json::from_slice::<Vec<ExecutorDescriptor>>(bytes)
        .map_err(|error| RuntimeError::Package(format!("invalid executor descriptors: {error}")))?;
    if descriptors.is_empty() {
        return Err(RuntimeError::Package(
            "executor descriptor registry is empty".to_owned(),
        ));
    }
    let mut registry = BTreeMap::new();
    for descriptor in descriptors {
        if descriptor.abi != REQUIRED_EXECUTOR_ABI {
            return Err(RuntimeError::IncompatibleTarget(format!(
                "executor '{}' requires unsupported ABI '{}'",
                descriptor.id, descriptor.abi
            )));
        }
        if descriptor.security.network {
            return Err(RuntimeError::IncompatibleTarget(format!(
                "executor '{}' requests network access",
                descriptor.id
            )));
        }
        let target_matches = descriptor.targets.iter().any(|target| {
            (target.os == "any" || target.os == std::env::consts::OS)
                && (target.arch == "any" || target.arch == std::env::consts::ARCH)
        });
        if !target_matches {
            return Err(RuntimeError::IncompatibleTarget(format!(
                "executor '{}' does not support host {}/{}",
                descriptor.id,
                std::env::consts::OS,
                std::env::consts::ARCH
            )));
        }
        let id = descriptor.id.clone();
        if registry.insert(id.clone(), descriptor).is_some() {
            return Err(RuntimeError::Package(format!(
                "duplicate executor descriptor '{id}'"
            )));
        }
    }
    Ok(registry)
}

fn validate_target(package: &VerifiedPackage) -> Result<(), RuntimeError> {
    let manifest = &package.manifest;
    if manifest.network_policy != "deny" || package.policies.network_allowed {
        return Err(RuntimeError::IncompatibleTarget(
            "reference runtime requires network-denied packages".to_owned(),
        ));
    }
    let host_os = std::env::consts::OS;
    if manifest.target_os != "any" && manifest.target_os != host_os {
        return Err(RuntimeError::IncompatibleTarget(format!(
            "package OS '{}' does not match host '{host_os}'",
            manifest.target_os
        )));
    }
    let host_arch = std::env::consts::ARCH;
    if manifest.target_arch != "any" && manifest.target_arch != host_arch {
        return Err(RuntimeError::IncompatibleTarget(format!(
            "package architecture '{}' does not match host '{host_arch}'",
            manifest.target_arch
        )));
    }
    Ok(())
}

fn validate_graphs(package: &VerifiedPackage) -> Result<(), RuntimeError> {
    for graph in &package.execution.graphs {
        if graph.nodes.is_empty() || graph.nodes.len() > MAX_GRAPH_NODES {
            return Err(RuntimeError::Graph(format!(
                "graph '{}' must contain 1..={MAX_GRAPH_NODES} nodes",
                graph.skill_id
            )));
        }
        if graph.edges.len() > MAX_GRAPH_EDGES {
            return Err(RuntimeError::Graph(format!(
                "graph '{}' exceeds {MAX_GRAPH_EDGES} edges",
                graph.skill_id
            )));
        }
        let ids = graph
            .nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect::<BTreeSet<_>>();
        if ids.len() != graph.nodes.len() || !ids.contains(graph.entry_node.as_str()) {
            return Err(RuntimeError::Graph(format!(
                "graph '{}' has duplicate nodes or a missing entry",
                graph.skill_id
            )));
        }
        for node in &graph.nodes {
            if node.retry_limit > MAX_RETRY_LIMIT {
                return Err(RuntimeError::Graph(format!(
                    "node '{}' exceeds retry limit {MAX_RETRY_LIMIT}",
                    node.id
                )));
            }
            if node.timeout_ms > MAX_NODE_TIMEOUT_MS {
                return Err(RuntimeError::Graph(format!(
                    "node '{}' exceeds timeout limit {MAX_NODE_TIMEOUT_MS} ms",
                    node.id
                )));
            }
            if node.kind == fb::NodeKind::LoopBounded
                && !(1..=MAX_LOOP_ITERATIONS).contains(&node.loop_max_iterations)
            {
                return Err(RuntimeError::Graph(format!(
                    "node '{}' has an invalid bounded-loop limit",
                    node.id
                )));
            }
            if node.side_effect && node.kind != fb::NodeKind::HumanReview {
                return Err(RuntimeError::Graph(format!(
                    "reference runtime does not permit side-effect node '{}'",
                    node.id
                )));
            }
        }
        for edge in &graph.edges {
            if !ids.contains(edge.from.as_str()) || !ids.contains(edge.to.as_str()) {
                return Err(RuntimeError::Graph(format!(
                    "edge '{}' -> '{}' references an unknown node",
                    edge.from, edge.to
                )));
            }
        }
        ensure_acyclic(graph, &ids)?;
    }
    Ok(())
}

fn ensure_acyclic(graph: &fb::ExecutionGraph, ids: &BTreeSet<&str>) -> Result<(), RuntimeError> {
    let mut indegree = ids
        .iter()
        .map(|id| (*id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut adjacency = BTreeMap::<&str, Vec<&str>>::new();
    for edge in &graph.edges {
        adjacency
            .entry(edge.from.as_str())
            .or_default()
            .push(edge.to.as_str());
        if let Some(value) = indegree.get_mut(edge.to.as_str()) {
            *value += 1;
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(*id))
        .collect::<Vec<_>>();
    let mut visited = 0_usize;
    while let Some(id) = ready.pop() {
        visited += 1;
        if let Some(targets) = adjacency.get(id) {
            for target in targets {
                if let Some(count) = indegree.get_mut(target) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        ready.push(target);
                    }
                }
            }
        }
    }
    if visited != ids.len() {
        return Err(RuntimeError::Graph(format!(
            "graph '{}' contains a cycle",
            graph.skill_id
        )));
    }
    Ok(())
}

fn build_provenance(package: &VerifiedPackage) -> BTreeMap<String, Evidence> {
    package
        .domain
        .provenance
        .iter()
        .map(|item| {
            (
                item.id.clone(),
                Evidence {
                    source: item.source_path.clone(),
                    span: item.field.clone().unwrap_or_else(|| item.line.to_string()),
                    provenance_id: item.id.clone(),
                    content_hash: item.content_hash.clone(),
                },
            )
        })
        .collect()
}

fn compile_schemas(
    package: &VerifiedPackage,
    skills: &BTreeMap<String, fb::Skill>,
    path: impl Fn(&fb::Skill) -> &str,
) -> Result<BTreeMap<String, JSONSchema>, RuntimeError> {
    let mut result = BTreeMap::new();
    for (id, skill) in skills {
        let schema_path = path(skill);
        let bytes = package
            .artifact(schema_path)
            .ok_or_else(|| RuntimeError::Package(format!("missing schema '{schema_path}'")))?;
        let mut value: Value = serde_json::from_slice(bytes)
            .map_err(|error| RuntimeError::Package(error.to_string()))?;
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "$id".to_owned(),
                Value::String(format!("d2i://local/{schema_path}")),
            );
        }
        let mut options = JSONSchema::options();
        options.with_draft(Draft::Draft202012);
        let schema = options
            .compile(&value)
            .map_err(|error| RuntimeError::Package(error.to_string()))?;
        result.insert(id.clone(), schema);
    }
    Ok(result)
}

fn build_knowledge(
    package: &VerifiedPackage,
    provenance: &BTreeMap<String, Evidence>,
) -> Result<KnowledgeIndex, RuntimeError> {
    let mut attributes = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut entity_provenance = BTreeMap::<String, String>::new();
    for record in &package.domain.entities {
        if record.kind == "entity" {
            attributes.entry(record.id.clone()).or_default();
            entity_provenance.insert(record.id.clone(), record.provenance_id.clone());
        } else if record.kind == "attribute" {
            let (Some(entity), Some(key), Some(value)) = (
                record.subject.as_ref(),
                record.predicate.as_ref(),
                record.object.as_ref(),
            ) else {
                return Err(RuntimeError::Package(
                    "malformed entity attribute record".to_owned(),
                ));
            };
            attributes
                .entry(entity.clone())
                .or_default()
                .insert(key.clone(), value.clone());
        }
    }
    let mut cases = Vec::new();
    for (id, values) in attributes {
        if !values.contains_key("fault_code") || !values.contains_key("recommended_step") {
            continue;
        }
        let provenance_id = entity_provenance.get(&id).cloned().unwrap_or_default();
        let evidence = provenance.get(&provenance_id).cloned().ok_or_else(|| {
            RuntimeError::Package(format!("missing provenance '{provenance_id}'"))
        })?;
        cases.push(CaseRecord {
            id,
            attributes: values,
            evidence,
        });
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));

    let mut canonical = BTreeMap::<String, (String, Evidence)>::new();
    for record in package
        .domain
        .terms
        .iter()
        .filter(|record| record.kind == "term")
    {
        let Some(value) = record.subject.as_ref() else {
            continue;
        };
        let Some(evidence) = provenance.get(&record.provenance_id).cloned() else {
            continue;
        };
        canonical.insert(record.id.clone(), (value.clone(), evidence.clone()));
        canonical.insert(normalize(value), (value.clone(), evidence));
    }
    let mut aliases = canonical.clone();
    for record in package
        .domain
        .terms
        .iter()
        .filter(|record| record.kind == "alias")
    {
        let (Some(term_id), Some(alias)) = (record.subject.as_ref(), record.object.as_ref()) else {
            continue;
        };
        if let Some((value, evidence)) = canonical.get(term_id) {
            aliases.insert(normalize(alias), (value.clone(), evidence.clone()));
        }
    }
    Ok(KnowledgeIndex { aliases, cases })
}

pub(crate) fn normalize(value: &str) -> String {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}
