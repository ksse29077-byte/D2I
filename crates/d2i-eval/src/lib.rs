//! Executor evaluation, Pareto selection, graph optimization, and benchmarks.

use d2i_core::{
    CachePolicy, EdgeKind, ExecutionEdge, ExecutionGraph, ExecutorId, NodeId, NodeKind,
};
use d2i_runtime_api::{DecisionEnvelope, DecisionStatus, RuntimeError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Executor implementation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKind {
    Constant,
    Cache,
    Rule,
    Lookup,
    Search,
    NativeFunction,
    ClassicalModel,
    NeuralExpert,
    LanguageExpert,
    Planner,
    DeviceAdapter,
    HumanReview,
}

/// Supported deployment target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSupport {
    pub os: String,
    pub arch: String,
}

/// Static executor resource estimates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceProfile {
    pub resident_memory_bytes: u64,
    pub cold_start_us: u64,
    pub package_size_bytes: u64,
    pub deterministic: bool,
}

/// Executor security capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityProfile {
    pub network: bool,
    pub side_effects: bool,
}

/// SPDX-oriented executor license metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseInfo {
    pub id: String,
}

/// Address and hash of an executor artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInfo {
    pub path: String,
    pub sha256: String,
}

/// Complete versioned executor descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorDescriptor {
    pub id: String,
    pub version: String,
    pub kind: ExecutorKind,
    pub abi: String,
    pub capabilities: Vec<String>,
    pub input_schemas: Vec<String>,
    pub output_schemas: Vec<String>,
    pub targets: Vec<TargetSupport>,
    pub resource_profile: ResourceProfile,
    pub security: SecurityProfile,
    pub license: LicenseInfo,
    pub artifact: ArtifactInfo,
}

/// Imported quality and cost observations for one equivalent task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkProfile {
    pub executor_id: String,
    pub dataset_id: String,
    pub dataset_hash: String,
    pub case_count: u64,
    pub task_success_rate: f64,
    pub field_accuracy: f64,
    pub critical_error_rate: f64,
    pub p50_latency_us: u64,
    pub p95_latency_us: u64,
    pub p99_latency_us: u64,
    pub cold_start_us: u64,
    pub peak_rss_bytes: u64,
    pub allocated_bytes: u64,
    pub copy_count: u64,
    pub copy_bytes: u64,
    pub repeatability_rate: f64,
}

/// Cost dimensions considered after hard quality and safety gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CostWeights {
    pub latency: f64,
    pub memory: f64,
    pub package_size: f64,
    pub cold_start: f64,
    pub copies: f64,
}

impl Default for CostWeights {
    fn default() -> Self {
        Self {
            latency: 1.0,
            memory: 1.0,
            package_size: 0.5,
            cold_start: 0.25,
            copies: 0.25,
        }
    }
}

/// User-controlled selection settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SelectionConfig {
    pub required_abi: String,
    pub weights: CostWeights,
    pub forced_bindings: BTreeMap<String, String>,
    pub fallbacks: BTreeMap<String, String>,
    pub small_first_cascade: bool,
}

impl Default for SelectionConfig {
    fn default() -> Self {
        Self {
            required_abi: "d2i-rust-executor-v1".to_owned(),
            weights: CostWeights::default(),
            forced_bindings: BTreeMap::new(),
            fallbacks: BTreeMap::new(),
            small_first_cascade: false,
        }
    }
}

/// Hard requirements for one skill operation.
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionRequest {
    pub capability: String,
    pub input_schema: String,
    pub output_schema: String,
    pub target_os: String,
    pub target_arch: String,
    pub max_memory_bytes: u64,
    pub min_task_success_rate: f64,
    pub min_field_accuracy: f64,
    pub max_critical_error_rate: f64,
    pub min_repeatability_rate: f64,
    pub network_allowed: bool,
    pub side_effects_allowed: bool,
}

/// Candidate exclusion with reproducible reasons.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRejection {
    pub executor_id: String,
    pub reasons: Vec<String>,
}

/// Selection result retained in build reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectionReport {
    pub capability: String,
    pub feasible: Vec<String>,
    pub rejected: Vec<CandidateRejection>,
    pub pareto_front: Vec<String>,
    pub selected: Option<String>,
    pub forced: bool,
    pub fallback: Option<String>,
    pub normalized_costs: BTreeMap<String, f64>,
    pub explanation: String,
}

/// Selects the lowest configured cost from the quality-safe Pareto front.
#[must_use]
pub fn select_executor(
    request: &SelectionRequest,
    descriptors: &[ExecutorDescriptor],
    benchmarks: &[BenchmarkProfile],
    config: &SelectionConfig,
) -> SelectionReport {
    let benchmark_by_id = benchmarks
        .iter()
        .map(|profile| (profile.executor_id.as_str(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut feasible = Vec::new();
    let mut rejected = Vec::new();
    for descriptor in descriptors {
        let mut reasons = compatibility_reasons(request, descriptor, config);
        let profile = benchmark_by_id.get(descriptor.id.as_str()).copied();
        match profile {
            Some(profile) => reasons.extend(quality_reasons(request, profile)),
            None => reasons.push("missing benchmark profile".to_owned()),
        }
        if reasons.is_empty() {
            if let Some(profile) = profile {
                feasible.push((descriptor, profile));
            }
        } else {
            rejected.push(CandidateRejection {
                executor_id: descriptor.id.clone(),
                reasons,
            });
        }
    }
    feasible.sort_by(|left, right| left.0.id.cmp(&right.0.id));
    rejected.sort_by(|left, right| left.executor_id.cmp(&right.executor_id));

    let forced_id = config.forced_bindings.get(&request.capability);
    if let Some(forced_id) = forced_id {
        let selected = feasible
            .iter()
            .find(|(descriptor, _)| &descriptor.id == forced_id)
            .map(|(descriptor, _)| descriptor.id.clone());
        let explanation = selected.as_ref().map_or_else(
            || format!("forced executor '{forced_id}' failed hard constraints"),
            |id| format!("forced binding selected '{id}' after all hard gates passed"),
        );
        return SelectionReport {
            capability: request.capability.clone(),
            feasible: feasible
                .iter()
                .map(|(descriptor, _)| descriptor.id.clone())
                .collect(),
            rejected,
            pareto_front: selected.clone().into_iter().collect(),
            selected,
            forced: true,
            fallback: None,
            normalized_costs: BTreeMap::new(),
            explanation,
        };
    }

    let pareto = pareto_candidates(&feasible);
    let normalized_costs = normalized_costs(&pareto, &config.weights);
    let selected = normalized_costs
        .iter()
        .min_by(|left, right| {
            left.1
                .partial_cmp(right.1)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.0.cmp(right.0))
        })
        .map(|(id, _)| id.clone());
    let fallback = selected
        .is_none()
        .then(|| config.fallbacks.get(&request.capability).cloned())
        .flatten();
    let explanation = selected.as_ref().map_or_else(
        || {
            fallback.as_ref().map_or_else(
                || "no candidate passed compatibility, quality, and safety gates".to_owned(),
                |fallback| format!("no candidate passed hard gates; fallback is '{fallback}'"),
            )
        },
        |id| {
            format!(
                "selected '{id}' from {} Pareto-safe candidate(s) using configured target costs",
                pareto.len()
            )
        },
    );
    SelectionReport {
        capability: request.capability.clone(),
        feasible: feasible
            .iter()
            .map(|(descriptor, _)| descriptor.id.clone())
            .collect(),
        rejected,
        pareto_front: pareto
            .iter()
            .map(|(descriptor, _)| descriptor.id.clone())
            .collect(),
        selected,
        forced: false,
        fallback,
        normalized_costs,
        explanation,
    }
}

fn compatibility_reasons(
    request: &SelectionRequest,
    descriptor: &ExecutorDescriptor,
    config: &SelectionConfig,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if !descriptor.capabilities.contains(&request.capability) {
        reasons.push(format!("missing capability '{}'", request.capability));
    }
    if !descriptor.input_schemas.contains(&request.input_schema) {
        reasons.push(format!(
            "input schema '{}' is unsupported",
            request.input_schema
        ));
    }
    if !descriptor.output_schemas.contains(&request.output_schema) {
        reasons.push(format!(
            "output schema '{}' is unsupported",
            request.output_schema
        ));
    }
    if descriptor.abi != config.required_abi {
        reasons.push(format!("ABI '{}' is unsupported", descriptor.abi));
    }
    if !descriptor.targets.iter().any(|target| {
        target_matches(&target.os, &request.target_os)
            && target_matches(&target.arch, &request.target_arch)
    }) {
        reasons.push(format!(
            "target {}/{} is unsupported",
            request.target_os, request.target_arch
        ));
    }
    if descriptor.resource_profile.resident_memory_bytes > request.max_memory_bytes {
        reasons.push("resident memory exceeds target limit".to_owned());
    }
    if descriptor.security.network && !request.network_allowed {
        reasons.push("network access is denied".to_owned());
    }
    if descriptor.security.side_effects && !request.side_effects_allowed {
        reasons.push("side effects are denied".to_owned());
    }
    if descriptor.license.id.trim().is_empty() {
        reasons.push("license identifier is missing".to_owned());
    }
    if !valid_sha256(&descriptor.artifact.sha256) {
        reasons.push("artifact hash is not a canonical SHA-256 digest".to_owned());
    }
    reasons
}

fn quality_reasons(request: &SelectionRequest, profile: &BenchmarkProfile) -> Vec<String> {
    let mut reasons = Vec::new();
    if profile.case_count == 0 {
        reasons.push("benchmark profile has no cases".to_owned());
    }
    if profile.task_success_rate < request.min_task_success_rate {
        reasons.push(format!(
            "task success {:.4} is below {:.4}",
            profile.task_success_rate, request.min_task_success_rate
        ));
    }
    if profile.field_accuracy < request.min_field_accuracy {
        reasons.push(format!(
            "field accuracy {:.4} is below {:.4}",
            profile.field_accuracy, request.min_field_accuracy
        ));
    }
    if profile.critical_error_rate > request.max_critical_error_rate {
        reasons.push(format!(
            "critical error {:.6} exceeds {:.6}",
            profile.critical_error_rate, request.max_critical_error_rate
        ));
    }
    if profile.repeatability_rate < request.min_repeatability_rate {
        reasons.push(format!(
            "repeatability {:.4} is below {:.4}",
            profile.repeatability_rate, request.min_repeatability_rate
        ));
    }
    reasons
}

fn pareto_candidates<'a>(
    feasible: &[(&'a ExecutorDescriptor, &'a BenchmarkProfile)],
) -> Vec<(&'a ExecutorDescriptor, &'a BenchmarkProfile)> {
    feasible
        .iter()
        .copied()
        .filter(|candidate| {
            !feasible
                .iter()
                .copied()
                .any(|other| other.0.id != candidate.0.id && dominates(other, *candidate))
        })
        .collect()
}

fn dominates(
    left: (&ExecutorDescriptor, &BenchmarkProfile),
    right: (&ExecutorDescriptor, &BenchmarkProfile),
) -> bool {
    let left_values = cost_values(left);
    let right_values = cost_values(right);
    left_values
        .iter()
        .zip(&right_values)
        .all(|(left, right)| left <= right)
        && left_values
            .iter()
            .zip(&right_values)
            .any(|(left, right)| left < right)
}

fn cost_values(candidate: (&ExecutorDescriptor, &BenchmarkProfile)) -> [u64; 5] {
    [
        candidate.1.p95_latency_us,
        candidate.0.resource_profile.resident_memory_bytes,
        candidate.0.resource_profile.package_size_bytes,
        candidate.1.cold_start_us,
        candidate.1.copy_bytes,
    ]
}

fn normalized_costs(
    candidates: &[(&ExecutorDescriptor, &BenchmarkProfile)],
    weights: &CostWeights,
) -> BTreeMap<String, f64> {
    let maxima = candidates.iter().fold([1_u64; 5], |mut maxima, candidate| {
        for (index, value) in cost_values(*candidate).into_iter().enumerate() {
            maxima[index] = maxima[index].max(value);
        }
        maxima
    });
    candidates
        .iter()
        .map(|candidate| {
            let values = cost_values(*candidate);
            let score = weights.latency * ratio(values[0], maxima[0])
                + weights.memory * ratio(values[1], maxima[1])
                + weights.package_size * ratio(values[2], maxima[2])
                + weights.cold_start * ratio(values[3], maxima[3])
                + weights.copies * ratio(values[4], maxima[4]);
            (candidate.0.id.clone(), score)
        })
        .collect()
}

fn ratio(value: u64, maximum: u64) -> f64 {
    value as f64 / maximum.max(1) as f64
}

fn target_matches(supported: &str, requested: &str) -> bool {
    supported == "any" || requested == "any" || supported == requested
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// One graph optimization action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationAction {
    pub pass: String,
    pub node_ids: Vec<String>,
    pub detail: String,
}

/// Deterministic graph optimization report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub skill_id: String,
    pub actions: Vec<OptimizationAction>,
}

/// Applies safe MVP graph rewrites and annotations.
#[must_use]
pub fn optimize_graph(
    graph: &mut ExecutionGraph,
    descriptors: &BTreeMap<String, ExecutorDescriptor>,
    selection: &BTreeMap<String, SelectionReport>,
    config: &SelectionConfig,
) -> OptimizationReport {
    let mut actions = Vec::new();
    for node in &mut graph.nodes {
        if matches!(node.kind, NodeKind::Lookup | NodeKind::Retrieve)
            && !node.cache.cacheable
            && node.executor_id.as_ref().is_some_and(|id| {
                descriptors
                    .get(id.as_str())
                    .is_some_and(|descriptor| descriptor.resource_profile.deterministic)
            })
        {
            node.cache = CachePolicy { cacheable: true };
            actions.push(action(
                "cache_annotation",
                vec![node.id.to_string()],
                "marked deterministic lookup as cacheable",
            ));
        }
        if let Some(executor_id) = &node.executor_id {
            if descriptors
                .get(executor_id.as_str())
                .is_some_and(|descriptor| descriptor.kind == ExecutorKind::Constant)
            {
                node.kind = NodeKind::Lookup;
                node.cache = CachePolicy { cacheable: true };
                actions.push(action(
                    "constant_folding",
                    vec![node.id.to_string()],
                    "lowered constant executor to a cacheable lookup",
                ));
            }
        }
    }
    merge_duplicates(
        graph,
        NodeKind::Normalize,
        "common_preprocessing",
        &mut actions,
    );
    merge_duplicates(
        graph,
        NodeKind::Lookup,
        "duplicate_lookup_removal",
        &mut actions,
    );
    remove_unbound_generation(graph, &mut actions);
    annotate_parallel_siblings(graph, &mut actions);
    if config.small_first_cascade {
        add_small_first_cascades(graph, descriptors, selection, &mut actions);
    }
    actions.sort_by(|left, right| {
        (&left.pass, &left.node_ids, &left.detail).cmp(&(
            &right.pass,
            &right.node_ids,
            &right.detail,
        ))
    });
    OptimizationReport {
        skill_id: graph.skill_id.to_string(),
        actions,
    }
}

fn merge_duplicates(
    graph: &mut ExecutionGraph,
    kind: NodeKind,
    pass: &str,
    actions: &mut Vec<OptimizationAction>,
) {
    let predecessors = graph
        .nodes
        .iter()
        .map(|node| {
            let mut incoming = graph
                .edges
                .iter()
                .filter(|edge| edge.to == node.id)
                .map(|edge| {
                    (
                        edge.from.to_string(),
                        edge_order(edge.kind),
                        edge.condition.clone(),
                    )
                })
                .collect::<Vec<_>>();
            incoming.sort();
            (node.id.clone(), incoming)
        })
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeMap::<
        (
            Option<String>,
            String,
            String,
            Vec<(String, u8, Option<String>)>,
        ),
        NodeId,
    >::new();
    let mut removals = BTreeMap::<NodeId, NodeId>::new();
    for node in &graph.nodes {
        if node.kind != kind {
            continue;
        }
        let key = (
            node.executor_id.as_ref().map(ToString::to_string),
            node.input_type.clone(),
            node.output_type.clone(),
            predecessors.get(&node.id).cloned().unwrap_or_default(),
        );
        if let Some(existing) = seen.get(&key) {
            removals.insert(node.id.clone(), existing.clone());
        } else {
            seen.insert(key, node.id.clone());
        }
    }
    for (duplicate, existing) in &removals {
        for edge in &mut graph.edges {
            if edge.from == *duplicate {
                edge.from = existing.clone();
            }
            if edge.to == *duplicate {
                edge.to = existing.clone();
            }
        }
        actions.push(action(
            pass,
            vec![duplicate.to_string(), existing.to_string()],
            "merged equivalent nodes",
        ));
    }
    graph.nodes.retain(|node| !removals.contains_key(&node.id));
    deduplicate_edges(&mut graph.edges);
}

fn remove_unbound_generation(graph: &mut ExecutionGraph, actions: &mut Vec<OptimizationAction>) {
    let removable = graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::ModelCall && node.executor_id.is_none())
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    for node_id in removable {
        let incoming = graph
            .edges
            .iter()
            .filter(|edge| edge.to == node_id && edge.kind == EdgeKind::Success)
            .cloned()
            .collect::<Vec<_>>();
        let outgoing = graph
            .edges
            .iter()
            .filter(|edge| edge.from == node_id && edge.kind == EdgeKind::Success)
            .cloned()
            .collect::<Vec<_>>();
        if incoming.len() == 1 && outgoing.len() == 1 {
            graph.edges.push(ExecutionEdge {
                from: incoming[0].from.clone(),
                to: outgoing[0].to.clone(),
                kind: EdgeKind::Success,
                condition: None,
                provenance_id: incoming[0].provenance_id.clone(),
            });
            graph
                .edges
                .retain(|edge| edge.from != node_id && edge.to != node_id);
            graph.nodes.retain(|node| node.id != node_id);
            actions.push(action(
                "unnecessary_generation_removal",
                vec![node_id.to_string()],
                "removed an unbound generation node",
            ));
        }
    }
    deduplicate_edges(&mut graph.edges);
}

fn annotate_parallel_siblings(graph: &mut ExecutionGraph, actions: &mut Vec<OptimizationAction>) {
    let nodes = graph
        .nodes
        .iter()
        .map(|node| (node.id.to_string(), node.side_effect))
        .collect::<BTreeMap<_, _>>();
    let sources = graph
        .edges
        .iter()
        .filter(|edge| edge.kind == EdgeKind::Success)
        .map(|edge| edge.from.clone())
        .collect::<BTreeSet<_>>();
    for source in sources {
        let targets = graph
            .edges
            .iter()
            .filter(|edge| edge.from == source && edge.kind == EdgeKind::Success)
            .map(|edge| edge.to.clone())
            .collect::<Vec<_>>();
        if targets.len() < 2
            || !targets.iter().all(|target| {
                nodes
                    .get(target.as_str())
                    .is_some_and(|side_effect| !side_effect)
            })
        {
            continue;
        }
        let group = format!("parallel-{source}");
        for target in &targets {
            if let Some(node) = graph.nodes.iter_mut().find(|node| node.id == *target) {
                node.parallel_group = Some(group.clone());
            }
        }
        for edge in graph
            .edges
            .iter_mut()
            .filter(|edge| edge.from == source && targets.contains(&edge.to))
        {
            edge.kind = EdgeKind::Parallel;
        }
        actions.push(action(
            "parallelization",
            targets.iter().map(ToString::to_string).collect(),
            "annotated independent sibling nodes as a parallel group",
        ));
    }
}

fn add_small_first_cascades(
    graph: &mut ExecutionGraph,
    descriptors: &BTreeMap<String, ExecutorDescriptor>,
    selection: &BTreeMap<String, SelectionReport>,
    actions: &mut Vec<OptimizationAction>,
) {
    let mut plans = Vec::new();
    for node in &graph.nodes {
        let Some(selected_id) = node.executor_id.as_ref().map(ToString::to_string) else {
            continue;
        };
        let Some(report) = selection
            .values()
            .find(|report| report.selected.as_deref() == Some(&selected_id))
        else {
            continue;
        };
        let smallest = report
            .pareto_front
            .iter()
            .filter_map(|id| descriptors.get(id))
            .min_by_key(|descriptor| descriptor.resource_profile.resident_memory_bytes);
        let Some(smallest) = smallest else {
            continue;
        };
        if smallest.id == selected_id {
            continue;
        }
        let Ok(small_id) = ExecutorId::new(smallest.id.clone()) else {
            continue;
        };
        let Ok(fallback_id) = NodeId::new(format!("{}-fallback", node.id)) else {
            continue;
        };
        if graph.nodes.iter().any(|node| node.id == fallback_id) {
            continue;
        }
        plans.push((
            node.id.clone(),
            fallback_id,
            small_id,
            selected_id,
            node.clone(),
        ));
    }
    for (node_id, fallback_id, small_id, selected_id, mut fallback_node) in plans {
        let Some(node) = graph.nodes.iter_mut().find(|node| node.id == node_id) else {
            continue;
        };
        node.executor_id = Some(small_id.clone());
        node.min_confidence = node.min_confidence.max(0.8);
        node.failure_target = Some(fallback_id.clone());
        fallback_node.id = fallback_id.clone();
        fallback_node.executor_id = ExecutorId::new(selected_id.clone()).ok();
        fallback_node.failure_target = None;
        fallback_node.min_confidence = 0.0;
        let success_edges = graph
            .edges
            .iter()
            .filter(|edge| edge.from == node_id && edge.kind != EdgeKind::Failure)
            .cloned()
            .map(|mut edge| {
                edge.from = fallback_id.clone();
                edge
            })
            .collect::<Vec<_>>();
        for edge in graph
            .edges
            .iter_mut()
            .filter(|edge| edge.from == node_id && edge.kind == EdgeKind::Failure)
        {
            edge.from = fallback_id.clone();
        }
        graph.edges.extend(success_edges);
        graph.edges.push(ExecutionEdge {
            from: node_id.clone(),
            to: fallback_id.clone(),
            kind: EdgeKind::Failure,
            condition: Some("confidence_below_threshold".to_owned()),
            provenance_id: fallback_node.provenance_id.clone(),
        });
        graph.nodes.push(fallback_node);
        actions.push(action(
            "small_first_cascade",
            vec![node_id.to_string(), fallback_id.to_string()],
            format!(
                "try '{}' before selected fallback '{}'",
                small_id, selected_id
            ),
        ));
    }
    deduplicate_edges(&mut graph.edges);
}

fn deduplicate_edges(edges: &mut Vec<ExecutionEdge>) {
    edges.sort_by(|left, right| {
        (
            left.from.as_str(),
            left.to.as_str(),
            edge_order(left.kind),
            left.condition.as_deref(),
        )
            .cmp(&(
                right.from.as_str(),
                right.to.as_str(),
                edge_order(right.kind),
                right.condition.as_deref(),
            ))
    });
    edges.dedup_by(|left, right| {
        left.from == right.from
            && left.to == right.to
            && left.kind == right.kind
            && left.condition == right.condition
    });
}

fn edge_order(kind: EdgeKind) -> u8 {
    match kind {
        EdgeKind::Success => 0,
        EdgeKind::Failure => 1,
        EdgeKind::BranchTrue => 2,
        EdgeKind::BranchFalse => 3,
        EdgeKind::Parallel => 4,
        EdgeKind::Join => 5,
    }
}

fn action(pass: &str, node_ids: Vec<String>, detail: impl Into<String>) -> OptimizationAction {
    OptimizationAction {
        pass: pass.to_owned(),
        node_ids,
        detail: detail.into(),
    }
}

/// Input case for runtime benchmark collection.
#[derive(Debug, Clone, PartialEq)]
pub struct BenchmarkCase {
    pub id: String,
    pub skill_id: String,
    pub request: Value,
    pub expected: Value,
}

/// Stable identity attached to one measured benchmark run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkMetadata<'a> {
    pub benchmark_id: &'a str,
    pub build_id: &'a str,
    pub dataset_id: &'a str,
    pub dataset_hash: &'a str,
    pub compiler_version: &'a str,
}

/// Measured runtime benchmark artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeBenchmarkReport {
    pub benchmark_id: String,
    pub build_id: String,
    pub dataset_id: String,
    pub dataset_hash: String,
    pub measured_at_unix_seconds: u64,
    pub host_os: String,
    pub host_arch: String,
    pub logical_cpus: usize,
    pub compiler_version: String,
    pub case_count: usize,
    pub measured_iterations: u32,
    pub task_success_rate: f64,
    pub field_accuracy: f64,
    pub critical_error_rate: f64,
    pub p50_latency_us: u64,
    pub p95_latency_us: u64,
    pub p99_latency_us: u64,
    pub cold_start_us: u64,
    pub warm_start_us: u64,
    pub peak_rss_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub copy_count: u64,
    pub copy_bytes: u64,
    pub repeatability_rate: f64,
    pub activated_modules: Vec<String>,
    pub timeout_rate: f64,
}

/// Measures equivalent cases through a caller-provided local runtime function.
pub fn benchmark_runtime(
    metadata: BenchmarkMetadata<'_>,
    cases: &[BenchmarkCase],
    measured_iterations: u32,
    mut run: impl FnMut(&BenchmarkCase) -> Result<DecisionEnvelope, RuntimeError>,
) -> Result<RuntimeBenchmarkReport, RuntimeError> {
    if cases.is_empty() || measured_iterations == 0 {
        return Err(RuntimeError::InvalidRequest(
            "benchmark requires cases and measured iterations".to_owned(),
        ));
    }
    let mut latencies = Vec::new();
    let mut successes = 0_u64;
    let mut matched_fields = 0_u64;
    let mut total_fields = 0_u64;
    let mut critical_errors = 0_u64;
    let mut timeouts = 0_u64;
    let mut copy_bytes = 0_u64;
    let mut modules = BTreeSet::new();
    let mut decision_hashes = BTreeMap::<String, BTreeSet<String>>::new();
    let mut cold_start_us = None;
    let mut warm_latencies = Vec::new();
    let total_runs = u64::from(measured_iterations)
        .saturating_mul(u64::try_from(cases.len()).unwrap_or(u64::MAX));
    for iteration in 0..measured_iterations {
        for case in cases {
            let started = Instant::now();
            let envelope = run(case)?;
            let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
            latencies.push(elapsed);
            if cold_start_us.is_none() {
                cold_start_us = Some(elapsed);
            } else {
                warm_latencies.push(elapsed);
            }
            let field_result = decision_field_metrics(&envelope, &case.expected);
            matched_fields = matched_fields.saturating_add(field_result.0);
            total_fields = total_fields.saturating_add(field_result.1);
            if field_result.0 == field_result.1 && field_result.1 > 0 {
                successes += 1;
            } else if case.expected["category"] == "critical" {
                critical_errors += 1;
            }
            if envelope.status == DecisionStatus::Timeout {
                timeouts += 1;
            }
            modules.extend(envelope.module_ids.iter().cloned());
            copy_bytes = copy_bytes
                .saturating_add(
                    u64::try_from(serde_json::to_vec(&case.request).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                )
                .saturating_add(
                    u64::try_from(serde_json::to_vec(&envelope).unwrap_or_default().len())
                        .unwrap_or(u64::MAX),
                );
            decision_hashes
                .entry(case.id.clone())
                .or_default()
                .insert(envelope.decision_hash());
        }
        if iteration == u32::MAX {
            break;
        }
    }
    latencies.sort_unstable();
    warm_latencies.sort_unstable();
    let repeatable = decision_hashes
        .values()
        .filter(|hashes| hashes.len() == 1)
        .count();
    Ok(RuntimeBenchmarkReport {
        benchmark_id: metadata.benchmark_id.to_owned(),
        build_id: metadata.build_id.to_owned(),
        dataset_id: metadata.dataset_id.to_owned(),
        dataset_hash: metadata.dataset_hash.to_owned(),
        measured_at_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs()),
        host_os: std::env::consts::OS.to_owned(),
        host_arch: std::env::consts::ARCH.to_owned(),
        logical_cpus: std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        compiler_version: metadata.compiler_version.to_owned(),
        case_count: cases.len(),
        measured_iterations,
        task_success_rate: rate(successes, total_runs),
        field_accuracy: rate(matched_fields, total_fields),
        critical_error_rate: rate(critical_errors, total_runs),
        p50_latency_us: percentile(&latencies, 50),
        p95_latency_us: percentile(&latencies, 95),
        p99_latency_us: percentile(&latencies, 99),
        cold_start_us: cold_start_us.unwrap_or(0),
        warm_start_us: percentile(&warm_latencies, 50),
        peak_rss_bytes: None,
        allocated_bytes: None,
        copy_count: total_runs.saturating_mul(2),
        copy_bytes,
        repeatability_rate: rate(
            u64::try_from(repeatable).unwrap_or(u64::MAX),
            u64::try_from(decision_hashes.len()).unwrap_or(u64::MAX),
        ),
        activated_modules: modules.into_iter().collect(),
        timeout_rate: rate(timeouts, total_runs),
    })
}

fn decision_field_metrics(envelope: &DecisionEnvelope, expected: &Value) -> (u64, u64) {
    let Some(fields) = expected.as_object() else {
        return (0, 0);
    };
    fields
        .iter()
        .filter(|(field, _)| field.as_str() != "category")
        .fold((0_u64, 0_u64), |(matched, total), (field, value)| {
            let field_matches = if field == "fault_code" {
                envelope.result["candidate_fault_codes"]
                    .as_array()
                    .is_some_and(|values| values.iter().any(|candidate| candidate == value))
            } else {
                envelope.result.get(field) == Some(value)
            };
            (matched + u64::from(field_matches), total + 1)
        })
}

fn rate(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len().saturating_sub(1))
        .saturating_mul(percentile)
        .div_ceil(100);
    sorted[index.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_core::{ExecutionNode, ProvenanceId, RetryPolicy, SkillId};
    use std::fmt::Debug;

    fn ok<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("test fixture must be valid: {error:?}"),
        }
    }

    fn some<T>(value: Option<T>, label: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("expected {label}"),
        }
    }

    fn descriptor(id: &str, memory: u64, package_size: u64) -> ExecutorDescriptor {
        ExecutorDescriptor {
            id: id.to_owned(),
            version: "1.0.0".to_owned(),
            kind: ExecutorKind::Search,
            abi: "d2i-rust-executor-v1".to_owned(),
            capabilities: vec!["retrieve".to_owned()],
            input_schemas: vec!["request".to_owned()],
            output_schemas: vec!["candidates".to_owned()],
            targets: vec![TargetSupport {
                os: "any".to_owned(),
                arch: "any".to_owned(),
            }],
            resource_profile: ResourceProfile {
                resident_memory_bytes: memory,
                cold_start_us: 10,
                package_size_bytes: package_size,
                deterministic: true,
            },
            security: SecurityProfile {
                network: false,
                side_effects: false,
            },
            license: LicenseInfo {
                id: "Apache-2.0".to_owned(),
            },
            artifact: ArtifactInfo {
                path: format!("executors/{id}"),
                sha256: format!("sha256:{}", "a".repeat(64)),
            },
        }
    }

    fn benchmark(
        id: &str,
        success: f64,
        critical_error: f64,
        latency: u64,
        copies: u64,
    ) -> BenchmarkProfile {
        BenchmarkProfile {
            executor_id: id.to_owned(),
            dataset_id: "gold".to_owned(),
            dataset_hash: format!("sha256:{}", "b".repeat(64)),
            case_count: 50,
            task_success_rate: success,
            field_accuracy: success,
            critical_error_rate: critical_error,
            p50_latency_us: latency / 2,
            p95_latency_us: latency,
            p99_latency_us: latency.saturating_mul(2),
            cold_start_us: latency / 10,
            peak_rss_bytes: 1,
            allocated_bytes: 1,
            copy_count: 2,
            copy_bytes: copies,
            repeatability_rate: 1.0,
        }
    }

    fn request() -> SelectionRequest {
        SelectionRequest {
            capability: "retrieve".to_owned(),
            input_schema: "request".to_owned(),
            output_schema: "candidates".to_owned(),
            target_os: "linux".to_owned(),
            target_arch: "x86_64".to_owned(),
            max_memory_bytes: 64 * 1024 * 1024,
            min_task_success_rate: 0.95,
            min_field_accuracy: 0.95,
            max_critical_error_rate: 0.0,
            min_repeatability_rate: 1.0,
            network_allowed: false,
            side_effects_allowed: false,
        }
    }

    fn candidates() -> (Vec<ExecutorDescriptor>, Vec<BenchmarkProfile>) {
        (
            vec![
                descriptor("compact", 1024, 1024),
                descriptor("fast", 8192, 8192),
                descriptor("low-quality", 512, 512),
            ],
            vec![
                benchmark("compact", 0.96, 0.0, 12_000, 2048),
                benchmark("fast", 0.98, 0.0, 4_000, 4096),
                benchmark("low-quality", 0.80, 0.02, 1_000, 1024),
            ],
        )
    }

    fn graph_node(
        id: &str,
        kind: NodeKind,
        executor: Option<&str>,
        provenance_id: &ProvenanceId,
    ) -> ExecutionNode {
        ExecutionNode {
            id: ok(NodeId::new(id)),
            kind,
            input_type: "record".to_owned(),
            output_type: "record".to_owned(),
            timeout_ms: 100,
            expected_memory_bytes: 1024,
            executor_id: executor.map(|id| ok(ExecutorId::new(id))),
            min_confidence: 0.0,
            failure_target: None,
            retry: RetryPolicy { limit: 0 },
            cache: CachePolicy { cacheable: false },
            side_effect: false,
            parallel_group: None,
            evidence_required: true,
            loop_max_iterations: None,
            provenance_id: provenance_id.clone(),
        }
    }

    fn graph_edge(from: &str, to: &str, provenance_id: &ProvenanceId) -> ExecutionEdge {
        ExecutionEdge {
            from: ok(NodeId::new(from)),
            to: ok(NodeId::new(to)),
            kind: EdgeKind::Success,
            condition: None,
            provenance_id: provenance_id.clone(),
        }
    }

    #[test]
    fn quality_gates_precede_pareto_cost_selection() {
        let (descriptors, benchmarks) = candidates();
        let report = select_executor(
            &request(),
            &descriptors,
            &benchmarks,
            &SelectionConfig::default(),
        );

        assert_eq!(report.selected.as_deref(), Some("compact"));
        assert_eq!(report.pareto_front, vec!["compact", "fast"]);
        assert!(report.rejected.iter().any(|rejection| {
            rejection.executor_id == "low-quality"
                && rejection
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("task success"))
        }));
    }

    #[test]
    fn target_costs_and_forced_bindings_change_only_safe_selection() {
        let (descriptors, benchmarks) = candidates();
        let mut latency_config = SelectionConfig {
            weights: CostWeights {
                latency: 10.0,
                memory: 0.01,
                package_size: 0.01,
                cold_start: 1.0,
                copies: 0.01,
            },
            ..SelectionConfig::default()
        };
        let latency_report =
            select_executor(&request(), &descriptors, &benchmarks, &latency_config);
        assert_eq!(latency_report.selected.as_deref(), Some("fast"));

        latency_config
            .forced_bindings
            .insert("retrieve".to_owned(), "low-quality".to_owned());
        let forced_report = select_executor(&request(), &descriptors, &benchmarks, &latency_config);
        assert!(forced_report.forced);
        assert!(forced_report.selected.is_none());
        assert!(forced_report
            .explanation
            .contains("failed hard constraints"));
    }

    #[test]
    fn small_first_cascade_preserves_selected_executor_as_fallback() {
        let (descriptors, benchmarks) = candidates();
        let descriptor_map = descriptors
            .iter()
            .cloned()
            .map(|descriptor| (descriptor.id.clone(), descriptor))
            .collect::<BTreeMap<_, _>>();
        let config = SelectionConfig {
            small_first_cascade: true,
            weights: CostWeights {
                latency: 10.0,
                memory: 0.01,
                package_size: 0.01,
                cold_start: 1.0,
                copies: 0.01,
            },
            ..SelectionConfig::default()
        };
        let report = select_executor(&request(), &descriptors, &benchmarks, &config);
        let provenance_id = ok(ProvenanceId::new("p000001"));
        let selected_node = ok(NodeId::new("retrieve"));
        let return_node = ok(NodeId::new("return"));
        let mut graph = ExecutionGraph {
            skill_id: ok(SkillId::new("diagnose")),
            entry_node: selected_node.clone(),
            nodes: vec![
                ExecutionNode {
                    id: selected_node.clone(),
                    kind: NodeKind::Retrieve,
                    input_type: "request".to_owned(),
                    output_type: "candidates".to_owned(),
                    timeout_ms: 100,
                    expected_memory_bytes: 8192,
                    executor_id: Some(ok(ExecutorId::new("fast"))),
                    min_confidence: 0.0,
                    failure_target: None,
                    retry: RetryPolicy { limit: 0 },
                    cache: CachePolicy { cacheable: false },
                    side_effect: false,
                    parallel_group: None,
                    evidence_required: true,
                    loop_max_iterations: None,
                    provenance_id: provenance_id.clone(),
                },
                ExecutionNode {
                    id: return_node.clone(),
                    kind: NodeKind::Return,
                    input_type: "candidates".to_owned(),
                    output_type: "response".to_owned(),
                    timeout_ms: 100,
                    expected_memory_bytes: 0,
                    executor_id: None,
                    min_confidence: 0.0,
                    failure_target: None,
                    retry: RetryPolicy { limit: 0 },
                    cache: CachePolicy { cacheable: false },
                    side_effect: false,
                    parallel_group: None,
                    evidence_required: true,
                    loop_max_iterations: None,
                    provenance_id: provenance_id.clone(),
                },
            ],
            edges: vec![ExecutionEdge {
                from: selected_node.clone(),
                to: return_node.clone(),
                kind: EdgeKind::Success,
                condition: None,
                provenance_id,
            }],
        };
        let selection = BTreeMap::from([("diagnose:retrieve".to_owned(), report)]);

        let optimization = optimize_graph(&mut graph, &descriptor_map, &selection, &config);

        let primary = some(
            graph.nodes.iter().find(|node| node.id == selected_node),
            "primary node",
        );
        let fallback = some(
            graph
                .nodes
                .iter()
                .find(|node| node.id.as_str() == "retrieve-fallback"),
            "fallback node",
        );
        assert_eq!(
            primary.executor_id.as_ref().map(ExecutorId::as_str),
            Some("compact")
        );
        assert_eq!(
            fallback.executor_id.as_ref().map(ExecutorId::as_str),
            Some("fast")
        );
        assert!(optimization
            .actions
            .iter()
            .any(|action| action.pass == "small_first_cascade"));
        assert!(graph.validate().is_empty());
    }

    #[test]
    fn typed_graph_passes_record_each_supported_optimization() {
        let provenance_id = ok(ProvenanceId::new("p000001"));
        let mut normalize = descriptor("normalize", 512, 512);
        normalize.kind = ExecutorKind::Lookup;
        let mut constant = descriptor("constant", 128, 128);
        constant.kind = ExecutorKind::Constant;
        let descriptors = BTreeMap::from([
            (normalize.id.clone(), normalize),
            (constant.id.clone(), constant),
        ]);
        let mut graph = ExecutionGraph {
            skill_id: ok(SkillId::new("optimize")),
            entry_node: ok(NodeId::new("input")),
            nodes: vec![
                graph_node("input", NodeKind::ReadInput, None, &provenance_id),
                graph_node(
                    "normalize-a",
                    NodeKind::Normalize,
                    Some("normalize"),
                    &provenance_id,
                ),
                graph_node(
                    "normalize-b",
                    NodeKind::Normalize,
                    Some("normalize"),
                    &provenance_id,
                ),
                graph_node(
                    "lookup-a",
                    NodeKind::Lookup,
                    Some("constant"),
                    &provenance_id,
                ),
                graph_node(
                    "lookup-b",
                    NodeKind::Lookup,
                    Some("constant"),
                    &provenance_id,
                ),
                graph_node("native-a", NodeKind::NativeCall, None, &provenance_id),
                graph_node("native-b", NodeKind::NativeCall, None, &provenance_id),
                graph_node("generation", NodeKind::ModelCall, None, &provenance_id),
                graph_node("return", NodeKind::Return, None, &provenance_id),
            ],
            edges: vec![
                graph_edge("input", "normalize-a", &provenance_id),
                graph_edge("input", "normalize-b", &provenance_id),
                graph_edge("normalize-a", "lookup-a", &provenance_id),
                graph_edge("normalize-b", "lookup-b", &provenance_id),
                graph_edge("lookup-a", "native-a", &provenance_id),
                graph_edge("lookup-a", "native-b", &provenance_id),
                graph_edge("native-a", "generation", &provenance_id),
                graph_edge("generation", "return", &provenance_id),
                graph_edge("native-b", "return", &provenance_id),
            ],
        };

        let report = optimize_graph(
            &mut graph,
            &descriptors,
            &BTreeMap::new(),
            &SelectionConfig::default(),
        );
        let passes = report
            .actions
            .iter()
            .map(|action| action.pass.as_str())
            .collect::<BTreeSet<_>>();

        for expected in [
            "cache_annotation",
            "common_preprocessing",
            "constant_folding",
            "duplicate_lookup_removal",
            "parallelization",
            "unnecessary_generation_removal",
        ] {
            assert!(
                passes.contains(expected),
                "missing optimizer pass {expected}"
            );
        }
        assert!(graph.validate().is_empty());
    }
}
