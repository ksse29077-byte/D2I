use crate::executors::deduplicate_evidence;
use crate::package::RuntimePackage;
use d2i_core::{ExecutorId, NodeId};
use d2i_runtime_api::{
    DecisionEnvelope, DecisionStatus, Evidence, ExecutorOutput, ExecutorRegistry, ExecutorRequest,
    ModuleTiming, PolicyResult, RuntimeError, TaskContext,
};
use d2i_schema::d2i::package as fb;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct BranchState {
    payload: Value,
    confidence: f64,
    status: DecisionStatus,
}

struct NodeResult {
    node_id: String,
    module_id: String,
    payload: Value,
    confidence: f64,
    evidence: Vec<Evidence>,
    warnings: Vec<String>,
    timing: ModuleTiming,
    succeeded: bool,
    status: DecisionStatus,
    policy: Option<PolicyResult>,
}

/// Deterministic DAG scheduler used by the reference runtime.
pub struct Scheduler {
    package: Arc<RuntimePackage>,
    registry: Arc<ExecutorRegistry>,
}

impl Scheduler {
    #[must_use]
    pub fn new(package: Arc<RuntimePackage>, registry: Arc<ExecutorRegistry>) -> Self {
        Self { package, registry }
    }

    /// Executes one compiled skill graph and records every activated node.
    pub fn execute(
        &self,
        context: TaskContext,
        request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        let skill_id = context.skill_id().to_string();
        let graph = self
            .package
            .graph(&skill_id)
            .ok_or_else(|| RuntimeError::UnsupportedSkill(skill_id.clone()))?
            .clone();
        let nodes = graph
            .nodes
            .iter()
            .cloned()
            .map(|node| (node.id.clone(), node))
            .collect::<BTreeMap<_, _>>();
        let mut pending = BTreeMap::<String, Vec<BranchState>>::new();
        pending.insert(
            graph.entry_node.clone(),
            vec![BranchState {
                payload: request.clone(),
                confidence: 0.0,
                status: DecisionStatus::Success,
            }],
        );

        let mut completed = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut warnings = Vec::new();
        let mut timings = Vec::new();
        let mut module_ids = Vec::new();
        let mut terminal_states = Vec::new();
        let mut terminal_status = DecisionStatus::Success;
        let mut policy = PolicyResult {
            allowed: true,
            reason: "no restricted action requested".to_owned(),
            human_review_required: false,
        };

        while !pending.is_empty() {
            let ready_ids = pending
                .iter()
                .filter_map(|(id, inputs)| {
                    let node = nodes.get(id)?;
                    let required = if node.kind == fb::NodeKind::Join {
                        incoming_count(&graph, id)
                    } else {
                        1
                    };
                    (inputs.len() >= required).then_some(id.clone())
                })
                .collect::<Vec<_>>();
            if ready_ids.is_empty() {
                return Err(RuntimeError::Graph(
                    "scheduler cannot satisfy a join dependency".to_owned(),
                ));
            }

            let mut jobs = Vec::new();
            for id in ready_ids {
                let inputs = pending.remove(&id).unwrap_or_default();
                if !completed.insert(id.clone()) {
                    return Err(RuntimeError::Graph(format!(
                        "node '{id}' was scheduled more than once"
                    )));
                }
                let node = nodes
                    .get(&id)
                    .cloned()
                    .ok_or_else(|| RuntimeError::Graph(format!("node '{id}' is missing")))?;
                let state = merge_states(inputs);
                jobs.push((node, state));
            }
            jobs.sort_by(|left, right| left.0.id.cmp(&right.0.id));

            let mut results = Vec::new();
            std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for (node, state) in jobs {
                    let package = self.package.clone();
                    let registry = self.registry.clone();
                    let task = context.clone();
                    let prior_evidence = evidence.clone();
                    handles.push(scope.spawn(move || {
                        execute_node(&package, &registry, &task, &node, state, &prior_evidence)
                    }));
                }
                for handle in handles {
                    match handle.join() {
                        Ok(result) => results.push(result),
                        Err(_) => results.push(Err(RuntimeError::Graph(
                            "scheduler worker panicked".to_owned(),
                        ))),
                    }
                }
            });

            let mut results = results.into_iter().collect::<Result<Vec<_>, _>>()?;
            results.sort_by(|left, right| left.node_id.cmp(&right.node_id));
            for result in results {
                let targets = selected_targets(&graph, &nodes, &result);
                if result.module_id.starts_with("executor:") {
                    let id = result.module_id.trim_start_matches("executor:").to_owned();
                    if !module_ids.contains(&id) {
                        module_ids.push(id);
                    }
                }
                evidence.extend(result.evidence.clone());
                warnings.extend(result.warnings.clone());
                timings.push(result.timing);
                if let Some(outcome) = result.policy {
                    policy = outcome;
                }

                if targets.is_empty() {
                    terminal_status = combine_status(terminal_status, result.status);
                    terminal_states.push(BranchState {
                        payload: result.payload,
                        confidence: result.confidence,
                        status: result.status,
                    });
                    continue;
                }
                for target in targets {
                    pending.entry(target).or_default().push(BranchState {
                        payload: result.payload.clone(),
                        confidence: result.confidence,
                        status: result.status,
                    });
                }
            }
            if completed.len() > nodes.len() {
                return Err(RuntimeError::Graph(
                    "scheduler exceeded the graph node bound".to_owned(),
                ));
            }
        }

        if terminal_states.is_empty() {
            return Err(RuntimeError::Graph(
                "execution graph produced no terminal result".to_owned(),
            ));
        }
        let final_state = merge_states(terminal_states);
        terminal_status = combine_status(terminal_status, final_state.status);
        deduplicate_evidence(&mut evidence);
        warnings.sort();
        warnings.dedup();
        let confidence = final_state.confidence.clamp(0.0, 1.0);
        let replay_key = replay_key(
            &self.package.summary().package_content_hash,
            &skill_id,
            &request,
        );
        Ok(DecisionEnvelope {
            request_id: context.request_id().to_owned(),
            build_id: self.package.summary().build_id.clone(),
            package_content_hash: self.package.summary().package_content_hash.clone(),
            skill_id,
            status: terminal_status,
            result: public_result(final_state.payload),
            module_ids,
            evidence,
            confidence,
            policy,
            timings,
            warnings,
            replay_key,
        })
    }
}

fn execute_node(
    package: &RuntimePackage,
    registry: &ExecutorRegistry,
    context: &TaskContext,
    node: &fb::ExecutionNode,
    state: BranchState,
    prior_evidence: &[Evidence],
) -> Result<NodeResult, RuntimeError> {
    let started = Instant::now();
    let mut attempts = 1_u32;
    let mut evidence = Vec::new();
    let mut warnings = Vec::new();
    let mut payload = state.payload;
    let mut confidence = state.confidence;
    let mut succeeded = true;
    let mut status = state.status;
    let mut policy = None;
    let module_id;
    if let Some(node_evidence) = package.provenance(&node.provenance_id) {
        evidence.push(node_evidence.clone());
    }

    if let Some(id) = node.executor_id.as_deref() {
        module_id = format!("executor:{id}");
        let typed = ExecutorId::new(id.to_owned())
            .map_err(|error| RuntimeError::MissingExecutor(error.to_string()))?;
        let executor = registry
            .get(&typed)
            .ok_or_else(|| RuntimeError::MissingExecutor(id.to_owned()))?;
        let request_node =
            NodeId::new(node.id.clone()).map_err(|error| RuntimeError::Graph(error.to_string()))?;
        let (result, used_attempts) = execute_with_retries(
            executor,
            context.clone(),
            ExecutorRequest {
                node_id: request_node,
                payload: payload.clone(),
            },
            node.timeout_ms,
            node.retry_limit,
        );
        attempts = used_attempts;
        match result {
            Ok(output) => {
                apply_output(
                    output,
                    &mut payload,
                    &mut confidence,
                    &mut evidence,
                    &mut warnings,
                );
                if node.min_confidence > 0.0 && confidence < node.min_confidence {
                    succeeded = false;
                    status = combine_status(status, DecisionStatus::Failed);
                    warnings.push(format!(
                        "executor confidence {confidence:.3} is below node threshold {:.3}",
                        node.min_confidence
                    ));
                }
            }
            Err(error) => {
                succeeded = false;
                status = combine_status(
                    status,
                    if matches!(error, RuntimeError::Timeout { .. }) {
                        DecisionStatus::Timeout
                    } else {
                        DecisionStatus::Failed
                    },
                );
                warnings.push(error.to_string());
            }
        }
    } else {
        module_id = format!("builtin:{:?}", node.kind).to_ascii_lowercase();
        match node.kind {
            fb::NodeKind::PolicyGate => {
                let threshold = package
                    .policies()
                    .confidence_thresholds
                    .iter()
                    .find(|item| item.skill_id == context.skill_id().as_str())
                    .map_or(node.min_confidence, |item| {
                        item.minimum.max(node.min_confidence)
                    });
                let has_evidence = !prior_evidence.is_empty() || !evidence.is_empty();
                let allowed = confidence >= threshold && (!node.evidence_required || has_evidence);
                succeeded = allowed;
                policy = Some(PolicyResult {
                    allowed,
                    reason: if allowed {
                        format!("confidence {confidence:.3} meets threshold {threshold:.3}")
                    } else {
                        format!(
                            "confidence {confidence:.3} or evidence does not meet policy threshold {threshold:.3}"
                        )
                    },
                    human_review_required: !allowed,
                });
                if !allowed {
                    status = combine_status(status, DecisionStatus::Denied);
                }
            }
            fb::NodeKind::HumanReview => {
                set_human_review(&mut payload);
                status = combine_status(status, DecisionStatus::HumanReview);
                warnings.push("decision requires human review".to_owned());
                policy = Some(PolicyResult {
                    allowed: false,
                    reason: "policy fallback requires human review".to_owned(),
                    human_review_required: true,
                });
            }
            _ => {}
        }
    }

    let duration_micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    Ok(NodeResult {
        node_id: node.id.clone(),
        module_id: module_id.clone(),
        payload,
        confidence,
        evidence,
        warnings,
        timing: ModuleTiming {
            node_id: node.id.clone(),
            module_id,
            duration_micros,
            attempts,
            status,
        },
        succeeded,
        status,
        policy,
    })
}

fn execute_with_timeout(
    executor: Arc<dyn d2i_runtime_api::Executor>,
    context: TaskContext,
    request: ExecutorRequest,
    node_timeout_ms: u32,
) -> Result<ExecutorOutput, RuntimeError> {
    let remaining = context.remaining().ok_or_else(|| RuntimeError::Timeout {
        node_id: request.node_id.to_string(),
        timeout_ms: 0,
    })?;
    let node_timeout = Duration::from_millis(u64::from(node_timeout_ms.max(1)));
    let timeout = remaining.min(node_timeout);
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let node_id = request.node_id.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = executor.execute(&context, request);
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(RuntimeError::Timeout {
            node_id,
            timeout_ms,
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(RuntimeError::Graph(
            "executor worker disconnected".to_owned(),
        )),
    }
}

fn execute_with_retries(
    executor: Arc<dyn d2i_runtime_api::Executor>,
    context: TaskContext,
    request: ExecutorRequest,
    node_timeout_ms: u32,
    retry_limit: u32,
) -> (Result<ExecutorOutput, RuntimeError>, u32) {
    let mut last_error = RuntimeError::Graph("executor was not attempted".to_owned());
    for attempt in 0..=retry_limit {
        match execute_with_timeout(
            executor.clone(),
            context.clone(),
            request.clone(),
            node_timeout_ms,
        ) {
            Ok(output) => return (Ok(output), attempt.saturating_add(1)),
            Err(error) => last_error = error,
        }
    }
    (Err(last_error), retry_limit.saturating_add(1))
}

fn apply_output(
    output: ExecutorOutput,
    payload: &mut Value,
    confidence: &mut f64,
    evidence: &mut Vec<Evidence>,
    warnings: &mut Vec<String>,
) {
    *payload = output.payload;
    *confidence = output.confidence.clamp(0.0, 1.0);
    evidence.extend(output.evidence);
    warnings.extend(output.warnings);
}

fn selected_targets(
    graph: &fb::ExecutionGraph,
    nodes: &BTreeMap<String, fb::ExecutionNode>,
    result: &NodeResult,
) -> Vec<String> {
    let mut targets = graph
        .edges
        .iter()
        .filter(|edge| edge.from == result.node_id)
        .filter(|edge| {
            if result.succeeded {
                match edge.kind {
                    fb::EdgeKind::Success | fb::EdgeKind::Parallel | fb::EdgeKind::Join => true,
                    fb::EdgeKind::BranchTrue => branch_value(&result.payload),
                    fb::EdgeKind::BranchFalse => !branch_value(&result.payload),
                    fb::EdgeKind::Failure => false,
                }
            } else {
                edge.kind == fb::EdgeKind::Failure
            }
        })
        .map(|edge| edge.to.clone())
        .collect::<Vec<_>>();
    if targets.is_empty() && !result.succeeded {
        if let Some(target) = nodes
            .get(&result.node_id)
            .and_then(|node| node.failure_target.clone())
        {
            targets.push(target);
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn branch_value(payload: &Value) -> bool {
    payload
        .get("_branch")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn incoming_count(graph: &fb::ExecutionGraph, target: &str) -> usize {
    graph
        .edges
        .iter()
        .filter(|edge| edge.to == target)
        .count()
        .max(1)
}

fn merge_states(states: Vec<BranchState>) -> BranchState {
    let mut payload = Map::new();
    let mut confidence = 1.0_f64;
    let mut status = DecisionStatus::Success;
    for state in states {
        confidence = confidence.min(state.confidence);
        status = combine_status(status, state.status);
        if let Value::Object(values) = state.payload {
            for (key, value) in values {
                payload.insert(key, value);
            }
        }
    }
    let confidence = if confidence == 1.0 && payload.is_empty() {
        0.0
    } else {
        confidence
    };
    BranchState {
        payload: Value::Object(payload),
        confidence,
        status,
    }
}

fn set_human_review(payload: &mut Value) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("human_review".to_owned(), Value::Bool(true));
    }
}

fn public_result(mut payload: Value) -> Value {
    if let Some(object) = payload.as_object_mut() {
        object.retain(|key, _| !key.starts_with('_'));
    }
    payload
}

fn combine_status(current: DecisionStatus, candidate: DecisionStatus) -> DecisionStatus {
    use DecisionStatus::{Denied, Failed, HumanReview, Success, Timeout, Unsupported};
    match (current, candidate) {
        (Failed, _) | (_, Failed) => Failed,
        (Timeout, _) | (_, Timeout) => Timeout,
        (HumanReview, _) | (_, HumanReview) => HumanReview,
        (Denied, _) | (_, Denied) => Denied,
        (Unsupported, _) | (_, Unsupported) => Unsupported,
        _ => Success,
    }
}

fn replay_key(package_hash: &str, skill_id: &str, request: &Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"d2i-replay-v1\0");
    for bytes in [
        package_hash.as_bytes(),
        skill_id.as_bytes(),
        &serde_json::to_vec(request).unwrap_or_default(),
    ] {
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_core::{ExecutorId, SkillId};
    use d2i_runtime_api::{Executor, ExecutorOutput};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    struct SlowExecutor {
        id: ExecutorId,
    }

    struct FlakyExecutor {
        id: ExecutorId,
        calls: AtomicUsize,
    }

    impl Executor for FlakyExecutor {
        fn id(&self) -> &ExecutorId {
            &self.id
        }

        fn execute(
            &self,
            _context: &TaskContext,
            request: ExecutorRequest,
        ) -> Result<ExecutorOutput, RuntimeError> {
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                return Err(RuntimeError::Executor {
                    executor_id: self.id.to_string(),
                    message: "transient failure".to_owned(),
                });
            }
            Ok(ExecutorOutput {
                payload: request.payload,
                confidence: 1.0,
                evidence: Vec::new(),
                warnings: Vec::new(),
            })
        }
    }

    impl Executor for SlowExecutor {
        fn id(&self) -> &ExecutorId {
            &self.id
        }

        fn execute(
            &self,
            _context: &TaskContext,
            request: ExecutorRequest,
        ) -> Result<ExecutorOutput, RuntimeError> {
            thread::sleep(Duration::from_millis(30));
            Ok(ExecutorOutput {
                payload: request.payload,
                confidence: 1.0,
                evidence: Vec::new(),
                warnings: Vec::new(),
            })
        }
    }

    #[test]
    fn executor_timeout_is_bounded() {
        let executor: Arc<dyn Executor> = Arc::new(SlowExecutor {
            id: ExecutorId::new("slow").unwrap_or_else(|error| panic!("{error}")),
        });
        let context = TaskContext::new(
            "timeout",
            SkillId::new("skill").unwrap_or_else(|error| panic!("{error}")),
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let request = ExecutorRequest {
            node_id: NodeId::new("slow-node").unwrap_or_else(|error| panic!("{error}")),
            payload: Value::Object(Map::new()),
        };
        assert!(matches!(
            execute_with_timeout(executor, context, request, 1),
            Err(RuntimeError::Timeout { .. })
        ));
    }

    #[test]
    fn bounded_retry_stops_after_success() {
        let executor: Arc<dyn Executor> = Arc::new(FlakyExecutor {
            id: ExecutorId::new("flaky").unwrap_or_else(|error| panic!("{error}")),
            calls: AtomicUsize::new(0),
        });
        let context = TaskContext::new(
            "retry",
            SkillId::new("skill").unwrap_or_else(|error| panic!("{error}")),
            Duration::from_secs(1),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let request = ExecutorRequest {
            node_id: NodeId::new("retry-node").unwrap_or_else(|error| panic!("{error}")),
            payload: Value::Object(Map::new()),
        };
        let (result, attempts) = execute_with_retries(executor, context, request, 100, 2);
        assert!(result.is_ok());
        assert_eq!(attempts, 2);
    }

    #[test]
    fn failure_and_parallel_edges_select_expected_targets() {
        let nodes = ["source", "fallback", "left", "right"]
            .into_iter()
            .map(|id| {
                (
                    id.to_owned(),
                    fb::ExecutionNode {
                        id: id.to_owned(),
                        ..Default::default()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let graph = fb::ExecutionGraph {
            edges: vec![
                edge("source", "fallback", fb::EdgeKind::Failure),
                edge("source", "left", fb::EdgeKind::Parallel),
                edge("source", "right", fb::EdgeKind::Parallel),
            ],
            ..Default::default()
        };
        let failure = node_result(false);
        assert_eq!(
            selected_targets(&graph, &nodes, &failure),
            vec!["fallback".to_owned()]
        );
        let success = node_result(true);
        assert_eq!(
            selected_targets(&graph, &nodes, &success),
            vec!["left".to_owned(), "right".to_owned()]
        );
    }

    fn edge(from: &str, to: &str, kind: fb::EdgeKind) -> fb::ExecutionEdge {
        fb::ExecutionEdge {
            from: from.to_owned(),
            to: to.to_owned(),
            kind,
            ..Default::default()
        }
    }

    fn node_result(succeeded: bool) -> NodeResult {
        NodeResult {
            node_id: "source".to_owned(),
            module_id: "test".to_owned(),
            payload: Value::Object(Map::new()),
            confidence: 0.0,
            evidence: Vec::new(),
            warnings: Vec::new(),
            timing: ModuleTiming {
                node_id: "source".to_owned(),
                module_id: "test".to_owned(),
                duration_micros: 0,
                attempts: 1,
                status: DecisionStatus::Success,
            },
            succeeded,
            status: DecisionStatus::Success,
            policy: None,
        }
    }
}
