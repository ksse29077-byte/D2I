//! Stable Rust contracts shared by D2I runtime implementations and executors.

use d2i_core::{ExecutorId, NodeId, SkillId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Terminal status for one runtime decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Success,
    HumanReview,
    Denied,
    Unsupported,
    Timeout,
    Failed,
}

/// Policy outcome carried by every decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyResult {
    pub allowed: bool,
    pub reason: String,
    pub human_review_required: bool,
}

/// Source-addressed evidence emitted by an executor or policy node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: String,
    pub span: String,
    pub provenance_id: String,
    pub content_hash: String,
}

/// Per-node timing and outcome record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleTiming {
    pub node_id: String,
    pub module_id: String,
    pub duration_micros: u64,
    pub attempts: u32,
    pub status: DecisionStatus,
}

/// Complete auditable result returned by a runtime.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEnvelope {
    pub request_id: String,
    pub build_id: String,
    pub package_content_hash: String,
    pub skill_id: String,
    pub status: DecisionStatus,
    pub result: Value,
    pub module_ids: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub confidence: f64,
    pub policy: PolicyResult,
    pub timings: Vec<ModuleTiming>,
    pub warnings: Vec<String>,
    pub replay_key: String,
}

impl DecisionEnvelope {
    /// Computes a timing-independent digest for deterministic replay checks.
    #[must_use]
    pub fn decision_hash(&self) -> String {
        let canonical = serde_json::json!({
            "request_id": self.request_id,
            "build_id": self.build_id,
            "package_content_hash": self.package_content_hash,
            "skill_id": self.skill_id,
            "status": self.status,
            "result": self.result,
            "module_ids": self.module_ids,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "policy": self.policy,
            "warnings": self.warnings,
            "replay_key": self.replay_key,
        });
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        format!("sha256:{:x}", Sha256::digest(bytes))
    }
}

/// Immutable context and deadline for one task.
#[derive(Debug, Clone)]
pub struct TaskContext {
    request_id: String,
    skill_id: SkillId,
    started: Instant,
    deadline: Instant,
    labels: BTreeMap<String, String>,
}

impl TaskContext {
    /// Creates a local task context with a bounded deadline.
    pub fn new(
        request_id: impl Into<String>,
        skill_id: SkillId,
        timeout: Duration,
    ) -> Result<Self, RuntimeError> {
        if timeout.is_zero() {
            return Err(RuntimeError::InvalidRequest(
                "task timeout must be greater than zero".to_owned(),
            ));
        }
        let started = Instant::now();
        let deadline = started.checked_add(timeout).ok_or_else(|| {
            RuntimeError::InvalidRequest("task timeout exceeds clock range".to_owned())
        })?;
        Ok(Self {
            request_id: request_id.into(),
            skill_id,
            started,
            deadline,
            labels: BTreeMap::new(),
        })
    }

    /// Adds a deterministic access or routing label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Returns the caller-visible request identifier.
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Returns the compiled skill selected for this task.
    #[must_use]
    pub fn skill_id(&self) -> &SkillId {
        &self.skill_id
    }

    /// Returns wall-clock time elapsed since context creation.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Returns time remaining before the task deadline.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline.checked_duration_since(Instant::now())
    }

    /// Returns deterministic access and routing labels.
    #[must_use]
    pub fn labels(&self) -> &BTreeMap<String, String> {
        &self.labels
    }
}

/// Owned input passed to one executor invocation.
#[derive(Debug, Clone)]
pub struct ExecutorRequest {
    pub node_id: NodeId,
    pub payload: Value,
}

/// Successful executor output merged into scheduler state.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutorOutput {
    pub payload: Value,
    pub confidence: f64,
    pub evidence: Vec<Evidence>,
    pub warnings: Vec<String>,
}

/// Versioned runtime executor contract.
pub trait Executor: Send + Sync {
    /// Returns the package-visible executor identifier.
    fn id(&self) -> &ExecutorId;
    /// Executes one owned node request without external network access.
    fn execute(
        &self,
        context: &TaskContext,
        request: ExecutorRequest,
    ) -> Result<ExecutorOutput, RuntimeError>;
}

/// Deterministic registry of executor implementations.
#[derive(Default)]
pub struct ExecutorRegistry {
    executors: BTreeMap<ExecutorId, Arc<dyn Executor>>,
}

impl ExecutorRegistry {
    /// Creates an empty deterministic registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one executor and rejects duplicate identifiers.
    pub fn register(&mut self, executor: Arc<dyn Executor>) -> Result<(), RuntimeError> {
        let id = executor.id().clone();
        if self.executors.insert(id.clone(), executor).is_some() {
            return Err(RuntimeError::DuplicateExecutor(id.to_string()));
        }
        Ok(())
    }

    /// Looks up one executor using its typed identifier.
    #[must_use]
    pub fn get(&self, id: &ExecutorId) -> Option<Arc<dyn Executor>> {
        self.executors.get(id).cloned()
    }

    /// Returns executor identifiers in deterministic order.
    pub fn ids(&self) -> impl Iterator<Item = &ExecutorId> {
        self.executors.keys()
    }
}

/// Replay record persisted by the runtime CLI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayRecord {
    pub request: Value,
    pub envelope: DecisionEnvelope,
}

/// Result of re-executing a recorded local request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayReport {
    pub matched: bool,
    pub expected_decision_hash: String,
    pub actual_decision_hash: String,
    pub envelope: DecisionEnvelope,
}

/// Runtime execution contract.
pub trait Runtime {
    /// Executes a validated request using the context's selected skill.
    fn execute(
        &self,
        context: TaskContext,
        request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError>;

    /// Re-executes a package-bound record and compares decision identity.
    fn replay(&self, record: &ReplayRecord) -> Result<ReplayReport, RuntimeError>;
}

/// Package-loader contract implemented by reference and proprietary runtimes.
pub trait PackageLoader {
    type Package;

    /// Verifies and loads a package from a local path.
    fn load(&self, path: &Path) -> Result<Self::Package, RuntimeError>;
}

/// Structured reference-runtime failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeError {
    Package(String),
    IncompatibleTarget(String),
    MissingExecutor(String),
    DuplicateExecutor(String),
    InvalidRequest(String),
    UnsupportedSkill(String),
    Graph(String),
    Executor {
        executor_id: String,
        message: String,
    },
    Timeout {
        node_id: String,
        timeout_ms: u64,
    },
    ReplayMismatch(String),
    AdapterUnavailable(String),
    AdapterProtocol(String),
    Io {
        path: String,
        message: String,
    },
}

impl Display for RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Package(message) => write!(formatter, "package load failed: {message}"),
            Self::IncompatibleTarget(message) => {
                write!(formatter, "incompatible runtime target: {message}")
            }
            Self::MissingExecutor(id) => write!(formatter, "executor '{id}' is not registered"),
            Self::DuplicateExecutor(id) => write!(formatter, "executor '{id}' is duplicated"),
            Self::InvalidRequest(message) => write!(formatter, "invalid request: {message}"),
            Self::UnsupportedSkill(id) => write!(formatter, "unsupported skill '{id}'"),
            Self::Graph(message) => write!(formatter, "execution graph failed: {message}"),
            Self::Executor {
                executor_id,
                message,
            } => write!(formatter, "executor '{executor_id}' failed: {message}"),
            Self::Timeout {
                node_id,
                timeout_ms,
            } => write!(
                formatter,
                "execution node '{node_id}' exceeded {timeout_ms} ms"
            ),
            Self::ReplayMismatch(message) => write!(formatter, "replay mismatch: {message}"),
            Self::AdapterUnavailable(message) => {
                write!(formatter, "runtime adapter is unavailable: {message}")
            }
            Self::AdapterProtocol(message) => {
                write!(formatter, "runtime adapter protocol failed: {message}")
            }
            Self::Io { path, message } => write!(formatter, "I/O error at {path}: {message}"),
        }
    }
}

impl Error for RuntimeError {}

/// Stable adapter-facing error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeErrorCode {
    Package,
    IncompatibleTarget,
    MissingExecutor,
    DuplicateExecutor,
    InvalidRequest,
    UnsupportedSkill,
    Graph,
    Executor,
    Timeout,
    ReplayMismatch,
    AdapterUnavailable,
    AdapterProtocol,
    Io,
}

impl RuntimeError {
    /// Maps detailed runtime failures to a stable adapter error category.
    #[must_use]
    pub const fn code(&self) -> RuntimeErrorCode {
        match self {
            Self::Package(_) => RuntimeErrorCode::Package,
            Self::IncompatibleTarget(_) => RuntimeErrorCode::IncompatibleTarget,
            Self::MissingExecutor(_) => RuntimeErrorCode::MissingExecutor,
            Self::DuplicateExecutor(_) => RuntimeErrorCode::DuplicateExecutor,
            Self::InvalidRequest(_) => RuntimeErrorCode::InvalidRequest,
            Self::UnsupportedSkill(_) => RuntimeErrorCode::UnsupportedSkill,
            Self::Graph(_) => RuntimeErrorCode::Graph,
            Self::Executor { .. } => RuntimeErrorCode::Executor,
            Self::Timeout { .. } => RuntimeErrorCode::Timeout,
            Self::ReplayMismatch(_) => RuntimeErrorCode::ReplayMismatch,
            Self::AdapterUnavailable(_) => RuntimeErrorCode::AdapterUnavailable,
            Self::AdapterProtocol(_) => RuntimeErrorCode::AdapterProtocol,
            Self::Io { .. } => RuntimeErrorCode::Io,
        }
    }
}
