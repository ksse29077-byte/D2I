//! D2I-facing runtime adapter contracts and conformance tooling.

use d2i_compiler::{load_verified_package, PACKAGE_FORMAT_VERSION, RUNTIME_ABI_VERSION};
use d2i_eval::{ExecutorDescriptor, ExecutorKind};
use d2i_runtime_api::{DecisionEnvelope, Runtime, RuntimeError, RuntimeErrorCode, TaskContext};
use d2i_runtime_ref::ReferenceRuntime;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

/// Version of the safe Rust adapter contract. This is not a native C ABI.
pub const ADAPTER_CONTRACT_VERSION: &str = "0.1.0";

/// Adapter implementation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Mock,
    ProprietaryPlaceholder,
}

/// D2I capabilities declared by an adapter implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterContract {
    pub adapter_id: String,
    pub adapter_version: String,
    pub contract_version: String,
    pub kind: AdapterKind,
    pub supported_package_formats: Vec<String>,
    pub supported_runtime_abis: Vec<String>,
    pub supported_os: Vec<String>,
    pub supported_arch: Vec<String>,
    pub supported_executor_kinds: Vec<ExecutorKind>,
    pub max_resident_memory_bytes: Option<u64>,
    pub network_allowed: bool,
}

impl AdapterContract {
    /// Returns the complete contract used by the in-process mock adapter.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            adapter_id: "d2i-mock-runtime".to_owned(),
            adapter_version: env!("CARGO_PKG_VERSION").to_owned(),
            contract_version: ADAPTER_CONTRACT_VERSION.to_owned(),
            kind: AdapterKind::Mock,
            supported_package_formats: vec![PACKAGE_FORMAT_VERSION.to_owned()],
            supported_runtime_abis: vec![RUNTIME_ABI_VERSION.to_owned()],
            supported_os: vec!["any".to_owned()],
            supported_arch: vec!["any".to_owned()],
            supported_executor_kinds: all_executor_kinds(),
            max_resident_memory_bytes: None,
            network_allowed: false,
        }
    }
}

/// One package compatibility failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityIssue {
    pub code: String,
    pub message: String,
}

/// Reproducible compatibility result for one package and adapter contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub compatible: bool,
    pub adapter_id: String,
    pub build_id: String,
    pub package_format_version: String,
    pub runtime_abi_version: String,
    pub required_executor_ids: Vec<String>,
    pub estimated_resident_memory_bytes: u64,
    pub issues: Vec<CompatibilityIssue>,
}

/// Checks a verified package against declared D2I adapter capabilities.
pub fn check_package_compatibility(
    path: &Path,
    contract: &AdapterContract,
) -> Result<CompatibilityReport, RuntimeError> {
    let package =
        load_verified_package(path).map_err(|error| RuntimeError::Package(error.to_string()))?;
    let descriptors = package
        .artifact("executors/descriptors.json")
        .ok_or_else(|| RuntimeError::Package("executor descriptor registry is missing".to_owned()))
        .and_then(|bytes| {
            serde_json::from_slice::<Vec<ExecutorDescriptor>>(bytes).map_err(|error| {
                RuntimeError::Package(format!("invalid executor descriptor registry: {error}"))
            })
        })?;
    let descriptor_by_id = descriptors
        .into_iter()
        .map(|descriptor| (descriptor.id.clone(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let required_executor_ids = package
        .execution
        .graphs
        .iter()
        .flat_map(|graph| graph.nodes.iter())
        .filter_map(|node| node.executor_id.clone())
        .collect::<BTreeSet<_>>();
    let mut issues = Vec::new();
    if contract.contract_version != ADAPTER_CONTRACT_VERSION {
        push_issue(
            &mut issues,
            "D2I5000",
            format!(
                "adapter contract '{}' is unsupported; expected '{}'",
                contract.contract_version, ADAPTER_CONTRACT_VERSION
            ),
        );
    }
    if !contract
        .supported_package_formats
        .contains(&package.summary.package_format_version)
    {
        push_issue(
            &mut issues,
            "D2I5001",
            format!(
                "package format '{}' is unsupported",
                package.summary.package_format_version
            ),
        );
    }
    if !contract
        .supported_runtime_abis
        .contains(&package.summary.runtime_abi_version)
    {
        push_issue(
            &mut issues,
            "D2I5002",
            format!(
                "runtime ABI '{}' is unsupported",
                package.summary.runtime_abi_version
            ),
        );
    }
    if !target_supported(&contract.supported_os, &package.manifest.target_os) {
        push_issue(
            &mut issues,
            "D2I5003",
            format!("target OS '{}' is unsupported", package.manifest.target_os),
        );
    }
    if !target_supported(&contract.supported_arch, &package.manifest.target_arch) {
        push_issue(
            &mut issues,
            "D2I5004",
            format!(
                "target architecture '{}' is unsupported",
                package.manifest.target_arch
            ),
        );
    }
    if (package.manifest.network_policy != "deny" || package.policies.network_allowed)
        && !contract.network_allowed
    {
        push_issue(
            &mut issues,
            "D2I5005",
            "package network policy exceeds adapter capability",
        );
    }
    let mut estimated_resident_memory_bytes = 0_u64;
    for id in &required_executor_ids {
        let Some(descriptor) = descriptor_by_id.get(id) else {
            push_issue(
                &mut issues,
                "D2I5006",
                format!("selected executor '{id}' has no descriptor"),
            );
            continue;
        };
        estimated_resident_memory_bytes = estimated_resident_memory_bytes
            .saturating_add(descriptor.resource_profile.resident_memory_bytes);
        if !contract.supported_executor_kinds.contains(&descriptor.kind) {
            push_issue(
                &mut issues,
                "D2I5007",
                format!(
                    "executor '{}' uses unsupported kind '{:?}'",
                    descriptor.id, descriptor.kind
                ),
            );
        }
        if descriptor.security.network && !contract.network_allowed {
            push_issue(
                &mut issues,
                "D2I5008",
                format!("executor '{}' requires network access", descriptor.id),
            );
        }
    }
    if contract
        .max_resident_memory_bytes
        .is_some_and(|limit| estimated_resident_memory_bytes > limit)
    {
        push_issue(
            &mut issues,
            "D2I5009",
            format!(
                "estimated executor memory {estimated_resident_memory_bytes} exceeds adapter limit"
            ),
        );
    }
    issues.sort_by(|left, right| (&left.code, &left.message).cmp(&(&right.code, &right.message)));
    Ok(CompatibilityReport {
        compatible: issues.is_empty(),
        adapter_id: contract.adapter_id.clone(),
        build_id: package.summary.build_id,
        package_format_version: package.summary.package_format_version,
        runtime_abi_version: package.summary.runtime_abi_version,
        required_executor_ids: required_executor_ids.into_iter().collect(),
        estimated_resident_memory_bytes,
        issues,
    })
}

/// Package identity returned after adapter load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterPackageInfo {
    pub build_id: String,
    pub package_content_hash: String,
}

/// Safe Rust boundary implemented by mock and future proprietary adapters.
///
/// TODO(proprietary-runtime): map these methods to the documented existing
/// runtime API when that API is supplied. No external handle or call shape is
/// assumed by this contract.
pub trait RuntimeAdapter: Send + Sync {
    fn contract(&self) -> &AdapterContract;
    fn load_package(&mut self, path: &Path) -> Result<AdapterPackageInfo, RuntimeError>;
    fn execute(
        &self,
        context: TaskContext,
        request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError>;
}

/// In-process adapter used to prove the Phase 5 boundary.
pub struct MockRuntimeAdapter {
    contract: AdapterContract,
    runtime: Option<ReferenceRuntime>,
}

impl Default for MockRuntimeAdapter {
    fn default() -> Self {
        Self {
            contract: AdapterContract::mock(),
            runtime: None,
        }
    }
}

impl MockRuntimeAdapter {
    /// Creates an unloaded mock adapter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl RuntimeAdapter for MockRuntimeAdapter {
    fn contract(&self) -> &AdapterContract {
        &self.contract
    }

    fn load_package(&mut self, path: &Path) -> Result<AdapterPackageInfo, RuntimeError> {
        let compatibility = check_package_compatibility(path, &self.contract)?;
        if !compatibility.compatible {
            return Err(RuntimeError::IncompatibleTarget(
                compatibility
                    .issues
                    .iter()
                    .map(|issue| format!("{}: {}", issue.code, issue.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        let runtime = ReferenceRuntime::load(path)?;
        let result = AdapterPackageInfo {
            build_id: runtime.package().summary().build_id.clone(),
            package_content_hash: runtime.package().summary().package_content_hash.clone(),
        };
        self.runtime = Some(runtime);
        Ok(result)
    }

    fn execute(
        &self,
        context: TaskContext,
        request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        self.runtime
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::AdapterUnavailable("mock package is not loaded".to_owned())
            })?
            .execute(context, request)
    }
}

/// Explicit nonfunctional placeholder for the undocumented proprietary API.
pub struct ProprietaryRuntimeAdapterPlaceholder {
    contract: AdapterContract,
}

impl ProprietaryRuntimeAdapterPlaceholder {
    /// Creates a placeholder from capabilities supplied by the integration owner.
    #[must_use]
    pub fn new(contract: AdapterContract) -> Self {
        Self { contract }
    }
}

impl RuntimeAdapter for ProprietaryRuntimeAdapterPlaceholder {
    fn contract(&self) -> &AdapterContract {
        &self.contract
    }

    fn load_package(&mut self, path: &Path) -> Result<AdapterPackageInfo, RuntimeError> {
        let report = check_package_compatibility(path, &self.contract)?;
        if !report.compatible {
            return Err(RuntimeError::IncompatibleTarget(
                "package does not satisfy the declared proprietary adapter contract".to_owned(),
            ));
        }
        Err(RuntimeError::AdapterUnavailable(
            "TODO: bind the documented proprietary runtime package-load API".to_owned(),
        ))
    }

    fn execute(
        &self,
        _context: TaskContext,
        _request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        Err(RuntimeError::AdapterUnavailable(
            "TODO: bind the documented proprietary runtime execute API".to_owned(),
        ))
    }
}

/// One stable error-code mapping at the D2I adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorMapping {
    pub runtime_code: RuntimeErrorCode,
    pub adapter_code: String,
}

/// Concrete Phase 5 mapping without inventing a native or proprietary ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterAbiMapping {
    pub package_runtime_abi_version: String,
    pub adapter_contract_version: String,
    pub request_fields: Vec<String>,
    pub response_fields: Vec<String>,
    pub error_mappings: Vec<ErrorMapping>,
    pub unresolved_external_contracts: Vec<String>,
}

/// Returns the versioned safe-Rust ABI mapping and unresolved external details.
#[must_use]
pub fn phase5_abi_mapping() -> AdapterAbiMapping {
    let error_codes = [
        RuntimeErrorCode::Package,
        RuntimeErrorCode::IncompatibleTarget,
        RuntimeErrorCode::MissingExecutor,
        RuntimeErrorCode::DuplicateExecutor,
        RuntimeErrorCode::InvalidRequest,
        RuntimeErrorCode::UnsupportedSkill,
        RuntimeErrorCode::Graph,
        RuntimeErrorCode::Executor,
        RuntimeErrorCode::Timeout,
        RuntimeErrorCode::ReplayMismatch,
        RuntimeErrorCode::AdapterUnavailable,
        RuntimeErrorCode::AdapterProtocol,
        RuntimeErrorCode::Io,
    ];
    AdapterAbiMapping {
        package_runtime_abi_version: RUNTIME_ABI_VERSION.to_owned(),
        adapter_contract_version: ADAPTER_CONTRACT_VERSION.to_owned(),
        request_fields: vec![
            "request_id".to_owned(),
            "skill_id".to_owned(),
            "deadline".to_owned(),
            "labels".to_owned(),
            "request_json".to_owned(),
        ],
        response_fields: vec![
            "build_id".to_owned(),
            "package_content_hash".to_owned(),
            "status".to_owned(),
            "result".to_owned(),
            "module_ids".to_owned(),
            "evidence".to_owned(),
            "confidence".to_owned(),
            "policy".to_owned(),
            "timings".to_owned(),
            "warnings".to_owned(),
            "replay_key".to_owned(),
        ],
        error_mappings: error_codes
            .into_iter()
            .map(|code| ErrorMapping {
                runtime_code: code,
                adapter_code: runtime_error_code_name(code).to_owned(),
            })
            .collect(),
        unresolved_external_contracts: vec![
            "proprietary package handle and lifetime".to_owned(),
            "proprietary request and response call signatures".to_owned(),
            "proprietary error code table".to_owned(),
            "proprietary cancellation and threading guarantees".to_owned(),
        ],
    }
}

/// Conformance run settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConformanceOptions {
    pub iterations: u32,
    pub timeout: Duration,
}

impl Default for ConformanceOptions {
    fn default() -> Self {
        Self {
            iterations: 1,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Per-vector semantic comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorComparison {
    pub vector_id: String,
    pub output_equal: bool,
    pub output_schema_valid: bool,
    pub error_code_equal: bool,
    pub reference_error: Option<RuntimeErrorCode>,
    pub adapter_error: Option<RuntimeErrorCode>,
}

/// Runtime latency summary collected by the conformance runner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterPerformance {
    pub runs: usize,
    pub p50_latency_us: u64,
    pub p95_latency_us: u64,
    pub p99_latency_us: u64,
}

/// Automated reference-versus-adapter conformance artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdapterConformanceReport {
    pub success: bool,
    pub adapter_id: String,
    pub build_id: String,
    pub case_count: usize,
    pub measured_iterations: u32,
    pub output_schema_match: bool,
    pub error_mapping_match: bool,
    pub vectors: Vec<VectorComparison>,
    pub reference_performance: AdapterPerformance,
    pub adapter_performance: AdapterPerformance,
    pub adapter_to_reference_p95_ratio: Option<f64>,
}

/// Runs identical package vectors through the reference runtime and an adapter.
pub fn run_conformance(
    path: &Path,
    adapter: &mut dyn RuntimeAdapter,
    options: ConformanceOptions,
) -> Result<AdapterConformanceReport, RuntimeError> {
    if options.iterations == 0 || options.iterations > 1_000 || options.timeout.is_zero() {
        return Err(RuntimeError::InvalidRequest(
            "conformance requires 1..=1000 iterations and a positive timeout".to_owned(),
        ));
    }
    let package_info = adapter.load_package(path)?;
    let reference = ReferenceRuntime::load(path)?;
    let cases = reference.package().benchmark_cases()?;
    if cases.is_empty() {
        return Err(RuntimeError::Package(
            "conformance requires bundled evaluation cases".to_owned(),
        ));
    }
    let mut reference_latencies = Vec::new();
    let mut adapter_latencies = Vec::new();
    let mut vectors = Vec::new();
    for iteration in 0..options.iterations {
        for case in &cases {
            let request_id = format!("conformance:{}:{iteration}", case.id);
            let reference_started = Instant::now();
            let reference_result = reference.run(
                &case.skill_id,
                request_id.clone(),
                case.request.clone(),
                options.timeout,
            );
            reference_latencies.push(elapsed_micros(reference_started));
            let context = TaskContext::new(
                request_id,
                d2i_core::SkillId::new(case.skill_id.clone())
                    .map_err(|error| RuntimeError::InvalidRequest(error.to_string()))?,
                options.timeout,
            )?;
            let adapter_started = Instant::now();
            let adapter_result = adapter.execute(context, case.request.clone());
            adapter_latencies.push(elapsed_micros(adapter_started));
            vectors.push(compare_vector(
                &format!("{}:{iteration}", case.id),
                &reference,
                &case.skill_id,
                reference_result,
                adapter_result,
            ));
        }
    }
    vectors.extend(error_vectors(
        &reference,
        adapter,
        &cases[0],
        options.timeout,
    )?);
    let reference_performance = performance(reference_latencies);
    let adapter_performance = performance(adapter_latencies);
    let output_schema_match = vectors.iter().all(|vector| vector.output_schema_valid);
    let error_mapping_match = vectors.iter().all(|vector| vector.error_code_equal);
    let success = output_schema_match
        && error_mapping_match
        && vectors.iter().all(|vector| vector.output_equal);
    let ratio = (reference_performance.p95_latency_us > 0).then(|| {
        adapter_performance.p95_latency_us as f64 / reference_performance.p95_latency_us as f64
    });
    Ok(AdapterConformanceReport {
        success,
        adapter_id: adapter.contract().adapter_id.clone(),
        build_id: package_info.build_id,
        case_count: cases.len(),
        measured_iterations: options.iterations,
        output_schema_match,
        error_mapping_match,
        vectors,
        reference_performance,
        adapter_performance,
        adapter_to_reference_p95_ratio: ratio,
    })
}

fn compare_vector(
    id: &str,
    reference: &ReferenceRuntime,
    skill_id: &str,
    expected: Result<DecisionEnvelope, RuntimeError>,
    actual: Result<DecisionEnvelope, RuntimeError>,
) -> VectorComparison {
    match (expected, actual) {
        (Ok(expected), Ok(actual)) => {
            let expected_schema = reference
                .package()
                .validate_result(skill_id, &expected.result)
                .is_ok();
            let actual_schema = reference
                .package()
                .validate_result(skill_id, &actual.result)
                .is_ok();
            VectorComparison {
                vector_id: id.to_owned(),
                output_equal: expected.decision_hash() == actual.decision_hash(),
                output_schema_valid: expected_schema && actual_schema,
                error_code_equal: true,
                reference_error: None,
                adapter_error: None,
            }
        }
        (Err(expected), Err(actual)) => VectorComparison {
            vector_id: id.to_owned(),
            output_equal: true,
            output_schema_valid: true,
            error_code_equal: expected.code() == actual.code(),
            reference_error: Some(expected.code()),
            adapter_error: Some(actual.code()),
        },
        (expected, actual) => VectorComparison {
            vector_id: id.to_owned(),
            output_equal: false,
            output_schema_valid: false,
            error_code_equal: false,
            reference_error: expected.err().map(|error| error.code()),
            adapter_error: actual.err().map(|error| error.code()),
        },
    }
}

fn error_vectors(
    reference: &ReferenceRuntime,
    adapter: &dyn RuntimeAdapter,
    case: &d2i_eval::BenchmarkCase,
    timeout: Duration,
) -> Result<Vec<VectorComparison>, RuntimeError> {
    let invalid_request_id = "conformance:error:invalid-request";
    let reference_invalid = reference.run(
        &case.skill_id,
        invalid_request_id,
        serde_json::json!({}),
        timeout,
    );
    let invalid_context = TaskContext::new(
        invalid_request_id,
        d2i_core::SkillId::new(case.skill_id.clone())
            .map_err(|error| RuntimeError::InvalidRequest(error.to_string()))?,
        timeout,
    )?;
    let adapter_invalid = adapter.execute(invalid_context, serde_json::json!({}));
    let unsupported_id = "phase5_unsupported_skill";
    let reference_unsupported = reference.run(
        unsupported_id,
        "conformance:error:skill",
        case.request.clone(),
        timeout,
    );
    let unsupported_context = TaskContext::new(
        "conformance:error:skill",
        d2i_core::SkillId::new(unsupported_id)
            .map_err(|error| RuntimeError::InvalidRequest(error.to_string()))?,
        timeout,
    )?;
    let adapter_unsupported = adapter.execute(unsupported_context, case.request.clone());
    Ok(vec![
        compare_vector(
            "error:invalid-request",
            reference,
            &case.skill_id,
            reference_invalid,
            adapter_invalid,
        ),
        compare_vector(
            "error:unsupported-skill",
            reference,
            unsupported_id,
            reference_unsupported,
            adapter_unsupported,
        ),
    ])
}

fn performance(mut latencies: Vec<u64>) -> AdapterPerformance {
    latencies.sort_unstable();
    AdapterPerformance {
        runs: latencies.len(),
        p50_latency_us: percentile(&latencies, 50),
        p95_latency_us: percentile(&latencies, 95),
        p99_latency_us: percentile(&latencies, 99),
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

fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn target_supported(supported: &[String], required: &str) -> bool {
    required == "any"
        || supported
            .iter()
            .any(|target| target == "any" || target == required)
}

fn push_issue(issues: &mut Vec<CompatibilityIssue>, code: &str, message: impl Into<String>) {
    issues.push(CompatibilityIssue {
        code: code.to_owned(),
        message: message.into(),
    });
}

fn all_executor_kinds() -> Vec<ExecutorKind> {
    vec![
        ExecutorKind::Constant,
        ExecutorKind::Cache,
        ExecutorKind::Rule,
        ExecutorKind::Lookup,
        ExecutorKind::Search,
        ExecutorKind::NativeFunction,
        ExecutorKind::ClassicalModel,
        ExecutorKind::NeuralExpert,
        ExecutorKind::LanguageExpert,
        ExecutorKind::Planner,
        ExecutorKind::DeviceAdapter,
        ExecutorKind::HumanReview,
    ]
}

const fn runtime_error_code_name(code: RuntimeErrorCode) -> &'static str {
    match code {
        RuntimeErrorCode::Package => "package",
        RuntimeErrorCode::IncompatibleTarget => "incompatible_target",
        RuntimeErrorCode::MissingExecutor => "missing_executor",
        RuntimeErrorCode::DuplicateExecutor => "duplicate_executor",
        RuntimeErrorCode::InvalidRequest => "invalid_request",
        RuntimeErrorCode::UnsupportedSkill => "unsupported_skill",
        RuntimeErrorCode::Graph => "graph",
        RuntimeErrorCode::Executor => "executor",
        RuntimeErrorCode::Timeout => "timeout",
        RuntimeErrorCode::ReplayMismatch => "replay_mismatch",
        RuntimeErrorCode::AdapterUnavailable => "adapter_unavailable",
        RuntimeErrorCode::AdapterProtocol => "adapter_protocol",
        RuntimeErrorCode::Io => "io",
    }
}
