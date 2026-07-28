use crate::{load_candidate_package, CandidatePackage, LearningError};
use d2i_compiler::load_verified_package;
use d2i_eval::{benchmark_runtime, BenchmarkMetadata, RuntimeBenchmarkReport};
use d2i_runtime_ref::ReferenceRuntime;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// Hard promotion thresholds evaluated against the existing gold set.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionPolicy {
    pub minimum_task_success_rate: f64,
    pub minimum_field_accuracy: f64,
    pub maximum_critical_error_rate: f64,
    pub minimum_repeatability_rate: f64,
    pub maximum_task_success_regression: f64,
    pub maximum_field_accuracy_regression: f64,
}

impl Default for PromotionPolicy {
    fn default() -> Self {
        Self {
            minimum_task_success_rate: 1.0,
            minimum_field_accuracy: 1.0,
            maximum_critical_error_rate: 0.0,
            minimum_repeatability_rate: 1.0,
            maximum_task_success_regression: 0.0,
            maximum_field_accuracy_regression: 0.0,
        }
    }
}

/// Result of every regression, integrity, poisoning, and shift gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationGate {
    pub passed: bool,
    pub reasons: Vec<String>,
}

/// Reproducible offline evaluation bound to base and candidate hashes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineEvaluationReport {
    pub schema_version: u32,
    pub candidate_id: String,
    pub candidate_content_hash: String,
    pub base_build_id: String,
    pub base_package_content_hash: String,
    pub evaluator_id: String,
    pub evaluated_at_unix_seconds: u64,
    pub gold_dataset_id: String,
    pub gold_dataset_hash: String,
    pub measured_iterations: u32,
    pub candidate_execution_mode: String,
    pub baseline: RuntimeBenchmarkReport,
    pub candidate: RuntimeBenchmarkReport,
    pub policy: PromotionPolicy,
    pub gate: EvaluationGate,
}

/// Runs the existing gold set through baseline and metadata-only candidate modes.
pub fn evaluate_candidate_package(
    candidate_root: &Path,
    base_package: &Path,
    evaluator_id: &str,
    evaluated_at_unix_seconds: u64,
    measured_iterations: u32,
    policy: PromotionPolicy,
) -> Result<OfflineEvaluationReport, LearningError> {
    if evaluator_id.is_empty()
        || evaluated_at_unix_seconds == 0
        || measured_iterations == 0
        || measured_iterations > 1000
    {
        return Err(LearningError::Invalid(
            "offline evaluation options are incomplete or outside bounds".to_owned(),
        ));
    }
    validate_policy(policy)?;
    let candidate_package = load_candidate_package(candidate_root)?;
    let verified_base = load_verified_package(base_package)
        .map_err(|error| LearningError::Package(error.to_string()))?;
    let base_summary = &verified_base.summary;
    ensure_base_matches(
        &candidate_package,
        &base_summary.build_id,
        &base_summary.package_content_hash,
    )?;
    let runtime = ReferenceRuntime::load(base_package)
        .map_err(|error| LearningError::Package(error.to_string()))?;
    let cases = runtime
        .package()
        .benchmark_cases()
        .map_err(|error| LearningError::Package(error.to_string()))?;
    if cases.is_empty() {
        return Err(LearningError::GateRejected(vec![
            "existing gold set is empty".to_owned(),
        ]));
    }
    let (gold_dataset_id, gold_dataset_hash) = runtime
        .package()
        .evaluation_dataset_identity()
        .ok_or_else(|| {
            LearningError::GateRejected(vec!["existing gold set identity is missing".to_owned()])
        })?;
    let gold_artifact_path = format!("eval/source/{gold_dataset_id}");
    let gold_bytes = verified_base.artifact(&gold_artifact_path).ok_or_else(|| {
        LearningError::GateRejected(vec!["existing gold set artifact is missing".to_owned()])
    })?;
    if crate::sha256_bytes(gold_bytes) != gold_dataset_hash {
        return Err(LearningError::Integrity(
            "gold set provenance hash does not match the packaged artifact".to_owned(),
        ));
    }
    let gold_dataset_id = gold_dataset_id.to_owned();
    let gold_dataset_hash = gold_dataset_hash.to_owned();
    let baseline = benchmark_runtime(
        BenchmarkMetadata {
            benchmark_id: "phase8-production-baseline",
            build_id: &base_summary.build_id,
            dataset_id: &gold_dataset_id,
            dataset_hash: &gold_dataset_hash,
            compiler_version: &base_summary.compiler_version,
        },
        &cases,
        measured_iterations,
        |case| {
            runtime.run(
                &case.skill_id,
                format!("phase8-baseline-{}", case.id),
                case.request.clone(),
                Duration::from_secs(30),
            )
        },
    )
    .map_err(|error| LearningError::Package(error.to_string()))?;
    let candidate_result = benchmark_runtime(
        BenchmarkMetadata {
            benchmark_id: "phase8-candidate-overlay",
            build_id: &base_summary.build_id,
            dataset_id: &gold_dataset_id,
            dataset_hash: &gold_dataset_hash,
            compiler_version: &base_summary.compiler_version,
        },
        &cases,
        measured_iterations,
        |case| {
            runtime.run(
                &case.skill_id,
                format!("phase8-candidate-{}", case.id),
                case.request.clone(),
                Duration::from_secs(30),
            )
        },
    )
    .map_err(|error| LearningError::Package(error.to_string()))?;
    let gate = evaluate_gate(&candidate_package, &baseline, &candidate_result, policy);
    Ok(OfflineEvaluationReport {
        schema_version: 1,
        candidate_id: candidate_package.manifest.candidate_id,
        candidate_content_hash: candidate_package.candidate_content_hash,
        base_build_id: base_summary.build_id.clone(),
        base_package_content_hash: base_summary.package_content_hash.clone(),
        evaluator_id: evaluator_id.to_owned(),
        evaluated_at_unix_seconds,
        gold_dataset_id,
        gold_dataset_hash,
        measured_iterations,
        candidate_execution_mode: "base_runtime_with_non_executable_adaptation_metadata".to_owned(),
        baseline,
        candidate: candidate_result,
        policy,
        gate,
    })
}

fn ensure_base_matches(
    candidate: &CandidatePackage,
    build_id: &str,
    package_hash: &str,
) -> Result<(), LearningError> {
    if candidate.manifest.base_build_id != build_id
        || candidate.manifest.base_package_content_hash != package_hash
    {
        return Err(LearningError::Integrity(
            "candidate is not bound to the supplied base package".to_owned(),
        ));
    }
    Ok(())
}

fn evaluate_gate(
    package: &CandidatePackage,
    baseline: &RuntimeBenchmarkReport,
    candidate: &RuntimeBenchmarkReport,
    policy: PromotionPolicy,
) -> EvaluationGate {
    let mut reasons = Vec::new();
    if candidate.task_success_rate < policy.minimum_task_success_rate {
        reasons.push("candidate task success is below the absolute threshold".to_owned());
    }
    if baseline.task_success_rate - candidate.task_success_rate
        > policy.maximum_task_success_regression
    {
        reasons.push("candidate task success regressed".to_owned());
    }
    if candidate.field_accuracy < policy.minimum_field_accuracy {
        reasons.push("candidate field accuracy is below the absolute threshold".to_owned());
    }
    if baseline.field_accuracy - candidate.field_accuracy > policy.maximum_field_accuracy_regression
    {
        reasons.push("candidate field accuracy regressed".to_owned());
    }
    if candidate.critical_error_rate > policy.maximum_critical_error_rate
        || candidate.critical_error_rate > baseline.critical_error_rate
    {
        reasons.push("candidate critical error rate increased".to_owned());
    }
    if candidate.repeatability_rate < policy.minimum_repeatability_rate {
        reasons.push("candidate repeatability is below threshold".to_owned());
    }
    if package.dataset_report.leakage_group_overlap_count != 0 {
        reasons.push("candidate dataset contains split leakage".to_owned());
    }
    if package.dataset_report.unresolved_poisoning_flag_count != 0 {
        reasons.push("candidate dataset has unresolved poisoning flags".to_owned());
    }
    if !package.dataset_report.distribution_shift_flags.is_empty() {
        reasons.push("candidate dataset has unresolved distribution shift".to_owned());
    }
    EvaluationGate {
        passed: reasons.is_empty(),
        reasons,
    }
}

pub(crate) fn verify_evaluation_report(
    package: &CandidatePackage,
    report: &OfflineEvaluationReport,
) -> Result<(), LearningError> {
    if report.schema_version != 1
        || report.candidate_id != package.manifest.candidate_id
        || report.candidate_content_hash != package.candidate_content_hash
        || report.base_build_id != package.manifest.base_build_id
        || report.base_package_content_hash != package.manifest.base_package_content_hash
        || report.measured_iterations == 0
        || report.evaluator_id.is_empty()
        || report.gold_dataset_id.is_empty()
        || report.baseline.build_id != report.base_build_id
        || report.candidate.build_id != report.base_build_id
        || report.baseline.dataset_hash != report.gold_dataset_hash
        || report.candidate.dataset_hash != report.gold_dataset_hash
    {
        return Err(LearningError::Integrity(
            "offline evaluation identity fields are inconsistent".to_owned(),
        ));
    }
    crate::episode::validate_hash(&report.gold_dataset_hash, "gold_dataset_hash")?;
    validate_policy(report.policy)?;
    let expected = evaluate_gate(package, &report.baseline, &report.candidate, report.policy);
    if report.gate != expected {
        return Err(LearningError::Integrity(
            "offline evaluation gate does not match measured metrics".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy(policy: PromotionPolicy) -> Result<(), LearningError> {
    let values = [
        policy.minimum_task_success_rate,
        policy.minimum_field_accuracy,
        policy.maximum_critical_error_rate,
        policy.minimum_repeatability_rate,
        policy.maximum_task_success_regression,
        policy.maximum_field_accuracy_regression,
    ];
    if values
        .into_iter()
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
    {
        return Err(LearningError::Invalid(
            "promotion policy rates must be finite values from 0 to 1".to_owned(),
        ));
    }
    Ok(())
}
