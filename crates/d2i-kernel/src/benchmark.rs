use crate::score_match_masks_into;
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_ITEMS: usize = 16 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 10_000;
const ADOPTION_SPEEDUP: f64 = 1.20;

/// Bounded inputs for one reproducible score-kernel benchmark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelBenchmarkOptions {
    pub item_count: usize,
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
}

impl Default for KernelBenchmarkOptions {
    fn default() -> Self {
        Self {
            item_count: 65_536,
            warmup_iterations: 20,
            measured_iterations: 200,
        }
    }
}

/// Explicit candidate library and allowlisted hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfig {
    pub library_path: PathBuf,
    pub expected_sha256: String,
}

/// One backend's correctness, cost, and build-complexity observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendBenchmark {
    pub backend: String,
    pub status: String,
    pub correctness_equal: Option<bool>,
    pub p50_latency_ns: Option<u64>,
    pub p95_latency_ns: Option<u64>,
    pub p99_latency_ns: Option<u64>,
    pub peak_rss_bytes: Option<u64>,
    pub working_memory_bytes: u64,
    pub boundary_copy_count: Option<u64>,
    pub boundary_copy_bytes: Option<u64>,
    pub required_tools: Vec<String>,
    pub build_steps: u32,
    pub diagnostic: Option<String>,
}

/// Rust baseline and optional Mojo-candidate comparison artifact.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KernelBenchmarkReport {
    pub schema_version: u32,
    pub kernel_id: String,
    pub os: String,
    pub architecture: String,
    pub options: KernelBenchmarkOptions,
    pub minimum_adoption_speedup: f64,
    pub rust: BackendBenchmark,
    pub mojo_candidate: BackendBenchmark,
    pub measured_speedup: Option<f64>,
    pub decision: String,
}

/// Measures the Rust baseline and an optional hash-allowlisted native candidate.
pub fn run_kernel_benchmark(
    options: KernelBenchmarkOptions,
    candidate: Option<&CandidateConfig>,
) -> Result<KernelBenchmarkReport, String> {
    validate_options(options)?;
    let masks = deterministic_masks(options.item_count);
    let mut rust_scores = vec![0_u16; masks.len()];
    for _ in 0..options.warmup_iterations {
        score_match_masks_into(&masks, &mut rust_scores).map_err(|error| error.to_string())?;
        black_box(&rust_scores);
    }
    let rust_times = measure(options.measured_iterations, || {
        score_match_masks_into(&masks, &mut rust_scores).map_err(|error| error.to_string())?;
        black_box(&rust_scores);
        Ok(())
    })?;
    let working_memory_bytes = working_memory_bytes(options.item_count)?;
    let rust = measured_backend(
        "rust",
        &rust_times,
        working_memory_bytes,
        Some(0),
        Some(0),
        vec!["cargo".to_owned()],
        1,
    );

    let (mojo_candidate, measured_speedup, decision) =
        measure_candidate(options, candidate, &masks, &rust_scores, &rust)?;

    Ok(KernelBenchmarkReport {
        schema_version: 1,
        kernel_id: "case-retriever-match-score-v1".to_owned(),
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        options,
        minimum_adoption_speedup: ADOPTION_SPEEDUP,
        rust,
        mojo_candidate,
        measured_speedup,
        decision,
    })
}

fn validate_options(options: KernelBenchmarkOptions) -> Result<(), String> {
    if options.item_count == 0 || options.item_count > MAX_ITEMS {
        return Err(format!("item count must be between 1 and {MAX_ITEMS}"));
    }
    if options.measured_iterations == 0 || options.measured_iterations > MAX_ITERATIONS {
        return Err(format!(
            "measured iterations must be between 1 and {MAX_ITERATIONS}"
        ));
    }
    if options.warmup_iterations > MAX_ITERATIONS {
        return Err(format!(
            "warmup iterations must not exceed {MAX_ITERATIONS}"
        ));
    }
    Ok(())
}

fn deterministic_masks(item_count: usize) -> Vec<u8> {
    (0..item_count)
        .map(|index| u8::try_from(index % 8).unwrap_or(0))
        .collect()
}

fn measure(
    iterations: u32,
    mut operation: impl FnMut() -> Result<(), String>,
) -> Result<Vec<Duration>, String> {
    let mut times = Vec::with_capacity(usize::try_from(iterations).unwrap_or(0));
    for _ in 0..iterations {
        let start = Instant::now();
        operation()?;
        times.push(start.elapsed());
    }
    Ok(times)
}

fn measured_backend(
    backend: &str,
    times: &[Duration],
    working_memory_bytes: u64,
    boundary_copy_count: Option<u64>,
    boundary_copy_bytes: Option<u64>,
    required_tools: Vec<String>,
    build_steps: u32,
) -> BackendBenchmark {
    BackendBenchmark {
        backend: backend.to_owned(),
        status: "measured".to_owned(),
        correctness_equal: Some(true),
        p50_latency_ns: percentile(times, 50),
        p95_latency_ns: percentile(times, 95),
        p99_latency_ns: percentile(times, 99),
        peak_rss_bytes: None,
        working_memory_bytes,
        boundary_copy_count,
        boundary_copy_bytes,
        required_tools,
        build_steps,
        diagnostic: None,
    }
}

fn unavailable_candidate(
    status: &str,
    diagnostic: String,
    working_memory_bytes: u64,
) -> BackendBenchmark {
    BackendBenchmark {
        backend: "mojo-1.0.0b2".to_owned(),
        status: status.to_owned(),
        correctness_equal: None,
        p50_latency_ns: None,
        p95_latency_ns: None,
        p99_latency_ns: None,
        peak_rss_bytes: None,
        working_memory_bytes,
        boundary_copy_count: None,
        boundary_copy_bytes: None,
        required_tools: vec![
            "cargo".to_owned(),
            "mojo 1.0.0b2".to_owned(),
            "platform linker".to_owned(),
        ],
        build_steps: 3,
        diagnostic: Some(diagnostic),
    }
}

#[cfg(not(feature = "mojo-backend"))]
fn measure_candidate(
    options: KernelBenchmarkOptions,
    candidate: Option<&CandidateConfig>,
    _masks: &[u8],
    _rust_scores: &[u16],
    _rust: &BackendBenchmark,
) -> Result<(BackendBenchmark, Option<f64>, String), String> {
    let diagnostic = if candidate.is_some() {
        "candidate was supplied but the mojo-backend Cargo feature is disabled"
    } else {
        "Mojo candidate library was not supplied and the feature is disabled"
    };
    Ok((
        unavailable_candidate(
            "unavailable",
            diagnostic.to_owned(),
            working_memory_bytes(options.item_count)?,
        ),
        None,
        "rejected_unavailable".to_owned(),
    ))
}

#[cfg(feature = "mojo-backend")]
fn measure_candidate(
    options: KernelBenchmarkOptions,
    candidate: Option<&CandidateConfig>,
    masks: &[u8],
    rust_scores: &[u16],
    rust: &BackendBenchmark,
) -> Result<(BackendBenchmark, Option<f64>, String), String> {
    use d2i_ffi::{NativeModulePolicy, NativeScoreKernel};

    let working_memory = working_memory_bytes(options.item_count)?;
    let Some(candidate) = candidate else {
        return Ok((
            unavailable_candidate(
                "unavailable",
                "Mojo candidate library was not supplied".to_owned(),
                working_memory,
            ),
            None,
            "rejected_unavailable".to_owned(),
        ));
    };
    let allowed_root = candidate
        .library_path
        .parent()
        .ok_or_else(|| "candidate library has no parent directory".to_owned())?
        .to_path_buf();
    let output_bytes = u64::try_from(options.item_count)
        .unwrap_or(u64::MAX)
        .saturating_mul(2);
    let policy = NativeModulePolicy {
        allowed_root,
        expected_sha256: candidate.expected_sha256.clone(),
        maximum_library_bytes: 64 * 1024 * 1024,
        maximum_input_bytes: u64::try_from(options.item_count).unwrap_or(u64::MAX),
        maximum_output_bytes: output_bytes,
    };
    let mut kernel = match NativeScoreKernel::load(&candidate.library_path, &policy) {
        Ok(kernel) => kernel,
        Err(error) => {
            return Ok((
                unavailable_candidate("load_failed", error.to_string(), working_memory),
                None,
                "rejected_load_failure".to_owned(),
            ));
        }
    };
    let mut candidate_scores = vec![0_u16; masks.len()];
    kernel
        .score_into(masks, &mut candidate_scores)
        .map_err(|error| error.to_string())?;
    if candidate_scores != rust_scores {
        let mut rejected = unavailable_candidate(
            "incorrect",
            "candidate output differs from the Rust baseline".to_owned(),
            working_memory,
        );
        rejected.correctness_equal = Some(false);
        return Ok((rejected, None, "rejected_correctness_mismatch".to_owned()));
    }
    for _ in 0..options.warmup_iterations {
        kernel
            .score_into(masks, &mut candidate_scores)
            .map_err(|error| error.to_string())?;
        black_box(&candidate_scores);
    }
    let candidate_times = measure(options.measured_iterations, || {
        kernel
            .score_into(masks, &mut candidate_scores)
            .map_err(|error| error.to_string())?;
        black_box(&candidate_scores);
        Ok(())
    })?;
    let metrics = kernel.copy_metrics().clone();
    let candidate_report = measured_backend(
        "mojo-1.0.0b2",
        &candidate_times,
        working_memory,
        Some(metrics.boundary_copy_count),
        Some(metrics.boundary_copy_bytes),
        vec![
            "cargo".to_owned(),
            "mojo 1.0.0b2".to_owned(),
            "platform linker".to_owned(),
        ],
        3,
    );
    let speedup = speedup(rust.p50_latency_ns, candidate_report.p50_latency_ns);
    let decision = if speedup.is_some_and(|value| value >= ADOPTION_SPEEDUP) {
        "eligible_for_controlled_adoption"
    } else {
        "rejected_no_reproducible_gain"
    };
    Ok((candidate_report, speedup, decision.to_owned()))
}

fn working_memory_bytes(item_count: usize) -> Result<u64, String> {
    let bytes = item_count
        .checked_mul(3)
        .ok_or_else(|| "working-memory size overflow".to_owned())?;
    u64::try_from(bytes).map_err(|_| "working-memory size exceeds u64".to_owned())
}

fn percentile(times: &[Duration], percentile: usize) -> Option<u64> {
    if times.is_empty() {
        return None;
    }
    let mut nanos = times
        .iter()
        .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
        .collect::<Vec<_>>();
    nanos.sort_unstable();
    let index = (nanos.len() - 1).saturating_mul(percentile) / 100;
    nanos.get(index).copied()
}

#[cfg(feature = "mojo-backend")]
fn speedup(baseline: Option<u64>, candidate: Option<u64>) -> Option<f64> {
    match (baseline, candidate) {
        (Some(baseline), Some(candidate)) if candidate > 0 => {
            Some(baseline as f64 / candidate as f64)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_report_is_measured_and_unavailable_candidate_is_rejected() {
        let report = match run_kernel_benchmark(
            KernelBenchmarkOptions {
                item_count: 128,
                warmup_iterations: 1,
                measured_iterations: 3,
            },
            None,
        ) {
            Ok(report) => report,
            Err(error) => panic!("benchmark failed: {error}"),
        };
        assert_eq!(report.rust.status, "measured");
        assert_eq!(report.rust.correctness_equal, Some(true));
        assert_eq!(report.mojo_candidate.status, "unavailable");
        assert_eq!(report.decision, "rejected_unavailable");
    }

    #[test]
    fn unbounded_benchmark_inputs_are_rejected() {
        assert!(run_kernel_benchmark(
            KernelBenchmarkOptions {
                item_count: 0,
                warmup_iterations: 0,
                measured_iterations: 1,
            },
            None,
        )
        .is_err());
    }
}
