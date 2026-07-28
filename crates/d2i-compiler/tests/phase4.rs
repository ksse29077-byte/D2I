use d2i_compiler::{build_ir, compile_package, load_verified_package};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn some<T>(value: Option<T>, label: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("expected {label}"),
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase4-{label}-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir_all(&path));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn example_pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/equipment-maintenance")
}

fn copied_pack(label: &str) -> TempDirectory {
    let temporary = TempDirectory::new(label);
    copy_directory(&example_pack(), temporary.path());
    temporary
}

fn copy_directory(source: &Path, destination: &Path) {
    ok(fs::create_dir_all(destination));
    for entry in ok(fs::read_dir(source)) {
        let entry = ok(entry);
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            ok(fs::copy(source_path, destination_path));
        }
    }
}

fn replace(path: &Path, from: &str, to: &str) {
    let contents = ok(fs::read_to_string(path));
    assert!(
        contents.contains(from),
        "{} did not contain {from}",
        path.display()
    );
    ok(fs::write(path, contents.replace(from, to)));
}

#[test]
fn default_selection_excludes_low_quality_and_records_pareto_rationale() {
    let report = build_ir(&example_pack());
    assert!(
        !report.has_errors(),
        "phase 4 diagnostics: {:?}",
        report.diagnostics
    );
    let phase4 = some(report.phase4, "Phase 4 build data");
    let retrieval = &phase4.selections["diagnose_fault:case-retriever"];

    assert_eq!(
        retrieval.selected.as_deref(),
        Some("case-retriever-compact")
    );
    assert_eq!(
        retrieval.pareto_front,
        vec!["case-retriever-compact", "case-retriever-fast"]
    );
    assert!(retrieval.rejected.iter().any(|candidate| {
        candidate.executor_id == "case-retriever-low-quality"
            && candidate
                .reasons
                .iter()
                .any(|reason| reason.starts_with("task success"))
    }));
    assert!(retrieval.explanation.contains("Pareto-safe"));
}

#[test]
fn latency_target_and_safe_forced_binding_select_fast_candidate() {
    let latency_pack = copied_pack("latency");
    let selection = latency_pack.path().join("models/selection.yaml");
    replace(&selection, "latency: 1.0", "latency: 10.0");
    replace(&selection, "memory: 1.0", "memory: 0.01");
    replace(&selection, "package_size: 0.5", "package_size: 0.01");
    replace(&selection, "copies: 0.25", "copies: 0.01");
    let latency_report = build_ir(latency_pack.path());
    assert!(!latency_report.has_errors());
    assert_eq!(
        some(latency_report.phase4, "latency Phase 4 build data").selections
            ["diagnose_fault:case-retriever"]
            .selected
            .as_deref(),
        Some("case-retriever-fast")
    );

    let forced_pack = copied_pack("forced");
    let selection = forced_pack.path().join("models/selection.yaml");
    replace(
        &selection,
        "forced_bindings: {}",
        "forced_bindings:\n  case-retriever: \"case-retriever-fast\"",
    );
    let forced_report = build_ir(forced_pack.path());
    assert!(!forced_report.has_errors());
    let phase4 = some(forced_report.phase4, "forced Phase 4 build data");
    let retrieval = &phase4.selections["diagnose_fault:case-retriever"];
    assert_eq!(retrieval.selected.as_deref(), Some("case-retriever-fast"));
    assert!(retrieval.forced);
    assert!(retrieval.explanation.contains("hard gates passed"));
}

#[test]
fn benchmark_quality_regression_blocks_the_build() {
    let regression_pack = copied_pack("regression");
    let benchmarks = regression_pack.path().join("models/benchmarks.yaml");
    replace(
        &benchmarks,
        "task_success_rate: 0.96",
        "task_success_rate: 0.80",
    );
    replace(&benchmarks, "field_accuracy: 0.96", "field_accuracy: 0.80");
    replace(
        &benchmarks,
        "task_success_rate: 0.98",
        "task_success_rate: 0.80",
    );
    replace(&benchmarks, "field_accuracy: 0.98", "field_accuracy: 0.80");

    let report = build_ir(regression_pack.path());
    assert!(report.has_errors());
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code() == "D2I2304"));
}

#[test]
fn package_retains_selection_and_optimization_artifacts() {
    let temporary = TempDirectory::new("package");
    let output = temporary.path().join("phase4.d2ip");
    let report = compile_package(&example_pack(), &output);
    assert!(
        !report.has_errors(),
        "compile diagnostics: {:?} {:?}",
        report.diagnostics,
        report.package_error
    );
    let build = some(report.build, "build report");
    assert_eq!(
        build.selected_executors["diagnose_fault:case-retriever"],
        "case-retriever-compact"
    );

    let verified = ok(load_verified_package(&output));
    for artifact in [
        "executors/descriptors.json",
        "eval/benchmark-profiles.json",
        "reports/selection.json",
        "reports/optimization.json",
    ] {
        assert!(verified.artifact(artifact).is_some(), "missing {artifact}");
    }
}
