use d2i_compiler::compile_package;
use d2i_eval::ExecutorKind;
use d2i_runtime_adapter::{
    check_package_compatibility, phase5_abi_mapping, run_conformance, AdapterContract, AdapterKind,
    ConformanceOptions, MockRuntimeAdapter, ProprietaryRuntimeAdapterPlaceholder, RuntimeAdapter,
    ADAPTER_CONTRACT_VERSION,
};
use d2i_runtime_api::{DecisionEnvelope, RuntimeError, RuntimeErrorCode, TaskContext};
use serde_json::Value;
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

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase5-{label}-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir_all(&path));
        Self(path)
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

fn package(label: &str) -> (TempDirectory, PathBuf) {
    let temporary = TempDirectory::new(label);
    let package = temporary.0.join("package.d2ip");
    let report = compile_package(&example_pack(), &package);
    assert!(
        !report.has_errors(),
        "compile diagnostics: {:?} {:?}",
        report.diagnostics,
        report.package_error
    );
    (temporary, package)
}

#[test]
fn mock_contract_accepts_the_reference_package() {
    let (_temporary, package) = package("compatible");
    let report = ok(check_package_compatibility(
        &package,
        &AdapterContract::mock(),
    ));

    assert!(report.compatible);
    assert_eq!(report.required_executor_ids.len(), 3);
    assert!(report.issues.is_empty());
}

#[test]
fn compatibility_checker_reports_abi_kind_and_memory_failures() {
    let (_temporary, package) = package("incompatible");
    let contract = AdapterContract {
        adapter_id: "limited-runtime".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        contract_version: ADAPTER_CONTRACT_VERSION.to_owned(),
        kind: AdapterKind::ProprietaryPlaceholder,
        supported_package_formats: vec!["1.0.0".to_owned()],
        supported_runtime_abis: vec!["9.0.0".to_owned()],
        supported_os: vec!["any".to_owned()],
        supported_arch: vec!["any".to_owned()],
        supported_executor_kinds: vec![ExecutorKind::Rule],
        max_resident_memory_bytes: Some(1),
        network_allowed: false,
    };
    let report = ok(check_package_compatibility(&package, &contract));
    let codes = report
        .issues
        .iter()
        .map(|issue| issue.code.as_str())
        .collect::<Vec<_>>();

    assert!(!report.compatible);
    assert!(codes.contains(&"D2I5002"));
    assert!(codes.contains(&"D2I5007"));
    assert!(codes.contains(&"D2I5009"));
}

#[test]
fn mock_matches_reference_vectors_output_schema_errors_and_decisions() {
    let (_temporary, package) = package("conformance");
    let mut adapter = MockRuntimeAdapter::new();
    let report = ok(run_conformance(
        &package,
        &mut adapter,
        ConformanceOptions::default(),
    ));

    assert!(report.success);
    assert_eq!(report.case_count, 50);
    assert_eq!(report.vectors.len(), 52);
    assert!(report.output_schema_match);
    assert!(report.error_mapping_match);
    assert!(report.vectors.iter().all(|vector| vector.output_equal));
}

#[test]
fn placeholder_stops_at_the_documented_todo_boundary() {
    let (_temporary, package) = package("placeholder");
    let mut adapter = ProprietaryRuntimeAdapterPlaceholder::new(AdapterContract::mock());
    let error = match adapter.load_package(&package) {
        Ok(_) => panic!("placeholder must not invent a proprietary package API"),
        Err(error) => error,
    };

    assert!(matches!(error, RuntimeError::AdapterUnavailable(_)));
    assert_eq!(error.code(), RuntimeErrorCode::AdapterUnavailable);
}

#[test]
fn abi_mapping_covers_every_runtime_error_category_and_marks_unknowns() {
    let mapping = phase5_abi_mapping();

    assert_eq!(mapping.adapter_contract_version, ADAPTER_CONTRACT_VERSION);
    assert_eq!(mapping.error_mappings.len(), 13);
    assert!(mapping.error_mappings.iter().any(|entry| entry.runtime_code
        == RuntimeErrorCode::AdapterProtocol
        && entry.adapter_code == "adapter_protocol"));
    assert!(!mapping.unresolved_external_contracts.is_empty());
}

struct FaultyAdapter {
    inner: MockRuntimeAdapter,
}

impl RuntimeAdapter for FaultyAdapter {
    fn contract(&self) -> &AdapterContract {
        self.inner.contract()
    }

    fn load_package(
        &mut self,
        path: &Path,
    ) -> Result<d2i_runtime_adapter::AdapterPackageInfo, RuntimeError> {
        self.inner.load_package(path)
    }

    fn execute(
        &self,
        context: TaskContext,
        request: Value,
    ) -> Result<DecisionEnvelope, RuntimeError> {
        if request.as_object().is_some_and(serde_json::Map::is_empty) {
            return Err(RuntimeError::AdapterProtocol(
                "intentional test mismatch".to_owned(),
            ));
        }
        let mut envelope = self.inner.execute(context, request)?;
        if let Some(result) = envelope.result.as_object_mut() {
            result.remove("human_review");
        }
        Ok(envelope)
    }
}

#[test]
fn conformance_detects_output_schema_and_error_mapping_regressions() {
    let (_temporary, package) = package("faulty");
    let mut adapter = FaultyAdapter {
        inner: MockRuntimeAdapter::new(),
    };
    let report = ok(run_conformance(
        &package,
        &mut adapter,
        ConformanceOptions::default(),
    ));

    assert!(!report.success);
    assert!(!report.output_schema_match);
    assert!(!report.error_mapping_match);
}
