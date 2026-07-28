use d2i_compiler::compile_package;
use d2i_runtime_api::{DecisionStatus, ReplayRecord, Runtime};
use d2i_runtime_ref::{cli, ReferenceRuntime};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase3-{label}-{}-{sequence}",
            std::process::id()
        ));
        if let Err(error) = fs::create_dir_all(&path) {
            panic!("cannot create test directory {}: {error}", path.display());
        }
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

fn build_runtime(label: &str) -> (TempDirectory, PathBuf, ReferenceRuntime) {
    let temporary = TempDirectory::new(label);
    let package = temporary.0.join("package.d2ip");
    let report = compile_package(&example_pack(), &package);
    assert!(
        !report.has_errors(),
        "compile failed: {:?} {:?}",
        report.diagnostics,
        report.package_error
    );
    let runtime =
        ReferenceRuntime::load(&package).unwrap_or_else(|error| panic!("load failed: {error}"));
    (temporary, package, runtime)
}

#[test]
fn selective_modules_produce_evidence_policy_and_timings() {
    let (_temporary, _package, runtime) = build_runtime("normal");
    let envelope = runtime
        .run(
            "diagnose_fault",
            "request-normal",
            json!({
                "equipment_id": "pump-1",
                "symptom": "shaking",
                "error_code": "E101"
            }),
            Duration::from_secs(2),
        )
        .unwrap_or_else(|error| panic!("runtime failed: {error}"));
    assert_eq!(envelope.status, DecisionStatus::Success);
    assert_eq!(
        envelope.module_ids,
        vec![
            "term-normalizer",
            "case-retriever-compact",
            "procedure-decider"
        ]
    );
    assert!(!envelope.evidence.is_empty());
    assert!(envelope.policy.allowed);
    assert!(!envelope.timings.is_empty());
    assert!(envelope
        .timings
        .iter()
        .all(|timing| !timing.node_id.is_empty() && !timing.module_id.is_empty()));
    assert_eq!(envelope.result["candidate_fault_codes"][0], "bearing-wear");
    assert_eq!(envelope.result["human_review"], false);
}

#[test]
fn ambiguous_and_critical_requests_follow_human_review_fallback() {
    let (_temporary, _package, runtime) = build_runtime("fallback");
    for (id, request) in [
        (
            "ambiguous",
            json!({"equipment_id": "pump-2", "symptom": "vibration"}),
        ),
        (
            "critical",
            json!({
                "equipment_id": "motor-1",
                "symptom": "overheating",
                "error_code": "E301",
                "sensor_snapshot": {"temperature_c": 150}
            }),
        ),
    ] {
        let envelope = runtime
            .run("diagnose_fault", id, request, Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("runtime failed: {error}"));
        assert_eq!(envelope.status, DecisionStatus::HumanReview);
        assert_eq!(envelope.result["human_review"], true);
        assert!(!envelope.policy.allowed);
        assert!(envelope.policy.human_review_required);
    }
}

#[test]
fn replay_is_timing_independent_and_package_bound() {
    let (_temporary, _package, runtime) = build_runtime("replay");
    let request = json!({
        "equipment_id": "generator-1",
        "symptom": "unstable voltage",
        "error_code": "E803"
    });
    let envelope = runtime
        .run(
            "diagnose_fault",
            "request-replay",
            request.clone(),
            Duration::from_secs(2),
        )
        .unwrap_or_else(|error| panic!("runtime failed: {error}"));
    let report = runtime
        .replay(&ReplayRecord { request, envelope })
        .unwrap_or_else(|error| panic!("replay failed: {error}"));
    assert!(report.matched);
    assert_eq!(report.expected_decision_hash, report.actual_decision_hash);
}

#[test]
fn package_contains_fifty_categorized_evaluation_cases() {
    let (_temporary, _package, runtime) = build_runtime("evaluation");
    assert_eq!(runtime.package().summary().evaluation_case_count, 50);
    assert_eq!(runtime.package().evaluation_cases().count(), 50);

    let text = fs::read_to_string(example_pack().join("eval/gold.jsonl"))
        .unwrap_or_else(|error| panic!("cannot read gold data: {error}"));
    let mut categories = std::collections::BTreeSet::new();
    for line in text.lines() {
        let value: Value =
            serde_json::from_str(line).unwrap_or_else(|error| panic!("invalid gold JSON: {error}"));
        if let Some(category) = value["expected"]["category"].as_str() {
            categories.insert(category.to_owned());
        }
    }
    assert_eq!(
        categories,
        [
            "ambiguous",
            "critical",
            "edge",
            "negative",
            "normal",
            "unsupported"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
}

#[test]
fn every_gold_request_returns_evidence_and_timings() {
    let (_temporary, _package, runtime) = build_runtime("all-gold");
    let text = fs::read_to_string(example_pack().join("eval/gold.jsonl"))
        .unwrap_or_else(|error| panic!("cannot read gold data: {error}"));
    assert_eq!(text.lines().count(), 50);
    for line in text.lines() {
        let case: Value =
            serde_json::from_str(line).unwrap_or_else(|error| panic!("invalid gold JSON: {error}"));
        let id = case["id"].as_str().unwrap_or("<missing-id>");
        let request = case["request"].clone();
        let expected = &case["expected"];
        let envelope = runtime
            .run("diagnose_fault", id, request, Duration::from_secs(2))
            .unwrap_or_else(|error| panic!("gold case '{id}' failed: {error}"));
        assert!(
            !envelope.evidence.is_empty(),
            "gold case '{id}' has no evidence"
        );
        assert!(
            !envelope.timings.is_empty(),
            "gold case '{id}' has no timings"
        );
        assert_eq!(envelope.module_ids.len(), 3);
        assert_eq!(
            envelope.result["human_review"], expected["human_review"],
            "gold case '{id}' review result differs"
        );
        if let Some(fault_code) = expected["fault_code"].as_str() {
            assert!(
                envelope.result["candidate_fault_codes"]
                    .as_array()
                    .is_some_and(|codes| codes.iter().any(|code| code == fault_code)),
                "gold case '{id}' is missing expected fault '{fault_code}'"
            );
        }
    }
}

#[test]
fn runtime_cli_runs_and_replays_locally() {
    let (temporary, package, _runtime) = build_runtime("cli");
    let request_path = temporary.0.join("request.json");
    let record_path = temporary.0.join("record.json");
    fs::write(
        &request_path,
        br#"{"equipment_id":"pump-1","symptom":"vibration","error_code":"E101"}"#,
    )
    .unwrap_or_else(|error| panic!("cannot write request: {error}"));
    let mut input = &b""[..];
    let mut output = Vec::new();
    let mut error = Vec::new();
    let code = cli::run_with_io(
        [
            "d2i-runtime",
            "run",
            "--package",
            package.to_string_lossy().as_ref(),
            "--request",
            request_path.to_string_lossy().as_ref(),
            "--record",
            record_path.to_string_lossy().as_ref(),
            "--json",
        ],
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(
        code,
        cli::EXIT_SUCCESS,
        "{}",
        String::from_utf8_lossy(&error)
    );
    let envelope: Value = serde_json::from_slice(&output)
        .unwrap_or_else(|parse_error| panic!("invalid CLI output: {parse_error}"));
    assert_eq!(envelope["status"], "success");

    output.clear();
    error.clear();
    let code = cli::run_with_io(
        [
            "d2i-runtime",
            "replay",
            "--package",
            package.to_string_lossy().as_ref(),
            "--record",
            record_path.to_string_lossy().as_ref(),
            "--json",
        ],
        &mut input,
        &mut output,
        &mut error,
    );
    assert_eq!(
        code,
        cli::EXIT_SUCCESS,
        "{}",
        String::from_utf8_lossy(&error)
    );
    let replay: Value = serde_json::from_slice(&output)
        .unwrap_or_else(|parse_error| panic!("invalid replay output: {parse_error}"));
    assert_eq!(replay["matched"], true);
}

#[test]
fn invalid_request_is_rejected_before_executor_activation() {
    let (_temporary, _package, runtime) = build_runtime("invalid");
    let error = match runtime.run(
        "diagnose_fault",
        "invalid",
        json!({"equipment_id": "pump-1"}),
        Duration::from_secs(1),
    ) {
        Ok(_) => panic!("request without symptom must fail"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        d2i_runtime_api::RuntimeError::InvalidRequest(_)
    ));
}

#[test]
fn loader_rejects_incompatible_target_and_missing_binding() {
    let target_temp = TempDirectory::new("target-mismatch");
    let target_source = target_temp.0.join("source");
    copy_tree(&example_pack(), &target_source);
    replace_in_file(
        &target_source.join("domain.yaml"),
        "os: \"any\"",
        "os: \"definitely-not-this-host\"",
    );
    let target_package = target_temp.0.join("target.d2ip");
    assert!(!compile_package(&target_source, &target_package).has_errors());
    assert!(matches!(
        ReferenceRuntime::load(&target_package),
        Err(d2i_runtime_api::RuntimeError::IncompatibleTarget(_))
    ));

    let binding_temp = TempDirectory::new("binding-mismatch");
    let binding_source = binding_temp.0.join("source");
    copy_tree(&example_pack(), &binding_source);
    replace_in_file(
        &binding_source.join("models/bindings.yaml"),
        "id: \"case-retriever-compact\"\n    version: \"1.0.0\"\n    kind: \"search\"",
        "id: \"case-retriever-compact\"\n    version: \"1.0.0\"\n    kind: \"device_adapter\"",
    );
    let binding_package = binding_temp.0.join("binding.d2ip");
    assert!(!compile_package(&binding_source, &binding_package).has_errors());
    assert!(matches!(
        ReferenceRuntime::load(&binding_package),
        Err(d2i_runtime_api::RuntimeError::MissingExecutor(_))
    ));
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", destination.display()));
    let entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source.display()));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read directory entry: {error}"));
        let from = entry.path();
        let to = destination.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).unwrap_or_else(|error| {
                panic!(
                    "cannot copy {} to {}: {error}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}

fn replace_in_file(path: &Path, from: &str, to: &str) {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert!(
        text.contains(from),
        "{} does not contain '{from}'",
        path.display()
    );
    fs::write(path, text.replace(from, to))
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
}
