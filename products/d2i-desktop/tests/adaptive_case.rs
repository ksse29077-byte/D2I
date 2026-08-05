use d2i_adaptive_planner::{PlannerCycleRecordV1, PlannerCycleStageV1, PlannerCycleStatusV1};
use d2i_desktop::{initialize_planner_ledger, verify_planner_ledger, PlannerLedgerEventKindV1};
use d2i_situation_model::ZERO_HASH;
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::fmt::Debug;
use std::path::{Path, PathBuf};

const SCHEMAS: [&str; 15] = [
    "approved-case-context-bundle-v1.schema.json",
    "case-situation-model-v1.schema.json",
    "situation-fact-v1.schema.json",
    "goal-understanding-request-v1.schema.json",
    "goal-understanding-result-v1.schema.json",
    "intelligence-provider-descriptor-v1.schema.json",
    "intelligence-provider-invocation-v1.schema.json",
    "intelligence-provider-result-v1.schema.json",
    "adaptive-plan-v1.schema.json",
    "adaptive-planning-request-v1.schema.json",
    "adaptive-planning-result-v1.schema.json",
    "next-step-decision-v1.schema.json",
    "planner-cycle-record-v1.schema.json",
    "model-evaluation-report-v1.schema.json",
    "model-e2e-report-v1.schema.json",
];

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| panic!("workspace root is absent"))
}

struct TestRoot(PathBuf);

impl TestRoot {
    fn create(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "d2i-work500-{label}-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("thread")
        ));
        if path.exists() {
            ok(std::fs::remove_dir_all(&path));
        }
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn all_public_work500_schemas_are_strict_draft_2020_12() {
    let schema_root = workspace_root().join("schemas/workforce");
    for name in SCHEMAS {
        let bytes = ok(std::fs::read(schema_root.join(name)));
        let schema: Value = ok(serde_json::from_slice(&bytes));
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "{name} has the wrong draft"
        );
        let strict_root = schema.get("additionalProperties") == Some(&Value::Bool(false));
        let strict_union = schema
            .get("oneOf")
            .and_then(Value::as_array)
            .is_some_and(|branches| {
                !branches.is_empty()
                    && branches.iter().all(|branch| {
                        if branch.get("additionalProperties") == Some(&Value::Bool(false)) {
                            return true;
                        }
                        let Some(reference) = branch.get("$ref").and_then(Value::as_str) else {
                            return false;
                        };
                        let Some(definition) = reference.strip_prefix("#/$defs/") else {
                            return false;
                        };
                        schema
                            .pointer(&format!("/$defs/{definition}"))
                            .and_then(|value| value.get("additionalProperties"))
                            == Some(&Value::Bool(false))
                    })
            });
        assert!(
            strict_root || strict_union,
            "{name} does not reject unknown root fields"
        );
        ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
    }
}

#[test]
fn schema_unknown_field_is_rejected() {
    let path = workspace_root()
        .join("schemas/workforce")
        .join("planner-cycle-record-v1.schema.json");
    let schema: Value = ok(serde_json::from_slice(&ok(std::fs::read(path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(!validator.is_valid(&json!({"schema_version": 1, "unknown": true})));
}

#[test]
fn protected_planner_ledger_persists_and_rejects_tampering() {
    let root = TestRoot::create("ledger");
    let mut ledger = ok(initialize_planner_ledger(
        &root.0,
        "ledger.work500.test",
        "organization.test",
        "case.test",
        ZERO_HASH,
        ZERO_HASH,
        32,
        1024 * 1024,
        1_000,
    ));
    let cycle = PlannerCycleRecordV1 {
        schema_version: 1,
        cycle_id: "cycle.test.1".to_owned(),
        sequence: 1,
        case_id: "case.test".to_owned(),
        stage: PlannerCycleStageV1::ProviderInvoked,
        status: PlannerCycleStatusV1::InProgress,
        provider_invocation_sha256: Some(ZERO_HASH.to_owned()),
        provider_result_sha256: None,
        goal_spec_sha256: None,
        situation_sha256: None,
        adaptive_plan_sha256: None,
        next_step_decision_sha256: None,
        kernel_run_sha256: None,
        verification_result_sha256: None,
        reason_codes: Vec::new(),
        recorded_at_unix_seconds: 1,
        previous_record_sha256: ZERO_HASH.to_owned(),
        protected_audit_terminal_sha256: ZERO_HASH.to_owned(),
        evidence_ids: vec!["evidence.test".to_owned()],
        record_sha256: ZERO_HASH.to_owned(),
    };
    ok(ledger.append(PlannerLedgerEventKindV1::ProviderInvoked, cycle, 1_001));
    let verified = ok(verify_planner_ledger(&root.0));
    assert_eq!(verified.record_count, 1);
    assert_eq!(verified.consumed_provider_invocation_hashes.len(), 1);

    let state = root.0.join("adaptive-planner-ledger-state.json");
    let mut bytes = ok(std::fs::read(&state));
    let index = bytes
        .iter()
        .position(|value| *value == b'1')
        .unwrap_or_else(|| panic!("ledger fixture lacks mutable byte"));
    bytes[index] = b'2';
    ok(std::fs::write(&state, bytes));
    assert!(verify_planner_ledger(&root.0).is_err());
}
