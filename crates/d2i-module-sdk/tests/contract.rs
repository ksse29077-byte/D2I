use d2i_module_sdk::{
    canonical_sha256, load_module_manifest, parse_json_strict, validate_invocation,
    validate_module_manifest, InvocationContext, ModuleError, ModuleErrorCode, ModuleIdentifier,
    ModuleInvocationEnvelope, ModuleManifest, ModuleProvenance, NetworkRequirement,
    RedactionMarker, ReplayContext, ResourceBudget, CONTRACT_VERSION_V1,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempModule {
    path: PathBuf,
}

impl TempModule {
    fn copy_from(source: &Path) -> Self {
        let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-module-sdk-test-{}-{suffix}",
            std::process::id()
        ));
        ok(fs::create_dir_all(path.join("artifacts")));
        ok(fs::create_dir_all(path.join("schemas")));
        for relative in [
            "module-manifest.yaml",
            "artifacts/example-module.ref",
            "schemas/input.schema.json",
            "schemas/output.schema.json",
        ] {
            ok(fs::copy(source.join(relative), path.join(relative)));
        }
        Self { path }
    }
}

impl Drop for TempModule {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn hash(byte: u8) -> String {
    format!("sha256:{byte:02x}{}", "0".repeat(62))
}

fn identifier() -> ModuleIdentifier {
    ModuleIdentifier {
        module_id: "test-module".to_owned(),
        module_version: "1.2.3".to_owned(),
        contract_version: CONTRACT_VERSION_V1,
        build_id: "test-build".to_owned(),
        artifact_sha256: hash(1),
        manifest_sha256: hash(2),
    }
}

fn invocation() -> ModuleInvocationEnvelope {
    ModuleInvocationEnvelope {
        contract_version: CONTRACT_VERSION_V1,
        invocation_id: "invoke-1".to_owned(),
        module: identifier(),
        requested_capability: "test.transform".to_owned(),
        input_schema_id: "test-input-v1".to_owned(),
        input_schema_version: 1,
        payload: json!({"text": "data"}),
        goal_id: "goal-1".to_owned(),
        source_observation_hash: Some(hash(3)),
        plan_generation_id: Some("plan-1".to_owned()),
        logical_sequence: 1,
        deadline_logical_tick: 10,
        resource_budget: ResourceBudget {
            max_input_bytes: 1024,
            max_output_bytes: 1024,
            memory_bytes: 4096,
            logical_operation_budget: 100,
        },
        trust_labels: BTreeSet::from(["fixture".to_owned()]),
        redactions: vec![RedactionMarker {
            field: "sensitive".to_owned(),
            reason: "redacted in fixture".to_owned(),
            replacement_sha256: hash(4),
        }],
        provenance: ModuleProvenance {
            source_id: "fixture-1".to_owned(),
            source_sha256: hash(5),
            producer: "test-author".to_owned(),
        },
        replay: ReplayContext {
            replay_id: "replay-1".to_owned(),
            seed: 7,
            fixture_hash: hash(6),
        },
        correlation_id: "correlation-1".to_owned(),
        trace_id: "trace-1".to_owned(),
    }
}

fn module_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../modules")
        .join(name)
}

#[test]
fn identifier_invocation_round_trip_and_schema_are_strict() {
    let value = invocation();
    assert!(value.validate().is_ok());
    let bytes = ok(serde_json::to_vec(&value));
    let decoded: ModuleInvocationEnvelope = ok(parse_json_strict(&bytes));
    assert_eq!(decoded, value);

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/modules/cognitive-module-contract-v1.schema.json");
    let schema: Value = ok(parse_json_strict(&ok(fs::read(schema_path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(validator.is_valid(&serde_json::to_value(&value).unwrap_or(Value::Null)));

    let mut unknown = serde_json::to_value(&value).unwrap_or(Value::Null);
    if let Some(object) = unknown.as_object_mut() {
        object.insert("unknown".to_owned(), json!(true));
    }
    assert!(!validator.is_valid(&unknown));
    assert!(serde_json::from_value::<ModuleInvocationEnvelope>(unknown).is_err());
}

#[test]
fn invalid_version_hash_enum_and_secret_fields_fail_closed() {
    let mut bad_version = invocation();
    bad_version.contract_version = 2;
    assert_eq!(
        bad_version.validate().err().map(|error| error.code),
        Some(ModuleErrorCode::ContractVersionMismatch)
    );

    let mut bad_hash = identifier();
    bad_hash.artifact_sha256 = "sha256:ABC".to_owned();
    assert!(bad_hash.validate().is_err());

    let invalid_enum = serde_json::to_vec(&json!({
        "code": "made_up",
        "retryable": false,
        "user_action_required": false,
        "message": "invalid",
        "redacted_detail": null,
        "fallback_available": false
    }))
    .unwrap_or_default();
    assert!(parse_json_strict::<ModuleError>(&invalid_enum).is_err());

    let mut secret = invocation();
    secret.payload = json!({"authentication_token": "must-not-cross"});
    assert_eq!(
        secret.validate().err().map(|error| error.code),
        Some(ModuleErrorCode::InvalidInput)
    );
}

#[test]
fn canonical_hash_is_key_order_independent_and_duplicate_keys_are_rejected() {
    let first = json!({"b": 2, "a": {"d": 4, "c": 3}});
    let second = json!({"a": {"c": 3, "d": 4}, "b": 2});
    assert_eq!(ok(canonical_sha256(&first)), ok(canonical_sha256(&second)));
    assert!(parse_json_strict::<Value>(br#"{"a":1,"a":2}"#).is_err());

    let deeply_nested = format!("{}0{}", "[".repeat(70), "]".repeat(70));
    assert!(parse_json_strict::<Value>(deeply_nested.as_bytes()).is_err());
}

#[test]
fn manifest_load_binds_artifact_schemas_defaults_and_identity() {
    let loaded = ok(load_module_manifest(&module_root(
        "rule-based-work-reporter",
    )));
    assert_eq!(loaded.identifier.module_id, "rule-based-work-reporter");
    assert_eq!(
        loaded.manifest.execution.network_requirement,
        NetworkRequirement::Denied
    );
    assert!(!loaded.manifest.execution.side_effect);
    assert!(loaded.manifest.identity.manifest_sha256.is_none());
    assert_eq!(
        loaded.manifest_sha256,
        ok(loaded.manifest.canonical_manifest_hash())
    );

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/modules/module-manifest-v1.schema.json");
    let schema: Value = ok(parse_json_strict(&ok(fs::read(schema_path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(validator.is_valid(&serde_json::to_value(&loaded.manifest).unwrap_or(Value::Null)));
}

#[test]
fn omitted_security_authority_fields_take_deny_by_default_values() {
    let source = ok(fs::read_to_string(
        module_root("example-module").join("module-manifest.yaml"),
    ));
    let omitted = source
        .lines()
        .filter(|line| {
            !matches!(
                line.trim_start(),
                value
                    if value.starts_with("network_requirement:")
                        || value.starts_with("side_effect:")
                        || value.starts_with("filesystem_required:")
                        || value.starts_with("environment_variables_allowed:")
                        || value.starts_with("secrets_required:")
                        || value.starts_with("raw_secret_input:")
                        || value.starts_with("privileged_operation:")
                        || value.starts_with("fail_policy:")
                        || value.starts_with("data_retention:")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let manifest: ModuleManifest = ok(serde_yaml::from_str(&omitted));
    assert_eq!(
        manifest.execution.network_requirement,
        NetworkRequirement::Denied
    );
    assert!(!manifest.execution.side_effect);
    assert!(!manifest.execution.filesystem_required);
    assert!(!manifest.execution.environment_variables_allowed);
    assert!(!manifest.security.secrets_required);
    assert!(!manifest.security.raw_secret_input);
    assert!(!manifest.security.privileged_operation);
    assert_eq!(
        manifest.security.fail_policy,
        d2i_module_sdk::FailPolicy::Closed
    );
    assert_eq!(
        manifest.security.data_retention,
        d2i_module_sdk::DataRetention::None
    );
}

#[test]
fn manifest_semantics_reject_capability_path_execution_and_license_failures() {
    let loaded = ok(load_module_manifest(&module_root("example-module")));

    let mut duplicate = loaded.manifest.clone();
    duplicate
        .capabilities
        .push(duplicate.capabilities[0].clone());
    assert!(validate_module_manifest(&duplicate)
        .iter()
        .any(|issue| issue.code == "D2IM1012"));

    let mut traversal = loaded.manifest.clone();
    traversal.schemas[0].path = "../escape.json".to_owned();
    assert!(validate_module_manifest(&traversal)
        .iter()
        .any(|issue| issue.code == "D2IM1020"));

    let mut network = loaded.manifest.clone();
    network.execution.network_requirement = NetworkRequirement::Required;
    assert!(validate_module_manifest(&network)
        .iter()
        .any(|issue| issue.code == "D2IM1033"));

    let mut side_effect = loaded.manifest.clone();
    side_effect.execution.side_effect = true;
    assert!(validate_module_manifest(&side_effect)
        .iter()
        .any(|issue| issue.code == "D2IM1034"));

    let mut license = loaded.manifest;
    license.provenance_and_license.artifact_license.clear();
    assert!(validate_module_manifest(&license)
        .iter()
        .any(|issue| issue.code == "D2IM1060"));
}

#[test]
fn artifact_tamper_and_manifest_identity_drift_are_detected() {
    let source = module_root("example-module");
    let artifact_tamper = TempModule::copy_from(&source);
    ok(fs::write(
        artifact_tamper.path.join("artifacts/example-module.ref"),
        b"tampered artifact",
    ));
    assert_eq!(
        load_module_manifest(&artifact_tamper.path)
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ArtifactMismatch)
    );

    let manifest_tamper = TempModule::copy_from(&source);
    let original = ok(load_module_manifest(&manifest_tamper.path));
    let manifest_path = manifest_tamper.path.join("module-manifest.yaml");
    let source_text = ok(fs::read_to_string(&manifest_path));
    ok(fs::write(
        &manifest_path,
        source_text.replace(
            "Copyable deterministic text transformation module.",
            "Tampered deterministic text transformation module.",
        ),
    ));
    let changed = ok(load_module_manifest(&manifest_tamper.path));
    assert_ne!(original.manifest_sha256, changed.manifest_sha256);

    let mut stale = invocation();
    stale.module = original.identifier;
    stale.requested_capability = "example.normalize-text".to_owned();
    stale.input_schema_id = "example-input-v1".to_owned();
    stale.payload = json!({"text": "data", "mode": "normalize"});
    stale.resource_budget = ResourceBudget {
        max_input_bytes: 65536,
        max_output_bytes: 65536,
        memory_bytes: 1048576,
        logical_operation_budget: 100,
    };
    stale.trust_labels = BTreeSet::from(["fixture".to_owned()]);
    let context = InvocationContext {
        current_logical_tick: 1,
        current_observation_hash: stale.source_observation_hash.clone(),
        current_plan_generation_id: stale.plan_generation_id.clone(),
        allowed_trust_labels: stale.trust_labels.clone(),
        invocation_trust_labels: stale.trust_labels.clone(),
    };
    assert_eq!(
        validate_invocation(&changed, &stale, &context)
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ArtifactMismatch)
    );
}

#[test]
fn module_error_builder_preserves_stable_policy_fields() {
    let error = ModuleError::new(
        ModuleErrorCode::DependencyUnavailable,
        "dependency unavailable",
    )
    .retryable(true)
    .user_action_required(true)
    .fallback_available(true)
    .with_redacted_detail("dependency identifier only");
    assert!(error.validate().is_ok());
    assert!(error.retryable);
    assert!(error.user_action_required);
    assert!(error.fallback_available);
    assert_eq!(error.code, ModuleErrorCode::DependencyUnavailable);
}
