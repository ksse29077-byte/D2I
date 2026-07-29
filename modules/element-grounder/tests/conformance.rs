use d2i_element_grounder::{
    ElementGrounder, ElementGroundingInput, ElementGroundingResult, BUILD_ID, MODULE_ID,
    MODULE_VERSION,
};
use d2i_module_sdk::{
    invoke_module, load_module_manifest, parse_json_strict, run_fixture_suite, ConformanceStatus,
    FixtureSpec, InvocationContext, Module, ModuleCapability, ModuleError, ModuleErrorCode,
    ModuleMetadata, ModuleOutput, ModuleResultStatus, SchemaCatalog, SelfCheck,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn load_fixture(relative: &str) -> FixtureSpec {
    ok(parse_json_strict(&ok(fs::read(root().join(relative)))))
}

fn invoke_fixture(relative: &str) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = load_fixture(relative);
    ok(invoke_module(
        &ElementGrounder,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ))
}

#[test]
fn reference_module_passes_with_stable_machine_readable_report() {
    let first = ok(run_fixture_suite(&ElementGrounder, &root()));
    let second = ok(run_fixture_suite(&ElementGrounder, &root()));
    assert_eq!(first, second);
    assert_eq!(first.status, ConformanceStatus::Pass);
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.failed, 0);
    assert_eq!(first.skipped, 0);
    assert_eq!(first.fixtures.len(), 6);

    let schema_path = root().join("../../schemas/modules/module-conformance-report-v1.schema.json");
    let schema: Value = ok(parse_json_strict(&ok(fs::read(schema_path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(validator.is_valid(&serde_json::to_value(&first).unwrap_or(Value::Null)));
}

#[test]
fn mirrored_cognitive_types_match_core_schema_definitions() {
    let module_schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("schemas/input.schema.json"),
    ))));
    let core_schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("../../schemas/cognitive/cognitive-ir-v1.schema.json"),
    ))));
    let mirrored = [
        "version",
        "token",
        "text",
        "hash",
        "value",
        "string_array",
        "provenance",
        "trust_label",
        "source_kind",
        "observable_element",
        "redaction",
        "observation_snapshot",
        "world_fact",
        "world_state",
    ];
    for definition in mirrored {
        assert_eq!(
            module_schema["$defs"][definition], core_schema["$defs"][definition],
            "Cognitive IR schema drift detected in $defs/{definition}"
        );
    }
}

#[test]
fn output_schema_enforces_selection_and_score_invariants() {
    let schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("schemas/output.schema.json"),
    ))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let valid = invoke_fixture("fixtures/valid/exact-label.json")
        .payload
        .unwrap_or(Value::Null);
    assert!(validator.is_valid(&valid));

    let mut non_unique_selection = valid.clone();
    non_unique_selection["status"] = json!("ambiguous");
    assert!(!validator.is_valid(&non_unique_selection));

    let mut invalid_score = valid;
    invalid_score["candidates"][0]["score"] = json!(1.1);
    assert!(!validator.is_valid(&invalid_score));
}

#[test]
fn stale_and_wrong_version_inputs_fail_before_module_output() {
    let stale = invoke_fixture("fixtures/invalid/stale-observation.json");
    assert_eq!(stale.status, ModuleResultStatus::Failed);
    assert_eq!(
        stale.error.map(|error| error.code),
        Some(ModuleErrorCode::DeterministicReplayMismatch)
    );
    assert!(stale.payload.is_none());

    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let mut fixture = load_fixture("fixtures/valid/exact-label.json");
    fixture.invocation.payload["schema_version"] = json!(2);
    let wrong_version = ok(invoke_module(
        &ElementGrounder,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ));
    assert_eq!(wrong_version.status, ModuleResultStatus::Failed);
    assert_eq!(
        wrong_version.error.map(|error| error.code),
        Some(ModuleErrorCode::SchemaMismatch)
    );
}

#[test]
fn untrusted_fixture_preserves_labels_as_data_without_secret_output() {
    let result = invoke_fixture("fixtures/security/untrusted-secret-content.json");
    assert_eq!(result.status, ModuleResultStatus::Succeeded);
    let payload = result.payload.unwrap_or(Value::Null);
    assert_eq!(payload["selected_element_id"], json!("element-real"));
    assert_eq!(payload["status"], json!("unique_match"));
    assert!(payload["candidates"]
        .as_array()
        .is_some_and(|candidates| candidates.iter().all(|candidate| {
            candidate["element_id"] != json!("element-secret")
                && candidate["trust_labels"] == json!(["untrusted_web_content"])
        })));
    let serialized = ok(serde_json::to_string(&payload));
    assert!(!serialized.contains("must-not-leak"));
    assert!(!serialized.contains("sk-secret"));
    assert!(payload["warnings"]
        .as_array()
        .is_some_and(|warnings| warnings.iter().any(|warning| warning
            .as_str()
            .is_some_and(|text| text.contains("only as data")))));
}

#[test]
fn strict_parser_rejects_duplicate_keys_and_malformed_json() {
    assert!(parse_json_strict::<Value>(br#"{"a":1,"a":2}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"a":"#).is_err());
}

struct PanicModule;

impl Module for PanicModule {
    type Input = ElementGroundingInput;
    type Output = ElementGroundingResult;

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            module_id: MODULE_ID.to_owned(),
            module_version: MODULE_VERSION.to_owned(),
            build_id: BUILD_ID.to_owned(),
        }
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        ElementGrounder.capabilities()
    }

    fn validate_input(
        &self,
        _input: &Self::Input,
        _context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        Ok(())
    }

    fn invoke(
        &self,
        _input: Self::Input,
        _context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        panic!("intentional Element Grounder conformance panic")
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec!["panic simulation".to_owned()],
        }
    }
}

struct TimeoutModule;

impl Module for TimeoutModule {
    type Input = ElementGroundingInput;
    type Output = ElementGroundingResult;

    fn metadata(&self) -> ModuleMetadata {
        PanicModule.metadata()
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        ElementGrounder.capabilities()
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        ElementGrounder.validate_input(input, context)
    }

    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let mut output = ElementGrounder.invoke(input, context)?;
        output.logical_elapsed_ticks = 1_000;
        Ok(output)
    }
}

fn invoke_with<M: Module<Input = ElementGroundingInput, Output = ElementGroundingResult>>(
    module: &M,
) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = load_fixture("fixtures/valid/exact-label.json");
    ok(invoke_module(
        module,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ))
}

#[test]
fn panic_and_logical_timeout_are_contained_fail_closed() {
    let panic = invoke_with(&PanicModule);
    assert_eq!(panic.status, ModuleResultStatus::Failed);
    assert_eq!(
        panic.error.map(|error| error.code),
        Some(ModuleErrorCode::PanicOrAbnormalTermination)
    );

    let timeout = invoke_with(&TimeoutModule);
    assert_eq!(timeout.status, ModuleResultStatus::Failed);
    assert_eq!(
        timeout.error.map(|error| error.code),
        Some(ModuleErrorCode::Timeout)
    );
}
