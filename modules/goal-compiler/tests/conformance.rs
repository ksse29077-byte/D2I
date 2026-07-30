use d2i_goal_compiler::{
    GoalCompilationInput, GoalCompilationResult, GoalCompiler, BUILD_ID, MODULE_ID, MODULE_VERSION,
};
use d2i_module_sdk::{
    invoke_module, load_module_manifest, parse_json_strict, run_fixture_suite, ConformanceStatus,
    FixtureSpec, InvocationContext, Module, ModuleCapability, ModuleError, ModuleErrorCode,
    ModuleMetadata, ModuleOutput, ModuleResultStatus, SchemaCatalog,
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

fn fixture(relative: &str) -> FixtureSpec {
    ok(parse_json_strict(&ok(fs::read(root().join(relative)))))
}

fn invoke_fixture(relative: &str) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = fixture(relative);
    ok(invoke_module(
        &GoalCompiler,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ))
}

#[test]
fn reference_suite_passes_and_replays_deterministically() {
    let first = ok(run_fixture_suite(&GoalCompiler, &root()));
    let second = ok(run_fixture_suite(&GoalCompiler, &root()));
    assert_eq!(first, second);
    assert_eq!(first.status, ConformanceStatus::Pass);
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.fixtures.len(), 4);
    assert_eq!(first.failed, 0);
    assert_eq!(first.skipped, 0);
}

#[test]
fn compiled_goal_schema_has_no_core_drift_and_round_trips_core_rust_type() {
    let output_schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("schemas/output.schema.json"),
    ))));
    let core_schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("../../schemas/cognitive/cognitive-ir-v1.schema.json"),
    ))));
    for definition in [
        "version",
        "token",
        "text",
        "hash",
        "value",
        "string_array",
        "provenance",
        "risk",
        "confirmation_policy",
        "comparison_op",
        "postcondition",
        "goal_spec",
    ] {
        assert_eq!(
            output_schema["$defs"][definition], core_schema["$defs"][definition],
            "Cognitive IR GoalSpec drift detected in $defs/{definition}"
        );
    }

    let result = invoke_fixture("fixtures/valid/read-only.json");
    let goal = result.payload.unwrap_or(Value::Null)["goal_spec"].clone();
    let core: d2i_cognitive_ir::GoalSpec = ok(serde_json::from_value(goal));
    ok(core.validate());
}

#[test]
fn tagged_union_rejects_mixed_variants_unknown_fields_and_bad_bounds() {
    let schema: Value = ok(parse_json_strict(&ok(fs::read(
        root().join("schemas/output.schema.json"),
    ))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let compiled = invoke_fixture("fixtures/valid/read-only.json")
        .payload
        .unwrap_or(Value::Null);
    let clarification = invoke_fixture("fixtures/valid/clarification.json")
        .payload
        .unwrap_or(Value::Null);
    assert!(validator.is_valid(&compiled));
    assert!(validator.is_valid(&clarification));

    let mut mixed = clarification.clone();
    mixed["goal_spec"] = compiled["goal_spec"].clone();
    assert!(!validator.is_valid(&mixed));
    let mut unknown = compiled;
    unknown["confidence"] = json!(0.1);
    assert!(!validator.is_valid(&unknown));
    let mut oversized = clarification;
    oversized["questions"] = Value::Array((0..65).map(|_| json!("질문")).collect());
    assert!(!validator.is_valid(&oversized));
}

#[test]
fn outer_statuses_distinguish_clarification_unsupported_and_failed() {
    let compiled = invoke_fixture("fixtures/valid/read-only.json");
    assert_eq!(compiled.status, ModuleResultStatus::Succeeded);
    assert_eq!(
        compiled.payload.as_ref().map(|payload| &payload["status"]),
        Some(&json!("compiled"))
    );

    let clarification = invoke_fixture("fixtures/valid/clarification.json");
    assert_eq!(clarification.status, ModuleResultStatus::Succeeded);
    assert_eq!(
        clarification
            .payload
            .as_ref()
            .map(|payload| &payload["status"]),
        Some(&json!("clarification_required"))
    );

    let unsupported = invoke_fixture("fixtures/unsupported/locale.json");
    assert_eq!(unsupported.status, ModuleResultStatus::Unsupported);
    assert!(unsupported.payload.is_none());
    assert!(unsupported.unsupported_reason.is_some());

    let failed = invoke_fixture("fixtures/invalid/untrusted.json");
    assert_eq!(failed.status, ModuleResultStatus::Failed);
    assert!(failed.payload.is_none());
    assert_eq!(
        failed.error.map(|error| error.code),
        Some(ModuleErrorCode::UntrustedInputViolation)
    );
}

#[test]
fn strict_parser_rejects_duplicate_and_malformed_json() {
    assert!(parse_json_strict::<Value>(br#"{"x":1,"x":2}"#).is_err());
    assert!(parse_json_strict::<Value>(br#"{"x":"#).is_err());
}

struct PanicModule;

impl Module for PanicModule {
    type Input = GoalCompilationInput;
    type Output = GoalCompilationResult;

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            module_id: MODULE_ID.to_owned(),
            module_version: MODULE_VERSION.to_owned(),
            build_id: BUILD_ID.to_owned(),
        }
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        GoalCompiler.capabilities()
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
        panic!("intentional Goal Compiler conformance panic")
    }
}

struct TimeoutModule;

impl Module for TimeoutModule {
    type Input = GoalCompilationInput;
    type Output = GoalCompilationResult;

    fn metadata(&self) -> ModuleMetadata {
        PanicModule.metadata()
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        GoalCompiler.capabilities()
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        GoalCompiler.validate_input(input, context)
    }

    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let mut output = GoalCompiler.invoke(input, context)?;
        output.logical_elapsed_ticks = 1_000;
        Ok(output)
    }
}

fn invoke_with<M: Module<Input = GoalCompilationInput, Output = GoalCompilationResult>>(
    module: &M,
) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = fixture("fixtures/valid/read-only.json");
    ok(invoke_module(
        module,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ))
}

#[test]
fn panic_and_timeout_fail_closed() {
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
