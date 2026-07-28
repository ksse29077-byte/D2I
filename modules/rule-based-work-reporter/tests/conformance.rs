use d2i_desktop::WorkReport;
use d2i_module_sdk::{
    invoke_module, load_module_manifest, parse_json_strict, run_fixture_suite,
    validate_result_binding, ConformanceReport, ConformanceStatus, FixtureSpec, InvocationContext,
    Module, ModuleCapability, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput,
    ModuleProvenance, ModuleResultStatus, SchemaCatalog, SelfCheck, CONFORMANCE_EXIT_FAILED,
};
use d2i_rule_based_work_reporter::{
    RuleBasedWorkReporter, WorkReporterInput, BUILD_ID, MODULE_ID, MODULE_VERSION,
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

fn valid_fixture() -> FixtureSpec {
    let path = root().join("fixtures/valid/single-step.json");
    ok(parse_json_strict(&ok(fs::read(path))))
}

fn metadata() -> ModuleMetadata {
    ModuleMetadata {
        module_id: MODULE_ID.to_owned(),
        module_version: MODULE_VERSION.to_owned(),
        build_id: BUILD_ID.to_owned(),
    }
}

fn capabilities() -> Vec<ModuleCapability> {
    RuleBasedWorkReporter.capabilities()
}

#[test]
fn reference_module_passes_with_stable_machine_readable_report() {
    let first = ok(run_fixture_suite(&RuleBasedWorkReporter, &root()));
    let second = ok(run_fixture_suite(&RuleBasedWorkReporter, &root()));
    assert_eq!(first, second);
    assert_eq!(first.status, ConformanceStatus::Pass);
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.failed, 0);
    assert_eq!(first.skipped, 0);

    let schema_path = root().join("../../schemas/modules/module-conformance-report-v1.schema.json");
    let schema: Value = ok(parse_json_strict(&ok(fs::read(schema_path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(validator.is_valid(&serde_json::to_value(&first).unwrap_or(Value::Null)));
}

#[test]
fn untrusted_instruction_text_is_not_promoted_into_completed_actions() {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture: FixtureSpec = ok(parse_json_strict(&ok(fs::read(
        root().join("fixtures/valid/untrusted-content.json"),
    ))));
    let result = ok(invoke_module(
        &RuleBasedWorkReporter,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ));
    assert_eq!(result.status, ModuleResultStatus::Succeeded);
    let payload = result.payload.unwrap_or(Value::Null);
    assert_eq!(payload["completed_actions"], json!([]));
    let serialized = serde_json::to_string(&payload).unwrap_or_default();
    assert!(!serialized.contains("IGNORE POLICY"));
}

#[test]
fn result_binding_rejects_wrong_invocation_and_module_identity() {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = valid_fixture();
    let result = ok(invoke_module(
        &RuleBasedWorkReporter,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ));

    let mut wrong_invocation = result.clone();
    wrong_invocation.invocation_id = "different-invocation".to_owned();
    assert_eq!(
        validate_result_binding(&fixture.invocation, &wrong_invocation)
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::DeterministicReplayMismatch)
    );

    let mut wrong_module = result;
    wrong_module.module.build_id = "different-build".to_owned();
    assert_eq!(
        validate_result_binding(&fixture.invocation, &wrong_module)
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ArtifactMismatch)
    );
}

struct PanicModule;

impl Module for PanicModule {
    type Input = WorkReporterInput;
    type Output = WorkReport;

    fn metadata(&self) -> ModuleMetadata {
        metadata()
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        capabilities()
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
        panic!("intentional conformance panic")
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
    type Input = WorkReporterInput;
    type Output = WorkReport;

    fn metadata(&self) -> ModuleMetadata {
        metadata()
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        capabilities()
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        RuleBasedWorkReporter.validate_input(input, context)
    }

    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let mut output = RuleBasedWorkReporter.invoke(input, context)?;
        output.logical_elapsed_ticks = 1_000;
        Ok(output)
    }
}

struct InvalidOutputModule;

impl Module for InvalidOutputModule {
    type Input = WorkReporterInput;
    type Output = Value;

    fn metadata(&self) -> ModuleMetadata {
        metadata()
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        capabilities()
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
        Ok(ModuleOutput::new(
            json!({"password": "must-not-leak"}),
            ModuleProvenance {
                source_id: "broken-module".to_owned(),
                source_sha256:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        .to_owned(),
                producer: MODULE_ID.to_owned(),
            },
        ))
    }
}

fn invoke_with<M: Module<Input = WorkReporterInput>>(
    module: &M,
) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = valid_fixture();
    ok(invoke_module(
        module,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ))
}

#[test]
fn panic_timeout_and_secret_output_fail_closed() {
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

    let invalid = invoke_with(&InvalidOutputModule);
    assert_eq!(invalid.status, ModuleResultStatus::Failed);
    assert!(invalid.payload.is_none());
    assert_eq!(
        invalid.error.map(|error| error.code),
        Some(ModuleErrorCode::InvalidInput)
    );
}

#[test]
fn intentionally_broken_module_fails_and_skipped_is_not_pass() {
    let report = ok(run_fixture_suite(&PanicModule, &root()));
    assert_eq!(report.status, ConformanceStatus::Fail);
    assert_eq!(report.exit_code, CONFORMANCE_EXIT_FAILED);
    assert!(report.failed > 0);

    let skipped = ConformanceReport {
        schema_version: 1,
        module_id: MODULE_ID.to_owned(),
        module_version: MODULE_VERSION.to_owned(),
        manifest_sha256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            .to_owned(),
        status: ConformanceStatus::Skipped,
        checks: Vec::new(),
        fixtures: Vec::new(),
        passed: 0,
        failed: 0,
        unsupported: 0,
        skipped: 1,
        exit_code: CONFORMANCE_EXIT_FAILED,
        report_hash: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            .to_owned(),
    };
    assert!(!skipped.is_pass());
}
