use d2i_module_sdk::{
    canonical_sha256, invoke_module, load_module_manifest, parse_json_strict, run_fixture_suite,
    ConformanceStatus, FixtureSpec, ModuleResultStatus, SchemaCatalog,
};
use d2i_plan_ranker::PlanRanker;
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
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

#[test]
fn plan_ranker_passes_its_registered_fixture_suite() {
    let first = ok(run_fixture_suite(&PlanRanker, &root()));
    let second = ok(run_fixture_suite(&PlanRanker, &root()));
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
    let report_value = serde_json::to_value(&first).unwrap_or(Value::Null);
    assert!(validator.is_valid(&report_value));
}

#[test]
fn maximum_fixture_repeats_with_identical_hash_and_bounded_resources() {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture_path = root().join("fixtures/valid/maximum-candidates.json");
    let fixture: FixtureSpec = ok(parse_json_strict(&ok(fs::read(fixture_path))));
    let first = ok(invoke_module(
        &PlanRanker,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ));
    assert_eq!(first.status, ModuleResultStatus::Succeeded, "{first:#?}");
    let first_hash = ok(canonical_sha256(&first));
    assert!(first.resource_usage.logical_operations <= 4_096);
    assert!(first.resource_usage.output_bytes <= 1_048_576);

    for _ in 1..100 {
        let replay = ok(invoke_module(
            &PlanRanker,
            &loaded,
            &schemas,
            &fixture.invocation,
            &fixture.context,
        ));
        assert_eq!(ok(canonical_sha256(&replay)), first_hash);
    }
}
