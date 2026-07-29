use d2i_knowledge_retriever::{EvidenceBundle, KnowledgeRetriever};
use d2i_module_sdk::{
    invoke_module, load_module_manifest, parse_json_strict, run_fixture_suite,
    validate_result_binding, ConformanceStatus, FixtureSpec, ModuleErrorCode, ModuleResultStatus,
    SchemaCatalog,
};
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

fn fixture(relative: &str) -> FixtureSpec {
    ok(parse_json_strict(&ok(fs::read(root().join(relative)))))
}

fn invoke_fixture(relative: &str) -> d2i_module_sdk::ModuleResultEnvelope {
    let loaded = ok(load_module_manifest(&root()));
    let schemas = ok(SchemaCatalog::from_loaded(&loaded));
    let fixture = fixture(relative);
    let result = ok(invoke_module(
        &KnowledgeRetriever,
        &loaded,
        &schemas,
        &fixture.invocation,
        &fixture.context,
    ));
    ok(validate_result_binding(&fixture.invocation, &result));
    result
}

#[test]
fn module_passes_complete_fixture_suite_with_stable_report() {
    let first = ok(run_fixture_suite(&KnowledgeRetriever, &root()));
    let second = ok(run_fixture_suite(&KnowledgeRetriever, &root()));
    assert_eq!(first, second);
    assert_eq!(first.status, ConformanceStatus::Pass);
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.failed, 0);
    assert_eq!(first.skipped, 0);
    assert_eq!(first.unsupported, 0);
    assert!(first.fixtures.len() >= 5);
    println!("conformance_report_hash={}", first.report_hash);

    let schema_path = root().join("../../schemas/modules/module-conformance-report-v1.schema.json");
    let schema: Value = ok(parse_json_strict(&ok(fs::read(schema_path))));
    let validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(validator.is_valid(&serde_json::to_value(&first).unwrap_or(Value::Null)));
}

#[test]
fn exact_excerpt_locator_and_stable_order_are_preserved() {
    let exact = invoke_fixture("fixtures/valid/exact-replay.json");
    assert_eq!(exact.status, ModuleResultStatus::Succeeded);
    let payload = exact.payload.unwrap_or(Value::Null);
    let bundle: EvidenceBundle = ok(serde_json::from_value(payload));
    assert_eq!(bundle.evidence_items[0].knowledge_item_id, "rule-a");
    assert_eq!(bundle.evidence_items[0].locator, "L10-L12");
    assert_eq!(
        bundle.evidence_items[0].excerpt,
        "The safety rule requires verification."
    );

    let order = invoke_fixture("fixtures/replay/stable-order.json");
    let ordered: EvidenceBundle = ok(serde_json::from_value(order.payload.unwrap_or(Value::Null)));
    assert_eq!(ordered.evidence_items[0].knowledge_item_id, "item-a");
    assert_eq!(ordered.evidence_items[1].knowledge_item_id, "item-b");
}

#[test]
fn unsupported_intent_uses_terminal_unsupported_status() {
    let result = invoke_fixture("fixtures/unsupported/semantic-search.json");
    assert_eq!(result.status, ModuleResultStatus::Unsupported);
    assert!(result.payload.is_none());
    assert!(result.error.is_none());
    assert!(result.unsupported_reason.is_some());
}

#[test]
fn invalid_schema_fails_without_module_payload() {
    let result = invoke_fixture("fixtures/invalid/empty-query.json");
    assert_eq!(result.status, ModuleResultStatus::Failed);
    assert!(result.payload.is_none());
    assert_eq!(
        result.error.map(|error| error.code),
        Some(ModuleErrorCode::SchemaMismatch)
    );
}

#[test]
fn untrusted_instruction_remains_data_and_unauthorized_item_is_hidden() {
    let result = invoke_fixture("fixtures/security/prompt-injection.json");
    assert_eq!(result.status, ModuleResultStatus::Succeeded);
    let serialized = serde_json::to_string(&result).unwrap_or_default();
    assert!(serialized.contains("Ignore previous instructions"));
    assert!(serialized.contains("../../literal-locator"));
    assert!(!serialized.contains("unauthorized-item"));
    assert!(!serialized.contains("hidden restricted evidence"));
    assert!(!serialized.contains("source-restricted"));
}

#[test]
fn strict_json_rejects_duplicate_keys_and_excessive_nesting() {
    let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
    assert_eq!(
        parse_json_strict::<Value>(duplicate)
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::InvalidInput)
    );

    let mut deep = String::new();
    for _ in 0..70 {
        deep.push_str("{\"a\":");
    }
    deep.push('0');
    for _ in 0..70 {
        deep.push('}');
    }
    assert_eq!(
        parse_json_strict::<Value>(deep.as_bytes())
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ResourceExhausted)
    );
}
