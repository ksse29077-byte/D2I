use d2i_spreadsheet_capability::{
    spreadsheet_canonical_sha256, SpreadsheetContextBudgetV1, SpreadsheetQueryPlanV1,
    SpreadsheetQueryV1, SpreadsheetScalarV1, SPREADSHEET_SCHEMA_VERSION, ZERO_HASH,
};
use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository root: {error}"))
}

fn schema(name: &str) -> Value {
    let path = repository_root().join("schemas/spreadsheet").join(name);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("schema {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("schema JSON {}: {error}", path.display()))
}

#[test]
fn all_fifteen_spreadsheet_schemas_are_strict_draft_2020_12() {
    let root = repository_root().join("schemas/spreadsheet");
    let mut paths = fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("schema directory: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("schema entry: {error}"));
    paths.sort_by_key(|entry| entry.file_name());
    assert_eq!(paths.len(), 15);
    for entry in paths {
        let value: Value = serde_json::from_slice(
            &fs::read(entry.path())
                .unwrap_or_else(|error| panic!("schema {}: {error}", entry.path().display())),
        )
        .unwrap_or_else(|error| panic!("schema JSON {}: {error}", entry.path().display()));
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&value)
            .unwrap_or_else(|error| panic!("schema compile {}: {error}", entry.path().display()));
    }
}

#[test]
fn query_schema_validates_the_sealed_tagged_contract() {
    let snapshot = spreadsheet_canonical_sha256(&"snapshot")
        .unwrap_or_else(|error| panic!("snapshot hash: {error}"));
    let query = SpreadsheetQueryV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        query_id: "query.schema.fixture".to_owned(),
        case_id: "case.office300".to_owned(),
        workbook_snapshot_sha256: snapshot,
        table_id: "table.sheet.0001.used_range".to_owned(),
        plan: SpreadsheetQueryPlanV1::Lookup {
            key_column_id: "column.sheet.0001.0001".to_owned(),
            key_value: SpreadsheetScalarV1::Text {
                value: "record-1".to_owned(),
            },
            projection_column_ids: vec!["column.sheet.0001.0002".to_owned()],
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 8,
            maximum_bytes: 8_192,
            maximum_estimated_tokens: 2_048,
        },
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        evidence_ids: vec!["evidence.schema.fixture".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("query seal: {error}"));
    let value = serde_json::to_value(query).unwrap_or_else(|error| panic!("query JSON: {error}"));
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema("spreadsheet-query-v1.schema.json"))
        .unwrap_or_else(|error| panic!("query schema: {error}"));
    if let Err(errors) = compiled.validate(&value) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("query schema validation: {messages:?}");
    };
}

#[test]
fn tagged_unions_reject_mixed_query_mutation_and_raw_formula_fields() {
    let query_plan_schema = &schema("spreadsheet-query-v1.schema.json")["properties"]["plan"];
    let query_plan = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(query_plan_schema)
        .unwrap_or_else(|error| panic!("query-plan schema: {error}"));
    let mixed_query = serde_json::json!({
        "query_kind": "lookup",
        "key_column_id": "column.1",
        "key_value": {"value_type": "text", "value": "x"},
        "projection_column_ids": ["column.2"],
        "predicates": []
    });
    assert!(query_plan.validate(&mixed_query).is_err());

    let intent_schema = schema("spreadsheet-operation-intent-v1.schema.json");
    let mutation_schema = &intent_schema["properties"]["mutation"]["oneOf"][0];
    let nullable_mutation = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(mutation_schema)
        .unwrap_or_else(|error| panic!("mutation schema: {error}"));
    let raw_formula = serde_json::json!({
        "mutation_kind": "set_cell_formula",
        "target_cell_id": "cell.sheet.0001.r000001.c000003",
        "formula": {
            "formula_kind": "difference",
            "left_cell_id": "cell.sheet.0001.r000001.c000001",
            "right_cell_id": "cell.sheet.0001.r000001.c000002",
            "formula_text": "=WEBSERVICE(\"https://example.test\")"
        }
    });
    assert!(nullable_mutation.validate(&raw_formula).is_err());
}
