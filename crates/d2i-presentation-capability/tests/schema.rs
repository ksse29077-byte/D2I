use d2i_presentation_capability::{
    presentation_canonical_sha256, PresentationQueryPlanV1, PresentationQueryV1, ZERO_HASH,
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
    let path = repository_root().join("schemas/presentation").join(name);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("schema {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("schema JSON {}: {error}", path.display()))
}

#[test]
fn all_twenty_seven_presentation_schemas_are_strict_draft_2020_12() {
    let root = repository_root().join("schemas/presentation");
    let mut paths = fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("schema directory: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("schema entry: {error}"));
    paths.sort_by_key(|entry| entry.file_name());
    assert_eq!(paths.len(), 27);
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
fn query_schema_validates_a_sealed_tagged_contract() {
    let query = PresentationQueryV1 {
        schema_version: 1,
        query_id: "query.presentation.schema".to_owned(),
        case_id: "case.office400".to_owned(),
        presentation_snapshot_sha256: presentation_canonical_sha256(&"snapshot")
            .unwrap_or_else(|error| panic!("snapshot hash: {error}")),
        plan: PresentationQueryPlanV1::TemplateSlides {
            layout_ids: vec!["layout.title-body".to_owned()],
        },
        maximum_results: 8,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 61_000,
        evidence_ids: vec!["evidence.presentation.schema".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("query seal: {error}"));
    let value = serde_json::to_value(query).unwrap_or_else(|error| panic!("query JSON: {error}"));
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema("presentation-query-v1.schema.json"))
        .unwrap_or_else(|error| panic!("query schema: {error}"));
    if let Err(errors) = compiled.validate(&value) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("query schema validation: {messages:?}");
    };
}

#[test]
fn tagged_unions_reject_mixed_raw_or_unknown_fields() {
    let query = schema("presentation-query-v1.schema.json");
    let query_plan = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&query["properties"]["plan"])
        .unwrap_or_else(|error| panic!("query-plan schema: {error}"));
    let mixed = serde_json::json!({
        "query_kind": "template_slides",
        "layout_ids": ["layout.title-body"],
        "slide_ids": ["slide.0001"]
    });
    assert!(query_plan.validate(&mixed).is_err());

    let intent = schema("presentation-operation-intent-v1.schema.json");
    let mutation = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&intent["properties"]["mutation"]["oneOf"][0])
        .unwrap_or_else(|error| panic!("mutation schema: {error}"));
    let raw_com = serde_json::json!({
        "mutation_kind": "set_text",
        "slide_id": "slide.0001",
        "shape_id": "shape.body",
        "text": "safe summary",
        "com_method": "PowerPoint.Application"
    });
    assert!(mutation.validate(&raw_com).is_err());
}
