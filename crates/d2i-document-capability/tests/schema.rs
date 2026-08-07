use d2i_document_capability::{
    DocumentContentPayloadV1, DocumentStyleRoleV1, DocumentStyleSpecV1, ZERO_HASH,
};
use d2i_office_capability::sha256_bytes;
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
    let path = repository_root().join("schemas/document").join(name);
    serde_json::from_slice(
        &fs::read(&path).unwrap_or_else(|error| panic!("schema {}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("schema JSON {}: {error}", path.display()))
}

#[test]
fn all_nineteen_document_schemas_are_strict_draft_2020_12() {
    let root = repository_root().join("schemas/document");
    let mut paths = fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("schema directory: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("schema entry: {error}"));
    paths.sort_by_key(|entry| entry.file_name());
    assert_eq!(paths.len(), 19);
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
fn schemas_validate_sealed_korean_payload_and_style() {
    let text = "2026년 7월 안전교육 결과보고서";
    let payload = DocumentContentPayloadV1 {
        schema_version: 1,
        payload_id: "payload.title".to_owned(),
        case_id: "case.office200".to_owned(),
        content_class_id: "document.heading".to_owned(),
        language_id: "ko-KR".to_owned(),
        text: text.to_owned(),
        character_count: u32::try_from(text.chars().count())
            .unwrap_or_else(|error| panic!("text length: {error}")),
        data_class_ids: vec!["internal.synthetic".to_owned()],
        source_evidence_ids: vec!["evidence.fixture".to_owned()],
        payload_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("payload: {error}"));
    let style = DocumentStyleSpecV1 {
        schema_version: 1,
        style_spec_id: "style.title".to_owned(),
        style_role: DocumentStyleRoleV1::Title,
        approved_template_style_id: Some("template.title".to_owned()),
        emphasis: true,
        style_spec_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("style: {error}"));
    for (name, value) in [
        (
            "document-content-payload-v1.schema.json",
            serde_json::to_value(payload).unwrap_or_else(|error| panic!("payload JSON: {error}")),
        ),
        (
            "document-style-spec-v1.schema.json",
            serde_json::to_value(style).unwrap_or_else(|error| panic!("style JSON: {error}")),
        ),
    ] {
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema(name))
            .unwrap_or_else(|error| panic!("schema compile {name}: {error}"));
        if let Err(errors) = compiled.validate(&value) {
            let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            panic!("schema validation {name}: {messages:?}");
        };
    }
}

#[test]
fn schemas_reject_unknown_fields_raw_paths_and_bad_hashes() {
    let schema = schema("document-operation-intent-v1.schema.json");
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("intent schema: {error}"));
    let invalid = serde_json::json!({
        "schema_version": 1,
        "intent_id": "intent.fixture",
        "case_id": "case.fixture",
        "planner_cycle_id": "cycle.fixture",
        "document_artifact_id": "artifact.fixture",
        "document_generation": 1,
        "semantic_state_sha256": sha256_bytes(b"semantic"),
        "operation": "append_paragraph",
        "target_node_ids": [],
        "content_payload_ids": ["payload.fixture"],
        "style_spec_ids": [],
        "image_spec_ids": [],
        "table_spec_id": null,
        "page_layout_spec_id": null,
        "required_postcondition_ids": ["postcondition.paragraph-present"],
        "risk_class": "reversible",
        "intent_sha256": "sha256:not-a-hash",
        "raw_path": "C:\\secret.docx"
    });
    assert!(compiled.validate(&invalid).is_err());
}
