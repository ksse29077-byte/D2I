use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/design")
}

#[test]
fn every_design_schema_is_strict_draft_2020_12_and_compiles() -> TestResult {
    let mut paths = fs::read_dir(schema_root())?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert!(
        paths.len() >= 40,
        "every production Design contract needs a schema"
    );
    for path in paths {
        let schema: Value = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .map_err(|error| io::Error::other(format!("{}: {error}", path.display())))?;
        let definitions = schema["$defs"]
            .as_object()
            .ok_or_else(|| io::Error::other("schema definitions missing"))?;
        for definition in definitions
            .values()
            .filter(|value| value["type"] == "object")
        {
            assert_eq!(definition["additionalProperties"], false);
        }
    }
    Ok(())
}

#[test]
fn design_schema_arrays_and_strings_are_bounded() -> TestResult {
    let path = schema_root().join("organization-design-corpus-v1.schema.json");
    let schema: Value = serde_json::from_slice(&fs::read(path)?)?;
    let corpus = &schema["$defs"]["OrganizationDesignCorpusV1"];
    assert_eq!(corpus["properties"]["artifacts"]["maxItems"], 4096);
    assert_eq!(corpus["properties"]["organization_id"]["maxLength"], 512);
    assert_eq!(corpus["additionalProperties"], false);
    Ok(())
}

#[test]
fn optional_fields_accept_explicit_null_but_unknown_fields_fail() -> TestResult {
    let path = schema_root().join("design-artifact-record-v1.schema.json");
    let schema: Value = serde_json::from_slice(&fs::read(path)?)?;
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let mut artifact = serde_json::json!({
        "artifact_id": "artifact.alpha.1",
        "artifact_sha256": format!("sha256:{}", "1".repeat(64)),
        "format": "pptx",
        "artifact_class": "monthly_report",
        "template_family_hint": null,
        "quality_label": "approved",
        "approval_state": "unapproved",
        "approved_at_unix_ms": null,
        "unit_ratings": [],
        "template_status_id": "template.candidate",
        "data_classification_id": "internal",
        "provenance_ids": [],
        "holdout": true
    });
    assert!(compiled.is_valid(&artifact));
    artifact["unexpected"] = serde_json::json!(true);
    assert!(!compiled.is_valid(&artifact));
    Ok(())
}
