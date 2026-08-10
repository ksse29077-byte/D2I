use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/pdf")
}

#[test]
fn every_pdf_schema_is_strict_bounded_draft_2020_12() -> TestResult {
    let mut paths = fs::read_dir(schema_root())?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    assert!(
        paths.len() >= 24,
        "every production PDF contract needs a schema"
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
            for property in definition["properties"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, value)| value)
            {
                if property["type"] == "array" {
                    assert_eq!(property["maxItems"], 4096);
                }
                if property["type"] == "string" {
                    assert!(property.get("maxLength").is_some());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn final_pair_schema_is_closed_and_hash_bound() -> TestResult {
    let schema: Value = serde_json::from_slice(&fs::read(
        schema_root().join("final-artifact-pair-v1.schema.json"),
    )?)?;
    let pair = &schema["$defs"]["FinalArtifactPairV1"];
    assert_eq!(pair["additionalProperties"], false);
    assert_eq!(
        pair["properties"]["pair_sha256"]["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    Ok(())
}
