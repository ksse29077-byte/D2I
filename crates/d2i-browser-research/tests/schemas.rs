use jsonschema::{Draft, JSONSchema};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

fn schema_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/research")
}

#[test]
fn every_browser_research_schema_is_strict_bounded_draft_2020_12() -> TestResult {
    let mut paths = fs::read_dir(schema_root())?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    assert!(paths.len() >= 39, "every research contract needs a schema");
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
fn network_and_download_schemas_are_closed_and_hash_bound() -> TestResult {
    for name in [
        "research-network-profile-v1.schema.json",
        "controlled-download-request-v1.schema.json",
    ] {
        let schema: Value = serde_json::from_slice(&fs::read(schema_root().join(name))?)?;
        let title = schema["title"]
            .as_str()
            .ok_or_else(|| io::Error::other("schema title missing"))?;
        let contract = &schema["$defs"][title];
        assert_eq!(contract["additionalProperties"], false);
        let hash = contract["properties"]
            .as_object()
            .and_then(|properties| {
                properties
                    .iter()
                    .find(|(key, _)| key.ends_with("sha256"))
                    .map(|(_, value)| value)
            })
            .ok_or_else(|| io::Error::other("hash property missing"))?;
        assert_eq!(hash["pattern"], "^sha256:[0-9a-f]{64}$");
    }
    Ok(())
}
