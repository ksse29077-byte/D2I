use d2i_office_capability::{
    canonical_sha256, sha256_bytes, CapabilitySourceKindV1, CapabilitySourceRecordV1,
    CapabilityTransportClassV1, McpToolCatalogSnapshotV1, SourceAssessmentStatusV1,
    ToolScopeClassV1, ToolSideEffectClassV1, ZERO_HASH,
};
use jsonschema::{Draft, JSONSchema};
use serde::Deserialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceLockV1 {
    schema_version: u32,
    assessed_at: String,
    runtime_policy: String,
    sources: Vec<SourceSeedV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSeedV1 {
    source_id: String,
    source_name: String,
    application_family_ids: Vec<String>,
    authority: String,
    source_url: String,
    exact_revision: String,
    content_sha256: String,
    license_id: String,
    license_verified: bool,
    runtime_language_ids: Vec<String>,
    architecture: String,
    tool_count: u32,
    capability_flags: Vec<String>,
    known_security_advisory_ids: Vec<String>,
    assessment_status: SourceAssessmentStatusV1,
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository root: {error}"))
}

fn source_lock() -> SourceLockV1 {
    let bytes =
        fs::read(repository_root().join("sources/office/office-capability-sources.lock.json"))
            .unwrap_or_else(|error| panic!("source lock: {error}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("source lock JSON: {error}"))
}

fn has_flag(seed: &SourceSeedV1, flag: &str) -> bool {
    seed.capability_flags.iter().any(|value| value == flag)
}

fn catalog(seed: &SourceSeedV1) -> Option<McpToolCatalogSnapshotV1> {
    if seed.authority == "official" {
        return None;
    }
    let count = usize::try_from(seed.tool_count)
        .unwrap_or_else(|error| panic!("tool count {}: {error}", seed.source_id));
    let ids = (0..count)
        .map(|index| format!("tool-{index:03}"))
        .collect::<Vec<_>>();
    let input_hashes = ids
        .iter()
        .map(|id| sha256_bytes(format!("{}:{id}:input", seed.source_id).as_bytes()))
        .collect::<Vec<_>>();
    let output_hashes = ids
        .iter()
        .map(|id| sha256_bytes(format!("{}:{id}:output", seed.source_id).as_bytes()))
        .collect::<Vec<_>>();
    let side_effect = if has_flag(seed, "process_launch") {
        ToolSideEffectClassV1::ProcessExecution
    } else {
        ToolSideEffectClassV1::FileMutation
    };
    let file_scope = if has_flag(seed, "raw_filesystem") {
        ToolScopeClassV1::ArbitraryLocal
    } else {
        ToolScopeClassV1::BoundedWorkspace
    };
    let process_scope = if has_flag(seed, "process_launch") {
        ToolScopeClassV1::ArbitraryLocal
    } else {
        ToolScopeClassV1::None
    };
    Some(
        McpToolCatalogSnapshotV1 {
            schema_version: 1,
            source_record_sha256: sha256_bytes(b"pending-source-record"),
            protocol_version: "pinned-repository-snapshot".to_owned(),
            transport_class: CapabilityTransportClassV1::Stdio,
            server_name: seed.source_id.clone(),
            server_version: seed.exact_revision.clone(),
            tool_ids: ids,
            tool_input_schema_sha256s: input_hashes,
            tool_output_schema_sha256s: output_hashes,
            tool_side_effect_classes: vec![side_effect; count],
            tool_filesystem_scope_classes: vec![file_scope; count],
            tool_process_scope_classes: vec![process_scope; count],
            tool_network_scope_classes: vec![ToolScopeClassV1::None; count],
            catalog_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .unwrap_or_else(|error| panic!("catalog {}: {error}", seed.source_id)),
    )
}

fn record(seed: &SourceSeedV1, catalog_sha256: String) -> CapabilitySourceRecordV1 {
    CapabilitySourceRecordV1 {
        schema_version: 1,
        source_id: seed.source_id.clone(),
        source_kind: if seed.authority == "official" {
            CapabilitySourceKindV1::OfficialApi
        } else {
            CapabilitySourceKindV1::PublicMcp
        },
        source_name: seed.source_name.clone(),
        source_version: "pinned".to_owned(),
        source_revision: seed.exact_revision.clone(),
        source_content_sha256: seed.content_sha256.clone(),
        publisher_or_owner_id: seed
            .source_id
            .split('.')
            .nth(1)
            .unwrap_or("unknown")
            .to_owned(),
        application_family_ids: seed.application_family_ids.clone(),
        license_id: seed.license_id.clone(),
        license_source: seed.source_url.clone(),
        license_verified: seed.license_verified,
        runtime_language_ids: seed.runtime_language_ids.clone(),
        runtime_dependency_ids: Vec::new(),
        transport_class: if seed.authority == "official" {
            CapabilityTransportClassV1::Documentation
        } else {
            CapabilityTransportClassV1::Stdio
        },
        requires_network: false,
        requires_local_application: has_flag(seed, "requires_com"),
        requires_python: has_flag(seed, "requires_python"),
        requires_node: has_flag(seed, "requires_node"),
        requires_com: has_flag(seed, "requires_com"),
        requires_admin: false,
        exposes_arbitrary_code: has_flag(seed, "arbitrary_code"),
        exposes_raw_filesystem: has_flag(seed, "raw_filesystem"),
        exposes_network: false,
        exposes_process_launch: has_flag(seed, "process_launch"),
        exposes_credentials: false,
        known_security_advisory_ids: seed.known_security_advisory_ids.clone(),
        tool_count: seed.tool_count,
        tool_catalog_sha256: catalog_sha256,
        assessment_status: seed.assessment_status,
        evidence_ids: vec!["office-capability-source-lock-v1".to_owned()],
        record_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("source {}: {error}", seed.source_id))
}

#[test]
fn source_lock_pins_official_and_public_sources_without_runtime_approval() {
    let lock = source_lock();
    assert_eq!(lock.schema_version, 1);
    assert_eq!(lock.assessed_at, "2026-08-08");
    assert_eq!(
        lock.runtime_policy,
        "reference_only_no_direct_model_execution"
    );
    assert_eq!(lock.sources.len(), 15);
    let mut official = 0;
    let mut catalogs = 0;
    let mut rejected = 0;
    let mut excel = 0;
    let mut powerpoint = 0;
    let mut hwp = 0;
    for seed in &lock.sources {
        assert!(!seed.architecture.is_empty());
        let mut catalog = catalog(seed);
        let catalog_sha256 = catalog.as_ref().map_or_else(
            || sha256_bytes(b"official-no-tool-catalog"),
            |value| value.catalog_sha256.clone(),
        );
        let source = record(seed, catalog_sha256);
        if let Some(value) = &mut catalog {
            value.source_record_sha256 = source.record_sha256.clone();
            value
                .validate_integrity()
                .unwrap_or_else(|error| panic!("linked catalog {}: {error}", seed.source_id));
            assert_eq!(value.catalog_sha256, source.tool_catalog_sha256);
            catalogs += 1;
        }
        official += u32::from(seed.authority == "official");
        rejected +=
            u32::from(seed.assessment_status == SourceAssessmentStatusV1::RejectedForRuntime);
        excel += u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.excel"),
        );
        powerpoint += u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.powerpoint"),
        );
        hwp += u32::from(
            seed.application_family_ids
                .iter()
                .any(|value| value == "office.hwp" || value == "office.hwpx"),
        );
    }
    assert!(official >= 3 && catalogs >= 6 && rejected >= 1);
    assert!(excel >= 2 && powerpoint >= 2 && hwp >= 2);
    let advisory = lock
        .sources
        .iter()
        .find(|source| source.source_id == "github.haris-musa.excel-mcp-server")
        .unwrap_or_else(|| panic!("security-risk source missing"));
    assert!(advisory
        .known_security_advisory_ids
        .iter()
        .any(|value| value == "GHSA-j98m-w3xp-9f56"));
}

#[test]
fn all_fourteen_office_schemas_are_strict_draft_2020_12() {
    let schema_root = repository_root().join("schemas/office");
    let mut paths = fs::read_dir(&schema_root)
        .unwrap_or_else(|error| panic!("schema directory: {error}"))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("schema entries: {error}"));
    paths.sort_by_key(|entry| entry.file_name());
    assert_eq!(paths.len(), 14);
    for entry in paths {
        let value: Value = serde_json::from_slice(
            &fs::read(entry.path()).unwrap_or_else(|error| panic!("schema read: {error}")),
        )
        .unwrap_or_else(|error| panic!("schema JSON: {error}"));
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
fn source_assessment_is_deterministic() {
    let lock = source_lock();
    let first = canonical_sha256(
        &lock
            .sources
            .iter()
            .map(|seed| &seed.source_id)
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|error| panic!("first hash: {error}"));
    let second = canonical_sha256(
        &lock
            .sources
            .iter()
            .map(|seed| &seed.source_id)
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|error| panic!("second hash: {error}"));
    assert_eq!(first, second);
}
