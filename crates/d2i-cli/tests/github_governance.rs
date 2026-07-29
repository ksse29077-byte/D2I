use serde_yaml::{Mapping, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    match fs::read_to_string(&full) {
        Ok(value) => value,
        Err(error) => panic!("cannot read {}: {error}", full.display()),
    }
}

fn yaml(path: &str) -> Value {
    let content = read(path);
    match serde_yaml::from_str(&content) {
        Ok(value) => value,
        Err(error) => panic!("{path} is not valid YAML: {error}"),
    }
}

fn mapping<'a>(value: &'a Value, context: &str) -> &'a Mapping {
    match value {
        Value::Mapping(value) => value,
        _ => panic!("{context} must be a YAML mapping"),
    }
}

fn sequence<'a>(value: &'a Value, context: &str) -> &'a Vec<Value> {
    match value {
        Value::Sequence(value) => value,
        _ => panic!("{context} must be a YAML sequence"),
    }
}

fn field<'a>(map: &'a Mapping, key: &str, context: &str) -> &'a Value {
    match map.get(Value::String(key.to_owned())) {
        Some(value) => value,
        None => panic!("{context} is missing '{key}'"),
    }
}

fn string<'a>(value: &'a Value, context: &str) -> &'a str {
    match value {
        Value::String(value) => value,
        _ => panic!("{context} must be a string"),
    }
}

fn form_ids(value: &Value, path: &str) -> Vec<String> {
    let root = mapping(value, path);
    let body = sequence(field(root, "body", path), "issue form body");
    body.iter()
        .filter_map(|item| {
            let item = mapping(item, "issue form item");
            item.get(Value::String("id".to_owned()))
                .map(|value| string(value, "issue form id").to_owned())
        })
        .collect()
}

#[test]
fn github_yaml_and_issue_forms_have_required_structure() {
    let config = yaml(".github/ISSUE_TEMPLATE/config.yml");
    let config = mapping(&config, "Issue template config");
    assert_eq!(
        field(config, "blank_issues_enabled", "Issue template config"),
        &Value::Bool(false)
    );

    let module = yaml(".github/ISSUE_TEMPLATE/cognitive-module.yml");
    let module_ids = form_ids(&module, "Cognitive Module Issue Form");
    for required in [
        "module_name",
        "module_id",
        "assignee",
        "classification",
        "priority",
        "purpose",
        "contract",
        "limits",
        "data_model_license",
        "evaluation_security",
        "completion",
    ] {
        assert!(
            module_ids.iter().any(|value| value == required),
            "Cognitive Module Issue Form is missing '{required}'"
        );
    }

    let rfc = yaml(".github/ISSUE_TEMPLATE/core-contract-rfc.yml");
    let rfc_ids = form_ids(&rfc, "Core RFC Issue Form");
    for required in [
        "blocked_issue",
        "current_contract_gap",
        "rationale",
        "alternatives",
        "compatibility",
        "impact",
        "decision",
        "gate",
    ] {
        assert!(
            rfc_ids.iter().any(|value| value == required),
            "Core RFC Issue Form is missing '{required}'"
        );
    }

    let workflow = yaml(".github/workflows/module-pr.yml");
    let workflow = mapping(&workflow, "module-pr workflow");
    let events = mapping(
        field(workflow, "on", "module-pr workflow"),
        "module-pr workflow events",
    );
    assert!(events.contains_key(Value::String("pull_request".to_owned())));
    assert!(!events.contains_key(Value::String("pull_request_target".to_owned())));
    let permissions = mapping(
        field(workflow, "permissions", "module-pr workflow"),
        "module-pr permissions",
    );
    assert_eq!(
        permissions.get(Value::String("contents".to_owned())),
        Some(&Value::String("read".to_owned()))
    );

    let ci = yaml(".github/workflows/ci.yml");
    let ci = mapping(&ci, "workspace CI");
    let jobs = mapping(field(ci, "jobs", "workspace CI"), "workspace CI jobs");
    let rust = mapping(
        field(jobs, "rust", "workspace CI jobs"),
        "workspace CI rust job",
    );
    assert_eq!(
        field(rust, "runs-on", "workspace CI rust job"),
        &Value::String("windows-latest".to_owned())
    );
    let serialized = match serde_yaml::to_string(&ci) {
        Ok(value) => value,
        Err(error) => panic!("cannot serialize workspace CI for inspection: {error}"),
    };
    for command in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        "cargo test --workspace --all-features",
        "cargo build --workspace --release",
    ] {
        assert!(
            serialized.contains(command),
            "workspace CI is missing '{command}'"
        );
    }
}

#[test]
fn core_ownership_and_module_ci_cover_contract_boundary() {
    let codeowners = read(".github/CODEOWNERS");
    let core_paths = read(".github/core-owned-paths.txt");
    for protected in [
        "schemas/cognitive/",
        "schemas/modules/",
        "crates/d2i-module-sdk/",
        "products/d2i-desktop/src/cognitive.rs",
        "crates/d2i-runtime-api/",
        "crates/d2i-ffi/",
        "crates/d2i-windows-host/",
    ] {
        assert!(
            codeowners.contains(protected),
            "CODEOWNERS does not cover {protected}"
        );
        assert!(
            core_paths.contains(protected),
            "Core-owned path list does not cover {protected}"
        );
    }

    let validator = read("scripts/ci/validate-module-pr.ps1");
    for required in [
        "'module', 'validate'",
        "'--test', 'conformance'",
        "fixtures/$kind",
        "untrusted_content",
        "replay_count",
        "licenses.json",
        "Core-owned paths",
        "module/<issue-number>-<module-id>",
    ] {
        assert!(
            validator.contains(required),
            "module PR validator is missing '{required}'"
        );
    }
}
