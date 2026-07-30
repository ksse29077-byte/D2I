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
    assert!(events.contains_key(Value::String("pull_request_review".to_owned())));
    assert!(!events.contains_key(Value::String("pull_request_target".to_owned())));
    let permissions = mapping(
        field(workflow, "permissions", "module-pr workflow"),
        "module-pr permissions",
    );
    assert_eq!(
        permissions.get(Value::String("contents".to_owned())),
        Some(&Value::String("read".to_owned()))
    );

    let core_workflow = yaml(".github/workflows/core-governance.yml");
    let core_workflow = mapping(&core_workflow, "core governance workflow");
    let core_events = mapping(
        field(core_workflow, "on", "core governance workflow"),
        "core governance workflow events",
    );
    assert!(core_events.contains_key(Value::String("pull_request_target".to_owned())));
    let core_serialized = match serde_yaml::to_string(&core_workflow) {
        Ok(value) => value,
        Err(error) => panic!("cannot serialize Core governance workflow: {error}"),
    };
    for required in [
        "persist-credentials",
        "github.event.pull_request.base.sha",
        "validate-core-approval.ps1",
    ] {
        assert!(
            core_serialized.contains(required),
            "trusted Core governance is missing '{required}'"
        );
    }

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
    let workspace_test = mapping(
        field(jobs, "workspace-test", "workspace CI jobs"),
        "workspace CI test job",
    );
    assert_eq!(
        field(workspace_test, "runs-on", "workspace CI test job"),
        &Value::String("ubuntu-latest".to_owned())
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
    for owner in ["@ksse29077-byte", "@graykavinjeo"] {
        assert!(
            codeowners.contains(owner),
            "CODEOWNERS does not contain confirmed owner {owner}"
        );
    }
    assert!(
        codeowners.lines().any(|line| {
            line.starts_with("/.github/")
                && line.contains("@ksse29077-byte")
                && line.contains("@graykavinjeo")
        }),
        "CODEOWNERS must protect its own directory with both confirmed owners"
    );
    for protected in [
        "Cargo.toml",
        "Cargo.lock",
        "docs/adr/",
        "docs/collaboration/",
        "docs/modules/",
        "scripts/ci/",
        "scripts/modules/",
        "templates/cognitive-module/",
        "schemas/cognitive/",
        "schemas/modules/",
        "crates/d2i-cognitive-ir/",
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
        "classify-change.ps1",
        "check-module.ps1",
        "Cargo.lock",
        "exactly one modules/<module-id>",
        "replay_count",
        "licenses.json",
        "module/<issue-number>-<module-id>",
        "Core workflows own this change",
    ] {
        assert!(
            validator.contains(required),
            "module PR validator is missing '{required}'"
        );
    }
}

#[test]
fn module_self_merge_policy_preserves_automated_protection() {
    let ruleset = read(".github/main-ruleset.json");
    for required in [
        "\"required_approving_review_count\": 0",
        "\"required_review_thread_resolution\": true",
        "\"strict_required_status_checks_policy\": true",
        "\"context\": \"rust\"",
        "\"context\": \"workspace-test\"",
        "\"context\": \"module-governance\"",
        "\"context\": \"core-approval\"",
        "\"type\": \"deletion\"",
        "\"type\": \"non_fast_forward\"",
        "\"bypass_actors\": []",
    ] {
        assert!(
            ruleset.contains(required),
            "main ruleset is missing '{required}'"
        );
    }

    let workflow = read("docs/collaboration/module-development-workflow.md");
    for required in [
        "a third-party",
        "approval is not a merge condition",
        "Peer review remains available but is optional",
        "current-head",
        "approval from a non-author Core CODEOWNER",
    ] {
        assert!(
            workflow.contains(required),
            "module workflow is missing '{required}'"
        );
    }

    let core_control = read("docs/collaboration/core-change-control.md");
    for required in [
        "review must bind to the current head commit",
        "self-approval are not approval evidence",
        "root `Cargo.toml` and root `Cargo.lock` are always Core-owned",
    ] {
        assert!(
            core_control.contains(required),
            "Core change control is missing '{required}'"
        );
    }
}

#[test]
fn standalone_module_workspaces_are_decoupled_from_core() {
    let root_manifest = read("Cargo.toml");
    assert!(root_manifest.contains("exclude = [\"modules/*\"]"));
    for module in [
        "example-module",
        "rule-based-work-reporter",
        "goal-compiler",
        "element-grounder",
    ] {
        assert!(
            !root_manifest.contains(&format!("\"modules/{module}\"")),
            "{module} must not be a root workspace member"
        );
        let manifest = read(&format!("modules/{module}/Cargo.toml"));
        assert!(
            manifest.starts_with("[workspace]"),
            "{module} is not a standalone workspace"
        );
        assert!(
            repo_root()
                .join(format!("modules/{module}/Cargo.lock"))
                .is_file(),
            "{module} is missing its local Cargo.lock"
        );
        for forbidden in [
            "d2i-desktop",
            "d2i-runtime",
            "d2i-cli",
            "d2i-ffi",
            "d2i-windows",
        ] {
            assert!(
                !manifest.contains(forbidden),
                "{module} directly depends on forbidden Core package {forbidden}"
            );
        }
    }

    let cli_manifest = read("crates/d2i-cli/Cargo.toml");
    for module_package in [
        "d2i-example-module",
        "d2i-rule-based-work-reporter",
        "d2i-goal-compiler",
        "d2i-element-grounder",
    ] {
        assert!(
            !cli_manifest.contains(module_package),
            "Core CLI must not link {module_package}"
        );
    }

    let ci = read(".github/workflows/ci.yml");
    for required in [
        "module_only",
        "core_contract",
        "mixed_core_migration",
        "check-all-modules.ps1",
    ] {
        assert!(
            ci.contains(required),
            "CI is missing decoupling contract '{required}'"
        );
    }
    for required in [
        "git cat-file -e",
        "git merge-base",
        "A force-pushed before SHA may be unreachable",
    ] {
        assert_eq!(
            ci.matches(required).count(),
            2,
            "both CI jobs must contain force-push fallback '{required}'"
        );
    }
}
