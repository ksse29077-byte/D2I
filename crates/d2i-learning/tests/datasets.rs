use d2i_learning::{
    check_dataset_registry, load_dataset_registry, verify_dataset_artifacts,
    DatasetAdmissionStatus, DatasetArtifact, DatasetLicense, DatasetPurpose, DatasetRegistry,
    DatasetRegistryEntry, DatasetReviews, DatasetRiskProfile, DatasetUse, LicenseScope,
    ReviewAttestation, ReviewDecision,
};
use jsonschema::{Draft, JSONSchema};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-learning-dataset-{label}-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir(&path));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn approved_review(label: &str) -> ReviewAttestation {
    ReviewAttestation {
        reviewer_id: format!("{label}-reviewer"),
        reviewed_at_unix_seconds: 10,
        decision: ReviewDecision::Approved,
        evidence_hash: hash(label.as_bytes()),
        notes: format!("{label} review approved for the pinned artifact"),
    }
}

fn approved_registry(artifact: DatasetArtifact) -> DatasetRegistry {
    DatasetRegistry {
        schema_version: 2,
        registry_id: "approved-test-registry".to_owned(),
        owner: "learning-review-board".to_owned(),
        reviewed_at_unix_seconds: 10,
        maximum_total_bytes: 1024 * 1024,
        datasets: vec![DatasetRegistryEntry {
            priority: 1,
            dataset_id: "reviewed-source".to_owned(),
            display_name: "Reviewed Source".to_owned(),
            purpose: DatasetPurpose::InstructionFollowing,
            source_url: "https://datasets.example/reviewed-source".to_owned(),
            source_revision: "1111111111111111111111111111111111111111".to_owned(),
            intended_uses: BTreeSet::from([
                DatasetUse::Evaluation,
                DatasetUse::SupervisedFineTuning,
            ]),
            license: DatasetLicense {
                declared_spdx_expression: "Apache-2.0".to_owned(),
                scope: LicenseScope::DatasetWide,
                evidence_url: "https://datasets.example/reviewed-source/LICENSE".to_owned(),
                evidence_revision: "1111111111111111111111111111111111111111".to_owned(),
                requires_attribution: true,
                requires_share_alike: false,
                attribution_plan_hash: Some(hash(b"attribution plan")),
                share_alike_plan_hash: None,
                component_license_inventory_hash: None,
            },
            risk: DatasetRiskProfile {
                contains_user_content: false,
                contains_model_generated_content: false,
                generation_system: None,
                requires_personal_data_review: false,
                contains_sensitive_safety_content: false,
                contains_third_party_content: false,
                contains_executable_content: false,
                contains_credentials_or_session_data: false,
                source_notes: "Synthetic fixture with reviewed provenance.".to_owned(),
            },
            reviews: DatasetReviews {
                legal: Some(approved_review("legal")),
                provenance: Some(approved_review("provenance")),
                privacy: None,
                security: None,
                generation_terms: None,
            },
            artifacts: vec![artifact],
            status: DatasetAdmissionStatus::ApprovedForOfflineUse,
        }],
    }
}

#[test]
fn supplied_candidate_registry_is_strict_and_fail_closed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/learning/dataset-registry.candidates.json");
    let registry = ok(load_dataset_registry(&path));
    let report = ok(check_dataset_registry(&registry));
    assert!(!report.admissible);
    assert_eq!(report.dataset_count, 6);
    assert_eq!(report.approved_count, 0);
    assert!(report.issues.iter().any(|issue| issue.dataset_id.as_deref()
        == Some("super-natural-instructions")
        && issue.code == "D2ID8012"));
    assert!(report.issues.iter().any(|issue| issue.dataset_id.as_deref()
        == Some("gorilla-apibench")
        && issue.code == "D2ID8013"));

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/learning/dataset-registry.schema.json");
    let schema: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(schema_path))));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let instance = ok(serde_json::to_value(&registry));
    assert!(compiled.is_valid(&instance));

    let output = ok(Command::new(env!("CARGO_BIN_EXE_d2i-learning"))
        .arg("dataset-check")
        .arg(path)
        .output());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli_report: serde_json::Value = ok(serde_json::from_slice(&output.stdout));
    assert_eq!(cli_report["admissible"], false);
}

#[test]
fn desktop_agent_candidates_preserve_license_scope_and_execution_risk() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/learning/desktop-agent-dataset-registry.candidates.json");
    let registry = ok(load_dataset_registry(&path));
    let report = ok(check_dataset_registry(&registry));
    assert!(!report.admissible);
    assert_eq!(report.dataset_count, 10);
    assert_eq!(report.approved_count, 0);

    let android = registry
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "android-in-the-wild");
    assert_eq!(
        android.map(|dataset| dataset.license.declared_spdx_expression.as_str()),
        Some("CC-BY-4.0")
    );
    let mind2web = registry
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "mind2web");
    assert_eq!(
        mind2web.map(|dataset| dataset.license.declared_spdx_expression.as_str()),
        Some("CC-BY-4.0")
    );
    let stack = registry
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "the-stack-v2-permissive-subset");
    assert_eq!(
        stack.map(|dataset| dataset.license.declared_spdx_expression.as_str()),
        Some("NOASSERTION")
    );
    assert!(stack.is_some_and(|dataset| {
        dataset.risk.contains_executable_content
            && dataset.risk.contains_third_party_content
            && dataset.risk.contains_credentials_or_session_data
    }));
    let magicoder = registry
        .datasets
        .iter()
        .find(|dataset| dataset.dataset_id == "magicoder-oss-instruct-75k");
    assert_eq!(
        magicoder.map(|dataset| dataset.license.declared_spdx_expression.as_str()),
        Some("MIT")
    );
    assert!(report.issues.iter().any(|issue| {
        issue.dataset_id.as_deref() == Some("osworld") && issue.code == "D2ID8013"
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.dataset_id.as_deref() == Some("mind2web-2") && issue.code == "D2ID8012"
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.dataset_id.as_deref() == Some("glaive-function-calling-v2")
            && issue.code == "D2ID8023"
    }));

    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/learning/dataset-registry.schema.json");
    let schema: serde_json::Value = ok(serde_json::from_slice(&ok(fs::read(schema_path))));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    assert!(compiled.is_valid(&ok(serde_json::to_value(&registry))));

    let output = ok(Command::new(env!("CARGO_BIN_EXE_d2i-learning"))
        .arg("dataset-check")
        .arg(path)
        .output());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli_report: serde_json::Value = ok(serde_json::from_slice(&output.stdout));
    assert_eq!(cli_report["dataset_count"], 10);
    assert_eq!(cli_report["admissible"], false);
}

#[test]
fn approved_artifacts_are_stream_verified_and_tamper_is_rejected() {
    let root = TempDirectory::new("artifacts");
    let dataset_root = root.path().join("reviewed-source");
    ok(fs::create_dir(&dataset_root));
    let bytes = b"{\"instruction\":\"inspect pump\",\"response\":\"check vibration\"}\n";
    let artifact_path = dataset_root.join("train.jsonl");
    ok(fs::write(&artifact_path, bytes));
    let registry = approved_registry(DatasetArtifact {
        relative_path: "reviewed-source/train.jsonl".to_owned(),
        content_hash: hash(bytes),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    });
    let report = ok(check_dataset_registry(&registry));
    assert!(report.admissible, "{:?}", report.issues);
    assert_eq!(report.schema_version, 2);
    let mut legacy_registry = registry.clone();
    legacy_registry.schema_version = 1;
    assert!(check_dataset_registry(&legacy_registry).is_err());
    let mut component_registry = registry.clone();
    component_registry.datasets[0].license.scope = LicenseScope::ComponentSpecific;
    component_registry.datasets[0]
        .license
        .component_license_inventory_hash = Some(hash(b"component license inventory"));
    assert!(ok(check_dataset_registry(&component_registry)).admissible);
    let verification = ok(verify_dataset_artifacts(&registry, root.path()));
    assert_eq!(verification.dataset_count, 1);
    assert_eq!(verification.artifact_count, 1);
    assert_eq!(verification.total_bytes, report.declared_total_bytes);

    let registry_file = root.path().join("registry.json");
    ok(fs::write(
        &registry_file,
        ok(serde_json::to_vec_pretty(&registry)),
    ));
    let output = ok(Command::new(env!("CARGO_BIN_EXE_d2i-learning"))
        .arg("dataset-verify")
        .arg(&registry_file)
        .arg(root.path())
        .output());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    ok(fs::write(&artifact_path, b"tampered"));
    assert!(verify_dataset_artifacts(&registry, root.path()).is_err());

    let mut traversal = registry;
    traversal.datasets[0].artifacts[0].relative_path = "../outside.jsonl".to_owned();
    assert!(check_dataset_registry(&traversal).is_err());
}
