use crate::{
    episode::{validate_hash, validate_text, validate_token},
    json_bytes, read_bounded, sha256_bytes, LearningError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

const MAX_REGISTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DATASETS: usize = 1_000;
const MAX_ARTIFACTS_PER_DATASET: usize = 10_000;
const DATASET_REGISTRY_SCHEMA_VERSION: u32 = 2;

/// Intended offline use of an admitted dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetUse {
    SupervisedFineTuning,
    RewardModeling,
    Evaluation,
    SafetyClassification,
}

/// Product capability a candidate dataset is expected to improve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetPurpose {
    MultiTurnConversation,
    InstructionFollowing,
    PreferenceAndQuality,
    KoreanInstruction,
    ApiCalling,
    SafetyClassification,
    DesktopInteraction,
    MobileInteraction,
    WebAutomation,
    FunctionCalling,
    ShellCommand,
    CodeGeneration,
}

/// Scope of the license statement attached to a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseScope {
    DatasetWide,
    MetadataOnly,
    ComponentSpecific,
    Unresolved,
}

/// Lifecycle state. Only the approved state may pass artifact verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetAdmissionStatus {
    Candidate,
    Quarantined,
    ApprovedForOfflineUse,
}

/// Human review decision attached to one immutable evidence artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approved,
    Rejected,
}

/// Auditable human review of legal, provenance, privacy, or security concerns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestation {
    pub reviewer_id: String,
    pub reviewed_at_unix_seconds: u64,
    pub decision: ReviewDecision,
    pub evidence_hash: String,
    pub notes: String,
}

/// License statement and required compliance artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetLicense {
    pub declared_spdx_expression: String,
    pub scope: LicenseScope,
    pub evidence_url: String,
    pub evidence_revision: String,
    pub requires_attribution: bool,
    pub requires_share_alike: bool,
    pub attribution_plan_hash: Option<String>,
    pub share_alike_plan_hash: Option<String>,
    pub component_license_inventory_hash: Option<String>,
}

/// Provenance and handling risks that determine mandatory reviews.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetRiskProfile {
    pub contains_user_content: bool,
    pub contains_model_generated_content: bool,
    pub generation_system: Option<String>,
    pub requires_personal_data_review: bool,
    pub contains_sensitive_safety_content: bool,
    pub contains_third_party_content: bool,
    pub contains_executable_content: bool,
    pub contains_credentials_or_session_data: bool,
    pub source_notes: String,
}

/// One immutable local file admitted for offline use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetArtifact {
    pub relative_path: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

/// Review evidence required before a candidate may become usable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetReviews {
    pub legal: Option<ReviewAttestation>,
    pub provenance: Option<ReviewAttestation>,
    pub privacy: Option<ReviewAttestation>,
    pub security: Option<ReviewAttestation>,
    pub generation_terms: Option<ReviewAttestation>,
}

/// One version-pinned dataset candidate or approved source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetRegistryEntry {
    pub priority: u16,
    pub dataset_id: String,
    pub display_name: String,
    pub purpose: DatasetPurpose,
    pub source_url: String,
    pub source_revision: String,
    pub intended_uses: BTreeSet<DatasetUse>,
    pub license: DatasetLicense,
    pub risk: DatasetRiskProfile,
    pub reviews: DatasetReviews,
    pub artifacts: Vec<DatasetArtifact>,
    pub status: DatasetAdmissionStatus,
}

/// Offline dataset source registry. It performs no download or training.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetRegistry {
    pub schema_version: u32,
    pub registry_id: String,
    pub owner: String,
    pub reviewed_at_unix_seconds: u64,
    pub maximum_total_bytes: u64,
    pub datasets: Vec<DatasetRegistryEntry>,
}

/// One actionable reason a registry is not admissible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetAdmissionIssue {
    pub dataset_id: Option<String>,
    pub code: String,
    pub message: String,
    pub remediation: String,
}

/// Deterministic metadata-only admission result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetRegistryReport {
    pub schema_version: u32,
    pub registry_id: String,
    pub admissible: bool,
    pub dataset_count: u64,
    pub approved_count: u64,
    pub declared_total_bytes: u64,
    pub issues: Vec<DatasetAdmissionIssue>,
}

/// Result of hashing every admitted local artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetArtifactVerification {
    pub schema_version: u32,
    pub registry_id: String,
    pub dataset_count: u64,
    pub artifact_count: u64,
    pub total_bytes: u64,
    pub aggregate_hash: String,
}

/// Loads one bounded strict JSON dataset registry.
pub fn load_dataset_registry(path: &Path) -> Result<DatasetRegistry, LearningError> {
    serde_json::from_slice(&read_bounded(path, MAX_REGISTRY_BYTES)?)
        .map_err(|error| LearningError::Json(error.to_string()))
}

/// Checks metadata, licenses, risks, reviews, and immutable artifact declarations.
pub fn check_dataset_registry(
    registry: &DatasetRegistry,
) -> Result<DatasetRegistryReport, LearningError> {
    validate_registry_shape(registry)?;
    let mut issues = Vec::new();
    let mut dataset_ids = BTreeSet::new();
    let mut priorities = BTreeSet::new();
    let mut declared_total_bytes = 0_u64;
    let mut approved_count = 0_u64;

    for dataset in &registry.datasets {
        if !dataset_ids.insert(dataset.dataset_id.clone()) {
            push_issue(
                &mut issues,
                Some(&dataset.dataset_id),
                "D2ID8001",
                "dataset_id is duplicated",
                "assign one stable ID to each source",
            );
        }
        if !priorities.insert(dataset.priority) {
            push_issue(
                &mut issues,
                Some(&dataset.dataset_id),
                "D2ID8002",
                "dataset priority is duplicated",
                "assign a deterministic unique priority",
            );
        }
        validate_entry(dataset, &mut issues)?;
        for artifact in &dataset.artifacts {
            declared_total_bytes = declared_total_bytes
                .checked_add(artifact.size_bytes)
                .ok_or_else(|| LearningError::Invalid("dataset size sum overflowed".to_owned()))?;
        }
        if dataset.status == DatasetAdmissionStatus::ApprovedForOfflineUse {
            approved_count = approved_count.saturating_add(1);
        } else {
            push_issue(
                &mut issues,
                Some(&dataset.dataset_id),
                "D2ID8003",
                "dataset has not been approved for offline use",
                "complete reviews and explicitly promote the immutable source revision",
            );
        }
    }
    if registry
        .datasets
        .windows(2)
        .any(|window| window[0].priority >= window[1].priority)
    {
        push_issue(
            &mut issues,
            None,
            "D2ID8004",
            "datasets are not sorted by strictly increasing priority",
            "sort the registry by unique priority",
        );
    }
    if declared_total_bytes > registry.maximum_total_bytes {
        push_issue(
            &mut issues,
            None,
            "D2ID8005",
            "declared artifacts exceed the registry byte budget",
            "reduce the admitted artifact set or approve a larger explicit bound",
        );
    }
    issues.sort_by(|left, right| {
        (&left.dataset_id, &left.code, &left.message).cmp(&(
            &right.dataset_id,
            &right.code,
            &right.message,
        ))
    });
    Ok(DatasetRegistryReport {
        schema_version: DATASET_REGISTRY_SCHEMA_VERSION,
        registry_id: registry.registry_id.clone(),
        admissible: issues.is_empty()
            && approved_count == u64::try_from(registry.datasets.len()).unwrap_or(u64::MAX),
        dataset_count: u64::try_from(registry.datasets.len()).unwrap_or(u64::MAX),
        approved_count,
        declared_total_bytes,
        issues,
    })
}

/// Verifies every approved artifact under a local root without network access.
pub fn verify_dataset_artifacts(
    registry: &DatasetRegistry,
    artifact_root: &Path,
) -> Result<DatasetArtifactVerification, LearningError> {
    let report = check_dataset_registry(registry)?;
    if !report.admissible {
        return Err(LearningError::GateRejected(
            report
                .issues
                .iter()
                .map(|issue| format!("{}: {}", issue.code, issue.message))
                .collect(),
        ));
    }
    validate_artifact_root(artifact_root)?;
    let mut artifact_count = 0_u64;
    let mut total_bytes = 0_u64;
    let mut verified = Vec::new();
    for dataset in &registry.datasets {
        for artifact in &dataset.artifacts {
            let path = resolve_artifact(artifact_root, &artifact.relative_path)?;
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| LearningError::Io {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != artifact.size_bytes
            {
                return Err(LearningError::Integrity(format!(
                    "dataset artifact '{}' type or size mismatch",
                    artifact.relative_path
                )));
            }
            let actual_hash = hash_file(&path)?;
            if actual_hash != artifact.content_hash {
                return Err(LearningError::Integrity(format!(
                    "dataset artifact '{}' hash mismatch",
                    artifact.relative_path
                )));
            }
            total_bytes = total_bytes
                .checked_add(metadata.len())
                .ok_or_else(|| LearningError::Invalid("verified byte sum overflowed".to_owned()))?;
            if total_bytes > registry.maximum_total_bytes {
                return Err(LearningError::Integrity(
                    "verified artifacts exceed the registry byte budget".to_owned(),
                ));
            }
            artifact_count = artifact_count.saturating_add(1);
            verified.push((
                dataset.dataset_id.as_str(),
                artifact.relative_path.as_str(),
                actual_hash,
                metadata.len(),
            ));
        }
    }
    Ok(DatasetArtifactVerification {
        schema_version: DATASET_REGISTRY_SCHEMA_VERSION,
        registry_id: registry.registry_id.clone(),
        dataset_count: u64::try_from(registry.datasets.len()).unwrap_or(u64::MAX),
        artifact_count,
        total_bytes,
        aggregate_hash: sha256_bytes(&json_bytes(&verified)?),
    })
}

fn validate_registry_shape(registry: &DatasetRegistry) -> Result<(), LearningError> {
    validate_token(&registry.registry_id, "dataset registry_id")?;
    validate_text(&registry.owner, "dataset registry owner")?;
    if registry.schema_version != DATASET_REGISTRY_SCHEMA_VERSION
        || registry.reviewed_at_unix_seconds == 0
        || registry.maximum_total_bytes == 0
        || registry.datasets.is_empty()
        || registry.datasets.len() > MAX_DATASETS
    {
        return Err(LearningError::Invalid(
            "dataset registry schema, review, byte budget, or count is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_entry(
    dataset: &DatasetRegistryEntry,
    issues: &mut Vec<DatasetAdmissionIssue>,
) -> Result<(), LearningError> {
    validate_token(&dataset.dataset_id, "dataset_id")?;
    validate_text(&dataset.display_name, "dataset display_name")?;
    validate_https_url(&dataset.source_url, "dataset source_url")?;
    validate_text(&dataset.source_revision, "dataset source_revision")?;
    validate_text(
        &dataset.license.declared_spdx_expression,
        "declared_spdx_expression",
    )?;
    validate_https_url(&dataset.license.evidence_url, "license evidence_url")?;
    validate_text(
        &dataset.license.evidence_revision,
        "license evidence_revision",
    )?;
    validate_text(&dataset.risk.source_notes, "dataset source_notes")?;
    if dataset.priority == 0 || dataset.intended_uses.is_empty() {
        return Err(LearningError::Invalid(
            "dataset priority or intended uses are incomplete".to_owned(),
        ));
    }
    if is_unresolved(&dataset.source_revision) || !is_immutable_revision(&dataset.source_revision) {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8010",
            "dataset source revision is unresolved or mutable",
            "pin an immutable 40-64 character hexadecimal commit or content revision",
        );
    }
    if is_unresolved(&dataset.license.evidence_revision)
        || !is_immutable_revision(&dataset.license.evidence_revision)
    {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8011",
            "license evidence revision is unresolved or mutable",
            "pin the exact revision whose license statement was reviewed",
        );
    }
    if dataset.license.declared_spdx_expression == "NOASSERTION"
        || matches!(
            dataset.license.scope,
            LicenseScope::MetadataOnly | LicenseScope::Unresolved
        )
    {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8012",
            "dataset-wide license coverage is unresolved",
            "inventory and review every component or original instance license",
        );
    }
    if matches!(
        dataset.license.scope,
        LicenseScope::MetadataOnly | LicenseScope::ComponentSpecific
    ) && dataset.license.component_license_inventory_hash.is_none()
    {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8013",
            "component license inventory is missing",
            "produce a hashed component-to-license inventory",
        );
    }
    validate_optional_hash(
        dataset.license.attribution_plan_hash.as_deref(),
        "attribution_plan_hash",
    )?;
    validate_optional_hash(
        dataset.license.share_alike_plan_hash.as_deref(),
        "share_alike_plan_hash",
    )?;
    validate_optional_hash(
        dataset.license.component_license_inventory_hash.as_deref(),
        "component_license_inventory_hash",
    )?;
    if dataset.license.requires_attribution && dataset.license.attribution_plan_hash.is_none() {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8014",
            "required attribution plan is missing",
            "record and hash the attribution and NOTICE delivery plan",
        );
    }
    if dataset.license.requires_share_alike && dataset.license.share_alike_plan_hash.is_none() {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8015",
            "required share-alike plan is missing",
            "record and hash the reviewed derivative-distribution plan",
        );
    }
    if dataset.risk.contains_model_generated_content && dataset.risk.generation_system.is_none() {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8016",
            "model-generated content has no generation-system provenance",
            "identify the generating model/provider and applicable terms",
        );
    }
    if let Some(system) = &dataset.risk.generation_system {
        validate_text(system, "dataset generation_system")?;
    }
    if dataset.risk.contains_third_party_content
        && dataset.license.scope != LicenseScope::ComponentSpecific
    {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8017",
            "third-party content is not covered by a component-specific license inventory",
            "classify the source as component-specific and inventory every embedded component",
        );
    }
    if dataset.risk.contains_credentials_or_session_data
        && !dataset.risk.requires_personal_data_review
    {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8018",
            "credential or session material is missing mandatory personal-data review",
            "enable personal-data review and define credential/session redaction",
        );
    }
    require_review(
        &dataset.dataset_id,
        "legal",
        dataset.reviews.legal.as_ref(),
        "D2ID8020",
        issues,
    )?;
    require_review(
        &dataset.dataset_id,
        "provenance",
        dataset.reviews.provenance.as_ref(),
        "D2ID8021",
        issues,
    )?;
    if dataset.risk.requires_personal_data_review || dataset.risk.contains_user_content {
        require_review(
            &dataset.dataset_id,
            "privacy",
            dataset.reviews.privacy.as_ref(),
            "D2ID8022",
            issues,
        )?;
    }
    if dataset.risk.contains_sensitive_safety_content
        || dataset.risk.contains_executable_content
        || dataset.risk.contains_credentials_or_session_data
    {
        require_review(
            &dataset.dataset_id,
            "security",
            dataset.reviews.security.as_ref(),
            "D2ID8023",
            issues,
        )?;
    }
    if dataset.risk.contains_model_generated_content {
        require_review(
            &dataset.dataset_id,
            "generation terms",
            dataset.reviews.generation_terms.as_ref(),
            "D2ID8024",
            issues,
        )?;
    }
    if dataset.artifacts.is_empty() || dataset.artifacts.len() > MAX_ARTIFACTS_PER_DATASET {
        push_issue(
            issues,
            Some(&dataset.dataset_id),
            "D2ID8030",
            "immutable local artifact inventory is missing or outside bounds",
            "stage bounded local files and record exact sizes and SHA-256 hashes",
        );
    }
    let mut paths = BTreeSet::new();
    for artifact in &dataset.artifacts {
        validate_relative_path(&artifact.relative_path)?;
        validate_hash(&artifact.content_hash, "dataset artifact content_hash")?;
        if artifact.size_bytes == 0 || !paths.insert(&artifact.relative_path) {
            return Err(LearningError::Invalid(
                "dataset artifact sizes must be positive and paths unique".to_owned(),
            ));
        }
    }
    Ok(())
}

fn require_review(
    dataset_id: &str,
    label: &str,
    review: Option<&ReviewAttestation>,
    code: &str,
    issues: &mut Vec<DatasetAdmissionIssue>,
) -> Result<(), LearningError> {
    let Some(review) = review else {
        push_issue(
            issues,
            Some(dataset_id),
            code,
            format!("{label} review is missing"),
            format!("attach an approved {label} review with immutable evidence"),
        );
        return Ok(());
    };
    validate_token(&review.reviewer_id, "dataset reviewer_id")?;
    validate_hash(&review.evidence_hash, "dataset review evidence_hash")?;
    validate_text(&review.notes, "dataset review notes")?;
    if review.reviewed_at_unix_seconds == 0 || review.decision != ReviewDecision::Approved {
        push_issue(
            issues,
            Some(dataset_id),
            code,
            format!("{label} review is not approved"),
            format!("resolve the {label} rejection before dataset admission"),
        );
    }
    Ok(())
}

fn validate_optional_hash(value: Option<&str>, field: &str) -> Result<(), LearningError> {
    if let Some(value) = value {
        validate_hash(value, field)?;
    }
    Ok(())
}

fn validate_https_url(value: &str, field: &str) -> Result<(), LearningError> {
    validate_text(value, field)?;
    if !value.starts_with("https://")
        || value.contains('\0')
        || value.chars().any(char::is_whitespace)
    {
        return Err(LearningError::Invalid(format!(
            "{field} must be an absolute HTTPS URL"
        )));
    }
    Ok(())
}

fn is_unresolved(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.contains("unresolved")
        || normalized.contains("replace-me")
        || matches!(
            normalized.as_str(),
            "main" | "master" | "latest" | "unknown"
        )
}

fn is_immutable_revision(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_relative_path(value: &str) -> Result<(), LearningError> {
    validate_text(value, "dataset artifact relative_path")?;
    let path = Path::new(value);
    if value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LearningError::Invalid(
            "dataset artifact path must be normalized and relative".to_owned(),
        ));
    }
    Ok(())
}

fn validate_artifact_root(root: &Path) -> Result<(), LearningError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LearningError::Integrity(
            "dataset artifact root must be a regular directory".to_owned(),
        ));
    }
    Ok(())
}

fn resolve_artifact(root: &Path, relative: &str) -> Result<std::path::PathBuf, LearningError> {
    validate_relative_path(relative)?;
    let root = std::fs::canonicalize(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let joined = root.join(relative);
    let canonical = std::fs::canonicalize(&joined).map_err(|error| LearningError::Io {
        path: joined.display().to_string(),
        message: error.to_string(),
    })?;
    if !canonical.starts_with(&root) {
        return Err(LearningError::Integrity(
            "dataset artifact escapes the approved root".to_owned(),
        ));
    }
    Ok(canonical)
}

fn hash_file(path: &Path) -> Result<String, LearningError> {
    let mut file = File::open(path).map_err(|error| LearningError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("sha256:{:x}", digest.finalize()))
}

fn push_issue(
    issues: &mut Vec<DatasetAdmissionIssue>,
    dataset_id: Option<&str>,
    code: &str,
    message: impl Into<String>,
    remediation: impl Into<String>,
) {
    issues.push(DatasetAdmissionIssue {
        dataset_id: dataset_id.map(str::to_owned),
        code: code.to_owned(),
        message: message.into(),
        remediation: remediation.into(),
    });
}
