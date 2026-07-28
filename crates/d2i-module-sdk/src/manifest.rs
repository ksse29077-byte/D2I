use crate::contract::{
    canonical_sha256, parse_json_strict, sha256_bytes, validate_contract_version,
    validate_identifier, validate_relative_path, validate_sha256, validate_text,
    ConfidenceSemantics, ExecutionMode, ModuleCapability, ModuleError, ModuleErrorCode,
    ModuleIdentifier, NetworkRequirement, SchemaReference, CONTRACT_VERSION_V1,
};
use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Module Manifest v1 schema version.
pub const MODULE_MANIFEST_VERSION_V1: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SCHEMA_BYTES: u64 = 2 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

/// Human and artifact identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIdentity {
    pub module_id: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub contract_version: u32,
    pub build_id: String,
    pub artifact_filename: String,
    pub artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<String>,
    pub author: String,
    pub maintainer: String,
}

/// Capability declaration plus schema and fallback bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityManifest {
    #[serde(flatten)]
    pub capability: ModuleCapability,
    pub input_schemas: Vec<String>,
    pub output_schemas: Vec<String>,
    pub unsupported_case_policy: String,
    pub fallback_capability: Option<String>,
    pub fallback_module: Option<String>,
}

/// Module execution limits and authority declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionManifest {
    pub mode: ExecutionMode,
    pub timeout_logical_ticks: u64,
    pub maximum_input_bytes: u64,
    pub maximum_output_bytes: u64,
    pub memory_limit_bytes: u64,
    pub logical_operation_budget: u64,
    pub maximum_retries: u32,
    pub maximum_concurrent_invocations: u32,
    #[serde(default)]
    pub network_requirement: NetworkRequirement,
    #[serde(default)]
    pub filesystem_required: bool,
    #[serde(default)]
    pub environment_variables_allowed: bool,
    #[serde(default)]
    pub side_effect: bool,
    #[serde(default)]
    pub reversible: bool,
}

/// Handling policy for content that may contain embedded instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UntrustedContentPolicy {
    TreatAsData,
    Reject,
}

/// Audit requirement declared without binding concrete storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRequirement {
    InvocationAndResult,
    ResultOnly,
}

/// Failure behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailPolicy {
    Closed,
    Open,
}

impl Default for FailPolicy {
    fn default() -> Self {
        Self::Closed
    }
}

/// Persistent retention declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataRetention {
    None,
    Invocation,
    Persistent,
}

impl Default for DataRetention {
    fn default() -> Self {
        Self::None
    }
}

/// Security boundary declared by the module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityManifest {
    pub accepted_trust_labels: Vec<String>,
    pub untrusted_content_handling: UntrustedContentPolicy,
    #[serde(default)]
    pub secrets_required: bool,
    #[serde(default)]
    pub raw_secret_input: bool,
    #[serde(default)]
    pub privileged_operation: bool,
    pub allowed_external_dependencies: Vec<String>,
    pub audit_requirement: AuditRequirement,
    #[serde(default)]
    pub fail_policy: FailPolicy,
    #[serde(default)]
    pub data_retention: DataRetention,
}

/// Evaluation set, metrics, and admission thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationManifest {
    pub evaluation_set_id: String,
    pub evaluation_set_version: String,
    pub metrics: Vec<String>,
    pub acceptance_thresholds: BTreeMap<String, f64>,
    pub critical_error_definition: String,
    pub known_unsupported_cases: Vec<String>,
    pub benchmark_reference: String,
    pub deterministic_replay_required: bool,
}

/// One third-party dependency and its license.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDeclaration {
    pub name: String,
    pub version: String,
    pub license: String,
    pub source: String,
}

/// Provenance and licensing gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenseManifest {
    pub source_repository: String,
    pub source_license: String,
    pub artifact_license: String,
    pub datasets: Vec<String>,
    pub dataset_licenses: BTreeMap<String, String>,
    pub commercial_use: String,
    pub attribution: Vec<String>,
    pub generated_artifact: bool,
    pub third_party_dependencies: Vec<DependencyDeclaration>,
    pub supply_chain_metadata: String,
    pub model_card: String,
    pub data_card: String,
    pub threat_model: String,
}

/// Strict Module Manifest v1.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    pub schema_version: u32,
    pub identity: ManifestIdentity,
    pub capabilities: Vec<CapabilityManifest>,
    pub schemas: Vec<SchemaReference>,
    pub execution: ExecutionManifest,
    pub security: SecurityManifest,
    pub evaluation: EvaluationManifest,
    pub provenance_and_license: LicenseManifest,
}

impl ModuleManifest {
    /// Computes the canonical self-hash with the self-hash field omitted.
    pub fn canonical_manifest_hash(&self) -> Result<String, ModuleError> {
        let mut unhashed = self.clone();
        unhashed.identity.manifest_sha256 = None;
        canonical_sha256(&unhashed)
    }

    /// Produces the runtime identity using the computed manifest hash.
    pub fn identifier(&self) -> Result<ModuleIdentifier, ModuleError> {
        let identifier = ModuleIdentifier {
            module_id: self.identity.module_id.clone(),
            module_version: self.identity.version.clone(),
            contract_version: self.identity.contract_version,
            build_id: self.identity.build_id.clone(),
            artifact_sha256: self.identity.artifact_sha256.clone(),
            manifest_sha256: self.canonical_manifest_hash()?,
        };
        identifier.validate()?;
        Ok(identifier)
    }
}

/// One stable manifest validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestValidationIssue {
    pub code: String,
    pub field: String,
    pub message: String,
}

/// Successfully loaded and artifact-bound manifest.
#[derive(Debug, Clone)]
pub struct LoadedModuleManifest {
    pub root: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest: ModuleManifest,
    pub identifier: ModuleIdentifier,
    pub manifest_sha256: String,
}

/// Performs semantic validation without touching artifacts.
#[must_use]
pub fn validate_module_manifest(manifest: &ModuleManifest) -> Vec<ManifestValidationIssue> {
    let mut issues = Vec::new();
    let mut push = |code: &str, field: &str, message: String| {
        issues.push(ManifestValidationIssue {
            code: code.to_owned(),
            field: field.to_owned(),
            message,
        });
    };

    if manifest.schema_version != MODULE_MANIFEST_VERSION_V1 {
        push(
            "D2IM1001",
            "schema_version",
            "unsupported module manifest schema version".to_owned(),
        );
    }
    if let Err(error) = validate_identifier(&manifest.identity.module_id, "module_id") {
        push("D2IM1002", "identity.module_id", error.to_string());
    }
    if let Err(error) = validate_contract_version(manifest.identity.contract_version) {
        push("D2IM1003", "identity.contract_version", error.to_string());
    }
    if manifest.identity.contract_version != CONTRACT_VERSION_V1 {
        push(
            "D2IM1003",
            "identity.contract_version",
            "manifest must declare Cognitive Module Contract v1".to_owned(),
        );
    }
    for (field, value) in [
        ("identity.display_name", &manifest.identity.display_name),
        ("identity.description", &manifest.identity.description),
        ("identity.author", &manifest.identity.author),
        ("identity.maintainer", &manifest.identity.maintainer),
    ] {
        if let Err(error) = validate_text(value, field) {
            push("D2IM1004", field, error.to_string());
        }
    }
    if let Err(error) = d2i_core::SemanticVersion::from_str(&manifest.identity.version) {
        push(
            "D2IM1005",
            "identity.version",
            format!("invalid semantic version: {error}"),
        );
    }
    if let Err(error) =
        validate_relative_path(&manifest.identity.artifact_filename, "artifact_filename")
    {
        push("D2IM1006", "identity.artifact_filename", error.to_string());
    }
    if let Err(error) = validate_sha256(&manifest.identity.artifact_sha256, "artifact_sha256") {
        push("D2IM1007", "identity.artifact_sha256", error.to_string());
    }
    if let Some(hash) = &manifest.identity.manifest_sha256 {
        if let Err(error) = validate_sha256(hash, "manifest_sha256") {
            push("D2IM1008", "identity.manifest_sha256", error.to_string());
        }
    }

    if manifest.capabilities.is_empty() {
        push(
            "D2IM1010",
            "capabilities",
            "at least one capability is required".to_owned(),
        );
    }
    let schema_ids = manifest
        .schemas
        .iter()
        .map(|schema| schema.schema_id.clone())
        .collect::<BTreeSet<_>>();
    let mut capability_ids = BTreeSet::new();
    for (index, capability) in manifest.capabilities.iter().enumerate() {
        let field = format!("capabilities[{index}]");
        if let Err(error) = capability.capability.validate() {
            push("D2IM1011", &field, error.to_string());
        }
        if !capability_ids.insert(capability.capability.capability_id.clone()) {
            push("D2IM1012", &field, "duplicate capability_id".to_owned());
        }
        for schema in capability
            .input_schemas
            .iter()
            .chain(&capability.output_schemas)
        {
            if !schema_ids.contains(schema) {
                push(
                    "D2IM1013",
                    &field,
                    format!("capability references undeclared schema '{schema}'"),
                );
            }
        }
    }

    let mut seen_schemas = BTreeSet::new();
    for (index, schema) in manifest.schemas.iter().enumerate() {
        let field = format!("schemas[{index}]");
        if let Err(error) = schema.validate() {
            push("D2IM1020", &field, error.to_string());
        }
        if !seen_schemas.insert(schema.schema_id.clone()) {
            push("D2IM1021", &field, "duplicate schema_id".to_owned());
        }
    }

    let execution = &manifest.execution;
    if !execution.mode.is_supported() {
        push(
            "D2IM1030",
            "execution.mode",
            "execution mode is reserved and unsupported by the v1 runner".to_owned(),
        );
    }
    if execution.timeout_logical_ticks == 0
        || execution.maximum_input_bytes == 0
        || execution.maximum_output_bytes == 0
        || execution.memory_limit_bytes == 0
        || execution.logical_operation_budget == 0
        || execution.maximum_concurrent_invocations == 0
    {
        push(
            "D2IM1031",
            "execution",
            "execution limits must be greater than zero".to_owned(),
        );
    }
    if execution.maximum_retries > 100 {
        push(
            "D2IM1032",
            "execution.maximum_retries",
            "maximum_retries must be at most 100".to_owned(),
        );
    }
    if execution.network_requirement != NetworkRequirement::Denied {
        push(
            "D2IM1033",
            "execution.network_requirement",
            "reference modules must deny network access".to_owned(),
        );
    }
    if execution.side_effect
        || execution.filesystem_required
        || execution.environment_variables_allowed
    {
        push(
            "D2IM1034",
            "execution",
            "reference modules cannot require side effects, filesystem, or environment variables"
                .to_owned(),
        );
    }

    let security = &manifest.security;
    if security.accepted_trust_labels.is_empty() {
        push(
            "D2IM1040",
            "security.accepted_trust_labels",
            "at least one trust label is required".to_owned(),
        );
    }
    if security.secrets_required
        || security.raw_secret_input
        || security.privileged_operation
        || security.fail_policy != FailPolicy::Closed
        || security.data_retention != DataRetention::None
    {
        push(
            "D2IM1041",
            "security",
            "reference security defaults require no secrets, no privilege, fail-closed, and no retention"
                .to_owned(),
        );
    }

    let evaluation = &manifest.evaluation;
    if evaluation.metrics.is_empty() || evaluation.acceptance_thresholds.is_empty() {
        push(
            "D2IM1050",
            "evaluation",
            "metrics and acceptance thresholds are required".to_owned(),
        );
    }
    for (metric, value) in &evaluation.acceptance_thresholds {
        if !value.is_finite() || !(0.0..=1.0).contains(value) {
            push(
                "D2IM1051",
                "evaluation.acceptance_thresholds",
                format!("threshold '{metric}' must be finite and within 0..1"),
            );
        }
    }
    if manifest.provenance_and_license.source_license.is_empty()
        || manifest.provenance_and_license.artifact_license.is_empty()
        || manifest.provenance_and_license.commercial_use.is_empty()
        || manifest.provenance_and_license.threat_model.is_empty()
        || manifest.provenance_and_license.model_card.is_empty()
        || manifest.provenance_and_license.data_card.is_empty()
    {
        push(
            "D2IM1060",
            "provenance_and_license",
            "license, commercial-use, model/data card, and threat-model metadata are required"
                .to_owned(),
        );
    }
    issues
}

/// Loads YAML or JSON manifest, checks paths, schemas, and artifact hashes.
pub fn load_module_manifest(root: &Path) -> Result<LoadedModuleManifest, ModuleError> {
    let root = fs::canonicalize(root).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("cannot canonicalize module root: {error}"),
        )
    })?;
    if !root.is_dir() {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "module root is not a directory",
        ));
    }
    let yaml = root.join("module-manifest.yaml");
    let json = root.join("module-manifest.json");
    let manifest_path = match (yaml.is_file(), json.is_file()) {
        (true, false) => yaml,
        (false, true) => json,
        (false, false) => {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "module root requires module-manifest.yaml or module-manifest.json",
            ))
        }
        (true, true) => {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "module root must not contain both YAML and JSON manifests",
            ))
        }
    };
    let bytes = read_bounded(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: ModuleManifest = if manifest_path
        .extension()
        .is_some_and(|value| value == "json")
    {
        parse_json_strict(&bytes)?
    } else {
        serde_yaml::from_slice(&bytes).map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("invalid module manifest YAML: {error}"),
            )
        })?
    };
    let issues = validate_module_manifest(&manifest);
    if let Some(issue) = issues.first() {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{} at {}: {}", issue.code, issue.field, issue.message),
        ));
    }
    let manifest_sha256 = manifest.canonical_manifest_hash()?;
    if let Some(declared) = &manifest.identity.manifest_sha256 {
        if declared != &manifest_sha256 {
            return Err(ModuleError::new(
                ModuleErrorCode::ArtifactMismatch,
                "declared manifest_sha256 does not match canonical manifest",
            ));
        }
    }

    let artifact_path = resolve_bounded_path(
        &root,
        &manifest.identity.artifact_filename,
        "module artifact",
    )?;
    let artifact_hash = sha256_bytes(&read_bounded(&artifact_path, MAX_ARTIFACT_BYTES)?);
    if artifact_hash != manifest.identity.artifact_sha256 {
        return Err(ModuleError::new(
            ModuleErrorCode::ArtifactMismatch,
            "module artifact hash does not match manifest",
        ));
    }

    for schema in &manifest.schemas {
        let path = resolve_bounded_path(&root, &schema.path, "module schema")?;
        let schema_bytes = read_bounded(&path, MAX_SCHEMA_BYTES)?;
        if sha256_bytes(&schema_bytes) != schema.sha256 {
            return Err(ModuleError::new(
                ModuleErrorCode::ArtifactMismatch,
                format!("schema '{}' hash does not match manifest", schema.schema_id),
            ));
        }
        let schema_json: Value = parse_json_strict(&schema_bytes)?;
        JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema_json)
            .map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::SchemaMismatch,
                    format!("schema '{}' is invalid: {error}", schema.schema_id),
                )
            })?;
    }

    let identifier = manifest.identifier()?;
    Ok(LoadedModuleManifest {
        root,
        manifest_path,
        manifest,
        identifier,
        manifest_sha256,
    })
}

pub(crate) fn resolve_bounded_path(
    root: &Path,
    relative: &str,
    label: &str,
) -> Result<PathBuf, ModuleError> {
    validate_relative_path(relative, label)?;
    let joined = root.join(relative);
    let canonical = fs::canonicalize(&joined).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("cannot open {label} '{relative}': {error}"),
        )
    })?;
    if !canonical.starts_with(root) {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{label} escapes the module root"),
        ));
    }
    Ok(canonical)
}

pub(crate) fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, ModuleError> {
    let metadata = fs::metadata(path).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::DependencyUnavailable,
            format!("cannot inspect '{}': {error}", path.display()),
        )
    })?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            format!("'{}' is not a bounded regular file", path.display()),
        ));
    }
    fs::read(path).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::DependencyUnavailable,
            format!("cannot read '{}': {error}", path.display()),
        )
    })
}

impl CapabilityManifest {
    /// Confidence semantics exposed for documentation and builders.
    #[must_use]
    pub const fn confidence_semantics(&self) -> &ConfidenceSemantics {
        &self.capability.confidence_semantics
    }
}
