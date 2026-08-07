//! Capability-source quarantine and bounded Office artifact-workspace contracts.

mod contracts;

pub use contracts::*;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

/// OFFICE-100 contract version.
pub const OFFICE_CAPABILITY_SCHEMA_VERSION: u32 = 1;
/// Canonical placeholder used only while sealing an artifact.
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// Maximum accepted strict JSON document size.
pub const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Maximum collection cardinality for public contracts.
pub const MAX_COLLECTION_ITEMS: usize = 512;
/// Maximum identifier or ordinary string bytes.
pub const MAX_STRING_BYTES: usize = 512;

/// Fail-closed OFFICE-100 contract error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfficeCapabilityError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    Resource(String),
    Signature(String),
}

impl Display for OfficeCapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::Replay(message) => ("replay", message),
            Self::Resource(message) => ("resource", message),
            Self::Signature(message) => ("signature", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for OfficeCapabilityError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, OfficeCapabilityError> {
    Err(OfficeCapabilityError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, OfficeCapabilityError> {
    Err(OfficeCapabilityError::Integrity(message.into()))
}

fn unauthorized<T>(message: impl Into<String>) -> Result<T, OfficeCapabilityError> {
    Err(OfficeCapabilityError::Unauthorized(message.into()))
}

/// Serializes recursively key-ordered canonical JSON.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, OfficeCapabilityError> {
    let value = serde_json::to_value(value)
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))?;
    serde_json::to_vec(&normalize_json(value))
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))
}

/// Computes canonical lowercase prefixed SHA-256.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, OfficeCapabilityError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

/// Computes lowercase prefixed SHA-256 over bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_without<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, OfficeCapabilityError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| OfficeCapabilityError::Invalid("artifact must be an object".to_owned()))?;
    for field in fields {
        object.remove(*field);
    }
    canonical_sha256(&value)
}

fn normalize_json(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| (key, normalize_json(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(normalize_json).collect()),
        value => value,
    }
}

/// Parses bounded JSON and rejects duplicate keys, floats, and secret fields.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, OfficeCapabilityError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(OfficeCapabilityError::Resource(
            "JSON input exceeds byte limit".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))?;
    validate_bounded_value(&strict.0, 0)?;
    reject_sensitive_payload(&strict.0)?;
    serde_json::from_value(strict.0)
        .map_err(|error| OfficeCapabilityError::Invalid(error.to_string()))
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("floating-point values are not accepted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("JSON array exceeds item limit"));
            }
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= MAX_COLLECTION_ITEMS {
                return Err(A::Error::custom("JSON object exceeds field limit"));
            }
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!("duplicate JSON key: {key}")));
            }
            values.insert(key, map.next_value::<StrictValue>()?.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn validate_bounded_value(value: &Value, depth: usize) -> Result<(), OfficeCapabilityError> {
    if depth > 32 {
        return Err(OfficeCapabilityError::Resource(
            "JSON nesting exceeds depth limit".to_owned(),
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => Err(
            OfficeCapabilityError::Resource("JSON string exceeds byte limit".to_owned()),
        ),
        Value::Array(values) => {
            for value in values {
                validate_bounded_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > MAX_STRING_BYTES {
                    return Err(OfficeCapabilityError::Resource(
                        "JSON key exceeds byte limit".to_owned(),
                    ));
                }
                validate_bounded_value(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn reject_sensitive_payload(value: &Value) -> Result<(), OfficeCapabilityError> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "authorization",
        "password",
        "api_key",
        "api-key",
        "bearer",
        "client_secret",
        "refresh_token",
        "private_key",
        "cookie",
        "set-cookie",
        "raw_secret",
        "absolute_path",
        "raw_path",
        "command_line",
        "script",
    ];
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if FORBIDDEN_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    return unauthorized("secret, raw path, command, or script field is forbidden");
                }
                reject_sensitive_payload(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_sensitive_payload(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validates canonical `sha256:<lowercase hex>`.
pub fn validate_hash(value: &str, label: &str) -> Result<(), OfficeCapabilityError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return invalid(format!("{label} must be lowercase canonical sha256"));
    }
    Ok(())
}

/// Validates a bounded opaque identifier without interpreting application taxonomy.
pub fn validate_id(value: &str, label: &str) -> Result<(), OfficeCapabilityError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return invalid(format!("{label} must be a bounded opaque identifier"));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), OfficeCapabilityError> {
    if value.is_empty() || value.len() > MAX_STRING_BYTES || value.chars().any(char::is_control) {
        return invalid(format!("{label} must be bounded text"));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), OfficeCapabilityError> {
    if values.len() > MAX_COLLECTION_ITEMS || (!allow_empty && values.is_empty()) {
        return invalid(format!("{label} has invalid cardinality"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(value, label)?;
        if !seen.insert(value) {
            return invalid(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn validate_hashes(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), OfficeCapabilityError> {
    if values.len() > MAX_COLLECTION_ITEMS || (!allow_empty && values.is_empty()) {
        return invalid(format!("{label} has invalid cardinality"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_hash(value, label)?;
        if !seen.insert(value) {
            return invalid(format!("{label} contains duplicates"));
        }
    }
    Ok(())
}

fn validate_version(version: u32, label: &str) -> Result<(), OfficeCapabilityError> {
    if version != OFFICE_CAPABILITY_SCHEMA_VERSION {
        return invalid(format!("{label} schema version is unsupported"));
    }
    Ok(())
}

fn validate_interval(from: u64, to: u64, label: &str) -> Result<(), OfficeCapabilityError> {
    if from >= to || to.saturating_sub(from) > 31 * 86_400_000 {
        return invalid(format!("{label} interval is invalid or exceeds 31 days"));
    }
    Ok(())
}

/// Validates a cognitive-safe canonical relative path token.
pub fn validate_relative_path_token(token: &str) -> Result<(), OfficeCapabilityError> {
    if token.is_empty()
        || token.len() > MAX_STRING_BYTES
        || token.starts_with('/')
        || token.starts_with('\\')
        || token.contains('\\')
        || token.contains(':')
        || token.contains('%')
        || token.contains("//")
        || token.chars().any(char::is_control)
    {
        return invalid("relative path token contains a forbidden path form");
    }
    let segments = token.split('/').collect::<Vec<_>>();
    if segments.len() > 16 {
        return invalid("relative path token exceeds depth limit");
    }
    for segment in segments {
        validate_filename_segment(segment)?;
    }
    Ok(())
}

/// Validates one filename or folder segment including Windows reserved names.
pub fn validate_filename_segment(segment: &str) -> Result<(), OfficeCapabilityError> {
    if segment.is_empty()
        || segment == "."
        || segment == ".."
        || segment.len() > 128
        || segment.ends_with('.')
        || segment.ends_with(' ')
        || segment.contains('~')
        || segment.chars().any(char::is_control)
        || segment.chars().any(|value| "<>:\"/\\|?*".contains(value))
    {
        return invalid("filename segment is not canonical and bounded");
    }
    let stem = segment
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || stem.strip_prefix("COM").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        })
        || stem.strip_prefix("LPT").is_some_and(|suffix| {
            matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
        });
    if reserved {
        return invalid("filename segment is a reserved Windows device name");
    }
    Ok(())
}

/// Returns deterministic reasons why a source can never be a direct runtime executor.
pub fn runtime_rejection_reason_ids(record: &CapabilitySourceRecordV1) -> Vec<String> {
    let mut reasons = Vec::new();
    if !record.license_verified {
        reasons.push("license.unverified".to_owned());
    }
    if record.exposes_arbitrary_code {
        reasons.push("tool.arbitrary-code".to_owned());
    }
    if record.exposes_process_launch {
        reasons.push("tool.process-launch".to_owned());
    }
    if record.exposes_raw_filesystem {
        reasons.push("tool.raw-filesystem".to_owned());
    }
    if record.exposes_credentials {
        reasons.push("tool.credentials".to_owned());
    }
    if record.exposes_network || record.transport_class == CapabilityTransportClassV1::RemoteHttp {
        reasons.push("tool.remote-network".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn validate_source(value: &CapabilitySourceRecordV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "capability source")?;
    validate_id(&value.source_id, "source_id")?;
    validate_text(&value.source_name, "source_name")?;
    validate_text(&value.source_version, "source_version")?;
    validate_text(&value.source_revision, "source_revision")?;
    validate_hash(&value.source_content_sha256, "source content")?;
    validate_id(&value.publisher_or_owner_id, "publisher_or_owner_id")?;
    validate_ids(&value.application_family_ids, "application families", false)?;
    validate_text(&value.license_id, "license_id")?;
    validate_text(&value.license_source, "license_source")?;
    validate_ids(&value.runtime_language_ids, "runtime languages", true)?;
    validate_ids(&value.runtime_dependency_ids, "runtime dependencies", true)?;
    validate_ids(
        &value.known_security_advisory_ids,
        "security advisories",
        true,
    )?;
    validate_hash(&value.tool_catalog_sha256, "tool catalog")?;
    validate_ids(&value.evidence_ids, "source evidence", false)?;
    if !value.license_verified
        && !matches!(
            value.assessment_status,
            SourceAssessmentStatusV1::ResearchOnly | SourceAssessmentStatusV1::RejectedForRuntime
        )
    {
        return invalid("unverified license cannot pass reference assessment");
    }
    if !runtime_rejection_reason_ids(value).is_empty()
        && value.assessment_status == SourceAssessmentStatusV1::ApprovedForOfflineConformance
    {
        return invalid("dangerous source cannot be approved for offline execution");
    }
    Ok(())
}

fn validate_catalog(value: &McpToolCatalogSnapshotV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "MCP catalog")?;
    validate_hash(&value.source_record_sha256, "source record")?;
    validate_text(&value.protocol_version, "protocol_version")?;
    validate_text(&value.server_name, "server_name")?;
    validate_text(&value.server_version, "server_version")?;
    validate_ids(&value.tool_ids, "tool IDs", false)?;
    validate_hashes(
        &value.tool_input_schema_sha256s,
        "tool input schemas",
        false,
    )?;
    validate_hashes(
        &value.tool_output_schema_sha256s,
        "tool output schemas",
        false,
    )?;
    let count = value.tool_ids.len();
    if value.tool_input_schema_sha256s.len() != count
        || value.tool_output_schema_sha256s.len() != count
        || value.tool_side_effect_classes.len() != count
        || value.tool_filesystem_scope_classes.len() != count
        || value.tool_process_scope_classes.len() != count
        || value.tool_network_scope_classes.len() != count
    {
        return invalid("MCP catalog parallel collections differ");
    }
    Ok(())
}

fn validate_candidate(value: &OfficeCapabilityCandidateV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "capability candidate")?;
    validate_id(&value.candidate_id, "candidate_id")?;
    validate_hash(&value.source_record_sha256, "candidate source")?;
    validate_id(&value.source_tool_id, "source_tool_id")?;
    validate_id(&value.application_family_id, "application_family_id")?;
    validate_id(&value.proposed_capability_id, "proposed_capability_id")?;
    validate_id(
        &value.proposed_semantic_operation_id,
        "proposed_semantic_operation_id",
    )?;
    validate_ids(&value.required_observation_class_ids, "observations", false)?;
    validate_ids(&value.required_precondition_ids, "preconditions", false)?;
    validate_ids(&value.required_postcondition_ids, "postconditions", false)?;
    validate_ids(
        &value.prohibited_argument_classes,
        "prohibited arguments",
        false,
    )?;
    validate_ids(&value.evidence_ids, "candidate evidence", false)?;
    if !value.reference_only {
        return unauthorized("OFFICE-100 candidate must remain reference-only");
    }
    Ok(())
}

fn validate_profile(value: &OfficeWorkspaceProfileV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace profile")?;
    validate_id(&value.workspace_id, "workspace_id")?;
    validate_id(&value.organization_id, "organization_id")?;
    validate_ids(&value.role_scope_ids, "Role scopes", false)?;
    validate_hash(&value.workspace_root_binding_sha256, "root binding")?;
    validate_ids(&value.allowed_artifact_classes, "artifact classes", false)?;
    validate_ids(&value.allowed_extensions, "allowed extensions", false)?;
    if value.maximum_total_bytes == 0
        || value.maximum_file_bytes == 0
        || value.maximum_file_bytes > value.maximum_total_bytes
        || value.maximum_files == 0
        || value.maximum_files as usize > MAX_COLLECTION_ITEMS
        || value.maximum_directories == 0
        || value.maximum_directories as usize > MAX_COLLECTION_ITEMS
        || value.maximum_depth == 0
        || value.maximum_depth > 16
        || value.allowed_operations.is_empty()
        || value.allowed_operations.len() > 32
    {
        return invalid("workspace resource limits or operation set are invalid");
    }
    let operations = value.allowed_operations.iter().collect::<BTreeSet<_>>();
    if operations.len() != value.allowed_operations.len() {
        return invalid("workspace operations contain duplicates");
    }
    for text in [
        &value.versioning_policy_id,
        &value.backup_policy_id,
        &value.overwrite_policy_id,
        &value.delete_policy_id,
        &value.retention_policy_id,
        &value.signer_key_id,
    ] {
        validate_id(text, "workspace profile policy")?;
    }
    if value.overwrite_policy_id != "deny-original-overwrite"
        || value.delete_policy_id != "prohibited"
    {
        return unauthorized("OFFICE-100 requires immutable originals and prohibited delete");
    }
    validate_interval(
        value.valid_from_unix_ms,
        value.valid_until_unix_ms,
        "profile",
    )?;
    validate_ids(&value.evidence_ids, "profile evidence", false)
}

fn validate_root(value: &WorkspaceRootBindingV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "root binding")?;
    validate_id(&value.workspace_id, "workspace_id")?;
    validate_text(&value.canonical_root, "canonical_root")?;
    validate_id(&value.root_identity, "root_identity")?;
    validate_id(&value.volume_identity, "volume_identity")?;
    validate_hash(&value.security_descriptor_sha256, "security descriptor")?;
    validate_interval(
        value.valid_from_unix_ms,
        value.valid_until_unix_ms,
        "root binding",
    )?;
    if !value.reparse_forbidden
        || !value.symlink_forbidden
        || value.network_share_allowed
        || value.removable_media_allowed
    {
        return unauthorized("v1 root must be local and forbid reparse and symlink traversal");
    }
    Ok(())
}

fn validate_artifact(value: &OfficeArtifactReferenceV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "artifact reference")?;
    validate_id(&value.artifact_id, "artifact_id")?;
    validate_id(&value.workspace_id, "workspace_id")?;
    validate_relative_path_token(&value.relative_path_token)?;
    validate_id(&value.artifact_class, "artifact_class")?;
    validate_id(&value.file_format_id, "file_format_id")?;
    validate_hash(&value.content_sha256, "artifact content")?;
    if value.byte_length == 0
        || value.creation_generation == 0
        || value.current_generation < value.creation_generation
    {
        return invalid("artifact length or generation is invalid");
    }
    if let Some(source) = &value.source_artifact_id {
        validate_id(source, "source_artifact_id")?;
    }
    if let Some(parent) = &value.parent_version_id {
        validate_id(parent, "parent_version_id")?;
    }
    validate_ids(&value.data_class_ids, "data classes", false)?;
    validate_ids(&value.evidence_ids, "artifact evidence", false)
}

fn validate_observation(
    value: &WorkspaceObservationSnapshotV1,
) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace observation")?;
    validate_id(&value.observation_id, "observation_id")?;
    validate_id(&value.workspace_id, "workspace_id")?;
    validate_ids(&value.artifact_ids, "observation artifacts", true)?;
    validate_hashes(&value.content_sha256s, "observation hashes", true)?;
    let count = value.artifact_ids.len();
    if value.artifact_generations.len() != count
        || value.content_sha256s.len() != count
        || value.sizes.len() != count
        || value.formats.len() != count
        || value.lock_states.len() != count
        || value.write_states.len() != count
        || value.observed_at_unix_ms >= value.freshness_expires_at_unix_ms
    {
        return invalid("workspace observation parallel collections or freshness differ");
    }
    for format in &value.formats {
        validate_id(format, "observation format")?;
    }
    for state in &value.write_states {
        validate_id(state, "observation write state")?;
    }
    Ok(())
}

fn validate_intent(value: &WorkspaceOperationIntentV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace intent")?;
    validate_id(&value.intent_id, "intent_id")?;
    validate_id(&value.workspace_id, "workspace_id")?;
    if let Some(source) = &value.source_artifact_id {
        validate_id(source, "source_artifact_id")?;
    }
    if let Some(folder) = &value.destination_folder_id {
        validate_id(folder, "destination_folder_id")?;
    }
    if let Some(filename) = &value.destination_filename {
        validate_filename_segment(filename)?;
    }
    for hash in [
        value.approved_content_sha256.as_deref(),
        value.expected_source_content_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_hash(hash, "intent hash")?;
    }
    validate_id(&value.case_id, "case_id")?;
    validate_id(&value.role_instance_id, "role_instance_id")?;
    validate_ids(&value.evidence_ids, "intent evidence", false)?;
    if matches!(
        value.operation,
        WorkspaceOperationClassV1::CreateWorkingCopy
            | WorkspaceOperationClassV1::CopyArtifact
            | WorkspaceOperationClassV1::RenameArtifact
            | WorkspaceOperationClassV1::MoveArtifact
            | WorkspaceOperationClassV1::CommitVersion
            | WorkspaceOperationClassV1::ExportCopy
            | WorkspaceOperationClassV1::RestoreVersion
    ) && (value.source_artifact_id.is_none()
        || value.expected_source_content_sha256.is_none()
        || value.expected_source_generation.is_none())
    {
        return invalid("mutation intent requires exact source hash and generation");
    }
    Ok(())
}

fn validate_binding(value: &WorkspaceOperationBindingV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace binding")?;
    validate_id(&value.binding_id, "binding_id")?;
    for hash in [
        &value.role_contract_sha256,
        &value.role_instance_sha256,
        &value.case_sha256,
        &value.lease_sha256,
        &value.work_grant_sha256,
        &value.workspace_profile_sha256,
        &value.workspace_root_binding_sha256,
        &value.operation_intent_sha256,
        &value.policy_decision_sha256,
        &value.cognitive_activation_admission_sha256,
    ] {
        validate_hash(hash, "workspace binding hash")?;
    }
    if let Some(hash) = &value.source_artifact_sha256 {
        validate_hash(hash, "binding source artifact")?;
    }
    validate_id(
        &value.expected_output_scope_token,
        "expected_output_scope_token",
    )?;
    validate_id(&value.one_time_use_id, "one_time_use_id")?;
    if value.expires_at_unix_ms == 0 {
        return invalid("workspace binding expiry is missing");
    }
    Ok(())
}

fn validate_receipt(value: &WorkspaceOperationReceiptV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace receipt")?;
    validate_id(&value.receipt_id, "receipt_id")?;
    validate_hash(&value.operation_intent_sha256, "receipt intent")?;
    validate_hash(&value.binding_sha256, "receipt binding")?;
    for hash in [
        value.source_artifact_sha256.as_deref(),
        value.destination_artifact_sha256.as_deref(),
        value.old_identity_sha256.as_deref(),
        value.new_identity_sha256.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_hash(hash, "receipt artifact identity")?;
    }
    validate_id(&value.structured_result_code, "structured_result_code")?;
    validate_hash(&value.verification_sha256, "receipt verification")?;
    if value.started_at_unix_ms > value.completed_at_unix_ms {
        return invalid("receipt completion precedes start");
    }
    Ok(())
}

fn validate_provenance(value: &OfficeArtifactProvenanceV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "artifact provenance")?;
    validate_hash(&value.artifact_sha256, "provenance artifact")?;
    validate_hashes(&value.source_artifact_sha256s, "provenance sources", false)?;
    validate_hash(&value.case_sha256, "provenance Case")?;
    validate_hash(&value.role_instance_sha256, "provenance Role")?;
    validate_hashes(
        &value.operation_receipt_sha256s,
        "provenance receipts",
        false,
    )?;
    validate_id(&value.application_family_id, "application_family_id")?;
    if value.created_at_unix_ms > value.modified_at_unix_ms {
        return invalid("provenance modification precedes creation");
    }
    validate_ids(&value.data_class_ids, "provenance data classes", false)?;
    validate_hashes(
        &value.verification_sha256s,
        "provenance verification",
        false,
    )
}

fn validate_replay(value: &OfficeWorkspaceReplayReportV1) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace replay")?;
    validate_id(&value.report_id, "report_id")?;
    for hash in [
        &value.input_set_sha256,
        &value.first_output_sha256,
        &value.final_output_sha256,
    ] {
        validate_hash(hash, "replay hash")?;
    }
    validate_ids(&value.evidence_ids, "replay evidence", false)?;
    if value.synthetic_scenario_count != 128
        || value.replay_runs != 100
        || value.deterministic_match_count != 100
        || value.deterministic_mismatch_count != 0
        || value.first_output_sha256 != value.final_output_sha256
    {
        return integrity("workspace replay evidence is not 128 by 100 deterministic");
    }
    Ok(())
}

fn validate_completion(
    value: &OfficeWorkspaceCompletionReportV1,
) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace completion")?;
    validate_id(&value.report_id, "report_id")?;
    for hash in [
        &value.source_tree_sha256,
        &value.predecessor_finished_sha256,
        &value.replay_report_sha256,
        &value.protected_audit_terminal_sha256,
    ] {
        validate_hash(hash, "completion hash")?;
    }
    let zero_security = value.path_escape_count == 0
        && value.wrong_file_count == 0
        && value.original_overwrite_count == 0
        && value.duplicate_mutation_count == 0
        && value.stale_write_count == 0
        && value.reparse_escape_count == 0
        && value.symlink_escape_count == 0
        && value.raw_absolute_path_in_model_context_count == 0
        && value.arbitrary_command_count == 0
        && value.arbitrary_code_execution_count == 0
        && value.credential_leak_count == 0
        && value.network_access_count == 0
        && value.false_completion_count == 0
        && value.critical_error_count == 0
        && value.residual_process_count == 0
        && value.residual_profile_count == 0
        && value.residual_lock_count == 0
        && value.residual_store_count == 0;
    if value.complete
        && (!value.office_capability_foundation_evidence
            || !value.office_workspace_evidence
            || !value.track_o_started
            || value.source_assessment_count < 9
            || value.excel_source_count < 2
            || value.powerpoint_source_count < 2
            || value.hwp_source_count < 2
            || value.official_source_count < 3
            || value.mcp_catalog_count < 6
            || value.rejected_runtime_source_count == 0
            || value.workspace_cases < 10
            || value.routine_verified < 6
            || value.operation_count < 6
            || value.version_count < 2
            || value.provenance_count == 0
            || value.stale_recoveries == 0
            || !zero_security)
    {
        return integrity("OFFICE-100 Completion gates are incomplete");
    }
    Ok(())
}

fn validate_certification(
    value: &OfficeWorkspaceCertificationV1,
) -> Result<(), OfficeCapabilityError> {
    validate_version(value.schema_version, "workspace certification")?;
    validate_id(&value.certification_id, "certification_id")?;
    for hash in [
        &value.completion_report_sha256,
        &value.workspace_profile_sha256,
        &value.workspace_root_binding_sha256,
        &value.replay_report_sha256,
    ] {
        validate_hash(hash, "certification hash")?;
    }
    validate_interval(
        value.issued_at_unix_ms,
        value.expires_at_unix_ms,
        "certification",
    )?;
    validate_id(&value.signer_id, "signer_id")?;
    validate_id(&value.signing_key_id, "signing_key_id")?;
    validate_ids(&value.evidence_ids, "certification evidence", false)
}

macro_rules! impl_hashed_artifact {
    ($type:ty, $field:ident, $validate:ident) => {
        impl $type {
            /// Seals and validates this artifact.
            pub fn seal(mut self) -> Result<Self, OfficeCapabilityError> {
                self.$field = hash_without(&self, &[stringify!($field)])?;
                self.validate_integrity()?;
                Ok(self)
            }

            /// Validates fields and canonical self-hash.
            pub fn validate_integrity(&self) -> Result<(), OfficeCapabilityError> {
                $validate(self)?;
                if self.$field != hash_without(self, &[stringify!($field)])? {
                    return integrity(concat!(stringify!($type), " hash differs"));
                }
                Ok(())
            }
        }
    };
}

impl_hashed_artifact!(CapabilitySourceRecordV1, record_sha256, validate_source);
impl_hashed_artifact!(
    OfficeCapabilityCandidateV1,
    candidate_sha256,
    validate_candidate
);

impl McpToolCatalogSnapshotV1 {
    /// Seals catalog contents independently of the later source-record link.
    pub fn seal(mut self) -> Result<Self, OfficeCapabilityError> {
        self.catalog_sha256 = hash_without(&self, &["catalog_sha256", "source_record_sha256"])?;
        self.validate_integrity()?;
        Ok(self)
    }

    /// Validates catalog fields and its non-circular content digest.
    pub fn validate_integrity(&self) -> Result<(), OfficeCapabilityError> {
        validate_catalog(self)?;
        if self.catalog_sha256 != hash_without(self, &["catalog_sha256", "source_record_sha256"])? {
            return integrity("McpToolCatalogSnapshotV1 hash differs");
        }
        Ok(())
    }
}
impl_hashed_artifact!(WorkspaceRootBindingV1, binding_sha256, validate_root);
impl_hashed_artifact!(
    OfficeArtifactReferenceV1,
    artifact_sha256,
    validate_artifact
);
impl_hashed_artifact!(
    WorkspaceObservationSnapshotV1,
    observation_sha256,
    validate_observation
);
impl_hashed_artifact!(WorkspaceOperationIntentV1, intent_sha256, validate_intent);
impl_hashed_artifact!(
    WorkspaceOperationBindingV1,
    binding_sha256,
    validate_binding
);
impl_hashed_artifact!(
    WorkspaceOperationReceiptV1,
    receipt_sha256,
    validate_receipt
);
impl_hashed_artifact!(
    OfficeArtifactProvenanceV1,
    provenance_sha256,
    validate_provenance
);
impl_hashed_artifact!(
    OfficeWorkspaceReplayReportV1,
    report_sha256,
    validate_replay
);
impl_hashed_artifact!(
    OfficeWorkspaceCompletionReportV1,
    finished_sha256,
    validate_completion
);

impl OfficeWorkspaceProfileV1 {
    /// Signs a canonical profile whose signature and self-hash fields are excluded.
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, OfficeCapabilityError> {
        self.signature_hex.clear();
        self.profile_sha256 = hash_without(&self, &["profile_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&key.sign(self.profile_sha256.as_bytes()).to_bytes());
        self.validate_signature(&key.verifying_key())?;
        Ok(self)
    }

    /// Validates profile fields, canonical hash, and Ed25519 signature.
    pub fn validate_signature(&self, key: &VerifyingKey) -> Result<(), OfficeCapabilityError> {
        validate_profile(self)?;
        if self.profile_sha256 != hash_without(self, &["profile_sha256", "signature_hex"])? {
            return integrity("workspace profile hash differs");
        }
        verify_signature(key, &self.profile_sha256, &self.signature_hex)
    }
}

impl OfficeWorkspaceCertificationV1 {
    /// Signs one exact completion certification.
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, OfficeCapabilityError> {
        self.signature_hex.clear();
        self.certification_sha256 =
            hash_without(&self, &["certification_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&key.sign(self.certification_sha256.as_bytes()).to_bytes());
        self.validate_signature(&key.verifying_key())?;
        Ok(self)
    }

    /// Validates certification fields, self-hash, and signature.
    pub fn validate_signature(&self, key: &VerifyingKey) -> Result<(), OfficeCapabilityError> {
        validate_certification(self)?;
        if self.certification_sha256
            != hash_without(self, &["certification_sha256", "signature_hex"])?
        {
            return integrity("workspace certification hash differs");
        }
        verify_signature(key, &self.certification_sha256, &self.signature_hex)
    }
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &str,
    signature_hex: &str,
) -> Result<(), OfficeCapabilityError> {
    let bytes = hex_decode_64(signature_hex)?;
    key.verify(payload.as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|error| OfficeCapabilityError::Signature(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_64(value: &str) -> Result<[u8; 64], OfficeCapabilityError> {
    if value.len() != 128 {
        return Err(OfficeCapabilityError::Signature(
            "Ed25519 signature length differs".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|error| OfficeCapabilityError::Signature(error.to_string()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|error| OfficeCapabilityError::Signature(error.to_string()))?;
    }
    Ok(bytes)
}

/// Replay-safe one-shot authority ledger for trusted workspace mutation.
#[derive(Debug, Default)]
pub struct WorkspaceActivationLedgerV1 {
    consumed_one_time_use_ids: BTreeSet<String>,
}

impl WorkspaceActivationLedgerV1 {
    /// Consumes an exact binding once after checking policy and admission hashes.
    pub fn consume(
        &mut self,
        binding: &WorkspaceOperationBindingV1,
        expected_policy_sha256: &str,
        expected_admission_sha256: &str,
        now_unix_ms: u64,
    ) -> Result<(), OfficeCapabilityError> {
        binding.validate_integrity()?;
        if binding.policy_decision_sha256 != expected_policy_sha256
            || binding.cognitive_activation_admission_sha256 != expected_admission_sha256
        {
            return unauthorized("workspace binding differs from policy activation");
        }
        if now_unix_ms > binding.expires_at_unix_ms {
            return Err(OfficeCapabilityError::Stale(
                "workspace binding expired".to_owned(),
            ));
        }
        if !self
            .consumed_one_time_use_ids
            .insert(binding.one_time_use_id.clone())
        {
            return Err(OfficeCapabilityError::Replay(
                "workspace activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Number of consumed mutation authorities.
    pub fn consumed_count(&self) -> usize {
        self.consumed_one_time_use_ids.len()
    }
}

#[cfg(test)]
mod tests;
