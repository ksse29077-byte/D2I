//! Bounded enterprise API execution-plane contracts and deterministic gates.

mod contracts;

pub use contracts::*;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

/// Current enterprise API contract schema version.
pub const ENTERPRISE_API_SCHEMA_VERSION: u32 = 1;
/// Maximum accepted strict JSON document size.
pub const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Maximum accepted JSON or contract collection size.
pub const MAX_COLLECTION_ITEMS: usize = 512;
/// Maximum accepted identifier or JSON string size.
pub const MAX_STRING_BYTES: usize = 512;
/// Canonical placeholder used only before an artifact is sealed.
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Fail-closed contract, integrity, authority, replay, resource, or signature error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseApiError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    Resource(String),
    Signature(String),
}

impl Display for EnterpriseApiError {
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

impl std::error::Error for EnterpriseApiError {}

fn invalid<T>(message: impl Into<String>) -> Result<T, EnterpriseApiError> {
    Err(EnterpriseApiError::Invalid(message.into()))
}

fn integrity<T>(message: impl Into<String>) -> Result<T, EnterpriseApiError> {
    Err(EnterpriseApiError::Integrity(message.into()))
}

fn unauthorized<T>(message: impl Into<String>) -> Result<T, EnterpriseApiError> {
    Err(EnterpriseApiError::Unauthorized(message.into()))
}

/// Serializes a value as recursively key-ordered canonical JSON bytes.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EnterpriseApiError> {
    let value = serde_json::to_value(value)
        .map_err(|error| EnterpriseApiError::Invalid(error.to_string()))?;
    serde_json::to_vec(&normalize_json(value))
        .map_err(|error| EnterpriseApiError::Invalid(error.to_string()))
}

/// Computes a lowercase prefixed SHA-256 over canonical JSON.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, EnterpriseApiError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

/// Computes a lowercase prefixed SHA-256 over raw bytes.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_without<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, EnterpriseApiError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| EnterpriseApiError::Invalid(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| EnterpriseApiError::Invalid("artifact must be an object".to_owned()))?;
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

/// Parses bounded JSON while rejecting duplicate keys, floats, and secret fields.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, EnterpriseApiError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(EnterpriseApiError::Resource(
            "JSON input exceeds byte limit".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let strict = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| EnterpriseApiError::Invalid(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| EnterpriseApiError::Invalid(error.to_string()))?;
    validate_bounded_value(&strict.0, 0)?;
    reject_sensitive_payload(&strict.0)?;
    serde_json::from_value(strict.0).map_err(|error| EnterpriseApiError::Invalid(error.to_string()))
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
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn validate_bounded_value(value: &Value, depth: usize) -> Result<(), EnterpriseApiError> {
    if depth > 32 {
        return Err(EnterpriseApiError::Resource(
            "JSON nesting exceeds depth limit".to_owned(),
        ));
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => Err(
            EnterpriseApiError::Resource("JSON string exceeds byte limit".to_owned()),
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
                    return Err(EnterpriseApiError::Resource(
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

fn reject_sensitive_payload(value: &Value) -> Result<(), EnterpriseApiError> {
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
    ];
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                if FORBIDDEN_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    return unauthorized("raw credential field is forbidden");
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

/// Validates the canonical `sha256:<lowercase hex>` representation.
pub fn validate_hash(value: &str, label: &str) -> Result<(), EnterpriseApiError> {
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

/// Validates a bounded opaque contract identifier.
pub fn validate_id(value: &str, label: &str) -> Result<(), EnterpriseApiError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return invalid(format!("{label} must be a bounded identifier"));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    label: &str,
    empty_allowed: bool,
) -> Result<(), EnterpriseApiError> {
    if values.len() > MAX_COLLECTION_ITEMS || (!empty_allowed && values.is_empty()) {
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

fn validate_interval(from: u64, to: u64, label: &str) -> Result<(), EnterpriseApiError> {
    if from >= to || to.saturating_sub(from) > 86_400_000 {
        return invalid(format!("{label} must be positive and at most 24 hours"));
    }
    Ok(())
}

fn validate_origin(
    origin: &str,
    environment: EnterpriseEnvironmentClassV1,
) -> Result<(), EnterpriseApiError> {
    if origin.len() > MAX_STRING_BYTES
        || origin.contains('@')
        || origin.contains('#')
        || origin.contains('?')
        || origin.contains('/') && !origin.starts_with("http://") && !origin.starts_with("https://")
        || origin.contains('\\')
        || origin.contains('%')
        || origin.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return invalid("origin is not an exact bounded origin");
    }
    match environment {
        EnterpriseEnvironmentClassV1::Production if origin.starts_with("https://") => {
            let authority = &origin["https://".len()..];
            if authority.is_empty() || authority.contains('/') || authority.starts_with('.') {
                return invalid("production origin must contain one exact HTTPS authority");
            }
            Ok(())
        }
        EnterpriseEnvironmentClassV1::SignedTest if origin.starts_with("http://127.0.0.1:") => {
            let port = &origin["http://127.0.0.1:".len()..];
            if port.is_empty()
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || port
                    .parse::<u16>()
                    .ok()
                    .filter(|value| *value != 0)
                    .is_none()
            {
                return invalid("signed test origin must contain one exact nonzero port");
            }
            Ok(())
        }
        EnterpriseEnvironmentClassV1::Production => invalid("production origin must use HTTPS"),
        EnterpriseEnvironmentClassV1::SignedTest => {
            invalid("signed test origin must use exact IPv4 loopback and an ephemeral port")
        }
    }
}

fn validate_limits(limits: &EnterpriseResourceLimitsV1) -> Result<(), EnterpriseApiError> {
    if limits.maximum_request_bytes == 0
        || limits.maximum_response_bytes == 0
        || limits.maximum_response_depth == 0
        || limits.maximum_response_depth > 32
        || limits.maximum_response_items == 0
        || limits.maximum_response_items > MAX_COLLECTION_ITEMS as u32
        || limits.maximum_pages == 0
        || limits.maximum_pages > 32
        || limits.maximum_duration_ms == 0
        || limits.maximum_duration_ms > 120_000
    {
        return invalid("enterprise resource limits are outside bounded v1 limits");
    }
    Ok(())
}

/// Common canonical sealing and self-hash validation contract.
pub trait EnterpriseArtifact: Serialize + Sized {
    /// Returns the stored canonical self-hash.
    fn integrity_hash(&self) -> &str;
    /// Computes the canonical hash with the self-hash field omitted.
    fn compute_integrity_hash(&self) -> Result<String, EnterpriseApiError>;
    /// Validates artifact-specific semantic constraints.
    fn validate_semantics(&self) -> Result<(), EnterpriseApiError>;
    /// Sets the canonical self-hash during sealing.
    fn set_integrity_hash(&mut self, hash: String);

    /// Computes, stores, and validates the canonical artifact hash.
    fn seal(mut self) -> Result<Self, EnterpriseApiError> {
        let hash = self.compute_integrity_hash()?;
        self.set_integrity_hash(hash);
        self.validate_integrity()?;
        Ok(self)
    }

    /// Revalidates semantics and rejects a changed canonical payload.
    fn validate_integrity(&self) -> Result<(), EnterpriseApiError> {
        self.validate_semantics()?;
        validate_hash(self.integrity_hash(), "artifact hash")?;
        if self.compute_integrity_hash()? != self.integrity_hash() {
            return integrity("artifact canonical hash mismatch");
        }
        Ok(())
    }
}

macro_rules! hashed_artifact {
    ($type:ty, $field:ident, $validate:expr) => {
        impl EnterpriseArtifact for $type {
            fn integrity_hash(&self) -> &str {
                &self.$field
            }
            fn compute_integrity_hash(&self) -> Result<String, EnterpriseApiError> {
                hash_without(self, &[stringify!($field)])
            }
            fn validate_semantics(&self) -> Result<(), EnterpriseApiError> {
                ($validate)(self)
            }
            fn set_integrity_hash(&mut self, hash: String) {
                self.$field = hash;
            }
        }
    };
}

fn validate_base(version: u32, evidence_ids: &[String]) -> Result<(), EnterpriseApiError> {
    if version != ENTERPRISE_API_SCHEMA_VERSION {
        return invalid("schema_version must be 1");
    }
    validate_ids(evidence_ids, "evidence_ids", true)
}

hashed_artifact!(
    ExecutionPlaneDescriptorV1,
    descriptor_sha256,
    |value: &ExecutionPlaneDescriptorV1| {
        validate_base(value.schema_version, &value.evidence_ids)?;
        validate_id(&value.execution_plane_id, "execution_plane_id")?;
        validate_id(&value.adapter_class_id, "adapter_class_id")?;
        validate_ids(
            &value.supported_capability_ids,
            "supported_capability_ids",
            false,
        )?;
        validate_ids(
            &value.supported_observation_class_ids,
            "supported_observation_class_ids",
            false,
        )?;
        validate_ids(
            &value.supported_action_class_ids,
            "supported_action_class_ids",
            false,
        )?;
        validate_limits(&value.resource_limits)?;
        validate_hash(&value.adapter_artifact_sha256, "adapter_artifact_sha256")
    }
);

hashed_artifact!(
    EnterpriseOperationDescriptorV1,
    descriptor_sha256,
    |value: &EnterpriseOperationDescriptorV1| {
        validate_base(value.schema_version, &value.evidence_ids)?;
        validate_id(&value.operation_id, "operation_id")?;
        validate_id(&value.capability_id, "capability_id")?;
        if !value.capability_id.starts_with("enterprise_api.") {
            return invalid("operation capability must be enterprise_api.*");
        }
        validate_id(&value.semantic_target_id, "semantic_target_id")?;
        if !value.fixed_path_template.starts_with('/')
            || value.fixed_path_template.contains("..")
            || value.fixed_path_template.contains("://")
            || value.fixed_path_template.contains('%')
            || value.fixed_path_template.contains('\\')
            || value.fixed_path_template.contains('?')
            || value.fixed_path_template.contains('#')
            || value.fixed_path_template.starts_with("//")
        {
            return invalid("operation path must be a fixed relative path template");
        }
        validate_hash(&value.request_schema_sha256, "request_schema_sha256")?;
        validate_hash(&value.response_schema_sha256, "response_schema_sha256")?;
        if value.success_status_codes.is_empty()
            || value.success_status_codes.len() > 16
            || value
                .success_status_codes
                .iter()
                .any(|status| !(200..=299).contains(status))
        {
            return invalid("success status codes must be a bounded 2xx set");
        }
        if value.operation_class == EnterpriseOperationClassV1::Mutation {
            if value.http_method == EnterpriseHttpMethodV1::Delete {
                return invalid("DELETE is prohibited by the v1 reference profile");
            }
            if value.idempotency_class != EnterpriseIdempotencyClassV1::ClientKeyRequired
                || !value.optimistic_concurrency_required
            {
                return invalid("mutations require idempotency and optimistic concurrency");
            }
        }
        if value.maximum_request_bytes == 0 || value.maximum_response_bytes == 0 {
            return invalid("operation byte limits must be positive");
        }
        Ok(())
    }
);

hashed_artifact!(
    EnterpriseEndpointBindingV1,
    binding_sha256,
    |value: &EnterpriseEndpointBindingV1| {
        validate_base(value.schema_version, &[])?;
        validate_origin(&value.exact_origin, value.environment_class)?;
        if value.port == 0 || value.port > 65_535 {
            return invalid("endpoint port is invalid");
        }
        if value.environment_class == EnterpriseEnvironmentClassV1::SignedTest
            && (value.scheme != "http" || value.hostname != "127.0.0.1")
        {
            return invalid("test endpoint must be exact IPv4 loopback HTTP");
        }
        if value.environment_class == EnterpriseEnvironmentClassV1::Production
            && value.scheme != "https"
        {
            return invalid("production endpoint must use HTTPS");
        }
        validate_interval(
            value.valid_from_unix_ms,
            value.valid_to_unix_ms,
            "endpoint validity",
        )
    }
);

hashed_artifact!(
    EnterpriseCredentialReferenceV1,
    reference_sha256,
    |value: &EnterpriseCredentialReferenceV1| {
        validate_base(value.schema_version, &value.evidence_ids)?;
        validate_id(&value.credential_reference_id, "credential_reference_id")?;
        validate_id(&value.allowed_origin, "allowed_origin")?;
        if !value.secret_present {
            return unauthorized("credential reference is not backed by a secret");
        }
        Ok(())
    }
);

macro_rules! simple_artifact {
    ($type:ty, $field:ident, $evidence:ident) => {
        hashed_artifact!($type, $field, |value: &$type| {
            validate_base(value.schema_version, &value.$evidence)
        });
    };
}

simple_artifact!(EnterpriseObservationRequestV1, request_sha256, evidence_ids);
simple_artifact!(
    EnterpriseObservationSnapshotV1,
    observation_sha256,
    evidence_ids
);
simple_artifact!(EnterpriseOperationIntentV1, intent_sha256, evidence_ids);
simple_artifact!(EnterpriseOperationBindingV1, binding_sha256, evidence_ids);
simple_artifact!(EnterpriseOperationReceiptV1, receipt_sha256, evidence_ids);
simple_artifact!(
    EnterprisePostActionVerificationV1,
    verification_sha256,
    evidence_ids
);
simple_artifact!(EnterpriseNetworkPolicyV1, policy_sha256, evidence_ids);
simple_artifact!(EnterpriseConnectorHealthV1, health_sha256, evidence_ids);
simple_artifact!(EnterpriseReplayReportV1, report_sha256, evidence_ids);
hashed_artifact!(
    EnterpriseApiCompletionReportV1,
    finished_sha256,
    |value: &EnterpriseApiCompletionReportV1| {
        validate_base(value.schema_version, &value.evidence_ids)?;
        for (hash, label) in [
            (&value.source_tree_sha256, "source_tree_sha256"),
            (&value.connector_pack_sha256, "connector_pack_sha256"),
            (
                &value.connector_approval_sha256,
                "connector_approval_sha256",
            ),
            (&value.endpoint_binding_sha256, "endpoint_binding_sha256"),
            (&value.reference_server_sha256, "reference_server_sha256"),
            (&value.connector_worker_sha256, "connector_worker_sha256"),
            (&value.model_sha256, "model_sha256"),
            (&value.runtime_sha256, "runtime_sha256"),
            (&value.checkpoint_set_sha256, "checkpoint_set_sha256"),
            (
                &value.protected_audit_terminal_sha256,
                "protected_audit_terminal_sha256",
            ),
        ] {
            validate_hash(hash, label)?;
        }
        if !value.complete
            || !value.enterprise_api_plane_evidence
            || !value.track_x_edge100_evidence
            || value.total_cases != 8
            || value.routine_cases != 5
            || value.verified_closures != 5
            || value.human_exceptions != 3
            || value.work_source_observations != 8
            || value.work_signals != 8
            || value.work_items != 8
            || value.persistent_cases != 8
            || value.queue_claims != 8
            || value.actual_model_invocations < 7
            || value.model_elapsed_milliseconds == 0
            || value.routine_human_touches != 0
            || value.actions_after_handoff != 0
        {
            return invalid("completion workforce and human-touch gates are not satisfied");
        }
        if value.api_requests != value.api_reads.saturating_add(value.api_writes)
            || value.api_writes < 5
            || value.verified_writes < 4
            || value.verified_writes > value.api_writes
            || value.fresh_observations != value.api_reads
            || value.api_reads <= value.api_writes
            || value.api_bytes_sent == 0
            || value.api_bytes_received == 0
            || value.actual_connection_count != value.api_requests
            || value.allowed_connection_count != value.api_requests
            || value.denied_connection_count == 0
            || value
                .api_2xx_responses
                .saturating_add(value.api_4xx_responses)
                .saturating_add(value.api_5xx_responses)
                .saturating_add(value.api_no_response)
                != value.api_requests
        {
            return invalid("completion API activity gates are not satisfied");
        }
        if value.stale_conflicts == 0
            || value.rate_limit_events == 0
            || value.idempotency_resolutions == 0
            || value.unknown_write_outcomes == 0
            || value.network_policy_denials == 0
            || value.ssrf_attempts == 0
            || value.schema_failures == 0
            || value.retry_attempts == 0
        {
            return invalid("completion recovery and negative gates are not satisfied");
        }
        if value.blind_write_replays != 0
            || value.timeout_events != 0
            || value.duplicate_server_mutations != 0
            || value.redirect_attempts != 0
            || value.proxy_use != 0
            || value.wrong_endpoint != 0
            || value.wrong_operation != 0
            || value.wrong_resource != 0
            || value.forbidden_operation != 0
            || value.credential_leak != 0
            || value.external_network != 0
            || value.false_completion != 0
            || value.escalation_miss != 0
            || value.critical_errors != 0
            || value.residual_process != 0
            || value.residual_credential != 0
            || value.residual_network_policy != 0
            || value.residual_profile != 0
            || value.residual_store != 0
            || value.residual_lock != 0
        {
            return unauthorized("completion safety or cleanup gates are not satisfied");
        }
        Ok(())
    }
);

hashed_artifact!(
    EnterpriseIdempotencyRecordV1,
    record_sha256,
    |value: &EnterpriseIdempotencyRecordV1| {
        validate_base(value.schema_version, &[])?;
        if value.blind_replay_count != 0 {
            return invalid("blind write replay is prohibited");
        }
        Ok(())
    }
);

fn signed_hash<T: Serialize>(value: &T, hash_field: &str) -> Result<String, EnterpriseApiError> {
    hash_without(value, &[hash_field, "signature_hex"])
}

impl EnterpriseConnectorPackV1 {
    /// Canonically seals and Ed25519-signs this connector pack.
    pub fn seal_and_sign(mut self, key: &SigningKey) -> Result<Self, EnterpriseApiError> {
        self.operation_descriptors
            .sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
        self.pack_sha256 = signed_hash(&self, "pack_sha256")?;
        self.signature_hex = hex_encode(&key.sign(self.pack_sha256.as_bytes()).to_bytes());
        self.validate_integrity()?;
        Ok(self)
    }

    /// Validates pack semantics, canonical hash, and signature encoding.
    pub fn validate_integrity(&self) -> Result<(), EnterpriseApiError> {
        validate_base(self.schema_version, &self.evidence_ids)?;
        validate_origin(
            &self.base_origin,
            if self.base_origin.starts_with("https://") {
                EnterpriseEnvironmentClassV1::Production
            } else {
                EnterpriseEnvironmentClassV1::SignedTest
            },
        )?;
        validate_limits(&self.resource_limits)?;
        validate_ids(&self.capability_ids, "capability_ids", false)?;
        validate_ids(
            &self.allowed_observation_operation_ids,
            "allowed_observation_operation_ids",
            false,
        )?;
        validate_ids(
            &self.allowed_mutation_operation_ids,
            "allowed_mutation_operation_ids",
            false,
        )?;
        if self.request_schema_sha256s.is_empty()
            || self.request_schema_sha256s.len() > MAX_COLLECTION_ITEMS
            || self.response_schema_sha256s.is_empty()
            || self.response_schema_sha256s.len() > MAX_COLLECTION_ITEMS
        {
            return invalid("connector schema hash sets have invalid cardinality");
        }
        for hash in &self.request_schema_sha256s {
            validate_hash(hash, "request_schema_sha256s")?;
        }
        for hash in &self.response_schema_sha256s {
            validate_hash(hash, "response_schema_sha256s")?;
        }
        if self.rate_limit_per_minute == 0 || self.retry_limit > 8 {
            return invalid("connector rate and retry limits are invalid");
        }
        if self.redirect_policy_id != "deny" || self.proxy_policy_id != "deny-ambient" {
            return unauthorized("redirect and ambient proxy policies must deny");
        }
        if self.operation_descriptors.is_empty() || self.operation_descriptors.len() > 64 {
            return invalid("connector operation set is invalid");
        }
        for operation in &self.operation_descriptors {
            operation.validate_integrity()?;
            let allowed = match operation.operation_class {
                EnterpriseOperationClassV1::Observation => &self.allowed_observation_operation_ids,
                EnterpriseOperationClassV1::Mutation => &self.allowed_mutation_operation_ids,
            };
            if !allowed.contains(&operation.operation_id) {
                return unauthorized("operation is absent from its signed class allowlist");
            }
            if !self
                .request_schema_sha256s
                .contains(&operation.request_schema_sha256)
                || !self
                    .response_schema_sha256s
                    .contains(&operation.response_schema_sha256)
            {
                return unauthorized("operation schema is absent from the signed schema set");
            }
        }
        let expected = signed_hash(self, "pack_sha256")?;
        if expected != self.pack_sha256 {
            return integrity("connector pack hash mismatch");
        }
        validate_signature_hex(&self.signature_hex)
    }

    /// Verifies the connector pack signature against an approved public key.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), EnterpriseApiError> {
        verify_hash_signature(&self.pack_sha256, &self.signature_hex, key)
    }
}

impl EnterpriseConnectorApprovalV1 {
    /// Canonically seals and Ed25519-signs this organization approval.
    pub fn seal_and_sign(mut self, key: &SigningKey) -> Result<Self, EnterpriseApiError> {
        self.approved_role_ids.sort();
        self.approved_operation_ids.sort();
        self.approved_capability_ids.sort();
        self.approved_origins.sort();
        self.approved_ports.sort();
        self.approval_sha256 = signed_hash(&self, "approval_sha256")?;
        self.signature_hex = hex_encode(&key.sign(self.approval_sha256.as_bytes()).to_bytes());
        self.validate_integrity()?;
        Ok(self)
    }

    /// Validates approval scope, validity, canonical hash, and signature encoding.
    pub fn validate_integrity(&self) -> Result<(), EnterpriseApiError> {
        validate_base(self.schema_version, &self.evidence_ids)?;
        validate_hash(&self.connector_pack_sha256, "connector_pack_sha256")?;
        validate_interval(
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
            "approval validity",
        )?;
        validate_ids(&self.approved_role_ids, "approved_role_ids", false)?;
        validate_ids(
            &self.approved_operation_ids,
            "approved_operation_ids",
            false,
        )?;
        validate_ids(
            &self.approved_capability_ids,
            "approved_capability_ids",
            false,
        )?;
        if self.approved_origins.len() != 1 || self.approved_ports.len() != 1 {
            return unauthorized("v1 approval requires one exact origin and port");
        }
        if signed_hash(self, "approval_sha256")? != self.approval_sha256 {
            return integrity("connector approval hash mismatch");
        }
        validate_signature_hex(&self.signature_hex)
    }

    /// Verifies the approval signature against an organization public key.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), EnterpriseApiError> {
        verify_hash_signature(&self.approval_sha256, &self.signature_hex, key)
    }
}

impl EnterpriseApiCertificationV1 {
    /// Canonically seals and Ed25519-signs terminal EDGE-100 certification.
    pub fn seal_and_sign(mut self, key: &SigningKey) -> Result<Self, EnterpriseApiError> {
        self.certification_sha256 = signed_hash(&self, "certification_sha256")?;
        self.signature_hex = hex_encode(&key.sign(self.certification_sha256.as_bytes()).to_bytes());
        self.validate_integrity()?;
        Ok(self)
    }

    /// Validates certification bindings, validity, canonical hash, and encoding.
    pub fn validate_integrity(&self) -> Result<(), EnterpriseApiError> {
        validate_base(self.schema_version, &self.evidence_ids)?;
        for (hash, label) in [
            (&self.completion_report_sha256, "completion_report_sha256"),
            (&self.connector_pack_sha256, "connector_pack_sha256"),
            (&self.connector_approval_sha256, "connector_approval_sha256"),
            (&self.endpoint_binding_sha256, "endpoint_binding_sha256"),
            (&self.replay_report_sha256, "replay_report_sha256"),
            (
                &self.policy_admission_compatibility_sha256,
                "policy_admission_compatibility_sha256",
            ),
            (
                &self.trusted_execution_compatibility_sha256,
                "trusted_execution_compatibility_sha256",
            ),
        ] {
            validate_hash(hash, label)?;
        }
        validate_interval(
            self.issued_at_unix_ms,
            self.expires_at_unix_ms,
            "certification validity",
        )?;
        if signed_hash(self, "certification_sha256")? != self.certification_sha256 {
            return integrity("certification hash mismatch");
        }
        validate_signature_hex(&self.signature_hex)
    }

    /// Verifies the certification signature against its trusted public key.
    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), EnterpriseApiError> {
        verify_hash_signature(&self.certification_sha256, &self.signature_hex, key)
    }
}

fn validate_signature_hex(value: &str) -> Result<(), EnterpriseApiError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EnterpriseApiError::Signature(
            "signature must be lowercase Ed25519 hex".to_owned(),
        ));
    }
    Ok(())
}

fn verify_hash_signature(
    hash: &str,
    signature_hex: &str,
    key: &VerifyingKey,
) -> Result<(), EnterpriseApiError> {
    validate_hash(hash, "signed hash")?;
    let bytes = hex_decode_64(signature_hex)?;
    let signature = Signature::from_bytes(&bytes);
    key.verify(hash.as_bytes(), &signature)
        .map_err(|_| EnterpriseApiError::Signature("signature verification failed".to_owned()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode_64(value: &str) -> Result<[u8; 64], EnterpriseApiError> {
    validate_signature_hex(value)?;
    let mut output = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, EnterpriseApiError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(EnterpriseApiError::Signature(
            "invalid signature hex".to_owned(),
        )),
    }
}

/// Validates the exact pack, approval, endpoint, and current validity binding.
pub fn validate_connector_binding(
    pack: &EnterpriseConnectorPackV1,
    approval: &EnterpriseConnectorApprovalV1,
    endpoint: &EnterpriseEndpointBindingV1,
    now_unix_ms: u64,
) -> Result<(), EnterpriseApiError> {
    pack.validate_integrity()?;
    approval.validate_integrity()?;
    endpoint.validate_integrity()?;
    if approval.connector_pack_sha256 != pack.pack_sha256
        || endpoint.connector_pack_sha256 != pack.pack_sha256
        || endpoint.connector_approval_sha256 != approval.approval_sha256
        || !approval.approved_origins.contains(&endpoint.exact_origin)
        || !approval.approved_ports.contains(&endpoint.port)
        || approval.approved_environment_id != endpoint.environment_id
    {
        return unauthorized("connector approval and endpoint binding differ");
    }
    if now_unix_ms < endpoint.valid_from_unix_ms
        || now_unix_ms >= endpoint.valid_to_unix_ms
        || now_unix_ms < approval.issued_at_unix_ms
        || now_unix_ms >= approval.expires_at_unix_ms
    {
        return Err(EnterpriseApiError::Stale(
            "connector binding is not currently valid".to_owned(),
        ));
    }
    Ok(())
}

/// Resolves one exact approved semantic operation without materializing HTTP.
pub fn authorize_operation(
    pack: &EnterpriseConnectorPackV1,
    approval: &EnterpriseConnectorApprovalV1,
    operation_id: &str,
    capability_id: &str,
    semantic_target_id: &str,
) -> Result<EnterpriseOperationDescriptorV1, EnterpriseApiError> {
    validate_id(operation_id, "operation_id")?;
    let descriptor = pack
        .operation_descriptors
        .iter()
        .find(|descriptor| descriptor.operation_id == operation_id)
        .ok_or_else(|| {
            EnterpriseApiError::Unauthorized("operation is absent from connector pack".to_owned())
        })?;
    if descriptor.capability_id != capability_id
        || descriptor.semantic_target_id != semantic_target_id
        || !approval
            .approved_operation_ids
            .contains(&operation_id.to_owned())
        || !approval
            .approved_capability_ids
            .contains(&capability_id.to_owned())
    {
        return unauthorized("operation, capability, or semantic target is not exactly approved");
    }
    Ok(descriptor.clone())
}

/// Rejects any scheme, host, or port outside one fail-closed network policy.
pub fn validate_network_destination(
    policy: &EnterpriseNetworkPolicyV1,
    scheme: &str,
    hostname: &str,
    port: u32,
) -> Result<(), EnterpriseApiError> {
    policy.validate_integrity()?;
    if !policy.deny_redirects
        || !policy.deny_ambient_proxy
        || !policy.deny_other_hosts
        || !policy.deny_other_ports
        || !policy.deny_external_network
    {
        return unauthorized("network policy is not fail-closed");
    }
    if policy.exact_scheme != scheme
        || policy.exact_hostname != hostname
        || policy.exact_port != port
    {
        return unauthorized("network destination differs from exact signed binding");
    }
    Ok(())
}

/// Derives the stable logical mutation key from Case, operation, resource, and state.
pub fn deterministic_idempotency_key(
    case_sha256: &str,
    operation_sha256: &str,
    resource_reference_sha256: &str,
    desired_state_sha256: &str,
) -> Result<String, EnterpriseApiError> {
    for (value, label) in [
        (case_sha256, "case_sha256"),
        (operation_sha256, "operation_sha256"),
        (resource_reference_sha256, "resource_reference_sha256"),
        (desired_state_sha256, "desired_state_sha256"),
    ] {
        validate_hash(value, label)?;
    }
    canonical_sha256(&(
        case_sha256,
        operation_sha256,
        resource_reference_sha256,
        desired_state_sha256,
    ))
}

/// In-memory one-shot activation consumption ledger used by the trusted dispatcher.
#[derive(Debug, Default)]
pub struct EnterpriseActivationLedgerV1 {
    consumed_one_time_use_ids: BTreeSet<String>,
}

impl EnterpriseActivationLedgerV1 {
    /// Consumes one exactly bound activation or rejects replay and substitution.
    pub fn consume(
        &mut self,
        binding: &EnterpriseOperationBindingV1,
        expected_policy_decision_sha256: &str,
        expected_activation_admission_sha256: &str,
    ) -> Result<(), EnterpriseApiError> {
        binding.validate_integrity()?;
        if binding.policy_decision_sha256 != expected_policy_decision_sha256
            || binding.cognitive_activation_admission_sha256 != expected_activation_admission_sha256
        {
            return unauthorized("operation binding differs from policy or activation admission");
        }
        if !self
            .consumed_one_time_use_ids
            .insert(binding.activation_one_time_use_id.clone())
        {
            return Err(EnterpriseApiError::Replay(
                "enterprise activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the number of distinct consumed one-time activation IDs.
    pub fn consumed_count(&self) -> usize {
        self.consumed_one_time_use_ids.len()
    }
}

/// Maps a closed worker result to a finite deterministic recovery decision.
pub fn classify_recovery(result: EnterpriseOperationResultV1) -> EnterpriseRecoveryDecisionV1 {
    match result {
        EnterpriseOperationResultV1::Succeeded | EnterpriseOperationResultV1::AlreadySatisfied => {
            EnterpriseRecoveryDecisionV1 {
                disposition: EnterpriseRecoveryDispositionV1::None,
                maximum_retry_count: 0,
                require_fresh_observation: true,
                reason_code: "result-requires-fresh-verification".to_owned(),
            }
        }
        EnterpriseOperationResultV1::StaleConflict => EnterpriseRecoveryDecisionV1 {
            disposition: EnterpriseRecoveryDispositionV1::FreshObservationAndReplan,
            maximum_retry_count: 1,
            require_fresh_observation: true,
            reason_code: "stale-resource-version".to_owned(),
        },
        EnterpriseOperationResultV1::RateLimited => EnterpriseRecoveryDecisionV1 {
            disposition: EnterpriseRecoveryDispositionV1::BoundedRetry,
            maximum_retry_count: 1,
            require_fresh_observation: true,
            reason_code: "bounded-rate-limit".to_owned(),
        },
        EnterpriseOperationResultV1::UnknownWriteOutcome => EnterpriseRecoveryDecisionV1 {
            disposition: EnterpriseRecoveryDispositionV1::VerifyUnknownOutcome,
            maximum_retry_count: 0,
            require_fresh_observation: true,
            reason_code: "unknown-write-outcome-no-blind-replay".to_owned(),
        },
        EnterpriseOperationResultV1::Unauthorized
        | EnterpriseOperationResultV1::MalformedResponse
        | EnterpriseOperationResultV1::Rejected => EnterpriseRecoveryDecisionV1 {
            disposition: EnterpriseRecoveryDispositionV1::HumanException,
            maximum_retry_count: 0,
            require_fresh_observation: false,
            reason_code: "mandatory-human-exception".to_owned(),
        },
    }
}

/// Returns an embedded strict Draft 2020-12 schema by public artifact name.
pub fn public_schema(name: &str) -> Option<&'static str> {
    match name {
        "execution-plane-descriptor-v1" => Some(include_str!(
            "../../../schemas/execution-planes/execution-plane-descriptor-v1.schema.json"
        )),
        "enterprise-connector-pack-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-connector-pack-v1.schema.json"
        )),
        "enterprise-connector-approval-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-connector-approval-v1.schema.json"
        )),
        "enterprise-operation-descriptor-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-operation-descriptor-v1.schema.json"
        )),
        "enterprise-endpoint-binding-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-endpoint-binding-v1.schema.json"
        )),
        "enterprise-credential-reference-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-credential-reference-v1.schema.json"
        )),
        "enterprise-observation-request-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-observation-request-v1.schema.json"
        )),
        "enterprise-observation-snapshot-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-observation-snapshot-v1.schema.json"
        )),
        "enterprise-operation-intent-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-operation-intent-v1.schema.json"
        )),
        "enterprise-operation-binding-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-operation-binding-v1.schema.json"
        )),
        "enterprise-operation-receipt-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-operation-receipt-v1.schema.json"
        )),
        "enterprise-post-action-verification-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-post-action-verification-v1.schema.json"
        )),
        "enterprise-network-policy-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-network-policy-v1.schema.json"
        )),
        "enterprise-idempotency-record-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-idempotency-record-v1.schema.json"
        )),
        "enterprise-connector-health-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-connector-health-v1.schema.json"
        )),
        "enterprise-replay-report-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-replay-report-v1.schema.json"
        )),
        "enterprise-api-completion-report-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-api-completion-report-v1.schema.json"
        )),
        "enterprise-api-certification-v1" => Some(include_str!(
            "../../../schemas/execution-planes/enterprise-api-certification-v1.schema.json"
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
