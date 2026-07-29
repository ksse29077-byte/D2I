use d2i_core::SemanticVersion;
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

/// Cognitive Module Contract v1.
pub const CONTRACT_VERSION_V1: u32 = 1;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_COLLECTION_ITEMS: usize = 1_024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_BYTES: usize = 8 * 1024 * 1024;

/// Stable module failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleErrorCode {
    InvalidInput,
    UnsupportedInput,
    UnsupportedCapability,
    SchemaMismatch,
    ContractVersionMismatch,
    Timeout,
    ResourceExhausted,
    PolicyProhibited,
    NetworkProhibited,
    UntrustedInputViolation,
    DeterministicReplayMismatch,
    InternalFailure,
    PanicOrAbnormalTermination,
    ArtifactMismatch,
    DependencyUnavailable,
}

/// Structured fail-closed module error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleError {
    pub code: ModuleErrorCode,
    pub retryable: bool,
    pub user_action_required: bool,
    pub message: String,
    pub redacted_detail: Option<String>,
    pub fallback_available: bool,
}

impl ModuleError {
    /// Creates a safe error without internal detail.
    #[must_use]
    pub fn new(code: ModuleErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            retryable: false,
            user_action_required: false,
            message: message.into(),
            redacted_detail: None,
            fallback_available: false,
        }
    }

    /// Marks whether the caller may retry.
    #[must_use]
    pub const fn retryable(mut self, value: bool) -> Self {
        self.retryable = value;
        self
    }

    /// Marks whether a user must act before continuing.
    #[must_use]
    pub const fn user_action_required(mut self, value: bool) -> Self {
        self.user_action_required = value;
        self
    }

    /// Adds bounded, redacted diagnostic detail.
    #[must_use]
    pub fn with_redacted_detail(mut self, value: impl Into<String>) -> Self {
        self.redacted_detail = Some(value.into());
        self
    }

    /// Marks whether a declared fallback exists.
    #[must_use]
    pub const fn fallback_available(mut self, value: bool) -> Self {
        self.fallback_available = value;
        self
    }

    /// Validates the error contract.
    pub fn validate(&self) -> Result<(), Self> {
        validate_text(&self.message, "module error message")?;
        if let Some(detail) = &self.redacted_detail {
            validate_text(detail, "module error redacted_detail")?;
        }
        Ok(())
    }
}

impl Display for ModuleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for ModuleError {}

/// Immutable identity bound to module and manifest artifacts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIdentifier {
    pub module_id: String,
    pub module_version: String,
    pub contract_version: u32,
    pub build_id: String,
    pub artifact_sha256: String,
    pub manifest_sha256: String,
}

impl ModuleIdentifier {
    /// Validates identifiers, semantic version, contract version, and hashes.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.module_id, "module_id")?;
        validate_identifier(&self.build_id, "build_id")?;
        SemanticVersion::from_str(&self.module_version).map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("invalid module_version: {error}"),
            )
        })?;
        validate_contract_version(self.contract_version)?;
        validate_sha256(&self.artifact_sha256, "artifact_sha256")?;
        validate_sha256(&self.manifest_sha256, "manifest_sha256")
    }
}

/// Extensible module category. Custom categories use the `x-` prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ModuleCategory(pub String);

impl ModuleCategory {
    /// Creates and validates a category.
    pub fn new(value: impl Into<String>) -> Result<Self, ModuleError> {
        let value = value.into();
        validate_identifier(&value, "module category")?;
        if !matches!(
            value.as_str(),
            "goal_compiler"
                | "observation_reducer"
                | "element_grounder"
                | "action_candidate_provider"
                | "plan_ranker"
                | "verifier"
                | "recovery_critic"
                | "work_reporter"
                | "knowledge_retriever"
                | "domain_evaluator"
                | "generic_transformation"
        ) && !value.starts_with("x-")
        {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "unknown module category must use the x- extension prefix",
            ));
        }
        Ok(Self(value))
    }

    /// Category text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates an existing category.
    pub fn validate(&self) -> Result<(), ModuleError> {
        Self::new(self.0.clone()).map(|_| ())
    }
}

/// Schema identity and repository-relative location.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaReference {
    pub schema_id: String,
    pub schema_version: u32,
    pub path: String,
    pub sha256: String,
}

impl SchemaReference {
    /// Validates schema identity, relative path, version, and hash.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.schema_id, "schema_id")?;
        if self.schema_version == 0 {
            return Err(ModuleError::new(
                ModuleErrorCode::SchemaMismatch,
                "schema_version must be greater than zero",
            ));
        }
        validate_relative_path(&self.path, "schema path")?;
        validate_sha256(&self.sha256, "schema sha256")
    }
}

/// Confidence interpretation declared by a capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceSemantics {
    Probability,
    CalibratedScore,
    RelativeRanking,
    NotApplicable,
}

/// Module network requirement. The default is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkRequirement {
    #[default]
    Denied,
    Required,
}

/// Reference and reserved module execution modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    InProcessRustReference,
    IsolatedProcessReference,
    FutureNativeAbi,
    FutureMojoWorker,
}

impl ExecutionMode {
    /// True only for the executable v1 reference mode.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::InProcessRustReference)
    }
}

/// One capability exported by a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleCapability {
    pub capability_id: String,
    pub capability_version: String,
    pub category: ModuleCategory,
    pub supported_input_kinds: Vec<String>,
    pub supported_output_kinds: Vec<String>,
    pub supported_risk_classes: Vec<String>,
    pub deterministic: bool,
    #[serde(default)]
    pub side_effect: bool,
    #[serde(default)]
    pub network_requirement: NetworkRequirement,
    pub streaming: bool,
    pub confidence_semantics: ConfidenceSemantics,
}

impl ModuleCapability {
    /// Validates capability identity and bounded declarations.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.capability_id, "capability_id")?;
        SemanticVersion::from_str(&self.capability_version).map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("invalid capability_version: {error}"),
            )
        })?;
        self.category.validate()?;
        validate_nonempty_identifiers(&self.supported_input_kinds, "supported_input_kinds")?;
        validate_nonempty_identifiers(&self.supported_output_kinds, "supported_output_kinds")?;
        validate_nonempty_identifiers(&self.supported_risk_classes, "supported_risk_classes")?;
        if self.side_effect {
            return Err(ModuleError::new(
                ModuleErrorCode::PolicyProhibited,
                "Cognitive Module Contract v1 reference modules cannot declare side effects",
            ));
        }
        if self.network_requirement != NetworkRequirement::Denied {
            return Err(ModuleError::new(
                ModuleErrorCode::NetworkProhibited,
                "Cognitive Module Contract v1 reference execution denies network access",
            ));
        }
        Ok(())
    }
}

/// Invocation resource limits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub memory_bytes: u64,
    pub logical_operation_budget: u64,
}

impl ResourceBudget {
    /// Validates nonzero bounded resources.
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.memory_bytes == 0
            || self.logical_operation_budget == 0
        {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "resource budget values must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Deterministic replay binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayContext {
    pub replay_id: String,
    pub seed: u64,
    pub fixture_hash: String,
}

impl ReplayContext {
    /// Validates replay identity and fixture binding.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.replay_id, "replay_id")?;
        validate_sha256(&self.fixture_hash, "fixture_hash")
    }
}

/// Redaction proof carried across a module boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionMarker {
    pub field: String,
    pub reason: String,
    pub replacement_sha256: String,
}

impl RedactionMarker {
    fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.field, "redaction field")?;
        validate_text(&self.reason, "redaction reason")?;
        validate_sha256(&self.replacement_sha256, "redaction replacement_sha256")
    }
}

/// Source trace for invocation and result values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleProvenance {
    pub source_id: String,
    pub source_sha256: String,
    pub producer: String,
}

impl ModuleProvenance {
    /// Validates provenance identity and source hash.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.source_id, "provenance source_id")?;
        validate_sha256(&self.source_sha256, "provenance source_sha256")?;
        validate_identifier(&self.producer, "provenance producer")
    }
}

/// Strict versioned module invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInvocationEnvelope {
    pub contract_version: u32,
    pub invocation_id: String,
    pub module: ModuleIdentifier,
    pub requested_capability: String,
    pub input_schema_id: String,
    pub input_schema_version: u32,
    pub payload: Value,
    pub goal_id: String,
    pub source_observation_hash: Option<String>,
    pub plan_generation_id: Option<String>,
    pub logical_sequence: u64,
    pub deadline_logical_tick: u64,
    pub resource_budget: ResourceBudget,
    pub trust_labels: BTreeSet<String>,
    pub redactions: Vec<RedactionMarker>,
    pub provenance: ModuleProvenance,
    pub replay: ReplayContext,
    pub correlation_id: String,
    pub trace_id: String,
}

impl ModuleInvocationEnvelope {
    /// Validates envelope shape and rejects raw secret fields.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_contract_version(self.contract_version)?;
        self.module.validate()?;
        validate_identifier(&self.invocation_id, "invocation_id")?;
        validate_identifier(&self.requested_capability, "requested_capability")?;
        validate_identifier(&self.input_schema_id, "input_schema_id")?;
        if self.input_schema_version == 0 {
            return Err(ModuleError::new(
                ModuleErrorCode::SchemaMismatch,
                "input_schema_version must be greater than zero",
            ));
        }
        validate_identifier(&self.goal_id, "goal_id")?;
        if let Some(hash) = &self.source_observation_hash {
            validate_sha256(hash, "source_observation_hash")?;
        }
        if let Some(generation) = &self.plan_generation_id {
            validate_identifier(generation, "plan_generation_id")?;
        }
        if self.deadline_logical_tick <= self.logical_sequence {
            return Err(ModuleError::new(
                ModuleErrorCode::Timeout,
                "module invocation deadline is expired",
            ));
        }
        self.resource_budget.validate()?;
        validate_nonempty_identifiers(
            &self.trust_labels.iter().cloned().collect::<Vec<_>>(),
            "trust_labels",
        )?;
        if self.redactions.len() > MAX_COLLECTION_ITEMS {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "too many redaction markers",
            ));
        }
        for marker in &self.redactions {
            marker.validate()?;
        }
        self.provenance.validate()?;
        self.replay.validate()?;
        validate_identifier(&self.correlation_id, "correlation_id")?;
        validate_identifier(&self.trace_id, "trace_id")?;
        reject_sensitive_fields(&self.payload, "input payload", false)?;
        validate_json_limits(&self.payload)?;
        let payload_size = canonical_json_bytes(&self.payload)?.len();
        let payload_size = u64::try_from(payload_size).map_err(|_| {
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "input payload size is not representable",
            )
        })?;
        if payload_size > self.resource_budget.max_input_bytes {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "input payload exceeds invocation byte budget",
            ));
        }
        Ok(())
    }
}

/// Module invocation terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleResultStatus {
    Succeeded,
    Unsupported,
    Failed,
}

/// Logical resources consumed by one invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub peak_memory_bytes: u64,
    pub logical_operations: u64,
}

/// Deterministic timing record without wall-clock entropy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimingRecord {
    pub phase: String,
    pub logical_tick: u64,
}

/// Replay metadata returned by a module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicReplayMetadata {
    pub replay_id: String,
    pub seed: u64,
    pub invocation_hash: String,
}

/// Strict versioned module result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleResultEnvelope {
    pub contract_version: u32,
    pub invocation_id: String,
    pub module: ModuleIdentifier,
    pub status: ModuleResultStatus,
    pub output_schema_id: String,
    pub output_schema_version: u32,
    pub payload: Option<Value>,
    pub confidence: Option<f64>,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
    pub unsupported_reason: Option<String>,
    pub error: Option<ModuleError>,
    pub resource_usage: ResourceUsage,
    pub timings: Vec<TimingRecord>,
    pub replay: DeterministicReplayMetadata,
    pub output_hash: String,
    pub provenance: ModuleProvenance,
}

impl ModuleResultEnvelope {
    /// Validates result invariants and output hash.
    pub fn validate(&self) -> Result<(), ModuleError> {
        validate_contract_version(self.contract_version)?;
        self.module.validate()?;
        validate_identifier(&self.invocation_id, "result invocation_id")?;
        validate_identifier(&self.output_schema_id, "output_schema_id")?;
        if self.output_schema_version == 0 {
            return Err(ModuleError::new(
                ModuleErrorCode::SchemaMismatch,
                "output_schema_version must be greater than zero",
            ));
        }
        if let Some(confidence) = self.confidence {
            if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
                return Err(ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "confidence must be finite and within 0..1",
                ));
            }
        }
        validate_text_collection(&self.evidence, "evidence")?;
        validate_text_collection(&self.warnings, "warnings")?;
        validate_identifier(&self.replay.replay_id, "result replay_id")?;
        validate_sha256(&self.replay.invocation_hash, "invocation_hash")?;
        self.provenance.validate()?;
        match self.status {
            ModuleResultStatus::Succeeded => {
                if self.payload.is_none()
                    || self.error.is_some()
                    || self.unsupported_reason.is_some()
                {
                    return Err(ModuleError::new(
                        ModuleErrorCode::InvalidInput,
                        "successful result requires payload and forbids error or unsupported_reason",
                    ));
                }
            }
            ModuleResultStatus::Unsupported => {
                if self.payload.is_some()
                    || self.error.is_some()
                    || self.unsupported_reason.is_none()
                {
                    return Err(ModuleError::new(
                        ModuleErrorCode::InvalidInput,
                        "unsupported result requires only unsupported_reason",
                    ));
                }
            }
            ModuleResultStatus::Failed => {
                if self.payload.is_some()
                    || self.error.is_none()
                    || self.unsupported_reason.is_some()
                {
                    return Err(ModuleError::new(
                        ModuleErrorCode::InvalidInput,
                        "failed result requires only a structured error",
                    ));
                }
            }
        }
        if let Some(reason) = &self.unsupported_reason {
            validate_text(reason, "unsupported_reason")?;
        }
        if let Some(error) = &self.error {
            error.validate()?;
        }
        if let Some(payload) = &self.payload {
            validate_json_limits(payload)?;
            reject_sensitive_fields(payload, "output payload", true)?;
        }
        validate_sha256(&self.output_hash, "output_hash")?;
        let expected_hash = result_payload_hash(
            self.status,
            self.payload.as_ref(),
            self.error.as_ref(),
            self.unsupported_reason.as_deref(),
        )?;
        if self.output_hash != expected_hash {
            return Err(ModuleError::new(
                ModuleErrorCode::DeterministicReplayMismatch,
                "result output_hash does not match canonical result content",
            ));
        }
        Ok(())
    }
}

/// Computes the canonical terminal-content hash used by result envelopes.
pub fn result_payload_hash(
    status: ModuleResultStatus,
    payload: Option<&Value>,
    error: Option<&ModuleError>,
    unsupported_reason: Option<&str>,
) -> Result<String, ModuleError> {
    canonical_sha256(&serde_json::json!({
        "status": status,
        "payload": payload,
        "error": error,
        "unsupported_reason": unsupported_reason
    }))
}

/// Serializes JSON with recursively sorted keys and no whitespace.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ModuleError> {
    let value = serde_json::to_value(value).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("cannot convert value to canonical JSON: {error}"),
        )
    })?;
    validate_json_limits(&value)?;
    let canonical = canonicalize_value(value);
    serde_json::to_vec(&canonical).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InternalFailure,
            format!("cannot serialize canonical JSON: {error}"),
        )
    })
}

/// Computes a canonical SHA-256 content hash.
pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, ModuleError> {
    let bytes = canonical_json_bytes(value)?;
    Ok(sha256_bytes(&bytes))
}

/// Parses strict JSON, rejecting duplicate keys and excessive nesting.
pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ModuleError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "JSON input exceeds maximum byte size",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer
        .deserialize_any(StrictValueVisitor)
        .map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("invalid strict JSON: {error}"),
            )
        })?;
    deserializer.end().map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("trailing JSON content: {error}"),
        )
    })?;
    validate_json_limits(&value)?;
    serde_json::from_value(value).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("JSON contract mismatch: {error}"),
        )
    })
}

fn canonicalize_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let ordered = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize_value(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.into_iter().map(canonicalize_value).collect()),
        other => other,
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate object key '{key}'"
                )));
            }
            let value = map.next_value_seed(StrictValueSeed)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

struct StrictValueSeed;

impl<'de> serde::de::DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

fn validate_json_limits(value: &Value) -> Result<(), ModuleError> {
    fn walk(value: &Value, depth: usize, count: &mut usize) -> Result<(), ModuleError> {
        if depth > MAX_JSON_DEPTH {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "JSON nesting exceeds maximum depth",
            ));
        }
        *count = count.saturating_add(1);
        if *count > MAX_COLLECTION_ITEMS.saturating_mul(16) {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "JSON value count exceeds maximum",
            ));
        }
        match value {
            Value::Array(items) => {
                if items.len() > MAX_COLLECTION_ITEMS {
                    return Err(ModuleError::new(
                        ModuleErrorCode::ResourceExhausted,
                        "JSON array exceeds maximum item count",
                    ));
                }
                for item in items {
                    walk(item, depth + 1, count)?;
                }
            }
            Value::Object(object) => {
                if object.len() > MAX_COLLECTION_ITEMS {
                    return Err(ModuleError::new(
                        ModuleErrorCode::ResourceExhausted,
                        "JSON object exceeds maximum field count",
                    ));
                }
                for (key, item) in object {
                    validate_text(key, "JSON object key")?;
                    walk(item, depth + 1, count)?;
                }
            }
            Value::String(text) => validate_text(text, "JSON string")?,
            _ => {}
        }
        Ok(())
    }
    walk(value, 0, &mut 0)
}

pub(crate) fn validate_contract_version(version: u32) -> Result<(), ModuleError> {
    if version != CONTRACT_VERSION_V1 {
        return Err(ModuleError::new(
            ModuleErrorCode::ContractVersionMismatch,
            format!("unsupported module contract version {version}"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_identifier(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must contain 1..={MAX_IDENTIFIER_BYTES} bytes"),
        ));
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must not be empty"),
        ));
    };
    if !first.is_ascii_alphanumeric()
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} is not a valid stable ASCII identifier"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_relative_path(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains(':')
        || value
            .split(['/', '\\'])
            .any(|part| part == ".." || part.is_empty())
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must be a normalized repository-relative path"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, field: &str) -> Result<(), ModuleError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ModuleError::new(
            ModuleErrorCode::ArtifactMismatch,
            format!("{field} must use sha256:<hex> form"),
        ));
    };
    if hex.len() != 64
        || !hex.chars().all(|ch| ch.is_ascii_hexdigit())
        || hex.chars().any(|ch| ch.is_ascii_uppercase())
    {
        return Err(ModuleError::new(
            ModuleErrorCode::ArtifactMismatch,
            format!("{field} must contain 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_text(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must be nonempty, bounded UTF-8 without NUL"),
        ));
    }
    Ok(())
}

fn validate_nonempty_identifiers(values: &[String], field: &str) -> Result<(), ModuleError> {
    if values.is_empty() || values.len() > MAX_COLLECTION_ITEMS {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must contain a bounded nonempty list"),
        ));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_identifier(value, field)?;
        if !unique.insert(value) {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("{field} contains a duplicate value"),
            ));
        }
    }
    Ok(())
}

fn validate_text_collection(values: &[String], field: &str) -> Result<(), ModuleError> {
    if values.len() > MAX_COLLECTION_ITEMS {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            format!("{field} exceeds maximum item count"),
        ));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

pub(crate) fn reject_sensitive_fields(
    value: &Value,
    field: &str,
    reject_secret_values: bool,
) -> Result<(), ModuleError> {
    reject_sensitive_fields_in(value, field, reject_secret_values, None)
}

fn reject_sensitive_fields_in(
    value: &Value,
    field: &str,
    reject_secret_values: bool,
    containing_object: Option<&str>,
) -> Result<(), ModuleError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized = key.to_ascii_lowercase();
                let prohibited_field = normalized == "password"
                    || normalized == "secret"
                    || normalized == "credential"
                    || normalized == "credentials"
                    || normalized == "raw_token"
                    || normalized == "authentication_token"
                    || normalized == "authorization";
                if prohibited_field && !is_credential_gate_status(containing_object, key, child) {
                    return Err(ModuleError::new(
                        ModuleErrorCode::InvalidInput,
                        format!("{field} contains prohibited raw secret field '{key}'"),
                    ));
                }
                reject_sensitive_fields_in(child, field, reject_secret_values, Some(key))?;
            }
        }
        Value::Array(items) => {
            for child in items {
                reject_sensitive_fields_in(child, field, reject_secret_values, None)?;
            }
        }
        Value::String(text)
            if reject_secret_values
                && (text.contains("-----BEGIN PRIVATE KEY-----")
                    || text.starts_with("Bearer ")
                    || (text.starts_with("AKIA")
                        && text.len() >= 20
                        && text.chars().all(|ch| ch.is_ascii_alphanumeric()))) =>
        {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("{field} contains a prohibited raw credential value"),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn is_credential_gate_status(containing_object: Option<&str>, key: &str, value: &Value) -> bool {
    containing_object == Some("gate_results")
        && key == "credential"
        && value
            .as_str()
            .is_some_and(|status| matches!(status, "passed" | "failed" | "unknown"))
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::reject_sensitive_fields;
    use serde_json::json;

    #[test]
    fn output_scan_allows_only_bounded_credential_gate_status() {
        let status = json!({
            "results": [{
                "gate_results": {
                    "credential": "failed"
                }
            }]
        });
        assert!(reject_sensitive_fields(&status, "output payload", true).is_ok());

        let raw_token = json!({"message": "Bearer must-not-cross"});
        assert!(reject_sensitive_fields(&raw_token, "output payload", true).is_err());

        let credential = json!({
            "gate_results": {
                "credential": "must-not-cross"
            }
        });
        assert!(reject_sensitive_fields(&credential, "output payload", true).is_err());
    }
}
