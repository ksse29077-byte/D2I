//! Reference-only episodic memory contracts for terminal Workforce Cases.
//!
//! The crate is platform-neutral. It cannot mutate a Case, grant authority,
//! invoke a provider, activate a capability, or execute an adapter.

mod contracts;

pub use contracts::*;
pub use d2i_role_contract::CrossCaseReusePolicyV1;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};

pub const EPISODIC_MEMORY_SCHEMA_VERSION: u32 = 1;
pub const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_EVENTS_PER_EPISODE: usize = 512;
pub const MAX_ARTIFACT_REFERENCES: usize = 512;
pub const MAX_EVIDENCE_IDS: usize = 256;
pub const MAX_DATA_CLASS_IDS: usize = 128;
pub const MAX_SUMMARIES_PER_EPISODE: usize = 1;
pub const MAX_SUMMARY_BYTES: usize = 2_048;
pub const MAX_EPISODE_BYTES: usize = 1024 * 1024;
pub const MAX_EPISODES_PER_NAMESPACE: u32 = 10_000;
pub const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_QUERY_RESULTS: u32 = 128;
pub const MAX_QUERY_FILTERS: usize = 128;
pub const MAX_RETENTION_DAYS: u32 = 3_650;
pub const MAX_LEGAL_HOLDS: usize = 128;
pub const MAX_TOMBSTONES: usize = 10_000;
pub const MAX_LEDGER_RECORDS: usize = 50_000;
pub const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_REPLAY_RECORDS: usize = 50_000;
pub const MAX_CONCURRENT_STORE_COORDINATORS: usize = 1;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub const EPISODE_MEMORY_NAMESPACE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-memory-namespace-v1.schema.json");
pub const MEMORY_NAMESPACE_APPROVAL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/memory-namespace-approval-v1.schema.json");
pub const CASE_EPISODE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-episode-v1.schema.json");
pub const EPISODE_EVENT_REFERENCE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-event-reference-v1.schema.json");
pub const EPISODE_SEAL_REQUEST_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-seal-request-v1.schema.json");
pub const EPISODE_SEAL_DECISION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-seal-decision-v1.schema.json");
pub const EPISODE_SEAL_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-seal-receipt-v1.schema.json");
pub const EPISODE_INDEX_ENTRY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-index-entry-v1.schema.json");
pub const APPROVED_EPISODE_SUMMARY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/approved-episode-summary-v1.schema.json");
pub const EPISODE_MEMORY_QUERY_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-memory-query-v1.schema.json");
pub const EPISODE_MEMORY_QUERY_RESULT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-memory-query-result-v1.schema.json");
pub const EPISODE_QUERY_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-query-receipt-v1.schema.json");
pub const MEMORY_AUGMENTED_CASE_CONTEXT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/memory-augmented-case-context-v1.schema.json");
pub const MEMORY_USE_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/memory-use-receipt-v1.schema.json");
pub const EPISODE_RETENTION_RECORD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-retention-record-v1.schema.json");
pub const EPISODE_TOMBSTONE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-tombstone-v1.schema.json");
pub const EPISODE_LEGAL_HOLD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-legal-hold-v1.schema.json");
pub const EPISODE_PURGE_RECEIPT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episode-purge-receipt-v1.schema.json");
pub const EPISODIC_MEMORY_REPLAY_REPORT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/episodic-memory-replay-report-v1.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpisodicMemoryError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    SensitiveContent(String),
    ResourceLimit(String),
    Duplicate(String),
    Json(String),
}

impl Display for EpisodicMemoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::SensitiveContent(message) => ("sensitive_content", message),
            Self::ResourceLimit(message) => ("resource_limit", message),
            Self::Duplicate(message) => ("duplicate", message),
            Self::Json(message) => ("json", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for EpisodicMemoryError {}

#[derive(Debug)]
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
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
            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
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
            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                StrictValue::deserialize(deserializer)
            }
            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = access.next_entry::<String, StrictValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON object key: {key}"
                        )));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, EpisodicMemoryError> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
        return Err(EpisodicMemoryError::ResourceLimit(
            "JSON input is empty or exceeds 2 MiB".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?;
    serde_json::from_value(value.0).map_err(|error| EpisodicMemoryError::Json(error.to_string()))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut output = Map::new();
            for (key, value) in entries {
                output.insert(key.clone(), canonicalize(value));
            }
            Value::Object(output)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EpisodicMemoryError> {
    let value = serde_json::to_value(value)
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?;
    serde_json::to_vec(&canonicalize(&value))
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, EpisodicMemoryError> {
    Ok(sha256_bytes(&canonical_json_bytes(value)?))
}

pub fn hash_without<T: Serialize>(
    value: &T,
    omitted_fields: &[&str],
) -> Result<String, EpisodicMemoryError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        EpisodicMemoryError::Invalid("hash input must be a JSON object".to_owned())
    })?;
    for field in omitted_fields {
        object.remove(*field);
    }
    Ok(sha256_bytes(
        &serde_json::to_vec(&canonicalize(&value))
            .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?,
    ))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

pub fn validate_hash(value: &str, field: &str) -> Result<(), EpisodicMemoryError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(EpisodicMemoryError::Invalid(format!(
            "{field} must use sha256:<lowercase-hex>"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EpisodicMemoryError::Invalid(format!(
            "{field} is not a lowercase SHA-256"
        )));
    }
    Ok(())
}

pub fn validate_id(value: &str, field: &str) -> Result<(), EpisodicMemoryError> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(EpisodicMemoryError::Invalid(format!(
            "{field} is empty, too long, or contains unsupported characters"
        )));
    }
    Ok(())
}

pub fn validate_ids(
    values: &[String],
    maximum: usize,
    field: &str,
) -> Result<(), EpisodicMemoryError> {
    if values.len() > maximum {
        return Err(EpisodicMemoryError::ResourceLimit(format!(
            "{field} exceeds {maximum} entries"
        )));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(value, field)?;
        if !seen.insert(value) {
            return Err(EpisodicMemoryError::Invalid(format!(
                "{field} contains a duplicate"
            )));
        }
    }
    Ok(())
}

pub fn reject_sensitive_value<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<(), EpisodicMemoryError> {
    let encoded = String::from_utf8(canonical_json_bytes(value)?).map_err(|error| {
        EpisodicMemoryError::Json(format!("{label} is not UTF-8 JSON: {error}"))
    })?;
    let lowered = encoded.to_ascii_lowercase();
    const FORBIDDEN: &[&str] = &[
        "password",
        "credential",
        "api_key",
        "api-key",
        "bearer ",
        "authorization",
        "private key",
        "raw locator",
        "css selector",
        "automationid",
        "screen coordinate",
        "raw ui payload",
        "clipboard content",
        "chain-of-thought",
        "chain_of_thought",
    ];
    if let Some(marker) = FORBIDDEN.iter().find(|marker| lowered.contains(**marker)) {
        return Err(EpisodicMemoryError::SensitiveContent(format!(
            "{label} contains prohibited marker {marker}"
        )));
    }
    Ok(())
}

fn sorted_unique(
    values: &mut Vec<String>,
    maximum: usize,
    field: &str,
) -> Result<(), EpisodicMemoryError> {
    values.sort();
    values.dedup();
    validate_ids(values, maximum, field)
}

impl EpisodeMemoryNamespaceV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        sorted_unique(&mut self.role_instance_scope, 128, "role_instance_scope")?;
        sorted_unique(
            &mut self.allowed_work_class_ids,
            128,
            "allowed_work_class_ids",
        )?;
        sorted_unique(
            &mut self.allowed_responsibility_ids,
            128,
            "allowed_responsibility_ids",
        )?;
        sorted_unique(
            &mut self.allowed_data_class_ids,
            MAX_DATA_CLASS_IDS,
            "allowed_data_class_ids",
        )?;
        sorted_unique(
            &mut self.prohibited_data_class_ids,
            MAX_DATA_CLASS_IDS,
            "prohibited_data_class_ids",
        )?;
        sorted_unique(&mut self.evidence_ids, MAX_EVIDENCE_IDS, "evidence_ids")?;
        self.namespace_sha256 = hash_without(&self, &["namespace_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), EpisodicMemoryError> {
        if self.schema_version != EPISODIC_MEMORY_SCHEMA_VERSION {
            return Err(EpisodicMemoryError::Invalid(
                "unsupported namespace schema".to_owned(),
            ));
        }
        for (field, value) in [
            ("namespace_id", self.namespace_id.as_str()),
            ("organization_id", self.organization_id.as_str()),
            ("role_contract_id", self.role_contract_id.as_str()),
            ("retention_class_id", self.retention_class_id.as_str()),
        ] {
            validate_id(value, field)?;
        }
        for (field, value) in [
            ("role_contract_sha256", self.role_contract_sha256.as_str()),
            (
                "memory_boundary_sha256",
                self.memory_boundary_sha256.as_str(),
            ),
            ("namespace_sha256", self.namespace_sha256.as_str()),
        ] {
            validate_hash(value, field)?;
        }
        if self.maximum_retention_days == 0 || self.maximum_retention_days > MAX_RETENTION_DAYS {
            return Err(EpisodicMemoryError::ResourceLimit(
                "retention must be finite and bounded".to_owned(),
            ));
        }
        if self.maximum_episodes == 0
            || self.maximum_episodes > MAX_EPISODES_PER_NAMESPACE
            || self.maximum_store_bytes == 0
            || self.maximum_store_bytes > MAX_STORE_BYTES
            || self.maximum_query_results == 0
            || self.maximum_query_results > MAX_QUERY_RESULTS
        {
            return Err(EpisodicMemoryError::ResourceLimit(
                "namespace limits are outside v1 bounds".to_owned(),
            ));
        }
        if self.valid_from_unix_ms == 0 || self.valid_from_unix_ms >= self.valid_to_unix_ms {
            return Err(EpisodicMemoryError::Invalid(
                "namespace validity interval is invalid".to_owned(),
            ));
        }
        let prohibited = self
            .prohibited_data_class_ids
            .iter()
            .collect::<BTreeSet<_>>();
        if self
            .allowed_data_class_ids
            .iter()
            .any(|id| prohibited.contains(id))
        {
            return Err(EpisodicMemoryError::Invalid(
                "data class cannot be both allowed and prohibited".to_owned(),
            ));
        }
        if hash_without(self, &["namespace_sha256"])? != self.namespace_sha256 {
            return Err(EpisodicMemoryError::Integrity(
                "namespace hash mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

fn signing_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, EpisodicMemoryError> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            EpisodicMemoryError::Invalid("signed artifact must be an object".to_owned())
        })?
        .remove("signature_hex");
    serde_json::to_vec(&canonicalize(&value))
        .map_err(|error| EpisodicMemoryError::Json(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_signature(value: &str) -> Result<Signature, EpisodicMemoryError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(EpisodicMemoryError::Unauthorized(
            "signature is not 64-byte hex".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 64];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| EpisodicMemoryError::Unauthorized(error.to_string()))?;
    }
    Ok(Signature::from_bytes(&bytes))
}

pub fn sign_namespace_approval(
    approval: &mut MemoryNamespaceApprovalV1,
    signing_key: &SigningKey,
) -> Result<(), EpisodicMemoryError> {
    approval.signature_hex.clear();
    approval.signature_hex = hex_encode(&signing_key.sign(&signing_bytes(approval)?).to_bytes());
    Ok(())
}

pub fn verify_namespace_approval(
    approval: &MemoryNamespaceApprovalV1,
    namespace: &EpisodeMemoryNamespaceV1,
    verifying_key: &VerifyingKey,
    trusted_now_unix_ms: u64,
) -> Result<(), EpisodicMemoryError> {
    if approval.schema_version != EPISODIC_MEMORY_SCHEMA_VERSION
        || approval.namespace_sha256 != namespace.namespace_sha256
        || approval.organization_id != namespace.organization_id
    {
        return Err(EpisodicMemoryError::Unauthorized(
            "namespace approval binding mismatch".to_owned(),
        ));
    }
    if trusted_now_unix_ms < approval.issued_at_unix_ms
        || trusted_now_unix_ms >= approval.expires_at_unix_ms
    {
        return Err(EpisodicMemoryError::Stale(
            "namespace approval is not current".to_owned(),
        ));
    }
    validate_id(&approval.nonce, "nonce")?;
    verifying_key
        .verify(
            &signing_bytes(approval)?,
            &decode_signature(&approval.signature_hex)?,
        )
        .map_err(|error| {
            EpisodicMemoryError::Unauthorized(format!(
                "namespace approval signature failed: {error}"
            ))
        })
}

impl EpisodeEventReferenceV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        self.evidence_ids.sort();
        self.event_reference_sha256 = hash_without(&self, &["event_reference_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), EpisodicMemoryError> {
        if self.schema_version != 1
            || self.event_sequence == 0
            || self.occurred_at_unix_ms == 0
            || self.source_ledger_sequence == 0
        {
            return Err(EpisodicMemoryError::Invalid(
                "event reference version, sequence, or time is invalid".to_owned(),
            ));
        }
        validate_hash(&self.source_ledger_head_sha256, "source_ledger_head_sha256")?;
        validate_hash(&self.source_artifact_sha256, "source_artifact_sha256")?;
        if hash_without(self, &["event_reference_sha256"])? != self.event_reference_sha256 {
            return Err(EpisodicMemoryError::Integrity(
                "event reference hash mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn derive_episode_id(
    case_id: &str,
    terminal_record_sha256: &str,
) -> Result<String, EpisodicMemoryError> {
    validate_id(case_id, "case_id")?;
    validate_hash(terminal_record_sha256, "terminal_record_sha256")?;
    let digest = sha256_bytes(
        format!("d2i-case-episode-v1\0{case_id}\0{terminal_record_sha256}").as_bytes(),
    );
    Ok(format!("episode-{}", &digest[7..31]))
}

impl CaseEpisodeV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        for values in [
            &mut self.application_pack_ids,
            &mut self.integration_ids,
            &mut self.capability_ids,
            &mut self.semantic_target_ids,
            &mut self.blocker_class_ids,
            &mut self.clarification_reason_codes,
            &mut self.escalation_reason_codes,
            &mut self.data_class_ids,
            &mut self.redaction_proof_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
            values.dedup();
        }
        for values in [
            &mut self.provider_descriptor_hashes,
            &mut self.provider_invocation_hashes,
            &mut self.provider_result_hashes,
            &mut self.situation_generation_hashes,
            &mut self.plan_generation_hashes,
            &mut self.kernel_run_hashes,
            &mut self.verified_action_hashes,
            &mut self.verification_result_hashes,
            &mut self.recovery_result_hashes,
        ] {
            values.sort();
            values.dedup();
        }
        self.canonical_episode_sha256 = hash_without(&self, &["canonical_episode_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), EpisodicMemoryError> {
        if self.schema_version != 1 || self.episode_generation != 1 {
            return Err(EpisodicMemoryError::Invalid(
                "Episode version or generation is unsupported".to_owned(),
            ));
        }
        if self.opened_at_unix_ms == 0 || self.opened_at_unix_ms > self.terminal_at_unix_ms {
            return Err(EpisodicMemoryError::Invalid(
                "Episode time interval is invalid".to_owned(),
            ));
        }
        if self.event_references.is_empty() || self.event_references.len() > MAX_EVENTS_PER_EPISODE
        {
            return Err(EpisodicMemoryError::ResourceLimit(
                "Episode event count is outside bounds".to_owned(),
            ));
        }
        let mut previous_time = 0;
        for (index, event) in self.event_references.iter().enumerate() {
            event.validate()?;
            if event.event_sequence as usize != index + 1
                || event.occurred_at_unix_ms < previous_time
            {
                return Err(EpisodicMemoryError::Integrity(
                    "Episode event sequence has a gap or time rollback".to_owned(),
                ));
            }
            previous_time = event.occurred_at_unix_ms;
        }
        if self.event_references.last().map(|event| event.event_kind)
            != Some(EpisodeEventKindV1::AuditTerminal)
            || !self
                .event_references
                .iter()
                .any(|event| event.event_kind == EpisodeEventKindV1::CaseTerminal)
        {
            return Err(EpisodicMemoryError::Integrity(
                "Episode lacks terminal Case or audit reference".to_owned(),
            ));
        }
        let expected_id = derive_episode_id(&self.case_id, &self.final_case_instance_sha256)?;
        if expected_id != self.episode_id {
            return Err(EpisodicMemoryError::Integrity(
                "Episode ID is not deterministically derived".to_owned(),
            ));
        }
        for hash in episode_hashes(self) {
            validate_hash(hash, "Episode hash field")?;
        }
        validate_ids(&self.data_class_ids, MAX_DATA_CLASS_IDS, "data_class_ids")?;
        validate_ids(&self.evidence_ids, MAX_EVIDENCE_IDS, "evidence_ids")?;
        reject_sensitive_value(self, "Episode")?;
        if canonical_json_bytes(self)?.len() > MAX_EPISODE_BYTES {
            return Err(EpisodicMemoryError::ResourceLimit(
                "Episode exceeds 1 MiB".to_owned(),
            ));
        }
        if hash_without(self, &["canonical_episode_sha256"])? != self.canonical_episode_sha256 {
            return Err(EpisodicMemoryError::Integrity(
                "Episode canonical hash mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

fn episode_hashes(episode: &CaseEpisodeV1) -> Vec<&str> {
    let mut hashes = vec![
        episode.memory_namespace_sha256.as_str(),
        episode.role_contract_sha256.as_str(),
        episode.role_instance_sha256.as_str(),
        episode.delegation_sha256.as_str(),
        episode.memory_boundary_sha256.as_str(),
        episode.case_contract_sha256.as_str(),
        episode.final_case_instance_sha256.as_str(),
        episode.work_item_sha256.as_str(),
        episode.intake_receipt_sha256.as_str(),
        episode.queue_ownership_terminal_sha256.as_str(),
        episode.terminal_evidence_index_sha256.as_str(),
        episode.protected_audit_terminal_sha256.as_str(),
        episode.retention_record_sha256.as_str(),
        episode.canonical_episode_sha256.as_str(),
    ];
    if let Some(hash) = &episode.case_work_grant_sha256 {
        hashes.push(hash);
    }
    if let Some(hash) = &episode.approved_summary_sha256 {
        hashes.push(hash);
    }
    hashes.extend(
        episode
            .provider_descriptor_hashes
            .iter()
            .map(String::as_str),
    );
    hashes.extend(
        episode
            .provider_invocation_hashes
            .iter()
            .map(String::as_str),
    );
    hashes.extend(episode.provider_result_hashes.iter().map(String::as_str));
    hashes.extend(
        episode
            .situation_generation_hashes
            .iter()
            .map(String::as_str),
    );
    hashes.extend(episode.plan_generation_hashes.iter().map(String::as_str));
    hashes.extend(episode.kernel_run_hashes.iter().map(String::as_str));
    hashes.extend(episode.verified_action_hashes.iter().map(String::as_str));
    hashes.extend(
        episode
            .verification_result_hashes
            .iter()
            .map(String::as_str),
    );
    hashes.extend(episode.recovery_result_hashes.iter().map(String::as_str));
    hashes
}

pub fn seal_episode(
    request: &EpisodeSealRequestV1,
    verifying_key: &VerifyingKey,
) -> Result<(CaseEpisodeV1, EpisodeSealDecisionV1, EpisodeSealReceiptV1), EpisodicMemoryError> {
    if request.schema_version != 1
        || !request.terminal_record_present
        || !request.source_references_resolvable
    {
        return Err(EpisodicMemoryError::Invalid(
            "only a resolvable terminal Case may be sealed".to_owned(),
        ));
    }
    request.namespace.validate()?;
    verify_namespace_approval(
        &request.namespace_approval,
        &request.namespace,
        verifying_key,
        request.trusted_now_unix_ms,
    )?;
    let episode = request.episode.clone().seal()?;
    validate_episode_namespace(&episode, &request.namespace, request.trusted_now_unix_ms)?;
    if request.authoritative_heads.len() < 6 || request.authoritative_heads.len() > 16 {
        return Err(EpisodicMemoryError::ResourceLimit(
            "authoritative head set is incomplete or oversized".to_owned(),
        ));
    }
    let mut classes = BTreeSet::new();
    for head in &request.authoritative_heads {
        if !classes.insert(head.source_ledger_class) {
            return Err(EpisodicMemoryError::Integrity(
                "duplicate authoritative ledger class".to_owned(),
            ));
        }
        if head.expected_sequence != head.current_sequence
            || head.expected_head_sha256 != head.current_head_sha256
        {
            return Err(EpisodicMemoryError::Stale(
                "authoritative ledger head changed before sealing".to_owned(),
            ));
        }
        validate_hash(&head.current_head_sha256, "current_head_sha256")?;
    }
    let required = [
        SourceLedgerClassV1::Role,
        SourceLedgerClassV1::Intake,
        SourceLedgerClassV1::Case,
        SourceLedgerClassV1::QueueOwnership,
        SourceLedgerClassV1::Planner,
        SourceLedgerClassV1::ProtectedAudit,
    ];
    if required.iter().any(|class| !classes.contains(class)) {
        return Err(EpisodicMemoryError::Integrity(
            "required authoritative ledger head is missing".to_owned(),
        ));
    }
    let status = match request.existing_episode_sha256.as_deref() {
        Some(existing) if existing == episode.canonical_episode_sha256 => {
            EpisodeSealStatusV1::ExactDuplicate
        }
        Some(_) => {
            return Err(EpisodicMemoryError::Duplicate(
                "Case ID already has different terminal semantics".to_owned(),
            ))
        }
        None => EpisodeSealStatusV1::Sealed,
    };
    let heads_sha256 = canonical_sha256(&request.authoritative_heads)?;
    let mut decision = EpisodeSealDecisionV1 {
        schema_version: 1,
        request_id: request.request_id.clone(),
        status,
        failure_code: EpisodeSealFailureCodeV1::None,
        episode_id: episode.episode_id.clone(),
        episode_sha256: episode.canonical_episode_sha256.clone(),
        authoritative_heads_sha256: heads_sha256.clone(),
        decision_sha256: ZERO_HASH.to_owned(),
    };
    decision.decision_sha256 = hash_without(&decision, &["decision_sha256"])?;
    let mut receipt = EpisodeSealReceiptV1 {
        schema_version: 1,
        request_id: request.request_id.clone(),
        episode_id: episode.episode_id.clone(),
        episode_sha256: episode.canonical_episode_sha256.clone(),
        namespace_sha256: request.namespace.namespace_sha256.clone(),
        decision_sha256: decision.decision_sha256.clone(),
        sealed_at_unix_ms: request.trusted_now_unix_ms,
        source_ledger_heads_sha256: heads_sha256,
        receipt_sha256: ZERO_HASH.to_owned(),
    };
    receipt.receipt_sha256 = hash_without(&receipt, &["receipt_sha256"])?;
    Ok((episode, decision, receipt))
}

fn validate_episode_namespace(
    episode: &CaseEpisodeV1,
    namespace: &EpisodeMemoryNamespaceV1,
    trusted_now_unix_ms: u64,
) -> Result<(), EpisodicMemoryError> {
    if episode.organization_id != namespace.organization_id
        || episode.memory_namespace_id != namespace.namespace_id
        || episode.memory_namespace_sha256 != namespace.namespace_sha256
        || episode.role_contract_sha256 != namespace.role_contract_sha256
        || episode.memory_boundary_sha256 != namespace.memory_boundary_sha256
    {
        return Err(EpisodicMemoryError::Unauthorized(
            "Episode namespace binding mismatch".to_owned(),
        ));
    }
    if trusted_now_unix_ms < namespace.valid_from_unix_ms
        || trusted_now_unix_ms >= namespace.valid_to_unix_ms
    {
        return Err(EpisodicMemoryError::Stale(
            "memory namespace is not current".to_owned(),
        ));
    }
    if !namespace
        .allowed_work_class_ids
        .contains(&episode.work_class_id)
        || !namespace
            .allowed_responsibility_ids
            .contains(&episode.responsibility_id)
    {
        return Err(EpisodicMemoryError::Unauthorized(
            "Episode work class or responsibility is outside namespace".to_owned(),
        ));
    }
    let prohibited = namespace
        .prohibited_data_class_ids
        .iter()
        .collect::<BTreeSet<_>>();
    if episode
        .data_class_ids
        .iter()
        .any(|class| prohibited.contains(class))
    {
        return Err(EpisodicMemoryError::SensitiveContent(
            "Episode contains a prohibited data class".to_owned(),
        ));
    }
    Ok(())
}

impl ApprovedEpisodeSummaryV1 {
    pub fn seal_and_sign(mut self, signing_key: &SigningKey) -> Result<Self, EpisodicMemoryError> {
        for values in [
            &mut self.situation_class_ids,
            &mut self.completed_subgoal_ids,
            &mut self.recovery_class_ids,
            &mut self.clarification_reason_codes,
            &mut self.escalation_reason_codes,
            &mut self.semantic_target_ids,
            &mut self.capability_ids,
            &mut self.verified_outcome_class_ids,
            &mut self.data_class_ids,
            &mut self.redaction_proof_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
            values.dedup();
        }
        self.signature_hex.clear();
        self.summary_sha256 = hash_without(&self, &["summary_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&signing_key.sign(&signing_bytes(&self)?).to_bytes());
        self.validate(&signing_key.verifying_key(), self.valid_from_unix_ms)?;
        Ok(self)
    }

    pub fn validate(
        &self,
        verifying_key: &VerifyingKey,
        trusted_now_unix_ms: u64,
    ) -> Result<(), EpisodicMemoryError> {
        if self.schema_version != 1
            || self.summary_generation == 0
            || self.concise_summary.is_empty()
            || self.concise_summary.len() > MAX_SUMMARY_BYTES
        {
            return Err(EpisodicMemoryError::ResourceLimit(
                "approved summary fields exceed v1 bounds".to_owned(),
            ));
        }
        if trusted_now_unix_ms < self.valid_from_unix_ms
            || trusted_now_unix_ms >= self.valid_to_unix_ms
        {
            return Err(EpisodicMemoryError::Stale(
                "approved summary is not current".to_owned(),
            ));
        }
        reject_sensitive_value(self, "approved summary")?;
        let lowered = self.concise_summary.to_ascii_lowercase();
        if [
            "ignore current",
            "execute ",
            "click ",
            "type ",
            "invoke ",
            "must follow",
        ]
        .iter()
        .any(|marker| lowered.contains(marker))
        {
            return Err(EpisodicMemoryError::Unauthorized(
                "instruction-like historical summary is prohibited".to_owned(),
            ));
        }
        if hash_without(self, &["summary_sha256", "signature_hex"])? != self.summary_sha256 {
            return Err(EpisodicMemoryError::Integrity(
                "approved summary hash mismatch".to_owned(),
            ));
        }
        verifying_key
            .verify(
                &signing_bytes(self)?,
                &decode_signature(&self.signature_hex)?,
            )
            .map_err(|error| {
                EpisodicMemoryError::Unauthorized(format!(
                    "approved summary signature failed: {error}"
                ))
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInputsV1<'a> {
    pub query: &'a EpisodeMemoryQueryV1,
    pub namespace: &'a EpisodeMemoryNamespaceV1,
    pub episodes: &'a [CaseEpisodeV1],
    pub summaries_by_episode: &'a BTreeMap<String, ApprovedEpisodeSummaryV1>,
    pub tombstoned_episode_hashes: &'a BTreeSet<String>,
    pub summary_verifying_key: &'a VerifyingKey,
    pub trusted_now_unix_ms: u64,
}

pub fn execute_exact_query(
    inputs: QueryInputsV1<'_>,
) -> Result<(EpisodeMemoryQueryResultV1, EpisodeQueryReceiptV1), EpisodicMemoryError> {
    validate_query(inputs.query, inputs.namespace, inputs.trusted_now_unix_ms)?;
    let effective_policy = narrow_policy(
        inputs.namespace.cross_case_reuse_policy,
        inputs.query.requested_policy,
    );
    let mut entries = Vec::new();
    let mut summaries = Vec::new();
    let mut denied = Vec::new();
    if effective_policy == CrossCaseReusePolicyV1::Forbidden {
        denied.push("reuse_forbidden".to_owned());
    } else {
        for episode in inputs.episodes {
            episode.validate()?;
            if matches_query(episode, inputs.query)
                && !inputs
                    .tombstoned_episode_hashes
                    .contains(&episode.canonical_episode_sha256)
            {
                let summary = inputs
                    .summaries_by_episode
                    .get(&episode.canonical_episode_sha256);
                if effective_policy == CrossCaseReusePolicyV1::ApprovedSummaryOnly {
                    let Some(summary) = summary else { continue };
                    summary.validate(inputs.summary_verifying_key, inputs.trusted_now_unix_ms)?;
                    if summary.organization_id != inputs.query.organization_id
                        || summary.namespace_sha256 != inputs.namespace.namespace_sha256
                        || summary.role_contract_sha256 != inputs.query.current_role_contract_sha256
                        || summary.episode_sha256 != episode.canonical_episode_sha256
                    {
                        continue;
                    }
                    summaries.push(summary.clone());
                }
                entries.push(index_entry(
                    episode,
                    summary.map(|value| value.summary_sha256.clone()),
                )?);
            }
        }
        entries.sort_by(|left, right| {
            right
                .terminal_at_unix_ms
                .cmp(&left.terminal_at_unix_ms)
                .then_with(|| left.episode_id.cmp(&right.episode_id))
                .then_with(|| left.episode_sha256.cmp(&right.episode_sha256))
        });
        entries.truncate(inputs.query.maximum_results as usize);
        let allowed = entries
            .iter()
            .map(|entry| entry.episode_sha256.as_str())
            .collect::<BTreeSet<_>>();
        summaries.retain(|summary| allowed.contains(summary.episode_sha256.as_str()));
        summaries.sort_by(|left, right| left.episode_sha256.cmp(&right.episode_sha256));
    }
    let mut result = EpisodeMemoryQueryResultV1 {
        schema_version: 1,
        query_sha256: inputs.query.query_sha256.clone(),
        reuse_policy: effective_policy,
        historical_trust_class: HistoricalTrustClassV1::HistoricalNonAuthoritative,
        episode_references: entries,
        approved_summaries: summaries,
        denied_reason_codes: denied,
        result_sha256: ZERO_HASH.to_owned(),
    };
    result.result_sha256 = hash_without(&result, &["result_sha256"])?;
    let mut receipt = EpisodeQueryReceiptV1 {
        schema_version: 1,
        query_sha256: inputs.query.query_sha256.clone(),
        result_sha256: result.result_sha256.clone(),
        namespace_sha256: inputs.namespace.namespace_sha256.clone(),
        reuse_policy: effective_policy,
        returned_episode_count: result.episode_references.len() as u32,
        returned_summary_count: result.approved_summaries.len() as u32,
        denied: effective_policy == CrossCaseReusePolicyV1::Forbidden,
        completed_at_unix_ms: inputs.trusted_now_unix_ms,
        receipt_sha256: ZERO_HASH.to_owned(),
    };
    receipt.receipt_sha256 = hash_without(&receipt, &["receipt_sha256"])?;
    Ok((result, receipt))
}

fn narrow_policy(
    left: CrossCaseReusePolicyV1,
    right: CrossCaseReusePolicyV1,
) -> CrossCaseReusePolicyV1 {
    fn rank(value: CrossCaseReusePolicyV1) -> u8 {
        match value {
            CrossCaseReusePolicyV1::Forbidden => 0,
            CrossCaseReusePolicyV1::HashReferenceOnly => 1,
            CrossCaseReusePolicyV1::ApprovedSummaryOnly => 2,
        }
    }
    if rank(left) <= rank(right) {
        left
    } else {
        right
    }
}

fn validate_query(
    query: &EpisodeMemoryQueryV1,
    namespace: &EpisodeMemoryNamespaceV1,
    now: u64,
) -> Result<(), EpisodicMemoryError> {
    if query.schema_version != 1
        || query.organization_id != namespace.organization_id
        || query.namespace_id != namespace.namespace_id
        || query.namespace_sha256 != namespace.namespace_sha256
    {
        return Err(EpisodicMemoryError::Unauthorized(
            "query namespace or organization mismatch".to_owned(),
        ));
    }
    if now < query.issued_at_unix_ms || now >= query.expires_at_unix_ms {
        return Err(EpisodicMemoryError::Stale(
            "query is expired or not yet valid".to_owned(),
        ));
    }
    if query.maximum_results == 0
        || query.maximum_results > namespace.maximum_query_results
        || query.maximum_results > MAX_QUERY_RESULTS
    {
        return Err(EpisodicMemoryError::ResourceLimit(
            "query result limit is invalid".to_owned(),
        ));
    }
    if hash_without(query, &["query_sha256"])? != query.query_sha256 {
        return Err(EpisodicMemoryError::Integrity(
            "query hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn matches_query(episode: &CaseEpisodeV1, query: &EpisodeMemoryQueryV1) -> bool {
    let filters = &query.filters;
    episode.organization_id == query.organization_id
        && episode.memory_namespace_id == query.namespace_id
        && filters
            .role_contract_sha256
            .as_ref()
            .is_none_or(|value| value == &episode.role_contract_sha256)
        && filters
            .work_class_id
            .as_ref()
            .is_none_or(|value| value == &episode.work_class_id)
        && filters
            .responsibility_id
            .as_ref()
            .is_none_or(|value| value == &episode.responsibility_id)
        && (filters.terminal_outcomes.is_empty()
            || filters
                .terminal_outcomes
                .contains(&episode.terminal_outcome))
        && filters
            .terminal_from_unix_ms
            .is_none_or(|value| episode.terminal_at_unix_ms >= value)
        && filters
            .terminal_to_unix_ms
            .is_none_or(|value| episode.terminal_at_unix_ms <= value)
        && (filters.episode_ids.is_empty() || filters.episode_ids.contains(&episode.episode_id))
        && (filters.episode_hashes.is_empty()
            || filters
                .episode_hashes
                .contains(&episode.canonical_episode_sha256))
        && filters
            .semantic_target_ids
            .iter()
            .all(|id| episode.semantic_target_ids.contains(id))
        && filters
            .capability_ids
            .iter()
            .all(|id| episode.capability_ids.contains(id))
}

fn index_entry(
    episode: &CaseEpisodeV1,
    summary_sha256: Option<String>,
) -> Result<EpisodeIndexEntryV1, EpisodicMemoryError> {
    let mut entry = EpisodeIndexEntryV1 {
        episode_id: episode.episode_id.clone(),
        episode_sha256: episode.canonical_episode_sha256.clone(),
        terminal_outcome: episode.terminal_outcome,
        work_class_id: episode.work_class_id.clone(),
        responsibility_id: episode.responsibility_id.clone(),
        terminal_at_unix_ms: episode.terminal_at_unix_ms,
        data_class_ids: episode.data_class_ids.clone(),
        evidence_sha256: episode.terminal_evidence_index_sha256.clone(),
        retention_status: EpisodeRetentionStatusV1::Active,
        approved_summary_sha256: summary_sha256,
        entry_sha256: ZERO_HASH.to_owned(),
    };
    entry.entry_sha256 = hash_without(&entry, &["entry_sha256"])?;
    Ok(entry)
}

impl EpisodeMemoryQueryV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        self.query_sha256 = hash_without(&self, &["query_sha256"])?;
        Ok(self)
    }
}

impl MemoryAugmentedCaseContextV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        self.retrieved_episode_hashes.sort();
        self.retrieved_episode_hashes.dedup();
        self.approved_summary_hashes.sort();
        self.approved_summary_hashes.dedup();
        if self.historical_trust_class != HistoricalTrustClassV1::HistoricalNonAuthoritative {
            return Err(EpisodicMemoryError::Unauthorized(
                "memory must remain historical_non_authoritative".to_owned(),
            ));
        }
        if self.reuse_policy == CrossCaseReusePolicyV1::Forbidden
            && (!self.retrieved_episode_hashes.is_empty()
                || !self.approved_summary_hashes.is_empty())
        {
            return Err(EpisodicMemoryError::Unauthorized(
                "forbidden memory context contains results".to_owned(),
            ));
        }
        if self.reuse_policy == CrossCaseReusePolicyV1::HashReferenceOnly
            && !self.approved_summary_hashes.is_empty()
        {
            return Err(EpisodicMemoryError::Unauthorized(
                "hash-only memory context contains summaries".to_owned(),
            ));
        }
        self.augmented_context_sha256 = hash_without(&self, &["augmented_context_sha256"])?;
        reject_sensitive_value(&self, "memory attachment")?;
        Ok(self)
    }
}

impl MemoryUseReceiptV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        if self.trust_class != HistoricalTrustClassV1::HistoricalNonAuthoritative
            || self.used_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(EpisodicMemoryError::Unauthorized(
                "memory use trust or validity is invalid".to_owned(),
            ));
        }
        self.episode_hashes.sort();
        self.episode_hashes.dedup();
        self.approved_summary_hashes.sort();
        self.approved_summary_hashes.dedup();
        self.receipt_sha256 = hash_without(&self, &["receipt_sha256"])?;
        Ok(self)
    }

    pub fn consumption_key(&self) -> Result<String, EpisodicMemoryError> {
        canonical_sha256(&(
            self.current_case_id.as_str(),
            self.current_work_grant_sha256.as_str(),
            self.planner_generation,
            self.query_result_sha256.as_str(),
        ))
    }
}

impl EpisodeRetentionRecordV1 {
    pub fn seal(
        mut self,
        role_maximum_days: u32,
        namespace_maximum_days: u32,
    ) -> Result<Self, EpisodicMemoryError> {
        let maximum = role_maximum_days
            .min(namespace_maximum_days)
            .min(MAX_RETENTION_DAYS);
        if maximum == 0 || self.maximum_retention_days == 0 || self.maximum_retention_days > maximum
        {
            return Err(EpisodicMemoryError::ResourceLimit(
                "retention exceeds effective Role/namespace maximum".to_owned(),
            ));
        }
        let maximum_ms = u64::from(self.maximum_retention_days).saturating_mul(86_400_000);
        if self.expires_at_unix_ms <= self.retained_from_unix_ms
            || self.expires_at_unix_ms - self.retained_from_unix_ms > maximum_ms
        {
            return Err(EpisodicMemoryError::Invalid(
                "retention interval is invalid".to_owned(),
            ));
        }
        self.record_sha256 = hash_without(&self, &["record_sha256"])?;
        Ok(self)
    }
}

impl EpisodeTombstoneV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        if self.tombstoned_at_unix_ms == 0 {
            return Err(EpisodicMemoryError::Invalid(
                "tombstone time is zero".to_owned(),
            ));
        }
        self.tombstone_sha256 = hash_without(&self, &["tombstone_sha256"])?;
        Ok(self)
    }
}

impl EpisodePurgeReceiptV1 {
    pub fn seal(mut self) -> Result<Self, EpisodicMemoryError> {
        if self.secure_erase_claimed {
            return Err(EpisodicMemoryError::Invalid(
                "v1 cannot claim physical secure erase".to_owned(),
            ));
        }
        self.receipt_sha256 = hash_without(&self, &["receipt_sha256"])?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
