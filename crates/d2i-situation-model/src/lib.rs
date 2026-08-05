//! Platform-neutral, non-authoritative WORK-500 situation contracts.

use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

pub const SITUATION_SCHEMA_VERSION: u32 = 1;
pub const MAX_JSON_BYTES: usize = 1024 * 1024;
pub const MAX_CONTEXT_BYTES: u64 = 128 * 1024;
pub const MAX_TEXT_BYTES: usize = 2_048;
pub const MAX_IDS: usize = 128;
pub const MAX_FACTS: usize = 256;
pub const MAX_ENTITIES: usize = 128;
pub const MAX_RELATIONS: usize = 256;
pub const MAX_UNKNOWNS: usize = 64;
pub const MAX_CONFLICTS: usize = 64;
pub const MAX_SUBGOALS: usize = 64;
pub const MAX_EVIDENCE_IDS: usize = 128;
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub const APPROVED_CASE_CONTEXT_BUNDLE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/approved-case-context-bundle-v1.schema.json");
pub const CASE_SITUATION_MODEL_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-situation-model-v1.schema.json");
pub const SITUATION_FACT_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/situation-fact-v1.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SituationError {
    Invalid(String),
    Integrity(String),
    ResourceLimit(String),
    SensitiveContent(String),
    Json(String),
}

impl Display for SituationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity: {message}"),
            Self::ResourceLimit(message) => write!(formatter, "resource_limit: {message}"),
            Self::SensitiveContent(message) => {
                write!(formatter, "sensitive_content: {message}")
            }
            Self::Json(message) => write!(formatter, "json: {message}"),
        }
    }
}

impl std::error::Error for SituationError {}

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

pub fn parse_json_strict<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SituationError> {
    if bytes.is_empty() || bytes.len() > MAX_JSON_BYTES {
        return Err(SituationError::ResourceLimit(
            "JSON input is empty or exceeds 1 MiB".to_owned(),
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| SituationError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| SituationError::Json(error.to_string()))?;
    serde_json::from_value(value.0).map_err(|error| SituationError::Json(error.to_string()))
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

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SituationError> {
    let value =
        serde_json::to_value(value).map_err(|error| SituationError::Json(error.to_string()))?;
    serde_json::to_vec(&canonicalize(&value))
        .map_err(|error| SituationError::Json(error.to_string()))
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, SituationError> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(canonical_json_bytes(value)?)
    ))
}

pub fn hash_without<T: Serialize>(value: &T, omitted: &[&str]) -> Result<String, SituationError> {
    let mut value =
        serde_json::to_value(value).map_err(|error| SituationError::Json(error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| SituationError::Json("self-hash payload is not an object".to_owned()))?;
    for field in omitted {
        if object.remove(*field).is_none() {
            return Err(SituationError::Integrity(format!(
                "self-hash field {field} is absent"
            )));
        }
    }
    canonical_sha256(&value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentTrustClassV1 {
    AuthenticatedInstruction,
    ApprovedPolicy,
    ApprovedProcedure,
    TrustedSystem,
    VerifiedObservation,
    ModelInference,
    UntrustedContent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SituationFactKindV1 {
    Observed,
    TrustedSystem,
    ApprovedPolicy,
    ApprovedProcedure,
    AuthenticatedAssertion,
    ModelInference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SituationUnknownKindV1 {
    Missing,
    Unavailable,
    Redacted,
    Stale,
    Ambiguous,
    Conflicting,
    Unsupported,
    AuthorityUnknown,
    PolicyUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SituationSubgoalStatusV1 {
    Open,
    Completed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKnowledgeStateV1 {
    AllowedByTrustedPolicy,
    DeniedByTrustedPolicy,
    ConfirmationRequired,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplicitConfidenceV1 {
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConfidenceV1 {
    Millionths(u32),
    Explicit(ExplicitConfidenceV1),
}

impl ConfidenceV1 {
    pub fn validate(self) -> Result<(), SituationError> {
        match self {
            Self::Millionths(value) if value <= 1_000_000 => Ok(()),
            Self::Explicit(ExplicitConfidenceV1::NotApplicable) => Ok(()),
            Self::Millionths(_) => Err(SituationError::Invalid(
                "confidence exceeds one million millionths".to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedArtifactRefV1 {
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub trust_class: ContentTrustClassV1,
    pub safe_summary: String,
}

impl ApprovedArtifactRefV1 {
    pub fn validate(&self) -> Result<(), SituationError> {
        validate_id(&self.artifact_id, "artifact ID")?;
        validate_hash(&self.artifact_sha256, "artifact hash")?;
        validate_text(&self.safe_summary, "artifact safe summary")?;
        if self.trust_class == ContentTrustClassV1::UntrustedContent {
            return Err(SituationError::Invalid(
                "untrusted content cannot be an approved context artifact".to_owned(),
            ));
        }
        reject_sensitive_text(&self.safe_summary, "artifact safe summary")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionProofV1 {
    pub field_id: String,
    pub redaction_reason: String,
    pub replacement_sha256: String,
}

impl RedactionProofV1 {
    fn validate(&self) -> Result<(), SituationError> {
        validate_id(&self.field_id, "redaction field")?;
        validate_text(&self.redaction_reason, "redaction reason")?;
        validate_hash(&self.replacement_sha256, "redaction replacement hash")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessBoundV1 {
    pub observed_at_unix_seconds: u64,
    pub valid_until_unix_seconds: u64,
    pub maximum_age_seconds: u64,
}

impl FreshnessBoundV1 {
    pub fn validate(&self) -> Result<(), SituationError> {
        if self.observed_at_unix_seconds == 0
            || self.maximum_age_seconds == 0
            || self.maximum_age_seconds > 86_400
            || self.valid_until_unix_seconds
                != self
                    .observed_at_unix_seconds
                    .saturating_add(self.maximum_age_seconds)
        {
            return Err(SituationError::Invalid(
                "freshness bound is invalid or exceeds one day".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedCaseContextBundleV1 {
    pub schema_version: u32,
    pub context_bundle_id: String,
    pub case_id: String,
    pub case_contract_sha256: String,
    pub case_instance_sha256: String,
    pub work_item_sha256: String,
    pub case_work_grant_sha256: String,
    pub lease_sha256: String,
    pub ownership_state_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub organization_id: String,
    pub work_class_id: String,
    pub responsibility_id: String,
    pub approved_objective_artifact_refs: Vec<ApprovedArtifactRefV1>,
    pub approved_structured_input_refs: Vec<ApprovedArtifactRefV1>,
    pub application_pack_refs: Vec<ApprovedArtifactRefV1>,
    pub approved_procedure_refs: Vec<ApprovedArtifactRefV1>,
    pub approved_policy_refs: Vec<ApprovedArtifactRefV1>,
    pub current_observation_refs: Vec<ApprovedArtifactRefV1>,
    pub previous_verified_attempt_refs: Vec<ApprovedArtifactRefV1>,
    pub unresolved_requirement_ids: Vec<String>,
    pub satisfied_requirement_ids: Vec<String>,
    pub content_trust_labels: Vec<ContentTrustClassV1>,
    pub redaction_proofs: Vec<RedactionProofV1>,
    pub freshness: FreshnessBoundV1,
    pub evidence_ids: Vec<String>,
    pub total_byte_count: u64,
    pub context_sha256: String,
}

impl ApprovedCaseContextBundleV1 {
    pub fn seal(mut self) -> Result<Self, SituationError> {
        for refs in [
            &mut self.approved_objective_artifact_refs,
            &mut self.approved_structured_input_refs,
            &mut self.application_pack_refs,
            &mut self.approved_procedure_refs,
            &mut self.approved_policy_refs,
            &mut self.current_observation_refs,
            &mut self.previous_verified_attempt_refs,
        ] {
            refs.sort();
            reject_duplicates(refs, "approved artifact references")?;
        }
        normalize_ids(&mut self.unresolved_requirement_ids, true)?;
        normalize_ids(&mut self.satisfied_requirement_ids, true)?;
        normalize_ids(&mut self.evidence_ids, false)?;
        self.content_trust_labels.sort();
        reject_duplicates(&self.content_trust_labels, "content trust labels")?;
        self.redaction_proofs.sort();
        reject_duplicates(&self.redaction_proofs, "redaction proofs")?;
        self.total_byte_count = approved_payload_bytes(&self)?;
        self.context_sha256 = hash_without(&self, &["context_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SituationError> {
        if self.schema_version != SITUATION_SCHEMA_VERSION {
            return Err(SituationError::Invalid(
                "approved context schema version is unsupported".to_owned(),
            ));
        }
        for (value, label) in [
            (&self.context_bundle_id, "context bundle ID"),
            (&self.case_id, "Case ID"),
            (&self.role_instance_id, "Role Instance ID"),
            (&self.organization_id, "organization ID"),
            (&self.work_class_id, "work class ID"),
            (&self.responsibility_id, "responsibility ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.case_contract_sha256, "Case Contract hash"),
            (&self.case_instance_sha256, "Case Instance hash"),
            (&self.work_item_sha256, "Work Item hash"),
            (&self.case_work_grant_sha256, "Case Work Grant hash"),
            (&self.lease_sha256, "lease hash"),
            (&self.ownership_state_sha256, "ownership hash"),
            (&self.role_instance_sha256, "Role Instance hash"),
            (&self.role_contract_sha256, "Role Contract hash"),
            (&self.delegation_sha256, "delegation hash"),
            (&self.context_sha256, "context hash"),
        ] {
            validate_hash(value, label)?;
        }
        let mut artifact_count = 0usize;
        for refs in [
            &self.approved_objective_artifact_refs,
            &self.approved_structured_input_refs,
            &self.application_pack_refs,
            &self.approved_procedure_refs,
            &self.approved_policy_refs,
            &self.current_observation_refs,
            &self.previous_verified_attempt_refs,
        ] {
            artifact_count = artifact_count.saturating_add(refs.len());
            if refs.len() > MAX_IDS {
                return Err(SituationError::ResourceLimit(
                    "approved artifact collection exceeds bound".to_owned(),
                ));
            }
            reject_duplicates(refs, "approved artifact references")?;
            for reference in refs {
                reference.validate()?;
            }
        }
        if artifact_count == 0 || artifact_count > MAX_IDS {
            return Err(SituationError::ResourceLimit(
                "total approved artifact references must be within 1..=128".to_owned(),
            ));
        }
        validate_ids(&self.unresolved_requirement_ids, true)?;
        validate_ids(&self.satisfied_requirement_ids, true)?;
        validate_ids(&self.evidence_ids, false)?;
        if self.content_trust_labels.is_empty() || self.content_trust_labels.len() > 8 {
            return Err(SituationError::Invalid(
                "context requires a bounded trust-label set".to_owned(),
            ));
        }
        reject_duplicates(&self.content_trust_labels, "content trust labels")?;
        if self
            .content_trust_labels
            .contains(&ContentTrustClassV1::UntrustedContent)
        {
            return Err(SituationError::SensitiveContent(
                "untrusted content cannot be promoted into approved model context".to_owned(),
            ));
        }
        if self.redaction_proofs.len() > MAX_IDS {
            return Err(SituationError::ResourceLimit(
                "redaction proof collection exceeds bound".to_owned(),
            ));
        }
        reject_duplicates(&self.redaction_proofs, "redaction proofs")?;
        for proof in &self.redaction_proofs {
            proof.validate()?;
        }
        self.freshness.validate()?;
        let actual_bytes = approved_payload_bytes(self)?;
        if self.total_byte_count != actual_bytes || actual_bytes > MAX_CONTEXT_BYTES {
            return Err(SituationError::ResourceLimit(
                "context byte count is incorrect or exceeds 128 KiB".to_owned(),
            ));
        }
        if hash_without(self, &["context_sha256"])? != self.context_sha256 {
            return Err(SituationError::Integrity(
                "approved context self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "approved Case context")
    }
}

fn approved_payload_bytes(value: &ApprovedCaseContextBundleV1) -> Result<u64, SituationError> {
    let mut clone = value.clone();
    clone.total_byte_count = 0;
    clone.context_sha256 = ZERO_HASH.to_owned();
    Ok(canonical_json_bytes(&clone)?.len() as u64)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationFactV1 {
    pub fact_id: String,
    pub fact_kind: SituationFactKindV1,
    pub subject: String,
    pub predicate: String,
    pub typed_object: Value,
    pub confidence: ConfidenceV1,
    pub evidence_refs: Vec<String>,
    pub source_trust_class: ContentTrustClassV1,
    pub provider_id: Option<String>,
    pub freshness: FreshnessBoundV1,
    pub contradiction_group_id: Option<String>,
    pub fact_sha256: String,
}

impl SituationFactV1 {
    pub fn seal(mut self) -> Result<Self, SituationError> {
        normalize_ids(&mut self.evidence_refs, false)?;
        self.fact_sha256 = hash_without(&self, &["fact_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SituationError> {
        validate_id(&self.fact_id, "fact ID")?;
        validate_id(&self.subject, "fact subject")?;
        validate_id(&self.predicate, "fact predicate")?;
        self.confidence.validate()?;
        validate_ids(&self.evidence_refs, false)?;
        if let Some(provider_id) = &self.provider_id {
            validate_id(provider_id, "fact provider ID")?;
        }
        if self.fact_kind == SituationFactKindV1::ModelInference {
            if self.source_trust_class != ContentTrustClassV1::ModelInference
                || self.provider_id.is_none()
            {
                return Err(SituationError::Invalid(
                    "model inference fact requires model trust label and provider".to_owned(),
                ));
            }
        } else if self.source_trust_class == ContentTrustClassV1::ModelInference {
            return Err(SituationError::Invalid(
                "non-inference fact cannot carry model-inference trust".to_owned(),
            ));
        }
        if let Some(group_id) = &self.contradiction_group_id {
            validate_id(group_id, "contradiction group ID")?;
        }
        self.freshness.validate()?;
        let object_bytes = serde_json::to_vec(&self.typed_object)
            .map_err(|error| SituationError::Json(error.to_string()))?;
        if object_bytes.len() > 8 * 1024 {
            return Err(SituationError::ResourceLimit(
                "fact object exceeds 8 KiB".to_owned(),
            ));
        }
        reject_sensitive_json(&self.typed_object, "fact object")?;
        validate_hash(&self.fact_sha256, "fact hash")?;
        if hash_without(self, &["fact_sha256"])? != self.fact_sha256 {
            return Err(SituationError::Integrity(
                "fact self-hash differs".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationEntityV1 {
    pub entity_id: String,
    pub entity_kind: String,
    pub safe_label: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationRelationV1 {
    pub relation_id: String,
    pub subject_entity_id: String,
    pub predicate: String,
    pub object_entity_id: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationUnknownV1 {
    pub unknown_id: String,
    pub requirement_id: String,
    pub kind: SituationUnknownKindV1,
    pub safe_summary: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationConflictV1 {
    pub conflict_id: String,
    pub contradiction_group_id: String,
    pub fact_ids: Vec<String>,
    pub safe_summary: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationSubgoalV1 {
    pub subgoal_id: String,
    pub semantic_intent: String,
    pub status: SituationSubgoalStatusV1,
    pub requirement_ids: Vec<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationPolicyStateV1 {
    pub policy_fact_id: String,
    pub capability_id: String,
    pub state: PolicyKnowledgeStateV1,
    pub trusted_policy_sha256: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SituationProgressV1 {
    pub total_requirements: u32,
    pub satisfied_requirements: u32,
    pub unresolved_requirements: u32,
    pub progress_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderProvenanceV1 {
    pub provider_id: String,
    pub provider_descriptor_sha256: String,
    pub invocation_sha256: String,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSituationModelV1 {
    pub schema_version: u32,
    pub situation_id: String,
    pub generation: u64,
    pub case_id: String,
    pub current_case_instance_sha256: String,
    pub case_work_grant_sha256: String,
    pub context_bundle_sha256: String,
    pub source_observation_hashes: Vec<String>,
    pub role_instance_sha256: String,
    pub ownership_state_sha256: String,
    pub lease_sha256: String,
    pub observed_facts: Vec<SituationFactV1>,
    pub trusted_system_facts: Vec<SituationFactV1>,
    pub approved_policy_facts: Vec<SituationFactV1>,
    pub approved_procedure_facts: Vec<SituationFactV1>,
    pub authenticated_assertions: Vec<SituationFactV1>,
    pub model_inferences: Vec<SituationFactV1>,
    pub entities: Vec<SituationEntityV1>,
    pub relations: Vec<SituationRelationV1>,
    pub completed_subgoals: Vec<SituationSubgoalV1>,
    pub open_subgoals: Vec<SituationSubgoalV1>,
    pub unresolved_requirement_ids: Vec<String>,
    pub satisfied_requirement_ids: Vec<String>,
    pub unknowns: Vec<SituationUnknownV1>,
    pub conflicts: Vec<SituationConflictV1>,
    pub blocker_ids: Vec<String>,
    pub policy_relevant_state: Vec<SituationPolicyStateV1>,
    pub allowed_semantic_target_ids: Vec<String>,
    pub allowed_capability_ids: Vec<String>,
    pub forbidden_capability_ids: Vec<String>,
    pub confidence_summary: ConfidenceV1,
    pub progress: SituationProgressV1,
    pub provider_provenance: Option<ProviderProvenanceV1>,
    pub evidence_ids: Vec<String>,
    pub previous_situation_sha256: Option<String>,
    pub situation_sha256: String,
}

impl CaseSituationModelV1 {
    pub fn seal(mut self) -> Result<Self, SituationError> {
        for facts in [
            &mut self.observed_facts,
            &mut self.trusted_system_facts,
            &mut self.approved_policy_facts,
            &mut self.approved_procedure_facts,
            &mut self.authenticated_assertions,
            &mut self.model_inferences,
        ] {
            facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
        }
        for ids in [
            &mut self.source_observation_hashes,
            &mut self.unresolved_requirement_ids,
            &mut self.satisfied_requirement_ids,
            &mut self.blocker_ids,
            &mut self.allowed_semantic_target_ids,
            &mut self.allowed_capability_ids,
            &mut self.forbidden_capability_ids,
            &mut self.evidence_ids,
        ] {
            ids.sort();
            ids.dedup();
        }
        self.entities.sort_by(|a, b| a.entity_id.cmp(&b.entity_id));
        self.relations
            .sort_by(|a, b| a.relation_id.cmp(&b.relation_id));
        self.unknowns
            .sort_by(|a, b| a.unknown_id.cmp(&b.unknown_id));
        self.conflicts
            .sort_by(|a, b| a.conflict_id.cmp(&b.conflict_id));
        self.completed_subgoals
            .sort_by(|a, b| a.subgoal_id.cmp(&b.subgoal_id));
        self.open_subgoals
            .sort_by(|a, b| a.subgoal_id.cmp(&b.subgoal_id));
        self.policy_relevant_state
            .sort_by(|a, b| a.policy_fact_id.cmp(&b.policy_fact_id));
        self.situation_sha256 = hash_without(&self, &["situation_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SituationError> {
        if self.schema_version != SITUATION_SCHEMA_VERSION || self.generation == 0 {
            return Err(SituationError::Invalid(
                "situation schema or generation is invalid".to_owned(),
            ));
        }
        validate_id(&self.situation_id, "situation ID")?;
        validate_id(&self.case_id, "situation Case ID")?;
        for (value, label) in [
            (&self.current_case_instance_sha256, "Case Instance hash"),
            (&self.case_work_grant_sha256, "Case Work Grant hash"),
            (&self.context_bundle_sha256, "context hash"),
            (&self.role_instance_sha256, "Role Instance hash"),
            (&self.ownership_state_sha256, "ownership hash"),
            (&self.lease_sha256, "lease hash"),
            (&self.situation_sha256, "situation hash"),
        ] {
            validate_hash(value, label)?;
        }
        if let Some(previous) = &self.previous_situation_sha256 {
            validate_hash(previous, "previous situation hash")?;
            if self.generation == 1 {
                return Err(SituationError::Invalid(
                    "generation one cannot have a previous situation".to_owned(),
                ));
            }
        } else if self.generation != 1 {
            return Err(SituationError::Invalid(
                "later situation generation requires previous hash".to_owned(),
            ));
        }
        if self.source_observation_hashes.is_empty()
            || self.source_observation_hashes.len() > MAX_IDS
        {
            return Err(SituationError::ResourceLimit(
                "situation requires bounded fresh observation hashes".to_owned(),
            ));
        }
        for hash in &self.source_observation_hashes {
            validate_hash(hash, "source observation hash")?;
        }
        reject_duplicates(&self.source_observation_hashes, "source observation hashes")?;
        validate_fact_group(&self.observed_facts, SituationFactKindV1::Observed)?;
        validate_fact_group(
            &self.trusted_system_facts,
            SituationFactKindV1::TrustedSystem,
        )?;
        validate_fact_group(
            &self.approved_policy_facts,
            SituationFactKindV1::ApprovedPolicy,
        )?;
        validate_fact_group(
            &self.approved_procedure_facts,
            SituationFactKindV1::ApprovedProcedure,
        )?;
        validate_fact_group(
            &self.authenticated_assertions,
            SituationFactKindV1::AuthenticatedAssertion,
        )?;
        validate_fact_group(&self.model_inferences, SituationFactKindV1::ModelInference)?;
        let total_facts = self.observed_facts.len()
            + self.trusted_system_facts.len()
            + self.approved_policy_facts.len()
            + self.approved_procedure_facts.len()
            + self.authenticated_assertions.len()
            + self.model_inferences.len();
        if total_facts == 0 || total_facts > MAX_FACTS {
            return Err(SituationError::ResourceLimit(
                "situation fact count must be within 1..=256".to_owned(),
            ));
        }
        validate_entities(&self.entities)?;
        validate_relations(&self.relations, &self.entities)?;
        validate_subgoals(
            &self.completed_subgoals,
            SituationSubgoalStatusV1::Completed,
        )?;
        validate_subgoals(&self.open_subgoals, SituationSubgoalStatusV1::Open)?;
        validate_unknowns(&self.unknowns)?;
        validate_conflicts(&self.conflicts, self)?;
        for ids in [
            &self.unresolved_requirement_ids,
            &self.satisfied_requirement_ids,
            &self.blocker_ids,
            &self.allowed_semantic_target_ids,
            &self.allowed_capability_ids,
            &self.forbidden_capability_ids,
            &self.evidence_ids,
        ] {
            validate_ids(ids, ids != &self.blocker_ids)?;
        }
        if self
            .allowed_capability_ids
            .iter()
            .any(|id| self.forbidden_capability_ids.contains(id))
        {
            return Err(SituationError::Invalid(
                "a capability cannot be both allowed and forbidden".to_owned(),
            ));
        }
        if self.policy_relevant_state.len() > MAX_IDS {
            return Err(SituationError::ResourceLimit(
                "policy state collection exceeds bound".to_owned(),
            ));
        }
        for policy in &self.policy_relevant_state {
            validate_id(&policy.policy_fact_id, "policy fact ID")?;
            validate_id(&policy.capability_id, "policy capability ID")?;
            validate_hash(&policy.trusted_policy_sha256, "trusted policy hash")?;
            validate_ids(&policy.evidence_refs, false)?;
        }
        self.confidence_summary.validate()?;
        self.progress.validate()?;
        if let Some(provenance) = &self.provider_provenance {
            provenance.validate()?;
        }
        if hash_without(self, &["situation_sha256"])? != self.situation_sha256 {
            return Err(SituationError::Integrity(
                "situation self-hash differs".to_owned(),
            ));
        }
        reject_sensitive_value(self, "Case situation model")
    }
}

impl SituationProgressV1 {
    fn validate(&self) -> Result<(), SituationError> {
        if self.total_requirements == 0
            || self.satisfied_requirements + self.unresolved_requirements != self.total_requirements
            || self.progress_millionths > 1_000_000
            || u64::from(self.progress_millionths) * u64::from(self.total_requirements)
                != u64::from(self.satisfied_requirements) * 1_000_000
        {
            return Err(SituationError::Invalid(
                "situation progress is inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

impl ProviderProvenanceV1 {
    fn validate(&self) -> Result<(), SituationError> {
        validate_id(&self.provider_id, "provider ID")?;
        validate_hash(&self.provider_descriptor_sha256, "provider descriptor hash")?;
        validate_hash(&self.invocation_sha256, "provider invocation hash")?;
        validate_hash(&self.result_sha256, "provider result hash")
    }
}

fn validate_fact_group(
    facts: &[SituationFactV1],
    expected: SituationFactKindV1,
) -> Result<(), SituationError> {
    if facts.len() > MAX_FACTS {
        return Err(SituationError::ResourceLimit(
            "fact collection exceeds bound".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for fact in facts {
        fact.validate()?;
        if fact.fact_kind != expected {
            return Err(SituationError::Invalid(
                "fact appears in the wrong provenance collection".to_owned(),
            ));
        }
        if !ids.insert(&fact.fact_id) {
            return Err(SituationError::Invalid("duplicate fact ID".to_owned()));
        }
    }
    Ok(())
}

fn validate_entities(values: &[SituationEntityV1]) -> Result<(), SituationError> {
    if values.len() > MAX_ENTITIES {
        return Err(SituationError::ResourceLimit(
            "entity collection exceeds bound".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for entity in values {
        validate_id(&entity.entity_id, "entity ID")?;
        validate_id(&entity.entity_kind, "entity kind")?;
        validate_text(&entity.safe_label, "entity safe label")?;
        reject_sensitive_text(&entity.safe_label, "entity safe label")?;
        validate_ids(&entity.evidence_refs, false)?;
        if !ids.insert(&entity.entity_id) {
            return Err(SituationError::Invalid("duplicate entity ID".to_owned()));
        }
    }
    Ok(())
}

fn validate_relations(
    values: &[SituationRelationV1],
    entities: &[SituationEntityV1],
) -> Result<(), SituationError> {
    if values.len() > MAX_RELATIONS {
        return Err(SituationError::ResourceLimit(
            "relation collection exceeds bound".to_owned(),
        ));
    }
    let entity_ids = entities
        .iter()
        .map(|entity| entity.entity_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    for relation in values {
        validate_id(&relation.relation_id, "relation ID")?;
        validate_id(&relation.predicate, "relation predicate")?;
        if !entity_ids.contains(relation.subject_entity_id.as_str())
            || !entity_ids.contains(relation.object_entity_id.as_str())
        {
            return Err(SituationError::Invalid(
                "relation references an unknown entity".to_owned(),
            ));
        }
        validate_ids(&relation.evidence_refs, false)?;
        if !ids.insert(&relation.relation_id) {
            return Err(SituationError::Invalid("duplicate relation ID".to_owned()));
        }
    }
    Ok(())
}

fn validate_subgoals(
    values: &[SituationSubgoalV1],
    expected: SituationSubgoalStatusV1,
) -> Result<(), SituationError> {
    if values.len() > MAX_SUBGOALS {
        return Err(SituationError::ResourceLimit(
            "subgoal collection exceeds bound".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for subgoal in values {
        validate_id(&subgoal.subgoal_id, "subgoal ID")?;
        validate_id(&subgoal.semantic_intent, "subgoal semantic intent")?;
        if subgoal.status != expected {
            return Err(SituationError::Invalid(
                "subgoal appears in the wrong status collection".to_owned(),
            ));
        }
        validate_ids(&subgoal.requirement_ids, false)?;
        validate_ids(&subgoal.evidence_refs, false)?;
        if !ids.insert(&subgoal.subgoal_id) {
            return Err(SituationError::Invalid("duplicate subgoal ID".to_owned()));
        }
    }
    Ok(())
}

fn validate_unknowns(values: &[SituationUnknownV1]) -> Result<(), SituationError> {
    if values.len() > MAX_UNKNOWNS {
        return Err(SituationError::ResourceLimit(
            "unknown collection exceeds bound".to_owned(),
        ));
    }
    let mut ids = BTreeSet::new();
    for unknown in values {
        validate_id(&unknown.unknown_id, "unknown ID")?;
        validate_id(&unknown.requirement_id, "unknown requirement ID")?;
        validate_text(&unknown.safe_summary, "unknown safe summary")?;
        reject_sensitive_text(&unknown.safe_summary, "unknown safe summary")?;
        validate_ids(&unknown.evidence_refs, true)?;
        if !ids.insert(&unknown.unknown_id) {
            return Err(SituationError::Invalid("duplicate unknown ID".to_owned()));
        }
    }
    Ok(())
}

fn validate_conflicts(
    values: &[SituationConflictV1],
    situation: &CaseSituationModelV1,
) -> Result<(), SituationError> {
    if values.len() > MAX_CONFLICTS {
        return Err(SituationError::ResourceLimit(
            "conflict collection exceeds bound".to_owned(),
        ));
    }
    let all_fact_ids = situation
        .observed_facts
        .iter()
        .chain(&situation.trusted_system_facts)
        .chain(&situation.approved_policy_facts)
        .chain(&situation.approved_procedure_facts)
        .chain(&situation.authenticated_assertions)
        .chain(&situation.model_inferences)
        .map(|fact| fact.fact_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    for conflict in values {
        validate_id(&conflict.conflict_id, "conflict ID")?;
        validate_id(
            &conflict.contradiction_group_id,
            "conflict contradiction group",
        )?;
        if conflict.fact_ids.len() < 2 || conflict.fact_ids.len() > MAX_IDS {
            return Err(SituationError::Invalid(
                "conflict requires at least two bounded facts".to_owned(),
            ));
        }
        validate_ids(&conflict.fact_ids, false)?;
        if conflict
            .fact_ids
            .iter()
            .any(|fact_id| !all_fact_ids.contains(fact_id.as_str()))
        {
            return Err(SituationError::Invalid(
                "conflict references an unknown fact".to_owned(),
            ));
        }
        validate_text(&conflict.safe_summary, "conflict safe summary")?;
        reject_sensitive_text(&conflict.safe_summary, "conflict safe summary")?;
        validate_ids(&conflict.evidence_refs, false)?;
        if !ids.insert(&conflict.conflict_id) {
            return Err(SituationError::Invalid("duplicate conflict ID".to_owned()));
        }
    }
    Ok(())
}

pub fn validate_id(value: &str, label: &str) -> Result<(), SituationError> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
        || value.contains("..")
        || value.contains("//")
        || matches!(value, "*" | "all" | "any")
    {
        return Err(SituationError::Invalid(format!("{label} is invalid")));
    }
    Ok(())
}

pub fn validate_hash(value: &str, label: &str) -> Result<(), SituationError> {
    let digest = value.strip_prefix("sha256:").unwrap_or(value);
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SituationError::Invalid(format!(
            "{label} is not lowercase SHA-256"
        )));
    }
    Ok(())
}

pub fn validate_text(value: &str, label: &str) -> Result<(), SituationError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(SituationError::Invalid(format!(
            "{label} is empty, oversized, or contains control characters"
        )));
    }
    Ok(())
}

pub fn validate_ids(values: &[String], allow_empty: bool) -> Result<(), SituationError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_IDS {
        return Err(SituationError::ResourceLimit(
            "ID collection is empty or exceeds bound".to_owned(),
        ));
    }
    for value in values {
        validate_id(value, "collection ID")?;
    }
    reject_duplicates(values, "ID collection")
}

pub fn normalize_ids(values: &mut [String], allow_empty: bool) -> Result<(), SituationError> {
    values.sort();
    validate_ids(values, allow_empty)
}

fn reject_duplicates<T: Ord>(values: &[T], label: &str) -> Result<(), SituationError> {
    let mut ordered = BTreeSet::new();
    for value in values {
        if !ordered.insert(value) {
            return Err(SituationError::Invalid(format!(
                "{label} contains duplicates"
            )));
        }
    }
    Ok(())
}

pub fn reject_sensitive_value<T: Serialize>(value: &T, label: &str) -> Result<(), SituationError> {
    let value =
        serde_json::to_value(value).map_err(|error| SituationError::Json(error.to_string()))?;
    reject_sensitive_json(&value, label)
}

fn reject_sensitive_json(value: &Value, label: &str) -> Result<(), SituationError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                if [
                    "password",
                    "credential",
                    "secret",
                    "private_key",
                    "api_key",
                    "client_secret",
                    "access_token",
                    "refresh_token",
                    "activation_token",
                    "automation_id",
                    "css_selector",
                    "raw_locator",
                    "shell_command",
                    "absolute_path",
                ]
                .iter()
                .any(|forbidden| lower.contains(forbidden))
                {
                    return Err(SituationError::SensitiveContent(format!(
                        "{label} contains forbidden field {key}"
                    )));
                }
                reject_sensitive_json(child, label)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_sensitive_json(child, label)?;
            }
        }
        Value::String(text) => reject_sensitive_text(text, label)?,
        _ => {}
    }
    Ok(())
}

pub fn reject_sensitive_text(value: &str, label: &str) -> Result<(), SituationError> {
    let lower = value.to_ascii_lowercase();
    if [
        "password=",
        "password:",
        "api_key=",
        "api_key:",
        "api key=",
        "api key:",
        "client_secret=",
        "client_secret:",
        "access_token",
        "refresh_token",
        "credential=",
        "credential:",
        "secret=",
        "secret:",
        "private key",
        "bearer ",
        "authorization:",
        "powershell -",
        "cmd.exe",
        "automationid=",
        "css selector",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return Err(SituationError::SensitiveContent(format!(
            "{label} resembles a secret, locator, or command"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_are_rejected() {
        let result = parse_json_strict::<Value>(br#"{"id":"one","id":"two"}"#);
        assert!(result
            .as_ref()
            .err()
            .is_some_and(|error| error.to_string().contains("duplicate")));
    }

    #[test]
    fn model_inference_cannot_masquerade_as_observation() {
        let fact = SituationFactV1 {
            fact_id: "fact.1".to_owned(),
            fact_kind: SituationFactKindV1::Observed,
            subject: "record".to_owned(),
            predicate: "requires_update".to_owned(),
            typed_object: Value::Bool(true),
            confidence: ConfidenceV1::Millionths(900_000),
            evidence_refs: vec!["evidence.1".to_owned()],
            source_trust_class: ContentTrustClassV1::ModelInference,
            provider_id: Some("provider.local".to_owned()),
            freshness: FreshnessBoundV1 {
                observed_at_unix_seconds: 10,
                valid_until_unix_seconds: 20,
                maximum_age_seconds: 10,
            },
            contradiction_group_id: None,
            fact_sha256: ZERO_HASH.to_owned(),
        };
        assert!(fact.seal().is_err());
    }

    #[test]
    fn sensitive_context_summary_is_rejected() {
        let reference = ApprovedArtifactRefV1 {
            artifact_id: "artifact.1".to_owned(),
            artifact_sha256: ZERO_HASH.to_owned(),
            trust_class: ContentTrustClassV1::AuthenticatedInstruction,
            safe_summary: "password: do-not-store".to_owned(),
        };
        assert!(reference.validate().is_err());
    }

    #[test]
    fn raw_api_key_summary_is_rejected() {
        assert!(reject_sensitive_text(
            "api_key=0123456789abcdef0123456789abcdef",
            "artifact safe summary"
        )
        .is_err());
    }

    #[test]
    fn non_secret_policy_summary_is_allowed() {
        assert!(reject_sensitive_text(
            "Never include an API key or credential in approved context.",
            "artifact safe summary"
        )
        .is_ok());
    }
}
