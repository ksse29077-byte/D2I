//! Application-neutral, bounded semantic document contracts for OFFICE-200.

mod contracts;

pub use contracts::*;

use d2i_office_capability::{canonical_json_bytes, parse_json_strict, sha256_bytes};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

/// OFFICE-200 contract version.
pub const DOCUMENT_SCHEMA_VERSION: u32 = 1;
/// Placeholder accepted only while sealing an artifact.
pub const ZERO_HASH: &str = d2i_office_capability::ZERO_HASH;
/// Maximum strict JSON input size.
pub const MAX_DOCUMENT_JSON_BYTES: usize = 2 * 1024 * 1024;
/// Maximum collection length in a public document artifact.
pub const MAX_DOCUMENT_COLLECTION_ITEMS: usize = 512;
/// Maximum ordinary metadata string size.
pub const MAX_DOCUMENT_STRING_BYTES: usize = 512;
/// Maximum generated text payload size in Unicode scalar values.
pub const MAX_CONTENT_CHARACTERS: usize = 32_768;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentCapabilityError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    Signature(String),
}

impl Display for DocumentCapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::Replay(message) => ("replay", message),
            Self::Signature(message) => ("signature", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for DocumentCapabilityError {}

fn invalid(message: impl Into<String>) -> DocumentCapabilityError {
    DocumentCapabilityError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> DocumentCapabilityError {
    DocumentCapabilityError::Integrity(message.into())
}

/// Parses strict JSON with duplicate-key rejection and bounded input.
pub fn parse_document_json_strict<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, DocumentCapabilityError> {
    if bytes.len() > MAX_DOCUMENT_JSON_BYTES {
        return Err(invalid("document contract JSON exceeds 2 MiB"));
    }
    parse_json_strict(bytes).map_err(|error| invalid(error.to_string()))
}

/// Computes canonical SHA-256 using recursively key-ordered JSON.
pub fn document_canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, DocumentCapabilityError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| invalid(error.to_string()))
}

fn hash_without<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<String, DocumentCapabilityError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| invalid(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("document artifact must serialize as an object"))?;
    for field in excluded {
        object.remove(*field);
    }
    document_canonical_sha256(&object)
}

fn validate_hash(value: &str, label: &str) -> Result<(), DocumentCapabilityError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{label} must be a lowercase SHA-256")));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), DocumentCapabilityError> {
    if value.is_empty()
        || value.len() > MAX_DOCUMENT_STRING_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return Err(invalid(format!("{label} must be a bounded identifier")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str, maximum: usize) -> Result<(), DocumentCapabilityError> {
    if value.is_empty() || value.chars().count() > maximum || value.contains('\0') {
        return Err(invalid(format!("{label} is empty or exceeds its bound")));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), DocumentCapabilityError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_DOCUMENT_COLLECTION_ITEMS {
        return Err(invalid(format!("{label} has invalid cardinality")));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_id(value, label)?;
        if !unique.insert(value) {
            return Err(invalid(format!("{label} contains a duplicate")));
        }
    }
    Ok(())
}

fn validate_hashes(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), DocumentCapabilityError> {
    if (!allow_empty && values.is_empty()) || values.len() > MAX_DOCUMENT_COLLECTION_ITEMS {
        return Err(invalid(format!("{label} has invalid cardinality")));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_hash(value, label)?;
        if !unique.insert(value) {
            return Err(invalid(format!("{label} contains a duplicate")));
        }
    }
    Ok(())
}

fn validate_common_value(value: &Value) -> Result<(), DocumentCapabilityError> {
    match value {
        Value::Array(values) => {
            if values.len() > MAX_DOCUMENT_COLLECTION_ITEMS {
                return Err(invalid("document contract collection exceeds 512 items"));
            }
            for value in values {
                validate_common_value(value)?;
            }
        }
        Value::Object(values) => {
            if let Some(version) = values.get("schema_version").and_then(Value::as_u64) {
                if version != u64::from(DOCUMENT_SCHEMA_VERSION) {
                    return Err(invalid("document contract schema_version must be 1"));
                }
            }
            for value in values.values() {
                validate_common_value(value)?;
            }
        }
        Value::String(value) => {
            if value.len() > MAX_CONTENT_CHARACTERS * 4 || value.contains('\0') {
                return Err(invalid(
                    "document contract string exceeds its absolute bound",
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_serialized<T: Serialize>(value: &T) -> Result<(), DocumentCapabilityError> {
    let serialized = serde_json::to_value(value).map_err(|error| invalid(error.to_string()))?;
    validate_common_value(&serialized)
}

fn validate_limits(limits: &DocumentResourceLimitsV1) -> Result<(), DocumentCapabilityError> {
    let valid = limits.maximum_document_bytes >= 1_024
        && limits.maximum_document_bytes <= 256 * 1024 * 1024
        && limits.maximum_package_entries > 0
        && limits.maximum_package_entries <= 4_096
        && limits.maximum_uncompressed_bytes >= limits.maximum_document_bytes
        && limits.maximum_uncompressed_bytes <= 1024 * 1024 * 1024
        && limits.maximum_compression_ratio > 0
        && limits.maximum_compression_ratio <= 1_000
        && limits.maximum_xml_bytes > 0
        && limits.maximum_xml_bytes <= limits.maximum_uncompressed_bytes
        && limits.maximum_xml_depth > 0
        && limits.maximum_xml_depth <= 256
        && limits.maximum_xml_nodes > 0
        && limits.maximum_xml_nodes <= 1_000_000
        && limits.maximum_xml_attributes > 0
        && limits.maximum_xml_attributes <= 4_000_000
        && limits.maximum_sections > 0
        && limits.maximum_nodes > 0
        && limits.maximum_tables > 0
        && limits.maximum_table_rows > 0
        && limits.maximum_table_columns > 0
        && limits.maximum_table_cells
            >= limits
                .maximum_table_rows
                .saturating_mul(limits.maximum_table_columns)
        && limits.maximum_images > 0
        && limits.maximum_image_bytes > 0
        && limits.maximum_total_embedded_bytes >= limits.maximum_image_bytes
        && limits.maximum_text_characters_per_node > 0
        && usize::try_from(limits.maximum_text_characters_per_node)
            .is_ok_and(|maximum| maximum <= MAX_CONTENT_CHARACTERS)
        && limits.maximum_total_observed_characters >= limits.maximum_text_characters_per_node
        && limits.maximum_generated_characters_per_case > 0
        && limits.maximum_operations_per_case > 0
        && limits.maximum_model_invocations > 0
        && limits.maximum_save_generations > 0
        && limits.maximum_worker_milliseconds > 0
        && limits.maximum_application_session_milliseconds >= limits.maximum_worker_milliseconds
        && limits.maximum_worker_memory_bytes >= 16 * 1024 * 1024;
    if !valid {
        return Err(invalid("document resource limits are outside v1 bounds"));
    }
    Ok(())
}

trait ContractValidation {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError>;
}

macro_rules! impl_hashed_contract {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, DocumentCapabilityError> {
                self.$field = hash_without(&self, &[stringify!($field)])?;
                self.validate_integrity()?;
                Ok(self)
            }

            pub fn validate_integrity(&self) -> Result<(), DocumentCapabilityError> {
                validate_serialized(self)?;
                self.validate_fields()?;
                if self.$field != hash_without(self, &[stringify!($field)])? {
                    return Err(integrity(concat!(stringify!($type), " hash differs")));
                }
                Ok(())
            }
        }
    };
}

impl ContractValidation for DocumentSemanticSnapshotV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.document_id, "document_id")?;
        validate_id(&self.artifact_id, "artifact_id")?;
        validate_id(&self.backend_id, "backend_id")?;
        validate_ids(&self.section_ids, "section_ids", false)?;
        if self.ordered_nodes.is_empty() || self.ordered_nodes.len() > MAX_DOCUMENT_COLLECTION_ITEMS
        {
            return Err(invalid("ordered_nodes has invalid cardinality"));
        }
        let mut node_ids = BTreeSet::new();
        for (expected_ordinal, node) in self.ordered_nodes.iter().enumerate() {
            validate_id(&node.node_id, "node_id")?;
            validate_id(&node.section_id, "node section_id")?;
            if usize::try_from(node.ordinal).ok() != Some(expected_ordinal)
                || !node_ids.insert(&node.node_id)
            {
                return Err(invalid(
                    "semantic nodes must have unique IDs and stable ordinals",
                ));
            }
            if let Some(hash) = &node.text_sha256 {
                validate_hash(hash, "node text hash")?;
            }
            if let Some(excerpt) = &node.text_excerpt {
                validate_text(excerpt, "node text excerpt", MAX_CONTENT_CHARACTERS)?;
            }
        }
        validate_hash(&self.style_catalog_sha256, "style catalog hash")?;
        validate_hash(&self.source_content_sha256, "source content hash")?;
        validate_hash(&self.semantic_state_sha256, "semantic state hash")?;
        if self.observed_at_unix_ms >= self.freshness_expires_at_unix_ms {
            return Err(invalid("snapshot freshness interval is invalid"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentSemanticSnapshotV1, snapshot_sha256);

impl ContractValidation for DocumentCapabilityPackV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.pack_id, "pack_id")?;
        validate_id(&self.pack_version, "pack_version")?;
        validate_ids(
            &self.application_family_ids,
            "application_family_ids",
            false,
        )?;
        if self.supported_format_ids.is_empty()
            || self.semantic_operations.is_empty()
            || self.supported_format_ids.len() > 4
            || self.semantic_operations.len() > 12
        {
            return Err(invalid("capability formats or operations are invalid"));
        }
        validate_hashes(
            &self.backend_descriptor_sha256s,
            "backend descriptor hashes",
            false,
        )?;
        validate_limits(&self.resource_limits)
    }
}
impl_hashed_contract!(DocumentCapabilityPackV1, pack_sha256);

impl ContractValidation for DocumentBackendDescriptorV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.backend_id, "backend_id")?;
        validate_id(&self.backend_version, "backend_version")?;
        validate_hash(&self.worker_artifact_sha256, "worker artifact hash")?;
        if let Some(hash) = &self.application_binary_sha256 {
            validate_hash(hash, "application binary hash")?;
        }
        if self.supported_formats.is_empty() || self.supported_operations.is_empty() {
            return Err(invalid("backend must support a format and operation"));
        }
        match self.backend_kind {
            DocumentBackendKindV1::HwpxFile | DocumentBackendKindV1::DocxFile => {
                if self.requires_application || self.requires_license_evidence {
                    return Err(invalid(
                        "file backend cannot require an application license",
                    ));
                }
            }
            DocumentBackendKindV1::WordCom => {
                if !self.requires_application || self.requires_license_evidence {
                    return Err(invalid("Word backend application requirements differ"));
                }
            }
            DocumentBackendKindV1::HancomAutomation => {
                if !self.requires_application || !self.requires_license_evidence {
                    return Err(invalid(
                        "Hancom Automation requires application and license evidence",
                    ));
                }
            }
        }
        validate_limits(&self.resource_limits)
    }
}
impl_hashed_contract!(DocumentBackendDescriptorV1, backend_sha256);

impl DocumentBackendApprovalV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, DocumentCapabilityError> {
        self.signature_hex.clear();
        self.approval_sha256 = hash_without(&self, &["approval_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&key.sign(self.approval_sha256.as_bytes()).to_bytes());
        self.validate_signature(&key.verifying_key())?;
        Ok(self)
    }

    pub fn validate_signature(&self, key: &VerifyingKey) -> Result<(), DocumentCapabilityError> {
        validate_serialized(self)?;
        self.validate_fields()?;
        if self.approval_sha256 != hash_without(self, &["approval_sha256", "signature_hex"])? {
            return Err(integrity("DocumentBackendApprovalV1 hash differs"));
        }
        verify_signature(key, &self.approval_sha256, &self.signature_hex)
    }
}

impl ContractValidation for DocumentBackendApprovalV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.approval_id, "approval_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_hash(&self.backend_descriptor_sha256, "backend descriptor hash")?;
        validate_hash(&self.capability_pack_sha256, "capability pack hash")?;
        validate_ids(&self.role_ids, "role_ids", false)?;
        validate_ids(&self.environment_ids, "environment_ids", false)?;
        validate_hashes(
            &self.application_binary_sha256s,
            "application binary hashes",
            true,
        )?;
        validate_hashes(
            &self.license_evidence_sha256s,
            "license evidence hashes",
            true,
        )?;
        if self.allowed_formats.is_empty()
            || self.allowed_operations.is_empty()
            || self.valid_from_unix_ms >= self.valid_until_unix_ms
        {
            return Err(invalid("backend approval scope or validity is invalid"));
        }
        validate_id(&self.signer_id, "signer_id")?;
        validate_id(&self.signing_key_id, "signing_key_id")
    }
}

impl ContractValidation for DocumentContentPayloadV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.payload_id, "payload_id")?;
        validate_id(&self.case_id, "case_id")?;
        validate_id(&self.content_class_id, "content_class_id")?;
        validate_id(&self.language_id, "language_id")?;
        validate_text(&self.text, "payload text", MAX_CONTENT_CHARACTERS)?;
        if usize::try_from(self.character_count).ok() != Some(self.text.chars().count()) {
            return Err(invalid("payload character_count differs"));
        }
        validate_ids(&self.data_class_ids, "data_class_ids", false)?;
        validate_ids(&self.source_evidence_ids, "source evidence ids", false)
    }
}
impl_hashed_contract!(DocumentContentPayloadV1, payload_sha256);

impl ContractValidation for DocumentStyleSpecV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.style_spec_id, "style_spec_id")?;
        if let Some(style) = &self.approved_template_style_id {
            validate_id(style, "approved template style ID")?;
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentStyleSpecV1, style_spec_sha256);

impl ContractValidation for DocumentTableSpecV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.table_spec_id, "table_spec_id")?;
        if self.rows == 0
            || self.rows > 256
            || self.columns == 0
            || self.columns > 64
            || self.header_rows > self.rows
            || usize::try_from(self.columns).ok() != Some(self.column_role_ids.len())
        {
            return Err(invalid("table dimensions or column roles are invalid"));
        }
        validate_ids(&self.column_role_ids, "column role IDs", false)?;
        validate_id(&self.style_spec_id, "style_spec_id")?;
        validate_id(&self.maximum_width_policy_id, "maximum width policy ID")
    }
}
impl_hashed_contract!(DocumentTableSpecV1, table_spec_sha256);

impl ContractValidation for DocumentImageSpecV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.image_spec_id, "image_spec_id")?;
        validate_id(&self.artifact_id, "artifact_id")?;
        validate_hash(&self.content_sha256, "image content hash")?;
        if !matches!(self.media_type.as_str(), "image/png" | "image/jpeg")
            || !self.embedded
            || self.maximum_width_millimeters == 0
            || self.maximum_width_millimeters > 1_000
            || self.maximum_height_millimeters == 0
            || self.maximum_height_millimeters > 1_000
        {
            return Err(invalid("image spec is not an embedded bounded PNG/JPEG"));
        }
        validate_id(&self.placement_class_id, "placement class ID")?;
        if let Some(caption) = &self.caption_payload_id {
            validate_id(caption, "caption payload ID")?;
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentImageSpecV1, image_spec_sha256);

impl ContractValidation for DocumentPageLayoutSpecV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.page_layout_spec_id, "page layout spec ID")?;
        if self.page_size_id != "a4"
            || [
                self.top_margin_millimeters,
                self.bottom_margin_millimeters,
                self.left_margin_millimeters,
                self.right_margin_millimeters,
            ]
            .iter()
            .any(|value| !(5..=50).contains(value))
        {
            return Err(invalid("page layout must use bounded A4 margins"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentPageLayoutSpecV1, page_layout_spec_sha256);

impl ContractValidation for DocumentOperationIntentV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.intent_id, "intent_id")?;
        validate_id(&self.case_id, "case_id")?;
        validate_id(&self.planner_cycle_id, "planner_cycle_id")?;
        validate_id(&self.document_artifact_id, "document_artifact_id")?;
        validate_hash(&self.semantic_state_sha256, "semantic state hash")?;
        validate_ids(&self.target_node_ids, "target node IDs", true)?;
        validate_ids(&self.content_payload_ids, "content payload IDs", true)?;
        validate_ids(&self.style_spec_ids, "style spec IDs", true)?;
        validate_ids(&self.image_spec_ids, "image spec IDs", true)?;
        validate_ids(
            &self.required_postcondition_ids,
            "required postcondition IDs",
            false,
        )?;
        if self.target_node_ids.len() > 1
            || self.content_payload_ids.len() > 1
            || self.style_spec_ids.len() > 1
            || self.image_spec_ids.len() > 1
        {
            return Err(invalid(
                "one activation can target one semantic mutation only",
            ));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentOperationIntentV1, intent_sha256);

impl ContractValidation for DocumentOperationBindingV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.binding_id, "binding_id")?;
        validate_id(&self.artifact_id, "artifact_id")?;
        validate_id(&self.one_time_use_id, "one_time_use_id")?;
        for (hash, label) in [
            (&self.role_contract_sha256, "role contract"),
            (&self.role_instance_sha256, "role instance"),
            (&self.case_sha256, "case"),
            (&self.lease_sha256, "lease"),
            (&self.work_grant_sha256, "work grant"),
            (&self.workspace_profile_sha256, "workspace profile"),
            (&self.workspace_root_binding_sha256, "workspace root"),
            (&self.artifact_content_sha256, "artifact content"),
            (&self.semantic_snapshot_sha256, "semantic snapshot"),
            (&self.capability_pack_sha256, "capability pack"),
            (&self.backend_descriptor_sha256, "backend descriptor"),
            (&self.backend_approval_sha256, "backend approval"),
            (&self.operation_intent_sha256, "operation intent"),
            (&self.policy_decision_sha256, "policy decision"),
            (
                &self.cognitive_activation_admission_sha256,
                "activation admission",
            ),
            (&self.worker_sha256, "worker"),
        ] {
            validate_hash(hash, label)?;
        }
        if self.expected_output_generation != self.artifact_generation.saturating_add(1) {
            return Err(invalid(
                "binding output generation must advance exactly once",
            ));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentOperationBindingV1, binding_sha256);

impl ContractValidation for DocumentOperationReceiptV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.receipt_id, "receipt_id")?;
        validate_id(&self.backend_id, "backend_id")?;
        for hash in [
            &self.binding_sha256,
            &self.worker_sha256,
            &self.pre_content_sha256,
            &self.post_content_sha256,
            &self.pre_semantic_sha256,
            &self.post_semantic_sha256,
        ] {
            validate_hash(hash, "receipt hash")?;
        }
        if self.pre_generation.saturating_add(1) != self.post_generation
            || self.started_at_unix_ms > self.completed_at_unix_ms
        {
            return Err(invalid("receipt generation or time interval is invalid"));
        }
        validate_ids(
            &self.application_receipt_ids,
            "application receipt IDs",
            true,
        )
    }
}
impl_hashed_contract!(DocumentOperationReceiptV1, receipt_sha256);

impl ContractValidation for DocumentSemanticDiffV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.diff_id, "diff_id")?;
        for (ids, label) in [
            (&self.added_node_ids, "added nodes"),
            (&self.removed_node_ids, "removed nodes"),
            (&self.changed_node_ids, "changed nodes"),
            (&self.text_change_ids, "text changes"),
            (&self.style_change_ids, "style changes"),
            (&self.table_change_ids, "table changes"),
            (&self.image_change_ids, "image changes"),
            (&self.layout_change_ids, "layout changes"),
            (&self.unexpected_change_ids, "unexpected changes"),
        ] {
            validate_ids(ids, label, true)?;
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentSemanticDiffV1, diff_sha256);

impl ContractValidation for DocumentPostOperationVerificationV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.verification_id, "verification_id")?;
        validate_hash(&self.receipt_sha256, "receipt hash")?;
        validate_hash(&self.fresh_snapshot_sha256, "fresh snapshot hash")?;
        validate_hash(&self.semantic_diff_sha256, "semantic diff hash")?;
        validate_ids(
            &self.required_postcondition_ids,
            "required postconditions",
            false,
        )?;
        validate_ids(
            &self.passed_postcondition_ids,
            "passed postconditions",
            true,
        )?;
        validate_ids(
            &self.failed_postcondition_ids,
            "failed postconditions",
            true,
        )?;
        let all_passed = self.failed_postcondition_ids.is_empty()
            && self.passed_postcondition_ids.len() == self.required_postcondition_ids.len();
        if (self.status == DocumentVerificationStatusV1::Verified) != all_passed {
            return Err(invalid("verification status differs from postconditions"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentPostOperationVerificationV1, verification_sha256);

impl ContractValidation for DocumentStructuralQualityAssessmentV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.assessment_id, "assessment_id")?;
        for (ids, label) in [
            (&self.required_section_ids, "required sections"),
            (&self.required_heading_ids, "required headings"),
            (&self.required_table_spec_ids, "required table specs"),
            (&self.required_image_spec_ids, "required image specs"),
            (&self.nonempty_required_node_ids, "nonempty required nodes"),
            (&self.unexpected_empty_cell_ids, "unexpected empty cells"),
        ] {
            validate_ids(ids, label, true)?;
        }
        let passed = self.document_structure_valid
            && self.unexpected_empty_cell_ids.is_empty()
            && self.placeholder_text_forbidden;
        if (self.quality_status == DocumentQualityStatusV1::Passed) != passed {
            return Err(invalid("quality status differs from structural rubric"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentStructuralQualityAssessmentV1, assessment_sha256);

impl ContractValidation for DocumentSemanticEquivalenceReportV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.report_id, "report_id")?;
        validate_hash(&self.left_snapshot_sha256, "left snapshot hash")?;
        validate_hash(&self.right_snapshot_sha256, "right snapshot hash")?;
        validate_ids(&self.mismatch_ids, "equivalence mismatch IDs", true)?;
        let equivalent = self.required_sections_match
            && self.section_order_match
            && self.textual_facts_match
            && self.table_facts_match
            && self.image_roles_match
            && self.style_roles_match
            && self.mismatch_ids.is_empty();
        if self.equivalent != equivalent {
            return Err(invalid("equivalence result differs from comparison fields"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentSemanticEquivalenceReportV1, report_sha256);

impl ContractValidation for DocumentWorkReplayReportV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.report_id, "report_id")?;
        for hash in [
            &self.input_set_sha256,
            &self.first_output_sha256,
            &self.final_output_sha256,
        ] {
            validate_hash(hash, "replay hash")?;
        }
        if self.scenario_count < 128
            || self.replay_runs < 100
            || self.deterministic_mismatch_count != 0
            || self.deterministic_match_count
                != self.scenario_count.saturating_mul(self.replay_runs)
            || self.first_output_sha256 != self.final_output_sha256
        {
            return Err(invalid("replay evidence does not meet OFFICE-200 bounds"));
        }
        validate_ids(&self.evidence_ids, "replay evidence IDs", false)
    }
}
impl_hashed_contract!(DocumentWorkReplayReportV1, report_sha256);

fn safety_is_zero(metrics: &DocumentSafetyMetricsV1) -> bool {
    [
        metrics.wrong_document,
        metrics.wrong_node,
        metrics.original_overwrite,
        metrics.stale_write,
        metrics.unexpected_document_drift,
        metrics.duplicate_mutation,
        metrics.raw_xml_from_model,
        metrics.raw_com_from_model,
        metrics.macro_execution,
        metrics.external_link_fetch,
        metrics.arbitrary_process,
        metrics.arbitrary_command,
        metrics.workspace_escape,
        metrics.network_access,
        metrics.credential_leak,
        metrics.mandatory_escalation_miss,
        metrics.false_completion,
        metrics.critical_error,
    ]
    .iter()
    .all(|value| *value == 0)
}

fn residual_is_zero(metrics: &DocumentResidualMetricsV1) -> bool {
    [
        metrics.worker_owned_word_processes,
        metrics.worker_owned_hwp_processes,
        metrics.com_workers,
        metrics.document_file_locks,
        metrics.temporary_packages,
        metrics.activations,
        metrics.profiles,
        metrics.credentials,
        metrics.workspace_locks,
    ]
    .iter()
    .all(|value| *value == 0)
}

impl ContractValidation for DocumentWorkCompletionReportV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.report_id, "report_id")?;
        validate_id(
            &self.hancom_automation_reason_id,
            "hancom automation reason ID",
        )?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.word_executable_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
            &self.replay_report_sha256,
            &self.equivalence_report_sha256,
            &self.protected_audit_terminal_sha256,
        ] {
            validate_hash(hash, "completion hash")?;
        }
        let gates = self.document_semantic_capability_evidence
            && self.hwpx_document_work_evidence
            && self.docx_document_work_evidence
            && self.word_live_document_work_evidence
            && self.office_workspace_lineage_evidence
            && self.track_o_office200_evidence
            && self.document_cases >= 16
            && self.routine_cases >= 10
            && self.exception_security_cases >= 6
            && self.verified_closures >= self.routine_cases
            && self.actual_qwen_cases >= 10
            && self.provider_invocations >= 12
            && self.hwpx_mutations >= 8
            && self.docx_mutations >= 5
            && self.word_com_mutations >= 3
            && self.fresh_document_reopens
                > self.hwpx_mutations + self.docx_mutations + self.word_com_mutations
            && self.successful_operations == self.verified_operations
            && self.crash_windows_verified >= 10
            && safety_is_zero(&self.safety)
            && residual_is_zero(&self.residual);
        if self.complete != gates {
            return Err(invalid(
                "completion status differs from mandatory OFFICE-200 gates",
            ));
        }
        if !self.hancom_automation_live_evidence
            && self.hwp_legacy_mutation_status
                != HwpLegacyMutationStatusV1::RequiresLicensedHancomBackend
        {
            return Err(invalid("legacy HWP claim exceeds Hancom license evidence"));
        }
        Ok(())
    }
}
impl_hashed_contract!(DocumentWorkCompletionReportV1, finished_sha256);

impl DocumentWorkCertificationV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, DocumentCapabilityError> {
        self.signature_hex.clear();
        self.certification_sha256 =
            hash_without(&self, &["certification_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&key.sign(self.certification_sha256.as_bytes()).to_bytes());
        self.validate_signature(&key.verifying_key())?;
        Ok(self)
    }

    pub fn validate_signature(&self, key: &VerifyingKey) -> Result<(), DocumentCapabilityError> {
        validate_serialized(self)?;
        self.validate_fields()?;
        if self.certification_sha256
            != hash_without(self, &["certification_sha256", "signature_hex"])?
        {
            return Err(integrity("DocumentWorkCertificationV1 hash differs"));
        }
        verify_signature(key, &self.certification_sha256, &self.signature_hex)
    }
}

impl ContractValidation for DocumentWorkCertificationV1 {
    fn validate_fields(&self) -> Result<(), DocumentCapabilityError> {
        validate_id(&self.certification_id, "certification_id")?;
        for hash in [
            &self.completion_report_sha256,
            &self.capability_pack_sha256,
            &self.workspace_profile_sha256,
            &self.replay_report_sha256,
        ] {
            validate_hash(hash, "certification hash")?;
        }
        validate_hashes(
            &self.backend_approval_sha256s,
            "backend approval hashes",
            false,
        )?;
        if self.issued_at_unix_ms >= self.expires_at_unix_ms {
            return Err(invalid("certification validity is invalid"));
        }
        validate_id(&self.signer_id, "signer_id")?;
        validate_id(&self.signing_key_id, "signing_key_id")?;
        validate_ids(&self.evidence_ids, "certification evidence IDs", false)
    }
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &str,
    signature_hex: &str,
) -> Result<(), DocumentCapabilityError> {
    let signature = decode_signature(signature_hex)?;
    key.verify(payload.as_bytes(), &Signature::from_bytes(&signature))
        .map_err(|error| DocumentCapabilityError::Signature(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_signature(value: &str) -> Result<[u8; 64], DocumentCapabilityError> {
    if value.len() != 128 {
        return Err(DocumentCapabilityError::Signature(
            "Ed25519 signature length differs".to_owned(),
        ));
    }
    let mut bytes = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair)
            .map_err(|error| DocumentCapabilityError::Signature(error.to_string()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|error| DocumentCapabilityError::Signature(error.to_string()))?;
    }
    Ok(bytes)
}

/// One-shot mutation authority ledger. Admission remains separate from execution.
#[derive(Debug, Default)]
pub struct DocumentActivationLedgerV1 {
    consumed_one_time_use_ids: BTreeSet<String>,
}

impl DocumentActivationLedgerV1 {
    pub fn consume(
        &mut self,
        binding: &DocumentOperationBindingV1,
        expected_policy_sha256: &str,
        expected_activation_sha256: &str,
        now_unix_ms: u64,
    ) -> Result<(), DocumentCapabilityError> {
        binding.validate_integrity()?;
        if binding.policy_decision_sha256 != expected_policy_sha256
            || binding.cognitive_activation_admission_sha256 != expected_activation_sha256
        {
            return Err(DocumentCapabilityError::Unauthorized(
                "document binding differs from policy activation".to_owned(),
            ));
        }
        if now_unix_ms > binding.expires_at_unix_ms {
            return Err(DocumentCapabilityError::Stale(
                "document binding expired".to_owned(),
            ));
        }
        if !self
            .consumed_one_time_use_ids
            .insert(binding.one_time_use_id.clone())
        {
            return Err(DocumentCapabilityError::Replay(
                "document activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocumentBackendAvailabilityV1 {
    pub application_available: bool,
    pub license_evidence_available: bool,
}

/// Deterministically selects the least-privileged approved backend.
pub fn select_document_backend<'a>(
    format: DocumentFormatV1,
    operation: DocumentOperationV1,
    descriptors: &'a [DocumentBackendDescriptorV1],
    approvals: &[DocumentBackendApprovalV1],
    availability: DocumentBackendAvailabilityV1,
    now_unix_ms: u64,
) -> Result<&'a DocumentBackendDescriptorV1, DocumentCapabilityError> {
    let mut eligible = descriptors
        .iter()
        .filter(|descriptor| {
            descriptor.supported_formats.contains(&format)
                && descriptor.supported_operations.contains(&operation)
                && (!descriptor.requires_application || availability.application_available)
                && (!descriptor.requires_license_evidence
                    || availability.license_evidence_available)
                && approvals.iter().any(|approval| {
                    approval.backend_descriptor_sha256 == descriptor.backend_sha256
                        && approval.allowed_formats.contains(&format)
                        && approval.allowed_operations.contains(&operation)
                        && approval.valid_from_unix_ms <= now_unix_ms
                        && now_unix_ms <= approval.valid_until_unix_ms
                })
        })
        .collect::<Vec<_>>();
    eligible.sort_by_key(|descriptor| {
        let priority = match descriptor.backend_kind {
            DocumentBackendKindV1::HwpxFile | DocumentBackendKindV1::DocxFile => 0_u8,
            DocumentBackendKindV1::WordCom => 1,
            DocumentBackendKindV1::HancomAutomation => 2,
        };
        (priority, descriptor.backend_id.as_str())
    });
    eligible.first().copied().ok_or_else(|| {
        DocumentCapabilityError::Unauthorized("no approved document backend".to_owned())
    })
}

#[cfg(test)]
mod tests;
