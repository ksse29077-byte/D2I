use crate::strict::{canonical_json_bytes, hash_without};
use crate::{
    WorkIntakeError, MAX_CYCLE_LOGICAL_OPERATIONS, MAX_EVENTS_PER_CYCLE, MAX_EVIDENCE,
    MAX_ID_LENGTH, MAX_RECORD_BYTES, MAX_REFERENCES, WORK_INTAKE_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{
    ObservationSourceKindV1, RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1,
    RoleInstanceV1,
};
use d2i_work_case::{
    WorkApplicationPackRefV1, WorkItemAdmissionDecisionV1, WorkItemDeduplicationResultV1,
    WorkPriorityClassV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const MAX_SOURCE_APPROVAL_TTL_SECONDS: u64 = 31_536_000;

/// Closed cursor handling. Every source still supplies a monotonic sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RadarCursorPolicyV1 {
    SequenceOnly,
    OpaqueCursorWithSequence,
}

/// Finite source and cycle budget. Retries are structurally disabled in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarResourceLimitsV1 {
    pub maximum_events_per_cycle: u32,
    pub maximum_subject_refs_per_event: u32,
    pub maximum_structured_input_refs_per_event: u32,
    pub maximum_attachment_refs_per_event: u32,
    pub maximum_evidence_ids_per_event: u32,
    pub maximum_trust_labels_per_event: u32,
    pub maximum_event_id_bytes: u32,
    pub maximum_record_bytes: u64,
    pub maximum_output_bytes: u64,
    pub maximum_receipts_per_cycle: u32,
    pub maximum_ledger_records: u64,
    pub maximum_logical_operations: u64,
    pub maximum_ticks: u64,
    pub maximum_retries: u32,
    pub maximum_concurrent_requests: u32,
}

impl RadarResourceLimitsV1 {
    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        let bounded_refs = [
            self.maximum_subject_refs_per_event,
            self.maximum_structured_input_refs_per_event,
            self.maximum_attachment_refs_per_event,
            self.maximum_trust_labels_per_event,
        ]
        .into_iter()
        .all(|value| value <= MAX_REFERENCES as u32);
        if self.maximum_events_per_cycle == 0
            || self.maximum_events_per_cycle > MAX_EVENTS_PER_CYCLE as u32
            || !bounded_refs
            || self.maximum_evidence_ids_per_event == 0
            || self.maximum_evidence_ids_per_event > MAX_EVIDENCE as u32
            || self.maximum_event_id_bytes == 0
            || self.maximum_event_id_bytes > MAX_ID_LENGTH as u32
            || self.maximum_record_bytes == 0
            || self.maximum_record_bytes > MAX_RECORD_BYTES
            || self.maximum_output_bytes == 0
            || self.maximum_output_bytes > MAX_RECORD_BYTES
            || self.maximum_receipts_per_cycle == 0
            || self.maximum_receipts_per_cycle > self.maximum_events_per_cycle
            || self.maximum_ledger_records == 0
            || self.maximum_ledger_records > 65_536
            || self.maximum_logical_operations == 0
            || self.maximum_logical_operations > MAX_CYCLE_LOGICAL_OPERATIONS
            || self.maximum_ticks == 0
            || self.maximum_ticks > MAX_CYCLE_LOGICAL_OPERATIONS
            || self.maximum_retries != 0
            || self.maximum_concurrent_requests != 1
        {
            return invalid("Radar resource limits exceed the closed v1 bounds");
        }
        Ok(())
    }
}

/// Approved, Role-bound registration for one read-only observation source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedRadarSourceRegistrationV1 {
    pub schema_version: u32,
    pub registration_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub approval_sha256: String,
    pub delegation_sha256: String,
    pub observation_source_id: String,
    pub source_kind: ObservationSourceKindV1,
    pub integration_id: String,
    pub application_pack_ref: Option<WorkApplicationPackRefV1>,
    pub allowed_event_class_ids: Vec<String>,
    pub minimum_trust_label: String,
    pub maximum_staleness_seconds: u64,
    pub cursor_policy: RadarCursorPolicyV1,
    pub maximum_sequence_advance: u64,
    pub resource_limits: RadarResourceLimitsV1,
    pub enabled: bool,
    pub evidence_ids: Vec<String>,
    pub registration_sha256: String,
}

impl ApprovedRadarSourceRegistrationV1 {
    /// Canonically seals an exact subset of one immutable Role source.
    pub fn seal_against(
        mut self,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
    ) -> Result<Self, WorkIntakeError> {
        normalize_ids(
            &mut self.allowed_event_class_ids,
            "allowed event classes",
            false,
        )?;
        normalize_ids(&mut self.evidence_ids, "registration evidence", false)?;
        self.registration_sha256 = hash_without(&self, &["registration_sha256"])?;
        self.validate_against(contract, delegation, instance)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || !self.enabled
            || self.maximum_staleness_seconds == 0
            || self.maximum_sequence_advance == 0
            || self.maximum_sequence_advance > 1_024
        {
            return invalid("registration schema, state, freshness, or gap policy is invalid");
        }
        for (value, label) in [
            (&self.registration_id, "registration ID"),
            (&self.organization_id, "registration organization"),
            (&self.role_contract_id, "registration Role Contract"),
            (&self.role_instance_id, "registration Role Instance"),
            (
                &self.observation_source_id,
                "registration observation source",
            ),
            (&self.integration_id, "registration integration"),
            (&self.minimum_trust_label, "registration trust floor"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.role_contract_sha256,
                "registration Role Contract hash",
            ),
            (
                &self.role_instance_sha256,
                "registration Role Instance hash",
            ),
            (&self.approval_sha256, "registration approval hash"),
            (&self.delegation_sha256, "registration delegation hash"),
            (&self.registration_sha256, "registration hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_ids(
            &self.allowed_event_class_ids,
            "allowed event classes",
            false,
        )?;
        validate_ids(&self.evidence_ids, "registration evidence", false)?;
        if let Some(reference) = &self.application_pack_ref {
            validate_application_ref(reference)?;
        }
        self.resource_limits.validate()?;
        if hash_without(self, &["registration_sha256"])? != self.registration_sha256 {
            return integrity("registration canonical hash differs");
        }
        reject_sensitive(self, "registration")
    }

    pub fn validate_against(
        &self,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
        instance: &RoleInstanceV1,
    ) -> Result<(), WorkIntakeError> {
        self.validate()?;
        contract.validate()?;
        instance.validate_shape()?;
        let source = contract
            .observation_sources
            .iter()
            .find(|source| source.observation_source_id == self.observation_source_id)
            .ok_or_else(|| WorkIntakeError::NotAdmissible("Role source is absent".to_owned()))?;
        let expected_pack = match &source.application_pack_id {
            Some(id) => {
                let binding = contract
                    .application_bindings
                    .iter()
                    .find(|binding| binding.application_pack_id == *id)
                    .ok_or_else(|| {
                        WorkIntakeError::Integrity("Role source pack binding is absent".to_owned())
                    })?;
                Some(WorkApplicationPackRefV1 {
                    application_pack_id: binding.application_pack_id.clone(),
                    application_pack_sha256: binding.application_pack_sha256.clone(),
                })
            }
            None => None,
        };
        if !source.enabled
            || !source.read_only
            || self.organization_id != contract.organization_scope.organization_id
            || self.organization_id != delegation.organization_id
            || self.organization_id != instance.organization_id
            || self.role_contract_id != contract.role_contract_id
            || self.role_contract_sha256 != contract.contract_sha256
            || self.role_instance_id != instance.role_instance_id
            || self.role_instance_sha256 != instance.instance_sha256
            || self.approval_sha256 != instance.approval_sha256
            || self.delegation_sha256 != delegation.delegation_sha256
            || self.delegation_sha256 != instance.delegation_sha256
            || self.source_kind != source.source_kind
            || self.integration_id != source.integration_id
            || self.application_pack_ref != expected_pack
            || self.allowed_event_class_ids != source.event_class_ids
            || self.minimum_trust_label != source.trust_floor
            || self.maximum_staleness_seconds != source.maximum_staleness_seconds
            || !delegation
                .delegated_integration_ids
                .contains(&self.integration_id)
            || self.application_pack_ref.as_ref().is_some_and(|reference| {
                !delegation
                    .delegated_application_pack_ids
                    .contains(&reference.application_pack_id)
            })
        {
            return Err(WorkIntakeError::NotAdmissible(
                "registration differs from the exact read-only Role source".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Signed organizational approval for one exact Radar source registration.
///
/// This artifact grants observation only. It carries no network credential,
/// execution permit, policy authority, or checkpoint mutation authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSourceApprovalV1 {
    pub schema_version: u32,
    pub source_approval_id: String,
    pub organization_id: String,
    pub role_contract_id: String,
    pub role_contract_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub role_approval_sha256: String,
    pub delegation_sha256: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub approved_by_actor_id: String,
    pub signer_key_id: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub approval_signature: String,
    pub source_approval_sha256: String,
}

/// Seals and signs an exact source-registration approval.
pub fn create_work_source_approval(
    mut approval: WorkSourceApprovalV1,
    registration: &ApprovedRadarSourceRegistrationV1,
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    signing_key: &SigningKey,
) -> Result<WorkSourceApprovalV1, WorkIntakeError> {
    registration.validate_against(contract, delegation, instance)?;
    normalize_ids(
        &mut approval.evidence_ids,
        "source approval evidence",
        false,
    )?;
    approval.approval_signature = "00".repeat(64);
    approval.source_approval_sha256 = hash_without(&approval, &["source_approval_sha256"])?;
    approval.validate_against(registration)?;
    approval.approval_signature =
        hex_encode(&signing_key.sign(&approval.signing_bytes()?).to_bytes());
    approval.source_approval_sha256 = hash_without(&approval, &["source_approval_sha256"])?;
    approval.validate_against(registration)?;
    Ok(approval)
}

/// Verifies source approval identity, exact registration binding, lifetime,
/// signer identity, and Ed25519 signature before a Radar scan may begin.
pub fn verify_work_source_approval(
    approval: &WorkSourceApprovalV1,
    registration: &ApprovedRadarSourceRegistrationV1,
    expected_signer_key_id: &str,
    verifying_key: &VerifyingKey,
    now_unix_seconds: u64,
) -> Result<(), WorkIntakeError> {
    approval.validate_against(registration)?;
    validate_id(
        expected_signer_key_id,
        "expected source approval signer key ID",
    )?;
    if approval.signer_key_id != expected_signer_key_id {
        return integrity("source approval signer key ID differs");
    }
    if now_unix_seconds < approval.issued_at_unix_seconds
        || now_unix_seconds >= approval.expires_at_unix_seconds
    {
        return Err(WorkIntakeError::NotAdmissible(
            "source approval is not active".to_owned(),
        ));
    }
    let signature = Signature::from_bytes(&hex_decode_array::<64>(&approval.approval_signature)?);
    verifying_key
        .verify(&approval.signing_bytes()?, &signature)
        .map_err(|error| {
            WorkIntakeError::Integrity(format!("source approval signature rejected: {error}"))
        })
}

impl WorkSourceApprovalV1 {
    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.issued_at_unix_seconds == 0
            || self.expires_at_unix_seconds <= self.issued_at_unix_seconds
            || self
                .expires_at_unix_seconds
                .saturating_sub(self.issued_at_unix_seconds)
                > MAX_SOURCE_APPROVAL_TTL_SECONDS
        {
            return invalid("source approval schema or lifetime is invalid");
        }
        for (value, label) in [
            (&self.source_approval_id, "source approval ID"),
            (&self.organization_id, "source approval organization"),
            (&self.role_contract_id, "source approval Role Contract"),
            (&self.role_instance_id, "source approval Role Instance"),
            (&self.registration_id, "source approval registration"),
            (&self.approved_by_actor_id, "source approval actor"),
            (&self.signer_key_id, "source approval signer key ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (
                &self.role_contract_sha256,
                "source approval Role Contract hash",
            ),
            (
                &self.role_instance_sha256,
                "source approval Role Instance hash",
            ),
            (
                &self.role_approval_sha256,
                "source approval governance hash",
            ),
            (&self.delegation_sha256, "source approval delegation hash"),
            (
                &self.registration_sha256,
                "source approval registration hash",
            ),
            (&self.source_approval_sha256, "source approval hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_ids(&self.evidence_ids, "source approval evidence", false)?;
        if self.approval_signature.len() != 128
            || !self
                .approval_signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return invalid("source approval signature encoding is invalid");
        }
        if hash_without(self, &["source_approval_sha256"])? != self.source_approval_sha256 {
            return integrity("source approval canonical hash differs");
        }
        reject_sensitive(self, "source approval")
    }

    pub fn validate_against(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
    ) -> Result<(), WorkIntakeError> {
        self.validate()?;
        registration.validate()?;
        if self.organization_id != registration.organization_id
            || self.role_contract_id != registration.role_contract_id
            || self.role_contract_sha256 != registration.role_contract_sha256
            || self.role_instance_id != registration.role_instance_id
            || self.role_instance_sha256 != registration.role_instance_sha256
            || self.role_approval_sha256 != registration.approval_sha256
            || self.delegation_sha256 != registration.delegation_sha256
            || self.registration_id != registration.registration_id
            || self.registration_sha256 != registration.registration_sha256
        {
            return integrity("source approval does not bind the exact registration");
        }
        Ok(())
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, WorkIntakeError> {
        let mut value =
            serde_json::to_value(self).map_err(|error| WorkIntakeError::Json(error.to_string()))?;
        let object = value.as_object_mut().ok_or_else(|| {
            WorkIntakeError::Json("source approval payload is not an object".to_owned())
        })?;
        object.remove("approval_signature");
        object.remove("source_approval_sha256");
        canonical_json_bytes(&value)
    }
}

/// Hash-only source authentication provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSignalProvenanceV1 {
    pub authenticated_actor_id: String,
    pub authentication_class_id: String,
    pub authentication_evidence_sha256: String,
}

impl WorkSignalProvenanceV1 {
    fn validate(&self) -> Result<(), WorkIntakeError> {
        validate_id(&self.authenticated_actor_id, "signal actor")?;
        validate_id(&self.authentication_class_id, "signal authentication class")?;
        validate_hash(
            &self.authentication_evidence_sha256,
            "signal authentication evidence",
        )
    }
}

/// Immutable, typed, hash-only indication that approved work may exist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSignalV1 {
    pub schema_version: u32,
    pub signal_id: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub organization_id: String,
    pub role_instance_id: String,
    pub delegation_sha256: String,
    pub source_system_id: String,
    pub event_id: String,
    pub source_sequence: u64,
    pub source_cursor: Option<String>,
    pub event_class_id: String,
    pub observed_at_unix_seconds: u64,
    pub received_at_unix_seconds: u64,
    pub source_record_sha256: String,
    pub payload_reference_sha256: String,
    pub attachment_reference_hashes: Vec<String>,
    pub subject_refs: Vec<String>,
    pub structured_input_kind_ids: Vec<String>,
    pub structured_input_refs: Vec<String>,
    pub trust_labels: Vec<String>,
    pub provenance: WorkSignalProvenanceV1,
    pub semantic_payload_sha256: String,
    pub evidence_ids: Vec<String>,
    pub signal_sha256: String,
}

impl WorkSignalV1 {
    pub fn seal(mut self) -> Result<Self, WorkIntakeError> {
        normalize_hashes(
            &mut self.attachment_reference_hashes,
            "signal attachment references",
            true,
        )?;
        for values in [
            &mut self.subject_refs,
            &mut self.structured_input_kind_ids,
            &mut self.structured_input_refs,
            &mut self.trust_labels,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.signal_sha256 = hash_without(&self, &["signal_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.source_sequence == 0
            || self.observed_at_unix_seconds == 0
            || self.received_at_unix_seconds < self.observed_at_unix_seconds
        {
            return invalid("signal schema, sequence, or timestamps are invalid");
        }
        for (value, label) in [
            (&self.signal_id, "signal ID"),
            (&self.registration_id, "signal registration ID"),
            (&self.organization_id, "signal organization"),
            (&self.role_instance_id, "signal Role Instance"),
            (&self.source_system_id, "signal source system"),
            (&self.event_id, "signal event ID"),
            (&self.event_class_id, "signal event class"),
        ] {
            validate_id(value, label)?;
        }
        if let Some(cursor) = &self.source_cursor {
            validate_id(cursor, "signal cursor")?;
        }
        for (value, label) in [
            (&self.registration_sha256, "signal registration hash"),
            (&self.delegation_sha256, "signal delegation hash"),
            (&self.source_record_sha256, "signal source record hash"),
            (&self.payload_reference_sha256, "signal payload reference"),
            (&self.semantic_payload_sha256, "signal semantic payload"),
            (&self.signal_sha256, "signal hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_hashes(
            &self.attachment_reference_hashes,
            "signal attachment references",
            true,
        )?;
        validate_ids(&self.subject_refs, "signal subject refs", false)?;
        validate_ids(
            &self.structured_input_kind_ids,
            "signal structured input kinds",
            true,
        )?;
        validate_ids(
            &self.structured_input_refs,
            "signal structured input refs",
            true,
        )?;
        if self.structured_input_kind_ids.len() != self.structured_input_refs.len() {
            return invalid("signal structured input kind/ref cardinality differs");
        }
        validate_ids(&self.trust_labels, "signal trust labels", false)?;
        validate_ids(&self.evidence_ids, "signal evidence", false)?;
        self.provenance.validate()?;
        if hash_without(self, &["signal_sha256"])? != self.signal_sha256 {
            return integrity("signal canonical hash differs");
        }
        reject_sensitive(self, "signal")
    }

    pub fn validate_against(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
        now_unix_seconds: u64,
    ) -> Result<(), WorkIntakeError> {
        self.validate()?;
        registration.validate()?;
        let stale = now_unix_seconds < self.observed_at_unix_seconds
            || now_unix_seconds < self.received_at_unix_seconds
            || now_unix_seconds.saturating_sub(self.observed_at_unix_seconds)
                > registration.maximum_staleness_seconds;
        let cursor_valid = match registration.cursor_policy {
            RadarCursorPolicyV1::SequenceOnly => self.source_cursor.is_none(),
            RadarCursorPolicyV1::OpaqueCursorWithSequence => self.source_cursor.is_some(),
        };
        if self.registration_id != registration.registration_id
            || self.registration_sha256 != registration.registration_sha256
            || self.organization_id != registration.organization_id
            || self.role_instance_id != registration.role_instance_id
            || self.delegation_sha256 != registration.delegation_sha256
            || self.source_system_id != registration.observation_source_id
            || !registration
                .allowed_event_class_ids
                .contains(&self.event_class_id)
            || !self
                .trust_labels
                .contains(&registration.minimum_trust_label)
            || stale
            || !cursor_valid
            || self.event_id.len() > registration.resource_limits.maximum_event_id_bytes as usize
            || self.subject_refs.len()
                > registration.resource_limits.maximum_subject_refs_per_event as usize
            || self.structured_input_refs.len()
                > registration
                    .resource_limits
                    .maximum_structured_input_refs_per_event as usize
            || self.attachment_reference_hashes.len()
                > registration
                    .resource_limits
                    .maximum_attachment_refs_per_event as usize
            || self.evidence_ids.len()
                > registration.resource_limits.maximum_evidence_ids_per_event as usize
            || self.trust_labels.len()
                > registration.resource_limits.maximum_trust_labels_per_event as usize
        {
            return Err(WorkIntakeError::NotAdmissible(
                "signal is stale, untrusted, oversized, or outside registration".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Closed deterministic due-time derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DueTimeDerivationV1 {
    None,
    FixedOffsetFromReceived,
    CallerSupplied,
}

/// Exact event-to-Work-Item profile. It grants no authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIntakeMappingProfileV1 {
    pub schema_version: u32,
    pub mapping_id: String,
    pub mapping_version: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub observation_source_id: String,
    pub event_class_id: String,
    pub work_class_id: String,
    pub work_class_contract_version: String,
    pub requested_outcome_class_ids: Vec<String>,
    pub requested_evidence_class_ids: Vec<String>,
    pub priority_class: WorkPriorityClassV1,
    pub risk_class: CognitiveRiskClass,
    pub application_pack_refs: Vec<WorkApplicationPackRefV1>,
    pub integration_ids: Vec<String>,
    pub capability_requirement_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub deduplication_scope_id: String,
    pub required_trust_labels: Vec<String>,
    pub allowed_structured_input_kind_ids: Vec<String>,
    pub minimum_subject_refs: u32,
    pub minimum_structured_input_refs: u32,
    pub due_time_derivation: DueTimeDerivationV1,
    pub due_time_offset_seconds: Option<u64>,
    pub evidence_ids: Vec<String>,
    pub mapping_sha256: String,
}

impl WorkIntakeMappingProfileV1 {
    pub fn seal_against(
        mut self,
        registration: &ApprovedRadarSourceRegistrationV1,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
    ) -> Result<Self, WorkIntakeError> {
        self.application_pack_refs.sort();
        for values in [
            &mut self.requested_outcome_class_ids,
            &mut self.requested_evidence_class_ids,
            &mut self.integration_ids,
            &mut self.capability_requirement_ids,
            &mut self.semantic_target_ids,
            &mut self.required_trust_labels,
            &mut self.allowed_structured_input_kind_ids,
            &mut self.evidence_ids,
        ] {
            values.sort();
        }
        self.mapping_sha256 = hash_without(&self, &["mapping_sha256"])?;
        self.validate_against(registration, contract, delegation)?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.minimum_subject_refs == 0
            || self.minimum_subject_refs > MAX_REFERENCES as u32
            || self.minimum_structured_input_refs > MAX_REFERENCES as u32
        {
            return invalid("mapping schema or cardinality is invalid");
        }
        for (value, label) in [
            (&self.mapping_id, "mapping ID"),
            (&self.mapping_version, "mapping version"),
            (&self.registration_id, "mapping registration"),
            (&self.observation_source_id, "mapping source"),
            (&self.event_class_id, "mapping event class"),
            (&self.work_class_id, "mapping work class"),
            (
                &self.work_class_contract_version,
                "mapping work class version",
            ),
            (&self.deduplication_scope_id, "mapping deduplication scope"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(&self.registration_sha256, "mapping registration hash")?;
        validate_hash(&self.mapping_sha256, "mapping hash")?;
        for (values, label, allow_empty) in [
            (
                &self.requested_outcome_class_ids,
                "mapping outcome classes",
                false,
            ),
            (
                &self.requested_evidence_class_ids,
                "mapping evidence classes",
                false,
            ),
            (&self.integration_ids, "mapping integrations", false),
            (
                &self.capability_requirement_ids,
                "mapping capabilities",
                false,
            ),
            (&self.semantic_target_ids, "mapping semantic targets", false),
            (&self.required_trust_labels, "mapping trust labels", false),
            (
                &self.allowed_structured_input_kind_ids,
                "mapping structured input kinds",
                true,
            ),
            (&self.evidence_ids, "mapping evidence", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        if self.application_pack_refs.is_empty()
            || self.application_pack_refs.len() > MAX_REFERENCES
            || !self
                .application_pack_refs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return invalid("mapping Application Pack refs are invalid");
        }
        for reference in &self.application_pack_refs {
            validate_application_ref(reference)?;
        }
        match (self.due_time_derivation, self.due_time_offset_seconds) {
            (DueTimeDerivationV1::None | DueTimeDerivationV1::CallerSupplied, None) => {}
            (DueTimeDerivationV1::FixedOffsetFromReceived, Some(value))
                if value > 0 && value <= 31_536_000 => {}
            _ => return invalid("mapping due-time derivation is inconsistent"),
        }
        if hash_without(self, &["mapping_sha256"])? != self.mapping_sha256 {
            return integrity("mapping canonical hash differs");
        }
        reject_sensitive(self, "mapping")
    }

    pub fn validate_against(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
        contract: &RoleContractV1,
        delegation: &RoleDelegationGrantV1,
    ) -> Result<(), WorkIntakeError> {
        self.validate()?;
        registration.validate()?;
        let work = contract
            .accepted_work_classes
            .iter()
            .find(|work| work.work_class_id == self.work_class_id)
            .ok_or_else(|| {
                WorkIntakeError::NotAdmissible("mapping work class is absent".to_owned())
            })?;
        let responsibility = contract
            .responsibilities
            .iter()
            .find(|item| item.responsibility_id == work.responsibility_id)
            .ok_or_else(|| {
                WorkIntakeError::Integrity("mapping responsibility is absent".to_owned())
            })?;
        let binding = registration
            .application_pack_ref
            .as_ref()
            .and_then(|reference| {
                contract
                    .application_bindings
                    .iter()
                    .find(|binding| binding.application_pack_id == reference.application_pack_id)
            });
        let exact_pack = registration
            .application_pack_ref
            .as_ref()
            .map(|reference| vec![reference.clone()])
            .unwrap_or_default();
        if self.registration_id != registration.registration_id
            || self.registration_sha256 != registration.registration_sha256
            || self.observation_source_id != registration.observation_source_id
            || !registration
                .allowed_event_class_ids
                .contains(&self.event_class_id)
            || self.work_class_contract_version != work.contract_version
            || !work
                .permitted_observation_source_ids
                .contains(&registration.observation_source_id)
            || !delegation
                .delegated_work_class_ids
                .contains(&self.work_class_id)
            || self.application_pack_refs != exact_pack
            || self.integration_ids != vec![registration.integration_id.clone()]
            || !is_subset(
                &self.requested_outcome_class_ids,
                &responsibility.outcome_class_ids,
            )
            || !is_subset(
                &self.requested_evidence_class_ids,
                &responsibility.evidence_class_ids,
            )
            || !is_subset(
                &self.capability_requirement_ids,
                &work.required_capability_ids,
            )
            || !is_subset(
                &self.capability_requirement_ids,
                &delegation.delegated_capability_ids,
            )
            || !is_subset(&self.integration_ids, &delegation.delegated_integration_ids)
            || binding.is_none_or(|binding| {
                !is_subset(
                    &self.semantic_target_ids,
                    &binding.allowed_semantic_target_ids,
                ) || !is_subset(
                    &self.capability_requirement_ids,
                    &binding.allowed_capability_ids,
                )
            })
            || !self
                .required_trust_labels
                .contains(&registration.minimum_trust_label)
        {
            return Err(WorkIntakeError::NotAdmissible(
                "mapping expands or differs from Role, delegation, or registration".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Durable replay cursor bound to the protected Intake ledger chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarCheckpointV1 {
    pub schema_version: u32,
    pub registration_id: String,
    pub registration_sha256: String,
    pub organization_id: String,
    pub source_system_id: String,
    pub last_durable_sequence: u64,
    pub last_durable_cursor: Option<String>,
    pub last_event_id: Option<String>,
    pub last_signal_sha256: Option<String>,
    pub previous_checkpoint_sha256: String,
    pub cycle_sequence: u64,
    pub intake_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub checkpoint_sha256: String,
}

impl RadarCheckpointV1 {
    pub fn initial(
        registration: &ApprovedRadarSourceRegistrationV1,
        intake_ledger_chain_head: String,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkIntakeError> {
        normalize_ids(&mut evidence_ids, "checkpoint evidence", false)?;
        let mut checkpoint = Self {
            schema_version: WORK_INTAKE_SCHEMA_VERSION,
            registration_id: registration.registration_id.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            organization_id: registration.organization_id.clone(),
            source_system_id: registration.observation_source_id.clone(),
            last_durable_sequence: 0,
            last_durable_cursor: None,
            last_event_id: None,
            last_signal_sha256: None,
            previous_checkpoint_sha256: ZERO_HASH.to_owned(),
            cycle_sequence: 0,
            intake_ledger_chain_head,
            evidence_ids,
            checkpoint_sha256: ZERO_HASH.to_owned(),
        };
        checkpoint.checkpoint_sha256 = hash_without(&checkpoint, &["checkpoint_sha256"])?;
        checkpoint.validate_against(registration)?;
        Ok(checkpoint)
    }

    pub fn advance(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
        signal: &WorkSignalV1,
        cycle_sequence: u64,
        intake_ledger_chain_head: String,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, WorkIntakeError> {
        self.validate_progress(registration, signal)?;
        if cycle_sequence != self.cycle_sequence.saturating_add(1) {
            return Err(WorkIntakeError::Replay(
                "checkpoint cycle sequence did not advance exactly once".to_owned(),
            ));
        }
        normalize_ids(&mut evidence_ids, "checkpoint evidence", false)?;
        let mut checkpoint = Self {
            schema_version: WORK_INTAKE_SCHEMA_VERSION,
            registration_id: self.registration_id.clone(),
            registration_sha256: self.registration_sha256.clone(),
            organization_id: self.organization_id.clone(),
            source_system_id: self.source_system_id.clone(),
            last_durable_sequence: signal.source_sequence,
            last_durable_cursor: signal.source_cursor.clone(),
            last_event_id: Some(signal.event_id.clone()),
            last_signal_sha256: Some(signal.signal_sha256.clone()),
            previous_checkpoint_sha256: self.checkpoint_sha256.clone(),
            cycle_sequence,
            intake_ledger_chain_head,
            evidence_ids,
            checkpoint_sha256: ZERO_HASH.to_owned(),
        };
        checkpoint.checkpoint_sha256 = hash_without(&checkpoint, &["checkpoint_sha256"])?;
        checkpoint.validate_against(registration)?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.cycle_sequence > self.last_durable_sequence
        {
            return invalid("checkpoint schema or monotonic counters are invalid");
        }
        for (value, label) in [
            (&self.registration_id, "checkpoint registration"),
            (&self.organization_id, "checkpoint organization"),
            (&self.source_system_id, "checkpoint source"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.registration_sha256, "checkpoint registration hash"),
            (&self.previous_checkpoint_sha256, "previous checkpoint hash"),
            (&self.intake_ledger_chain_head, "checkpoint ledger head"),
            (&self.checkpoint_sha256, "checkpoint hash"),
        ] {
            validate_hash(value, label)?;
        }
        match (
            self.last_durable_sequence,
            &self.last_durable_cursor,
            &self.last_event_id,
            &self.last_signal_sha256,
        ) {
            (0, None, None, None) if self.cycle_sequence == 0 => {}
            (1.., _, Some(event), Some(hash)) => {
                validate_id(event, "checkpoint event")?;
                validate_hash(hash, "checkpoint signal")?;
            }
            _ => return invalid("checkpoint terminal source fields are inconsistent"),
        }
        if let Some(cursor) = &self.last_durable_cursor {
            validate_id(cursor, "checkpoint cursor")?;
        }
        validate_ids(&self.evidence_ids, "checkpoint evidence", false)?;
        if hash_without(self, &["checkpoint_sha256"])? != self.checkpoint_sha256 {
            return integrity("checkpoint canonical hash differs");
        }
        reject_sensitive(self, "checkpoint")
    }

    pub fn validate_against(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
    ) -> Result<(), WorkIntakeError> {
        self.validate()?;
        if self.registration_id != registration.registration_id
            || self.registration_sha256 != registration.registration_sha256
            || self.organization_id != registration.organization_id
            || self.source_system_id != registration.observation_source_id
            || matches!(
                registration.cursor_policy,
                RadarCursorPolicyV1::SequenceOnly
            ) && self.last_durable_cursor.is_some()
            || matches!(
                registration.cursor_policy,
                RadarCursorPolicyV1::OpaqueCursorWithSequence
            ) && self.last_durable_sequence > 0
                && self.last_durable_cursor.is_none()
        {
            return integrity("checkpoint differs from registration");
        }
        Ok(())
    }

    pub fn validate_progress(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
        signal: &WorkSignalV1,
    ) -> Result<(), WorkIntakeError> {
        self.validate_against(registration)?;
        signal.validate()?;
        let advance = signal
            .source_sequence
            .saturating_sub(self.last_durable_sequence);
        if signal.source_sequence <= self.last_durable_sequence
            || advance == 0
            || advance > registration.maximum_sequence_advance
            || self.last_event_id.as_ref() == Some(&signal.event_id)
            || self.last_signal_sha256.as_ref() == Some(&signal.signal_sha256)
        {
            return Err(WorkIntakeError::Replay(
                "signal sequence, event, hash, or bounded gap replays checkpoint state".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Closed Intake terminal classification. Only one value permits Case creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkIntakeDispositionV1 {
    AdmittedCaseCreated,
    DuplicateOpen,
    DuplicateTerminal,
    AdmissionDenied,
    ClarificationRequired,
    EscalationRequired,
    InactiveRole,
    OutsideOperatingWindow,
    StaleSource,
    UnsupportedEventClass,
    MalformedSignal,
    IntegrityConflict,
    Quarantined,
    NoWork,
}

/// Durable hash-only record of one signal disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIntakeReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub cycle_id: String,
    pub cycle_sequence: u64,
    pub signal_id: String,
    pub signal_sha256: String,
    pub source_approval_sha256: String,
    pub source_envelope_sha256: Option<String>,
    pub work_item_sha256: Option<String>,
    pub admission_sha256: Option<String>,
    pub case_id: Option<String>,
    pub case_contract_sha256: Option<String>,
    pub case_instance_sha256: Option<String>,
    pub duplicate_result: Option<WorkItemDeduplicationResultV1>,
    pub disposition: WorkIntakeDispositionV1,
    pub reason_codes: Vec<String>,
    pub checkpoint_before_sha256: String,
    pub checkpoint_after_sha256: String,
    pub case_ledger_chain_head: String,
    pub role_ledger_chain_head: String,
    pub intake_ledger_chain_head: String,
    pub evidence_ids: Vec<String>,
    pub decided_at_unix_seconds: u64,
    pub receipt_sha256: String,
}

impl WorkIntakeReceiptV1 {
    pub fn seal(mut self) -> Result<Self, WorkIntakeError> {
        normalize_ids(&mut self.reason_codes, "receipt reason codes", false)?;
        normalize_ids(&mut self.evidence_ids, "receipt evidence", false)?;
        self.receipt_sha256 = hash_without(&self, &["receipt_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.cycle_sequence == 0
            || self.decided_at_unix_seconds == 0
        {
            return invalid("receipt schema, cycle, or time is invalid");
        }
        for (value, label) in [
            (&self.receipt_id, "receipt ID"),
            (&self.cycle_id, "receipt cycle ID"),
            (&self.signal_id, "receipt signal ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.signal_sha256, "receipt signal hash"),
            (&self.source_approval_sha256, "receipt source approval hash"),
            (&self.checkpoint_before_sha256, "receipt prior checkpoint"),
            (&self.checkpoint_after_sha256, "receipt next checkpoint"),
            (&self.case_ledger_chain_head, "receipt Case ledger head"),
            (&self.role_ledger_chain_head, "receipt Role ledger head"),
            (&self.intake_ledger_chain_head, "receipt Intake ledger head"),
            (&self.receipt_sha256, "receipt hash"),
        ] {
            validate_hash(value, label)?;
        }
        for (value, label) in [
            (&self.source_envelope_sha256, "receipt source envelope"),
            (&self.work_item_sha256, "receipt Work Item"),
            (&self.admission_sha256, "receipt admission"),
            (&self.case_contract_sha256, "receipt Case Contract"),
            (&self.case_instance_sha256, "receipt Case Instance"),
        ] {
            if let Some(value) = value {
                validate_hash(value, label)?;
            }
        }
        if let Some(case_id) = &self.case_id {
            validate_id(case_id, "receipt Case ID")?;
        }
        validate_ids(&self.reason_codes, "receipt reason codes", false)?;
        validate_ids(&self.evidence_ids, "receipt evidence", false)?;
        let created = self.disposition == WorkIntakeDispositionV1::AdmittedCaseCreated;
        if created
            != (self.source_envelope_sha256.is_some()
                && self.work_item_sha256.is_some()
                && self.admission_sha256.is_some()
                && self.case_id.is_some()
                && self.case_contract_sha256.is_some()
                && self.case_instance_sha256.is_some()
                && self.duplicate_result == Some(WorkItemDeduplicationResultV1::New))
        {
            return integrity("receipt Case fields differ from disposition");
        }
        if hash_without(self, &["receipt_sha256"])? != self.receipt_sha256 {
            return integrity("receipt canonical hash differs");
        }
        reject_sensitive(self, "receipt")
    }
}

/// Deterministic aggregate of one bounded Radar pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarCycleReportV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub cycle_sequence: u64,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub source_approval_sha256: String,
    pub checkpoint_before_sha256: String,
    pub checkpoint_after_sha256: String,
    pub observed_signals: u32,
    pub accepted_signals: u32,
    pub cases_created: u32,
    pub duplicate_open: u32,
    pub duplicate_terminal: u32,
    pub denied: u32,
    pub clarification_required: u32,
    pub escalation_required: u32,
    pub quarantined: u32,
    pub logical_operations: u64,
    pub ticks_consumed: u64,
    pub retries: u32,
    pub receipt_hashes: Vec<String>,
    pub cycle_sha256: String,
}

impl RadarCycleReportV1 {
    pub fn seal(mut self) -> Result<Self, WorkIntakeError> {
        self.receipt_hashes.sort();
        self.cycle_sha256 = hash_without(&self, &["cycle_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.cycle_sequence == 0
            || self.observed_signals > MAX_EVENTS_PER_CYCLE as u32
            || self.accepted_signals > self.observed_signals
            || self.receipt_hashes.len() != self.observed_signals as usize
            || self.logical_operations > MAX_CYCLE_LOGICAL_OPERATIONS
            || self.ticks_consumed > MAX_CYCLE_LOGICAL_OPERATIONS
            || self.retries != 0
        {
            return invalid("cycle counters or resource use are invalid");
        }
        for (value, label) in [
            (&self.cycle_id, "cycle ID"),
            (&self.role_instance_id, "cycle Role Instance"),
            (&self.registration_id, "cycle registration"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.role_instance_sha256, "cycle Role Instance hash"),
            (&self.registration_sha256, "cycle registration hash"),
            (&self.source_approval_sha256, "cycle source approval hash"),
            (&self.checkpoint_before_sha256, "cycle checkpoint before"),
            (&self.checkpoint_after_sha256, "cycle checkpoint after"),
            (&self.cycle_sha256, "cycle hash"),
        ] {
            validate_hash(value, label)?;
        }
        validate_hashes(&self.receipt_hashes, "cycle receipt hashes", true)?;
        if hash_without(self, &["cycle_sha256"])? != self.cycle_sha256 {
            return integrity("cycle canonical hash differs");
        }
        Ok(())
    }
}

pub(crate) fn validate_id(value: &str, label: &str) -> Result<(), WorkIntakeError> {
    if value.is_empty()
        || value.len() > MAX_ID_LENGTH
        || value == "*"
        || value.eq_ignore_ascii_case("all")
        || value.eq_ignore_ascii_case("any")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return invalid(format!("{label} is not a bounded explicit identifier"));
    }
    Ok(())
}

pub(crate) fn validate_hash(value: &str, label: &str) -> Result<(), WorkIntakeError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return invalid(format!("{label} is not a lowercase SHA-256 digest"));
    }
    Ok(())
}

pub(crate) fn normalize_ids(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkIntakeError> {
    values.sort();
    validate_ids(values, label, allow_empty)
}

pub(crate) fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkIntakeError> {
    if values.len() > MAX_EVIDENCE
        || (!allow_empty && values.is_empty())
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(format!(
            "{label} is empty, duplicate, unsorted, or oversized"
        ));
    }
    for value in values {
        validate_id(value, label)?;
    }
    Ok(())
}

pub(crate) fn normalize_hashes(
    values: &mut [String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkIntakeError> {
    values.sort();
    validate_hashes(values, label, allow_empty)
}

pub(crate) fn validate_hashes(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), WorkIntakeError> {
    if values.len() > MAX_EVIDENCE
        || (!allow_empty && values.is_empty())
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return invalid(format!("{label} is duplicate, unsorted, or oversized"));
    }
    for value in values {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_application_ref(reference: &WorkApplicationPackRefV1) -> Result<(), WorkIntakeError> {
    validate_id(&reference.application_pack_id, "Application Pack ID")?;
    validate_hash(&reference.application_pack_sha256, "Application Pack hash")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], WorkIntakeError> {
    if value.len() != N * 2 {
        return invalid("source approval signature length is invalid");
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for (index, output_byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *output_byte = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Result<u8, WorkIntakeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => invalid("source approval signature is not lowercase hexadecimal"),
    }
}

pub(crate) fn reject_sensitive<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<(), WorkIntakeError> {
    let serialized = String::from_utf8(crate::canonical_json_bytes(value)?)
        .map_err(|error| WorkIntakeError::Json(error.to_string()))?
        .to_ascii_lowercase();
    for marker in [
        "raw_payload",
        "raw_body",
        "document_body",
        "email_body",
        "raw_instruction",
        "credential",
        "password",
        "private_key",
        "access_token",
        "authorization: bearer",
        "locator",
        "selector",
        "process_command",
        "c:\\\\",
    ] {
        if serialized.contains(marker) {
            return integrity(format!("{label} contains forbidden sensitive material"));
        }
    }
    Ok(())
}

pub(crate) fn invalid<T>(message: impl Into<String>) -> Result<T, WorkIntakeError> {
    Err(WorkIntakeError::Invalid(message.into()))
}

pub(crate) fn integrity<T>(message: impl Into<String>) -> Result<T, WorkIntakeError> {
    Err(WorkIntakeError::Integrity(message.into()))
}

pub(crate) fn is_subset(values: &[String], maximum: &[String]) -> bool {
    values
        .iter()
        .all(|value| maximum.binary_search(value).is_ok())
}

pub(crate) fn role_is_active(instance: &RoleInstanceV1, now: u64) -> bool {
    instance.current_status == RoleInstanceStatusV1::Active
        && instance
            .activated_at_unix_seconds
            .is_some_and(|activated| activated <= now)
        && now < instance.expires_at_unix_seconds
}

pub(crate) fn admission_disposition(
    admission: &WorkItemAdmissionDecisionV1,
) -> WorkIntakeDispositionV1 {
    use d2i_work_case::WorkItemAdmissionOutcomeV1;
    match admission.outcome {
        WorkItemAdmissionOutcomeV1::Admitted => WorkIntakeDispositionV1::AdmittedCaseCreated,
        WorkItemAdmissionOutcomeV1::Denied => WorkIntakeDispositionV1::AdmissionDenied,
        WorkItemAdmissionOutcomeV1::Duplicate => match admission.deduplication_result {
            WorkItemDeduplicationResultV1::DuplicateOpen => WorkIntakeDispositionV1::DuplicateOpen,
            WorkItemDeduplicationResultV1::DuplicateTerminal => {
                WorkIntakeDispositionV1::DuplicateTerminal
            }
            _ => WorkIntakeDispositionV1::IntegrityConflict,
        },
        WorkItemAdmissionOutcomeV1::ClarificationRequired => {
            WorkIntakeDispositionV1::ClarificationRequired
        }
        WorkItemAdmissionOutcomeV1::EscalationRequired => {
            WorkIntakeDispositionV1::EscalationRequired
        }
        WorkItemAdmissionOutcomeV1::InactiveRole => WorkIntakeDispositionV1::InactiveRole,
        WorkItemAdmissionOutcomeV1::OutsideOperatingWindow => {
            WorkIntakeDispositionV1::OutsideOperatingWindow
        }
    }
}
