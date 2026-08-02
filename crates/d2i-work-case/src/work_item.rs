use crate::strict::hash_without;
use crate::{
    integrity, invalid, normalize_hashes, normalize_ids, reject_sensitive, validate_hash,
    validate_hashes, validate_id, validate_ids, WorkCaseError, WORK_CASE_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{
    ObservationSourceKindV1, RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1,
    RoleInstanceV1, RoleOperationalTimeContextV1,
};
use serde::{Deserialize, Serialize};

/// Explicit, pre-authenticated source category. No connector is implemented in v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemSourceKindV1 {
    AuthenticatedInstruction,
    ApprovedManualImport,
    ApprovedSystemEvent,
    ApprovedScheduleEvent,
    ApprovedExternalReference,
}

impl WorkItemSourceKindV1 {
    fn compatible_with(self, role_kind: ObservationSourceKindV1) -> bool {
        matches!(
            (self, role_kind),
            (
                Self::AuthenticatedInstruction | Self::ApprovedManualImport,
                ObservationSourceKindV1::ManualAuthenticatedInstruction
            ) | (
                Self::AuthenticatedInstruction,
                ObservationSourceKindV1::DesktopUia
            ) | (
                Self::ApprovedSystemEvent,
                ObservationSourceKindV1::EventStream
            ) | (
                Self::ApprovedScheduleEvent,
                ObservationSourceKindV1::Schedule
            ) | (
                Self::ApprovedExternalReference,
                ObservationSourceKindV1::EnterpriseApi
                    | ObservationSourceKindV1::DesktopUia
                    | ObservationSourceKindV1::WebDriver
                    | ObservationSourceKindV1::SensorSummary
            )
        )
    }
}

/// Hash-only provenance for a caller-supplied source envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemProvenanceV1 {
    pub authenticated_actor_id: String,
    pub authentication_class_id: String,
    pub authentication_evidence_sha256: String,
    pub source_record_sha256: String,
}

impl WorkItemProvenanceV1 {
    fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.authenticated_actor_id, "provenance actor")?;
        validate_id(
            &self.authentication_class_id,
            "provenance authentication class",
        )?;
        validate_hash(
            &self.authentication_evidence_sha256,
            "provenance authentication evidence",
        )?;
        validate_hash(&self.source_record_sha256, "provenance source record")
    }
}

/// Explicit hash-only source supplied by a trusted caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemSourceEnvelopeV1 {
    pub schema_version: u32,
    pub source_envelope_id: String,
    pub source_kind: WorkItemSourceKindV1,
    pub source_system_id: String,
    pub source_event_id: String,
    pub organization_id: String,
    pub observed_at_unix_seconds: u64,
    pub received_at_unix_seconds: u64,
    pub trust_labels: Vec<String>,
    pub provenance: WorkItemProvenanceV1,
    pub payload_reference_sha256: String,
    pub attachment_reference_hashes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub envelope_sha256: String,
}

impl WorkItemSourceEnvelopeV1 {
    /// Canonically orders sets and seals the immutable envelope.
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        normalize_ids(&mut self.trust_labels, "source trust labels", false)?;
        normalize_hashes(
            &mut self.attachment_reference_hashes,
            "source attachment hashes",
            true,
        )?;
        normalize_ids(&mut self.evidence_ids, "source evidence IDs", false)?;
        self.envelope_sha256 = hash_without(&self, &["envelope_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    /// Validates bounds, provenance, timestamps, and canonical identity.
    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.observed_at_unix_seconds == 0
            || self.received_at_unix_seconds < self.observed_at_unix_seconds
        {
            return invalid("source envelope schema or timestamps are invalid");
        }
        for (value, label) in [
            (&self.source_envelope_id, "source_envelope_id"),
            (&self.source_system_id, "source_system_id"),
            (&self.source_event_id, "source_event_id"),
            (&self.organization_id, "source organization_id"),
        ] {
            validate_id(value, label)?;
        }
        validate_ids(&self.trust_labels, "source trust labels", false)?;
        if self
            .trust_labels
            .iter()
            .any(|label| label == "untrusted-command" || label == "authority")
        {
            return invalid("source trust labels may not confer command authority");
        }
        self.provenance.validate()?;
        validate_hash(&self.payload_reference_sha256, "source payload reference")?;
        validate_hashes(
            &self.attachment_reference_hashes,
            "source attachment hashes",
            true,
        )?;
        validate_ids(&self.evidence_ids, "source evidence IDs", false)?;
        validate_hash(&self.envelope_sha256, "source envelope hash")?;
        if hash_without(self, &["envelope_sha256"])? != self.envelope_sha256 {
            return integrity("source envelope self-hash differs");
        }
        reject_sensitive(self, "source envelope")
    }
}

/// Closed priority declaration. Urgency never bypasses authority or policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkPriorityClassV1 {
    Routine,
    Normal,
    Elevated,
    Urgent,
}

impl WorkPriorityClassV1 {
    fn role_aliases(self) -> &'static [&'static str] {
        match self {
            Self::Routine => &["routine"],
            Self::Normal => &["normal"],
            // WORK-100's canonical safety fixture predates the closed v1 name.
            Self::Elevated => &["elevated", "high"],
            Self::Urgent => &["urgent"],
        }
    }
}

/// Exact immutable package reference without a local path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkApplicationPackRefV1 {
    pub application_pack_id: String,
    pub application_pack_sha256: String,
}

impl WorkApplicationPackRefV1 {
    pub(crate) fn validate(&self) -> Result<(), WorkCaseError> {
        validate_id(&self.application_pack_id, "Work Item Application Pack")?;
        validate_hash(
            &self.application_pack_sha256,
            "Work Item Application Pack hash",
        )
    }
}

/// Immutable normalized Work Item candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemV1 {
    pub schema_version: u32,
    pub work_item_id: String,
    pub work_item_generation: u64,
    pub source_envelope_sha256: String,
    pub organization_id: String,
    pub work_class_id: String,
    pub work_class_contract_version: String,
    pub subject_refs: Vec<String>,
    pub requested_outcome_class_ids: Vec<String>,
    pub requested_evidence_class_ids: Vec<String>,
    pub priority_class: WorkPriorityClassV1,
    pub risk_class: CognitiveRiskClass,
    pub application_pack_refs: Vec<WorkApplicationPackRefV1>,
    pub integration_ids: Vec<String>,
    pub capability_requirement_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub requested_due_at_unix_seconds: Option<u64>,
    pub received_at_unix_seconds: u64,
    pub deduplication_scope_id: String,
    pub deduplication_key_sha256: String,
    pub content_trust_labels: Vec<String>,
    pub structured_input_refs: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub work_item_sha256: String,
}

impl WorkItemV1 {
    /// Validates the normalized immutable Work Item.
    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION
            || self.work_item_generation != 1
            || self.received_at_unix_seconds == 0
            || self
                .requested_due_at_unix_seconds
                .is_some_and(|due| due <= self.received_at_unix_seconds)
        {
            return invalid("Work Item schema, generation, or time is invalid");
        }
        for (value, label) in [
            (&self.work_item_id, "work_item_id"),
            (&self.organization_id, "Work Item organization_id"),
            (&self.work_class_id, "work_class_id"),
            (
                &self.work_class_contract_version,
                "work_class_contract_version",
            ),
            (&self.deduplication_scope_id, "deduplication_scope_id"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.source_envelope_sha256, "source envelope hash"),
            (&self.deduplication_key_sha256, "deduplication key hash"),
            (&self.work_item_sha256, "Work Item hash"),
        ] {
            validate_hash(hash, label)?;
        }
        for (values, label, allow_empty) in [
            (&self.subject_refs, "subject refs", false),
            (
                &self.requested_outcome_class_ids,
                "requested outcome classes",
                false,
            ),
            (
                &self.requested_evidence_class_ids,
                "requested evidence classes",
                false,
            ),
            (&self.integration_ids, "Work Item integrations", false),
            (
                &self.capability_requirement_ids,
                "capability requirements",
                false,
            ),
            (&self.semantic_target_ids, "semantic targets", true),
            (&self.content_trust_labels, "content trust labels", false),
            (&self.structured_input_refs, "structured input refs", true),
            (&self.evidence_ids, "Work Item evidence IDs", false),
        ] {
            validate_ids(values, label, allow_empty)?;
        }
        if self.application_pack_refs.is_empty()
            || self.application_pack_refs.len() > crate::MAX_ITEMS
            || !self
                .application_pack_refs
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return invalid("Application Pack refs are empty, duplicated, or unsorted");
        }
        for reference in &self.application_pack_refs {
            reference.validate()?;
        }
        if self
            .content_trust_labels
            .iter()
            .any(|label| matches!(label.as_str(), "authority" | "execution-permit" | "policy"))
        {
            return invalid("Work Item content labels may not confer authority");
        }
        if hash_without(self, &["work_item_sha256"])? != self.work_item_sha256 {
            return integrity("Work Item self-hash differs");
        }
        reject_sensitive(self, "Work Item")
    }
}

/// Caller-supplied typed input to deterministic Work Item normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemNormalizationInputV1 {
    pub work_item_id: String,
    pub work_class_id: String,
    pub work_class_contract_version: String,
    pub subject_refs: Vec<String>,
    pub requested_outcome_class_ids: Vec<String>,
    pub requested_evidence_class_ids: Vec<String>,
    pub priority_class: WorkPriorityClassV1,
    pub risk_class: CognitiveRiskClass,
    pub application_pack_refs: Vec<WorkApplicationPackRefV1>,
    pub integration_ids: Vec<String>,
    pub capability_requirement_ids: Vec<String>,
    pub semantic_target_ids: Vec<String>,
    pub requested_due_at_unix_seconds: Option<u64>,
    pub deduplication_scope_id: String,
    pub semantic_payload_sha256: String,
    pub content_trust_labels: Vec<String>,
    pub structured_input_refs: Vec<String>,
    pub evidence_ids: Vec<String>,
}

/// Stable one-to-one duplicate key for a semantic Work Item source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemDeduplicationKeyV1 {
    pub organization_id: String,
    pub source_system_id: String,
    pub source_event_id: String,
    pub work_class_id: String,
    pub subject_refs_sha256: String,
    pub deduplication_scope_id: String,
    pub semantic_payload_sha256: String,
    pub key_sha256: String,
}

impl WorkItemDeduplicationKeyV1 {
    pub fn validate(&self) -> Result<(), WorkCaseError> {
        for (value, label) in [
            (&self.organization_id, "dedup organization"),
            (&self.source_system_id, "dedup source system"),
            (&self.source_event_id, "dedup source event"),
            (&self.work_class_id, "dedup work class"),
            (&self.deduplication_scope_id, "dedup scope"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.subject_refs_sha256, "dedup subject hash"),
            (&self.semantic_payload_sha256, "dedup semantic hash"),
            (&self.key_sha256, "dedup key hash"),
        ] {
            validate_hash(hash, label)?;
        }
        if hash_without(self, &["key_sha256"])? != self.key_sha256 {
            return integrity("deduplication key self-hash differs");
        }
        Ok(())
    }
}

/// Deterministically normalizes an explicit source into a Work Item and dedup key.
pub fn normalize_work_item(
    envelope: &WorkItemSourceEnvelopeV1,
    mut input: WorkItemNormalizationInputV1,
) -> Result<(WorkItemV1, WorkItemDeduplicationKeyV1), WorkCaseError> {
    envelope.validate()?;
    validate_hash(&input.semantic_payload_sha256, "semantic payload hash")?;
    normalize_ids(&mut input.subject_refs, "subject refs", false)?;
    normalize_ids(
        &mut input.requested_outcome_class_ids,
        "requested outcome classes",
        false,
    )?;
    normalize_ids(
        &mut input.requested_evidence_class_ids,
        "requested evidence classes",
        false,
    )?;
    input.application_pack_refs.sort();
    normalize_ids(&mut input.integration_ids, "Work Item integrations", false)?;
    normalize_ids(
        &mut input.capability_requirement_ids,
        "capability requirements",
        false,
    )?;
    normalize_ids(&mut input.semantic_target_ids, "semantic targets", true)?;
    normalize_ids(
        &mut input.content_trust_labels,
        "content trust labels",
        false,
    )?;
    normalize_ids(
        &mut input.structured_input_refs,
        "structured input refs",
        true,
    )?;
    normalize_ids(&mut input.evidence_ids, "Work Item evidence IDs", false)?;
    let subject_refs_sha256 = crate::canonical_sha256(&input.subject_refs)?;
    let mut key = WorkItemDeduplicationKeyV1 {
        organization_id: envelope.organization_id.clone(),
        source_system_id: envelope.source_system_id.clone(),
        source_event_id: envelope.source_event_id.clone(),
        work_class_id: input.work_class_id.clone(),
        subject_refs_sha256,
        deduplication_scope_id: input.deduplication_scope_id.clone(),
        semantic_payload_sha256: input.semantic_payload_sha256,
        key_sha256: ZERO_HASH.to_owned(),
    };
    key.key_sha256 = hash_without(&key, &["key_sha256"])?;
    key.validate()?;
    let mut work_item = WorkItemV1 {
        schema_version: WORK_CASE_SCHEMA_VERSION,
        work_item_id: input.work_item_id,
        work_item_generation: 1,
        source_envelope_sha256: envelope.envelope_sha256.clone(),
        organization_id: envelope.organization_id.clone(),
        work_class_id: input.work_class_id,
        work_class_contract_version: input.work_class_contract_version,
        subject_refs: input.subject_refs,
        requested_outcome_class_ids: input.requested_outcome_class_ids,
        requested_evidence_class_ids: input.requested_evidence_class_ids,
        priority_class: input.priority_class,
        risk_class: input.risk_class,
        application_pack_refs: input.application_pack_refs,
        integration_ids: input.integration_ids,
        capability_requirement_ids: input.capability_requirement_ids,
        semantic_target_ids: input.semantic_target_ids,
        requested_due_at_unix_seconds: input.requested_due_at_unix_seconds,
        received_at_unix_seconds: envelope.received_at_unix_seconds,
        deduplication_scope_id: input.deduplication_scope_id,
        deduplication_key_sha256: key.key_sha256.clone(),
        content_trust_labels: input.content_trust_labels,
        structured_input_refs: input.structured_input_refs,
        evidence_ids: input.evidence_ids,
        work_item_sha256: ZERO_HASH.to_owned(),
    };
    work_item.work_item_sha256 = hash_without(&work_item, &["work_item_sha256"])?;
    work_item.validate()?;
    Ok((work_item, key))
}

/// Duplicate result prior to Case creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemDeduplicationResultV1 {
    New,
    DuplicateOpen,
    DuplicateTerminal,
    Conflict,
}

/// One durable dedup registry projection. Persistence belongs to Desktop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemDeduplicationEntryV1 {
    pub key: WorkItemDeduplicationKeyV1,
    pub work_item_id: String,
    pub work_item_sha256: String,
    pub case_id: Option<String>,
    pub terminal: bool,
}

/// Pure duplicate classifier reconstructed from the Case ledger.
pub fn classify_duplicate(
    candidate: &WorkItemDeduplicationKeyV1,
    entries: &[WorkItemDeduplicationEntryV1],
) -> Result<WorkItemDeduplicationResultV1, WorkCaseError> {
    candidate.validate()?;
    for entry in entries {
        entry.key.validate()?;
        validate_id(&entry.work_item_id, "dedup entry Work Item")?;
        validate_hash(&entry.work_item_sha256, "dedup entry Work Item hash")?;
        if let Some(case_id) = &entry.case_id {
            validate_id(case_id, "dedup entry Case")?;
        }
        let same_source_scope = entry.key.organization_id == candidate.organization_id
            && entry.key.source_system_id == candidate.source_system_id
            && entry.key.source_event_id == candidate.source_event_id
            && entry.key.deduplication_scope_id == candidate.deduplication_scope_id;
        if same_source_scope {
            if entry.key.semantic_payload_sha256 != candidate.semantic_payload_sha256
                || entry.key.work_class_id != candidate.work_class_id
                || entry.key.subject_refs_sha256 != candidate.subject_refs_sha256
            {
                return Ok(WorkItemDeduplicationResultV1::Conflict);
            }
            return Ok(if entry.terminal {
                WorkItemDeduplicationResultV1::DuplicateTerminal
            } else {
                WorkItemDeduplicationResultV1::DuplicateOpen
            });
        }
    }
    Ok(WorkItemDeduplicationResultV1::New)
}

/// Pre-Goal, pre-policy Work Item admission request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemAdmissionRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub work_item: WorkItemV1,
    pub source_envelope: WorkItemSourceEnvelopeV1,
    pub role_instance_sha256: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub operational_time_context: RoleOperationalTimeContextV1,
    pub trusted_policy_snapshot_sha256: String,
    pub policy_set_sha256: String,
    pub deduplication_result: WorkItemDeduplicationResultV1,
    pub admitted_at_unix_seconds: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl WorkItemAdmissionRequestV1 {
    pub fn seal(mut self) -> Result<Self, WorkCaseError> {
        normalize_ids(&mut self.evidence_ids, "admission request evidence", false)?;
        self.request_sha256 = hash_without(&self, &["request_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION || self.admitted_at_unix_seconds == 0 {
            return invalid("Work Item admission schema or time is invalid");
        }
        validate_id(&self.request_id, "Work Item admission request_id")?;
        self.work_item.validate()?;
        self.source_envelope.validate()?;
        if self.work_item.source_envelope_sha256 != self.source_envelope.envelope_sha256
            || self.work_item.organization_id != self.source_envelope.organization_id
        {
            return integrity("Work Item and source envelope binding differs");
        }
        for (hash, label) in [
            (&self.role_instance_sha256, "admission Role Instance"),
            (&self.role_contract_sha256, "admission Role Contract"),
            (&self.delegation_sha256, "admission delegation"),
            (
                &self.trusted_policy_snapshot_sha256,
                "admission policy snapshot",
            ),
            (&self.policy_set_sha256, "admission policy set"),
            (&self.request_sha256, "admission request"),
        ] {
            validate_hash(hash, label)?;
        }
        self.operational_time_context
            .validate()
            .map_err(|error| WorkCaseError::Integrity(error.to_string()))?;
        validate_ids(&self.evidence_ids, "admission request evidence", false)?;
        if hash_without(self, &["request_sha256"])? != self.request_sha256 {
            return integrity("Work Item admission request self-hash differs");
        }
        reject_sensitive(self, "Work Item admission request")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemAdmissionOutcomeV1 {
    Admitted,
    Denied,
    Duplicate,
    ClarificationRequired,
    EscalationRequired,
    InactiveRole,
    OutsideOperatingWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkItemAdmissionReasonCodeV1 {
    WithinRoleScope,
    InactiveRole,
    OrganizationMismatch,
    WorkClassNotAccepted,
    WorkClassProhibited,
    SourceKindDenied,
    ApplicationPackDenied,
    IntegrationDenied,
    CapabilityDenied,
    ProhibitedCapability,
    RiskExceeded,
    PolicyMismatch,
    OutsideOperatingWindow,
    StaleSource,
    DuplicateOpen,
    DuplicateTerminal,
    DeduplicationConflict,
    MissingRequiredInformation,
    IntegrityMismatch,
}

/// Deterministic admission decision. Only `admitted` may create a Case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItemAdmissionDecisionV1 {
    pub schema_version: u32,
    pub admission_id: String,
    pub request_sha256: String,
    pub work_item_id: String,
    pub work_item_sha256: String,
    pub role_instance_id: String,
    pub role_contract_sha256: String,
    pub delegation_sha256: String,
    pub work_class_id: String,
    pub outcome: WorkItemAdmissionOutcomeV1,
    pub reason_codes: Vec<WorkItemAdmissionReasonCodeV1>,
    pub selected_responsibility_id: Option<String>,
    pub selected_sla_profile_id: Option<String>,
    pub selected_reporting_obligation_ids: Vec<String>,
    pub deduplication_result: WorkItemDeduplicationResultV1,
    pub evidence_ids: Vec<String>,
    pub decided_at_unix_seconds: u64,
    pub decision_sha256: String,
}

impl WorkItemAdmissionDecisionV1 {
    pub fn validate(&self) -> Result<(), WorkCaseError> {
        if self.schema_version != WORK_CASE_SCHEMA_VERSION || self.decided_at_unix_seconds == 0 {
            return invalid("Work Item decision schema or time is invalid");
        }
        for (value, label) in [
            (&self.admission_id, "admission_id"),
            (&self.work_item_id, "decision Work Item"),
            (&self.role_instance_id, "decision Role Instance"),
            (&self.work_class_id, "decision work class"),
        ] {
            validate_id(value, label)?;
        }
        for (hash, label) in [
            (&self.request_sha256, "decision request"),
            (&self.work_item_sha256, "decision Work Item hash"),
            (&self.role_contract_sha256, "decision Role Contract"),
            (&self.delegation_sha256, "decision delegation"),
            (&self.decision_sha256, "decision hash"),
        ] {
            validate_hash(hash, label)?;
        }
        if self.reason_codes.is_empty()
            || !self.reason_codes.windows(2).all(|pair| pair[0] < pair[1])
        {
            return invalid("decision reason codes are empty, duplicated, or unsorted");
        }
        validate_ids(
            &self.selected_reporting_obligation_ids,
            "selected reporting obligations",
            true,
        )?;
        validate_ids(&self.evidence_ids, "decision evidence", false)?;
        let admitted = self.outcome == WorkItemAdmissionOutcomeV1::Admitted;
        if admitted
            != (self.selected_responsibility_id.is_some() && self.selected_sla_profile_id.is_some())
        {
            return integrity("only admitted decisions may contain selected Role bindings");
        }
        if let Some(id) = &self.selected_responsibility_id {
            validate_id(id, "selected responsibility")?;
        }
        if let Some(id) = &self.selected_sla_profile_id {
            validate_id(id, "selected SLA profile")?;
        }
        if hash_without(self, &["decision_sha256"])? != self.decision_sha256 {
            return integrity("Work Item admission decision self-hash differs");
        }
        Ok(())
    }
}

/// Evaluates one Work Item before any Goal, module, policy, activation, or mutation.
pub fn admit_work_item(
    request: &WorkItemAdmissionRequestV1,
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
) -> Result<WorkItemAdmissionDecisionV1, WorkCaseError> {
    request.validate()?;
    contract
        .validate()
        .map_err(|error| WorkCaseError::Integrity(error.to_string()))?;
    let mut outcome = WorkItemAdmissionOutcomeV1::Admitted;
    let mut reasons = Vec::new();
    let work = contract
        .accepted_work_classes
        .iter()
        .find(|work| work.work_class_id == request.work_item.work_class_id);

    if request.role_instance_sha256 != instance.instance_sha256
        || request.role_contract_sha256 != contract.contract_sha256
        || request.delegation_sha256 != delegation.delegation_sha256
        || instance.contract_sha256 != contract.contract_sha256
        || instance.delegation_sha256 != delegation.delegation_sha256
        || request.policy_set_sha256 != contract.policy_set_sha256
        || instance.policy_set_sha256 != contract.policy_set_sha256
        || request.admitted_at_unix_seconds < request.source_envelope.received_at_unix_seconds
        || request.operational_time_context.observed_at_unix_seconds
            > request.admitted_at_unix_seconds
    {
        outcome = WorkItemAdmissionOutcomeV1::Denied;
        reasons.push(WorkItemAdmissionReasonCodeV1::IntegrityMismatch);
    } else if instance.current_status != RoleInstanceStatusV1::Active
        || instance
            .activated_at_unix_seconds
            .is_none_or(|activated| request.admitted_at_unix_seconds < activated)
        || request.admitted_at_unix_seconds < delegation.valid_from_unix_seconds
        || request.admitted_at_unix_seconds >= instance.expires_at_unix_seconds
        || request.admitted_at_unix_seconds >= delegation.expires_at_unix_seconds
    {
        outcome = WorkItemAdmissionOutcomeV1::InactiveRole;
        reasons.push(WorkItemAdmissionReasonCodeV1::InactiveRole);
    } else if request.work_item.organization_id != contract.organization_scope.organization_id
        || request.work_item.organization_id != delegation.organization_id
        || request.work_item.organization_id != instance.organization_id
    {
        outcome = WorkItemAdmissionOutcomeV1::Denied;
        reasons.push(WorkItemAdmissionReasonCodeV1::OrganizationMismatch);
    } else if contract
        .prohibited_work_class_ids
        .contains(&request.work_item.work_class_id)
    {
        outcome = WorkItemAdmissionOutcomeV1::Denied;
        reasons.push(WorkItemAdmissionReasonCodeV1::WorkClassProhibited);
    } else if work.is_none()
        || !delegation
            .delegated_work_class_ids
            .contains(&request.work_item.work_class_id)
    {
        outcome = WorkItemAdmissionOutcomeV1::Denied;
        reasons.push(WorkItemAdmissionReasonCodeV1::WorkClassNotAccepted);
    } else if request.deduplication_result != WorkItemDeduplicationResultV1::New {
        match request.deduplication_result {
            WorkItemDeduplicationResultV1::DuplicateOpen => {
                outcome = WorkItemAdmissionOutcomeV1::Duplicate;
                reasons.push(WorkItemAdmissionReasonCodeV1::DuplicateOpen);
            }
            WorkItemDeduplicationResultV1::DuplicateTerminal => {
                outcome = WorkItemAdmissionOutcomeV1::Duplicate;
                reasons.push(WorkItemAdmissionReasonCodeV1::DuplicateTerminal);
            }
            WorkItemDeduplicationResultV1::Conflict => {
                outcome = WorkItemAdmissionOutcomeV1::EscalationRequired;
                reasons.push(WorkItemAdmissionReasonCodeV1::DeduplicationConflict);
            }
            WorkItemDeduplicationResultV1::New => {}
        }
    }

    let mut responsibility = None;
    let mut sla = None;
    let mut reporting = Vec::new();
    if outcome == WorkItemAdmissionOutcomeV1::Admitted {
        let work =
            work.ok_or_else(|| WorkCaseError::Integrity("work class vanished".to_owned()))?;
        let source = contract.observation_sources.iter().find(|source| {
            source.enabled
                && source.observation_source_id == request.source_envelope.source_system_id
                && request
                    .source_envelope
                    .source_kind
                    .compatible_with(source.source_kind)
                && work
                    .permitted_observation_source_ids
                    .contains(&source.observation_source_id)
        });
        if source.is_none() {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::SourceKindDenied);
        } else if source.is_some_and(|source| {
            request.source_envelope.received_at_unix_seconds
                > request
                    .source_envelope
                    .observed_at_unix_seconds
                    .saturating_add(source.maximum_staleness_seconds)
                || request.admitted_at_unix_seconds
                    > request
                        .source_envelope
                        .received_at_unix_seconds
                        .saturating_add(source.maximum_staleness_seconds)
        }) {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::StaleSource);
        } else if !work.allowed_priority_classes.iter().any(|candidate| {
            request
                .work_item
                .priority_class
                .role_aliases()
                .contains(&candidate.as_str())
        }) {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::WorkClassNotAccepted);
        } else if request.work_item.semantic_target_ids.is_empty()
            || request.work_item.structured_input_refs.is_empty()
        {
            outcome = if work.clarification_allowed {
                WorkItemAdmissionOutcomeV1::ClarificationRequired
            } else {
                WorkItemAdmissionOutcomeV1::Denied
            };
            reasons.push(WorkItemAdmissionReasonCodeV1::MissingRequiredInformation);
        } else if !request
            .work_item
            .application_pack_refs
            .iter()
            .all(|reference| {
                work.required_application_pack_ids
                    .contains(&reference.application_pack_id)
                    && delegation
                        .delegated_application_pack_ids
                        .contains(&reference.application_pack_id)
                    && contract.application_bindings.iter().any(|binding| {
                        binding.application_pack_id == reference.application_pack_id
                            && binding.application_pack_sha256 == reference.application_pack_sha256
                    })
            })
        {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::ApplicationPackDenied);
        } else if !request.work_item.integration_ids.iter().all(|integration| {
            work.required_integration_ids.contains(integration)
                && delegation.delegated_integration_ids.contains(integration)
        }) {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::IntegrationDenied);
        } else if request
            .work_item
            .capability_requirement_ids
            .iter()
            .any(|capability| {
                delegation.prohibited_capability_ids.contains(capability)
                    || contract
                        .capability_policy
                        .prohibited_capability_ids
                        .contains(capability)
            })
        {
            outcome = WorkItemAdmissionOutcomeV1::EscalationRequired;
            reasons.push(WorkItemAdmissionReasonCodeV1::ProhibitedCapability);
        } else if !request
            .work_item
            .capability_requirement_ids
            .iter()
            .all(|capability| {
                work.required_capability_ids.contains(capability)
                    && delegation.delegated_capability_ids.contains(capability)
                    && contract
                        .capability_policy
                        .allowed_capability_ids
                        .contains(capability)
            })
        {
            outcome = WorkItemAdmissionOutcomeV1::Denied;
            reasons.push(WorkItemAdmissionReasonCodeV1::CapabilityDenied);
        } else if request.work_item.risk_class > work.maximum_risk
            || request.work_item.risk_class > delegation.maximum_confirmable_risk
            || request.work_item.risk_class > contract.risk_policy.maximum_confirmable_risk
        {
            outcome = WorkItemAdmissionOutcomeV1::EscalationRequired;
            reasons.push(WorkItemAdmissionReasonCodeV1::RiskExceeded);
        } else if !inside_operating_window(contract, &request.operational_time_context) {
            outcome = WorkItemAdmissionOutcomeV1::OutsideOperatingWindow;
            reasons.push(WorkItemAdmissionReasonCodeV1::OutsideOperatingWindow);
        } else {
            reasons.push(WorkItemAdmissionReasonCodeV1::WithinRoleScope);
            responsibility = Some(work.responsibility_id.clone());
            sla = Some(work.sla_profile_id.clone());
            reporting = contract
                .responsibilities
                .iter()
                .find(|item| item.responsibility_id == work.responsibility_id)
                .map(|item| item.reporting_obligation_ids.clone())
                .unwrap_or_default();
        }
    }
    reasons.sort();
    reasons.dedup();
    reporting.sort();
    let mut decision = WorkItemAdmissionDecisionV1 {
        schema_version: WORK_CASE_SCHEMA_VERSION,
        admission_id: format!("work-admission:{}", request.request_id),
        request_sha256: request.request_sha256.clone(),
        work_item_id: request.work_item.work_item_id.clone(),
        work_item_sha256: request.work_item.work_item_sha256.clone(),
        role_instance_id: instance.role_instance_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        work_class_id: request.work_item.work_class_id.clone(),
        outcome,
        reason_codes: reasons,
        selected_responsibility_id: responsibility,
        selected_sla_profile_id: sla,
        selected_reporting_obligation_ids: reporting,
        deduplication_result: request.deduplication_result,
        evidence_ids: request.evidence_ids.clone(),
        decided_at_unix_seconds: request.admitted_at_unix_seconds,
        decision_sha256: ZERO_HASH.to_owned(),
    };
    decision.decision_sha256 = hash_without(&decision, &["decision_sha256"])?;
    decision.validate()?;
    Ok(decision)
}

fn inside_operating_window(contract: &RoleContractV1, time: &RoleOperationalTimeContextV1) -> bool {
    time.calendar_sha256 == contract.working_calendar.calendar_sha256
        && !contract
            .working_calendar
            .blackout_date_ids
            .contains(&time.local_date)
        && contract
            .working_calendar
            .weekly_windows
            .iter()
            .any(|window| {
                window.weekday == time.weekday
                    && time.local_minute_of_day >= window.start_minute_local
                    && time.local_minute_of_day < window.end_minute_local
            })
}
