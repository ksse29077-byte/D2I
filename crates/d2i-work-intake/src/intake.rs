use crate::contract::{
    admission_disposition, invalid, is_subset, role_is_active, validate_hash, validate_id,
};
use crate::strict::hash_without;
use crate::{
    verify_work_source_approval, ApprovedRadarSourceRegistrationV1, DueTimeDerivationV1,
    RadarCheckpointV1, WorkIntakeDispositionV1, WorkIntakeError, WorkIntakeMappingProfileV1,
    WorkSignalV1, WorkSourceApprovalV1, MAX_EVENTS_PER_CYCLE, WORK_INTAKE_SCHEMA_VERSION,
    ZERO_HASH,
};
use d2i_role_contract::{
    verify_role_contract_approval, verify_role_delegation, RoleContractApprovalV1, RoleContractV1,
    RoleDelegationGrantV1, RoleInstanceV1, RoleOperationalTimeContextV1,
};
use d2i_work_case::{
    admit_work_item, classify_duplicate, normalize_work_item, WorkItemAdmissionDecisionV1,
    WorkItemAdmissionRequestV1, WorkItemDeduplicationEntryV1, WorkItemDeduplicationKeyV1,
    WorkItemDeduplicationResultV1, WorkItemNormalizationInputV1, WorkItemProvenanceV1,
    WorkItemSourceEnvelopeV1, WorkItemSourceKindV1, WorkItemV1,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// Explicit, bounded one-shot scan request. The caller supplies all time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarScanRequestV1 {
    pub schema_version: u32,
    pub cycle_id: String,
    pub cycle_sequence: u64,
    pub registration_id: String,
    pub registration_sha256: String,
    pub source_approval_sha256: String,
    pub checkpoint_sha256: String,
    pub issued_at_unix_seconds: u64,
    pub deadline_unix_seconds: u64,
    pub maximum_events: u32,
    pub maximum_record_bytes: u64,
    pub request_sha256: String,
}

impl RadarScanRequestV1 {
    pub fn create(
        cycle_id: String,
        cycle_sequence: u64,
        registration: &ApprovedRadarSourceRegistrationV1,
        source_approval: &WorkSourceApprovalV1,
        checkpoint: &RadarCheckpointV1,
        issued_at_unix_seconds: u64,
        deadline_unix_seconds: u64,
    ) -> Result<Self, WorkIntakeError> {
        registration.validate()?;
        source_approval.validate_against(registration)?;
        checkpoint.validate_against(registration)?;
        let mut request = Self {
            schema_version: WORK_INTAKE_SCHEMA_VERSION,
            cycle_id,
            cycle_sequence,
            registration_id: registration.registration_id.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            source_approval_sha256: source_approval.source_approval_sha256.clone(),
            checkpoint_sha256: checkpoint.checkpoint_sha256.clone(),
            issued_at_unix_seconds,
            deadline_unix_seconds,
            maximum_events: registration.resource_limits.maximum_events_per_cycle,
            maximum_record_bytes: registration.resource_limits.maximum_record_bytes,
            request_sha256: ZERO_HASH.to_owned(),
        };
        request.request_sha256 = hash_without(&request, &["request_sha256"])?;
        request.validate(registration, source_approval, checkpoint)?;
        Ok(request)
    }

    pub fn validate(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
        source_approval: &WorkSourceApprovalV1,
        checkpoint: &RadarCheckpointV1,
    ) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.cycle_sequence != checkpoint.cycle_sequence.saturating_add(1)
            || self.issued_at_unix_seconds == 0
            || self.deadline_unix_seconds <= self.issued_at_unix_seconds
            || self
                .deadline_unix_seconds
                .saturating_sub(self.issued_at_unix_seconds)
                > 300
            || self.maximum_events == 0
            || self.maximum_events > registration.resource_limits.maximum_events_per_cycle
            || self.maximum_record_bytes == 0
            || self.maximum_record_bytes > registration.resource_limits.maximum_record_bytes
        {
            return invalid("Radar scan request bounds or deadline are invalid");
        }
        validate_id(&self.cycle_id, "Radar cycle ID")?;
        for (value, label) in [
            (&self.registration_sha256, "scan registration hash"),
            (&self.source_approval_sha256, "scan source approval hash"),
            (&self.checkpoint_sha256, "scan checkpoint hash"),
            (&self.request_sha256, "scan request hash"),
        ] {
            validate_hash(value, label)?;
        }
        if self.registration_id != registration.registration_id
            || self.registration_sha256 != registration.registration_sha256
            || self.source_approval_sha256 != source_approval.source_approval_sha256
            || self.checkpoint_sha256 != checkpoint.checkpoint_sha256
            || hash_without(self, &["request_sha256"])? != self.request_sha256
        {
            return Err(WorkIntakeError::Integrity(
                "Radar scan request binding differs".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Bounded immutable output from one source adapter call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarSignalBatchV1 {
    pub schema_version: u32,
    pub request_sha256: String,
    pub registration_sha256: String,
    pub source_approval_sha256: String,
    pub checkpoint_sha256: String,
    pub signals: Vec<WorkSignalV1>,
    pub records_examined: u32,
    pub bytes_examined: u64,
    pub logical_operations: u64,
    pub completed_at_unix_seconds: u64,
    pub batch_sha256: String,
}

impl RadarSignalBatchV1 {
    pub fn seal(mut self, request: &RadarScanRequestV1) -> Result<Self, WorkIntakeError> {
        self.signals
            .sort_by(|left, right| left.source_sequence.cmp(&right.source_sequence));
        self.batch_sha256 = hash_without(&self, &["batch_sha256"])?;
        self.validate(request)?;
        Ok(self)
    }

    pub fn validate(&self, request: &RadarScanRequestV1) -> Result<(), WorkIntakeError> {
        if self.schema_version != WORK_INTAKE_SCHEMA_VERSION
            || self.signals.len() > request.maximum_events as usize
            || self.signals.len() > MAX_EVENTS_PER_CYCLE
            || self.records_examined < self.signals.len() as u32
            || self.bytes_examined > request.maximum_record_bytes
            || self.logical_operations == 0
            || self.completed_at_unix_seconds < request.issued_at_unix_seconds
            || self.completed_at_unix_seconds > request.deadline_unix_seconds
            || !self
                .signals
                .windows(2)
                .all(|pair| pair[0].source_sequence < pair[1].source_sequence)
        {
            return Err(WorkIntakeError::ResourceLimit(
                "Radar batch violates request bounds or ordering".to_owned(),
            ));
        }
        for signal in &self.signals {
            signal.validate()?;
        }
        for (value, label) in [
            (&self.request_sha256, "batch request"),
            (&self.registration_sha256, "batch registration"),
            (&self.source_approval_sha256, "batch source approval"),
            (&self.checkpoint_sha256, "batch checkpoint"),
            (&self.batch_sha256, "batch hash"),
        ] {
            validate_hash(value, label)?;
        }
        if self.request_sha256 != request.request_sha256
            || self.registration_sha256 != request.registration_sha256
            || self.source_approval_sha256 != request.source_approval_sha256
            || self.checkpoint_sha256 != request.checkpoint_sha256
            || hash_without(self, &["batch_sha256"])? != self.batch_sha256
        {
            return Err(WorkIntakeError::Integrity(
                "Radar batch binding or canonical hash differs".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Explicit signer and caller-time inputs checked before one source scan.
pub struct RadarSourceApprovalVerificationV1<'a> {
    pub source_approval: &'a WorkSourceApprovalV1,
    pub expected_signer_key_id: &'a str,
    pub verifying_key: &'a VerifyingKey,
    pub now_unix_seconds: u64,
}

impl RadarSourceApprovalVerificationV1<'_> {
    fn verify(
        &self,
        registration: &ApprovedRadarSourceRegistrationV1,
    ) -> Result<(), WorkIntakeError> {
        verify_work_source_approval(
            self.source_approval,
            registration,
            self.expected_signer_key_id,
            self.verifying_key,
            self.now_unix_seconds,
        )
    }
}

/// Narrow authority-free observation adapter. It cannot commit checkpoints.
pub trait RadarSourceAdapterV1 {
    fn scan_once(
        &mut self,
        registration: &ApprovedRadarSourceRegistrationV1,
        source_approval: RadarSourceApprovalVerificationV1<'_>,
        checkpoint: &RadarCheckpointV1,
        request: &RadarScanRequestV1,
    ) -> Result<RadarSignalBatchV1, WorkIntakeError>;
}

/// Deterministic local fixture feed used only for conformance and product gates.
#[derive(Debug, Clone)]
pub struct FixtureRadarSourceV1 {
    signals: Vec<WorkSignalV1>,
    bytes_examined: u64,
    completed_at_unix_seconds: u64,
    consumed: bool,
}

impl FixtureRadarSourceV1 {
    pub fn new(
        signals: Vec<WorkSignalV1>,
        bytes_examined: u64,
        completed_at_unix_seconds: u64,
    ) -> Result<Self, WorkIntakeError> {
        if signals.len() > MAX_EVENTS_PER_CYCLE || bytes_examined > crate::MAX_RECORD_BYTES {
            return Err(WorkIntakeError::ResourceLimit(
                "fixture Radar source exceeds global bounds".to_owned(),
            ));
        }
        Ok(Self {
            signals,
            bytes_examined,
            completed_at_unix_seconds,
            consumed: false,
        })
    }
}

impl RadarSourceAdapterV1 for FixtureRadarSourceV1 {
    fn scan_once(
        &mut self,
        registration: &ApprovedRadarSourceRegistrationV1,
        source_approval: RadarSourceApprovalVerificationV1<'_>,
        checkpoint: &RadarCheckpointV1,
        request: &RadarScanRequestV1,
    ) -> Result<RadarSignalBatchV1, WorkIntakeError> {
        if self.consumed {
            return Err(WorkIntakeError::Replay(
                "fixture Radar adapter is one-shot".to_owned(),
            ));
        }
        source_approval.verify(registration)?;
        request.validate(registration, source_approval.source_approval, checkpoint)?;
        self.consumed = true;
        let records_examined = u32::try_from(self.signals.len()).map_err(|_| {
            WorkIntakeError::ResourceLimit("fixture signal count overflow".to_owned())
        })?;
        RadarSignalBatchV1 {
            schema_version: WORK_INTAKE_SCHEMA_VERSION,
            request_sha256: request.request_sha256.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            source_approval_sha256: source_approval
                .source_approval
                .source_approval_sha256
                .clone(),
            checkpoint_sha256: checkpoint.checkpoint_sha256.clone(),
            signals: self.signals.clone(),
            records_examined,
            bytes_examined: self.bytes_examined,
            logical_operations: u64::from(records_examined).saturating_add(1),
            completed_at_unix_seconds: self.completed_at_unix_seconds,
            batch_sha256: ZERO_HASH.to_owned(),
        }
        .seal(request)
    }
}

/// Trusted caller inputs needed to reverify Role governance and admission.
pub struct WorkIntakeEvaluationContextV1<'a> {
    pub role_contract: &'a RoleContractV1,
    pub approval: &'a RoleContractApprovalV1,
    pub delegation: &'a RoleDelegationGrantV1,
    pub role_instance: &'a RoleInstanceV1,
    pub expected_approval_signer_key_id: &'a str,
    pub approval_verifying_key: &'a VerifyingKey,
    pub expected_delegation_signer_key_id: &'a str,
    pub delegation_verifying_key: &'a VerifyingKey,
    pub registration: &'a ApprovedRadarSourceRegistrationV1,
    pub source_approval: &'a WorkSourceApprovalV1,
    pub expected_source_approval_signer_key_id: &'a str,
    pub source_approval_verifying_key: &'a VerifyingKey,
    pub mappings: &'a [WorkIntakeMappingProfileV1],
    pub checkpoint: &'a RadarCheckpointV1,
    pub deduplication_entries: &'a [WorkItemDeduplicationEntryV1],
    pub operational_time_context: RoleOperationalTimeContextV1,
    pub trusted_policy_snapshot_sha256: String,
    pub policy_set_sha256: String,
    pub caller_due_at_unix_seconds: Option<u64>,
    pub now_unix_seconds: u64,
}

/// Authority-free result. `disposition=None` means Desktop must durably create
/// the admitted Case before it may issue an `admitted_case_created` receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntakeEvaluationV1 {
    pub signal_sha256: String,
    pub mapping_sha256: Option<String>,
    pub source_envelope: Option<WorkItemSourceEnvelopeV1>,
    pub work_item: Option<WorkItemV1>,
    pub deduplication_key: Option<WorkItemDeduplicationKeyV1>,
    pub duplicate_result: Option<WorkItemDeduplicationResultV1>,
    pub admission: Option<WorkItemAdmissionDecisionV1>,
    pub disposition: Option<WorkIntakeDispositionV1>,
    pub reason_codes: Vec<String>,
}

impl WorkIntakeEvaluationV1 {
    #[must_use]
    pub fn requires_case_creation(&self) -> bool {
        self.disposition.is_none()
            && self.admission.as_ref().is_some_and(|admission| {
                admission.outcome == d2i_work_case::WorkItemAdmissionOutcomeV1::Admitted
            })
    }
}

/// Revalidates governance and deterministically maps one signal into WORK-200.
pub fn evaluate_work_signal(
    context: WorkIntakeEvaluationContextV1<'_>,
    signal: &WorkSignalV1,
) -> Result<WorkIntakeEvaluationV1, WorkIntakeError> {
    verify_role_contract_approval(
        context.approval,
        context.role_contract,
        context.expected_approval_signer_key_id,
        context.approval_verifying_key,
        context.now_unix_seconds,
    )?;
    verify_role_delegation(
        context.delegation,
        context.role_contract,
        context.approval,
        context.expected_delegation_signer_key_id,
        context.delegation_verifying_key,
        context.now_unix_seconds,
    )?;
    context.registration.validate_against(
        context.role_contract,
        context.delegation,
        context.role_instance,
    )?;
    verify_work_source_approval(
        context.source_approval,
        context.registration,
        context.expected_source_approval_signer_key_id,
        context.source_approval_verifying_key,
        context.now_unix_seconds,
    )?;
    context.checkpoint.validate_against(context.registration)?;

    if signal.event_class_id.is_empty()
        || !context
            .registration
            .allowed_event_class_ids
            .contains(&signal.event_class_id)
    {
        return disposed(
            signal,
            WorkIntakeDispositionV1::UnsupportedEventClass,
            "unsupported_event_class",
        );
    }
    if context.now_unix_seconds < signal.observed_at_unix_seconds
        || context.now_unix_seconds < signal.received_at_unix_seconds
        || context
            .now_unix_seconds
            .saturating_sub(signal.observed_at_unix_seconds)
            > context.registration.maximum_staleness_seconds
    {
        return disposed(signal, WorkIntakeDispositionV1::StaleSource, "stale_source");
    }
    signal.validate_against(context.registration, context.now_unix_seconds)?;
    context
        .checkpoint
        .validate_progress(context.registration, signal)?;

    let candidates = context
        .mappings
        .iter()
        .filter(|mapping| {
            mapping.registration_id == context.registration.registration_id
                && mapping.observation_source_id == signal.source_system_id
                && mapping.event_class_id == signal.event_class_id
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return disposed(
            signal,
            WorkIntakeDispositionV1::Quarantined,
            "mapping_not_found",
        );
    }
    if candidates.len() != 1 {
        return disposed(
            signal,
            WorkIntakeDispositionV1::IntegrityConflict,
            "ambiguous_mapping",
        );
    }
    let mapping = candidates[0];
    mapping.validate_against(
        context.registration,
        context.role_contract,
        context.delegation,
    )?;
    if signal.subject_refs.len() < mapping.minimum_subject_refs as usize
        || signal.structured_input_refs.len() < mapping.minimum_structured_input_refs as usize
    {
        return Ok(WorkIntakeEvaluationV1 {
            signal_sha256: signal.signal_sha256.clone(),
            mapping_sha256: Some(mapping.mapping_sha256.clone()),
            source_envelope: None,
            work_item: None,
            deduplication_key: None,
            duplicate_result: None,
            admission: None,
            disposition: Some(WorkIntakeDispositionV1::ClarificationRequired),
            reason_codes: vec!["required_structured_reference_missing".to_owned()],
        });
    }
    if !is_subset(&mapping.required_trust_labels, &signal.trust_labels)
        || !is_subset(
            &signal.structured_input_kind_ids,
            &mapping.allowed_structured_input_kind_ids,
        )
    {
        return disposed(
            signal,
            WorkIntakeDispositionV1::Quarantined,
            "signal_mapping_trust_mismatch",
        );
    }
    if !role_is_active(context.role_instance, context.now_unix_seconds) {
        // Continue through the existing admission function so WORK-200 remains
        // the authoritative lifecycle classifier.
    }

    let source_envelope = WorkItemSourceEnvelopeV1 {
        schema_version: 1,
        source_envelope_id: format!("source-envelope:{}", signal.signal_id),
        source_kind: source_kind(context.registration.source_kind),
        source_system_id: signal.source_system_id.clone(),
        source_event_id: signal.event_id.clone(),
        organization_id: signal.organization_id.clone(),
        observed_at_unix_seconds: signal.observed_at_unix_seconds,
        received_at_unix_seconds: signal.received_at_unix_seconds,
        trust_labels: signal.trust_labels.clone(),
        provenance: WorkItemProvenanceV1 {
            authenticated_actor_id: signal.provenance.authenticated_actor_id.clone(),
            authentication_class_id: signal.provenance.authentication_class_id.clone(),
            authentication_evidence_sha256: signal
                .provenance
                .authentication_evidence_sha256
                .clone(),
            source_record_sha256: signal.source_record_sha256.clone(),
        },
        payload_reference_sha256: signal.payload_reference_sha256.clone(),
        attachment_reference_hashes: signal.attachment_reference_hashes.clone(),
        evidence_ids: signal.evidence_ids.clone(),
        envelope_sha256: d2i_work_case::canonical_sha256(&())?,
    }
    .seal()?;
    let requested_due_at_unix_seconds = match mapping.due_time_derivation {
        DueTimeDerivationV1::None => None,
        DueTimeDerivationV1::FixedOffsetFromReceived => mapping
            .due_time_offset_seconds
            .map(|offset| signal.received_at_unix_seconds.saturating_add(offset)),
        DueTimeDerivationV1::CallerSupplied => context.caller_due_at_unix_seconds,
    };
    let (work_item, deduplication_key) = normalize_work_item(
        &source_envelope,
        WorkItemNormalizationInputV1 {
            work_item_id: format!("work-item:{}", signal.signal_id),
            work_class_id: mapping.work_class_id.clone(),
            work_class_contract_version: mapping.work_class_contract_version.clone(),
            subject_refs: signal.subject_refs.clone(),
            requested_outcome_class_ids: mapping.requested_outcome_class_ids.clone(),
            requested_evidence_class_ids: mapping.requested_evidence_class_ids.clone(),
            priority_class: mapping.priority_class,
            risk_class: mapping.risk_class,
            application_pack_refs: mapping.application_pack_refs.clone(),
            integration_ids: mapping.integration_ids.clone(),
            capability_requirement_ids: mapping.capability_requirement_ids.clone(),
            semantic_target_ids: mapping.semantic_target_ids.clone(),
            requested_due_at_unix_seconds,
            deduplication_scope_id: mapping.deduplication_scope_id.clone(),
            semantic_payload_sha256: signal.semantic_payload_sha256.clone(),
            content_trust_labels: signal.trust_labels.clone(),
            structured_input_refs: signal.structured_input_refs.clone(),
            evidence_ids: mapping.evidence_ids.clone(),
        },
    )?;
    let duplicate_result = classify_duplicate(&deduplication_key, context.deduplication_entries)?;
    let request = WorkItemAdmissionRequestV1 {
        schema_version: 1,
        request_id: format!("intake-request:{}", signal.signal_id),
        work_item: work_item.clone(),
        source_envelope: source_envelope.clone(),
        role_instance_sha256: context.role_instance.instance_sha256.clone(),
        role_contract_sha256: context.role_contract.contract_sha256.clone(),
        delegation_sha256: context.delegation.delegation_sha256.clone(),
        operational_time_context: context.operational_time_context,
        trusted_policy_snapshot_sha256: context.trusted_policy_snapshot_sha256,
        policy_set_sha256: context.policy_set_sha256,
        deduplication_result: duplicate_result,
        admitted_at_unix_seconds: context.now_unix_seconds,
        evidence_ids: vec![format!("intake-admission:{}", signal.signal_id)],
        request_sha256: d2i_work_case::canonical_sha256(&())?,
    }
    .seal()?;
    let admission = admit_work_item(
        &request,
        context.role_contract,
        context.delegation,
        context.role_instance,
    )?;
    let disposition = (admission.outcome != d2i_work_case::WorkItemAdmissionOutcomeV1::Admitted)
        .then(|| admission_disposition(&admission));
    let mut reason_codes = admission
        .reason_codes
        .iter()
        .map(|reason| format!("{reason:?}").to_ascii_lowercase())
        .collect::<Vec<_>>();
    reason_codes.sort();
    Ok(WorkIntakeEvaluationV1 {
        signal_sha256: signal.signal_sha256.clone(),
        mapping_sha256: Some(mapping.mapping_sha256.clone()),
        source_envelope: Some(source_envelope),
        work_item: Some(work_item),
        deduplication_key: Some(deduplication_key),
        duplicate_result: Some(duplicate_result),
        admission: Some(admission),
        disposition,
        reason_codes,
    })
}

fn disposed(
    signal: &WorkSignalV1,
    disposition: WorkIntakeDispositionV1,
    reason: &str,
) -> Result<WorkIntakeEvaluationV1, WorkIntakeError> {
    Ok(WorkIntakeEvaluationV1 {
        signal_sha256: signal.signal_sha256.clone(),
        mapping_sha256: None,
        source_envelope: None,
        work_item: None,
        deduplication_key: None,
        duplicate_result: None,
        admission: None,
        disposition: Some(disposition),
        reason_codes: vec![reason.to_owned()],
    })
}

fn source_kind(kind: d2i_role_contract::ObservationSourceKindV1) -> WorkItemSourceKindV1 {
    use d2i_role_contract::ObservationSourceKindV1;
    match kind {
        ObservationSourceKindV1::EventStream => WorkItemSourceKindV1::ApprovedSystemEvent,
        ObservationSourceKindV1::Schedule => WorkItemSourceKindV1::ApprovedScheduleEvent,
        ObservationSourceKindV1::ManualAuthenticatedInstruction => {
            WorkItemSourceKindV1::AuthenticatedInstruction
        }
        ObservationSourceKindV1::DesktopUia
        | ObservationSourceKindV1::WebDriver
        | ObservationSourceKindV1::EnterpriseApi
        | ObservationSourceKindV1::SensorSummary => WorkItemSourceKindV1::ApprovedExternalReference,
    }
}
