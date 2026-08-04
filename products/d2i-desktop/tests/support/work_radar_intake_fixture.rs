use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{
    initialize_role_instance_ledger, RoleInstanceLedgerEventKindV1, RoleInstanceLedgerRecordV1,
    RoleInstanceLedgerV1,
};
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
};
use d2i_work_case::*;
use d2i_work_intake::*;
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::Path;

const ROLE_SOURCE: &str =
    include_str!("../../../../examples/workforce/general-office-operations-employee/role.yaml");
pub const NOW: u64 = 1_785_000_100;

pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

pub fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

pub struct GovernanceFixture {
    pub contract: RoleContractV1,
    pub approval: RoleContractApprovalV1,
    pub delegation: RoleDelegationGrantV1,
    pub instance: RoleInstanceV1,
    pub approval_key: SigningKey,
    pub delegation_key: SigningKey,
    pub source_approval_key: SigningKey,
    pub role_ledger_head: String,
}

pub fn activate_governance(root: &Path) -> GovernanceFixture {
    let contract = ok(compile_role_source(
        ROLE_SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    let approval_key = SigningKey::from_bytes(&[31_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[37_u8; 32]);
    let source_approval_key = SigningKey::from_bytes(&[41_u8; 32]);
    let approval = ok(create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: 1,
            approval_id: "approval-general-office-radar".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "office-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "office-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            approval_signature: String::new(),
            evidence_ids: vec!["office-role-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval_key,
    ));
    let delegation = ok(create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: 1,
            delegation_id: "delegation-general-office-radar".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: "general-office-role-instance".to_owned(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: contract.organization_scope.clone(),
            delegated_work_class_ids: contract
                .accepted_work_classes
                .iter()
                .map(|work| work.work_class_id.clone())
                .collect(),
            delegated_application_pack_ids: vec!["kernel-e2e-name-save".to_owned()],
            delegated_integration_ids: vec!["internal-records-read".to_owned()],
            delegated_capability_ids: vec!["enterprise_api.read".to_owned()],
            autonomous_capability_ids: vec!["enterprise_api.read".to_owned()],
            confirmation_capability_ids: Vec::new(),
            prohibited_capability_ids: vec![
                "enterprise_api.delete".to_owned(),
                "enterprise_api.write".to_owned(),
            ],
            maximum_autonomous_risk: CognitiveRiskClass::ReadOnly,
            maximum_confirmable_risk: CognitiveRiskClass::Reversible,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            assigned_by_actor_id: "office-role-assigner".to_owned(),
            signer_key_id: "office-delegation-key-v1".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["office-role-delegation".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval,
        &delegation_key,
    ));
    let mut ledger = ok(initialize_role_instance_ledger(
        root,
        "role-ledger-general-office",
        "general-office-role-instance",
        128,
        1_784_999_000_000,
    ));
    append_role(
        &mut ledger,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleContractRegistered,
        None,
        1_784_999_100_000,
    );
    append_role(
        &mut ledger,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleContractApproved,
        None,
        1_784_999_200_000,
    );
    let provisioned = ok(RoleInstanceV1::provision(
        "general-office-role-instance".to_owned(),
        &contract,
        &approval,
        &delegation,
        "role-ledger-general-office".to_owned(),
        digest('a'),
        digest('b'),
        vec!["general-office-role-provisioned".to_owned()],
    ));
    let provisioned =
        ok(provisioned.bind_ledger_head(ledger.verification().terminal_record_hash.clone()));
    append_role(
        &mut ledger,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleInstanceProvisioned,
        Some(provisioned),
        1_784_999_300_000,
    );
    let active = ok(ledger
        .verification()
        .current_instance
        .as_ref()
        .unwrap_or_else(|| panic!("provisioned Role is absent"))
        .transition(RoleInstanceStatusV1::Active, 1_785_000_000));
    append_role(
        &mut ledger,
        &contract,
        RoleInstanceLedgerEventKindV1::RoleInstanceActivated,
        Some(active),
        1_785_000_000_000,
    );
    let instance = ledger
        .verification()
        .current_instance
        .clone()
        .unwrap_or_else(|| panic!("active Role is absent"));
    GovernanceFixture {
        contract,
        approval,
        delegation,
        instance,
        approval_key,
        delegation_key,
        source_approval_key,
        role_ledger_head: ledger.verification().terminal_record_hash.clone(),
    }
}

fn append_role(
    ledger: &mut RoleInstanceLedgerV1,
    contract: &RoleContractV1,
    event_kind: RoleInstanceLedgerEventKindV1,
    instance_after: Option<RoleInstanceV1>,
    recorded_at_unix_ms: u64,
) {
    ok(ledger.append(RoleInstanceLedgerRecordV1 {
        schema_version: 1,
        sequence: 1,
        ledger_id: "role-ledger-general-office".to_owned(),
        role_instance_id: "general-office-role-instance".to_owned(),
        event_kind,
        role_contract_id: contract.role_contract_id.clone(),
        role_version: contract.role_version.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        instance_after,
        task_request_sha256: None,
        task_admission_sha256: None,
        role_context_sha256: None,
        artifact_hashes: BTreeMap::new(),
        audit_record_hash: digest('9'),
        recorded_at_unix_ms,
        previous_record_hash: ZERO_HASH.to_owned(),
        record_hash: ZERO_HASH.to_owned(),
    }));
}

pub fn registration(governance: &GovernanceFixture) -> ApprovedRadarSourceRegistrationV1 {
    ok(
        ApprovedRadarSourceRegistrationV1 {
            schema_version: 1,
            registration_id: "radar-registration-internal-records".to_owned(),
            organization_id: governance
                .contract
                .organization_scope
                .organization_id
                .clone(),
            role_contract_id: governance.contract.role_contract_id.clone(),
            role_contract_sha256: governance.contract.contract_sha256.clone(),
            role_instance_id: governance.instance.role_instance_id.clone(),
            role_instance_sha256: governance.instance.instance_sha256.clone(),
            approval_sha256: governance.approval.approval_sha256.clone(),
            delegation_sha256: governance.delegation.delegation_sha256.clone(),
            observation_source_id: "internal-records".to_owned(),
            source_kind: d2i_role_contract::ObservationSourceKindV1::EnterpriseApi,
            integration_id: "internal-records-read".to_owned(),
            application_pack_ref: Some(WorkApplicationPackRefV1 {
                application_pack_id: "kernel-e2e-name-save".to_owned(),
                application_pack_sha256:
                    "sha256:63af89c06cb5a7b6623e1619718a9a4f3d8346d1387acb52ea339b8ad710411e"
                        .to_owned(),
            }),
            allowed_event_class_ids: vec!["internal-record-updated".to_owned()],
            minimum_trust_label: "authenticated-internal-record".to_owned(),
            maximum_staleness_seconds: 300,
            cursor_policy: RadarCursorPolicyV1::SequenceOnly,
            maximum_sequence_advance: 1,
            resource_limits: RadarResourceLimitsV1 {
                maximum_events_per_cycle: 128,
                maximum_subject_refs_per_event: 16,
                maximum_structured_input_refs_per_event: 16,
                maximum_attachment_refs_per_event: 16,
                maximum_evidence_ids_per_event: 32,
                maximum_trust_labels_per_event: 16,
                maximum_event_id_bytes: 128,
                maximum_record_bytes: 1_048_576,
                maximum_output_bytes: 1_048_576,
                maximum_receipts_per_cycle: 128,
                maximum_ledger_records: 4096,
                maximum_logical_operations: 4096,
                maximum_ticks: 4096,
                maximum_retries: 0,
                maximum_concurrent_requests: 1,
            },
            enabled: true,
            evidence_ids: vec!["approved-radar-source".to_owned()],
            registration_sha256: ZERO_HASH.to_owned(),
        }
        .seal_against(
            &governance.contract,
            &governance.delegation,
            &governance.instance,
        ),
    )
}

pub fn source_approval(
    governance: &GovernanceFixture,
    registration: &ApprovedRadarSourceRegistrationV1,
) -> WorkSourceApprovalV1 {
    ok(create_work_source_approval(
        WorkSourceApprovalV1 {
            schema_version: 1,
            source_approval_id: "source-approval-internal-records".to_owned(),
            organization_id: registration.organization_id.clone(),
            role_contract_id: registration.role_contract_id.clone(),
            role_contract_sha256: registration.role_contract_sha256.clone(),
            role_instance_id: registration.role_instance_id.clone(),
            role_instance_sha256: registration.role_instance_sha256.clone(),
            role_approval_sha256: registration.approval_sha256.clone(),
            delegation_sha256: registration.delegation_sha256.clone(),
            registration_id: registration.registration_id.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            approved_by_actor_id: "office-source-governance".to_owned(),
            signer_key_id: "office-source-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            evidence_ids: vec!["approved-internal-record-source".to_owned()],
            approval_signature: String::new(),
            source_approval_sha256: ZERO_HASH.to_owned(),
        },
        registration,
        &governance.contract,
        &governance.delegation,
        &governance.instance,
        &governance.source_approval_key,
    ))
}

pub fn mapping(
    governance: &GovernanceFixture,
    registration: &ApprovedRadarSourceRegistrationV1,
) -> WorkIntakeMappingProfileV1 {
    ok(WorkIntakeMappingProfileV1 {
        schema_version: 1,
        mapping_id: "mapping-office-record-update".to_owned(),
        mapping_version: "1.0.0".to_owned(),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        observation_source_id: registration.observation_source_id.clone(),
        event_class_id: "internal-record-updated".to_owned(),
        work_class_id: "office.record.update".to_owned(),
        work_class_contract_version: "1.0.0".to_owned(),
        requested_outcome_class_ids: vec!["internal-record-update-prepared".to_owned()],
        requested_evidence_class_ids: vec!["approved-record-reference".to_owned()],
        priority_class: WorkPriorityClassV1::Normal,
        risk_class: CognitiveRiskClass::ReadOnly,
        application_pack_refs: vec![registration
            .application_pack_ref
            .clone()
            .unwrap_or_else(|| panic!("registration pack is absent"))],
        integration_ids: vec!["internal-records-read".to_owned()],
        capability_requirement_ids: vec!["enterprise_api.read".to_owned()],
        semantic_target_ids: vec!["employee_name_input".to_owned()],
        deduplication_scope_id: "office-internal-record".to_owned(),
        required_trust_labels: vec!["authenticated-internal-record".to_owned()],
        allowed_structured_input_kind_ids: vec!["internal-record-ref".to_owned()],
        minimum_subject_refs: 1,
        minimum_structured_input_refs: 1,
        due_time_derivation: DueTimeDerivationV1::FixedOffsetFromReceived,
        due_time_offset_seconds: Some(86_400),
        evidence_ids: vec!["approved-intake-mapping".to_owned()],
        mapping_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(registration, &governance.contract, &governance.delegation))
}

pub fn signal(
    registration: &ApprovedRadarSourceRegistrationV1,
    event_id: &str,
    sequence: u64,
    semantic: char,
) -> WorkSignalV1 {
    ok(WorkSignalV1 {
        schema_version: 1,
        signal_id: format!("signal-office-record-{sequence}"),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        organization_id: registration.organization_id.clone(),
        role_instance_id: registration.role_instance_id.clone(),
        delegation_sha256: registration.delegation_sha256.clone(),
        source_system_id: registration.observation_source_id.clone(),
        event_id: event_id.to_owned(),
        source_sequence: sequence,
        source_cursor: None,
        event_class_id: "internal-record-updated".to_owned(),
        observed_at_unix_seconds: NOW - 10,
        received_at_unix_seconds: NOW - 9,
        source_record_sha256: digest('c'),
        payload_reference_sha256: digest('d'),
        attachment_reference_hashes: Vec::new(),
        subject_refs: vec!["employee-record:opaque-1".to_owned()],
        structured_input_kind_ids: vec!["internal-record-ref".to_owned()],
        structured_input_refs: vec!["record-change:opaque-approved".to_owned()],
        trust_labels: vec!["authenticated-internal-record".to_owned()],
        provenance: WorkSignalProvenanceV1 {
            authenticated_actor_id: "fixture-office-records-system".to_owned(),
            authentication_class_id: "fixture-signed-record".to_owned(),
            authentication_evidence_sha256: digest('e'),
        },
        semantic_payload_sha256: digest(semantic),
        evidence_ids: vec!["fixture-office-record-evidence".to_owned()],
        signal_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

pub fn evaluate(
    governance: &GovernanceFixture,
    registration: &ApprovedRadarSourceRegistrationV1,
    source_approval: &WorkSourceApprovalV1,
    mapping: &WorkIntakeMappingProfileV1,
    checkpoint: &RadarCheckpointV1,
    signal: &WorkSignalV1,
    entries: &[WorkItemDeduplicationEntryV1],
) -> WorkIntakeEvaluationV1 {
    ok(evaluate_work_signal(
        WorkIntakeEvaluationContextV1 {
            role_contract: &governance.contract,
            approval: &governance.approval,
            delegation: &governance.delegation,
            role_instance: &governance.instance,
            expected_approval_signer_key_id: "office-approval-key-v1",
            approval_verifying_key: &governance.approval_key.verifying_key(),
            expected_delegation_signer_key_id: "office-delegation-key-v1",
            delegation_verifying_key: &governance.delegation_key.verifying_key(),
            registration,
            source_approval,
            expected_source_approval_signer_key_id: "office-source-approval-key-v1",
            source_approval_verifying_key: &governance.source_approval_key.verifying_key(),
            mappings: std::slice::from_ref(mapping),
            checkpoint,
            deduplication_entries: entries,
            operational_time_context: operational_time(&governance.contract),
            trusted_policy_snapshot_sha256: digest('2'),
            policy_set_sha256: governance.contract.policy_set_sha256.clone(),
            caller_due_at_unix_seconds: None,
            now_unix_seconds: NOW,
        },
        signal,
    ))
}

fn operational_time(contract: &RoleContractV1) -> RoleOperationalTimeContextV1 {
    ok(RoleOperationalTimeContextV1 {
        schema_version: 1,
        calendar_sha256: contract.working_calendar.calendar_sha256.clone(),
        timezone_id: contract.working_calendar.timezone_id.clone(),
        local_date: "2026-08-03".to_owned(),
        weekday: 0,
        local_minute_of_day: 600,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: NOW - 5,
        evidence_ids: vec!["trusted-intake-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

pub struct NewCaseArtifacts {
    pub contract: CaseContractV1,
    pub instance: CaseInstanceV1,
    pub evidence_index: EvidenceIndexV1,
}

pub fn new_case(
    governance: &GovernanceFixture,
    evaluation: &WorkIntakeEvaluationV1,
    case_ledger_id: &str,
) -> NewCaseArtifacts {
    new_case_with_id(
        governance,
        evaluation,
        case_ledger_id,
        "case-office-record-update-1",
    )
}

pub fn new_case_with_id(
    governance: &GovernanceFixture,
    evaluation: &WorkIntakeEvaluationV1,
    case_ledger_id: &str,
    case_id: &str,
) -> NewCaseArtifacts {
    let work_item = evaluation
        .work_item
        .as_ref()
        .unwrap_or_else(|| panic!("admitted Work Item is absent"));
    let admission = evaluation
        .admission
        .as_ref()
        .unwrap_or_else(|| panic!("admission is absent"));
    let case_id = case_id.to_owned();
    let ownership = ok(CaseOwnershipBindingV1::create(
        case_id.clone(),
        work_item,
        admission,
        &governance.contract,
        &governance.delegation,
        &governance.instance,
        NOW + 1,
        governance.instance.expires_at_unix_seconds,
        vec!["intake-case-ownership".to_owned()],
    ));
    let role_sla = governance
        .contract
        .sla_profiles
        .iter()
        .find(|profile| profile.sla_profile_id == "office-standard")
        .unwrap_or_else(|| panic!("office SLA is absent"));
    let sla = ok(CaseSlaBindingV1::create(
        case_id.clone(),
        work_item.priority_class,
        work_item.received_at_unix_seconds,
        role_sla,
        vec!["intake-case-sla".to_owned()],
    ));
    let success = ok(CaseSuccessRequirementV1 {
        requirement_id: "internal-record-update-prepared".to_owned(),
        outcome_class_id: "internal-record-update-prepared".to_owned(),
        verification_kind: CaseVerificationKindV1::TrustedEvidencePresent,
        required: true,
        minimum_satisfied_count: 1,
        referenced_requirement_ids: Vec::new(),
        target_state_ref: None,
        comparison_op: None,
        expected_value_hash: None,
        trusted_evidence_class_ids: vec!["approved-record-reference".to_owned()],
        authoritative_source_class_ids: vec!["internal-records".to_owned()],
        evidence_ids: vec!["intake-success-requirement".to_owned()],
        requirement_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let evidence = ok(CaseEvidenceRequirementV1 {
        evidence_requirement_id: "approved-record-reference-required".to_owned(),
        evidence_class_id: "approved-record-reference".to_owned(),
        minimum_count: 1,
        accepted_producer_kinds: vec![CaseEvidenceProducerKindV1::SignedExternalEvidence],
        required_trust_floor: CaseEvidenceTrustFloorV1::Authenticated,
        required_artifact_type_ids: vec!["approved-record-reference".to_owned()],
        maximum_staleness_seconds: Some(300),
        retention_class_id: governance
            .contract
            .memory_boundary
            .retention_class_id
            .clone(),
        redaction_required: true,
        required: true,
        requirement_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let work = governance
        .contract
        .accepted_work_classes
        .iter()
        .find(|candidate| candidate.work_class_id == work_item.work_class_id)
        .unwrap_or_else(|| panic!("accepted work class is absent"));
    let contract = ok(CaseContractV1 {
        schema_version: 1,
        case_id: case_id.clone(),
        case_generation: 1,
        organization_id: work_item.organization_id.clone(),
        source_work_item_id: work_item.work_item_id.clone(),
        source_work_item_sha256: work_item.work_item_sha256.clone(),
        work_item_admission_sha256: admission.decision_sha256.clone(),
        role_instance_id: governance.instance.role_instance_id.clone(),
        role_contract_sha256: governance.contract.contract_sha256.clone(),
        delegation_sha256: governance.delegation.delegation_sha256.clone(),
        ownership_binding: ownership,
        work_class_id: work_item.work_class_id.clone(),
        responsibility_id: admission
            .selected_responsibility_id
            .clone()
            .unwrap_or_else(|| panic!("responsibility is absent")),
        priority_class: work_item.priority_class,
        risk_class: work_item.risk_class,
        subject_refs: work_item.subject_refs.clone(),
        outcome_requirements: vec![success],
        evidence_requirements: vec![evidence],
        sla_binding: sla,
        allowed_application_pack_refs: work_item.application_pack_refs.clone(),
        allowed_integration_ids: work_item.integration_ids.clone(),
        allowed_capability_ids: work_item.capability_requirement_ids.clone(),
        prohibited_capability_ids: governance
            .contract
            .capability_policy
            .prohibited_capability_ids
            .clone(),
        allowed_semantic_target_ids: work_item.semantic_target_ids.clone(),
        maximum_task_attempts: 4,
        maximum_recovery_cycles_per_task: 2,
        clarification_allowed: work.clarification_allowed,
        automatic_recovery_allowed: work.automatic_recovery_allowed,
        mandatory_escalation_reason_codes: work.mandatory_escalation_reason_codes.clone(),
        reporting_obligation_ids: admission.selected_reporting_obligation_ids.clone(),
        retention_class_id: governance
            .contract
            .memory_boundary
            .retention_class_id
            .clone(),
        opened_at_unix_seconds: NOW + 1,
        evidence_ids: vec!["intake-case-contract".to_owned()],
        contract_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(
        work_item,
        admission,
        &governance.contract,
        &governance.delegation,
        &governance.instance,
    ));
    let evidence_index = ok(EvidenceIndexV1::empty(case_id));
    let instance = ok(CaseInstanceV1::open(
        &contract,
        evidence_index.index_sha256.clone(),
        case_ledger_id.to_owned(),
        ZERO_HASH.to_owned(),
        vec!["intake-case-opened".to_owned()],
    ));
    NewCaseArtifacts {
        contract,
        instance,
        evidence_index,
    }
}
