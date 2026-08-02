use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
    ROLE_CONTRACT_SCHEMA_VERSION,
};
use d2i_work_case::*;
use ed25519_dalek::SigningKey;

const ROLE_SOURCE: &str =
    include_str!("../../../../examples/workforce/kernel-e2e-operator/role.yaml");
pub const ZERO_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub const PACK_HASH: &str =
    "sha256:63af89c06cb5a7b6623e1619718a9a4f3d8346d1387acb52ea339b8ad710411e";

pub fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

pub fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

pub struct Fixture {
    pub role_contract: RoleContractV1,
    pub role_instance: RoleInstanceV1,
    pub work_item: WorkItemV1,
    pub dedup_key: WorkItemDeduplicationKeyV1,
    pub admission: WorkItemAdmissionDecisionV1,
    pub case_contract: CaseContractV1,
    pub case_instance: CaseInstanceV1,
    pub evidence_index: EvidenceIndexV1,
}

pub fn fixture() -> Fixture {
    let role_contract = ok(compile_role_source(
        ROLE_SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    let (delegation, role_instance) = governance(&role_contract);
    fixture_with_governance(role_contract, delegation, role_instance, 1_785_000_010)
}

pub fn fixture_with_governance(
    role_contract: RoleContractV1,
    delegation: RoleDelegationGrantV1,
    role_instance: RoleInstanceV1,
    admitted_at_unix_seconds: u64,
) -> Fixture {
    let envelope = ok(WorkItemSourceEnvelopeV1 {
        schema_version: 1,
        source_envelope_id: "source-envelope-kernel-case".to_owned(),
        source_kind: WorkItemSourceKindV1::AuthenticatedInstruction,
        source_system_id: "kernel-uia".to_owned(),
        source_event_id: "instruction-kernel-name-save-1".to_owned(),
        organization_id: "organization-1".to_owned(),
        observed_at_unix_seconds: admitted_at_unix_seconds.saturating_sub(10),
        received_at_unix_seconds: admitted_at_unix_seconds.saturating_sub(9),
        trust_labels: vec!["authenticated-instruction".to_owned()],
        provenance: WorkItemProvenanceV1 {
            authenticated_actor_id: "kernel-e2e-actor".to_owned(),
            authentication_class_id: "local-test-signature".to_owned(),
            authentication_evidence_sha256: digest('c'),
            source_record_sha256: digest('d'),
        },
        payload_reference_sha256: digest('e'),
        attachment_reference_hashes: Vec::new(),
        evidence_ids: vec!["authenticated-source-evidence".to_owned()],
        envelope_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let (work_item, dedup_key) = ok(normalize_work_item(
        &envelope,
        WorkItemNormalizationInputV1 {
            work_item_id: "work-item-kernel-name-save".to_owned(),
            work_class_id: "workforce.kernel_e2e.name_save".to_owned(),
            work_class_contract_version: "1.0.0".to_owned(),
            subject_refs: vec!["employee-record:opaque-1".to_owned()],
            requested_outcome_class_ids: vec!["employee-name-saved".to_owned()],
            requested_evidence_class_ids: vec![
                "final-goal-verification".to_owned(),
                "kernel-task-run-record".to_owned(),
                "work-report".to_owned(),
            ],
            priority_class: WorkPriorityClassV1::Normal,
            risk_class: CognitiveRiskClass::BusinessStateChange,
            application_pack_refs: vec![WorkApplicationPackRefV1 {
                application_pack_id: "kernel-e2e-name-save".to_owned(),
                application_pack_sha256: PACK_HASH.to_owned(),
            }],
            integration_ids: vec!["windows-kernel-e2e".to_owned()],
            capability_requirement_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            semantic_target_ids: vec!["employee_name_input".to_owned(), "save_button".to_owned()],
            requested_due_at_unix_seconds: Some(
                role_instance.expires_at_unix_seconds.saturating_sub(1),
            ),
            deduplication_scope_id: "kernel-name-save".to_owned(),
            semantic_payload_sha256: digest('f'),
            content_trust_labels: vec!["authenticated-structured-input".to_owned()],
            structured_input_refs: vec!["employee-name-value:fixture".to_owned()],
            evidence_ids: vec!["normalized-work-evidence".to_owned()],
        },
    ));
    let time = ok(RoleOperationalTimeContextV1 {
        schema_version: 1,
        calendar_sha256: role_contract.working_calendar.calendar_sha256.clone(),
        timezone_id: role_contract.working_calendar.timezone_id.clone(),
        local_date: "2026-08-03".to_owned(),
        weekday: 0,
        local_minute_of_day: 600,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: admitted_at_unix_seconds.saturating_sub(5),
        evidence_ids: vec!["trusted-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let request = ok(WorkItemAdmissionRequestV1 {
        schema_version: 1,
        request_id: "request-kernel-case".to_owned(),
        work_item: work_item.clone(),
        source_envelope: envelope,
        role_instance_sha256: role_instance.instance_sha256.clone(),
        role_contract_sha256: role_contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        operational_time_context: time,
        trusted_policy_snapshot_sha256: digest('2'),
        policy_set_sha256: role_contract.policy_set_sha256.clone(),
        deduplication_result: WorkItemDeduplicationResultV1::New,
        admitted_at_unix_seconds,
        evidence_ids: vec!["work-admission-evidence".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let admission = ok(admit_work_item(
        &request,
        &role_contract,
        &delegation,
        &role_instance,
    ));
    let ownership = ok(CaseOwnershipBindingV1::create(
        "case-kernel-name-save".to_owned(),
        &work_item,
        &admission,
        &role_contract,
        &delegation,
        &role_instance,
        admitted_at_unix_seconds.saturating_add(1),
        role_instance.expires_at_unix_seconds,
        vec!["ownership-evidence".to_owned()],
    ));
    let sla_profile = match role_contract
        .sla_profiles
        .iter()
        .find(|profile| profile.sla_profile_id == "kernel-e2e-sla")
    {
        Some(value) => value,
        None => panic!("fixture SLA profile absent"),
    };
    let sla = ok(CaseSlaBindingV1::create(
        ownership.case_id.clone(),
        work_item.priority_class,
        work_item.received_at_unix_seconds,
        sla_profile,
        vec!["sla-binding-evidence".to_owned()],
    ));
    let success = ok(CaseSuccessRequirementV1 {
        requirement_id: "goal-complete".to_owned(),
        outcome_class_id: "employee-name-saved".to_owned(),
        verification_kind: CaseVerificationKindV1::KernelGoalComplete,
        required: true,
        minimum_satisfied_count: 1,
        referenced_requirement_ids: Vec::new(),
        target_state_ref: None,
        comparison_op: None,
        expected_value_hash: None,
        trusted_evidence_class_ids: vec!["final-goal-verification".to_owned()],
        authoritative_source_class_ids: vec!["kernel-final-verifier".to_owned()],
        evidence_ids: vec!["outcome-requirement-evidence".to_owned()],
        requirement_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let evidence_requirements = vec![
        evidence_requirement(
            "require-kernel-run",
            "kernel-task-run-record",
            "kernel-task-run-record",
            CaseEvidenceProducerKindV1::KernelTaskRun,
        ),
        evidence_requirement(
            "require-final-verification",
            "final-goal-verification",
            "final-goal-verification",
            CaseEvidenceProducerKindV1::FinalGoalVerification,
        ),
        evidence_requirement(
            "require-work-report",
            "work-report",
            "work-report",
            CaseEvidenceProducerKindV1::KernelTaskRun,
        ),
    ];
    let case_contract = ok(CaseContractV1 {
        schema_version: 1,
        case_id: ownership.case_id.clone(),
        case_generation: 1,
        organization_id: work_item.organization_id.clone(),
        source_work_item_id: work_item.work_item_id.clone(),
        source_work_item_sha256: work_item.work_item_sha256.clone(),
        work_item_admission_sha256: admission.decision_sha256.clone(),
        role_instance_id: role_instance.role_instance_id.clone(),
        role_contract_sha256: role_contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        ownership_binding: ownership,
        work_class_id: work_item.work_class_id.clone(),
        responsibility_id: "verified-name-save".to_owned(),
        priority_class: work_item.priority_class,
        risk_class: work_item.risk_class,
        subject_refs: work_item.subject_refs.clone(),
        outcome_requirements: vec![success],
        evidence_requirements,
        sla_binding: sla,
        allowed_application_pack_refs: work_item.application_pack_refs.clone(),
        allowed_integration_ids: work_item.integration_ids.clone(),
        allowed_capability_ids: work_item.capability_requirement_ids.clone(),
        prohibited_capability_ids: vec!["uia.set_protected".to_owned()],
        allowed_semantic_target_ids: work_item.semantic_target_ids.clone(),
        maximum_task_attempts: 3,
        maximum_recovery_cycles_per_task: 2,
        clarification_allowed: true,
        automatic_recovery_allowed: true,
        mandatory_escalation_reason_codes: vec!["unsafe_verification".to_owned()],
        reporting_obligation_ids: admission.selected_reporting_obligation_ids.clone(),
        retention_class_id: "test-evidence".to_owned(),
        opened_at_unix_seconds: admitted_at_unix_seconds.saturating_add(1),
        evidence_ids: vec!["case-contract-evidence".to_owned()],
        contract_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(
        &work_item,
        &admission,
        &role_contract,
        &delegation,
        &role_instance,
    ));
    let evidence_index = ok(EvidenceIndexV1::empty(case_contract.case_id.clone()));
    let case_instance = ok(CaseInstanceV1::open(
        &case_contract,
        evidence_index.index_sha256.clone(),
        "case-ledger-example".to_owned(),
        digest('0'),
        vec!["case-open-evidence".to_owned()],
    ));
    Fixture {
        role_contract,
        role_instance,
        work_item,
        dedup_key,
        admission,
        case_contract,
        case_instance,
        evidence_index,
    }
}

fn evidence_requirement(
    id: &str,
    class: &str,
    artifact: &str,
    producer: CaseEvidenceProducerKindV1,
) -> CaseEvidenceRequirementV1 {
    ok(CaseEvidenceRequirementV1 {
        evidence_requirement_id: id.to_owned(),
        evidence_class_id: class.to_owned(),
        minimum_count: 1,
        accepted_producer_kinds: vec![producer],
        required_trust_floor: CaseEvidenceTrustFloorV1::Trusted,
        required_artifact_type_ids: vec![artifact.to_owned()],
        maximum_staleness_seconds: None,
        retention_class_id: "test-evidence".to_owned(),
        redaction_required: true,
        required: true,
        requirement_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn governance(contract: &RoleContractV1) -> (RoleDelegationGrantV1, RoleInstanceV1) {
    let approval = ok(create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            approval_id: "approval-kernel-case-v1".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "organization-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            approval_signature: String::new(),
            evidence_ids: vec!["organization-approval-record".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        contract,
        &SigningKey::from_bytes(&[7_u8; 32]),
    ));
    let delegation = ok(create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: 1,
            delegation_id: "delegation-kernel-case-v1".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: "kernel-e2e-actor".to_owned(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: contract.organization_scope.clone(),
            delegated_work_class_ids: vec!["workforce.kernel_e2e.name_save".to_owned()],
            delegated_application_pack_ids: vec!["kernel-e2e-name-save".to_owned()],
            delegated_integration_ids: vec!["windows-kernel-e2e".to_owned()],
            delegated_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            autonomous_capability_ids: vec!["uia.set_value".to_owned()],
            confirmation_capability_ids: vec!["uia.invoke".to_owned()],
            prohibited_capability_ids: vec!["uia.set_protected".to_owned()],
            maximum_autonomous_risk: CognitiveRiskClass::Reversible,
            maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            assigned_by_actor_id: "organization-role-assigner".to_owned(),
            signer_key_id: "delegation-key-v1".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["delegation-record".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        contract,
        &approval,
        &SigningKey::from_bytes(&[11_u8; 32]),
    ));
    let provisioned = ok(RoleInstanceV1::provision(
        "kernel-e2e-actor".to_owned(),
        contract,
        &approval,
        &delegation,
        "role-ledger-kernel-e2e".to_owned(),
        digest('a'),
        digest('b'),
        vec!["role-instance-provisioned".to_owned()],
    ));
    let active = ok(provisioned.transition(RoleInstanceStatusV1::Active, 1_785_000_000));
    (delegation, active)
}
