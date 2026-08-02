use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_cognitive_recovery::{
    EscalationRequestV1, EscalationSeverityV1, RecommendedNextActionCodeV1, RecoveryReasonCodeV1,
    RecoveryStageV1, RequiredAuthorityClassV1, SafeStateSummaryCodeV1, RECOVERY_SCHEMA_VERSION,
};
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
    ROLE_CONTRACT_SCHEMA_VERSION,
};
use d2i_work_case::*;
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};

const ROLE_SOURCE: &str = include_str!("../../../examples/workforce/kernel-e2e-operator/role.yaml");
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn role_contract() -> RoleContractV1 {
    ok(compile_role_source(
        ROLE_SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract
}

fn governance(
    contract: &RoleContractV1,
) -> (
    RoleContractApprovalV1,
    RoleDelegationGrantV1,
    RoleInstanceV1,
) {
    let approval_key = SigningKey::from_bytes(&[7_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[11_u8; 32]);
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
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 10_000,
            approval_signature: String::new(),
            evidence_ids: vec!["organization-approval-record".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        contract,
        &approval_key,
    ));
    let delegation = ok(create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
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
            valid_from_unix_seconds: 200,
            expires_at_unix_seconds: 9_000,
            assigned_by_actor_id: "organization-role-assigner".to_owned(),
            signer_key_id: "delegation-key-v1".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["delegation-record".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        contract,
        &approval,
        &delegation_key,
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
    let active = ok(provisioned.transition(RoleInstanceStatusV1::Active, 300));
    (approval, delegation, active)
}

fn source_envelope() -> WorkItemSourceEnvelopeV1 {
    ok(WorkItemSourceEnvelopeV1 {
        schema_version: 1,
        source_envelope_id: "source-envelope-kernel-case".to_owned(),
        source_kind: WorkItemSourceKindV1::AuthenticatedInstruction,
        source_system_id: "kernel-uia".to_owned(),
        source_event_id: "instruction-kernel-name-save-1".to_owned(),
        organization_id: "organization-1".to_owned(),
        observed_at_unix_seconds: 400,
        received_at_unix_seconds: 401,
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
    .seal())
}

fn normalized_work_item(
    envelope: &WorkItemSourceEnvelopeV1,
) -> (WorkItemV1, WorkItemDeduplicationKeyV1) {
    ok(normalize_work_item(
        envelope,
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
                application_pack_sha256:
                    "sha256:63af89c06cb5a7b6623e1619718a9a4f3d8346d1387acb52ea339b8ad710411e"
                        .to_owned(),
            }],
            integration_ids: vec!["windows-kernel-e2e".to_owned()],
            capability_requirement_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
            semantic_target_ids: vec!["employee_name_input".to_owned(), "save_button".to_owned()],
            requested_due_at_unix_seconds: Some(700),
            deduplication_scope_id: "kernel-name-save".to_owned(),
            semantic_payload_sha256: digest('f'),
            content_trust_labels: vec!["authenticated-structured-input".to_owned()],
            structured_input_refs: vec!["employee-name-value:fixture".to_owned()],
            evidence_ids: vec!["normalized-work-evidence".to_owned()],
        },
    ))
}

fn time_context(contract: &RoleContractV1) -> RoleOperationalTimeContextV1 {
    ok(RoleOperationalTimeContextV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        calendar_sha256: contract.working_calendar.calendar_sha256.clone(),
        timezone_id: contract.working_calendar.timezone_id.clone(),
        local_date: "2026-08-03".to_owned(),
        weekday: 0,
        local_minute_of_day: 600,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: 405,
        evidence_ids: vec!["trusted-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

struct Fixture {
    contract: RoleContractV1,
    delegation: RoleDelegationGrantV1,
    instance: RoleInstanceV1,
    envelope: WorkItemSourceEnvelopeV1,
    work_item: WorkItemV1,
    dedup_key: WorkItemDeduplicationKeyV1,
    admission: WorkItemAdmissionDecisionV1,
    case_contract: CaseContractV1,
    case_instance: CaseInstanceV1,
    evidence_index: EvidenceIndexV1,
}

fn fixture() -> Fixture {
    let contract = role_contract();
    let (_, delegation, instance) = governance(&contract);
    let envelope = source_envelope();
    let (work_item, dedup_key) = normalized_work_item(&envelope);
    let request = ok(WorkItemAdmissionRequestV1 {
        schema_version: 1,
        request_id: "request-kernel-case".to_owned(),
        work_item: work_item.clone(),
        source_envelope: envelope.clone(),
        role_instance_sha256: instance.instance_sha256.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        operational_time_context: time_context(&contract),
        trusted_policy_snapshot_sha256: digest('2'),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        deduplication_result: WorkItemDeduplicationResultV1::New,
        admitted_at_unix_seconds: 410,
        evidence_ids: vec!["work-admission-evidence".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let admission = ok(admit_work_item(&request, &contract, &delegation, &instance));
    assert_eq!(
        admission.outcome,
        WorkItemAdmissionOutcomeV1::Admitted,
        "unexpected admission reasons: {:?}",
        admission.reason_codes
    );
    let ownership = ok(CaseOwnershipBindingV1::create(
        "case-kernel-name-save".to_owned(),
        &work_item,
        &admission,
        &contract,
        &delegation,
        &instance,
        411,
        8_000,
        vec!["ownership-evidence".to_owned()],
    ));
    let sla_profile = match contract
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
    let outcome = ok(CaseSuccessRequirementV1 {
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
        role_instance_id: instance.role_instance_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        ownership_binding: ownership,
        work_class_id: work_item.work_class_id.clone(),
        responsibility_id: "verified-name-save".to_owned(),
        priority_class: work_item.priority_class,
        risk_class: work_item.risk_class,
        subject_refs: work_item.subject_refs.clone(),
        outcome_requirements: vec![outcome],
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
        opened_at_unix_seconds: 411,
        evidence_ids: vec!["case-contract-evidence".to_owned()],
        contract_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&work_item, &admission, &contract, &delegation, &instance));
    let evidence_index = ok(EvidenceIndexV1::empty(case_contract.case_id.clone()));
    let case_instance = ok(CaseInstanceV1::open(
        &case_contract,
        evidence_index.index_sha256.clone(),
        "case-ledger-example".to_owned(),
        digest('0'),
        vec!["case-open-evidence".to_owned()],
    ));
    Fixture {
        contract,
        delegation,
        instance,
        envelope,
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

fn active_case(fixture: &Fixture) -> CaseInstanceV1 {
    ok(fixture
        .case_instance
        .transition_non_terminal(CaseLifecycleStatusV1::Active, 420, None))
}

fn task_request(fixture: &Fixture, instance: &CaseInstanceV1) -> CaseTaskRequestV1 {
    ok(CaseTaskRequestV1 {
        schema_version: 1,
        case_task_id: "case-task-name-save-1".to_owned(),
        case_id: fixture.case_contract.case_id.clone(),
        case_contract_sha256: fixture.case_contract.contract_sha256.clone(),
        case_instance_sha256: instance.instance_sha256.clone(),
        task_sequence: 1,
        role_instance_id: fixture.instance.role_instance_id.clone(),
        ownership_sha256: fixture
            .case_contract
            .ownership_binding
            .ownership_sha256
            .clone(),
        work_class_id: fixture.work_item.work_class_id.clone(),
        responsibility_id: fixture.case_contract.responsibility_id.clone(),
        authenticated_instruction_sha256: digest('3'),
        goal_spec_sha256: digest('4'),
        role_task_admission_sha256: digest('5'),
        role_bound_kernel_context_sha256: digest('6'),
        application_pack_sha256:
            "sha256:63af89c06cb5a7b6623e1619718a9a4f3d8346d1387acb52ea339b8ad710411e".to_owned(),
        integration_id: "windows-kernel-e2e".to_owned(),
        required_capability_ids: fixture.case_contract.allowed_capability_ids.clone(),
        addressed_requirement_ids: vec!["goal-complete".to_owned()],
        evidence_requirement_ids: fixture
            .case_contract
            .evidence_requirements
            .iter()
            .map(|item| item.evidence_requirement_id.clone())
            .collect(),
        requested_at_unix_seconds: 421,
        expires_at_unix_seconds: 500,
        evidence_ids: vec!["case-task-request-evidence".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&fixture.case_contract, instance))
}

fn attempt(request: &CaseTaskRequestV1, outcome: CaseTaskAttemptOutcomeV1) -> CaseTaskAttemptV1 {
    let verified = outcome == CaseTaskAttemptOutcomeV1::VerifiedGoalComplete;
    ok(CaseTaskAttemptV1 {
        schema_version: 1,
        attempt_id: "attempt-case-task-1".to_owned(),
        case_id: request.case_id.clone(),
        case_task_request_sha256: request.request_sha256.clone(),
        task_sequence: request.task_sequence,
        role_task_admission_sha256: request.role_task_admission_sha256.clone(),
        role_bound_kernel_context_sha256: request.role_bound_kernel_context_sha256.clone(),
        kernel_task_run_record_sha256: digest('7'),
        work_report_sha256: digest('8'),
        final_goal_verification_sha256: verified.then(|| digest('9')),
        verified_action_result_hashes: verified.then(|| digest('a')).into_iter().collect(),
        recovery_result_hashes: Vec::new(),
        execution_receipt_hashes: verified.then(|| digest('b')).into_iter().collect(),
        outcome,
        addressed_requirement_ids: request.addressed_requirement_ids.clone(),
        satisfied_requirement_ids: if verified {
            request.addressed_requirement_ids.clone()
        } else {
            Vec::new()
        },
        produced_evidence_ref_ids: if verified {
            vec![
                "evidence-final".to_owned(),
                "evidence-kernel".to_owned(),
                "evidence-report".to_owned(),
            ]
        } else {
            Vec::new()
        },
        started_at_unix_seconds: 422,
        completed_at_unix_seconds: 430,
        evidence_ids: vec!["attempt-evidence".to_owned()],
        attempt_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(request))
}

fn completed_evidence(index: &EvidenceIndexV1) -> EvidenceIndexV1 {
    let mut result = index.clone();
    for (id, class, artifact, hash, producer) in [
        (
            "evidence-kernel",
            "kernel-task-run-record",
            "kernel-task-run-record",
            digest('7'),
            CaseEvidenceProducerKindV1::KernelTaskRun,
        ),
        (
            "evidence-final",
            "final-goal-verification",
            "final-goal-verification",
            digest('9'),
            CaseEvidenceProducerKindV1::FinalGoalVerification,
        ),
        (
            "evidence-report",
            "work-report",
            "work-report",
            digest('8'),
            CaseEvidenceProducerKindV1::KernelTaskRun,
        ),
    ] {
        result = ok(result.append(ok(CaseEvidenceRefV1 {
            evidence_id: id.to_owned(),
            evidence_class_id: class.to_owned(),
            artifact_type_id: artifact.to_owned(),
            artifact_sha256: hash,
            producer_kind: producer,
            producer_id: "kernel-task-run-1".to_owned(),
            trust_floor: CaseEvidenceTrustFloorV1::Protected,
            trust_labels: vec!["protected-kernel-evidence".to_owned()],
            observed_at_unix_seconds: 429,
            created_at_unix_seconds: 430,
            retention_class_id: "test-evidence".to_owned(),
            redacted: true,
            source_case_id: Some(index.case_id.clone()),
            supersedes_evidence_id: None,
            evidence_ref_sha256: ZERO_HASH.to_owned(),
        }
        .seal())));
    }
    result
}

#[test]
fn work_item_normalization_and_hash_are_deterministic() {
    let envelope = source_envelope();
    let first = normalized_work_item(&envelope);
    let second = normalized_work_item(&envelope);
    assert_eq!(first, second);
    assert_eq!(first.0.deduplication_key_sha256, first.1.key_sha256);
}

#[test]
fn duplicate_open_terminal_and_conflict_are_distinct() {
    let fixture = fixture();
    let entry = WorkItemDeduplicationEntryV1 {
        key: fixture.dedup_key.clone(),
        work_item_id: fixture.work_item.work_item_id.clone(),
        work_item_sha256: fixture.work_item.work_item_sha256.clone(),
        case_id: Some(fixture.case_contract.case_id.clone()),
        terminal: false,
    };
    assert_eq!(
        ok(classify_duplicate(
            &fixture.dedup_key,
            std::slice::from_ref(&entry)
        )),
        WorkItemDeduplicationResultV1::DuplicateOpen
    );
    let mut terminal = entry.clone();
    terminal.terminal = true;
    assert_eq!(
        ok(classify_duplicate(&fixture.dedup_key, &[terminal])),
        WorkItemDeduplicationResultV1::DuplicateTerminal
    );
    let mut changed = fixture.dedup_key.clone();
    changed.semantic_payload_sha256 = digest('9');
    changed.key_sha256 = ZERO_HASH.to_owned();
    changed.key_sha256 = ok(canonical_sha256(&json!({
        "organization_id": changed.organization_id,
        "source_system_id": changed.source_system_id,
        "source_event_id": changed.source_event_id,
        "work_class_id": changed.work_class_id,
        "subject_refs_sha256": changed.subject_refs_sha256,
        "deduplication_scope_id": changed.deduplication_scope_id,
        "semantic_payload_sha256": changed.semantic_payload_sha256
    })));
    assert_eq!(
        ok(classify_duplicate(&changed, &[entry])),
        WorkItemDeduplicationResultV1::Conflict
    );
}

#[test]
fn failed_task_remains_non_terminal_and_requirements_unresolved() {
    let fixture = fixture();
    let active = active_case(&fixture);
    let request = task_request(&fixture, &active);
    let failed = attempt(&request, CaseTaskAttemptOutcomeV1::Failed);
    let next = ok(active.attach_attempt(
        &fixture.case_contract,
        &failed,
        fixture.evidence_index.index_sha256.clone(),
    ));
    assert_ne!(next.current_status, CaseLifecycleStatusV1::Terminal);
    assert_eq!(next.terminal_outcome, None);
    assert_eq!(next.unresolved_requirement_ids, vec!["goal-complete"]);
}

#[test]
fn verified_closure_requires_kernel_final_and_all_evidence() {
    let fixture = fixture();
    let active = active_case(&fixture);
    let request = task_request(&fixture, &active);
    let attempt = attempt(&request, CaseTaskAttemptOutcomeV1::VerifiedGoalComplete);
    let evidence = completed_evidence(&fixture.evidence_index);
    let attempted = ok(active.attach_attempt(
        &fixture.case_contract,
        &attempt,
        evidence.index_sha256.clone(),
    ));
    let awaiting = ok(attempted.transition_non_terminal(
        CaseLifecycleStatusV1::AwaitingVerification,
        431,
        None,
    ));
    let evaluation = ok(evaluate_case_closure(CaseClosureContextV1 {
        contract: &fixture.case_contract,
        instance: &awaiting,
        evidence_index: &evidence,
        attempts: std::slice::from_ref(&attempt),
        unresolved_blocks: &[],
        unsafe_evidence_ids: &[],
        refusal: None,
        escalation: None,
        ownership_role_valid: true,
        audit_integrity_valid: true,
        ledger_integrity_valid: true,
        evaluated_at_unix_seconds: 432,
    }));
    assert_eq!(
        evaluation.outcome,
        CaseClosureEvaluationOutcomeV1::VerifiedComplete
    );
    let terminal = ok(awaiting.close(
        &evaluation,
        CaseTerminalOutcomeV1::VerifiedComplete,
        433,
        None,
    ));
    assert_eq!(terminal.current_status, CaseLifecycleStatusV1::Terminal);
    assert!(terminal
        .transition_non_terminal(CaseLifecycleStatusV1::Active, 434, None)
        .is_err());
}

#[test]
fn refusal_and_exact_recovery_escalation_are_the_only_alternate_terminals() {
    let fixture = fixture();
    let active = active_case(&fixture);
    let refusal = ok(CaseRefusalV1 {
        refusal_id: "refusal-case-v1".to_owned(),
        case_id: fixture.case_contract.case_id.clone(),
        role_instance_id: fixture.case_contract.role_instance_id.clone(),
        authority_class: "organization-owner".to_owned(),
        refusal_reason_codes: vec!["unsupported-work-class".to_owned()],
        refusal_category: CaseRefusalCategoryV1::UnsupportedWork,
        authorized_actor_id: "organization-owner".to_owned(),
        authorization_artifact_sha256: digest('a'),
        raised_at_unix_seconds: 431,
        evidence_ids: vec!["refusal-authorization".to_owned()],
        refusal_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let refusal_evaluation = ok(evaluate_case_closure(CaseClosureContextV1 {
        contract: &fixture.case_contract,
        instance: &active,
        evidence_index: &fixture.evidence_index,
        attempts: &[],
        unresolved_blocks: &[],
        unsafe_evidence_ids: &[],
        refusal: Some(&refusal),
        escalation: None,
        ownership_role_valid: true,
        audit_integrity_valid: true,
        ledger_integrity_valid: true,
        evaluated_at_unix_seconds: 432,
    }));
    assert_eq!(
        ok(active.close(
            &refusal_evaluation,
            CaseTerminalOutcomeV1::ExplicitRefusal,
            433,
            None,
        ))
        .terminal_outcome,
        Some(CaseTerminalOutcomeV1::ExplicitRefusal)
    );

    let pending =
        ok(active.transition_non_terminal(CaseLifecycleStatusV1::EscalationPending, 431, None));
    let request = ok(EscalationRequestV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        escalation_id: "recovery-escalation-case-v1".to_owned(),
        recovery_decision_sha256: digest('b'),
        goal_id: "goal-kernel-e2e".to_owned(),
        severity: EscalationSeverityV1::Elevated,
        reason_codes: vec![RecoveryReasonCodeV1::AuthorityExceeded],
        originating_stage: RecoveryStageV1::Policy,
        required_authority_class: RequiredAuthorityClassV1::PolicyOwner,
        blocked_capability_ids: vec!["uia.invoke".to_owned()],
        policy_set_sha256: fixture.contract.policy_set_sha256.clone(),
        authority_sha256: digest('c'),
        latest_observation_hash: digest('d'),
        verified_action_result_sha256: None,
        protected_violation_count: 0,
        unexpected_change_count: 0,
        safe_state_summary_codes: vec![SafeStateSummaryCodeV1::AutomaticMutationBlocked],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::ReviewAuthorityScope],
        evidence_ids: vec!["recovery-escalation-evidence".to_owned()],
        raised_at_unix_ms: 431_000,
        escalation_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let binding = ok(CaseEscalationBindingV1 {
        binding_id: "case-escalation-binding-v1".to_owned(),
        case_id: fixture.case_contract.case_id.clone(),
        role_instance_id: fixture.case_contract.role_instance_id.clone(),
        case_contract_sha256: fixture.case_contract.contract_sha256.clone(),
        case_instance_sha256: pending.instance_sha256.clone(),
        originating_task_attempt_sha256: None,
        escalation_request_sha256: request.escalation_sha256.clone(),
        escalation_severity: request.severity,
        reason_codes: vec!["authority-exceeded".to_owned()],
        routing_class_id: "policy-owner".to_owned(),
        required_evidence_ids: vec!["recovery-escalation-evidence".to_owned()],
        bound_at_unix_seconds: 432,
        evidence_ids: vec!["recovery-escalation-evidence".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&request));
    let escalation_evaluation = ok(evaluate_case_closure(CaseClosureContextV1 {
        contract: &fixture.case_contract,
        instance: &pending,
        evidence_index: &fixture.evidence_index,
        attempts: &[],
        unresolved_blocks: &[],
        unsafe_evidence_ids: &[],
        refusal: None,
        escalation: Some(&binding),
        ownership_role_valid: true,
        audit_integrity_valid: true,
        ledger_integrity_valid: true,
        evaluated_at_unix_seconds: 433,
    }));
    assert_eq!(
        ok(pending.close(
            &escalation_evaluation,
            CaseTerminalOutcomeV1::Escalated,
            434,
            Some(binding.binding_sha256),
        ))
        .terminal_outcome,
        Some(CaseTerminalOutcomeV1::Escalated)
    );
}

#[test]
fn work_report_only_cannot_close_case() {
    let fixture = fixture();
    let active = active_case(&fixture);
    let only_report = ok(fixture.evidence_index.append(ok(CaseEvidenceRefV1 {
        evidence_id: "evidence-report-only".to_owned(),
        evidence_class_id: "work-report".to_owned(),
        artifact_type_id: "work-report".to_owned(),
        artifact_sha256: digest('8'),
        producer_kind: CaseEvidenceProducerKindV1::KernelTaskRun,
        producer_id: "kernel-task-run-1".to_owned(),
        trust_floor: CaseEvidenceTrustFloorV1::Protected,
        trust_labels: vec!["protected-kernel-evidence".to_owned()],
        observed_at_unix_seconds: 429,
        created_at_unix_seconds: 430,
        retention_class_id: "test-evidence".to_owned(),
        redacted: true,
        source_case_id: Some(fixture.case_contract.case_id.clone()),
        supersedes_evidence_id: None,
        evidence_ref_sha256: ZERO_HASH.to_owned(),
    }
    .seal())));
    let mut rebound = active.clone();
    rebound.evidence_index_sha256 = only_report.index_sha256.clone();
    let value = serde_json::to_value(&rebound);
    assert!(value.is_ok());
    // A stale instance/evidence substitution fails closed before prose can close the Case.
    assert!(evaluate_case_closure(CaseClosureContextV1 {
        contract: &fixture.case_contract,
        instance: &active,
        evidence_index: &only_report,
        attempts: &[],
        unresolved_blocks: &[],
        unsafe_evidence_ids: &[],
        refusal: None,
        escalation: None,
        ownership_role_valid: true,
        audit_integrity_valid: true,
        ledger_integrity_valid: true,
        evaluated_at_unix_seconds: 432,
    })
    .is_err());
}

#[test]
fn case_task_scope_and_ownership_expiry_cannot_expand() {
    let fixture = fixture();
    let active = active_case(&fixture);
    let request = task_request(&fixture, &active);

    let mut wrong_integration = request.clone();
    wrong_integration.integration_id = "windows-unapproved".to_owned();
    wrong_integration.request_sha256 = ZERO_HASH.to_owned();
    assert!(wrong_integration
        .seal_against(&fixture.case_contract, &active)
        .is_err());

    let mut wrong_pack = request.clone();
    wrong_pack.application_pack_sha256 = digest('7');
    wrong_pack.request_sha256 = ZERO_HASH.to_owned();
    assert!(wrong_pack
        .seal_against(&fixture.case_contract, &active)
        .is_err());

    let mut beyond_ownership = request;
    beyond_ownership.requested_at_unix_seconds = fixture
        .case_contract
        .ownership_binding
        .expires_at_unix_seconds
        .saturating_sub(60);
    beyond_ownership.expires_at_unix_seconds = fixture
        .case_contract
        .ownership_binding
        .expires_at_unix_seconds
        .saturating_add(1);
    beyond_ownership.request_sha256 = ZERO_HASH.to_owned();
    assert!(beyond_ownership
        .seal_against(&fixture.case_contract, &active)
        .is_err());
}

#[test]
fn aggregate_cycle_and_unknown_fields_fail_closed() {
    let fixture = fixture();
    let mut contract = fixture.case_contract.clone();
    let first = ok(CaseSuccessRequirementV1 {
        requirement_id: "aggregate-a".to_owned(),
        outcome_class_id: "aggregate".to_owned(),
        verification_kind: CaseVerificationKindV1::AggregateAll,
        required: true,
        minimum_satisfied_count: 1,
        referenced_requirement_ids: vec!["aggregate-b".to_owned()],
        target_state_ref: None,
        comparison_op: None,
        expected_value_hash: None,
        trusted_evidence_class_ids: Vec::new(),
        authoritative_source_class_ids: Vec::new(),
        evidence_ids: Vec::new(),
        requirement_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let mut second = first.clone();
    second.requirement_id = "aggregate-b".to_owned();
    second.referenced_requirement_ids = vec!["aggregate-a".to_owned()];
    second.requirement_sha256 = ZERO_HASH.to_owned();
    second = ok(second.seal());
    contract.outcome_requirements = vec![first, second];
    contract.contract_sha256 = ZERO_HASH.to_owned();
    assert!(contract.validate().is_err());

    let mut json = ok(serde_json::to_value(&fixture.work_item));
    if let Value::Object(object) = &mut json {
        object.insert("unknown".to_owned(), json!(true));
    }
    assert!(parse_json_strict::<WorkItemV1>(&ok(serde_json::to_vec(&json))).is_err());
}

#[test]
fn published_schemas_compile_and_validate_canonical_artifacts() {
    let fixture = fixture();
    for (schema, artifact) in [
        (
            WORK_ITEM_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.work_item)),
        ),
        (
            CASE_CONTRACT_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.case_contract)),
        ),
        (
            CASE_INSTANCE_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.case_instance)),
        ),
    ] {
        let schema: Value = ok(serde_json::from_str(schema));
        let compiled = ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
        assert!(compiled.is_valid(&artifact));
    }
}

#[test]
fn fixture_bindings_remain_exact_and_hash_only() {
    let fixture = fixture();
    assert_eq!(
        fixture.envelope.envelope_sha256,
        fixture.work_item.source_envelope_sha256
    );
    assert_eq!(
        fixture.admission.outcome,
        WorkItemAdmissionOutcomeV1::Admitted
    );
    assert_eq!(
        fixture.contract.contract_sha256,
        fixture.case_contract.role_contract_sha256
    );
    assert_eq!(
        fixture.delegation.delegation_sha256,
        fixture.case_contract.delegation_sha256
    );
    let serialized = ok(serde_json::to_string(&fixture.case_contract)).to_ascii_lowercase();
    for forbidden in ["raw_payload", "locator", "credential", "private_key"] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn ai_safety_reference_cases_are_execution_free_and_role_compatible() {
    const TRAINING: &str = include_str!(
        "../../../examples/workforce/ai-safety-operations-employee/cases/training-compliance-follow-up/case-fixture.json"
    );
    const CORRECTIVE: &str = include_str!(
        "../../../examples/workforce/ai-safety-operations-employee/cases/corrective-action-tracking/case-fixture.json"
    );
    let safety_role = ok(compile_role_source(
        include_bytes!("../../../examples/workforce/ai-safety-operations-employee/role.yaml"),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    for source in [TRAINING, CORRECTIVE] {
        let fixture: Value = ok(serde_json::from_str(source));
        assert_eq!(fixture["schema_version"], 1);
        assert_eq!(fixture["execution_mode"], "none");
        assert_eq!(
            fixture["accepted_role_contract_id"],
            safety_role.role_contract_id
        );
        let work_class = match fixture["work_item"]["work_class_id"].as_str() {
            Some(value) => value,
            None => panic!("safety fixture work class absent"),
        };
        assert!(safety_role
            .accepted_work_classes
            .iter()
            .any(|accepted| accepted.work_class_id == work_class));
        assert_eq!(
            fixture["case_contract"]["terminal_outcomes"],
            json!(["verified_complete", "explicit_refusal", "escalated"])
        );
        let serialized = ok(canonical_json_bytes(&fixture));
        assert_eq!(serialized, ok(canonical_json_bytes(&fixture)));
        let lower = String::from_utf8_lossy(&serialized).to_ascii_lowercase();
        for forbidden in ["raw_payload", "locator", "credential", "private_key"] {
            assert!(!lower.contains(forbidden));
        }
    }
}
