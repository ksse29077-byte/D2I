use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{
    compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
};
use d2i_work_case::{WorkApplicationPackRefV1, WorkItemDeduplicationResultV1, WorkPriorityClassV1};
use d2i_work_intake::*;
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};

const ROLE_SOURCE: &str =
    include_str!("../../../examples/workforce/ai-safety-operations-employee/role.yaml");
const OFFICE_ROLE_SOURCE: &str =
    include_str!("../../../examples/workforce/general-office-operations-employee/role.yaml");
const NOW: u64 = 1_785_000_100;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

struct Fixture {
    contract: RoleContractV1,
    approval: RoleContractApprovalV1,
    delegation: RoleDelegationGrantV1,
    instance: RoleInstanceV1,
    approval_key: SigningKey,
    delegation_key: SigningKey,
    source_approval_key: SigningKey,
    registration: ApprovedRadarSourceRegistrationV1,
    source_approval: WorkSourceApprovalV1,
    mapping: WorkIntakeMappingProfileV1,
    checkpoint: RadarCheckpointV1,
    signal: WorkSignalV1,
}

fn fixture() -> Fixture {
    let contract = ok(compile_role_source(
        ROLE_SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    let approval_key = SigningKey::from_bytes(&[17_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[23_u8; 32]);
    let source_approval_key = SigningKey::from_bytes(&[29_u8; 32]);
    let approval = ok(create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: 1,
            approval_id: "approval-ai-safety-intake-v1".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "safety-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "safety-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            approval_signature: String::new(),
            evidence_ids: vec!["safety-role-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval_key,
    ));
    let delegation = ok(create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: 1,
            delegation_id: "delegation-ai-safety-intake-v1".to_owned(),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: "ai-safety-role-instance".to_owned(),
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
            delegated_application_pack_ids: vec!["safety-operations-shadow".to_owned()],
            delegated_integration_ids: vec!["safety-records-read".to_owned()],
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
            assigned_by_actor_id: "safety-role-assigner".to_owned(),
            signer_key_id: "safety-delegation-key-v1".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec!["safety-role-delegation".to_owned()],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval,
        &delegation_key,
    ));
    let provisioned = ok(RoleInstanceV1::provision(
        "ai-safety-role-instance".to_owned(),
        &contract,
        &approval,
        &delegation,
        "role-ledger-ai-safety".to_owned(),
        digest('a'),
        digest('b'),
        vec!["ai-safety-role-provisioned".to_owned()],
    ));
    let instance = ok(provisioned.transition(RoleInstanceStatusV1::Active, 1_785_000_000));
    let registration = ok(ApprovedRadarSourceRegistrationV1 {
        schema_version: 1,
        registration_id: "radar-registration-safety-records".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        role_instance_id: instance.role_instance_id.clone(),
        role_instance_sha256: instance.instance_sha256.clone(),
        approval_sha256: approval.approval_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        observation_source_id: "safety-records".to_owned(),
        source_kind: d2i_role_contract::ObservationSourceKindV1::EnterpriseApi,
        integration_id: "safety-records-read".to_owned(),
        application_pack_ref: Some(WorkApplicationPackRefV1 {
            application_pack_id: "safety-operations-shadow".to_owned(),
            application_pack_sha256: digest('1'),
        }),
        allowed_event_class_ids: vec!["safety-record-updated".to_owned()],
        minimum_trust_label: "authenticated-enterprise-record".to_owned(),
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
    .seal_against(&contract, &delegation, &instance));
    let source_approval = ok(create_work_source_approval(
        WorkSourceApprovalV1 {
            schema_version: 1,
            source_approval_id: "source-approval-safety-records".to_owned(),
            organization_id: registration.organization_id.clone(),
            role_contract_id: registration.role_contract_id.clone(),
            role_contract_sha256: registration.role_contract_sha256.clone(),
            role_instance_id: registration.role_instance_id.clone(),
            role_instance_sha256: registration.role_instance_sha256.clone(),
            role_approval_sha256: registration.approval_sha256.clone(),
            delegation_sha256: registration.delegation_sha256.clone(),
            registration_id: registration.registration_id.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            approved_by_actor_id: "safety-source-governance".to_owned(),
            signer_key_id: "safety-source-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            evidence_ids: vec!["approved-safety-source".to_owned()],
            approval_signature: String::new(),
            source_approval_sha256: ZERO_HASH.to_owned(),
        },
        &registration,
        &contract,
        &delegation,
        &instance,
        &source_approval_key,
    ));
    let mapping = ok(WorkIntakeMappingProfileV1 {
        schema_version: 1,
        mapping_id: "mapping-safety-training-followup".to_owned(),
        mapping_version: "1.0.0".to_owned(),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        observation_source_id: registration.observation_source_id.clone(),
        event_class_id: "safety-record-updated".to_owned(),
        work_class_id: "safety.training.compliance_followup".to_owned(),
        work_class_contract_version: "1.0.0".to_owned(),
        requested_outcome_class_ids: vec!["training-followup-prepared".to_owned()],
        requested_evidence_class_ids: vec!["approved-summary".to_owned()],
        priority_class: WorkPriorityClassV1::Normal,
        risk_class: CognitiveRiskClass::ReadOnly,
        application_pack_refs: vec![registration
            .application_pack_ref
            .clone()
            .unwrap_or_else(|| panic!("fixture pack absent"))],
        integration_ids: vec!["safety-records-read".to_owned()],
        capability_requirement_ids: vec!["enterprise_api.read".to_owned()],
        semantic_target_ids: vec!["safety-record".to_owned()],
        deduplication_scope_id: "safety-training-record".to_owned(),
        required_trust_labels: vec!["authenticated-enterprise-record".to_owned()],
        allowed_structured_input_kind_ids: vec!["training-record-ref".to_owned()],
        minimum_subject_refs: 1,
        minimum_structured_input_refs: 1,
        due_time_derivation: DueTimeDerivationV1::FixedOffsetFromReceived,
        due_time_offset_seconds: Some(86_400),
        evidence_ids: vec!["approved-intake-mapping".to_owned()],
        mapping_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&registration, &contract, &delegation));
    let checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["initial-source-checkpoint".to_owned()],
    ));
    let signal = ok(WorkSignalV1 {
        schema_version: 1,
        signal_id: "signal-safety-training-1".to_owned(),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        organization_id: registration.organization_id.clone(),
        role_instance_id: registration.role_instance_id.clone(),
        delegation_sha256: registration.delegation_sha256.clone(),
        source_system_id: registration.observation_source_id.clone(),
        event_id: "safety-record-event-1".to_owned(),
        source_sequence: 1,
        source_cursor: None,
        event_class_id: "safety-record-updated".to_owned(),
        observed_at_unix_seconds: NOW - 10,
        received_at_unix_seconds: NOW - 9,
        source_record_sha256: digest('c'),
        payload_reference_sha256: digest('d'),
        attachment_reference_hashes: Vec::new(),
        subject_refs: vec!["training-record:opaque-1".to_owned()],
        structured_input_kind_ids: vec!["training-record-ref".to_owned()],
        structured_input_refs: vec!["training-status:opaque-incomplete".to_owned()],
        trust_labels: vec!["authenticated-enterprise-record".to_owned()],
        provenance: WorkSignalProvenanceV1 {
            authenticated_actor_id: "fixture-safety-system".to_owned(),
            authentication_class_id: "fixture-signed-record".to_owned(),
            authentication_evidence_sha256: digest('e'),
        },
        semantic_payload_sha256: digest('f'),
        evidence_ids: vec!["fixture-safety-record-evidence".to_owned()],
        signal_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    Fixture {
        contract,
        approval,
        delegation,
        instance,
        approval_key,
        delegation_key,
        source_approval_key,
        registration,
        source_approval,
        mapping,
        checkpoint,
        signal,
    }
}

fn derived_role_source(domain: &str) -> String {
    match domain {
        "office" => OFFICE_ROLE_SOURCE.to_owned(),
        "hr" => OFFICE_ROLE_SOURCE
            .replace(
                "general-office-operations-employee",
                "hr-operations-employee",
            )
            .replace(
                "General Office Operations Employee",
                "HR Operations Employee",
            )
            .replace("example-office-organization", "example-hr-organization")
            .replace("general-office", "human-resources")
            .replace("office.record.update", "hr.employee.record.review")
            .replace("office.record.delete", "hr.employee.record.delete")
            .replace("internal-record-updated", "hr-record-updated")
            .replace("internal-records-read", "hr-records-read")
            .replace("internal-records", "hr-records")
            .replace("authenticated-internal-record", "authenticated-hr-record")
            .replace("employee_name_input", "employee_record")
            .replace("save_button", "employee_record_state"),
        "it" => OFFICE_ROLE_SOURCE
            .replace(
                "general-office-operations-employee",
                "it-service-operations-employee",
            )
            .replace(
                "General Office Operations Employee",
                "IT Service Operations Employee",
            )
            .replace("example-office-organization", "example-it-organization")
            .replace("general-office", "it-service")
            .replace("office.record.update", "it.service.ticket.review")
            .replace("office.record.delete", "it.service.ticket.delete")
            .replace("internal-record-updated", "service-ticket-updated")
            .replace("internal-records-read", "service-desk-read")
            .replace("internal-records", "service-desk")
            .replace(
                "authenticated-internal-record",
                "authenticated-service-ticket",
            )
            .replace("kernel-e2e-name-save", "service-desk-shadow")
            .replace("employee_name_input", "service_ticket")
            .replace("save_button", "service_ticket_state"),
        "schedule" => {
            OFFICE_ROLE_SOURCE.replace("source_kind: enterprise_api", "source_kind: schedule")
        }
        other => panic!("unsupported derived fixture domain: {other}"),
    }
}

fn cross_domain_evaluation(domain: &str) -> WorkIntakeEvaluationV1 {
    let source = derived_role_source(domain);
    let contract = ok(compile_role_source(
        source.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    let approval_key = SigningKey::from_bytes(&[51_u8; 32]);
    let delegation_key = SigningKey::from_bytes(&[53_u8; 32]);
    let source_approval_key = SigningKey::from_bytes(&[55_u8; 32]);
    let approval = ok(create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: 1,
            approval_id: format!("approval-{domain}-cross-domain"),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: format!("{domain}-role-governance"),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: "cross-domain-role-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            approval_signature: String::new(),
            evidence_ids: vec![format!("{domain}-role-approved")],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval_key,
    ));
    let delegation = ok(create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: 1,
            delegation_id: format!("delegation-{domain}-cross-domain"),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: format!("{domain}-cross-domain-instance"),
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
            delegated_application_pack_ids: contract
                .application_bindings
                .iter()
                .map(|binding| binding.application_pack_id.clone())
                .collect(),
            delegated_integration_ids: contract
                .application_bindings
                .iter()
                .flat_map(|binding| binding.integration_ids.iter().cloned())
                .collect(),
            delegated_capability_ids: contract.capability_policy.allowed_capability_ids.clone(),
            autonomous_capability_ids: contract.capability_policy.autonomous_capability_ids.clone(),
            confirmation_capability_ids: contract
                .capability_policy
                .confirmation_capability_ids
                .clone(),
            prohibited_capability_ids: contract.capability_policy.prohibited_capability_ids.clone(),
            maximum_autonomous_risk: contract.risk_policy.maximum_autonomous_risk,
            maximum_confirmable_risk: contract.risk_policy.maximum_confirmable_risk,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            assigned_by_actor_id: format!("{domain}-role-assigner"),
            signer_key_id: "cross-domain-delegation-key-v1".to_owned(),
            delegation_signature: String::new(),
            evidence_ids: vec![format!("{domain}-delegation")],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval,
        &delegation_key,
    ));
    let provisioned = ok(RoleInstanceV1::provision(
        format!("{domain}-cross-domain-instance"),
        &contract,
        &approval,
        &delegation,
        format!("{domain}-role-ledger"),
        digest('1'),
        digest('2'),
        vec![format!("{domain}-provisioned")],
    ));
    let instance = ok(provisioned.transition(RoleInstanceStatusV1::Active, 1_785_000_000));
    let observation = contract
        .observation_sources
        .first()
        .unwrap_or_else(|| panic!("{domain} observation source absent"));
    let application_pack_ref = observation.application_pack_id.as_ref().map(|pack_id| {
        let binding = contract
            .application_bindings
            .iter()
            .find(|binding| binding.application_pack_id == *pack_id)
            .unwrap_or_else(|| panic!("{domain} pack binding absent"));
        WorkApplicationPackRefV1 {
            application_pack_id: binding.application_pack_id.clone(),
            application_pack_sha256: binding.application_pack_sha256.clone(),
        }
    });
    let registration = ok(ApprovedRadarSourceRegistrationV1 {
        schema_version: 1,
        registration_id: format!("registration-{domain}-cross-domain"),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        role_instance_id: instance.role_instance_id.clone(),
        role_instance_sha256: instance.instance_sha256.clone(),
        approval_sha256: approval.approval_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        observation_source_id: observation.observation_source_id.clone(),
        source_kind: observation.source_kind,
        integration_id: observation.integration_id.clone(),
        application_pack_ref,
        allowed_event_class_ids: observation.event_class_ids.clone(),
        minimum_trust_label: observation.trust_floor.clone(),
        maximum_staleness_seconds: observation.maximum_staleness_seconds,
        cursor_policy: RadarCursorPolicyV1::SequenceOnly,
        maximum_sequence_advance: 1,
        resource_limits: RadarResourceLimitsV1 {
            maximum_events_per_cycle: 8,
            maximum_subject_refs_per_event: 4,
            maximum_structured_input_refs_per_event: 4,
            maximum_attachment_refs_per_event: 4,
            maximum_evidence_ids_per_event: 8,
            maximum_trust_labels_per_event: 4,
            maximum_event_id_bytes: 128,
            maximum_record_bytes: 65_536,
            maximum_output_bytes: 65_536,
            maximum_receipts_per_cycle: 8,
            maximum_ledger_records: 128,
            maximum_logical_operations: 128,
            maximum_ticks: 128,
            maximum_retries: 0,
            maximum_concurrent_requests: 1,
        },
        enabled: true,
        evidence_ids: vec![format!("{domain}-source-registration")],
        registration_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&contract, &delegation, &instance));
    let source_approval = ok(create_work_source_approval(
        WorkSourceApprovalV1 {
            schema_version: 1,
            source_approval_id: format!("source-approval-{domain}"),
            organization_id: registration.organization_id.clone(),
            role_contract_id: registration.role_contract_id.clone(),
            role_contract_sha256: registration.role_contract_sha256.clone(),
            role_instance_id: registration.role_instance_id.clone(),
            role_instance_sha256: registration.role_instance_sha256.clone(),
            role_approval_sha256: registration.approval_sha256.clone(),
            delegation_sha256: registration.delegation_sha256.clone(),
            registration_id: registration.registration_id.clone(),
            registration_sha256: registration.registration_sha256.clone(),
            approved_by_actor_id: format!("{domain}-source-governance"),
            signer_key_id: "cross-domain-source-key-v1".to_owned(),
            issued_at_unix_seconds: 1_780_000_000,
            expires_at_unix_seconds: 1_800_000_000,
            evidence_ids: vec![format!("{domain}-source-approved")],
            approval_signature: String::new(),
            source_approval_sha256: ZERO_HASH.to_owned(),
        },
        &registration,
        &contract,
        &delegation,
        &instance,
        &source_approval_key,
    ));
    let work = contract
        .accepted_work_classes
        .first()
        .unwrap_or_else(|| panic!("{domain} work class absent"));
    let responsibility = contract
        .responsibilities
        .iter()
        .find(|candidate| candidate.responsibility_id == work.responsibility_id)
        .unwrap_or_else(|| panic!("{domain} responsibility absent"));
    let semantic_target = contract
        .application_bindings
        .first()
        .and_then(|binding| binding.allowed_semantic_target_ids.first())
        .cloned()
        .unwrap_or_else(|| panic!("{domain} semantic target absent"));
    let mapping = ok(WorkIntakeMappingProfileV1 {
        schema_version: 1,
        mapping_id: format!("mapping-{domain}-cross-domain"),
        mapping_version: "1.0.0".to_owned(),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        observation_source_id: registration.observation_source_id.clone(),
        event_class_id: registration.allowed_event_class_ids[0].clone(),
        work_class_id: work.work_class_id.clone(),
        work_class_contract_version: work.contract_version.clone(),
        requested_outcome_class_ids: responsibility.outcome_class_ids.clone(),
        requested_evidence_class_ids: responsibility.evidence_class_ids.clone(),
        priority_class: WorkPriorityClassV1::Normal,
        risk_class: CognitiveRiskClass::ReadOnly,
        application_pack_refs: registration
            .application_pack_ref
            .clone()
            .into_iter()
            .collect(),
        integration_ids: work.required_integration_ids.clone(),
        capability_requirement_ids: work.required_capability_ids.clone(),
        semantic_target_ids: vec![semantic_target],
        deduplication_scope_id: format!("{domain}-cross-domain-scope"),
        required_trust_labels: vec![registration.minimum_trust_label.clone()],
        allowed_structured_input_kind_ids: vec![format!("{domain}-record-ref")],
        minimum_subject_refs: 1,
        minimum_structured_input_refs: 1,
        due_time_derivation: DueTimeDerivationV1::None,
        due_time_offset_seconds: None,
        evidence_ids: vec![format!("{domain}-mapping")],
        mapping_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&registration, &contract, &delegation));
    let checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec![format!("{domain}-checkpoint")],
    ));
    let signal = ok(WorkSignalV1 {
        schema_version: 1,
        signal_id: format!("signal-{domain}-cross-domain"),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        organization_id: registration.organization_id.clone(),
        role_instance_id: registration.role_instance_id.clone(),
        delegation_sha256: registration.delegation_sha256.clone(),
        source_system_id: registration.observation_source_id.clone(),
        event_id: format!("event-{domain}-cross-domain"),
        source_sequence: 1,
        source_cursor: None,
        event_class_id: registration.allowed_event_class_ids[0].clone(),
        observed_at_unix_seconds: NOW - 10,
        received_at_unix_seconds: NOW - 9,
        source_record_sha256: digest('3'),
        payload_reference_sha256: digest('4'),
        attachment_reference_hashes: Vec::new(),
        subject_refs: vec![format!("{domain}-subject:opaque-1")],
        structured_input_kind_ids: vec![format!("{domain}-record-ref")],
        structured_input_refs: vec![format!("{domain}-input:opaque-1")],
        trust_labels: vec![registration.minimum_trust_label.clone()],
        provenance: WorkSignalProvenanceV1 {
            authenticated_actor_id: format!("{domain}-fixture-source"),
            authentication_class_id: "fixture-signed-record".to_owned(),
            authentication_evidence_sha256: digest('5'),
        },
        semantic_payload_sha256: digest('6'),
        evidence_ids: vec![format!("{domain}-signal-evidence")],
        signal_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(evaluate_work_signal(
        WorkIntakeEvaluationContextV1 {
            role_contract: &contract,
            approval: &approval,
            delegation: &delegation,
            role_instance: &instance,
            expected_approval_signer_key_id: "cross-domain-role-approval-key-v1",
            approval_verifying_key: &approval_key.verifying_key(),
            expected_delegation_signer_key_id: "cross-domain-delegation-key-v1",
            delegation_verifying_key: &delegation_key.verifying_key(),
            registration: &registration,
            source_approval: &source_approval,
            expected_source_approval_signer_key_id: "cross-domain-source-key-v1",
            source_approval_verifying_key: &source_approval_key.verifying_key(),
            mappings: std::slice::from_ref(&mapping),
            checkpoint: &checkpoint,
            deduplication_entries: &[],
            operational_time_context: time(&contract),
            trusted_policy_snapshot_sha256: digest('7'),
            policy_set_sha256: contract.policy_set_sha256.clone(),
            caller_due_at_unix_seconds: None,
            now_unix_seconds: NOW,
        },
        &signal,
    ))
}

fn time(contract: &RoleContractV1) -> RoleOperationalTimeContextV1 {
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

fn evaluate(
    fixture: &Fixture,
    mappings: &[WorkIntakeMappingProfileV1],
    signal: &WorkSignalV1,
) -> WorkIntakeEvaluationV1 {
    ok(evaluate_work_signal(
        WorkIntakeEvaluationContextV1 {
            role_contract: &fixture.contract,
            approval: &fixture.approval,
            delegation: &fixture.delegation,
            role_instance: &fixture.instance,
            expected_approval_signer_key_id: "safety-approval-key-v1",
            approval_verifying_key: &fixture.approval_key.verifying_key(),
            expected_delegation_signer_key_id: "safety-delegation-key-v1",
            delegation_verifying_key: &fixture.delegation_key.verifying_key(),
            registration: &fixture.registration,
            source_approval: &fixture.source_approval,
            expected_source_approval_signer_key_id: "safety-source-approval-key-v1",
            source_approval_verifying_key: &fixture.source_approval_key.verifying_key(),
            mappings,
            checkpoint: &fixture.checkpoint,
            deduplication_entries: &[],
            operational_time_context: time(&fixture.contract),
            trusted_policy_snapshot_sha256: digest('2'),
            policy_set_sha256: fixture.contract.policy_set_sha256.clone(),
            caller_due_at_unix_seconds: None,
            now_unix_seconds: NOW,
        },
        signal,
    ))
}

#[test]
fn approved_signal_reaches_existing_work_item_admission_deterministically() {
    let fixture = fixture();
    let first = evaluate(
        &fixture,
        std::slice::from_ref(&fixture.mapping),
        &fixture.signal,
    );
    let second = evaluate(
        &fixture,
        std::slice::from_ref(&fixture.mapping),
        &fixture.signal,
    );
    assert!(first.requires_case_creation());
    assert_eq!(first, second);
    assert_eq!(
        first.duplicate_result,
        Some(WorkItemDeduplicationResultV1::New)
    );
    assert_eq!(
        first
            .work_item
            .as_ref()
            .map(|work| work.work_class_id.as_str()),
        Some("safety.training.compliance_followup")
    );
    assert_eq!(
        ok(canonical_sha256(&first.work_item)),
        ok(canonical_sha256(&second.work_item))
    );
}

#[test]
fn opaque_cross_domain_mappings_are_deterministic_without_core_taxonomy() {
    for (domain, expected_work_class) in [
        ("office", "office.record.update"),
        ("hr", "hr.employee.record.review"),
        ("it", "it.service.ticket.review"),
        ("safety", "safety.training.compliance_followup"),
    ] {
        let first = if domain == "safety" {
            let fixture = fixture();
            evaluate(
                &fixture,
                std::slice::from_ref(&fixture.mapping),
                &fixture.signal,
            )
        } else {
            cross_domain_evaluation(domain)
        };
        let second = if domain == "safety" {
            let fixture = fixture();
            evaluate(
                &fixture,
                std::slice::from_ref(&fixture.mapping),
                &fixture.signal,
            )
        } else {
            cross_domain_evaluation(domain)
        };
        assert!(first.requires_case_creation());
        assert_eq!(first, second);
        assert_eq!(
            first
                .work_item
                .as_ref()
                .map(|work| work.work_class_id.as_str()),
            Some(expected_work_class)
        );
    }
}

#[test]
fn schedule_source_uses_the_same_bounded_one_shot_mapping_contract() {
    let first = cross_domain_evaluation("schedule");
    let second = cross_domain_evaluation("schedule");
    assert!(first.requires_case_creation());
    assert_eq!(first, second);
    assert_eq!(
        first
            .source_envelope
            .as_ref()
            .map(|envelope| envelope.source_kind),
        Some(d2i_work_case::WorkItemSourceKindV1::ApprovedScheduleEvent)
    );
}

#[test]
fn fixture_adapter_is_one_shot_and_checkpoint_rejects_replay() {
    let fixture = fixture();
    let request = ok(RadarScanRequestV1::create(
        "cycle-safety-1".to_owned(),
        1,
        &fixture.registration,
        &fixture.source_approval,
        &fixture.checkpoint,
        NOW - 1,
        NOW + 10,
    ));
    let mut adapter = ok(FixtureRadarSourceV1::new(
        vec![fixture.signal.clone()],
        1024,
        NOW,
    ));
    let batch = ok(adapter.scan_once(
        &fixture.registration,
        RadarSourceApprovalVerificationV1 {
            source_approval: &fixture.source_approval,
            expected_signer_key_id: "safety-source-approval-key-v1",
            verifying_key: &fixture.source_approval_key.verifying_key(),
            now_unix_seconds: NOW,
        },
        &fixture.checkpoint,
        &request,
    ));
    assert_eq!(batch.signals.len(), 1);
    assert!(adapter
        .scan_once(
            &fixture.registration,
            RadarSourceApprovalVerificationV1 {
                source_approval: &fixture.source_approval,
                expected_signer_key_id: "safety-source-approval-key-v1",
                verifying_key: &fixture.source_approval_key.verifying_key(),
                now_unix_seconds: NOW,
            },
            &fixture.checkpoint,
            &request,
        )
        .is_err());
    let advanced = ok(fixture.checkpoint.advance(
        &fixture.registration,
        &fixture.signal,
        1,
        digest('7'),
        vec!["checkpoint-advanced".to_owned()],
    ));
    assert!(advanced
        .validate_progress(&fixture.registration, &fixture.signal)
        .is_err());
}

#[test]
fn stale_ambiguous_missing_and_sensitive_signals_fail_closed() {
    let fixture = fixture();
    let mut stale = fixture.signal.clone();
    stale.observed_at_unix_seconds = NOW - 301;
    stale.received_at_unix_seconds = NOW - 300;
    stale.signal_sha256 = ZERO_HASH.to_owned();
    stale = ok(stale.seal());
    assert_eq!(
        evaluate(&fixture, std::slice::from_ref(&fixture.mapping), &stale).disposition,
        Some(WorkIntakeDispositionV1::StaleSource)
    );

    let ambiguous = vec![fixture.mapping.clone(), fixture.mapping.clone()];
    assert_eq!(
        evaluate(&fixture, &ambiguous, &fixture.signal).disposition,
        Some(WorkIntakeDispositionV1::IntegrityConflict)
    );

    let mut missing = fixture.signal.clone();
    missing.structured_input_kind_ids.clear();
    missing.structured_input_refs.clear();
    missing.signal_sha256 = ZERO_HASH.to_owned();
    missing = ok(missing.seal());
    assert_eq!(
        evaluate(&fixture, std::slice::from_ref(&fixture.mapping), &missing).disposition,
        Some(WorkIntakeDispositionV1::ClarificationRequired)
    );

    let mut secret = fixture.signal.clone();
    secret.structured_input_refs = vec!["credential:opaque-1".to_owned()];
    secret.signal_sha256 = ZERO_HASH.to_owned();
    assert!(secret.seal().is_err());

    let mut future = fixture.signal.clone();
    future.observed_at_unix_seconds = NOW + 1;
    future.received_at_unix_seconds = NOW + 1;
    future.signal_sha256 = ZERO_HASH.to_owned();
    future = ok(future.seal());
    assert_eq!(
        evaluate(&fixture, std::slice::from_ref(&fixture.mapping), &future).disposition,
        Some(WorkIntakeDispositionV1::StaleSource)
    );

    let mut wrong_source = fixture.signal.clone();
    wrong_source.source_system_id = "substituted-source".to_owned();
    wrong_source.signal_sha256 = ZERO_HASH.to_owned();
    wrong_source = ok(wrong_source.seal());
    assert!(evaluate_work_signal(
        WorkIntakeEvaluationContextV1 {
            role_contract: &fixture.contract,
            approval: &fixture.approval,
            delegation: &fixture.delegation,
            role_instance: &fixture.instance,
            expected_approval_signer_key_id: "safety-approval-key-v1",
            approval_verifying_key: &fixture.approval_key.verifying_key(),
            expected_delegation_signer_key_id: "safety-delegation-key-v1",
            delegation_verifying_key: &fixture.delegation_key.verifying_key(),
            registration: &fixture.registration,
            source_approval: &fixture.source_approval,
            expected_source_approval_signer_key_id: "safety-source-approval-key-v1",
            source_approval_verifying_key: &fixture.source_approval_key.verifying_key(),
            mappings: std::slice::from_ref(&fixture.mapping),
            checkpoint: &fixture.checkpoint,
            deduplication_entries: &[],
            operational_time_context: time(&fixture.contract),
            trusted_policy_snapshot_sha256: digest('2'),
            policy_set_sha256: fixture.contract.policy_set_sha256.clone(),
            caller_due_at_unix_seconds: None,
            now_unix_seconds: NOW,
        },
        &wrong_source,
    )
    .is_err());

    let mut expanded = fixture.mapping.clone();
    expanded.capability_requirement_ids = vec!["enterprise_api.write".to_owned()];
    expanded.mapping_sha256 = ZERO_HASH.to_owned();
    assert!(expanded
        .seal_against(
            &fixture.registration,
            &fixture.contract,
            &fixture.delegation,
        )
        .is_err());

    assert!(FixtureRadarSourceV1::new(
        vec![fixture.signal.clone(); MAX_EVENTS_PER_CYCLE + 1],
        1024,
        NOW,
    )
    .is_err());
}

#[test]
fn source_approval_rejects_wrong_signer_expiry_tamper_and_binding_substitution() {
    let fixture = fixture();
    assert!(verify_work_source_approval(
        &fixture.source_approval,
        &fixture.registration,
        "wrong-source-key",
        &fixture.source_approval_key.verifying_key(),
        NOW,
    )
    .is_err());
    assert!(verify_work_source_approval(
        &fixture.source_approval,
        &fixture.registration,
        "safety-source-approval-key-v1",
        &fixture.source_approval_key.verifying_key(),
        1_800_000_000,
    )
    .is_err());

    let mut tampered = fixture.source_approval.clone();
    tampered.approval_signature.replace_range(0..2, "ff");
    tampered.source_approval_sha256 = ok(canonical_sha256(&serde_json::json!({
        "tampered": true
    })));
    assert!(verify_work_source_approval(
        &tampered,
        &fixture.registration,
        "safety-source-approval-key-v1",
        &fixture.source_approval_key.verifying_key(),
        NOW,
    )
    .is_err());

    let mut substituted_registration = fixture.registration.clone();
    substituted_registration.organization_id = "other-organization".to_owned();
    assert!(fixture
        .source_approval
        .validate_against(&substituted_registration)
        .is_err());
}

#[test]
fn strict_json_rejects_duplicate_unknown_and_wildcard_fields() {
    let fixture = fixture();
    let bytes = ok(serde_json::to_vec(&fixture.signal));
    let parsed: WorkSignalV1 = ok(parse_json_strict(&bytes));
    assert_eq!(parsed, fixture.signal);
    let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
    assert!(parse_json_strict::<WorkSignalV1>(duplicate).is_err());
    let mut unknown = ok(serde_json::to_value(&fixture.signal));
    unknown["unexpected"] = serde_json::json!(true);
    assert!(parse_json_strict::<WorkSignalV1>(&ok(serde_json::to_vec(&unknown))).is_err());
    let mut wildcard = fixture.signal.clone();
    wildcard.event_id = "*".to_owned();
    wildcard.signal_sha256 = ZERO_HASH.to_owned();
    assert!(wildcard.seal().is_err());
}

#[test]
fn every_published_schema_accepts_only_its_strict_artifact() {
    let fixture = fixture();
    let next = ok(fixture.checkpoint.advance(
        &fixture.registration,
        &fixture.signal,
        1,
        ZERO_HASH.to_owned(),
        vec!["schema-checkpoint".to_owned()],
    ));
    let receipt = ok(WorkIntakeReceiptV1 {
        schema_version: 1,
        receipt_id: "receipt-schema-1".to_owned(),
        cycle_id: "cycle-schema-1".to_owned(),
        cycle_sequence: 1,
        signal_id: fixture.signal.signal_id.clone(),
        signal_sha256: fixture.signal.signal_sha256.clone(),
        source_approval_sha256: fixture.source_approval.source_approval_sha256.clone(),
        source_envelope_sha256: None,
        work_item_sha256: None,
        admission_sha256: None,
        case_id: None,
        case_contract_sha256: None,
        case_instance_sha256: None,
        duplicate_result: None,
        disposition: WorkIntakeDispositionV1::Quarantined,
        reason_codes: vec!["schema-fixture".to_owned()],
        checkpoint_before_sha256: fixture.checkpoint.checkpoint_sha256.clone(),
        checkpoint_after_sha256: next.checkpoint_sha256.clone(),
        case_ledger_chain_head: ZERO_HASH.to_owned(),
        role_ledger_chain_head: ZERO_HASH.to_owned(),
        intake_ledger_chain_head: ZERO_HASH.to_owned(),
        evidence_ids: vec!["schema-receipt".to_owned()],
        decided_at_unix_seconds: NOW,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let report = ok(RadarCycleReportV1 {
        schema_version: 1,
        cycle_id: "cycle-schema-1".to_owned(),
        cycle_sequence: 1,
        role_instance_id: fixture.instance.role_instance_id.clone(),
        role_instance_sha256: fixture.instance.instance_sha256.clone(),
        registration_id: fixture.registration.registration_id.clone(),
        registration_sha256: fixture.registration.registration_sha256.clone(),
        source_approval_sha256: fixture.source_approval.source_approval_sha256.clone(),
        checkpoint_before_sha256: fixture.checkpoint.checkpoint_sha256.clone(),
        checkpoint_after_sha256: next.checkpoint_sha256.clone(),
        observed_signals: 1,
        accepted_signals: 0,
        cases_created: 0,
        duplicate_open: 0,
        duplicate_terminal: 0,
        denied: 0,
        clarification_required: 0,
        escalation_required: 0,
        quarantined: 1,
        logical_operations: 8,
        ticks_consumed: 1,
        retries: 0,
        receipt_hashes: vec![receipt.receipt_sha256.clone()],
        cycle_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let artifacts = [
        (
            RADAR_SOURCE_REGISTRATION_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.registration)),
        ),
        (
            WORK_SOURCE_APPROVAL_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.source_approval)),
        ),
        (
            WORK_SIGNAL_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.signal)),
        ),
        (
            WORK_INTAKE_MAPPING_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.mapping)),
        ),
        (RADAR_CHECKPOINT_V1_SCHEMA, ok(serde_json::to_value(&next))),
        (
            WORK_INTAKE_RECEIPT_V1_SCHEMA,
            ok(serde_json::to_value(&receipt)),
        ),
        (
            RADAR_CYCLE_REPORT_V1_SCHEMA,
            ok(serde_json::to_value(&report)),
        ),
    ];
    for (schema, artifact) in artifacts {
        let schema = ok(serde_json::from_str(schema));
        let validator = ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
        assert!(validator.is_valid(&artifact));
        let mut unknown = artifact;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(!validator.is_valid(&unknown));
    }
}
