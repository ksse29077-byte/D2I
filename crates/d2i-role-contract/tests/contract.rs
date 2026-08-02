use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_policy_admission::{TrustedPolicySnapshotV1, TrustedPolicyStateV1};
use d2i_role_contract::{
    admit_role_task, compile_role_source, create_role_contract_approval, create_role_delegation,
    parse_json_strict, verify_role_contract_approval, verify_role_delegation, RoleCompileFormatV1,
    RoleContractApprovalV1, RoleContractBundleV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1, RoleSourcePackV1,
    RoleTaskAdmissionOutcomeV1, RoleTaskAdmissionRequestV1, ROLE_CONTRACT_SCHEMA_VERSION,
    ROLE_CONTRACT_V1_SCHEMA, ROLE_INSTANCE_V1_SCHEMA,
};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde_json::{json, Value};

const SOURCE: &str = include_str!("../../../examples/workforce/kernel-e2e-operator/role.yaml");
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

type SourceMutation = Box<dyn Fn(&mut RoleSourcePackV1)>;
type DelegationMutation = Box<dyn Fn(&mut RoleDelegationGrantV1)>;
type RequestMutation = Box<dyn Fn(&mut RoleTaskAdmissionRequestV1)>;

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn source() -> RoleSourcePackV1 {
    ok(serde_yaml::from_str(SOURCE))
}

fn bundle() -> RoleContractBundleV1 {
    ok(compile_role_source(
        SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
}

fn approval_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn delegation_key() -> SigningKey {
    SigningKey::from_bytes(&[11_u8; 32])
}

fn approval(contract: &RoleContractV1) -> RoleContractApprovalV1 {
    ok(create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            approval_id: "approval-kernel-role-v1".to_owned(),
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
        &approval_key(),
    ))
}

fn delegation(
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
) -> RoleDelegationGrantV1 {
    ok(create_role_delegation(
        delegation_draft(contract, approval),
        contract,
        approval,
        &delegation_key(),
    ))
}

fn delegation_draft(
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
) -> RoleDelegationGrantV1 {
    RoleDelegationGrantV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        delegation_id: "delegation-kernel-role-v1".to_owned(),
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
    }
}

fn provisioned(
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    delegation: &RoleDelegationGrantV1,
) -> RoleInstanceV1 {
    ok(RoleInstanceV1::provision(
        "kernel-e2e-actor".to_owned(),
        contract,
        approval,
        delegation,
        "role-ledger-kernel-e2e".to_owned(),
        digest('a'),
        digest('b'),
        vec!["role-instance-provisioned".to_owned()],
    ))
}

fn active(
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    delegation: &RoleDelegationGrantV1,
) -> RoleInstanceV1 {
    ok(provisioned(contract, approval, delegation).transition(RoleInstanceStatusV1::Active, 300))
}

fn policy(contract: &RoleContractV1) -> TrustedPolicySnapshotV1 {
    ok(TrustedPolicySnapshotV1 {
        schema_version: 1,
        policy_set_id: contract.policy_set_id.clone(),
        policy_set_version: contract.policy_set_version.clone(),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        organization_id: contract.organization_scope.organization_id.clone(),
        policy_state: TrustedPolicyStateV1::Effective,
        allowed_risk_classes: vec![
            CognitiveRiskClass::ReadOnly,
            CognitiveRiskClass::Reversible,
            CognitiveRiskClass::BusinessStateChange,
        ],
        denied_capability_ids: Vec::new(),
        mandatory_confirmation_capability_ids: Vec::new(),
        mandatory_escalation_capability_ids: Vec::new(),
        forbidden_semantic_targets: Vec::new(),
        effective_from_unix_seconds: 100,
        expires_at_unix_seconds: 10_000,
        evidence_ids: vec!["trusted-policy".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
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
        observed_at_unix_seconds: 400,
        evidence_ids: vec!["trusted-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn request(
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    policy: &TrustedPolicySnapshotV1,
) -> RoleTaskAdmissionRequestV1 {
    ok(RoleTaskAdmissionRequestV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        request_id: "role-task-request-1".to_owned(),
        role_instance_sha256: instance.instance_sha256.clone(),
        contract_sha256: contract.contract_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        organization_id: contract.organization_scope.organization_id.clone(),
        authenticated_actor_id: instance.role_instance_id.clone(),
        authenticated_role_id: contract.role_contract_id.clone(),
        authenticated_instruction_sha256: digest('c'),
        goal_spec_sha256: digest('d'),
        work_class_id: "workforce.kernel_e2e.name_save".to_owned(),
        requested_application_pack_id: "kernel-e2e-name-save".to_owned(),
        requested_application_pack_sha256: contract.application_bindings[0]
            .application_pack_sha256
            .clone(),
        requested_integration_id: "windows-kernel-e2e".to_owned(),
        required_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
        semantic_target_ids: vec!["employee_name_input".to_owned(), "save_button".to_owned()],
        task_risk: CognitiveRiskClass::BusinessStateChange,
        trusted_policy_snapshot_sha256: policy.snapshot_sha256.clone(),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        operational_time_context: time_context(contract),
        requested_at_unix_seconds: 400,
        expires_at_unix_seconds: 500,
        evidence_ids: vec!["authenticated-task".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn admit(
    request: &RoleTaskAdmissionRequestV1,
    contract: &RoleContractV1,
    approval: &RoleContractApprovalV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    policy: &TrustedPolicySnapshotV1,
) -> d2i_role_contract::RoleTaskAdmissionArtifactsV1 {
    ok(admit_role_task(
        request,
        contract,
        approval,
        delegation,
        instance,
        policy,
        "approval-key-v1",
        &approval_key().verifying_key(),
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        401,
    ))
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

#[test]
fn yaml_json_ordering_and_repeated_compile_are_deterministic() {
    let source = source();
    let yaml = ok(serde_yaml::to_string(&source));
    let json = ok(serde_json::to_vec(&source));
    let from_yaml = ok(compile_role_source(
        yaml.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ));
    let from_json = ok(compile_role_source(&json, RoleCompileFormatV1::Json));
    assert_eq!(
        from_yaml.contract.contract_sha256,
        from_json.contract.contract_sha256
    );
    assert_eq!(from_yaml.bundle_sha256, from_json.bundle_sha256);

    let mut reordered = source;
    reordered.responsibilities.reverse();
    reordered.accepted_work_classes.reverse();
    reordered.capability_policy.allowed_capability_ids.reverse();
    let reordered = ok(compile_role_source(
        &ok(serde_json::to_vec(&reordered)),
        RoleCompileFormatV1::Json,
    ));
    assert_eq!(
        from_json.contract.contract_sha256,
        reordered.contract.contract_sha256
    );
    assert_eq!(from_json.bundle_sha256, reordered.bundle_sha256);
}

#[test]
fn compiler_rejects_duplicate_dangling_wildcard_overlap_risk_and_calendar() {
    let cases: Vec<SourceMutation> = vec![
        Box::new(|source| {
            source
                .responsibilities
                .push(source.responsibilities[0].clone())
        }),
        Box::new(|source| {
            source.accepted_work_classes[0].sla_profile_id = "missing-sla".to_owned()
        }),
        Box::new(|source| {
            source
                .capability_policy
                .allowed_capability_ids
                .push("*".to_owned())
        }),
        Box::new(|source| {
            source
                .prohibited_work_class_ids
                .push(source.accepted_work_classes[0].work_class_id.clone())
        }),
        Box::new(|source| {
            source.risk_policy.maximum_autonomous_risk = CognitiveRiskClass::HighCriticality
        }),
        Box::new(|source| {
            source
                .working_calendar
                .weekly_windows
                .push(source.working_calendar.weekly_windows[0].clone())
        }),
    ];
    for mutation in cases {
        let mut value = source();
        mutation(&mut value);
        assert!(
            compile_role_source(&ok(serde_json::to_vec(&value)), RoleCompileFormatV1::Json,)
                .is_err()
        );
    }
}

#[test]
fn strict_json_and_published_schemas_reject_drift() {
    let bundle = bundle();
    let contract_schema: Value = ok(serde_json::from_str(ROLE_CONTRACT_V1_SCHEMA));
    let instance_schema: Value = ok(serde_json::from_str(ROLE_INSTANCE_V1_SCHEMA));
    let contract_validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&contract_schema));
    assert!(contract_validator.is_valid(&ok(serde_json::to_value(&bundle.contract))));

    let approval = approval(&bundle.contract);
    let delegation = delegation(&bundle.contract, &approval);
    let instance = provisioned(&bundle.contract, &approval, &delegation);
    let instance_validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&instance_schema));
    assert!(instance_validator.is_valid(&ok(serde_json::to_value(&instance))));

    let mut unknown = ok(serde_json::to_value(&bundle.contract));
    if let Some(object) = unknown.as_object_mut() {
        object.insert("unknown".to_owned(), json!(true));
    }
    assert!(!contract_validator.is_valid(&unknown));
    assert!(
        parse_json_strict::<RoleContractV1>(br#"{"schema_version":1,"schema_version":1}"#).is_err()
    );
}

#[test]
fn approval_and_delegation_signatures_are_exact_and_bounded() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    ok(verify_role_contract_approval(
        &approval,
        &contract,
        "approval-key-v1",
        &approval_key().verifying_key(),
        300,
    ));
    assert!(verify_role_contract_approval(
        &approval,
        &contract,
        "wrong-key",
        &approval_key().verifying_key(),
        300,
    )
    .is_err());
    assert!(verify_role_contract_approval(
        &approval,
        &contract,
        "approval-key-v1",
        &approval_key().verifying_key(),
        10_000,
    )
    .is_err());

    let delegation = delegation(&contract, &approval);
    ok(verify_role_delegation(
        &delegation,
        &contract,
        &approval,
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        300,
    ));
    assert!(verify_role_delegation(
        &delegation,
        &contract,
        &approval,
        "delegation-key-v1",
        &SigningKey::from_bytes(&[12_u8; 32]).verifying_key(),
        300,
    )
    .is_err());
}

#[test]
fn delegation_cannot_expand_scope_capability_work_risk_or_validity() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    let mutations: Vec<DelegationMutation> = vec![
        Box::new(|grant| grant.delegated_scope.organization_id = "other-organization".to_owned()),
        Box::new(|grant| {
            grant
                .delegated_capability_ids
                .push("process.launch".to_owned())
        }),
        Box::new(|grant| {
            grant
                .delegated_work_class_ids
                .push("unknown.work".to_owned())
        }),
        Box::new(|grant| grant.maximum_autonomous_risk = CognitiveRiskClass::HighCriticality),
        Box::new(|grant| grant.expires_at_unix_seconds = 10_001),
    ];
    for mutation in mutations {
        let mut draft = delegation_draft(&contract, &approval);
        mutation(&mut draft);
        assert!(create_role_delegation(draft, &contract, &approval, &delegation_key()).is_err());
    }
}

#[test]
fn lifecycle_is_closed_and_terminal_states_cannot_reactivate() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);
    let provisioned = provisioned(&contract, &approval, &delegation);
    let active = ok(provisioned.transition(RoleInstanceStatusV1::Active, 300));
    let suspended = ok(active.transition(RoleInstanceStatusV1::Suspended, 310));
    let resumed = ok(suspended.transition(RoleInstanceStatusV1::Active, 320));
    let revoked = ok(resumed.transition(RoleInstanceStatusV1::Revoked, 330));
    assert!(revoked
        .transition(RoleInstanceStatusV1::Active, 340)
        .is_err());
    assert!(provisioned
        .transition(RoleInstanceStatusV1::Suspended, 300)
        .is_err());
    let expired = ok(active.transition(RoleInstanceStatusV1::Expired, 9_000));
    assert!(expired
        .transition(RoleInstanceStatusV1::Active, 9_001)
        .is_err());
}

#[test]
fn admitted_task_projects_existing_authority_recovery_and_role_context() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);
    let instance = active(&contract, &approval, &delegation);
    let policy = policy(&contract);
    let request = request(&contract, &delegation, &instance, &policy);
    let artifacts = admit(
        &request,
        &contract,
        &approval,
        &delegation,
        &instance,
        &policy,
    );
    assert_eq!(
        artifacts.decision.outcome,
        RoleTaskAdmissionOutcomeV1::Admitted
    );
    let authority = match artifacts.authority_projection {
        Some(value) => value,
        None => panic!("authority projection missing"),
    };
    ok(authority.validate());
    assert_eq!(
        authority.allowed_application_pack_sha256,
        request.requested_application_pack_sha256
    );
    assert_eq!(
        authority.allowed_integration_ids,
        vec!["windows-kernel-e2e"]
    );
    assert_eq!(
        authority.allowed_capability_ids,
        request.required_capability_ids
    );
    let recovery = match artifacts.recovery_profile_projection {
        Some(value) => value,
        None => panic!("recovery projection missing"),
    };
    ok(recovery.validate());
    assert!(recovery
        .mandatory_escalation_failure_classes
        .contains(&d2i_cognitive_recovery::RecoveryFailureClassV1::UnsafeSideEffect));
    let context = match artifacts.role_task_context {
        Some(value) => value,
        None => panic!("role context missing"),
    };
    ok(context.validate(401));
    assert_eq!(
        context.authenticated_instruction_sha256,
        request.authenticated_instruction_sha256
    );
    assert_eq!(context.goal_spec_sha256, request.goal_spec_sha256);
}

#[test]
fn task_admission_denies_scope_lifecycle_time_policy_and_stale_requests_without_projection() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);
    let policy = policy(&contract);
    let active = active(&contract, &approval, &delegation);
    let cases: Vec<RequestMutation> = vec![
        Box::new(|request| request.organization_id = "other-organization".to_owned()),
        Box::new(|request| request.authenticated_actor_id = "wrong-actor".to_owned()),
        Box::new(|request| request.work_class_id = "unknown.work".to_owned()),
        Box::new(|request| request.requested_application_pack_id = "other-pack".to_owned()),
        Box::new(|request| request.requested_integration_id = "other-integration".to_owned()),
        Box::new(|request| request.required_capability_ids = vec!["process.launch".to_owned()]),
        Box::new(|request| request.task_risk = CognitiveRiskClass::HighCriticality),
        Box::new(|request| request.policy_set_sha256 = digest('9')),
    ];
    for mutation in cases {
        let mut value = request(&contract, &delegation, &active, &policy);
        mutation(&mut value);
        value.request_sha256 = ZERO_HASH.to_owned();
        let value = ok(value.seal());
        let artifacts = admit(&value, &contract, &approval, &delegation, &active, &policy);
        assert_ne!(
            artifacts.decision.outcome,
            RoleTaskAdmissionOutcomeV1::Admitted
        );
        assert!(artifacts.authority_projection.is_none());
        assert!(artifacts.recovery_profile_projection.is_none());
        assert!(artifacts.role_task_context.is_none());
    }

    let inactive = provisioned(&contract, &approval, &delegation);
    let inactive_request = request(&contract, &delegation, &inactive, &policy);
    let inactive_result = admit(
        &inactive_request,
        &contract,
        &approval,
        &delegation,
        &inactive,
        &policy,
    );
    assert_eq!(
        inactive_result.decision.outcome,
        RoleTaskAdmissionOutcomeV1::InactiveRole
    );

    let mut outside = request(&contract, &delegation, &active, &policy);
    outside.operational_time_context.local_minute_of_day = 600;
    outside.operational_time_context.weekday = 0;
    outside.operational_time_context.context_sha256 = ZERO_HASH.to_owned();
    outside.operational_time_context = ok(outside.operational_time_context.seal());
    let mut changed_contract = contract.clone();
    changed_contract.working_calendar.weekly_windows[0].start_minute_local = 700;
    changed_contract.working_calendar.calendar_sha256 = ZERO_HASH.to_owned();
    assert!(changed_contract.validate().is_err());
}

#[test]
fn approval_and_delegation_reject_contract_identity_and_signature_substitution() {
    let contract = bundle().contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);

    let mut tampered_contract = contract.clone();
    tampered_contract.purpose = "substituted purpose".to_owned();
    assert!(verify_role_contract_approval(
        &approval,
        &tampered_contract,
        "approval-key-v1",
        &approval_key().verifying_key(),
        300,
    )
    .is_err());

    let mut wrong_organization = approval.clone();
    wrong_organization.organization_id = "other-organization".to_owned();
    assert!(verify_role_contract_approval(
        &wrong_organization,
        &contract,
        "approval-key-v1",
        &approval_key().verifying_key(),
        300,
    )
    .is_err());

    let mut invalid_approval_signature = approval.clone();
    let replacement = if invalid_approval_signature
        .approval_signature
        .starts_with("00")
    {
        "01"
    } else {
        "00"
    };
    invalid_approval_signature
        .approval_signature
        .replace_range(0..2, replacement);
    assert!(verify_role_contract_approval(
        &invalid_approval_signature,
        &contract,
        "approval-key-v1",
        &approval_key().verifying_key(),
        300,
    )
    .is_err());

    let mut wrong_instance = delegation.clone();
    wrong_instance.role_instance_id = "other-role-instance".to_owned();
    assert!(verify_role_delegation(
        &wrong_instance,
        &contract,
        &approval,
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        300,
    )
    .is_err());

    let mut substituted_signature = delegation;
    substituted_signature.delegation_signature = approval.approval_signature.clone();
    assert!(verify_role_delegation(
        &substituted_signature,
        &contract,
        &approval,
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        300,
    )
    .is_err());
}

#[test]
fn outside_calendar_stale_request_and_replay_are_deterministic_without_projection() {
    let mut source = source();
    source
        .working_calendar
        .weekly_windows
        .retain(|window| window.weekday == 0);
    let contract = ok(compile_role_source(
        &ok(serde_json::to_vec(&source)),
        RoleCompileFormatV1::Json,
    ))
    .contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);
    let instance = active(&contract, &approval, &delegation);
    let policy = policy(&contract);

    let mut outside = request(&contract, &delegation, &instance, &policy);
    outside.operational_time_context.weekday = 1;
    outside.operational_time_context.context_sha256 = ZERO_HASH.to_owned();
    outside.operational_time_context = ok(outside.operational_time_context.seal());
    outside.request_sha256 = ZERO_HASH.to_owned();
    outside = ok(outside.seal());
    let first = admit(
        &outside,
        &contract,
        &approval,
        &delegation,
        &instance,
        &policy,
    );
    let second = admit(
        &outside,
        &contract,
        &approval,
        &delegation,
        &instance,
        &policy,
    );
    assert_eq!(first, second);
    assert_eq!(
        first.decision.outcome,
        RoleTaskAdmissionOutcomeV1::OutsideOperatingWindow
    );
    assert!(first.role_task_context.is_none());

    let fresh = request(&contract, &delegation, &instance, &policy);
    let stale = ok(admit_role_task(
        &fresh,
        &contract,
        &approval,
        &delegation,
        &instance,
        &policy,
        "approval-key-v1",
        &approval_key().verifying_key(),
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        fresh.expires_at_unix_seconds,
    ));
    assert_ne!(stale.decision.outcome, RoleTaskAdmissionOutcomeV1::Admitted);
    assert!(stale.authority_projection.is_none());
}

#[test]
fn role_upgrade_requires_new_immutable_contract_generation() {
    let first_contract = bundle().contract;
    let first_approval = approval(&first_contract);
    let first_delegation = delegation(&first_contract, &first_approval);
    let current = active(&first_contract, &first_approval, &first_delegation);

    let mut next_source = source();
    next_source.role_version = "1.1.0".to_owned();
    let next_contract = ok(compile_role_source(
        &ok(serde_json::to_vec(&next_source)),
        RoleCompileFormatV1::Json,
    ))
    .contract;
    let next_approval = approval(&next_contract);
    let next_delegation = delegation(&next_contract, &next_approval);
    let upgraded = ok(current.upgrade(
        &next_contract,
        &next_approval,
        &next_delegation,
        digest('e'),
        digest('f'),
        vec!["role-upgrade".to_owned()],
    ));
    assert_eq!(upgraded.instance_generation, 2);
    assert_eq!(upgraded.current_status, RoleInstanceStatusV1::Provisioned);
    assert_ne!(upgraded.contract_sha256, current.contract_sha256);
    assert!(current
        .upgrade(
            &first_contract,
            &first_approval,
            &first_delegation,
            digest('e'),
            digest('f'),
            vec!["invalid-same-version-upgrade".to_owned()],
        )
        .is_err());

    let revoked = ok(current.transition(RoleInstanceStatusV1::Revoked, 500));
    assert!(revoked
        .upgrade(
            &next_contract,
            &next_approval,
            &next_delegation,
            digest('e'),
            digest('f'),
            vec!["invalid-terminal-upgrade".to_owned()],
        )
        .is_err());
}
