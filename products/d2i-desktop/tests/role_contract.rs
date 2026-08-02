#![cfg(windows)]

use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_desktop::{
    initialize_role_instance_ledger, initialize_windows_deployment_audit,
    verify_role_instance_ledger, verify_windows_deployment_audit, CognitiveKernelTaskRuntimeV1,
    RoleInstanceLedgerEventKindV1, RoleInstanceLedgerRecordV1, RoleInstanceLedgerV1,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditStatus,
};
use d2i_policy_admission::{TrustedPolicySnapshotV1, TrustedPolicyStateV1};
use d2i_role_contract::{
    admit_role_task, compile_role_source, create_role_contract_approval, create_role_delegation,
    RoleCompileFormatV1, RoleContractApprovalV1, RoleContractV1, RoleDelegationGrantV1,
    RoleInstanceStatusV1, RoleInstanceV1, RoleOperationalTimeContextV1,
    RoleTaskAdmissionArtifactsV1, RoleTaskAdmissionOutcomeV1, RoleTaskAdmissionRequestV1,
    ROLE_CONTRACT_SCHEMA_VERSION,
};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SOURCE: &str = include_str!("../../../examples/workforce/kernel-e2e-operator/role.yaml");
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

struct RoleFixture {
    root: PathBuf,
    audit_root: PathBuf,
    ledger: RoleInstanceLedgerV1,
    audit: d2i_desktop::WindowsDeploymentAuditLedger,
    contract: RoleContractV1,
    approval: RoleContractApprovalV1,
    delegation: RoleDelegationGrantV1,
}

impl Drop for RoleFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.audit_root);
    }
}

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(character: char) -> String {
    format!("sha256:{}", character.to_string().repeat(64))
}

fn unique_root(label: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("d2i-role-{label}-{}-{now}", std::process::id()))
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
        },
        contract,
        approval,
        &delegation_key(),
    ))
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

fn request(
    contract: &RoleContractV1,
    delegation: &RoleDelegationGrantV1,
    instance: &RoleInstanceV1,
    policy: &TrustedPolicySnapshotV1,
    request_id: &str,
) -> RoleTaskAdmissionRequestV1 {
    let time = ok(RoleOperationalTimeContextV1 {
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
    .seal());
    ok(RoleTaskAdmissionRequestV1 {
        schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
        request_id: request_id.to_owned(),
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
        operational_time_context: time,
        requested_at_unix_seconds: 400,
        expires_at_unix_seconds: 500,
        evidence_ids: vec!["authenticated-task".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn admit(
    fixture: &RoleFixture,
    instance: &RoleInstanceV1,
    request: &RoleTaskAdmissionRequestV1,
) -> RoleTaskAdmissionArtifactsV1 {
    ok(admit_role_task(
        request,
        &fixture.contract,
        &fixture.approval,
        &fixture.delegation,
        instance,
        &policy(&fixture.contract),
        "approval-key-v1",
        &approval_key().verifying_key(),
        "delegation-key-v1",
        &delegation_key().verifying_key(),
        401,
    ))
}

fn audit_kind(event: RoleInstanceLedgerEventKindV1) -> WindowsDeploymentAuditEventKind {
    use RoleInstanceLedgerEventKindV1 as Role;
    match event {
        Role::RoleContractRegistered => WindowsDeploymentAuditEventKind::RoleContractRegistered,
        Role::RoleContractApproved => WindowsDeploymentAuditEventKind::RoleContractApproved,
        Role::RoleInstanceProvisioned => WindowsDeploymentAuditEventKind::RoleInstanceProvisioned,
        Role::RoleInstanceActivated => WindowsDeploymentAuditEventKind::RoleInstanceActivated,
        Role::RoleInstanceSuspended => WindowsDeploymentAuditEventKind::RoleInstanceSuspended,
        Role::RoleInstanceResumed => WindowsDeploymentAuditEventKind::RoleInstanceResumed,
        Role::RoleInstanceRevoked => WindowsDeploymentAuditEventKind::RoleInstanceRevoked,
        Role::RoleInstanceExpired => WindowsDeploymentAuditEventKind::RoleInstanceExpired,
        Role::RoleInstanceUpgraded => WindowsDeploymentAuditEventKind::RoleInstanceUpgraded,
        Role::RoleTaskAdmitted => WindowsDeploymentAuditEventKind::RoleTaskAdmitted,
        Role::RoleTaskDenied => WindowsDeploymentAuditEventKind::RoleTaskDenied,
        Role::RoleTaskEscalationRequired => {
            WindowsDeploymentAuditEventKind::RoleTaskEscalationRequired
        }
        Role::RoleBoundTaskStarted => WindowsDeploymentAuditEventKind::RoleBoundTaskStarted,
        Role::RoleBoundTaskTerminal => WindowsDeploymentAuditEventKind::RoleBoundTaskTerminal,
    }
}

#[allow(clippy::too_many_arguments)]
fn append(
    fixture: &mut RoleFixture,
    event: RoleInstanceLedgerEventKindV1,
    instance: Option<RoleInstanceV1>,
    task_request_sha256: Option<String>,
    task_admission_sha256: Option<String>,
    role_context_sha256: Option<String>,
    recorded_at_unix_ms: u64,
) -> Result<String, d2i_desktop::DesktopError> {
    let audit_record_hash = fixture.audit.append(WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id: format!("role-event-{recorded_at_unix_ms}"),
        kind: audit_kind(event),
        status: WindowsDeploymentAuditStatus::Succeeded,
        artifact_hashes: BTreeMap::from([(
            "contract".to_owned(),
            fixture.contract.contract_sha256.clone(),
        )]),
        detail_hash: digest('e'),
        recorded_at_unix_ms,
    })?;
    fixture.ledger.append(RoleInstanceLedgerRecordV1 {
        schema_version: 1,
        sequence: 1,
        ledger_id: "role-ledger-kernel-e2e".to_owned(),
        role_instance_id: "kernel-e2e-actor".to_owned(),
        event_kind: event,
        role_contract_id: fixture.contract.role_contract_id.clone(),
        role_version: fixture.contract.role_version.clone(),
        contract_sha256: fixture.contract.contract_sha256.clone(),
        instance_after: instance,
        task_request_sha256,
        task_admission_sha256,
        role_context_sha256,
        artifact_hashes: BTreeMap::new(),
        audit_record_hash,
        recorded_at_unix_ms,
        previous_record_hash: ZERO_HASH.to_owned(),
        record_hash: ZERO_HASH.to_owned(),
    })
}

fn initialized_fixture(label: &str) -> RoleFixture {
    let contract = ok(compile_role_source(
        SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract;
    let approval = approval(&contract);
    let delegation = delegation(&contract, &approval);
    let root = unique_root(label);
    let audit_root = unique_root(&format!("{label}-audit"));
    let ledger = ok(initialize_role_instance_ledger(
        &root,
        "role-ledger-kernel-e2e",
        "kernel-e2e-actor",
        64,
        100_000,
    ));
    let audit = ok(initialize_windows_deployment_audit(
        &audit_root,
        "role-audit-ledger",
        "role-audit-session",
        128,
        100_000,
    ));
    RoleFixture {
        root,
        audit_root,
        ledger,
        audit,
        contract,
        approval,
        delegation,
    }
}

fn activate(fixture: &mut RoleFixture) -> RoleInstanceV1 {
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleContractRegistered,
        None,
        None,
        None,
        None,
        200_000,
    ));
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleContractApproved,
        None,
        None,
        None,
        None,
        201_000,
    ));
    let provisioned = ok(RoleInstanceV1::provision(
        "kernel-e2e-actor".to_owned(),
        &fixture.contract,
        &fixture.approval,
        &fixture.delegation,
        "role-ledger-kernel-e2e".to_owned(),
        digest('a'),
        digest('b'),
        vec!["role-instance-provisioned".to_owned()],
    ));
    let provisioned =
        ok(provisioned
            .bind_ledger_head(fixture.ledger.verification().terminal_record_hash.clone()));
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceProvisioned,
        Some(provisioned),
        None,
        None,
        None,
        300_000,
    ));
    let active = ok(fixture
        .ledger
        .verification()
        .current_instance
        .as_ref()
        .unwrap_or_else(|| panic!("missing provisioned Role"))
        .transition(RoleInstanceStatusV1::Active, 400));
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceActivated,
        Some(active),
        None,
        None,
        None,
        400_000,
    ));
    fixture
        .ledger
        .verification()
        .current_instance
        .clone()
        .unwrap_or_else(|| panic!("missing active Role"))
}

fn append_admission(fixture: &mut RoleFixture, artifacts: &RoleTaskAdmissionArtifactsV1) -> String {
    let context = artifacts
        .role_task_context
        .as_ref()
        .unwrap_or_else(|| panic!("missing role context"));
    let current = fixture
        .ledger
        .verification()
        .current_instance
        .clone()
        .unwrap_or_else(|| panic!("missing active Role"));
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleTaskAdmitted,
        Some(current),
        Some(artifacts.decision.request_sha256.clone()),
        Some(artifacts.decision.admission_sha256.clone()),
        Some(context.context_sha256.clone()),
        401_000,
    ));
    let current = fixture
        .ledger
        .verification()
        .current_instance
        .clone()
        .unwrap_or_else(|| panic!("missing admitted Role"));
    ok(append(
        fixture,
        RoleInstanceLedgerEventKindV1::RoleBoundTaskStarted,
        Some(current),
        None,
        Some(artifacts.decision.admission_sha256.clone()),
        Some(context.context_sha256.clone()),
        402_000,
    ))
}

#[test]
fn protected_role_ledger_reopens_replays_lifecycle_and_rejects_tamper() {
    let mut fixture = initialized_fixture("lifecycle");
    let active = activate(&mut fixture);
    let suspended = ok(active.transition(RoleInstanceStatusV1::Suspended, 410));
    ok(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceSuspended,
        Some(suspended),
        None,
        None,
        None,
        410_000,
    ));
    let resumed = ok(fixture
        .ledger
        .verification()
        .current_instance
        .as_ref()
        .unwrap_or_else(|| panic!("missing suspended Role"))
        .transition(RoleInstanceStatusV1::Active, 420));
    ok(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceResumed,
        Some(resumed),
        None,
        None,
        None,
        420_000,
    ));

    let reopened = ok(RoleInstanceLedgerV1::open(&fixture.root));
    assert_eq!(reopened.verification().record_count, 6);
    assert_eq!(
        reopened
            .verification()
            .current_instance
            .as_ref()
            .map(|instance| instance.current_status),
        Some(RoleInstanceStatusV1::Active)
    );
    assert_eq!(
        ok(verify_windows_deployment_audit(&fixture.audit_root)).record_count,
        6
    );

    let state = fixture.root.join("role-instance-ledger-state.json");
    let mut bytes = ok(std::fs::read(&state));
    if let Some(byte) = bytes.iter_mut().find(|byte| **byte == b'c') {
        *byte = b'd';
    }
    ok(std::fs::write(&state, bytes));
    assert!(verify_role_instance_ledger(&fixture.root).is_err());
}

#[test]
fn role_admission_is_one_time_and_exactly_binds_kernel_entry() {
    let mut fixture = initialized_fixture("admission");
    let active = activate(&mut fixture);
    let policy = policy(&fixture.contract);
    let request = request(
        &fixture.contract,
        &fixture.delegation,
        &active,
        &policy,
        "role-task-request-1",
    );
    let artifacts = admit(&fixture, &active, &request);
    assert_eq!(
        artifacts.decision.outcome,
        RoleTaskAdmissionOutcomeV1::Admitted
    );
    append_admission(&mut fixture, &artifacts);

    let authority = artifacts
        .authority_projection
        .as_ref()
        .unwrap_or_else(|| panic!("missing authority"));
    let recovery = artifacts
        .recovery_profile_projection
        .as_ref()
        .unwrap_or_else(|| panic!("missing recovery"));
    let context = artifacts
        .role_task_context
        .as_ref()
        .unwrap_or_else(|| panic!("missing context"));
    let runtime = ok(CognitiveKernelTaskRuntimeV1::begin_role_bound(
        "role-bound-kernel-run".to_owned(),
        request.authenticated_instruction_sha256.clone(),
        &request.goal_spec_sha256,
        &request.requested_application_pack_sha256,
        &request.requested_integration_id,
        context,
        authority,
        recovery,
        fixture.ledger.verification(),
        402,
        1,
    ));
    assert_eq!(
        runtime.role_context_sha256(),
        Some(context.context_sha256.as_str())
    );
    assert_eq!(runtime.stages().len(), 1);

    let replay_instance = fixture.ledger.verification().current_instance.clone();
    assert!(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleTaskAdmitted,
        replay_instance,
        Some(artifacts.decision.request_sha256.clone()),
        Some(artifacts.decision.admission_sha256.clone()),
        Some(context.context_sha256.clone()),
        403_000,
    )
    .is_err());

    assert!(CognitiveKernelTaskRuntimeV1::begin_role_bound(
        "substituted-kernel-run".to_owned(),
        digest('f'),
        &request.goal_spec_sha256,
        &request.requested_application_pack_sha256,
        &request.requested_integration_id,
        context,
        authority,
        recovery,
        fixture.ledger.verification(),
        402,
        1,
    )
    .is_err());
}

#[test]
fn suspended_revoked_and_out_of_scope_roles_never_create_kernel_context() {
    let mut fixture = initialized_fixture("denied");
    let active = activate(&mut fixture);
    let policy = policy(&fixture.contract);

    let mut outside = request(
        &fixture.contract,
        &fixture.delegation,
        &active,
        &policy,
        "outside-request",
    );
    outside.work_class_id = "safety.audit.readiness".to_owned();
    outside.request_sha256 = ZERO_HASH.to_owned();
    outside = ok(outside.seal());
    let denied = admit(&fixture, &active, &outside);
    assert_ne!(
        denied.decision.outcome,
        RoleTaskAdmissionOutcomeV1::Admitted
    );
    assert!(denied.role_task_context.is_none());

    let suspended = ok(active.transition(RoleInstanceStatusV1::Suspended, 410));
    ok(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceSuspended,
        Some(suspended),
        None,
        None,
        None,
        410_000,
    ));
    let suspended_instance = fixture
        .ledger
        .verification()
        .current_instance
        .clone()
        .unwrap_or_else(|| panic!("missing suspended Role"));
    let suspended_request = request(
        &fixture.contract,
        &fixture.delegation,
        &suspended_instance,
        &policy,
        "suspended-request",
    );
    let suspended_result = admit(&fixture, &suspended_instance, &suspended_request);
    assert_eq!(
        suspended_result.decision.outcome,
        RoleTaskAdmissionOutcomeV1::InactiveRole
    );
    assert!(suspended_result.role_task_context.is_none());

    let revoked = ok(suspended_instance.transition(RoleInstanceStatusV1::Revoked, 420));
    ok(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleInstanceRevoked,
        Some(revoked),
        None,
        None,
        None,
        420_000,
    ));
    let revoked = fixture
        .ledger
        .verification()
        .current_instance
        .as_ref()
        .unwrap_or_else(|| panic!("missing revoked Role"));
    assert!(revoked
        .transition(RoleInstanceStatusV1::Active, 430)
        .is_err());
}

#[test]
fn contract_version_collision_and_duplicate_transition_fail_closed() {
    let mut fixture = initialized_fixture("collision");
    ok(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleContractRegistered,
        None,
        None,
        None,
        None,
        200_000,
    ));
    assert!(append(
        &mut fixture,
        RoleInstanceLedgerEventKindV1::RoleContractRegistered,
        None,
        None,
        None,
        None,
        201_000,
    )
    .is_err());

    let mut collision = RoleInstanceLedgerRecordV1 {
        schema_version: 1,
        sequence: 1,
        ledger_id: "role-ledger-kernel-e2e".to_owned(),
        role_instance_id: "kernel-e2e-actor".to_owned(),
        event_kind: RoleInstanceLedgerEventKindV1::RoleContractApproved,
        role_contract_id: fixture.contract.role_contract_id.clone(),
        role_version: fixture.contract.role_version.clone(),
        contract_sha256: digest('9'),
        instance_after: None,
        task_request_sha256: None,
        task_admission_sha256: None,
        role_context_sha256: None,
        artifact_hashes: BTreeMap::new(),
        audit_record_hash: digest('8'),
        recorded_at_unix_ms: 202_000,
        previous_record_hash: ZERO_HASH.to_owned(),
        record_hash: ZERO_HASH.to_owned(),
    };
    assert!(fixture.ledger.append(collision.clone()).is_err());
    collision.contract_sha256 = fixture.contract.contract_sha256.clone();
    ok(fixture.ledger.append(collision));
}

#[test]
fn ledger_artifacts_are_hash_only_and_cleanup_leaves_no_role_state() {
    let root = unique_root("cleanup");
    let ledger = ok(initialize_role_instance_ledger(
        &root,
        "cleanup-ledger",
        "cleanup-role",
        4,
        100_000,
    ));
    assert_eq!(ledger.verification().record_count, 0);
    ok(std::fs::remove_dir_all(&root));
    assert!(!Path::new(&root).exists());
}
