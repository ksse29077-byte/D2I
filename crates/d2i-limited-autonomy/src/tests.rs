use super::*;
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[29_u8; 32])
}

fn readiness() -> AutonomyReadinessBindingV1 {
    ok(AutonomyReadinessBindingV1 {
        schema_version: 1,
        binding_id: "work900-readiness-binding".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        target_role_contract_id: "general-office-operations-employee".to_owned(),
        target_role_contract_version: "1.4.0".to_owned(),
        shadow_role_sha256: digest('1'),
        shadow_profile_sha256: digest('2'),
        shadow_cohort_sha256: digest('3'),
        shadow_readiness_policy_sha256: digest('4'),
        shadow_readiness_assessment_sha256: digest('5'),
        readiness_status: AutonomyReadinessStatusV1::EligibleForWork900Design,
        model_sha256: digest('6'),
        runtime_sha256: digest('7'),
        provider_descriptor_sha256: digest('8'),
        prompt_template_hashes: vec![digest('9')],
        application_pack_hashes: vec![digest('a')],
        policy_set_sha256: digest('b'),
        trusted_execution_compatibility_sha256: digest('c'),
        evidence_coverage_sha256: digest('d'),
        critical_error_count: 0,
        false_completion_count: 0,
        escalation_miss_count: 0,
        forbidden_capability_count: 0,
        authority_expansion_count: 0,
        assessed_at_unix_ms: 1_000,
        valid_until_unix_ms: 20_000,
        evidence_ids: vec!["work800-completion-evidence".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn thresholds() -> AutonomyHealthThresholdsV1 {
    AutonomyHealthThresholdsV1 {
        maximum_verification_failures: 2,
        maximum_recovery_failures: 1,
        maximum_provider_failures: 1,
        maximum_sla_breaches: 0,
        maximum_residual_failures: 0,
        maximum_false_completions: 0,
        maximum_authority_expansions: 0,
        maximum_wrong_target_attempts: 0,
        maximum_escalation_misses: 0,
        maximum_secret_leakage: 0,
    }
}

fn profile() -> LimitedAutonomyProfileV1 {
    ok(LimitedAutonomyProfileV1 {
        schema_version: 1,
        profile_id: "general-office-limited-autonomy".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.4.0".to_owned(),
        role_contract_sha256: digest('e'),
        delegation_constraint_hashes: vec![digest('f')],
        policy_set_sha256: digest('b'),
        model_sha256: digest('6'),
        runtime_sha256: digest('7'),
        provider_descriptor_sha256: digest('8'),
        prompt_template_hashes: vec![digest('9')],
        application_pack_hashes: vec![digest('a')],
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["internal-record-maintenance".to_owned()],
        allowed_source_ids: vec!["approved-internal-record-events".to_owned()],
        allowed_source_class_ids: vec!["internal-record-change".to_owned()],
        allowed_environment_ids: vec!["limited-autonomy".to_owned()],
        autonomous_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
        confirmation_capability_ids: Vec::new(),
        prohibited_capability_ids: vec!["network.external".to_owned()],
        allowed_semantic_target_ids: vec![
            "employee_name_input".to_owned(),
            "save_button".to_owned(),
        ],
        maximum_autonomous_risk: AutonomyRiskClassV1::BusinessStateChange,
        mandatory_human_exception_reason_codes: vec![
            "authority_exceeded".to_owned(),
            "policy_unknown".to_owned(),
        ],
        automatic_recovery_class_ids: vec!["fresh-reobserve-replan".to_owned()],
        maximum_cases_per_duty_cycle: 8,
        maximum_concurrent_cases: 1,
        maximum_actions_per_case: 4,
        maximum_model_invocations_per_case: 4,
        maximum_recovery_cycles: 2,
        maximum_reobservations_per_case: 8,
        maximum_total_autonomous_side_effects: 16,
        maximum_cycle_duration_ms: 900_000,
        maximum_case_duration_ms: 600_000,
        maximum_exception_pending_count: 3,
        maximum_exception_handoffs_per_cycle: 3,
        maximum_active_leases: 1,
        maximum_control_commands_per_cycle: 8,
        maximum_health_records_per_cycle: 32,
        maximum_store_objects: 1_024,
        maximum_store_bytes: 134_217_728,
        maximum_audit_records_per_cycle: 4_096,
        maximum_evidence_references: 256,
        maximum_report_bytes: 4_194_304,
        maximum_resume_checkpoints: 32,
        maximum_consecutive_failures: 1,
        maximum_verification_failures: 2,
        health_thresholds: thresholds(),
        rollout_maximum_cases: 8,
        rollout_maximum_side_effects: 16,
        valid_from_unix_ms: 1_000,
        valid_to_unix_ms: 20_000,
        evidence_ids: vec!["signed-role-1.4.0".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn approval() -> AutonomyDeploymentApprovalV1 {
    let readiness = readiness();
    let profile = profile();
    ok(AutonomyDeploymentApprovalV1 {
        schema_version: 1,
        approval_id: "work900-deployment-approval".to_owned(),
        organization_id: profile.organization_id.clone(),
        target_role_sha256: profile.role_contract_sha256.clone(),
        autonomy_profile_sha256: profile.profile_sha256.clone(),
        readiness_binding_sha256: readiness.binding_sha256,
        approved_environment_ids: profile.allowed_environment_ids.clone(),
        approved_work_class_ids: profile.allowed_work_class_ids.clone(),
        approved_capability_ids: profile.autonomous_capability_ids.clone(),
        approved_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        approved_maximum_risk: profile.maximum_autonomous_risk,
        rollout_maximum_cases: 8,
        issued_at_unix_ms: 2_000,
        expires_at_unix_ms: 19_000,
        signer_id: "organization-autonomy-approver".to_owned(),
        signing_key_id: "work900-test-key".to_owned(),
        nonce: "deployment-nonce-0001".to_owned(),
        evidence_ids: vec!["organizational-approval".to_owned()],
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

fn state(status: AutonomyRoleStatusV1, generation: u64) -> AutonomyRoleRuntimeStateV1 {
    let profile = profile();
    let approval = approval();
    ok(AutonomyRoleRuntimeStateV1 {
        schema_version: 1,
        state_id: format!("autonomy-state-{generation}"),
        role_instance_sha256: digest('1'),
        autonomy_profile_sha256: profile.profile_sha256,
        deployment_approval_sha256: approval.approval_sha256,
        readiness_binding_sha256: readiness().binding_sha256,
        status,
        enabled_at_unix_ms: (status == AutonomyRoleStatusV1::Enabled).then_some(2_000),
        paused_at_unix_ms: (status == AutonomyRoleStatusV1::Paused).then_some(2_500),
        state_generation: generation,
        processed_case_count: 0,
        active_case_count: 0,
        successful_autonomous_case_count: 0,
        exception_count: 0,
        failure_count: 0,
        current_health_snapshot_sha256: digest('2'),
        current_control_command_sha256: digest('3'),
        previous_state_sha256: digest('4'),
        evidence_ids: vec!["protected-state-ledger".to_owned()],
        state_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn control(operation: AutonomyControlOperationV1, generation: u64) -> AutonomyControlCommandV1 {
    ok(AutonomyControlCommandV1 {
        schema_version: 1,
        command_id: format!("control-{generation}"),
        organization_id: "example-office-organization".to_owned(),
        role_instance_sha256: digest('1'),
        autonomy_profile_sha256: profile().profile_sha256,
        operation,
        state_generation: generation,
        signer_id: "autonomy-operator".to_owned(),
        signer_scope_id: "general-office-role-control".to_owned(),
        signing_key_id: "work900-test-key".to_owned(),
        issued_at_unix_ms: 3_000,
        expires_at_unix_ms: 4_000,
        nonce: format!("control-nonce-{generation}"),
        evidence_ids: vec!["operator-signed-command".to_owned()],
        command_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

fn eligibility() -> AutonomyCaseEligibilityV1 {
    ok(AutonomyCaseEligibilityV1 {
        schema_version: 1,
        eligibility_id: "eligibility-case-a".to_owned(),
        role_instance_sha256: digest('1'),
        autonomy_state_sha256: state(AutonomyRoleStatusV1::Enabled, 1).state_sha256,
        deployment_approval_sha256: approval().approval_sha256,
        autonomy_profile_sha256: profile().profile_sha256,
        readiness_binding_sha256: readiness().binding_sha256,
        case_contract_sha256: digest('2'),
        current_case_instance_sha256: digest('3'),
        current_ownership_sha256: digest('4'),
        queue_entry_sha256: digest('5'),
        active_lease_sha256: digest('6'),
        work_item_sha256: digest('7'),
        source_approval_sha256: digest('8'),
        work_class_id: "office.record.update".to_owned(),
        requested_capability_ids: vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()],
        requested_semantic_target_ids: vec![
            "employee_name_input".to_owned(),
            "save_button".to_owned(),
        ],
        risk_class: AutonomyRiskClassV1::BusinessStateChange,
        policy_set_sha256: digest('9'),
        health_snapshot_sha256: digest('a'),
        evaluated_at_unix_ms: 3_000,
        status: AutonomyCaseEligibilityStatusV1::NotEligible,
        reason_codes: vec!["unevaluated".to_owned()],
        eligibility_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn health() -> AutonomyHealthSnapshotV1 {
    AutonomyHealthSnapshotV1 {
        schema_version: 1,
        window_id: "health-window-1".to_owned(),
        role_instance_sha256: digest('1'),
        autonomy_state_sha256: digest('2'),
        total_autonomous_cases: 8,
        verified_closure_cases: 5,
        exception_cases: 3,
        failed_cases: 0,
        false_completions: 0,
        unsafe_side_effects: 0,
        verification_failures: 0,
        recovery_failures: 0,
        policy_denials: 2,
        policy_bypasses: 0,
        activation_bypasses: 0,
        forbidden_proposals: 0,
        forbidden_executed_capabilities: 0,
        authority_expansions: 0,
        wrong_target_attempts: 0,
        duplicate_attempts: 0,
        escalation_misses: 0,
        secret_leakage: 0,
        residual_failures: 0,
        average_actions_per_case_millionths: 1_000_000,
        provider_failures: 0,
        sla_breaches: 0,
        threshold_state_ids: vec!["all-critical-thresholds-clear".to_owned()],
        critical_error_count: 0,
        health_status: AutonomyHealthStatusV1::Healthy,
        evidence_ids: vec!["actual-duty-cycle".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
}

fn eligible_case() -> AutonomyCaseEligibilityV1 {
    let state = state(AutonomyRoleStatusV1::Enabled, 1);
    let profile = profile();
    let capabilities = profile.autonomous_capability_ids.clone();
    let targets = profile.allowed_semantic_target_ids.clone();
    ok(evaluate_case_eligibility(
        eligibility(),
        &CaseEligibilityInputV1 {
            role_active: true,
            delegation_active: true,
            source_approved: true,
            case_non_terminal: true,
            ownership_current: true,
            lease_current: true,
            work_grant_current: true,
            policy_known: true,
            confirmation_required: false,
            mandatory_exception: false,
            work_class_id: "office.record.update",
            capability_ids: &capabilities,
            semantic_target_ids: &targets,
            risk_class: AutonomyRiskClassV1::BusinessStateChange,
            now_unix_ms: 3_001,
        },
        &state,
        &profile,
    ))
}

fn admission(eligibility: &AutonomyCaseEligibilityV1) -> AutonomyCaseAdmissionV1 {
    let profile = profile();
    ok(AutonomyCaseAdmissionV1 {
        schema_version: 1,
        admission_id: "admission-case-a".to_owned(),
        role_instance_sha256: eligibility.role_instance_sha256.clone(),
        autonomy_state_sha256: eligibility.autonomy_state_sha256.clone(),
        deployment_approval_sha256: eligibility.deployment_approval_sha256.clone(),
        autonomy_profile_sha256: eligibility.autonomy_profile_sha256.clone(),
        readiness_binding_sha256: eligibility.readiness_binding_sha256.clone(),
        case_contract_sha256: eligibility.case_contract_sha256.clone(),
        current_case_instance_sha256: eligibility.current_case_instance_sha256.clone(),
        current_ownership_sha256: eligibility.current_ownership_sha256.clone(),
        active_lease_sha256: eligibility.active_lease_sha256.clone(),
        work_grant_sha256: digest('b'),
        case_eligibility_sha256: eligibility.eligibility_sha256.clone(),
        allowed_autonomous_capability_ids: profile.autonomous_capability_ids,
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids,
        maximum_risk: profile.maximum_autonomous_risk,
        action_budget: 4,
        model_invocation_budget: 4,
        recovery_budget: 2,
        issued_at_unix_ms: 3_001,
        expires_at_unix_ms: 4_000,
        evidence_ids: vec!["current-authority-bindings".to_owned()],
        admission_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn handoff() -> HumanExceptionHandoffV1 {
    ok(HumanExceptionHandoffV1 {
        schema_version: 1,
        handoff_id: "handoff-case-e".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_sha256: profile().role_contract_sha256,
        role_instance_sha256: digest('1'),
        case_id: "case-e".to_owned(),
        case_sha256: digest('2'),
        autonomy_case_admission_sha256: ZERO_HASH.to_owned(),
        source_failure_sha256: digest('3'),
        reason_codes: vec!["material_ambiguity".to_owned()],
        severity: HumanExceptionSeverityV1::Clarification,
        situation_model_sha256: digest('4'),
        current_observation_sha256: digest('5'),
        case_progress_class_id: "paused-at-clarification".to_owned(),
        applied_action_hashes: Vec::new(),
        unresolved_requirement_ids: vec!["employee-name-fact".to_owned()],
        required_human_response_class_id: "provide-bounded-fact".to_owned(),
        work700_escalation_item_sha256: digest('6'),
        internal_route_id: "general-office-exception-desk".to_owned(),
        created_at_unix_ms: 3_000,
        evidence_ids: vec!["exception-classification".to_owned()],
        handoff_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn readiness_profile_and_signed_deployment_are_exactly_bound() {
    let readiness = readiness();
    let profile = profile();
    let approval = approval();
    ok(verify_deployment_approval(
        &approval,
        &profile,
        &readiness,
        &key().verifying_key(),
        3_000,
    ));

    let mut expanded = approval.clone();
    expanded
        .approved_capability_ids
        .push("uia.unknown".to_owned());
    expanded.approved_capability_ids.sort();
    let expanded = ok(expanded.seal_and_sign(&key()));
    assert!(verify_deployment_approval(
        &expanded,
        &profile,
        &readiness,
        &key().verifying_key(),
        3_000,
    )
    .is_err());
}

#[test]
fn case_eligibility_is_deterministic_and_model_independent() {
    let state = state(AutonomyRoleStatusV1::Enabled, 1);
    let profile = profile();
    let capabilities = profile.autonomous_capability_ids.clone();
    let targets = profile.allowed_semantic_target_ids.clone();
    let input = CaseEligibilityInputV1 {
        role_active: true,
        delegation_active: true,
        source_approved: true,
        case_non_terminal: true,
        ownership_current: true,
        lease_current: true,
        work_grant_current: true,
        policy_known: true,
        confirmation_required: false,
        mandatory_exception: false,
        work_class_id: "office.record.update",
        capability_ids: &capabilities,
        semantic_target_ids: &targets,
        risk_class: AutonomyRiskClassV1::BusinessStateChange,
        now_unix_ms: 3_001,
    };
    let first = ok(evaluate_case_eligibility(
        eligibility(),
        &input,
        &state,
        &profile,
    ));
    let second = ok(evaluate_case_eligibility(
        eligibility(),
        &input,
        &state,
        &profile,
    ));
    assert_eq!(first, second);
    assert_eq!(first.status, AutonomyCaseEligibilityStatusV1::Eligible);

    let mut unknown = input.clone();
    unknown.policy_known = false;
    let result = ok(evaluate_case_eligibility(
        eligibility(),
        &unknown,
        &state,
        &profile,
    ));
    assert_eq!(
        result.status,
        AutonomyCaseEligibilityStatusV1::HumanExceptionRequired
    );
}

#[test]
fn signed_control_is_monotonic_and_never_self_resumes() {
    let paused = state(AutonomyRoleStatusV1::Paused, 4);
    let resume = control(AutonomyControlOperationV1::Resume, 5);
    assert!(
        apply_control_command(&paused, &resume, &key().verifying_key(), 3_500, false,).is_err()
    );
    let resumed = ok(apply_control_command(
        &paused,
        &resume,
        &key().verifying_key(),
        3_500,
        true,
    ));
    assert_eq!(resumed.status, AutonomyRoleStatusV1::Enabled);

    let mut ledger = ReplayLedgerV1::default();
    ok(ledger.consume_command(&resume));
    assert!(ledger.consume_command(&resume).is_err());
}

#[test]
fn case_admission_and_task_binding_reject_stale_authority() {
    let eligibility = eligible_case();
    let admission = admission(&eligibility);
    let state = state(AutonomyRoleStatusV1::Enabled, 1);
    let profile = profile();
    ok(validate_case_admission(
        &admission,
        &eligibility,
        &state,
        &profile,
        3_100,
    ));
    let binding = ok(AutonomousCaseTaskBindingV1 {
        schema_version: 1,
        autonomy_case_admission_sha256: admission.admission_sha256.clone(),
        case_task_request_sha256: digest('1'),
        role_task_admission_sha256: digest('2'),
        current_case_instance_sha256: admission.current_case_instance_sha256.clone(),
        active_lease_sha256: admission.active_lease_sha256.clone(),
        work_grant_sha256: admission.work_grant_sha256.clone(),
        goal_spec_sha256: digest('3'),
        situation_model_sha256: digest('4'),
        planner_cycle_sha256: digest('5'),
        next_step_decision_sha256: digest('6'),
        policy_input_binding_sha256: digest('7'),
        evidence_ids: vec!["one-step-kernel-binding".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_case_task_binding(&binding, &admission));

    let mut wrong_lease = admission.clone();
    wrong_lease.active_lease_sha256 = digest('f');
    let wrong_lease = ok(wrong_lease.seal());
    assert!(validate_case_admission(&wrong_lease, &eligibility, &state, &profile, 3_100).is_err());
    assert!(validate_case_admission(&admission, &eligibility, &state, &profile, 4_001).is_err());
}

#[test]
fn human_exception_is_exactly_once_and_response_is_bounded() {
    let handoff = handoff();
    ok(validate_handoff(&handoff));
    let response = ok(HumanExceptionResponseV1 {
        schema_version: 1,
        response_id: "response-case-e".to_owned(),
        handoff_sha256: handoff.handoff_sha256.clone(),
        response_class: HumanExceptionResponseClassV1::ProvideBoundedFact,
        actor_class_id: "authorized-exception-operator".to_owned(),
        approved_bounded_fact_sha256: Some(digest('7')),
        confirmation_artifact_sha256: None,
        resolution_reference_sha256: Some(digest('8')),
        responded_at_unix_ms: 3_100,
        valid_until_unix_ms: 3_200,
        signing_key_id: "work900-test-key".to_owned(),
        evidence_ids: vec!["bounded-response".to_owned()],
        response_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()));
    ok(verify_human_response(
        &response,
        &handoff.handoff_sha256,
        &key().verifying_key(),
        3_150,
    ));
    assert!(
        verify_human_response(&response, &digest('9'), &key().verifying_key(), 3_150,).is_err()
    );
    assert!(verify_human_response(
        &response,
        &handoff.handoff_sha256,
        &key().verifying_key(),
        3_201,
    )
    .is_err());
    let mut ledger = ReplayLedgerV1::default();
    ok(ledger.consume_handoff(&handoff));
    assert!(ledger.consume_handoff(&handoff).is_err());
    ok(ledger.consume_response(&response));
    assert!(ledger.consume_response(&response).is_err());
}

#[test]
fn any_critical_health_count_trips_fail_closed() {
    let healthy = ok(evaluate_health(health(), &thresholds()));
    assert_eq!(healthy.health_status, AutonomyHealthStatusV1::Healthy);
    let mut unsafe_snapshot = health();
    unsafe_snapshot.wrong_target_attempts = 1;
    let critical = ok(evaluate_health(unsafe_snapshot, &thresholds()));
    assert_eq!(critical.health_status, AutonomyHealthStatusV1::Critical);
    assert_eq!(critical.critical_error_count, 1);
}

#[test]
fn negative_readiness_control_case_and_health_paths_fail_closed() {
    let profile = profile();
    let mut wrong_model = readiness();
    wrong_model.model_sha256 = digest('f');
    let wrong_model = ok(wrong_model.seal());
    assert!(verify_deployment_approval(
        &approval(),
        &profile,
        &wrong_model,
        &key().verifying_key(),
        3_000,
    )
    .is_err());
    assert!(readiness().validate(20_001).is_err());

    let paused = state(AutonomyRoleStatusV1::Paused, 4);
    let expired = control(AutonomyControlOperationV1::Resume, 5);
    assert!(
        apply_control_command(&paused, &expired, &key().verifying_key(), 4_001, true,).is_err()
    );
    let disabled = state(AutonomyRoleStatusV1::Disabled, 1);
    let capabilities = profile.autonomous_capability_ids.clone();
    let targets = profile.allowed_semantic_target_ids.clone();
    let input = CaseEligibilityInputV1 {
        role_active: true,
        delegation_active: true,
        source_approved: true,
        case_non_terminal: true,
        ownership_current: true,
        lease_current: true,
        work_grant_current: true,
        policy_known: true,
        confirmation_required: false,
        mandatory_exception: false,
        work_class_id: "office.record.update",
        capability_ids: &capabilities,
        semantic_target_ids: &targets,
        risk_class: AutonomyRiskClassV1::BusinessStateChange,
        now_unix_ms: 3_001,
    };
    let result = ok(evaluate_case_eligibility(
        eligibility(),
        &input,
        &disabled,
        &profile,
    ));
    assert_eq!(
        result.status,
        AutonomyCaseEligibilityStatusV1::AutonomyPaused
    );

    let mutators: [fn(&mut AutonomyHealthSnapshotV1); 8] = [
        |value: &mut AutonomyHealthSnapshotV1| value.false_completions = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.unsafe_side_effects = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.escalation_misses = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.authority_expansions = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.wrong_target_attempts = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.secret_leakage = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.policy_bypasses = 1,
        |value: &mut AutonomyHealthSnapshotV1| value.activation_bypasses = 1,
    ];
    for mutate in mutators {
        let mut value = health();
        mutate(&mut value);
        assert_eq!(
            ok(evaluate_health(value, &thresholds())).health_status,
            AutonomyHealthStatusV1::Critical
        );
    }
}

#[test]
fn crash_windows_a_through_l_never_direct_blind_replay() {
    let windows = [
        CrashWindowV1::RadarBeforeCheckpoint,
        CrashWindowV1::IntakeBeforeCase,
        CrashWindowV1::QueueBeforeLease,
        CrashWindowV1::ModelBeforeActionAdmission,
        CrashWindowV1::ActivationBeforeOutcome,
        CrashWindowV1::ActionBeforeVerification,
        CrashWindowV1::VerificationBeforeCaseLedger,
        CrashWindowV1::TerminalCaseBeforeEpisode,
        CrashWindowV1::HandoffBeforeRoutePublication,
        CrashWindowV1::PauseBeforeRuntimeState,
        CrashWindowV1::HealthTripBeforeIndex,
        CrashWindowV1::ClosureBeforeReport,
    ];
    let directives = windows.map(crash_recovery_directive);
    assert_eq!(directives.len(), 12);
    assert_eq!(
        directives[4],
        CrashRecoveryDirectiveV1::ReobserveAndVerifyNoReplay
    );
    assert_eq!(
        directives[5],
        CrashRecoveryDirectiveV1::ReobserveAndVerifyNoReplay
    );
    assert_eq!(
        directives[9],
        CrashRecoveryDirectiveV1::RestorePausedNoAction
    );
    assert_eq!(
        directives[10],
        CrashRecoveryDirectiveV1::RestorePausedNoAction
    );
}

#[test]
fn strict_parser_rejects_duplicate_float_unknown_and_sensitive_fields() {
    assert!(parse_json_strict::<AutonomyReadinessBindingV1>(
        b"{\"schema_version\":1,\"schema_version\":1}"
    )
    .is_err());
    assert!(parse_json_strict::<serde_json::Value>(b"{\"confidence\":0.5}").is_err());
    assert!(parse_json_strict::<AutonomyReadinessBindingV1>(
        b"{\"schema_version\":1,\"unknown\":true}"
    )
    .is_err());
    assert!(parse_json_strict::<serde_json::Value>(b"{\"raw_secret\":\"forbidden\"}").is_err());
}

#[test]
fn completion_and_replay_gates_reject_partial_evidence() {
    let report = ok(LimitedAutonomyCompletionReportV1 {
        schema_version: 1,
        report_id: "work900-completion".to_owned(),
        role_contract_sha256: digest('1'),
        profile_sha256: digest('2'),
        deployment_approval_sha256: digest('3'),
        readiness_binding_sha256: digest('4'),
        total_canary_cases: 8,
        routine_cases: 5,
        routine_verified_closure: 5,
        routine_human_touches: 0,
        human_exception_cases: 3,
        mandatory_exception_handoff_recall_millionths: 1_000_000,
        actual_model_backed_cases: 5,
        actual_krn_side_effect_actions: 8,
        observations: 17,
        actions: 8,
        provider_invocations: 8,
        false_completions: 0,
        wrong_targets: 0,
        wrong_actions: 0,
        duplicate_actions: 0,
        duplicate_claims: 0,
        authority_expansions: 0,
        forbidden_capabilities: 0,
        mandatory_escalation_misses: 0,
        secret_leakage: 0,
        network_accesses: 0,
        critical_errors: 0,
        autonomous_case_completion_rate_millionths: 625_000,
        human_touches_per_case_millionths: 375_000,
        routine_human_touches_per_case_millionths: 0,
        exception_rate_millionths: 375_000,
        verified_closure_rate_millionths: 750_000,
        false_completion_rate_millionths: 0,
        sla_compliance_millionths: 1_000_000,
        human_supervisor_count: 1,
        cases_per_human_supervisor_millionths: 8_000_000,
        autonomy_evidence: true,
        human_by_exception_evidence: true,
        track_w_completion_evidence: true,
        completed_at_unix_ms: 10_000,
        evidence_ids: vec!["actual-general-office-canary".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_completion_report(&report));
    let mut partial = report.clone();
    partial.actual_krn_side_effect_actions = 7;
    let partial = ok(partial.seal());
    assert!(validate_completion_report(&partial).is_err());

    let replay = ok(LimitedAutonomyReplayReportV1 {
        schema_version: 1,
        report_id: "work900-replay".to_owned(),
        input_count: 128,
        iterations_per_input: 100,
        mismatch_count: 0,
        duplicate_consumption_count: 0,
        input_set_sha256: digest('a'),
        output_set_sha256: digest('b'),
        evidence_ids: vec!["deterministic-core-replay".to_owned()],
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_replay_report(&replay));
}

#[test]
fn all_public_schemas_are_strict_draft_2020_12() {
    let names = [
        "autonomy-readiness-binding-v1",
        "limited-autonomy-profile-v1",
        "autonomy-deployment-approval-v1",
        "autonomy-role-runtime-state-v1",
        "autonomy-control-command-v1",
        "autonomy-case-eligibility-v1",
        "autonomy-case-admission-v1",
        "autonomous-case-task-binding-v1",
        "autonomy-rollout-cohort-v1",
        "autonomy-health-snapshot-v1",
        "autonomy-health-trip-v1",
        "human-exception-handoff-v1",
        "human-exception-response-v1",
        "autonomous-role-duty-cycle-request-v1",
        "autonomous-role-duty-cycle-result-v1",
        "limited-autonomy-completion-report-v1",
        "limited-autonomy-replay-report-v1",
        "limited-autonomy-certification-v1",
    ];
    for name in names {
        let schema: serde_json::Value = ok(serde_json::from_str(match public_schema(name) {
            Some(schema) => schema,
            None => panic!("missing schema: {name}"),
        }));
        assert_eq!(
            schema.get("$schema").and_then(serde_json::Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(
            schema
                .get("additionalProperties")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
    }
}
