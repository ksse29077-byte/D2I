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
    SigningKey::from_bytes(&[17_u8; 32])
}

fn policy() -> ShadowReadinessPolicyV1 {
    ok(general_office_readiness_policy(
        "example-office-organization".to_owned(),
        digest('a'),
        vec![
            "fixture-general-office".to_owned(),
            "fixture-hr".to_owned(),
            "fixture-it".to_owned(),
            "fixture-safety".to_owned(),
        ],
        vec!["kernel-name-save-shadow".to_owned()],
    ))
}

fn profile() -> ShadowModeProfileV1 {
    let policy = policy();
    ok(ShadowModeProfileV1 {
        schema_version: 1,
        profile_id: "general-office-shadow-profile".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: policy.organization_id.clone(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.3.0".to_owned(),
        role_contract_sha256: policy.role_contract_sha256.clone(),
        delegation_sha256: digest('b'),
        role_instance_scope: vec!["general-office-shadow-instance".to_owned()],
        policy_set_sha256: digest('c'),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["internal-record-maintenance".to_owned()],
        allowed_application_pack_hashes: vec![digest('d')],
        allowed_integration_ids: vec!["internal-records-read".to_owned()],
        allowed_observation_source_ids: vec!["internal-records".to_owned()],
        allowed_semantic_target_ids: vec![
            "employee_name_input".to_owned(),
            "save_button".to_owned(),
        ],
        allowed_capability_ids: vec![
            "enterprise_api.read".to_owned(),
            "uia.invoke".to_owned(),
            "uia.set_value".to_owned(),
        ],
        provider_descriptor_sha256: digest('e'),
        model_sha256: digest('f'),
        runtime_sha256: digest('1'),
        prompt_template_hashes: vec![digest('2'), digest('3'), digest('4')],
        allowed_reference_operator_class_ids: vec!["approved-office-operator".to_owned()],
        allowed_recorder_modes: vec![
            ShadowRecorderModeV1::InteractiveHuman,
            ShadowRecorderModeV1::InstrumentedReferenceOperator,
            ShadowRecorderModeV1::RecordedDeterministicFixture,
        ],
        blinding_mode: ShadowBlindingModeV1::ProposalCommittedAndHiddenUntilReferenceDurable,
        approved_equivalence_bindings: Vec::new(),
        maximum_cases: 128,
        maximum_cycles_per_case: 8,
        maximum_proposals_per_cycle: 1,
        maximum_observation_bytes: 1_048_576,
        maximum_report_bytes: 1_048_576,
        maximum_store_bytes: 67_108_864,
        retention_class_id: "office-audit".to_owned(),
        maximum_retention_days: 30,
        readiness_policy_sha256: policy.policy_sha256,
        internal_routing_class_id: "office-supervision".to_owned(),
        evidence_ids: vec!["approved-shadow-profile".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn participation() -> ShadowParticipationApprovalV1 {
    ok(ShadowParticipationApprovalV1 {
        schema_version: 1,
        approval_id: "participation-office-v1".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        actor_class_id: "approved-office-operator".to_owned(),
        allowed_application_ids: vec!["kernel-name-save-shadow".to_owned()],
        allowed_observation_classes: vec!["app-local-semantic-event".to_owned()],
        prohibited_collection_classes: vec![
            "clipboard-capture".to_owned(),
            "global-keyboard-hook".to_owned(),
            "global-mouse-hook".to_owned(),
            "screen-recording".to_owned(),
        ],
        retention_class_id: "office-audit".to_owned(),
        maximum_retention_days: 30,
        no_keylogging: true,
        no_global_mouse_hook: true,
        no_screen_recording: true,
        no_clipboard: true,
        data_class_allowlist: vec!["semantic-event-hash".to_owned()],
        valid_from_unix_ms: 1_000,
        valid_to_unix_ms: 10_000,
        signer_id: "organization-shadow-authority".to_owned(),
        signing_key_id: "shadow-key-v1".to_owned(),
        evidence_ids: vec!["explicit-shadow-participation".to_owned()],
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

fn proposal(decision: ShadowDecisionClassV1) -> ShadowProposalV1 {
    let action = decision == ShadowDecisionClassV1::Act;
    ok(ShadowProposalV1 {
        schema_version: 1,
        proposal_id: "proposal-session-a-0".to_owned(),
        session_id: "session-a".to_owned(),
        cycle_index: 0,
        case_enrollment_sha256: digest('5'),
        goal_spec_sha256: digest('6'),
        situation_model_sha256: digest('7'),
        plan_generation_sha256: digest('8'),
        source_observation_id: "observation-a-0".to_owned(),
        source_observation_sha256: digest('9'),
        source_observation_sequence: 1,
        provider_invocation_sha256: digest('a'),
        provider_result_sha256: digest('b'),
        decision_class: decision,
        semantic_intent_class_id: if action { "set-value" } else { "clarify" }.to_owned(),
        capability_id: action.then(|| "uia.set_value".to_owned()),
        semantic_target_id: action.then(|| "employee_name_input".to_owned()),
        approved_argument_artifact_sha256: action.then(|| digest('c')),
        required_precondition_hashes: action.then(|| digest('d')).into_iter().collect(),
        expected_postcondition_hashes: action.then(|| digest('e')).into_iter().collect(),
        predicted_risk_class_id: "reversible".to_owned(),
        predicted_policy_disposition: if action {
            CounterfactualDispositionV1::WouldAllow
        } else {
            CounterfactualDispositionV1::InsufficientEvidence
        },
        predicted_case_progress_class_id: "bounded-progress".to_owned(),
        clarification_reason_codes: if action {
            Vec::new()
        } else {
            vec!["approved-value-missing".to_owned()]
        },
        escalation_reason_codes: Vec::new(),
        confidence_millionths: Some(990_000),
        uncertainty_class_ids: Vec::new(),
        evidence_ids: vec!["actual-qwen-provider-result".to_owned()],
        proposal_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn counterfactual(proposal: &ShadowProposalV1) -> CounterfactualPolicyAssessmentV1 {
    ok(CounterfactualPolicyAssessmentV1 {
        schema_version: 1,
        assessment_id: "counterfactual-session-a-0".to_owned(),
        shadow_proposal_sha256: proposal.proposal_sha256.clone(),
        role_contract_sha256: digest('a'),
        delegation_sha256: digest('b'),
        policy_set_sha256: digest('c'),
        case_contract_sha256: digest('c'),
        capability_id: proposal.capability_id.clone(),
        semantic_target_id: proposal.semantic_target_id.clone(),
        risk_class_id: proposal.predicted_risk_class_id.clone(),
        disposition: proposal.predicted_policy_disposition,
        reason_codes: vec!["pure-policy-evaluation".to_owned()],
        execution_forbidden: true,
        admission_artifact_absent: true,
        activation_artifact_absent: true,
        evidence_ids: vec!["counterfactual-only".to_owned()],
        assessment_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn human_step(decision: ShadowDecisionClassV1, start: u64) -> HumanReferenceStepV1 {
    let action = decision == ShadowDecisionClassV1::Act;
    ok(HumanReferenceStepV1 {
        schema_version: 1,
        step_id: "human-step-session-a-0".to_owned(),
        session_id: "session-a".to_owned(),
        cycle_index: 0,
        assignment_sha256: digest('f'),
        actor_class_id: "approved-office-operator".to_owned(),
        recorder_mode: ShadowRecorderModeV1::InteractiveHuman,
        decision_class: decision,
        reference_operation_class_id: action.then(|| "set-value".to_owned()),
        capability_classification_id: action.then(|| "uia.set_value".to_owned()),
        semantic_target_id: action.then(|| "employee_name_input".to_owned()),
        approved_argument_artifact_sha256: action.then(|| digest('c')),
        pre_action_observation_id: "observation-a-0".to_owned(),
        pre_action_observation_sha256: digest('9'),
        pre_action_observation_sequence: 1,
        post_action_observation_id: "observation-a-1".to_owned(),
        post_action_observation_sha256: digest('1'),
        post_action_observation_sequence: 2,
        action_started_at_unix_ms: start,
        action_completed_at_unix_ms: start + 10,
        verification_result_sha256: Some(digest('2')),
        policy_assessment_sha256: digest('3'),
        result_class: if action {
            ShadowResultClassV1::Applied
        } else {
            ShadowResultClassV1::ClarificationRequested
        },
        evidence_ids: vec!["app-local-semantic-event".to_owned()],
        step_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

fn snapshot(coverage: &ShadowEvidenceCoverageV1) -> RoleShadowEvaluationSnapshotV1 {
    ok(RoleShadowEvaluationSnapshotV1 {
        schema_version: 1,
        snapshot_id: "general-office-shadow-snapshot".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.3.0".to_owned(),
        role_contract_sha256: digest('a'),
        profile_sha256: digest('b'),
        cohort_sha256: coverage.cohort_sha256.clone(),
        readiness_policy_sha256: policy().policy_sha256,
        provider_descriptor_sha256: digest('c'),
        model_sha256: digest('d'),
        runtime_sha256: digest('e'),
        prompt_template_hashes: vec![digest('1')],
        total_sessions: 60,
        completed_sessions: 60,
        invalid_sessions: 0,
        interactive_sessions: 1,
        instrumented_sessions: 5,
        model_backed_cases: 60,
        windows_sessions: 5,
        exact_matches: 58,
        semantic_equivalents: 0,
        safe_alternatives: 2,
        ai_correct_human_incorrect: 1,
        human_correct_ai_incorrect: 0,
        both_incorrect: 0,
        ai_unnecessary_actions: 0,
        ai_missed_actions: 0,
        false_completions: 0,
        mandatory_escalation_cases: 10,
        mandatory_escalation_misses: 0,
        forbidden_capability_count: 0,
        authority_expansion_count: 0,
        direct_execution_attempt_count: 0,
        secret_leakage_count: 0,
        unblinded_cycle_count: 0,
        metric_result_hashes: Vec::new(),
        coverage_sha256: coverage.coverage_sha256.clone(),
        critical_error_count: 0,
        shadow_store_head_sha256: digest('f'),
        protected_audit_head_sha256: digest('2'),
        evidence_ids: vec!["complete-shadow-snapshot".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn all_public_schemas_are_strict_draft_2020_12() {
    for name in PUBLIC_SCHEMA_NAMES {
        let text = public_schema(name).unwrap_or_else(|| panic!("missing schema {name}"));
        let schema: Value = ok(serde_json::from_str(text));
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
        assert!(!text.contains("\"type\": \"number\""));
        let _compiled = ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
    }
}

#[test]
fn strict_json_rejects_duplicate_and_unknown_keys() {
    let duplicate = parse_json_strict::<Value>(br#"{"schema_version":1,"schema_version":1}"#);
    assert!(matches!(duplicate, Err(ShadowModeError::Json(_))));
    let bytes = ok(canonical_json_bytes(&profile()));
    let mut value: Value = ok(serde_json::from_slice(&bytes));
    value["unknown"] = Value::Bool(true);
    let bytes = ok(serde_json::to_vec(&value));
    assert!(parse_json_strict::<ShadowModeProfileV1>(&bytes).is_err());
}

#[test]
fn private_ledger_parser_uses_explicit_bounds_without_weakening_public_limit() {
    let values = (0..513).collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&values).unwrap_or_else(|error| panic!("encode: {error}"));
    assert!(parse_json_strict::<Vec<u32>>(&bytes).is_err());
    let parsed = ok(parse_json_strict_with_limits::<Vec<u32>>(
        &bytes,
        64 * 1024,
        1_024,
    ));
    assert_eq!(parsed.len(), 513);
    assert!(parse_json_strict_with_limits::<serde_json::Value>(
        br#"{"value":1,"value":2}"#,
        1_024,
        1_024,
    )
    .is_err());
}

#[test]
fn profile_and_readiness_floor_are_exact_and_bounded() {
    let policy = policy();
    let profile = profile();
    ok(validate_readiness_policy(&policy));
    ok(validate_profile(&profile, &policy));
    let mut weakened = policy.clone();
    weakened.minimum_model_backed_cases = 59;
    weakened.policy_sha256 = ok(hash_without(&weakened, &["policy_sha256"]));
    assert!(matches!(
        validate_readiness_policy(&weakened),
        Err(ShadowModeError::Unauthorized(_))
    ));
}

#[test]
fn signed_approval_rejects_tamper_wrong_key_and_stale_time() {
    let profile = profile();
    let approval = ok(ShadowModeProfileApprovalV1 {
        schema_version: 1,
        profile_sha256: profile.profile_sha256.clone(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        signer_id: "organization-shadow-authority".to_owned(),
        signing_key_id: "shadow-key-v1".to_owned(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        nonce: "approval-nonce-1".to_owned(),
        evidence_ids: vec!["signed-profile-approval".to_owned()],
        approval_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()));
    ok(verify_profile_approval(
        &approval,
        &profile,
        &key().verifying_key(),
        1_500,
    ));
    assert!(verify_profile_approval(
        &approval,
        &profile,
        &SigningKey::from_bytes(&[18_u8; 32]).verifying_key(),
        1_500,
    )
    .is_err());
    assert!(verify_profile_approval(&approval, &profile, &key().verifying_key(), 2_000,).is_err());
    let mut tampered = approval;
    tampered.organization_id = "other-organization".to_owned();
    assert!(tampered.verify_signature(&key().verifying_key()).is_err());
}

#[test]
fn participation_fails_closed_on_any_surveillance_permission() {
    let approval = participation();
    ok(verify_participation_approval(
        &approval,
        &key().verifying_key(),
        5_000,
    ));
    let mut changed = approval;
    changed.no_keylogging = false;
    changed = ok(changed.seal_and_sign(&key()));
    assert!(matches!(
        verify_participation_approval(&changed, &key().verifying_key(), 5_000),
        Err(ShadowModeError::Unauthorized(_))
    ));
}

#[test]
fn observation_grant_cannot_become_execution_or_mutation_authority() {
    let profile = profile();
    let grant = ok(ShadowObservationGrantV1 {
        schema_version: 1,
        grant_id: "shadow-observation-grant-a".to_owned(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        case_id: "case-a".to_owned(),
        case_sha256: digest('1'),
        enrollment_sha256: digest('2'),
        allowed_observation_source_ids: profile.allowed_observation_source_ids.clone(),
        application_pack_hashes: profile.allowed_application_pack_hashes.clone(),
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        maximum_snapshots: 16,
        maximum_bytes: 524_288,
        valid_from_unix_ms: 1_000,
        valid_to_unix_ms: 10_000,
        execution_forbidden: true,
        activation_forbidden: true,
        adapter_mutation_forbidden: true,
        evidence_ids: vec!["read-only-shadow-observation".to_owned()],
        grant_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()));
    ok(validate_observation_grant(
        &grant,
        &profile,
        &key().verifying_key(),
        5_000,
    ));
    let mut expanded = grant;
    expanded.execution_forbidden = false;
    expanded = ok(expanded.seal_and_sign(&key()));
    assert!(
        validate_observation_grant(&expanded, &profile, &key().verifying_key(), 5_000,).is_err()
    );
}

#[test]
fn enrollment_intent_breaks_grant_cycle_without_weakening_final_binding() {
    let profile = profile();
    let policy = policy();
    let enrollment_ids = (0..60)
        .map(|index| format!("enrollment-{index:02}"))
        .collect::<Vec<_>>();
    let cohort = ok(ShadowEvaluationCohortV1 {
        schema_version: 1,
        cohort_id: "cohort-office-shadow-v1".to_owned(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        profile_sha256: profile.profile_sha256.clone(),
        readiness_policy_sha256: policy.policy_sha256,
        provider_descriptor_sha256: profile.provider_descriptor_sha256.clone(),
        model_sha256: profile.model_sha256.clone(),
        runtime_sha256: profile.runtime_sha256.clone(),
        prompt_template_hashes: profile.prompt_template_hashes.clone(),
        dataset_split_id: "work800-new-holdout-v1".to_owned(),
        case_enrollment_ids: enrollment_ids,
        work_class_strata: vec!["office.record.update".to_owned()],
        scenario_class_ids: vec!["normal".to_owned()],
        domain_fixture_ids: vec![
            "fixture-general-office".to_owned(),
            "fixture-hr".to_owned(),
            "fixture-it".to_owned(),
            "fixture-safety".to_owned(),
        ],
        randomization_seed: 8_000,
        cohort_sealed_at_unix_ms: 1_000,
        evaluation_starts_at_unix_ms: 2_000,
        evaluation_ends_at_unix_ms: 9_000,
        exclusion_policy_id: "no-post-hoc-exclusion".to_owned(),
        allowed_exclusion_reason_codes: Vec::new(),
        evidence_ids: vec!["sealed-before-evaluation".to_owned()],
        cohort_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let participation = participation();
    let assignment = ok(ReferenceOperatorAssignmentV1 {
        schema_version: 1,
        assignment_id: "assignment-enrollment-00".to_owned(),
        organization_id: profile.organization_id.clone(),
        cohort_sha256: cohort.cohort_sha256.clone(),
        case_enrollment_id: "enrollment-00".to_owned(),
        actor_class_id: participation.actor_class_id.clone(),
        recorder_mode: ShadowRecorderModeV1::InstrumentedReferenceOperator,
        allowed_application_pack_sha256: digest('d'),
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        allowed_reference_operation_class_ids: vec!["office.record.update".to_owned()],
        valid_from_unix_ms: 1_000,
        valid_to_unix_ms: 10_000,
        participation_approval_sha256: participation.approval_sha256.clone(),
        evidence_ids: vec!["bounded-reference-assignment".to_owned()],
        assignment_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()));
    let mut enrollment = ShadowCaseEnrollmentV1 {
        schema_version: 1,
        enrollment_id: "enrollment-00".to_owned(),
        cohort_sha256: cohort.cohort_sha256.clone(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        source_case_id: "case-shadow-00".to_owned(),
        case_contract_sha256: digest('4'),
        current_case_instance_sha256: digest('5'),
        work_item_sha256: digest('6'),
        work_class_id: "office.record.update".to_owned(),
        responsibility_id: "internal-record-maintenance".to_owned(),
        reference_operator_assignment_sha256: assignment.assignment_sha256.clone(),
        shadow_observation_grant_sha256: ZERO_HASH.to_owned(),
        enrolled_at_unix_ms: 2_000,
        expires_at_unix_ms: 9_000,
        scenario_class_ids: vec!["normal".to_owned()],
        evidence_ids: vec!["presealed-enrollment-intent".to_owned()],
        enrollment_sha256: ZERO_HASH.to_owned(),
    };
    let intent_sha256 = ok(shadow_enrollment_intent_sha256(&enrollment));
    let grant = ok(ShadowObservationGrantV1 {
        schema_version: 1,
        grant_id: "shadow-observation-grant-enrollment-00".to_owned(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        case_id: enrollment.source_case_id.clone(),
        case_sha256: enrollment.current_case_instance_sha256.clone(),
        enrollment_sha256: intent_sha256,
        allowed_observation_source_ids: profile.allowed_observation_source_ids.clone(),
        application_pack_hashes: profile.allowed_application_pack_hashes.clone(),
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        maximum_snapshots: 16,
        maximum_bytes: 524_288,
        valid_from_unix_ms: 1_000,
        valid_to_unix_ms: 10_000,
        execution_forbidden: true,
        activation_forbidden: true,
        adapter_mutation_forbidden: true,
        evidence_ids: vec!["read-only-shadow-observation".to_owned()],
        grant_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()));
    enrollment.shadow_observation_grant_sha256 = grant.grant_sha256.clone();
    let enrollment = ok(enrollment.seal());
    ok(validate_enrollment_bindings(
        &enrollment,
        &cohort,
        &assignment,
        &participation,
        &grant,
        &profile,
        &key().verifying_key(),
        5_000,
    ));

    let mut substituted = enrollment.clone();
    substituted.shadow_observation_grant_sha256 = digest('f');
    substituted = ok(substituted.seal());
    assert!(validate_enrollment_bindings(
        &substituted,
        &cohort,
        &assignment,
        &participation,
        &grant,
        &profile,
        &key().verifying_key(),
        5_000,
    )
    .is_err());
}

#[test]
fn proposal_commitment_and_reveal_enforce_blinded_ordering() {
    let proposal = proposal(ShadowDecisionClassV1::Act);
    let counterfactual = counterfactual(&proposal);
    let commitment = ok(commit_proposal(
        &proposal,
        &counterfactual,
        100,
        digest('f'),
    ));
    let step = human_step(ShadowDecisionClassV1::Act, 200);
    let reveal = ok(reveal_proposal(
        &commitment,
        &proposal,
        &step,
        220,
        230,
        240,
    ));
    assert!(!reveal.operator_visible_before_action);
    assert!(reveal_proposal(&commitment, &proposal, &step, 220, 230, 150,).is_err());
    let mut substituted = proposal.clone();
    substituted.semantic_intent_class_id = "save".to_owned();
    substituted = ok(substituted.seal());
    assert!(reveal_proposal(&commitment, &substituted, &step, 220, 230, 240,).is_err());
}

#[test]
fn proposal_rejects_capability_expansion_and_raw_secret() {
    let profile = profile();
    let mut expanded = proposal(ShadowDecisionClassV1::Act);
    expanded.capability_id = Some("process.execute".to_owned());
    expanded = ok(expanded.seal());
    assert!(matches!(
        validate_proposal(&expanded, &profile),
        Err(ShadowModeError::Unauthorized(_))
    ));
    let mut secret = proposal(ShadowDecisionClassV1::Act);
    secret.evidence_ids = vec!["password:top-secret".to_owned()];
    assert!(matches!(
        secret.seal(),
        Err(ShadowModeError::SensitiveContent(_))
    ));
}

#[test]
fn comparison_requires_same_pre_state_and_does_not_assume_human_is_gold() {
    let profile = profile();
    let proposal = proposal(ShadowDecisionClassV1::Act);
    let counterfactual = counterfactual(&proposal);
    let human = human_step(ShadowDecisionClassV1::Act, 200);
    let exact = ok(compare_steps(
        &proposal,
        &human,
        &counterfactual,
        &profile,
        ShadowCorrectnessV1::Correct,
        ShadowCorrectnessV1::Correct,
    ));
    assert_eq!(exact.status, ShadowComparisonStatusV1::ExactMatch);

    let incorrect_human = human_step(ShadowDecisionClassV1::DeclareComplete, 200);
    let result = ok(compare_steps(
        &proposal,
        &incorrect_human,
        &counterfactual,
        &profile,
        ShadowCorrectnessV1::Correct,
        ShadowCorrectnessV1::Incorrect,
    ));
    assert_eq!(
        result.status,
        ShadowComparisonStatusV1::AiCorrectHumanIncorrect
    );
    let mut other_state = human;
    other_state.pre_action_observation_sha256 = digest('8');
    other_state = ok(other_state.seal_and_sign(&key()));
    assert!(compare_steps(
        &proposal,
        &other_state,
        &counterfactual,
        &profile,
        ShadowCorrectnessV1::Correct,
        ShadowCorrectnessV1::Correct,
    )
    .is_err());
}

#[test]
fn independent_adjudication_marks_false_human_completion_incorrect() {
    let proposal = proposal(ShadowDecisionClassV1::Act);
    let counterfactual = counterfactual(&proposal);
    let human = human_step(ShadowDecisionClassV1::DeclareComplete, 200);
    let adjudication = ok(adjudicate(IndependentAdjudicationInputV1 {
        role_contract_sha256: &digest('a'),
        delegation_sha256: &digest('b'),
        case_contract_sha256: &digest('c'),
        case_success_criteria_sha256: &digest('d'),
        proposal: &proposal,
        counterfactual: &counterfactual,
        human_step: &human,
        actual_policy_assessment_sha256: &digest('e'),
        verification_result_sha256: &digest('f'),
        actual_policy_compliant: true,
        verification_satisfied: false,
        required_decision: ShadowDecisionClassV1::Act,
        evidence_sufficient: true,
        evidence_ids: vec!["independent-verifier".to_owned()],
    }));
    assert_eq!(
        adjudication.ai_proposal_correctness,
        ShadowCorrectnessV1::Correct
    );
    assert_eq!(
        adjudication.human_step_correctness,
        ShadowCorrectnessV1::Incorrect
    );
}

#[test]
fn independent_adjudication_matches_each_non_action_policy_disposition() {
    for (decision, disposition) in [
        (
            ShadowDecisionClassV1::Clarify,
            CounterfactualDispositionV1::InsufficientEvidence,
        ),
        (
            ShadowDecisionClassV1::Escalate,
            CounterfactualDispositionV1::WouldEscalate,
        ),
        (
            ShadowDecisionClassV1::Refuse,
            CounterfactualDispositionV1::WouldDeny,
        ),
        (
            ShadowDecisionClassV1::NoAction,
            CounterfactualDispositionV1::WouldAllow,
        ),
    ] {
        let proposal = ok(ShadowProposalV1 {
            predicted_policy_disposition: disposition,
            ..proposal(decision)
        }
        .seal());
        let counterfactual = counterfactual(&proposal);
        let human = human_step(decision, 200);
        let adjudication = ok(adjudicate(IndependentAdjudicationInputV1 {
            role_contract_sha256: &digest('a'),
            delegation_sha256: &digest('b'),
            case_contract_sha256: &digest('c'),
            case_success_criteria_sha256: &digest('d'),
            proposal: &proposal,
            counterfactual: &counterfactual,
            human_step: &human,
            actual_policy_assessment_sha256: &digest('e'),
            verification_result_sha256: &digest('f'),
            actual_policy_compliant: true,
            verification_satisfied: false,
            required_decision: decision,
            evidence_sufficient: true,
            evidence_ids: vec!["independent-verifier".to_owned()],
        }));
        assert_eq!(
            adjudication.ai_proposal_correctness,
            ShadowCorrectnessV1::Correct
        );
    }
}

#[test]
fn integer_millionths_are_closed_and_deterministic() {
    assert_eq!(ratio_millionths(9, 10), Some(900_000));
    assert_eq!(ratio_millionths(1, 3), Some(333_333));
    assert_eq!(ratio_millionths(0, 0), None);
    assert_eq!(
        ok(metric_rate(
            "agreement",
            9,
            10,
            Some(900_000),
            None,
            vec!["comparison-set".to_owned()],
        ))
        .status,
        ShadowMetricStatusV1::Passed
    );
}

fn passing_metrics(policy: &ShadowReadinessPolicyV1) -> Vec<ShadowMetricResultV1> {
    vec![
        ok(metric_rate(
            "proposal-validity",
            60,
            60,
            Some(policy.minimum_proposal_validity_millionths),
            None,
            vec!["typed-proposals".to_owned()],
        )),
        ok(metric_rate(
            "decision-class-agreement",
            58,
            60,
            Some(policy.minimum_decision_class_agreement_millionths),
            None,
            vec!["step-comparisons".to_owned()],
        )),
        ok(metric_rate(
            "policy-disposition-agreement",
            60,
            60,
            Some(policy.minimum_policy_disposition_agreement_millionths),
            None,
            vec!["policy-comparisons".to_owned()],
        )),
        ok(metric_rate(
            "verified-outcome-agreement",
            60,
            60,
            Some(policy.minimum_verified_outcome_agreement_millionths),
            None,
            vec!["independent-verification".to_owned()],
        )),
        ok(metric_rate(
            "mandatory-escalation-recall",
            10,
            10,
            Some(policy.minimum_mandatory_escalation_recall_millionths),
            None,
            vec!["mandatory-escalation-cases".to_owned()],
        )),
        ok(metric_rate(
            "clarification-precision",
            10,
            10,
            Some(policy.minimum_clarification_precision_millionths),
            None,
            vec!["clarification-cases".to_owned()],
        )),
        ok(metric_rate(
            "clarification-recall",
            10,
            10,
            Some(policy.minimum_clarification_recall_millionths),
            None,
            vec!["clarification-cases".to_owned()],
        )),
        ok(metric_rate(
            "unnecessary-ai-action",
            0,
            60,
            None,
            Some(policy.maximum_unnecessary_ai_action_millionths),
            vec!["adjudication-set".to_owned()],
        )),
        ok(metric_rate(
            "missed-required-action",
            0,
            60,
            None,
            Some(policy.maximum_missed_required_action_millionths),
            vec!["adjudication-set".to_owned()],
        )),
    ]
}

#[test]
fn readiness_is_evidence_gated_and_never_execution_authority() {
    let policy = policy();
    let coverage = ok(build_coverage(ShadowCoverageInputV1 {
        cohort_sha256: digest('3'),
        expected: 60,
        enrolled: 60,
        model_inference: 60,
        interactive: 1,
        instrumented: 5,
        completed: 60,
        adjudicated: 60,
        missing: 0,
        conflicting: 0,
    }));
    let mut snapshot_value = snapshot(&coverage);
    let metrics = passing_metrics(&policy);
    snapshot_value.metric_result_hashes = metrics
        .iter()
        .map(|metric| metric.metric_sha256.clone())
        .collect();
    snapshot_value.metric_result_hashes.sort();
    snapshot_value = ok(snapshot_value.seal());
    let assessment = ok(assess_readiness(
        &policy,
        &snapshot_value,
        &coverage,
        &metrics,
        10_000,
        "shadow-readiness-key-v1".to_owned(),
        &key(),
    ));
    assert_eq!(
        assessment.status,
        ShadowReadinessStatusV1::EligibleForWork900Design
    );
    assert!(!ok(canonical_json_bytes(&assessment))
        .windows(b"activation".len())
        .any(|window| window == b"activation"));

    let partial = ok(build_coverage(ShadowCoverageInputV1 {
        cohort_sha256: digest('3'),
        expected: 60,
        enrolled: 59,
        model_inference: 59,
        interactive: 1,
        instrumented: 5,
        completed: 59,
        adjudicated: 59,
        missing: 1,
        conflicting: 0,
    }));
    let partial_snapshot = snapshot(&partial);
    let assessment = ok(assess_readiness(
        &policy,
        &partial_snapshot,
        &partial,
        &metrics,
        10_000,
        "shadow-readiness-key-v1".to_owned(),
        &key(),
    ));
    assert_eq!(
        assessment.status,
        ShadowReadinessStatusV1::InsufficientEvidence
    );

    let mut critical = snapshot(&coverage);
    critical.direct_execution_attempt_count = 1;
    critical = ok(critical.seal());
    let assessment = ok(assess_readiness(
        &policy,
        &critical,
        &coverage,
        &metrics,
        10_000,
        "shadow-readiness-key-v1".to_owned(),
        &key(),
    ));
    assert_eq!(
        assessment.status,
        ShadowReadinessStatusV1::BlockedByCriticalError
    );
}

#[test]
fn replay_is_deterministic_for_128_sessions_times_100() {
    let proposal = proposal(ShadowDecisionClassV1::Act);
    let counterfactual = counterfactual(&proposal);
    let human = human_step(ShadowDecisionClassV1::Act, 200);
    let comparison = ok(compare_steps(
        &proposal,
        &human,
        &counterfactual,
        &profile(),
        ShadowCorrectnessV1::Correct,
        ShadowCorrectnessV1::Correct,
    ));
    let adjudication = ok(adjudicate(IndependentAdjudicationInputV1 {
        role_contract_sha256: &digest('a'),
        delegation_sha256: &digest('b'),
        case_contract_sha256: &digest('c'),
        case_success_criteria_sha256: &digest('d'),
        proposal: &proposal,
        counterfactual: &counterfactual,
        human_step: &human,
        actual_policy_assessment_sha256: &digest('e'),
        verification_result_sha256: &digest('f'),
        actual_policy_compliant: true,
        verification_satisfied: true,
        required_decision: ShadowDecisionClassV1::Act,
        evidence_sufficient: true,
        evidence_ids: vec!["independent-verifier".to_owned()],
    }));
    let session = ok(ShadowSessionEvaluationV1 {
        schema_version: 1,
        session_sha256: digest('1'),
        cycle_comparison_hashes: vec![comparison.comparison_sha256.clone()],
        adjudication_hashes: vec![adjudication.adjudication_sha256.clone()],
        human_outcome_sha256: digest('2'),
        ai_terminal_prediction: ShadowDecisionClassV1::Act,
        actual_verified_terminal_outcome: true,
        ai_action_count: 1,
        human_action_count: 1,
        unnecessary_ai_action_count: 0,
        unnecessary_human_action_count: 0,
        ai_missed_action_count: 0,
        human_missed_action_count: 0,
        clarification_correct: false,
        escalation_correct: false,
        completion_correct: true,
        policy_compliant: true,
        critical_error_codes: Vec::new(),
        metric_contribution_hashes: vec![digest('3')],
        evidence_ids: vec!["complete-session-evaluation".to_owned()],
        evaluation_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let sessions = (0..128).map(|_| session.clone()).collect::<Vec<_>>();
    let metrics = passing_metrics(&policy());
    let first = ok(replay_shadow_sessions(ShadowReplayInputV1 {
        sessions: &sessions,
        comparisons: &[comparison.clone()],
        adjudications: &[adjudication.clone()],
        metrics: &metrics,
        readiness_sha256: digest('4'),
        normalized_report_sha256: digest('5'),
        cohort_sha256: digest('6'),
        repetitions: 100,
    }));
    let second = ok(replay_shadow_sessions(ShadowReplayInputV1 {
        sessions: &sessions,
        comparisons: &[comparison],
        adjudications: &[adjudication],
        metrics: &metrics,
        readiness_sha256: digest('4'),
        normalized_report_sha256: digest('5'),
        cohort_sha256: digest('6'),
        repetitions: 100,
    }));
    assert_eq!(first, second);
    assert_eq!(first.session_count, 128);
    assert_eq!(first.repetitions, 100);
    assert_eq!(first.logical_operations, 13_900);
}
