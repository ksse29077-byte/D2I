use d2i_cognitive_ir::{
    CognitiveRiskClass, GoalProgress, PlanEdge, PlanEdgeKind, PlanGraph, PlanNode, PlanNodeKind,
};
use d2i_cognitive_recovery::*;
use jsonschema::{Draft, JSONSchema};
use std::collections::BTreeSet;
use std::fs;

trait TestValue<T> {
    fn test_value(self, context: &str) -> T;
}

impl<T, E: std::fmt::Display> TestValue<T> for Result<T, E> {
    fn test_value(self, context: &str) -> T {
        self.unwrap_or_else(|error| panic!("{context}: {error}"))
    }
}

impl<T> TestValue<T> for Option<T> {
    fn test_value(self, context: &str) -> T {
        self.unwrap_or_else(|| panic!("{context}"))
    }
}

fn hash(seed: char) -> String {
    format!("sha256:{}", seed.to_string().repeat(64))
}

fn indexed_hash(namespace: u64, index: u32) -> String {
    format!("sha256:{:064x}", namespace * 1_000 + u64::from(index))
}

fn trigger(stage: RecoveryStageV1, reasons: Vec<RecoveryReasonCodeV1>) -> RecoveryTriggerV1 {
    let plan = !matches!(stage, RecoveryStageV1::Observation);
    let proposal = matches!(
        stage,
        RecoveryStageV1::Policy
            | RecoveryStageV1::Confirmation
            | RecoveryStageV1::Activation
            | RecoveryStageV1::TargetResolution
            | RecoveryStageV1::Preparation
            | RecoveryStageV1::Execution
            | RecoveryStageV1::Verification
    );
    let policy = matches!(
        stage,
        RecoveryStageV1::Activation
            | RecoveryStageV1::TargetResolution
            | RecoveryStageV1::Preparation
            | RecoveryStageV1::Execution
            | RecoveryStageV1::Verification
    );
    let activation = matches!(
        stage,
        RecoveryStageV1::TargetResolution
            | RecoveryStageV1::Preparation
            | RecoveryStageV1::Execution
            | RecoveryStageV1::Verification
    );
    let verification = stage == RecoveryStageV1::Verification;
    RecoveryTriggerV1 {
        schema_version: 1,
        trigger_id: "trigger-1".to_owned(),
        stage,
        goal_id: "goal-1".to_owned(),
        plan_generation_id: plan.then(|| "plan-1".to_owned()),
        proposal_id: proposal.then(|| "proposal-1".to_owned()),
        proposal_sha256: proposal.then(|| hash('1')),
        capability_id: proposal.then(|| "cap.primary".to_owned()),
        source_observation_id: "observation-1".to_owned(),
        source_observation_hash: hash('2'),
        source_observation_sequence: 1,
        fresh_observation_id: verification.then(|| "observation-2".to_owned()),
        fresh_observation_hash: verification.then(|| hash('3')),
        fresh_observation_sequence: verification.then_some(2),
        execution_receipt_sha256: verification.then(|| hash('4')),
        verified_action_result_sha256: verification.then(|| hash('5')),
        policy_decision_sha256: policy.then(|| hash('6')),
        activation_admission_sha256: activation.then(|| hash('7')),
        reason_codes: reasons,
        evidence_ids: vec!["evidence-1".to_owned()],
        detected_at_unix_ms: 1_000,
        trigger_sha256: hash('0'),
    }
    .seal()
    .test_value("fixture trigger")
}

fn budget() -> RecoveryBudgetV1 {
    RecoveryBudgetV1 {
        schema_version: 1,
        budget_id: "budget-1".to_owned(),
        goal_id: "goal-1".to_owned(),
        maximum_total_cycles: 6,
        remaining_total_cycles: 6,
        maximum_reobservations: 2,
        remaining_reobservations: 2,
        maximum_fresh_retries: 2,
        remaining_fresh_retries: 2,
        maximum_alternate_capability_attempts: 2,
        remaining_alternate_capability_attempts: 2,
        maximum_replans: 1,
        remaining_replans: 1,
        maximum_clarifications: 1,
        remaining_clarifications: 1,
        started_at_unix_ms: 900,
        deadline_unix_ms: 10_000,
        evidence_ids: vec!["budget-source".to_owned()],
        budget_sha256: hash('0'),
    }
    .seal()
    .test_value("fixture budget")
}

fn history() -> RecoveryHistoryV1 {
    RecoveryHistoryV1::empty("history-1".to_owned(), "goal-1".to_owned())
        .test_value("fixture history")
}

fn profile() -> RecoveryPolicyProfileV1 {
    RecoveryPolicyProfileV1 {
        schema_version: 1,
        profile_id: "profile-1".to_owned(),
        policy_set_sha256: hash('a'),
        authority_sha256: hash('b'),
        retryable_failure_classes: vec![
            RecoveryFailureClassV1::ExecutionFailed,
            RecoveryFailureClassV1::ExpectedChangeMissing,
            RecoveryFailureClassV1::PostconditionFailed,
        ],
        reobservable_failure_classes: vec![
            RecoveryFailureClassV1::AmbiguousTarget,
            RecoveryFailureClassV1::ExecutionTimeoutOrUnknown,
            RecoveryFailureClassV1::StaleBinding,
            RecoveryFailureClassV1::VerificationInconclusive,
        ],
        alternate_capability_failure_classes: vec![
            RecoveryFailureClassV1::ExecutionFailed,
            RecoveryFailureClassV1::NoCandidate,
            RecoveryFailureClassV1::UnsupportedCapability,
        ],
        replannable_failure_classes: vec![
            RecoveryFailureClassV1::NoCandidate,
            RecoveryFailureClassV1::Unrecoverable,
        ],
        clarifiable_failure_classes: vec![
            RecoveryFailureClassV1::AmbiguousTarget,
            RecoveryFailureClassV1::ClarificationRequired,
        ],
        mandatory_escalation_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        forbidden_automatic_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        retryable_capability_ids: vec!["cap.primary".to_owned()],
        alternate_capability_groups: vec![AlternateCapabilityGroupV1 {
            group_id: "desktop-edit".to_owned(),
            capability_ids: vec!["cap.alternate".to_owned(), "cap.primary".to_owned()],
        }],
        maximum_same_capability_attempts: 2,
        allow_replan: true,
        allow_clarification: true,
        escalation_risk_threshold: CognitiveRiskClass::HighCriticality,
        evidence_ids: vec!["policy-evidence".to_owned()],
        profile_sha256: hash('0'),
    }
    .seal()
    .test_value("fixture profile")
}

fn context() -> RecoveryDecisionContextV1 {
    RecoveryDecisionContextV1 {
        verification_verdict: Some(RecoveryVerificationVerdictV1::Failed),
        goal_progress: GoalProgress::InProgress,
        latest_observation_trusted: true,
        bounded_user_fact_missing: false,
        same_failure_count: 0,
        same_capability_attempts: 1,
        current_proposal_id: Some("proposal-1".to_owned()),
        current_proposal_sha256: Some(hash('1')),
        current_capability_id: Some("cap.primary".to_owned()),
        current_risk: CognitiveRiskClass::Reversible,
        alternate_capability_ids: vec!["cap.alternate".to_owned(), "cap.primary".to_owned()],
        replan_available: true,
    }
}

fn decision(
    reasons: Vec<RecoveryReasonCodeV1>,
    context: RecoveryDecisionContextV1,
) -> (
    RecoveryTriggerV1,
    RecoveryClassificationV1,
    RecoveryDecisionV1,
) {
    let trigger = trigger(RecoveryStageV1::Verification, reasons);
    let classification = classify_recovery_trigger(&trigger).test_value("classification");
    let decision = decide_recovery(
        "recovery-1".to_owned(),
        &trigger,
        &classification,
        &budget(),
        &history(),
        &profile(),
        &context,
        1_100,
        vec!["decision-evidence".to_owned()],
    )
    .test_value("decision");
    (trigger, classification, decision)
}

fn history_entry(index: u32, sequence: u64) -> RecoveryHistoryEntryV1 {
    RecoveryHistoryEntryV1 {
        schema_version: 1,
        cycle_index: index,
        trigger_sha256: indexed_hash(1, index),
        classification_sha256: indexed_hash(2, index),
        decision_sha256: indexed_hash(3, index),
        plan_generation_id: Some(format!("plan-{index}")),
        proposal_id: Some(format!("proposal-{index}")),
        proposal_sha256: Some(indexed_hash(4, index)),
        capability_id: Some("cap.primary".to_owned()),
        input_sha256: Some(indexed_hash(5, index)),
        source_observation_hash: indexed_hash(6, index),
        source_observation_sequence: sequence,
        fresh_observation_hash: Some(indexed_hash(7, index)),
        fresh_observation_sequence: Some(sequence + 1),
        policy_decision_sha256: Some(indexed_hash(8, index)),
        cognitive_admission_sha256: Some(indexed_hash(9, index)),
        activation_record_hash: Some(indexed_hash(10, index)),
        execution_receipt_sha256: Some(indexed_hash(11, index)),
        verified_action_result_sha256: Some(indexed_hash(12, index)),
        terminal_outcome: RecoveryHistoryOutcomeV1::Failed,
        evidence_ids: vec![format!("history-evidence-{index}")],
        entry_sha256: hash('0'),
    }
    .seal()
    .test_value("history entry")
}

#[test]
fn every_stage_has_a_valid_trigger_shape_and_unknown_fields_fail() {
    for stage in [
        RecoveryStageV1::Observation,
        RecoveryStageV1::Grounding,
        RecoveryStageV1::CandidateGeneration,
        RecoveryStageV1::Ranking,
        RecoveryStageV1::Policy,
        RecoveryStageV1::Confirmation,
        RecoveryStageV1::Activation,
        RecoveryStageV1::TargetResolution,
        RecoveryStageV1::Preparation,
        RecoveryStageV1::Execution,
        RecoveryStageV1::Verification,
    ] {
        trigger(stage, vec![RecoveryReasonCodeV1::ExecutionFailed])
            .validate()
            .test_value("valid stage fixture");
    }
    let value = serde_json::to_value(trigger(
        RecoveryStageV1::Verification,
        vec![RecoveryReasonCodeV1::ExecutionFailed],
    ))
    .test_value("serialize");
    let mut object = value.as_object().test_value("object").clone();
    object.insert("authority".to_owned(), serde_json::json!(true));
    assert!(parse_json_strict::<RecoveryTriggerV1>(
        &serde_json::to_vec(&object).test_value("bytes")
    )
    .is_err());
}

#[test]
fn trigger_rejects_impossible_lifecycle_and_tamper() {
    let mut value = trigger(
        RecoveryStageV1::Verification,
        vec![RecoveryReasonCodeV1::ExecutionFailed],
    );
    value.activation_admission_sha256 = None;
    assert!(value.validate().is_err());
    let mut value = trigger(
        RecoveryStageV1::Verification,
        vec![RecoveryReasonCodeV1::ExecutionFailed],
    );
    value.reason_codes = vec![RecoveryReasonCodeV1::PolicyDenied];
    assert!(value.validate().is_err());
}

#[test]
fn classification_is_deterministic_and_unsafe_has_priority() {
    let trigger = trigger(
        RecoveryStageV1::Verification,
        vec![
            RecoveryReasonCodeV1::ExecutionFailed,
            RecoveryReasonCodeV1::UnsafeSideEffect,
            RecoveryReasonCodeV1::ProtectedInvariantViolation,
        ],
    );
    let first = classify_recovery_trigger(&trigger).test_value("classification");
    let second = classify_recovery_trigger(&trigger).test_value("classification");
    assert_eq!(first, second);
    assert_eq!(
        first.primary_class,
        RecoveryFailureClassV1::ProtectedInvariantViolation
    );
    assert_eq!(first.safety_severity, RecoverySafetySeverityV1::Unsafe);
}

#[test]
fn budget_consumption_is_atomic_bounded_and_deadline_aware() {
    let before = budget();
    let after = before
        .consume_for(RecoveryDecisionKindV1::RetryFreshCycle, 1_100)
        .test_value("consume retry");
    assert_eq!(after.remaining_total_cycles, 5);
    assert_eq!(after.remaining_fresh_retries, 1);
    assert_eq!(after.remaining_reobservations, 2);
    after
        .validate_transition_from(&before, RecoveryDecisionKindV1::RetryFreshCycle)
        .test_value("exact transition");
    assert!(before
        .consume_for(RecoveryDecisionKindV1::RetryFreshCycle, 10_000)
        .is_err());
    let mut increased = after.clone();
    increased.remaining_reobservations = 3;
    assert!(increased
        .validate_transition_from(&before, RecoveryDecisionKindV1::RetryFreshCycle)
        .is_err());
}

#[test]
fn history_rejects_replay_and_blind_failure_loops() {
    let first = history_entry(1, 2);
    let first_history = history().append(first.clone()).test_value("first append");
    let mut replay = history_entry(2, 4);
    replay.proposal_id = first.proposal_id.clone();
    replay = replay.seal().test_value("resealed replay");
    assert!(first_history.append(replay).is_err());

    let mut repeated = history_entry(2, 4);
    repeated.source_observation_hash = first.source_observation_hash.clone();
    repeated.capability_id = first.capability_id.clone();
    repeated.input_sha256 = first.input_sha256.clone();
    repeated = repeated.seal().test_value("resealed fingerprint");
    assert!(first_history.append(repeated).is_err());
}

#[test]
fn history_rejects_each_consumed_trust_identity_and_the_sixty_fifth_cycle() {
    let first = history_entry(1, 2);
    let first_history = history().append(first.clone()).test_value("first append");

    let mut duplicate_admission = history_entry(2, 4);
    duplicate_admission.cognitive_admission_sha256 = first.cognitive_admission_sha256.clone();
    duplicate_admission = duplicate_admission
        .seal()
        .test_value("duplicate admission fixture");
    assert!(first_history.append(duplicate_admission).is_err());

    let mut duplicate_activation = history_entry(2, 4);
    duplicate_activation.activation_record_hash = first.activation_record_hash.clone();
    duplicate_activation = duplicate_activation
        .seal()
        .test_value("duplicate activation fixture");
    assert!(first_history.append(duplicate_activation).is_err());

    let mut duplicate_receipt = history_entry(2, 4);
    duplicate_receipt.execution_receipt_sha256 = first.execution_receipt_sha256.clone();
    duplicate_receipt = duplicate_receipt
        .seal()
        .test_value("duplicate receipt fixture");
    assert!(first_history.append(duplicate_receipt).is_err());

    let mut full = history();
    for index in 1..=MAX_RECOVERY_CYCLES as u32 {
        full = full
            .append(history_entry(index, u64::from(index) * 2))
            .test_value("bounded history append");
    }
    let mut sixty_fifth = full
        .entries
        .last()
        .cloned()
        .test_value("last bounded history entry");
    sixty_fifth.cycle_index = MAX_RECOVERY_CYCLES as u32 + 1;
    sixty_fifth.source_observation_sequence = (MAX_RECOVERY_CYCLES as u64 + 1) * 2;
    assert!(full.append(sixty_fifth).is_err());
}

#[test]
fn decision_matrix_distinguishes_complete_continue_retry_reobserve_and_safety() {
    let mut value = context();
    value.verification_verdict = Some(RecoveryVerificationVerdictV1::Passed);
    value.goal_progress = GoalProgress::Complete;
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::NoFailure], value)
            .2
            .decision_kind,
        RecoveryDecisionKindV1::NoRecoveryComplete
    );

    let mut value = context();
    value.verification_verdict = Some(RecoveryVerificationVerdictV1::Passed);
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::NoFailure], value)
            .2
            .decision_kind,
        RecoveryDecisionKindV1::ContinueExecution
    );
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::ExecutionFailed], context())
            .2
            .decision_kind,
        RecoveryDecisionKindV1::RetryFreshCycle
    );
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::StaleBinding], context())
            .2
            .decision_kind,
        RecoveryDecisionKindV1::Reobserve
    );
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::PolicyDenied], context())
            .2
            .decision_kind,
        RecoveryDecisionKindV1::Stop
    );
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::PolicyUnknown], context())
            .2
            .decision_kind,
        RecoveryDecisionKindV1::Escalate
    );
    assert_eq!(
        decision(vec![RecoveryReasonCodeV1::UnsafeSideEffect], context())
            .2
            .decision_kind,
        RecoveryDecisionKindV1::Escalate
    );
}

#[test]
fn exhausted_budget_stops_without_underflow_or_new_execution_authority() {
    let trigger = trigger(
        RecoveryStageV1::Verification,
        vec![RecoveryReasonCodeV1::BudgetExhausted],
    );
    let classification = classify_recovery_trigger(&trigger).test_value("classification");
    let mut exhausted = budget();
    exhausted.remaining_total_cycles = 0;
    exhausted = exhausted.seal().test_value("exhausted budget");
    let decision = decide_recovery(
        "recovery-exhausted".to_owned(),
        &trigger,
        &classification,
        &exhausted,
        &history(),
        &profile(),
        &context(),
        1_100,
        vec!["budget-exhausted".to_owned()],
    )
    .test_value("stop decision");
    assert_eq!(decision.decision_kind, RecoveryDecisionKindV1::Stop);
    assert_eq!(decision.budget_after.remaining_total_cycles, 0);
    assert!(!decision.required_new_observation);
    assert!(!decision.required_new_platform_activation);
}

#[test]
fn repeated_capability_selects_alternate_and_ambiguous_requests_clarification() {
    let mut value = context();
    value.same_capability_attempts = 2;
    let alternate = decision(vec![RecoveryReasonCodeV1::ExecutionFailed], value).2;
    assert_eq!(
        alternate.decision_kind,
        RecoveryDecisionKindV1::SelectAlternateCapability
    );
    assert_eq!(alternate.excluded_capability_ids, vec!["cap.primary"]);

    let mut value = context();
    value.same_failure_count = 1;
    value.bounded_user_fact_missing = true;
    let clarification = decision(vec![RecoveryReasonCodeV1::AmbiguousTarget], value).2;
    assert_eq!(
        clarification.decision_kind,
        RecoveryDecisionKindV1::RequestClarification
    );
}

#[test]
fn fresh_cycle_requires_wholly_new_trust_chain_material() {
    let (_, _, decision) = decision(vec![RecoveryReasonCodeV1::ExecutionFailed], context());
    let history = history();
    let request = FreshRecoveryCycleRequestV1::from_decision(
        "cycle-2".to_owned(),
        &decision,
        "goal-1".to_owned(),
        "plan-1".to_owned(),
        Some(hash('1')),
        Some("cap.primary".to_owned()),
        "observation-2".to_owned(),
        hash('8'),
        2,
        &history,
        hash('b'),
        hash('a'),
        1_200,
        2_000,
        vec!["fresh-cycle".to_owned()],
    )
    .test_value("fresh request");
    let mut evidence = FreshRecoveryCycleEvidenceV1 {
        schema_version: 1,
        cycle_request_sha256: request.cycle_request_sha256.clone(),
        observation_id: "observation-3".to_owned(),
        observation_hash: hash('9'),
        observation_sequence: 3,
        plan_generation_id: "plan-1".to_owned(),
        proposal_id: "proposal-2".to_owned(),
        proposal_sha256: hash('c'),
        capability_id: "cap.primary".to_owned(),
        input_sha256: hash('d'),
        policy_decision_sha256: hash('e'),
        cognitive_admission_sha256: hash('f'),
        activation_record_hash: hash('a'),
        execution_receipt_sha256: hash('b'),
        verified_action_result_sha256: hash('c'),
        verification_verdict: RecoveryVerificationVerdictV1::Passed,
    };
    evidence
        .validate_against(&request, &history)
        .test_value("fresh evidence");
    evidence.proposal_id = "proposal-1".to_owned();
    assert!(evidence.validate_against(&request, &history).is_err());
}

fn replan_request() -> ReplanRequestV1 {
    ReplanRequestV1 {
        schema_version: 1,
        replan_id: "replan-1".to_owned(),
        recovery_decision_sha256: hash('1'),
        goal_id: "goal-1".to_owned(),
        old_plan_generation_id: "plan-1".to_owned(),
        old_plan_sha256: hash('2'),
        latest_observation_id: "observation-2".to_owned(),
        latest_observation_hash: hash('3'),
        latest_observation_sequence: 2,
        failure_class: RecoveryFailureClassV1::NoCandidate,
        excluded_proposal_ids: vec!["proposal-1".to_owned()],
        excluded_capability_ids: vec!["cap.primary".to_owned()],
        authority_sha256: hash('4'),
        policy_snapshot_sha256: hash('5'),
        constraints: vec![
            ReplanConstraintCodeV1::BoundedLoopsOnly,
            ReplanConstraintCodeV1::PreserveGoal,
            ReplanConstraintCodeV1::ReversibleOnly,
            ReplanConstraintCodeV1::StayWithinAuthority,
        ],
        evidence_ids: vec!["replan-evidence".to_owned()],
        request_sha256: hash('0'),
    }
    .seal()
    .test_value("replan request")
}

fn plan(generation: &str, capability: &str) -> PlanGraph {
    PlanGraph {
        schema_version: 1,
        plan_generation_id: generation.to_owned(),
        entry_node: "select".to_owned(),
        nodes: vec![
            PlanNode {
                node_id: "select".to_owned(),
                kind: PlanNodeKind::SelectCapability,
                capability_id: Some(capability.to_owned()),
                loop_bound: None,
            },
            PlanNode {
                node_id: "return".to_owned(),
                kind: PlanNodeKind::Return,
                capability_id: None,
                loop_bound: None,
            },
        ],
        edges: vec![PlanEdge {
            from: "select".to_owned(),
            to: "return".to_owned(),
            kind: PlanEdgeKind::Sequence,
            condition: None,
        }],
    }
}

#[test]
fn replanner_requires_new_complete_authorized_acyclic_plan() {
    let request = replan_request();
    let authorized = BTreeSet::from(["cap.alternate".to_owned()]);
    let result = DeterministicFixtureReplanner::replan(
        &request,
        plan("plan-2", "cap.alternate"),
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &authorized,
    )
    .test_value("valid replan");
    result
        .validate_against(&request, &authorized)
        .test_value("valid result");
    assert!(DeterministicFixtureReplanner::replan(
        &request,
        plan("plan-1", "cap.alternate"),
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &authorized,
    )
    .is_err());
    assert!(DeterministicFixtureReplanner::replan(
        &request,
        plan("plan-2", "cap.primary"),
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &authorized,
    )
    .is_err());

    let mut cyclic = plan("plan-2", "cap.alternate");
    cyclic.edges.push(PlanEdge {
        from: "return".to_owned(),
        to: "select".to_owned(),
        kind: PlanEdgeKind::Recovery,
        condition: None,
    });
    assert!(DeterministicFixtureReplanner::replan(
        &request,
        cyclic,
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &authorized,
    )
    .is_err());

    let mut unbounded = plan("plan-2", "cap.alternate");
    unbounded.nodes[0].kind = PlanNodeKind::LoopBounded;
    assert!(DeterministicFixtureReplanner::replan(
        &request,
        unbounded,
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &authorized,
    )
    .is_err());
}

fn clarification(kind: ClarificationQuestionKindV1) -> ClarificationRequestV1 {
    ClarificationRequestV1 {
        schema_version: 1,
        clarification_id: "clarification-1".to_owned(),
        recovery_decision_sha256: hash('1'),
        goal_id: "goal-1".to_owned(),
        question_code: ClarificationQuestionCodeV1::ConfirmGoalConstraint,
        question_kind: kind,
        prompt_template_id: "confirm-goal-constraint-v1".to_owned(),
        allowed_options: if kind == ClarificationQuestionKindV1::ChooseOne {
            vec!["first".to_owned(), "second".to_owned()]
        } else {
            Vec::new()
        },
        value_schema_id: "bounded-answer-v1".to_owned(),
        maximum_text_bytes: 128,
        sensitive_input_allowed: false,
        blocks_capability_ids: vec!["cap.primary".to_owned()],
        requested_at_unix_ms: 1_200,
        expires_at_unix_ms: 2_000,
        evidence_ids: vec!["clarification-evidence".to_owned()],
        request_sha256: hash('0'),
    }
    .seal()
    .test_value("clarification request")
}

#[test]
fn clarification_is_typed_bounded_non_secret_and_exactly_bound() {
    for (kind, answer) in [
        (
            ClarificationQuestionKindV1::Boolean,
            ClarificationAnswerV1::Boolean(true),
        ),
        (
            ClarificationQuestionKindV1::ChooseOne,
            ClarificationAnswerV1::ChooseOne("first".to_owned()),
        ),
        (
            ClarificationQuestionKindV1::BoundedNonSecretText,
            ClarificationAnswerV1::BoundedNonSecretText("safe-value".to_owned()),
        ),
    ] {
        let request = clarification(kind);
        ClarificationResponseV1 {
            schema_version: 1,
            response_id: format!("response-{kind:?}"),
            clarification_request_sha256: request.request_sha256.clone(),
            goal_id: "goal-1".to_owned(),
            authenticated_instruction_provenance_sha256: hash('2'),
            answer,
            responded_at_unix_ms: 1_300,
            response_sha256: hash('0'),
        }
        .seal(&request)
        .test_value("typed answer");
    }
    let request = clarification(ClarificationQuestionKindV1::BoundedNonSecretText);
    let response = ClarificationResponseV1 {
        schema_version: 1,
        response_id: "response-secret".to_owned(),
        clarification_request_sha256: request.request_sha256.clone(),
        goal_id: "goal-1".to_owned(),
        authenticated_instruction_provenance_sha256: hash('2'),
        answer: ClarificationAnswerV1::BoundedNonSecretText("password=hunter2".to_owned()),
        responded_at_unix_ms: 1_300,
        response_sha256: hash('0'),
    };
    assert!(response.seal(&request).is_err());

    let request = clarification(ClarificationQuestionKindV1::Boolean);
    let wrong_request = ClarificationResponseV1 {
        schema_version: 1,
        response_id: "response-wrong-request".to_owned(),
        clarification_request_sha256: hash('f'),
        goal_id: "goal-1".to_owned(),
        authenticated_instruction_provenance_sha256: hash('2'),
        answer: ClarificationAnswerV1::Boolean(true),
        responded_at_unix_ms: 1_300,
        response_sha256: hash('0'),
    };
    assert!(wrong_request.seal(&request).is_err());

    let wrong_goal = ClarificationResponseV1 {
        schema_version: 1,
        response_id: "response-wrong-goal".to_owned(),
        clarification_request_sha256: request.request_sha256.clone(),
        goal_id: "goal-2".to_owned(),
        authenticated_instruction_provenance_sha256: hash('2'),
        answer: ClarificationAnswerV1::Boolean(true),
        responded_at_unix_ms: 1_300,
        response_sha256: hash('0'),
    };
    assert!(wrong_goal.seal(&request).is_err());
}

#[test]
fn escalation_is_non_executable_hash_only_and_high_risk_safe() {
    let escalation = EscalationRequestV1 {
        schema_version: 1,
        escalation_id: "escalation-1".to_owned(),
        recovery_decision_sha256: hash('1'),
        goal_id: "goal-1".to_owned(),
        severity: EscalationSeverityV1::High,
        reason_codes: vec![RecoveryReasonCodeV1::UnsafeSideEffect],
        originating_stage: RecoveryStageV1::Verification,
        required_authority_class: RequiredAuthorityClassV1::SecurityOwner,
        blocked_capability_ids: vec!["cap.primary".to_owned()],
        policy_set_sha256: hash('2'),
        authority_sha256: hash('3'),
        latest_observation_hash: hash('4'),
        verified_action_result_sha256: Some(hash('5')),
        protected_violation_count: 1,
        unexpected_change_count: 1,
        safe_state_summary_codes: vec![
            SafeStateSummaryCodeV1::AutomaticMutationBlocked,
            SafeStateSummaryCodeV1::ProtectedInvariantViolated,
        ],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::InspectProtectedEvidence],
        evidence_ids: vec!["escalation-evidence".to_owned()],
        raised_at_unix_ms: 1_300,
        escalation_sha256: hash('0'),
    }
    .seal()
    .test_value("escalation");
    escalation.validate().test_value("valid escalation");
}

#[test]
fn only_meaning_preserving_decisions_project_to_legacy_contract() {
    let retry = decision(vec![RecoveryReasonCodeV1::ExecutionFailed], context()).2;
    project_legacy_decision(&retry).test_value("retry projection");
    let unsafe_decision = decision(vec![RecoveryReasonCodeV1::UnsafeSideEffect], context()).2;
    assert!(matches!(
        project_legacy_decision(&unsafe_decision),
        Err(RecoveryError::Unsupported(_))
    ));
}

#[test]
fn strict_json_rejects_duplicate_fields() {
    let bytes = br#"{"schema_version":1,"schema_version":1}"#;
    assert!(parse_json_strict::<RecoveryBudgetV1>(bytes).is_err());
}

#[test]
fn draft_2020_12_schema_accepts_canonical_artifacts_and_rejects_unknown_fields() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/cognitive/cognitive-recovery-control-v1.schema.json");
    let schema: serde_json::Value =
        serde_json::from_slice(&fs::read(path).test_value("schema bytes"))
            .test_value("schema JSON");
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .test_value("compiled recovery schema");

    let trigger = trigger(
        RecoveryStageV1::Verification,
        vec![RecoveryReasonCodeV1::ExecutionFailed],
    );
    let classification = classify_recovery_trigger(&trigger).test_value("classification");
    let history = history();
    let budget = budget();
    let profile = profile();
    let decision = decide_recovery(
        "recovery-1".to_owned(),
        &trigger,
        &classification,
        &budget,
        &history,
        &profile,
        &context(),
        1_100,
        vec!["decision-evidence".to_owned()],
    )
    .test_value("decision");
    let fresh_request = FreshRecoveryCycleRequestV1::from_decision(
        "cycle-2".to_owned(),
        &decision,
        "goal-1".to_owned(),
        "plan-1".to_owned(),
        Some(hash('1')),
        Some("cap.primary".to_owned()),
        "observation-2".to_owned(),
        hash('8'),
        2,
        &history,
        hash('b'),
        hash('a'),
        1_200,
        2_000,
        vec!["fresh-cycle".to_owned()],
    )
    .test_value("fresh request");
    let fresh_evidence = FreshRecoveryCycleEvidenceV1 {
        schema_version: 1,
        cycle_request_sha256: fresh_request.cycle_request_sha256.clone(),
        observation_id: "observation-3".to_owned(),
        observation_hash: hash('9'),
        observation_sequence: 3,
        plan_generation_id: "plan-1".to_owned(),
        proposal_id: "proposal-2".to_owned(),
        proposal_sha256: hash('c'),
        capability_id: "cap.primary".to_owned(),
        input_sha256: hash('d'),
        policy_decision_sha256: hash('e'),
        cognitive_admission_sha256: hash('f'),
        activation_record_hash: hash('a'),
        execution_receipt_sha256: hash('b'),
        verified_action_result_sha256: hash('c'),
        verification_verdict: RecoveryVerificationVerdictV1::Passed,
    };
    let replan_request = replan_request();
    let replan_result = DeterministicFixtureReplanner::replan(
        &replan_request,
        plan("plan-2", "cap.alternate"),
        "fixture-planner".to_owned(),
        ReplanRationaleCodeV1::RemoveFailedCapability,
        &BTreeSet::from(["cap.alternate".to_owned()]),
    )
    .test_value("replan result");
    let clarification_request = clarification(ClarificationQuestionKindV1::Boolean);
    let clarification_response = ClarificationResponseV1 {
        schema_version: 1,
        response_id: "response-1".to_owned(),
        clarification_request_sha256: clarification_request.request_sha256.clone(),
        goal_id: "goal-1".to_owned(),
        authenticated_instruction_provenance_sha256: hash('2'),
        answer: ClarificationAnswerV1::Boolean(true),
        responded_at_unix_ms: 1_300,
        response_sha256: hash('0'),
    }
    .seal(&clarification_request)
    .test_value("clarification response");
    let escalation = EscalationRequestV1 {
        schema_version: 1,
        escalation_id: "escalation-1".to_owned(),
        recovery_decision_sha256: hash('1'),
        goal_id: "goal-1".to_owned(),
        severity: EscalationSeverityV1::High,
        reason_codes: vec![RecoveryReasonCodeV1::UnsafeSideEffect],
        originating_stage: RecoveryStageV1::Verification,
        required_authority_class: RequiredAuthorityClassV1::SecurityOwner,
        blocked_capability_ids: vec!["cap.primary".to_owned()],
        policy_set_sha256: hash('2'),
        authority_sha256: hash('3'),
        latest_observation_hash: hash('4'),
        verified_action_result_sha256: Some(hash('5')),
        protected_violation_count: 1,
        unexpected_change_count: 1,
        safe_state_summary_codes: vec![SafeStateSummaryCodeV1::AutomaticMutationBlocked],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::InspectProtectedEvidence],
        evidence_ids: vec!["escalation-evidence".to_owned()],
        raised_at_unix_ms: 1_300,
        escalation_sha256: hash('0'),
    }
    .seal()
    .test_value("escalation");
    let cycle_result = RecoveryCycleResultV1 {
        schema_version: 1,
        recovery_id: "recovery-1".to_owned(),
        outcome: RecoveryCycleOutcomeV1::Recovered,
        trigger_sha256: trigger.trigger_sha256.clone(),
        classification_sha256: classification.classification_sha256.clone(),
        decision_sha256: decision.decision_sha256.clone(),
        budget_before_sha256: budget.budget_sha256.clone(),
        budget_after_sha256: decision.budget_after.budget_sha256.clone(),
        history_before_sha256: history.history_sha256.clone(),
        history_after_sha256: hash('3'),
        fresh_cycle_request_sha256: Some(fresh_request.cycle_request_sha256.clone()),
        replan_result_sha256: None,
        clarification_sha256: None,
        escalation_sha256: None,
        new_proposal_sha256: Some(fresh_evidence.proposal_sha256.clone()),
        new_admission_sha256: Some(fresh_evidence.cognitive_admission_sha256.clone()),
        new_activation_record_hash: Some(fresh_evidence.activation_record_hash.clone()),
        new_execution_receipt_sha256: Some(fresh_evidence.execution_receipt_sha256.clone()),
        new_verification_result_sha256: Some(fresh_evidence.verified_action_result_sha256.clone()),
        terminal_verified_result_sha256: Some(fresh_evidence.verified_action_result_sha256.clone()),
        evidence_ids: vec!["cycle-result".to_owned()],
        result_sha256: hash('0'),
    }
    .seal()
    .test_value("cycle result");

    for value in [
        serde_json::to_value(&trigger).test_value("trigger JSON"),
        serde_json::to_value(&classification).test_value("classification JSON"),
        serde_json::to_value(&budget).test_value("budget JSON"),
        serde_json::to_value(&history).test_value("history JSON"),
        serde_json::to_value(&profile).test_value("profile JSON"),
        serde_json::to_value(&decision).test_value("decision JSON"),
        serde_json::to_value(&fresh_request).test_value("request JSON"),
        serde_json::to_value(&fresh_evidence).test_value("evidence JSON"),
        serde_json::to_value(&replan_request).test_value("replan request JSON"),
        serde_json::to_value(&replan_result).test_value("replan result JSON"),
        serde_json::to_value(&clarification_request).test_value("clarification request JSON"),
        serde_json::to_value(&clarification_response).test_value("clarification response JSON"),
        serde_json::to_value(&escalation).test_value("escalation JSON"),
        serde_json::to_value(&cycle_result).test_value("cycle result JSON"),
    ] {
        assert!(validator.is_valid(&value), "schema rejected {value}");
    }

    let mut unknown = serde_json::to_value(&trigger).test_value("trigger JSON");
    unknown
        .as_object_mut()
        .test_value("object")
        .insert("raw_ui_text".to_owned(), serde_json::json!("untrusted"));
    assert!(!validator.is_valid(&unknown));
}
