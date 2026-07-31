#![cfg(windows)]

use d2i_desktop::*;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn ok<T, E: std::fmt::Display>(result: Result<T, E>) -> T {
    result.unwrap_or_else(|error| panic!("{error}"))
}

fn hash(seed: char) -> String {
    format!("sha256:{}", seed.to_string().repeat(64))
}

fn unique_root(label: &str) -> std::path::PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!("d2i-recovery-{label}-{}-{now}", std::process::id()))
}

struct Roots {
    base: std::path::PathBuf,
    ledger: std::path::PathBuf,
    audit: std::path::PathBuf,
}

impl Roots {
    fn new(label: &str) -> Self {
        let base = unique_root(label);
        ok(std::fs::create_dir(&base));
        Self {
            ledger: base.join("ledger"),
            audit: base.join("audit"),
            base,
        }
    }
}

impl Drop for Roots {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn budget() -> RecoveryBudgetV1 {
    ok(RecoveryBudgetV1 {
        schema_version: 1,
        budget_id: "budget-1".to_owned(),
        goal_id: "goal-1".to_owned(),
        maximum_total_cycles: 6,
        remaining_total_cycles: 6,
        maximum_reobservations: 2,
        remaining_reobservations: 2,
        maximum_fresh_retries: 2,
        remaining_fresh_retries: 2,
        maximum_alternate_capability_attempts: 1,
        remaining_alternate_capability_attempts: 1,
        maximum_replans: 1,
        remaining_replans: 1,
        maximum_clarifications: 1,
        remaining_clarifications: 1,
        started_at_unix_ms: 900,
        deadline_unix_ms: 20_000,
        evidence_ids: vec!["bounded-policy".to_owned()],
        budget_sha256: hash('0'),
    }
    .seal())
}

fn history() -> RecoveryHistoryV1 {
    ok(RecoveryHistoryV1::empty(
        "history-1".to_owned(),
        "goal-1".to_owned(),
    ))
}

fn profile() -> RecoveryPolicyProfileV1 {
    ok(RecoveryPolicyProfileV1 {
        schema_version: 1,
        profile_id: "profile-1".to_owned(),
        policy_set_sha256: hash('a'),
        authority_sha256: hash('b'),
        retryable_failure_classes: vec![
            RecoveryFailureClassV1::ExecutionFailed,
            RecoveryFailureClassV1::ExpectedChangeMissing,
        ],
        reobservable_failure_classes: vec![
            RecoveryFailureClassV1::AmbiguousTarget,
            RecoveryFailureClassV1::StaleBinding,
            RecoveryFailureClassV1::VerificationInconclusive,
        ],
        alternate_capability_failure_classes: vec![RecoveryFailureClassV1::ExecutionFailed],
        replannable_failure_classes: vec![RecoveryFailureClassV1::NoCandidate],
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
            group_id: "fixture".to_owned(),
            capability_ids: vec!["cap.alternate".to_owned(), "cap.primary".to_owned()],
        }],
        maximum_same_capability_attempts: 2,
        allow_replan: true,
        allow_clarification: true,
        escalation_risk_threshold: CognitiveRiskClass::HighCriticality,
        evidence_ids: vec!["trusted-recovery-policy".to_owned()],
        profile_sha256: hash('0'),
    }
    .seal())
}

fn trigger(reason: RecoveryReasonCodeV1) -> RecoveryTriggerV1 {
    ok(RecoveryTriggerV1 {
        schema_version: 1,
        trigger_id: "trigger-1".to_owned(),
        stage: RecoveryStageV1::Verification,
        goal_id: "goal-1".to_owned(),
        plan_generation_id: Some("plan-1".to_owned()),
        proposal_id: Some("proposal-1".to_owned()),
        proposal_sha256: Some(hash('1')),
        capability_id: Some("cap.primary".to_owned()),
        source_observation_id: "observation-1".to_owned(),
        source_observation_hash: hash('2'),
        source_observation_sequence: 1,
        fresh_observation_id: Some("observation-2".to_owned()),
        fresh_observation_hash: Some(hash('3')),
        fresh_observation_sequence: Some(2),
        execution_receipt_sha256: Some(hash('4')),
        verified_action_result_sha256: Some(hash('5')),
        policy_decision_sha256: Some(hash('6')),
        activation_admission_sha256: Some(hash('7')),
        reason_codes: vec![reason],
        evidence_ids: vec!["verification-evidence".to_owned()],
        detected_at_unix_ms: 1_000,
        trigger_sha256: hash('0'),
    }
    .seal())
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

fn coordinator(roots: &Roots) -> CognitiveRecoveryCoordinatorV1 {
    let ledger = ok(initialize_recovery_ledger(
        &roots.ledger,
        "ledger-1",
        "session-1",
        "goal-1",
        64,
        900,
    ));
    let audit = ok(initialize_windows_deployment_audit(
        &roots.audit,
        "audit-1",
        "session-1",
        128,
        900,
    ));
    ok(CognitiveRecoveryCoordinatorV1::restore(
        "goal-1".to_owned(),
        "plan-1".to_owned(),
        budget(),
        history(),
        profile(),
        ledger,
        audit,
    ))
}

fn begin_retry(coordinator: &mut CognitiveRecoveryCoordinatorV1) -> RecoveryDecisionV1 {
    ok(coordinator.begin(trigger(RecoveryReasonCodeV1::ExecutionFailed), 1_010));
    ok(coordinator.classify(1_020));
    ok(coordinator.decide(&context(), 1_030)).clone()
}

fn request(
    decision: &RecoveryDecisionV1,
    history: &RecoveryHistoryV1,
) -> FreshRecoveryCycleRequestV1 {
    ok(FreshRecoveryCycleRequestV1::from_decision(
        "cycle-2".to_owned(),
        decision,
        "goal-1".to_owned(),
        "plan-1".to_owned(),
        Some(hash('1')),
        Some("cap.primary".to_owned()),
        "observation-2".to_owned(),
        hash('3'),
        2,
        history,
        hash('b'),
        hash('a'),
        1_040,
        2_000,
        vec!["fresh-retry".to_owned()],
    ))
}

fn fresh_evidence(request: &FreshRecoveryCycleRequestV1) -> FreshRecoveryCycleEvidenceV1 {
    FreshRecoveryCycleEvidenceV1 {
        schema_version: 1,
        cycle_request_sha256: request.cycle_request_sha256.clone(),
        observation_id: "observation-3".to_owned(),
        observation_hash: hash('8'),
        observation_sequence: 3,
        plan_generation_id: "plan-1".to_owned(),
        proposal_id: "proposal-2".to_owned(),
        proposal_sha256: hash('9'),
        capability_id: "cap.primary".to_owned(),
        input_sha256: hash('a'),
        policy_decision_sha256: hash('b'),
        cognitive_admission_sha256: hash('c'),
        activation_record_hash: hash('d'),
        execution_receipt_sha256: hash('e'),
        verified_action_result_sha256: hash('f'),
        verification_verdict: RecoveryVerificationVerdictV1::Passed,
    }
}

#[test]
fn durable_fresh_cycle_replaces_every_one_shot_identity_and_restores() {
    let roots = Roots::new("fresh");
    let mut coordinator = coordinator(&roots);
    let decision = begin_retry(&mut coordinator);
    assert_eq!(
        decision.decision_kind,
        RecoveryDecisionKindV1::RetryFreshCycle
    );
    assert_eq!(coordinator.budget().remaining_fresh_retries, 1);
    let request = request(&decision, coordinator.history());
    let result =
        ok(coordinator.execute_fresh_cycle(&request, 1_050, || Ok(fresh_evidence(&request))));
    assert_eq!(result.outcome, RecoveryCycleOutcomeV1::Recovered);
    assert_ne!(result.new_proposal_sha256, Some(hash('1')));
    assert_ne!(result.new_admission_sha256, Some(hash('7')));
    assert_ne!(result.new_activation_record_hash, Some(hash('7')));
    assert_ne!(result.new_execution_receipt_sha256, Some(hash('4')));
    assert_eq!(coordinator.history().entries.len(), 1);
    assert_eq!(
        coordinator.state(),
        CognitiveRecoveryCoordinatorStateV1::NextCycle
    );
    drop(coordinator);

    let restored = ok(verify_recovery_ledger(&roots.ledger));
    assert_eq!(restored.record_count, 5);
    assert_eq!(restored.latest_budget, Some(decision.budget_after));
    assert_eq!(
        restored
            .latest_history
            .as_ref()
            .map(|value| value.entries.len()),
        Some(1)
    );
    assert_eq!(
        ok(verify_windows_deployment_audit(&roots.audit)).record_count,
        5
    );
    ok(RecoveryLedgerV1::open(&roots.ledger));
}

#[test]
fn unsafe_trigger_escalates_without_invoking_a_second_mutation() {
    let roots = Roots::new("unsafe");
    let mut coordinator = coordinator(&roots);
    ok(coordinator.begin(trigger(RecoveryReasonCodeV1::UnsafeSideEffect), 1_010));
    ok(coordinator.classify(1_020));
    let decision = ok(coordinator.decide(&context(), 1_030)).clone();
    assert_eq!(decision.decision_kind, RecoveryDecisionKindV1::Escalate);
    let second_mutation = AtomicBool::new(false);
    let escalation = ok(EscalationRequestV1 {
        schema_version: 1,
        escalation_id: "escalation-1".to_owned(),
        recovery_decision_sha256: decision.decision_sha256,
        goal_id: "goal-1".to_owned(),
        severity: EscalationSeverityV1::High,
        reason_codes: vec![RecoveryReasonCodeV1::UnsafeSideEffect],
        originating_stage: RecoveryStageV1::Verification,
        required_authority_class: RequiredAuthorityClassV1::SecurityOwner,
        blocked_capability_ids: vec!["cap.primary".to_owned()],
        policy_set_sha256: hash('a'),
        authority_sha256: hash('b'),
        latest_observation_hash: hash('3'),
        verified_action_result_sha256: Some(hash('5')),
        protected_violation_count: 1,
        unexpected_change_count: 1,
        safe_state_summary_codes: vec![SafeStateSummaryCodeV1::AutomaticMutationBlocked],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::InspectProtectedEvidence],
        evidence_ids: vec!["unsafe-verification".to_owned()],
        raised_at_unix_ms: 1_040,
        escalation_sha256: hash('0'),
    }
    .seal());
    let result = ok(coordinator.escalate(&escalation, 1_040));
    assert_eq!(result.outcome, RecoveryCycleOutcomeV1::Escalated);
    assert!(!second_mutation.load(Ordering::SeqCst));
    assert_eq!(
        coordinator.state(),
        CognitiveRecoveryCoordinatorStateV1::Terminal
    );
}

#[test]
fn clarification_is_deterministic_typed_and_one_shot() {
    let roots = Roots::new("clarification");
    let mut coordinator = coordinator(&roots);
    ok(coordinator.begin(trigger(RecoveryReasonCodeV1::AmbiguousTarget), 1_010));
    ok(coordinator.classify(1_020));
    let mut decision_context = context();
    decision_context.same_failure_count = 1;
    decision_context.bounded_user_fact_missing = true;
    let decision = ok(coordinator.decide(&decision_context, 1_030)).clone();
    assert_eq!(
        decision.decision_kind,
        RecoveryDecisionKindV1::RequestClarification
    );
    let fixture = ClarificationRequestV1 {
        schema_version: 1,
        clarification_id: "clarification-1".to_owned(),
        recovery_decision_sha256: decision.decision_sha256,
        goal_id: "goal-1".to_owned(),
        question_code: ClarificationQuestionCodeV1::ChooseSemanticTarget,
        question_kind: ClarificationQuestionKindV1::ChooseOne,
        prompt_template_id: "choose-semantic-target-v1".to_owned(),
        allowed_options: vec!["target-a".to_owned(), "target-b".to_owned()],
        value_schema_id: "semantic-target-id-v1".to_owned(),
        maximum_text_bytes: 128,
        sensitive_input_allowed: false,
        blocks_capability_ids: vec!["cap.primary".to_owned()],
        requested_at_unix_ms: 1_040,
        expires_at_unix_ms: 2_000,
        evidence_ids: vec!["bounded-ambiguity".to_owned()],
        request_sha256: hash('0'),
    };
    let first = ok(fixture.clone().seal());
    let second = ok(fixture.seal());
    assert_eq!(first.request_sha256, second.request_sha256);
    ok(coordinator.request_clarification(first.clone(), 1_040));
    let response = ok(ClarificationResponseV1 {
        schema_version: 1,
        response_id: "response-1".to_owned(),
        clarification_request_sha256: first.request_sha256,
        goal_id: "goal-1".to_owned(),
        authenticated_instruction_provenance_sha256: hash('f'),
        answer: ClarificationAnswerV1::ChooseOne("target-a".to_owned()),
        responded_at_unix_ms: 1_050,
        response_sha256: hash('0'),
    }
    .seal(&second));
    ok(coordinator.consume_clarification(&response, 1_060));
    assert!(coordinator.consume_clarification(&response, 1_070).is_err());
}

#[test]
fn audit_failure_prevents_fresh_cycle_execution() {
    let roots = Roots::new("audit-failure");
    let mut coordinator = coordinator(&roots);
    let decision = begin_retry(&mut coordinator);
    let request = request(&decision, coordinator.history());
    let records = roots.audit.join("windows-deployment-audit-records.jsonl");
    let mut file = ok(OpenOptions::new().append(true).open(records));
    ok(file.write_all(b"not-json\n"));
    ok(file.sync_all());
    let invoked = AtomicBool::new(false);
    assert!(coordinator
        .execute_fresh_cycle(&request, 1_050, || {
            invoked.store(true, Ordering::SeqCst);
            Ok(fresh_evidence(&request))
        })
        .is_err());
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn ledger_failure_prevents_fresh_cycle_execution() {
    let roots = Roots::new("ledger-failure");
    let mut coordinator = coordinator(&roots);
    let decision = begin_retry(&mut coordinator);
    let request = request(&decision, coordinator.history());
    ok(std::fs::write(
        roots.ledger.join("cognitive-recovery-ledger-state.json"),
        b"{}",
    ));
    let invoked = AtomicBool::new(false);
    assert!(coordinator
        .execute_fresh_cycle(&request, 1_050, || {
            invoked.store(true, Ordering::SeqCst);
            Ok(fresh_evidence(&request))
        })
        .is_err());
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn recovery_ledger_detects_state_tampering() {
    let roots = Roots::new("tamper");
    let mut coordinator = coordinator(&roots);
    let _ = begin_retry(&mut coordinator);
    std::mem::forget(coordinator);
    let path = roots.ledger.join("cognitive-recovery-ledger-state.json");
    let mut bytes = ok(std::fs::read(&path));
    let byte = bytes
        .iter_mut()
        .find(|value| **value == b'r')
        .unwrap_or_else(|| panic!("fixture state has no mutable byte"));
    *byte = b's';
    ok(std::fs::write(path, bytes));
    assert!(verify_recovery_ledger(&roots.ledger).is_err());
}

#[test]
fn reobserve_records_only_a_newer_read_only_observation() {
    let roots = Roots::new("reobserve");
    let mut coordinator = coordinator(&roots);
    ok(coordinator.begin(trigger(RecoveryReasonCodeV1::StaleBinding), 1_010));
    ok(coordinator.classify(1_020));
    let decision = ok(coordinator.decide(&context(), 1_030)).clone();
    assert_eq!(decision.decision_kind, RecoveryDecisionKindV1::Reobserve);
    let fresh = ok(coordinator.execute_reobservation(1_040, || {
        Ok(ok(RecoveryTriggerV1 {
            schema_version: 1,
            trigger_id: "trigger-reobserved".to_owned(),
            stage: RecoveryStageV1::Observation,
            goal_id: "goal-1".to_owned(),
            plan_generation_id: None,
            proposal_id: None,
            proposal_sha256: None,
            capability_id: None,
            source_observation_id: "observation-3".to_owned(),
            source_observation_hash: hash('8'),
            source_observation_sequence: 3,
            fresh_observation_id: None,
            fresh_observation_hash: None,
            fresh_observation_sequence: None,
            execution_receipt_sha256: None,
            verified_action_result_sha256: None,
            policy_decision_sha256: None,
            activation_admission_sha256: None,
            reason_codes: vec![RecoveryReasonCodeV1::ObservationUnavailable],
            evidence_ids: vec!["fresh-read-only-observation".to_owned()],
            detected_at_unix_ms: 1_041,
            trigger_sha256: hash('0'),
        }
        .seal()))
    }));
    assert_eq!(fresh.source_observation_sequence, 3);
    assert_eq!(coordinator.history().entries.len(), 1);
    assert_eq!(coordinator.budget().remaining_reobservations, 1);
    assert_eq!(
        coordinator.state(),
        CognitiveRecoveryCoordinatorStateV1::NextCycle
    );
}

#[test]
fn passed_complete_finishes_without_creating_execution_material() {
    let roots = Roots::new("complete");
    let mut coordinator = coordinator(&roots);
    ok(coordinator.begin(trigger(RecoveryReasonCodeV1::NoFailure), 1_010));
    ok(coordinator.classify(1_020));
    let mut passed = context();
    passed.verification_verdict = Some(RecoveryVerificationVerdictV1::Passed);
    passed.goal_progress = GoalProgress::Complete;
    let decision = ok(coordinator.decide(&passed, 1_030)).clone();
    assert_eq!(
        decision.decision_kind,
        RecoveryDecisionKindV1::NoRecoveryComplete
    );
    let result = ok(coordinator.finish_without_mutation(Some(hash('f')), 1_040));
    assert_eq!(result.outcome, RecoveryCycleOutcomeV1::Completed);
    assert!(result.new_proposal_sha256.is_none());
    assert!(result.new_activation_record_hash.is_none());
    assert_eq!(
        coordinator.state(),
        CognitiveRecoveryCoordinatorStateV1::Terminal
    );
}

#[test]
fn crash_after_decision_restores_consumed_budget_and_rejects_the_old_trigger() {
    let roots = Roots::new("crash-restore");
    let mut coordinator = coordinator(&roots);
    let old_trigger = trigger(RecoveryReasonCodeV1::ExecutionFailed);
    ok(coordinator.begin(old_trigger.clone(), 1_010));
    ok(coordinator.classify(1_020));
    let decision = ok(coordinator.decide(&context(), 1_030)).clone();
    let durable_budget = decision.budget_after.clone();
    assert_eq!(durable_budget.remaining_fresh_retries, 1);
    std::mem::forget(coordinator);

    let ledger = ok(RecoveryLedgerV1::open(&roots.ledger));
    assert_eq!(
        ledger.verification().latest_budget,
        Some(durable_budget.clone())
    );
    let audit = ok(WindowsDeploymentAuditLedger::open(&roots.audit));
    let mut restored = ok(CognitiveRecoveryCoordinatorV1::restore(
        "goal-1".to_owned(),
        "plan-1".to_owned(),
        durable_budget,
        history(),
        profile(),
        ledger,
        audit,
    ));
    assert!(restored.begin(old_trigger, 1_040).is_err());

    let mut fresh_trigger = trigger(RecoveryReasonCodeV1::ExecutionFailed);
    fresh_trigger.trigger_id = "trigger-after-crash".to_owned();
    fresh_trigger.source_observation_id = "observation-3".to_owned();
    fresh_trigger.source_observation_hash = hash('8');
    fresh_trigger.source_observation_sequence = 3;
    fresh_trigger.fresh_observation_id = Some("observation-4".to_owned());
    fresh_trigger.fresh_observation_hash = Some(hash('9'));
    fresh_trigger.fresh_observation_sequence = Some(4);
    fresh_trigger.proposal_id = Some("proposal-2".to_owned());
    fresh_trigger.proposal_sha256 = Some(hash('a'));
    fresh_trigger.execution_receipt_sha256 = Some(hash('b'));
    fresh_trigger.verified_action_result_sha256 = Some(hash('c'));
    fresh_trigger.policy_decision_sha256 = Some(hash('d'));
    fresh_trigger.activation_admission_sha256 = Some(hash('e'));
    fresh_trigger.detected_at_unix_ms = 1_040;
    fresh_trigger = ok(fresh_trigger.seal());
    ok(restored.begin(fresh_trigger, 1_040));
    assert_eq!(restored.budget().remaining_fresh_retries, 1);
}
