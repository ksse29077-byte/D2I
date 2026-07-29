use d2i_goal_compiler::{
    ClarificationReasonCode, ComparisonOp, ConfirmationPolicy, GoalCompilationInput,
    GoalCompilationResult, GoalCompiler, GoalReplayContext, MissingField, Postcondition,
    TrustLabel,
};
use d2i_module_sdk::{canonical_sha256, InvocationContext, Module, ModuleErrorCode};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("test operation failed: {error:?}"),
    }
}

fn criterion() -> Postcondition {
    Postcondition {
        target_state: "course.status".to_owned(),
        op: ComparisonOp::Equals,
        expected_value: json!("complete"),
        required: true,
        timeout_ms: 1_000,
    }
}

fn input(instruction: &str) -> GoalCompilationInput {
    let mut value = GoalCompilationInput {
        schema_version: 1,
        instruction: instruction.to_owned(),
        locale: "ko-KR".to_owned(),
        source_id: "user-request-1".to_owned(),
        source_hash: format!("sha256:{}", "0".repeat(64)),
        scope_hints: BTreeMap::new(),
        explicit_constraints: Vec::new(),
        success_criteria: vec![criterion()],
        confirmation_policy: None,
        trust_labels: BTreeSet::from([TrustLabel::AuthenticatedUserInstruction]),
        replay_context: GoalReplayContext {
            replay_id: "goal-replay-1".to_owned(),
            seed: 1,
        },
    };
    value.source_hash = ok(value.compute_source_hash());
    value
}

fn context(input: &GoalCompilationInput) -> InvocationContext {
    InvocationContext {
        current_logical_tick: 1,
        current_observation_hash: None,
        current_plan_generation_id: None,
        allowed_trust_labels: BTreeSet::from(["authenticated_user_instruction".to_owned()]),
        invocation_trust_labels: input
            .trust_labels
            .iter()
            .map(|label| match label {
                TrustLabel::AuthenticatedUserInstruction => {
                    "authenticated_user_instruction".to_owned()
                }
                TrustLabel::ApprovedPolicy => "approved_policy".to_owned(),
                TrustLabel::ApprovedProcedure => "approved_procedure".to_owned(),
                TrustLabel::VerifiedOperationalState => "verified_operational_state".to_owned(),
                TrustLabel::ObservedUiState => "observed_ui_state".to_owned(),
                TrustLabel::UntrustedWebContent => "untrusted_web_content".to_owned(),
                TrustLabel::UntrustedDocumentContent => "untrusted_document_content".to_owned(),
                TrustLabel::Fixture => "fixture".to_owned(),
            })
            .collect(),
    }
}

fn run(input: GoalCompilationInput) -> GoalCompilationResult {
    let context = context(&input);
    ok(GoalCompiler.validate_input(&input, &context));
    ok(GoalCompiler.invoke(input, &context)).value
}

#[test]
fn explicit_read_only_instruction_compiles_complete_core_goal() {
    let result = run(input(
        "목표: 교육 현황을 조회\n범위: 2026년 교육 포털\n결과: 수료 상태 목록\n제약: 읽기 전용",
    ));
    let GoalCompilationResult::Compiled { goal_spec } = result else {
        panic!("expected compiled result");
    };
    assert_eq!(goal_spec.objective, "교육 현황을 조회");
    assert_eq!(
        goal_spec.risk_class,
        d2i_goal_compiler::CognitiveRiskClass::ReadOnly
    );
    assert_eq!(goal_spec.confirmation_policy, ConfirmationPolicy::Never);
    assert_eq!(goal_spec.required_outcomes, vec!["수료 상태 목록"]);
    assert_eq!(goal_spec.success_criteria, vec![criterion()]);
    assert!(goal_spec.goal_id.starts_with("goal-"));

    let serialized = ok(serde_json::to_value(&goal_spec));
    let core: d2i_desktop::GoalSpec = ok(serde_json::from_value(serialized));
    ok(core.validate());
}

#[test]
fn risky_goal_requires_approval_and_compiles_when_explicit() {
    let instruction = "목표: 신청서를 제출\n범위: 교육 포털\n결과: 제출 완료";
    let clarification = run(input(instruction));
    let GoalCompilationResult::ClarificationRequired {
        missing_fields,
        reason_codes,
        ..
    } = clarification
    else {
        panic!("expected clarification");
    };
    assert!(missing_fields.contains(&MissingField::ApprovalCondition));
    assert!(reason_codes.contains(&ClarificationReasonCode::RiskyActionRequiresApproval));

    let mut approved = input(instruction);
    approved.confirmation_policy = Some(ConfirmationPolicy::BeforeRiskyAction);
    let GoalCompilationResult::Compiled { goal_spec } = run(approved) else {
        panic!("expected approved compilation");
    };
    assert_eq!(
        goal_spec.risk_class,
        d2i_goal_compiler::CognitiveRiskClass::BusinessStateChange
    );
}

#[test]
fn missing_fields_are_typed_successful_clarification() {
    let mut value = input("목표: 교육 현황을 조회");
    value.success_criteria.clear();
    let result = run(value);
    let GoalCompilationResult::ClarificationRequired {
        missing_fields,
        questions,
        reason_codes,
        ..
    } = result
    else {
        panic!("expected clarification");
    };
    assert_eq!(
        missing_fields,
        vec![
            MissingField::Scope,
            MissingField::RequiredOutcomes,
            MissingField::SuccessCriteria
        ]
    );
    assert!(!questions.is_empty());
    assert_eq!(
        reason_codes,
        vec![ClarificationReasonCode::MissingRequiredField]
    );
}

#[test]
fn multiple_goals_conflicts_and_free_success_text_do_not_compile() {
    let mut value = input(
        "목표: 현황을 조회\n목표: 결과를 비교\n범위: 포털\n결과: 목록\n제약: 저장\n제약: 저장 금지\n성공조건: 화면에 완료가 보임",
    );
    value.success_criteria.clear();
    let GoalCompilationResult::ClarificationRequired {
        ambiguities,
        reason_codes,
        ..
    } = run(value)
    else {
        panic!("expected clarification");
    };
    assert_eq!(ambiguities.len(), 3);
    assert!(reason_codes.contains(&ClarificationReasonCode::MultipleObjectives));
    assert!(reason_codes.contains(&ClarificationReasonCode::ConflictingConstraints));
    assert!(reason_codes.contains(&ClarificationReasonCode::StructuredSuccessCriterionRequired));
}

#[test]
fn unsupported_locale_grammar_and_operation_use_outer_unsupported_error() {
    let mut locale = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    locale.locale = "en-US".to_owned();
    locale.source_hash = ok(locale.compute_source_hash());
    assert_eq!(
        GoalCompiler
            .invoke(locale.clone(), &context(&locale))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::UnsupportedInput)
    );

    let grammar = input("교육 현황을 알아봐 주세요");
    assert_eq!(
        GoalCompiler
            .invoke(grammar.clone(), &context(&grammar))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::UnsupportedInput)
    );

    let operation = input("목표: 새로운 교육을 기획\n범위: 포털\n결과: 계획");
    assert_eq!(
        GoalCompiler
            .invoke(operation.clone(), &context(&operation))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::UnsupportedInput)
    );
}

#[test]
fn stale_source_untrusted_authority_and_secret_fields_fail_closed() {
    let mut stale = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    stale.source_hash = format!("sha256:{}", "f".repeat(64));
    assert_eq!(
        GoalCompiler
            .validate_input(&stale, &context(&stale))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::DeterministicReplayMismatch)
    );

    let mut untrusted = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    untrusted.trust_labels = BTreeSet::from([TrustLabel::UntrustedWebContent]);
    assert_eq!(
        GoalCompiler
            .validate_input(&untrusted, &context(&untrusted))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::UntrustedInputViolation)
    );

    let mut secret = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    secret
        .scope_hints
        .insert("api_token".to_owned(), json!("must-not-leak"));
    assert_eq!(
        GoalCompiler
            .validate_input(&secret, &context(&secret))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::InvalidInput)
    );
}

#[test]
fn replay_goal_id_and_output_hash_are_stable() {
    let value = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    let first = run(value.clone());
    let second = run(value);
    assert_eq!(first, second);
    assert_eq!(ok(canonical_sha256(&first)), ok(canonical_sha256(&second)));
}

#[test]
fn unknown_fields_wrong_version_oversize_and_depth_are_rejected() {
    let base = input("목표: 현황을 조회\n범위: 포털\n결과: 목록");
    let mut json_value = ok(serde_json::to_value(&base));
    json_value["unknown"] = Value::Bool(true);
    assert!(serde_json::from_value::<GoalCompilationInput>(json_value).is_err());

    let mut version = base.clone();
    version.schema_version = 2;
    assert_eq!(
        GoalCompiler
            .validate_input(&version, &context(&version))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ContractVersionMismatch)
    );

    let mut oversized = base.clone();
    oversized.instruction = "가".repeat(4_097);
    assert_eq!(
        GoalCompiler
            .validate_input(&oversized, &context(&oversized))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::InvalidInput)
    );

    let mut deep_value = Value::Null;
    for _ in 0..34 {
        deep_value = json!([deep_value]);
    }
    let mut deep = base;
    deep.scope_hints.insert("nested".to_owned(), deep_value);
    assert_eq!(
        GoalCompiler
            .validate_input(&deep, &context(&deep))
            .err()
            .map(|error| error.code),
        Some(ModuleErrorCode::ResourceExhausted)
    );
}
