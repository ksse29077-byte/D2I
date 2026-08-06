use super::*;
use d2i_role_contract::{compile_role_source, KpiDirectionV1, RoleCompileFormatV1, RoleContractV1};
use d2i_work_case::{CaseSlaBindingV1, WorkPriorityClassV1};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeSet, HashSet};

const ROLE_SOURCE: &str = include_str!(
    "../../../examples/workforce/general-office-operations-employee-operations-v1/role.yaml"
);

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn assert_schema_roundtrip<T>(value: &T, schema: &str)
where
    T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let bytes = ok(canonical_json_bytes(value));
    let roundtrip: T = ok(parse_json_strict(&bytes));
    assert_eq!(&roundtrip, value);
    let schema_value: serde_json::Value = ok(serde_json::from_str(schema));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_value));
    assert!(compiled.is_valid(&ok(serde_json::to_value(value))));
}

fn role() -> RoleContractV1 {
    ok(compile_role_source(
        ROLE_SOURCE.as_bytes(),
        RoleCompileFormatV1::Yaml,
    ))
    .contract
}

fn formula(metric_id: &str) -> KpiFormulaKindV1 {
    match metric_id {
        "escalation_rate" => KpiFormulaKindV1::EscalationRate,
        "human_touches_per_case" => KpiFormulaKindV1::HumanTouchesPerCase,
        "sla_compliance_rate" => KpiFormulaKindV1::SlaComplianceRate,
        "verified_closure_rate" => KpiFormulaKindV1::VerifiedClosureRate,
        other => panic!("unexpected General Office metric: {other}"),
    }
}

fn operations_profile(contract: &RoleContractV1) -> RoleOperationsProfileV1 {
    let mut bindings = contract
        .kpi_definitions
        .iter()
        .filter(|definition| definition.enabled)
        .map(|definition| {
            ok(KpiMetricBindingV1 {
                schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
                kpi_id: definition.kpi_id.clone(),
                metric_id: definition.metric_id.clone(),
                formula_kind: formula(&definition.metric_id),
                unit: "millionths".to_owned(),
                direction: definition.direction,
                target_millionths: definition.target_millionths,
                target_integer: definition.target_integer,
                warning_threshold: definition.warning_threshold,
                breach_behavior: definition.breach_behavior,
                required_evidence_class_ids: definition.evidence_class_ids.clone(),
                binding_sha256: ZERO_HASH.to_owned(),
            }
            .seal())
        })
        .collect::<Vec<_>>();
    bindings.sort_by(|left, right| left.kpi_id.cmp(&right.kpi_id));

    let mut routes = contract
        .reporting_obligations
        .iter()
        .filter(|obligation| obligation.enabled)
        .map(|obligation| obligation.routing_class_id.clone())
        .chain(
            contract
                .escalation_policy
                .routing_class_by_severity
                .values()
                .cloned(),
        )
        .chain([
            contract
                .escalation_policy
                .authority_exceeded_route_class
                .clone(),
            contract.escalation_policy.unsafe_route_class.clone(),
            contract.escalation_policy.legal_review_route_class.clone(),
            contract
                .escalation_policy
                .policy_conflict_route_class
                .clone(),
        ])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    routes.sort();
    let internal_route_bindings = routes
        .iter()
        .map(|route| InternalRouteBindingV1 {
            routing_class_id: route.clone(),
            internal_inbox_id: format!("protected-inbox-{route}"),
        })
        .collect();
    let milestone_mapping = ok(SlaMilestoneMappingV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        received_source: SlaMilestoneSourceV1::WorkItemReceived,
        acknowledged_source: SlaMilestoneSourceV1::FirstExclusiveLeaseClaim,
        begun_source: SlaMilestoneSourceV1::FirstPlannerStepAdmitted,
        resolved_source: SlaMilestoneSourceV1::TerminalCaseTimestamp,
        escalated_source: SlaMilestoneSourceV1::DurableEscalationItem,
        mapping_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let pause_binding = ok(SlaPauseConditionBindingV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        pause_condition_id: "awaiting-approved-reference".to_owned(),
        allowed_source_event_classes: vec!["approved-reference-awaiting".to_owned()],
        allowed_case_block_classes: vec!["awaiting-approved-reference".to_owned()],
        allowed_clarification_reason_codes: vec!["approved-reference-missing".to_owned()],
        required_evidence_class_ids: vec!["approved-pause-evidence".to_owned()],
        maximum_single_pause_seconds: 3_600,
        maximum_cumulative_pause_seconds: 7_200,
        automatic_pause_allowed: false,
        approval_required: true,
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let profile = ok(RoleOperationsProfileV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        profile_id: "general-office-operations-profile-v1".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_id: contract.role_contract_id.clone(),
        role_contract_version: contract.role_version.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        role_instance_scope: vec!["general-office-operations-instance-v1".to_owned()],
        delegation_sha256: digest('d'),
        policy_set_sha256: contract.policy_set_sha256.clone(),
        working_calendar_sha256: contract.working_calendar.calendar_sha256.clone(),
        kpi_metric_bindings: bindings,
        measurement_window_profiles: vec![MeasurementWindowProfileV1 {
            measurement_window_profile_id: "fixture-run".to_owned(),
            role_measurement_window_id: "general-office-fixture-window".to_owned(),
            maximum_window_seconds: 100_000,
        }],
        sla_milestone_mapping: milestone_mapping,
        sla_pause_condition_bindings: vec![pause_binding],
        report_frequency_profile_ids: vec!["fixture-run".to_owned()],
        routing_class_allowlist: routes,
        internal_route_bindings,
        warning_remaining_millionths: 200_000,
        critical_remaining_seconds: 300,
        maximum_cases_per_cycle: 128,
        maximum_reports_per_cycle: 128,
        maximum_escalations_per_cycle: 128,
        maximum_report_bytes: 1_048_576,
        maximum_store_bytes: 33_554_432,
        maximum_pending_escalation_seconds: 86_400,
        maximum_resolution_seconds: 86_400,
        logical_operation_budget: 1_000_000,
        evidence_ids: vec!["approved-role-operations-profile".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_profile_against_role(
        &profile,
        contract,
        &digest('d'),
    ));
    profile
}

fn trusted_time(now: u64, tick: u64) -> TrustedRoleOperationsTimeContextV1 {
    ok(TrustedRoleOperationsTimeContextV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        context_id: format!("trusted-time-{tick}"),
        trusted_now_unix_seconds: now,
        timezone_id: "Asia/Seoul".to_owned(),
        timezone_projection_sha256: digest('a'),
        operational_date_id: "2026-08-06".to_owned(),
        window_start_unix_seconds: 1,
        window_end_unix_seconds: 200_000,
        tick_sequence: tick,
        prior_tick_sha256: None,
        caller_trust_class: "protected-desktop-runtime".to_owned(),
        evidence_ids: vec!["trusted-caller-time".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn measurement_window(time: &TrustedRoleOperationsTimeContextV1) -> RoleMeasurementWindowV1 {
    ok(RoleMeasurementWindowV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        window_id: "general-office-fixture-window".to_owned(),
        measurement_window_profile_id: "fixture-run".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_sha256: role().contract_sha256,
        start_unix_seconds: 100,
        end_unix_seconds: 100_000,
        timezone_projection_sha256: time.timezone_projection_sha256.clone(),
        status: MeasurementWindowStatusV1::Closed,
        source_tick_sha256: time.context_sha256.clone(),
        previous_window_sha256: None,
        window_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn milestone(
    case_id: &str,
    binding: &CaseSlaBindingV1,
    milestone: SlaMilestoneV1,
    source: SlaMilestoneSourceV1,
    occurred_at: u64,
) -> SlaMilestoneEventV1 {
    ok(SlaMilestoneEventV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        event_id: format!("event-{case_id}-{milestone:?}").to_ascii_lowercase(),
        case_id: case_id.to_owned(),
        sla_binding_sha256: binding.binding_sha256.clone(),
        milestone,
        source,
        occurred_at_unix_seconds: occurred_at,
        source_artifact_sha256: digest('a'),
        source_ledger_head_sha256: digest('b'),
        evidence_ids: vec!["authoritative-ledger-event".to_owned()],
        event_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn case_evidence(
    contract: &RoleContractV1,
    case_id: &str,
    resolved_at: Option<u64>,
    pause: bool,
) -> CaseOperationsEvidenceV1 {
    let sla = &contract.sla_profiles[0];
    let binding = ok(CaseSlaBindingV1::create(
        case_id.to_owned(),
        WorkPriorityClassV1::Normal,
        100,
        sla,
        vec!["role-task-admission".to_owned()],
    ));
    let mut events = vec![
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Received,
            SlaMilestoneSourceV1::WorkItemReceived,
            100,
        ),
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Acknowledged,
            SlaMilestoneSourceV1::FirstExclusiveLeaseClaim,
            120,
        ),
        milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Begun,
            SlaMilestoneSourceV1::FirstPlannerStepAdmitted,
            130,
        ),
    ];
    if let Some(resolved_at) = resolved_at {
        events.push(milestone(
            case_id,
            &binding,
            SlaMilestoneV1::Resolved,
            SlaMilestoneSourceV1::TerminalCaseTimestamp,
            resolved_at,
        ));
    }
    let pause_intervals = if pause {
        vec![ok(SlaPauseIntervalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            pause_id: format!("pause-{case_id}-1"),
            case_id: case_id.to_owned(),
            sla_binding_sha256: binding.binding_sha256.clone(),
            pause_condition_id: "awaiting-approved-reference".to_owned(),
            source_event_class_id: "approved-reference-awaiting".to_owned(),
            case_block_class_id: Some("awaiting-approved-reference".to_owned()),
            clarification_reason_code: None,
            started_at_unix_seconds: 200,
            ended_at_unix_seconds: Some(300),
            source_case_state_sha256: digest('c'),
            source_block_or_clarification_sha256: digest('e'),
            approval_sha256: Some(digest('f')),
            evidence_ids: vec!["approved-pause-evidence".to_owned()],
            previous_pause_sha256: None,
            pause_sha256: ZERO_HASH.to_owned(),
        }
        .seal())]
    } else {
        Vec::new()
    };
    CaseOperationsEvidenceV1 {
        case_id: case_id.to_owned(),
        case_contract_sha256: digest('1'),
        current_case_instance_sha256: digest('2'),
        role_contract_sha256: contract.contract_sha256.clone(),
        role_instance_id: "general-office-operations-instance-v1".to_owned(),
        sla_binding: binding,
        milestone_events: events,
        pause_intervals,
        terminal_outcome: resolved_at.map(|_| "verified_complete".to_owned()),
        blocked: false,
        awaiting_clarification: false,
        awaiting_verification: false,
        escalation_pending: resolved_at.is_none(),
        verified_complete: resolved_at.is_some(),
        explicit_refusal: false,
        escalated: resolved_at.is_none(),
        autonomous_completion: resolved_at.is_some(),
        clarification_count: 0,
        recovery_attempt_count: 0,
        recovery_success_count: 0,
        unsupported: false,
        terminal_episode_sha256: resolved_at.map(|_| digest('3')),
        case_ledger_head_sha256: digest('4'),
        queue_ledger_head_sha256: digest('5'),
        planner_ledger_head_sha256: digest('6'),
        evidence_class_ids: vec!["authoritative-sla-runtime-state".to_owned()],
    }
}

fn population() -> RoleMetricPopulationV1 {
    RoleMetricPopulationV1 {
        admitted_cases: 5,
        terminal_cases: 4,
        verified_complete_cases: 2,
        explicit_refusal_cases: 1,
        escalated_cases: 2,
        autonomous_completed_cases: 2,
        sla_applicable_cases: 5,
        sla_compliant_cases: 2,
        clarified_cases: 0,
        recovery_attempts: 1,
        recovery_successes: 1,
        unsupported_cases: 0,
        acknowledge_seconds_total: 100,
        acknowledge_duration_count: 5,
        begin_seconds_total: 150,
        begin_duration_count: 5,
        resolve_seconds_total: 300,
        resolve_duration_count: 4,
        human_interaction_count: 2,
        human_interaction_seconds: 180,
        human_duration_covered_count: 2,
        false_completion_review_population: 4,
        false_completion_review_covered: 4,
        false_completion_count: 1,
        missing_evidence_count: 0,
        conflicting_evidence_count: 0,
    }
}

fn metric_binding(formula_kind: KpiFormulaKindV1) -> KpiMetricBindingV1 {
    ok(KpiMetricBindingV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        kpi_id: "fixture-kpi".to_owned(),
        metric_id: "fixture_metric".to_owned(),
        formula_kind,
        unit: "millionths".to_owned(),
        direction: KpiDirectionV1::AtLeast,
        target_millionths: Some(400_000),
        target_integer: None,
        warning_threshold: Some(200_000),
        breach_behavior: d2i_role_contract::KpiBreachBehaviorV1::Report,
        required_evidence_class_ids: vec!["verified-evidence".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn strict_parser_rejects_duplicate_keys_and_floats() {
    let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
    assert!(parse_json_strict::<serde_json::Value>(duplicate).is_err());
    assert!(parse_json_strict::<serde_json::Value>(br#"{"value":1.5}"#).is_err());
}

#[test]
fn canonical_hash_is_key_order_independent() {
    let left = json!({"b": 2, "a": 1});
    let right = json!({"a": 1, "b": 2});
    assert_eq!(ok(canonical_sha256(&left)), ok(canonical_sha256(&right)));
}

#[test]
fn profile_is_an_exact_signed_role_narrowing() {
    let contract = role();
    assert_eq!(contract.role_version, "1.2.0");
    let profile = operations_profile(&contract);
    let key = SigningKey::from_bytes(&[17_u8; 32]);
    let approval = ok(sign_profile_approval(
        RoleOperationsProfileApprovalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            profile_sha256: profile.profile_sha256.clone(),
            organization_id: profile.organization_id.clone(),
            role_contract_sha256: profile.role_contract_sha256.clone(),
            signer_id: "organization-operations-approver".to_owned(),
            signing_key_id: "operations-approval-key-v1".to_owned(),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 1_000,
            nonce: "operations-approval-nonce-1".to_owned(),
            evidence_ids: vec!["organization-operations-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &profile,
        &key,
    ));
    ok(verify_profile_approval(
        &approval,
        &profile,
        "operations-approval-key-v1",
        &key.verifying_key(),
        500,
    ));
    assert_schema_roundtrip(&profile, ROLE_OPERATIONS_PROFILE_V1_SCHEMA);
    assert_schema_roundtrip(&approval, ROLE_OPERATIONS_PROFILE_APPROVAL_V1_SCHEMA);
    let mut expanded = profile.clone();
    expanded.kpi_metric_bindings[0].target_millionths = Some(999_999);
    expanded = ok(expanded.seal());
    assert!(validate_profile_against_role(&expanded, &contract, &digest('d')).is_err());
    assert!(
        verify_profile_approval(&approval, &profile, "wrong-key", &key.verifying_key(), 500)
            .is_err()
    );
}

#[test]
fn trusted_time_rejects_rollback_replay_and_window_overlap() {
    let first = trusted_time(1_000, 1);
    ok(validate_time_context(&first, None));
    let mut second = trusted_time(1_100, 2);
    second.prior_tick_sha256 = Some(first.context_sha256.clone());
    second = ok(second.seal());
    ok(validate_time_context(&second, Some(&first)));
    let mut rollback = second.clone();
    rollback.trusted_now_unix_seconds = 999;
    rollback = ok(rollback.seal());
    assert!(validate_time_context(&rollback, Some(&first)).is_err());
    let window = measurement_window(&first);
    ok(validate_measurement_window(&window, &first, None));
    assert_schema_roundtrip(&first, TRUSTED_ROLE_OPERATIONS_TIME_CONTEXT_V1_SCHEMA);
    assert_schema_roundtrip(&window, ROLE_MEASUREMENT_WINDOW_V1_SCHEMA);
    let mut overlap = window.clone();
    overlap.window_id = "overlapping-window".to_owned();
    overlap.previous_window_sha256 = Some(window.window_sha256.clone());
    overlap = ok(overlap.seal());
    assert!(validate_measurement_window(&overlap, &first, Some(&window)).is_err());
}

#[test]
fn pause_aware_sla_preserves_baseline_and_breaches_exactly_once() {
    let contract = role();
    let profile = operations_profile(&contract);
    let time = trusted_time(90_000, 1);
    let on_time = case_evidence(&contract, "case-a", Some(500), false);
    let state_a = ok(evaluate_case_sla(
        &on_time,
        &contract.sla_profiles[0],
        &profile,
        &time,
        None,
    ));
    assert_eq!(state_a.overall_sla_status, OverallSlaStatusV1::Compliant);
    let paused = case_evidence(&contract, "case-b", Some(86_600), true);
    let state_b = ok(evaluate_case_sla(
        &paused,
        &contract.sla_profiles[0],
        &profile,
        &time,
        None,
    ));
    assert_eq!(state_b.total_approved_pause_seconds, 100);
    assert_eq!(
        state_b.baseline_resolve_due_at_unix_seconds + 100,
        state_b.effective_resolve_due_at_unix_seconds
    );
    assert_eq!(state_b.overall_sla_status, OverallSlaStatusV1::Compliant);

    let overdue = case_evidence(&contract, "case-c", None, false);
    let state_c = ok(evaluate_case_sla(
        &overdue,
        &contract.sla_profiles[0],
        &profile,
        &time,
        None,
    ));
    assert_eq!(state_c.overall_sla_status, OverallSlaStatusV1::Breached);
    let records = ok(detect_sla_breaches(&state_c, &time, &BTreeSet::new()));
    assert!(!records.is_empty());
    assert_schema_roundtrip(
        &profile.sla_milestone_mapping,
        SLA_MILESTONE_MAPPING_V1_SCHEMA,
    );
    assert_schema_roundtrip(
        &profile.sla_pause_condition_bindings[0],
        SLA_PAUSE_CONDITION_BINDING_V1_SCHEMA,
    );
    assert_schema_roundtrip(&on_time.milestone_events[0], SLA_MILESTONE_EVENT_V1_SCHEMA);
    assert_schema_roundtrip(&paused.pause_intervals[0], SLA_PAUSE_INTERVAL_V1_SCHEMA);
    assert_schema_roundtrip(&state_b, CASE_SLA_RUNTIME_STATE_V1_SCHEMA);
    assert_schema_roundtrip(&records[0], SLA_BREACH_RECORD_V1_SCHEMA);
    let existing = records
        .iter()
        .map(|record| {
            (
                record.case_id.clone(),
                record.sla_binding_sha256.clone(),
                record.milestone,
            )
        })
        .collect::<BTreeSet<_>>();
    assert!(ok(detect_sla_breaches(&state_c, &time, &existing)).is_empty());

    let mut unauthorized = paused.clone();
    unauthorized.pause_intervals[0].source_event_class_id = "unapproved-event".to_owned();
    unauthorized.pause_intervals[0] = ok(unauthorized.pause_intervals[0].clone().seal());
    assert!(evaluate_case_sla(
        &unauthorized,
        &contract.sla_profiles[0],
        &profile,
        &time,
        None
    )
    .is_err());
    let mut out_of_window_time = time.clone();
    out_of_window_time.trusted_now_unix_seconds = out_of_window_time.window_end_unix_seconds + 1;
    out_of_window_time = ok(out_of_window_time.seal());
    assert!(evaluate_case_sla(
        &on_time,
        &contract.sla_profiles[0],
        &profile,
        &out_of_window_time,
        None,
    )
    .is_err());
}

#[test]
fn generic_metrics_fail_closed_on_missing_conflicting_and_zero_population() {
    let time = trusted_time(90_000, 1);
    let window = measurement_window(&time);
    let binding = metric_binding(KpiFormulaKindV1::VerifiedClosureRate);
    let (coverage, complete) = ok(evaluate_metric(
        &binding,
        &population(),
        &window,
        vec!["verified-evidence".to_owned()],
    ));
    assert_eq!(complete.millionths_value, Some(500_000));
    assert_eq!(complete.result_status, RoleMetricResultStatusV1::Met);
    assert_schema_roundtrip(&binding, KPI_METRIC_BINDING_V1_SCHEMA);
    assert_schema_roundtrip(&coverage, METRIC_EVIDENCE_COVERAGE_V1_SCHEMA);
    assert_schema_roundtrip(&complete, ROLE_METRIC_RESULT_V1_SCHEMA);

    let mut missing = population();
    missing.missing_evidence_count = 1;
    let (_, result) = ok(evaluate_metric(
        &binding,
        &missing,
        &window,
        vec!["verified-evidence".to_owned()],
    ));
    assert_eq!(
        result.result_status,
        RoleMetricResultStatusV1::InsufficientEvidence
    );
    assert_eq!(result.millionths_value, None);

    let mut conflicting = population();
    conflicting.conflicting_evidence_count = 1;
    let (_, result) = ok(evaluate_metric(
        &binding,
        &conflicting,
        &window,
        vec!["verified-evidence".to_owned()],
    ));
    assert_eq!(
        result.result_status,
        RoleMetricResultStatusV1::ConflictingEvidence
    );

    let mut uncovered_review = population();
    uncovered_review.false_completion_review_covered = 2;
    let (_, result) = ok(evaluate_metric(
        &metric_binding(KpiFormulaKindV1::FalseCompletionRate),
        &uncovered_review,
        &window,
        vec!["verified-evidence".to_owned()],
    ));
    assert_eq!(
        result.result_status,
        RoleMetricResultStatusV1::InsufficientEvidence
    );

    let mut zero = population();
    zero.terminal_cases = 0;
    zero.verified_complete_cases = 0;
    zero.explicit_refusal_cases = 0;
    zero.autonomous_completed_cases = 0;
    zero.resolve_duration_count = 0;
    zero.false_completion_review_population = 0;
    zero.false_completion_review_covered = 0;
    zero.false_completion_count = 0;
    let (_, result) = ok(evaluate_metric(
        &binding,
        &zero,
        &window,
        vec!["verified-evidence".to_owned()],
    ));
    assert_eq!(
        result.result_status,
        RoleMetricResultStatusV1::NotApplicable
    );

    let mut impossible = population();
    impossible.verified_complete_cases = impossible.terminal_cases + 1;
    assert!(evaluate_metric(
        &binding,
        &impossible,
        &window,
        vec!["verified-evidence".to_owned()]
    )
    .is_err());

    for domain in ["general-office", "hr", "it-service", "safety"] {
        let (_, result) = ok(evaluate_metric(
            &binding,
            &population(),
            &window,
            vec![format!("{domain}-verified-evidence")],
        ));
        assert_eq!(result.millionths_value, Some(500_000));
    }
}

#[test]
fn reports_routes_and_escalations_are_bounded_and_non_executable() {
    let contract = role();
    let profile = operations_profile(&contract);
    let time = trusted_time(90_000, 1);
    let window = measurement_window(&time);
    let case = case_evidence(&contract, "case-report", Some(500), false);
    let state = ok(evaluate_case_sla(
        &case,
        &contract.sla_profiles[0],
        &profile,
        &time,
        None,
    ));
    let metrics = profile
        .kpi_metric_bindings
        .iter()
        .map(|binding| {
            ok(evaluate_metric(
                binding,
                &population(),
                &window,
                vec!["verified-evidence".to_owned()],
            ))
            .1
        })
        .collect::<Vec<_>>();
    let snapshot = ok(build_role_snapshot(
        &profile,
        &contract,
        &window,
        std::slice::from_ref(&case),
        std::slice::from_ref(&state),
        &[],
        &metrics,
        &[],
        digest('7'),
        digest('8'),
        digest('9'),
    ));
    let mut cross_bound_state = state.clone();
    cross_bound_state.case_id = "other-case".to_owned();
    cross_bound_state = ok(cross_bound_state.seal());
    assert!(build_role_snapshot(
        &profile,
        &contract,
        &window,
        std::slice::from_ref(&case),
        std::slice::from_ref(&cross_bound_state),
        &[],
        &metrics,
        &[],
        digest('7'),
        digest('8'),
        digest('9'),
    )
    .is_err());
    let mut substituted_metrics = metrics.clone();
    substituted_metrics[0].metric_binding_sha256 = digest('f');
    substituted_metrics[0] = ok(substituted_metrics[0].clone().seal());
    assert!(build_role_snapshot(
        &profile,
        &contract,
        &window,
        std::slice::from_ref(&case),
        std::slice::from_ref(&state),
        &[],
        &substituted_metrics,
        &[],
        digest('7'),
        digest('8'),
        digest('9'),
    )
    .is_err());
    let trigger = ok(ReportingTriggerEventV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        trigger_id: "task-complete-case-report".to_owned(),
        trigger_kind: ReportingTriggerKindV1::OnTaskComplete,
        role_contract_sha256: contract.contract_sha256.clone(),
        obligation_id: "report-office-work".to_owned(),
        source_case_id: Some(case.case_id.clone()),
        source_artifact_hashes: vec![digest('a')],
        triggered_at_unix_seconds: 600,
        evidence_ids: vec!["verified-task-outcome".to_owned()],
        trigger_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_report_trigger(&trigger, &contract));
    let evaluation = ok(evaluate_report_evidence(
        "report-office-work".to_owned(),
        vec!["verified-task-outcome".to_owned()],
        vec!["verified-task-outcome".to_owned()],
        Vec::new(),
    ));
    let report = ok(build_role_report(
        &contract,
        &trigger,
        &snapshot,
        &evaluation,
        1,
        Vec::new(),
        0,
    ));
    assert_schema_roundtrip(&snapshot, ROLE_OPERATIONS_SNAPSHOT_V1_SCHEMA);
    assert_schema_roundtrip(&trigger, REPORTING_TRIGGER_EVENT_V1_SCHEMA);
    assert_schema_roundtrip(&evaluation, REPORT_EVIDENCE_EVALUATION_V1_SCHEMA);
    assert_schema_roundtrip(&report, ROLE_OPERATIONS_REPORT_V1_SCHEMA);
    let incomplete = ok(evaluate_report_evidence(
        "report-office-work".to_owned(),
        vec!["verified-task-outcome".to_owned()],
        Vec::new(),
        Vec::new(),
    ));
    assert!(build_role_report(
        &contract,
        &trigger,
        &snapshot,
        &incomplete,
        2,
        Vec::new(),
        0
    )
    .is_err());
    let weakened = ok(evaluate_report_evidence(
        "report-office-work".to_owned(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    assert_eq!(weakened.status, ReportEvidenceStatusV1::Complete);
    assert!(
        build_role_report(&contract, &trigger, &snapshot, &weakened, 2, Vec::new(), 0).is_err()
    );

    let registry = ok(RoleRoutingRegistryV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        registry_id: "general-office-internal-routes".to_owned(),
        registry_version: "1.0.0".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        allowed_routing_class_ids: profile.routing_class_allowlist.clone(),
        route_bindings: profile.internal_route_bindings.clone(),
        report_class_allowlist: vec![
            "office-escalation".to_owned(),
            "office-operations-periodic".to_owned(),
            "office-sla-breach".to_owned(),
            "office-work-result".to_owned(),
        ],
        escalation_severity_allowlist: vec![
            RoleEscalationSeverityV1::Routine,
            RoleEscalationSeverityV1::Elevated,
            RoleEscalationSeverityV1::High,
            RoleEscalationSeverityV1::Unsafe,
        ],
        valid_from_unix_seconds: 100,
        valid_to_unix_seconds: 100_000,
        evidence_ids: vec!["organization-internal-routing-approval".to_owned()],
        registry_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let key = SigningKey::from_bytes(&[23_u8; 32]);
    let approval = ok(sign_routing_registry_approval(
        RoleRoutingRegistryApprovalV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            registry_sha256: registry.registry_sha256.clone(),
            organization_id: registry.organization_id.clone(),
            role_contract_sha256: registry.role_contract_sha256.clone(),
            signer_id: "organization-routing-approver".to_owned(),
            signing_key_id: "routing-key-v1".to_owned(),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 100_000,
            nonce: "routing-approval-nonce-1".to_owned(),
            evidence_ids: vec!["organization-routing-approval".to_owned()],
            approval_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &registry,
        &key,
    ));
    assert_schema_roundtrip(&registry, ROLE_ROUTING_REGISTRY_V1_SCHEMA);
    assert_schema_roundtrip(&approval, ROLE_ROUTING_REGISTRY_APPROVAL_V1_SCHEMA);
    ok(verify_routing_registry_approval(
        &approval,
        &registry,
        "routing-key-v1",
        &key.verifying_key(),
        1_000,
    ));
    let verifying_key = key.verifying_key();
    let routing = ApprovedRoutingContext {
        registry: &registry,
        approval: &approval,
        expected_signer_key_id: "routing-key-v1",
        verifying_key: &verifying_key,
        trusted_now_unix_seconds: 1_000,
    };
    let inbox = ok(resolve_internal_route(
        &routing,
        &InternalRouteQuery {
            organization_id: &report.organization_id,
            role_contract_sha256: &report.role_contract_sha256,
            routing_class_id: &report.routing_class_id,
            report_class_id: Some(&report.report_class_id),
            severity: None,
        },
    ));
    assert!(inbox.starts_with("protected-inbox-"));
    assert!(resolve_internal_route(
        &routing,
        &InternalRouteQuery {
            organization_id: "other-organization",
            role_contract_sha256: &report.role_contract_sha256,
            routing_class_id: &report.routing_class_id,
            report_class_id: Some(&report.report_class_id),
            severity: None,
        }
    )
    .is_err());
    let mut forged_approval = approval.clone();
    forged_approval.signature_hex = "00".repeat(64);
    let forged_routing = ApprovedRoutingContext {
        registry: &registry,
        approval: &forged_approval,
        expected_signer_key_id: "routing-key-v1",
        verifying_key: &verifying_key,
        trusted_now_unix_seconds: 1_000,
    };
    assert!(resolve_internal_route(
        &forged_routing,
        &InternalRouteQuery {
            organization_id: &report.organization_id,
            role_contract_sha256: &report.role_contract_sha256,
            routing_class_id: &report.routing_class_id,
            report_class_id: Some(&report.report_class_id),
            severity: None,
        }
    )
    .is_err());
    let publication = ok(build_report_publication(
        "publication-report-office-work".to_owned(),
        &report,
        &routing,
    ));
    let receipt = ok(build_report_publication_receipt(
        &publication,
        digest('f'),
        1,
        1_000,
    ));
    assert_schema_roundtrip(&publication, REPORT_PUBLICATION_ENVELOPE_V1_SCHEMA);
    assert_schema_roundtrip(&receipt, REPORT_PUBLICATION_RECEIPT_V1_SCHEMA);
    let mut substituted_publication = publication.clone();
    substituted_publication.internal_inbox_id = "protected-inbox-substituted".to_owned();
    substituted_publication = ok(substituted_publication.seal());
    assert!(validate_report_publication(&substituted_publication, &report, &routing).is_err());
    let mut substituted_receipt = receipt.clone();
    substituted_receipt.durable_object_sha256 = digest('e');
    substituted_receipt = ok(substituted_receipt.seal());
    assert!(validate_report_publication_receipt(&substituted_receipt, &publication).is_err());

    let escalation_trigger = ok(RoleEscalationTriggerV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        trigger_id: "policy-unknown-case-report".to_owned(),
        organization_id: contract.organization_scope.organization_id.clone(),
        role_contract_sha256: contract.contract_sha256.clone(),
        case_id: Some(case.case_id.clone()),
        trigger_source_kind: EscalationTriggerSourceKindV1::PolicyUnknown,
        source_artifact_sha256: digest('b'),
        reason_codes: vec!["policy_unknown".to_owned()],
        safety_severity: RoleEscalationSeverityV1::High,
        authority_impact: EscalationAuthorityImpactV1::RequiresAuthorizedHuman,
        sla_breach_sha256: None,
        kpi_breach_sha256: None,
        case_escalation_request_sha256: None,
        detected_at_unix_seconds: 1_000,
        evidence_ids: vec!["protected-recovery-evidence".to_owned()],
        trigger_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(validate_escalation_trigger(&escalation_trigger, &contract));
    let route = select_escalation_route(&contract, &escalation_trigger);
    assert_eq!(route.as_deref(), Some("office-governance"));
    let item = ok(build_escalation_item(
        &escalation_trigger,
        &contract,
        &profile,
        &routing,
        digest('4'),
        digest('7'),
        digest('5'),
    ));
    assert_schema_roundtrip(&escalation_trigger, ROLE_ESCALATION_TRIGGER_V1_SCHEMA);
    assert_schema_roundtrip(&item, ROLE_ESCALATION_ITEM_V1_SCHEMA);
    assert_eq!(
        item.escalation_kind,
        EscalationKindV1::HumanExceptionHandoff
    );
    let acknowledgement = ok(sign_escalation_acknowledgement(
        EscalationAcknowledgementV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            acknowledgement_id: "ack-policy-unknown-case-report".to_owned(),
            escalation_item_sha256: item.item_sha256.clone(),
            authenticated_actor_class_id: "authorized-office-supervisor".to_owned(),
            acknowledged_at_unix_seconds: 1_100,
            acknowledgement_kind: EscalationAcknowledgementKindV1::AcceptedForReview,
            evidence_ids: vec!["authenticated-acknowledgement".to_owned()],
            signer_key_id: "routing-key-v1".to_owned(),
            acknowledgement_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &item,
        &key,
    ));
    ok(verify_escalation_acknowledgement(
        &acknowledgement,
        &item,
        "routing-key-v1",
        &key.verifying_key(),
    ));
    let mut unsigned_acknowledgement = acknowledgement.clone();
    unsigned_acknowledgement.signature_hex = "00".repeat(64);
    assert!(verify_escalation_acknowledgement(
        &unsigned_acknowledgement,
        &item,
        "routing-key-v1",
        &key.verifying_key(),
    )
    .is_err());
    assert_schema_roundtrip(&acknowledgement, ESCALATION_ACKNOWLEDGEMENT_V1_SCHEMA);
    let resolution = ok(sign_escalation_resolution(
        EscalationResolutionV1 {
            schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
            resolution_id: "resolution-policy-unknown-case-report".to_owned(),
            escalation_item_sha256: item.item_sha256.clone(),
            latest_acknowledgement_sha256: acknowledgement.acknowledgement_sha256.clone(),
            resolution_disposition: EscalationResolutionDispositionV1::EscalationAccepted,
            resolved_at_unix_seconds: 1_200,
            follow_up_work_item_reference: None,
            external_handling_reference_sha256: None,
            evidence_ids: vec!["bounded-resolution-record".to_owned()],
            signer_key_id: "routing-key-v1".to_owned(),
            resolution_sha256: ZERO_HASH.to_owned(),
            signature_hex: String::new(),
        },
        &item,
        &acknowledgement,
        &key,
    ));
    ok(verify_escalation_resolution(
        &resolution,
        &item,
        &acknowledgement,
        "routing-key-v1",
        &key.verifying_key(),
    ));
    assert_schema_roundtrip(&resolution, ESCALATION_RESOLUTION_V1_SCHEMA);
    let mut downgraded = escalation_trigger;
    downgraded.authority_impact = EscalationAuthorityImpactV1::OperationalAttention;
    downgraded = ok(downgraded.seal());
    assert!(validate_escalation_trigger(&downgraded, &contract).is_err());
}

#[test]
fn remaining_public_artifacts_roundtrip_through_their_schemas() {
    let interaction = ok(HumanInteractionEventV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        interaction_id: "human-interaction-1".to_owned(),
        case_id: "case-a".to_owned(),
        interaction_kind: "authorized-review".to_owned(),
        authenticated_actor_class: "authorized-supervisor".to_owned(),
        started_at_unix_seconds: 100,
        ended_at_unix_seconds: Some(160),
        source_artifact_sha256: digest('1'),
        evidence_ids: vec!["authenticated-human-interaction".to_owned()],
        interaction_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let review = ok(FalseCompletionReviewRecordV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        original_terminal_case_sha256: digest('2'),
        original_terminal_episode_sha256: digest('3'),
        review_covered: true,
        authoritative_correction_or_incident_sha256: None,
        reviewer_trust_class: "authorized-quality-review".to_owned(),
        false_completion: Some(false),
        evidence_ids: vec!["authoritative-completion-review".to_owned()],
        record_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let publication = ok(ReportPublicationEnvelopeV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        publication_id: "publication-1".to_owned(),
        report_sha256: digest('4'),
        reporting_obligation_id: "report-office-work".to_owned(),
        report_class_id: "office-work-result".to_owned(),
        routing_class_id: "office-supervision".to_owned(),
        internal_inbox_id: "protected-inbox-office-supervision".to_owned(),
        registry_sha256: digest('5'),
        published_at_unix_seconds: 200,
        retention_class_id: "office-audit".to_owned(),
        evidence_ids: vec![digest('4')],
        publication_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let receipt = ok(ReportPublicationReceiptV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        publication_sha256: publication.publication_sha256.clone(),
        internal_inbox_ledger_head_sha256: digest('6'),
        durable_object_sha256: publication.publication_sha256.clone(),
        publication_sequence: 1,
        status: ReportPublicationStatusV1::PublishedToInternalRoute,
        recorded_at_unix_seconds: 201,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let time = trusted_time(90_000, 1);
    let request = ok(RoleOperationsCycleRequestV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        cycle_id: "operations-cycle-1".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_sha256: digest('7'),
        role_instance_ids: vec!["general-office-instance-1".to_owned()],
        operations_profile_sha256: digest('8'),
        time_context: time,
        measurement_window_sha256: digest('9'),
        role_ledger_head_sha256: digest('a'),
        intake_ledger_head_sha256: digest('b'),
        case_ledger_head_sha256: digest('c'),
        queue_ledger_head_sha256: digest('d'),
        planner_ledger_head_hashes: vec![digest('e')],
        memory_store_head_sha256: digest('f'),
        audit_ledger_head_sha256: digest('0'),
        maximum_cases: 128,
        maximum_reports: 128,
        maximum_escalations: 128,
        logical_operation_budget: 1_000_000,
        evidence_ids: vec!["authoritative-role-operations-cycle".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let result = ok(RoleOperationsCycleResultV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        request_sha256: request.request_sha256.clone(),
        processed_cases: 5,
        sla_state_hashes: vec![digest('1')],
        new_breach_hashes: vec![digest('2')],
        duplicate_breaches: 0,
        metric_result_hashes: vec![digest('3')],
        report_trigger_hashes: vec![digest('4')],
        generated_report_hashes: vec![digest('5')],
        published_report_hashes: vec![digest('6')],
        generated_escalation_hashes: vec![digest('7')],
        routed_escalation_hashes: vec![digest('8')],
        overdue_escalations: 0,
        rejected_artifacts: 0,
        logical_operations: 100,
        output_hashes: vec![digest('9')],
        cycle_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let replay = ok(RoleOperationsReplayReportV1 {
        schema_version: ROLE_OPERATIONS_SCHEMA_VERSION,
        total_cases: 128,
        active_cases: 0,
        terminal_cases: 128,
        compliant_cases: 96,
        at_risk_cases: 0,
        paused_cases: 0,
        breached_cases: 32,
        verified_complete_cases: 96,
        explicit_refusal_cases: 16,
        escalated_cases: 16,
        reports_generated: 128,
        reports_published: 128,
        escalations_generated: 16,
        acknowledged_escalations: 16,
        resolved_escalations: 16,
        evidence_incomplete_metrics: 0,
        input_bytes: 4_096,
        output_bytes: 4_096,
        peak_records: 512,
        logical_operations: 1_536,
        critical_error_count: 0,
        sla_state_set_sha256: digest('a'),
        role_snapshot_sha256: digest('b'),
        metric_set_sha256: digest('c'),
        report_set_sha256: digest('d'),
        escalation_set_sha256: digest('e'),
        normalized_replay_sha256: ZERO_HASH.to_owned(),
    }
    .seal());

    assert_schema_roundtrip(&interaction, HUMAN_INTERACTION_EVENT_V1_SCHEMA);
    assert_schema_roundtrip(&review, FALSE_COMPLETION_REVIEW_RECORD_V1_SCHEMA);
    assert_schema_roundtrip(&publication, REPORT_PUBLICATION_ENVELOPE_V1_SCHEMA);
    assert_schema_roundtrip(&receipt, REPORT_PUBLICATION_RECEIPT_V1_SCHEMA);
    assert_schema_roundtrip(&request, ROLE_OPERATIONS_CYCLE_REQUEST_V1_SCHEMA);
    assert_schema_roundtrip(&result, ROLE_OPERATIONS_CYCLE_RESULT_V1_SCHEMA);
    assert_schema_roundtrip(&replay, ROLE_OPERATIONS_REPLAY_REPORT_V1_SCHEMA);
}

#[test]
fn all_public_schemas_are_strict_draft_2020_12() {
    let schemas = [
        ROLE_OPERATIONS_PROFILE_V1_SCHEMA,
        ROLE_OPERATIONS_PROFILE_APPROVAL_V1_SCHEMA,
        TRUSTED_ROLE_OPERATIONS_TIME_CONTEXT_V1_SCHEMA,
        ROLE_MEASUREMENT_WINDOW_V1_SCHEMA,
        SLA_MILESTONE_MAPPING_V1_SCHEMA,
        SLA_MILESTONE_EVENT_V1_SCHEMA,
        SLA_PAUSE_CONDITION_BINDING_V1_SCHEMA,
        SLA_PAUSE_INTERVAL_V1_SCHEMA,
        CASE_SLA_RUNTIME_STATE_V1_SCHEMA,
        SLA_BREACH_RECORD_V1_SCHEMA,
        KPI_METRIC_BINDING_V1_SCHEMA,
        METRIC_EVIDENCE_COVERAGE_V1_SCHEMA,
        ROLE_METRIC_RESULT_V1_SCHEMA,
        HUMAN_INTERACTION_EVENT_V1_SCHEMA,
        FALSE_COMPLETION_REVIEW_RECORD_V1_SCHEMA,
        ROLE_OPERATIONS_SNAPSHOT_V1_SCHEMA,
        REPORTING_TRIGGER_EVENT_V1_SCHEMA,
        REPORT_EVIDENCE_EVALUATION_V1_SCHEMA,
        ROLE_OPERATIONS_REPORT_V1_SCHEMA,
        ROLE_ROUTING_REGISTRY_V1_SCHEMA,
        ROLE_ROUTING_REGISTRY_APPROVAL_V1_SCHEMA,
        REPORT_PUBLICATION_ENVELOPE_V1_SCHEMA,
        REPORT_PUBLICATION_RECEIPT_V1_SCHEMA,
        ROLE_ESCALATION_TRIGGER_V1_SCHEMA,
        ROLE_ESCALATION_ITEM_V1_SCHEMA,
        ESCALATION_ACKNOWLEDGEMENT_V1_SCHEMA,
        ESCALATION_RESOLUTION_V1_SCHEMA,
        ROLE_OPERATIONS_CYCLE_REQUEST_V1_SCHEMA,
        ROLE_OPERATIONS_CYCLE_RESULT_V1_SCHEMA,
        ROLE_OPERATIONS_REPLAY_REPORT_V1_SCHEMA,
    ];
    assert_eq!(schemas.len(), 30);
    for source in schemas {
        let value: serde_json::Value = ok(serde_json::from_str(source));
        assert_eq!(
            value.get("$schema").and_then(serde_json::Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert_eq!(
            value
                .get("additionalProperties")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&value));
    }
    let time = trusted_time(90_000, 1);
    let schema_value: serde_json::Value = ok(serde_json::from_str(
        TRUSTED_ROLE_OPERATIONS_TIME_CONTEXT_V1_SCHEMA,
    ));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema_value));
    let instance = ok(serde_json::to_value(&time));
    assert!(compiled.is_valid(&instance));
    let mut unknown = instance;
    if let Some(object) = unknown.as_object_mut() {
        object.insert("unknown".to_owned(), json!(true));
    }
    assert!(!compiled.is_valid(&unknown));
}

#[test]
fn one_hundred_replays_of_128_cases_are_identical() {
    #[derive(Serialize)]
    struct ReplayProjection {
        case_hashes: Vec<String>,
        total_cases: u32,
        logical_operations: u64,
    }
    let case_hashes = (0..128)
        .map(|index| {
            ok(canonical_sha256(
                &json!({"case_id": format!("case-{index:03}")}),
            ))
        })
        .collect::<Vec<_>>();
    let projection = ReplayProjection {
        case_hashes,
        total_cases: 128,
        logical_operations: 128 * 12,
    };
    let expected = ok(canonical_sha256(&projection));
    let hashes = (0..100)
        .map(|_| ok(canonical_sha256(&projection)))
        .collect::<HashSet<_>>();
    assert_eq!(hashes.len(), 1);
    assert!(hashes.contains(&expected));
}
