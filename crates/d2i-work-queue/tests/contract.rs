#[allow(dead_code)]
#[path = "../../../products/d2i-desktop/tests/support/work_case_fixture.rs"]
mod work_case_fixture;

use d2i_cognitive_ir::CognitiveRiskClass;
use d2i_role_contract::{RoleInstanceStatusV1, RoleOperationalTimeContextV1};
use d2i_work_case::CaseLifecycleStatusV1;
use d2i_work_queue::*;
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use work_case_fixture::{digest, distinct_fixtures, fixture, ok, Fixture};

const NOW: u64 = 1_785_000_100;

struct QueueFixture {
    base: Fixture,
    policy: WorkQueuePolicyV1,
    pool: CaseOwnershipPoolV1,
    ownership: CurrentCaseOwnershipStateV1,
    entry: WorkQueueEntryV1,
    snapshot: WorkQueueSnapshotV1,
    tick: WorkSchedulerTickV1,
    decision: WorkSchedulerDecisionV1,
    lease: CaseLeaseV1,
    leased_ownership: CurrentCaseOwnershipStateV1,
    grant: CaseWorkGrantV1,
}

fn queue_fixture() -> QueueFixture {
    let base = fixture();
    let policy = ok(WorkQueuePolicyV1 {
        schema_version: 1,
        policy_id: "general-office-queue-policy".to_owned(),
        policy_version: "1.0.0".to_owned(),
        queue_id: "general-office-queue".to_owned(),
        organization_id: base.case_contract.organization_id.clone(),
        role_contract_id: base.role_contract.role_contract_id.clone(),
        role_version: base.role_contract.role_version.clone(),
        role_contract_sha256: base.role_contract.contract_sha256.clone(),
        allowed_work_class_ids: vec![base.case_contract.work_class_id.clone()],
        allowed_role_instance_ids: vec![base.role_instance.role_instance_id.clone()],
        maximum_queue_entries: 128,
        maximum_entries_examined_per_tick: 128,
        claim_lease_duration_seconds: 300,
        minimum_lease_duration_seconds: 30,
        maximum_lease_duration_seconds: 900,
        maximum_lease_renewals: 2,
        maximum_concurrent_leases_per_role: 1,
        maximum_open_cases_per_role: 128,
        aging_interval_seconds: 60,
        maximum_aging_buckets: 16,
        require_inside_operating_calendar: true,
        blocked_treatment: QueueStateTreatmentV1::Exclude,
        awaiting_clarification_treatment: QueueStateTreatmentV1::Exclude,
        awaiting_verification_treatment: QueueStateTreatmentV1::Eligible,
        escalation_pending_treatment: QueueStateTreatmentV1::Attention,
        owner_unavailable_treatment: QueueStateTreatmentV1::Attention,
        lease_expiry_behavior: LeaseExpiryBehaviorV1::ReturnToReady,
        reassignment_allowed: true,
        automatic_reassignment_reasons: vec![AutomaticReassignmentReasonV1::OwnerSuspended],
        maximum_ownership_generations: 16,
        maximum_queue_operations: 65_536,
        maximum_snapshot_bytes: 8 * 1024 * 1024,
        maximum_decision_bytes: 8 * 1024 * 1024,
        maximum_ledger_bytes: 64 * 1024 * 1024,
        logical_operation_budget: 16_384,
        maximum_scheduler_ticks_per_invocation: 1,
        maximum_concurrent_coordinators: 1,
        maximum_replay_records: 65_536,
        evidence_ids: vec!["approved-queue-policy".to_owned()],
        policy_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let member = CaseOwnershipPoolMemberV1 {
        role_instance_id: base.role_instance.role_instance_id.clone(),
        role_instance_sha256: base.role_instance.instance_sha256.clone(),
        delegation_sha256: base.role_instance.delegation_sha256.clone(),
        allowed_work_class_ids: vec![base.case_contract.work_class_id.clone()],
        allowed_responsibility_ids: vec![base.case_contract.responsibility_id.clone()],
        allowed_application_pack_ids: base.role_instance.application_pack_ids.clone(),
        allowed_integration_ids: base.role_instance.integration_ids.clone(),
        allowed_capability_ids: base.role_instance.capability_ids.clone(),
        active: true,
        expires_at_unix_seconds: base.role_instance.expires_at_unix_seconds,
        ownership_expires_at_unix_seconds: base.role_instance.expires_at_unix_seconds,
        active_lease_count: 0,
        non_terminal_case_count: 1,
    };
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let pool = ok(create_case_ownership_pool(
        CaseOwnershipPoolV1 {
            schema_version: 1,
            pool_id: "general-office-ownership-pool".to_owned(),
            pool_version: "1.0.0".to_owned(),
            organization_id: base.case_contract.organization_id.clone(),
            role_contract_id: base.role_contract.role_contract_id.clone(),
            role_version: base.role_contract.role_version.clone(),
            role_contract_sha256: base.role_contract.contract_sha256.clone(),
            members: vec![member],
            allowed_work_class_ids: vec![base.case_contract.work_class_id.clone()],
            allowed_responsibility_ids: vec![base.case_contract.responsibility_id.clone()],
            allowed_application_pack_ids: base.role_instance.application_pack_ids.clone(),
            allowed_integration_ids: base.role_instance.integration_ids.clone(),
            allowed_capability_ids: base.role_instance.capability_ids.clone(),
            maximum_risk: CognitiveRiskClass::BusinessStateChange,
            automatic_reassignment_reasons: vec![AutomaticReassignmentReasonV1::OwnerSuspended],
            maximum_concurrent_leases_per_role: 1,
            valid_from_unix_seconds: NOW - 100,
            expires_at_unix_seconds: base.role_instance.expires_at_unix_seconds,
            signer_id: "organization-governance".to_owned(),
            signer_key_id: "ownership-pool-key-v1".to_owned(),
            evidence_ids: vec!["signed-ownership-pool".to_owned()],
            approval_signature: String::new(),
            pool_sha256: ZERO_HASH.to_owned(),
        },
        &signing_key,
    ));
    ok(verify_case_ownership_pool(
        &pool,
        "ownership-pool-key-v1",
        &signing_key.verifying_key(),
        std::slice::from_ref(&base.role_instance),
        NOW,
    ));
    let ownership = ok(derive_initial_ownership(
        &base.case_contract,
        &base.case_instance,
        &base.role_instance,
        &policy,
        &pool,
        NOW - 10,
        digest('a'),
        digest('b'),
        vec!["origin-ownership-projection".to_owned()],
    ));
    let entry = ok(project_case_to_queue(
        &policy,
        &base.case_contract,
        &base.case_instance,
        &ownership,
        &base.role_instance,
        NOW,
        1,
        digest('c'),
        digest('a'),
        digest('b'),
        vec!["queue-projection".to_owned()],
    ));
    let snapshot = ok(WorkQueueSnapshotV1::create(
        "snapshot-1".to_owned(),
        &policy,
        1,
        vec![entry.clone()],
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["queue-snapshot".to_owned()],
    ));
    let operational_time_context = ok(RoleOperationalTimeContextV1 {
        schema_version: 1,
        calendar_sha256: base.role_contract.working_calendar.calendar_sha256.clone(),
        timezone_id: base.role_contract.working_calendar.timezone_id.clone(),
        local_date: "2026-08-03".to_owned(),
        weekday: 0,
        local_minute_of_day: 600,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: NOW,
        evidence_ids: vec!["trusted-scheduler-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let tick = ok(WorkSchedulerTickV1 {
        schema_version: 1,
        tick_id: "tick-1".to_owned(),
        queue_id: policy.queue_id.clone(),
        queue_policy_sha256: policy.policy_sha256.clone(),
        queue_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        trusted_now_unix_seconds: NOW,
        operational_time_context,
        current_role_ledger_head: digest('a'),
        current_case_ledger_head: digest('b'),
        current_queue_ledger_head: digest('d'),
        maximum_entries: 128,
        logical_operation_budget: 16_384,
        evidence_ids: vec!["trusted-scheduler-tick".to_owned()],
        tick_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let decision = ok(schedule_next_case(
        &policy,
        &snapshot,
        &tick,
        SchedulerEvaluationContextV1 {
            role_contract: &base.role_contract,
            case_contracts: std::slice::from_ref(&base.case_contract),
            case_instances: std::slice::from_ref(&base.case_instance),
            ownership_states: std::slice::from_ref(&ownership),
            role_instances: std::slice::from_ref(&base.role_instance),
            leases: &[],
        },
    ));
    let lease = ok(claim_case_lease(
        &policy,
        &snapshot,
        &decision,
        &entry,
        &base.case_contract,
        &base.case_instance,
        &ownership,
        &base.role_instance,
        &[],
        1,
        1,
        NOW,
        digest('d'),
        digest('b'),
        digest('a'),
        vec!["exclusive-claim".to_owned()],
    ));
    let leased_ownership = ok(ownership.with_active_lease(Some(lease.lease_sha256.clone())));
    let grant = ok(create_case_work_grant(
        "work-grant-1".to_owned(),
        1,
        &base.case_contract,
        &base.case_instance,
        &leased_ownership,
        &lease,
        NOW,
        vec!["non-executable-grant".to_owned()],
    ));
    QueueFixture {
        base,
        policy,
        pool,
        ownership,
        entry,
        snapshot,
        tick,
        decision,
        lease,
        leased_ownership,
        grant,
    }
}

#[test]
fn signed_pool_queue_scheduler_lease_and_grant_are_exact() {
    let fixture = queue_fixture();
    assert_eq!(fixture.decision.outcome, SchedulerOutcomeV1::CaseSelected);
    assert_eq!(
        fixture.decision.selected_case_id.as_deref(),
        Some(fixture.base.case_contract.case_id.as_str())
    );
    assert!(fixture.lease.is_active_at(NOW));
    assert_eq!(
        fixture.leased_ownership.active_lease_sha256.as_ref(),
        Some(&fixture.lease.lease_sha256)
    );
    assert_eq!(fixture.grant.lease_sha256, fixture.lease.lease_sha256);
    let serialized = ok(serde_json::to_string(&fixture.grant));
    for forbidden in [
        "goal_spec",
        "action_proposal",
        "locator",
        "credential",
        "activation_token",
        "adapter_input",
    ] {
        assert!(!serialized.contains(forbidden));
    }
}

#[test]
fn duplicate_claim_stale_state_and_lease_epoch_replay_fail_closed() {
    let fixture = queue_fixture();
    let duplicate = claim_case_lease(
        &fixture.policy,
        &fixture.snapshot,
        &fixture.decision,
        &fixture.entry,
        &fixture.base.case_contract,
        &fixture.base.case_instance,
        &fixture.ownership,
        &fixture.base.role_instance,
        std::slice::from_ref(&fixture.lease),
        2,
        1,
        NOW + 1,
        digest('d'),
        digest('b'),
        digest('a'),
        vec!["duplicate-claim".to_owned()],
    );
    assert!(matches!(duplicate, Err(WorkQueueError::Replay(_))));

    let mut stale = fixture.entry.clone();
    stale.current_case_instance_sha256 = digest('e');
    assert!(schedule_next_case(
        &fixture.policy,
        &fixture.snapshot,
        &fixture.tick,
        SchedulerEvaluationContextV1 {
            role_contract: &fixture.base.role_contract,
            case_contracts: std::slice::from_ref(&fixture.base.case_contract),
            case_instances: std::slice::from_ref(&fixture.base.case_instance),
            ownership_states: std::slice::from_ref(&fixture.ownership),
            role_instances: std::slice::from_ref(&fixture.base.role_instance),
            leases: &[],
        },
    )
    .is_ok());
    stale.entry_sha256 = digest('f');
    assert!(stale.validate().is_err());
}

#[test]
fn lease_expiry_release_renewal_and_grant_replay_are_bounded() {
    let fixture = queue_fixture();
    let renewed = ok(renew_case_lease(
        &fixture.policy,
        &fixture.lease,
        &fixture.base.role_instance,
        NOW + 10,
        60,
        digest('d'),
        digest('b'),
        digest('a'),
    ));
    assert_eq!(renewed.renewal_count, 1);
    assert_eq!(
        renewed.previous_lease_sha256,
        Some(fixture.lease.lease_sha256.clone())
    );
    let released = ok(terminate_case_lease(
        &renewed,
        LeaseStatusV1::Released,
        NOW + 11,
        digest('e'),
    ));
    assert_eq!(released.lease_status, LeaseStatusV1::Released);
    assert!(renew_case_lease(
        &fixture.policy,
        &released,
        &fixture.base.role_instance,
        NOW + 12,
        60,
        digest('e'),
        digest('b'),
        digest('a'),
    )
    .is_err());
    assert!(consume_work_grant(
        &fixture.grant,
        std::slice::from_ref(&fixture.grant.grant_sha256),
        &[],
        NOW + 1,
    )
    .is_err());
}

#[test]
fn input_order_schema_unknown_fields_and_pool_tamper_are_rejected() {
    let fixture = queue_fixture();
    let mut reversed = fixture.snapshot.entries.clone();
    reversed.reverse();
    let rebuilt = ok(WorkQueueSnapshotV1::create(
        "snapshot-1".to_owned(),
        &fixture.policy,
        1,
        reversed,
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["queue-snapshot".to_owned()],
    ));
    assert_eq!(rebuilt.snapshot_sha256, fixture.snapshot.snapshot_sha256);

    let mut unknown = ok(serde_json::to_value(&fixture.policy));
    unknown["unexpected"] = serde_json::json!(true);
    assert!(parse_json_strict::<WorkQueuePolicyV1>(&ok(serde_json::to_vec(&unknown))).is_err());
    assert!(
        parse_json_strict::<WorkQueuePolicyV1>(br#"{"schema_version":1,"schema_version":1}"#)
            .is_err()
    );
    let mut tampered = fixture.pool.clone();
    tampered.maximum_concurrent_leases_per_role = 2;
    assert!(tampered.validate().is_err());
}

#[test]
fn public_artifacts_match_strict_draft_2020_12_schemas() {
    let fixture = queue_fixture();
    let transfer = ok(CaseOwnershipTransferV1 {
        schema_version: 1,
        transfer_id: "schema-transfer-1".to_owned(),
        case_id: fixture.base.case_contract.case_id.clone(),
        case_contract_sha256: fixture.base.case_contract.contract_sha256.clone(),
        current_case_instance_sha256: fixture.base.case_instance.instance_sha256.clone(),
        current_queue_entry_sha256: fixture.entry.entry_sha256.clone(),
        previous_ownership_state_sha256: fixture.ownership.state_sha256.clone(),
        source_role_instance_id: fixture.base.role_instance.role_instance_id.clone(),
        source_role_instance_sha256: fixture.base.role_instance.instance_sha256.clone(),
        target_role_instance_id: "standby-role-instance".to_owned(),
        target_role_instance_sha256: digest('9'),
        organization_id: fixture.policy.organization_id.clone(),
        role_contract_id: fixture.policy.role_contract_id.clone(),
        role_version: fixture.policy.role_version.clone(),
        role_contract_sha256: fixture.policy.role_contract_sha256.clone(),
        responsibility_id: fixture.base.case_contract.responsibility_id.clone(),
        work_class_id: fixture.base.case_contract.work_class_id.clone(),
        ownership_pool_sha256: fixture.pool.pool_sha256.clone(),
        transfer_reason: AutomaticReassignmentReasonV1::OwnerSuspended,
        transfer_at_unix_seconds: NOW,
        current_case_ledger_head: digest('b'),
        current_queue_ledger_head: digest('d'),
        current_role_ledger_head: digest('a'),
        next_ownership_generation: 2,
        evidence_ids: vec!["schema-transfer".to_owned()],
        transfer_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let receipt = ok(WorkQueueOperationReceiptV1 {
        schema_version: 1,
        receipt_id: "schema-receipt-1".to_owned(),
        operation_kind: QueueOperationKindV1::WorkGrantCreated,
        queue_id: fixture.policy.queue_id.clone(),
        case_id: fixture.base.case_contract.case_id.clone(),
        source_intake_receipt_sha256: digest('c'),
        queue_entry_sha256: Some(fixture.entry.entry_sha256.clone()),
        scheduler_decision_sha256: Some(fixture.decision.decision_sha256.clone()),
        lease_sha256: Some(fixture.lease.lease_sha256.clone()),
        ownership_state_sha256: Some(fixture.leased_ownership.state_sha256.clone()),
        ownership_transfer_sha256: Some(transfer.transfer_sha256.clone()),
        work_grant_sha256: Some(fixture.grant.grant_sha256.clone()),
        role_ledger_chain_head: digest('a'),
        case_ledger_chain_head: digest('b'),
        queue_ledger_chain_head: digest('d'),
        recorded_at_unix_seconds: NOW,
        evidence_ids: vec!["schema-receipt".to_owned()],
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let report = ok(NormalizedQueueReplayReportV1 {
        schema_version: 1,
        queue_entries: 1,
        eligible: 1,
        waiting: 0,
        blocked: 0,
        attention: 0,
        leased: 1,
        terminal_removed: 0,
        examined_entries: 1,
        logical_operations: fixture.decision.logical_operations,
        input_bytes: ok(canonical_size(&fixture.snapshot)),
        output_bytes: ok(canonical_size(&fixture.decision)),
        peak_records: 1,
        queue_ordering_sha256: ok(queue_ordering_sha256(&fixture.snapshot)),
        queue_snapshot_sha256: fixture.snapshot.snapshot_sha256.clone(),
        scheduler_decision_sha256: fixture.decision.decision_sha256.clone(),
        lease_sha256: fixture.lease.lease_sha256.clone(),
        work_grant_sha256: fixture.grant.grant_sha256.clone(),
        ownership_state_sha256: fixture.leased_ownership.state_sha256.clone(),
        critical_error_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let artifacts = vec![
        (
            WORK_QUEUE_POLICY_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.policy)),
        ),
        (
            CASE_OWNERSHIP_POOL_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.pool)),
        ),
        (
            CURRENT_CASE_OWNERSHIP_STATE_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.ownership)),
        ),
        (
            WORK_QUEUE_ENTRY_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.entry)),
        ),
        (
            WORK_QUEUE_SNAPSHOT_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.snapshot)),
        ),
        (
            WORK_SCHEDULER_TICK_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.tick)),
        ),
        (
            WORK_SCHEDULER_DECISION_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.decision)),
        ),
        (
            CASE_LEASE_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.lease)),
        ),
        (
            CASE_OWNERSHIP_TRANSFER_V1_SCHEMA,
            ok(serde_json::to_value(&transfer)),
        ),
        (
            CASE_WORK_GRANT_V1_SCHEMA,
            ok(serde_json::to_value(&fixture.grant)),
        ),
        (
            WORK_QUEUE_OPERATION_RECEIPT_V1_SCHEMA,
            ok(serde_json::to_value(&receipt)),
        ),
        (
            NORMALIZED_QUEUE_REPLAY_REPORT_V1_SCHEMA,
            ok(serde_json::to_value(&report)),
        ),
    ];
    for (schema, artifact) in artifacts {
        let schema = ok(serde_json::from_str(schema));
        let validator = ok(JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema));
        if !validator.is_valid(&artifact) {
            let errors = validator
                .validate(&artifact)
                .err()
                .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
                .unwrap_or_default();
            panic!("schema rejected valid artifact: {errors:?}");
        }
        let mut unknown = artifact;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(!validator.is_valid(&unknown));
    }

    let snapshot_schema = ok(serde_json::from_str(WORK_QUEUE_SNAPSHOT_V1_SCHEMA));
    let snapshot_validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&snapshot_schema));
    let mut nested_snapshot = ok(serde_json::to_value(&fixture.snapshot));
    nested_snapshot["entries"][0]["unexpected"] = serde_json::json!(true);
    assert!(!snapshot_validator.is_valid(&nested_snapshot));

    let tick_schema = ok(serde_json::from_str(WORK_SCHEDULER_TICK_V1_SCHEMA));
    let tick_validator = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&tick_schema));
    let mut nested_tick = ok(serde_json::to_value(&fixture.tick));
    nested_tick["operational_time_context"]["unexpected"] = serde_json::json!(true);
    assert!(!tick_validator.is_valid(&nested_tick));
}

#[test]
fn deterministic_report_replay_requires_exact_run_count_and_hashes() {
    let fixture = queue_fixture();
    let report = ok(NormalizedQueueReplayReportV1 {
        schema_version: 1,
        queue_entries: fixture.snapshot.entries.len() as u32,
        eligible: fixture.decision.eligible_entry_count,
        waiting: fixture.decision.waiting_entry_count,
        blocked: 0,
        attention: fixture.decision.attention_entry_count,
        leased: 1,
        terminal_removed: fixture.snapshot.terminal_removed_count,
        examined_entries: fixture.decision.examined_entry_count,
        logical_operations: fixture.decision.logical_operations,
        input_bytes: ok(canonical_size(&fixture.snapshot)),
        output_bytes: ok(canonical_size(&fixture.decision)),
        peak_records: fixture.snapshot.entries.len() as u32,
        queue_ordering_sha256: ok(queue_ordering_sha256(&fixture.snapshot)),
        queue_snapshot_sha256: fixture.snapshot.snapshot_sha256.clone(),
        scheduler_decision_sha256: fixture.decision.decision_sha256.clone(),
        lease_sha256: fixture.lease.lease_sha256.clone(),
        work_grant_sha256: fixture.grant.grant_sha256.clone(),
        ownership_state_sha256: fixture.ownership.state_sha256.clone(),
        critical_error_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    let reports = vec![report; 100];
    let hash = ok(verify_replay_reports(&reports, 100));
    assert!(hash.starts_with("sha256:"));
    assert!(verify_replay_reports(&reports, 99).is_err());
}

#[test]
fn scheduler_closed_states_and_stale_inputs_never_select_a_case() {
    let fixture = queue_fixture();

    let empty_snapshot = ok(WorkQueueSnapshotV1::create(
        "empty-snapshot".to_owned(),
        &fixture.policy,
        2,
        Vec::new(),
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["empty-queue".to_owned()],
    ));
    let empty_tick = tick_for(&fixture.tick, "empty-tick", &empty_snapshot, None, None);
    let empty = ok(schedule_next_case(
        &fixture.policy,
        &empty_snapshot,
        &empty_tick,
        SchedulerEvaluationContextV1 {
            role_contract: &fixture.base.role_contract,
            case_contracts: &[],
            case_instances: &[],
            ownership_states: &[],
            role_instances: &[],
            leases: &[],
        },
    ));
    assert_eq!(empty.outcome, SchedulerOutcomeV1::QueueEmpty);

    let mut outside_tick = tick_for(
        &fixture.tick,
        "outside-window-tick",
        &fixture.snapshot,
        Some(0),
        None,
    );
    outside_tick.operational_time_context.blackout_date_ids =
        vec!["caller-blackout-date".to_owned()];
    outside_tick.operational_time_context.context_sha256 = ZERO_HASH.to_owned();
    outside_tick.operational_time_context = ok(outside_tick.operational_time_context.seal());
    outside_tick.tick_sha256 = ZERO_HASH.to_owned();
    let outside_tick = ok(outside_tick.seal());
    let outside = ok(schedule_next_case(
        &fixture.policy,
        &fixture.snapshot,
        &outside_tick,
        evaluation_context(
            &fixture,
            &fixture.ownership,
            &fixture.base.role_instance,
            &[],
        ),
    ));
    assert_eq!(outside.outcome, SchedulerOutcomeV1::OutsideOperatingWindow);

    let budget_tick = tick_for(
        &fixture.tick,
        "budget-tick",
        &fixture.snapshot,
        None,
        Some(1),
    );
    let budget = ok(schedule_next_case(
        &fixture.policy,
        &fixture.snapshot,
        &budget_tick,
        evaluation_context(
            &fixture,
            &fixture.ownership,
            &fixture.base.role_instance,
            &[],
        ),
    ));
    assert_eq!(budget.outcome, SchedulerOutcomeV1::ResourceLimit);

    let active = ok(fixture.base.case_instance.transition_non_terminal(
        CaseLifecycleStatusV1::Active,
        NOW - 20,
        None,
    ));
    let blocked = ok(active.transition_non_terminal(
        CaseLifecycleStatusV1::Blocked,
        NOW - 10,
        Some(digest('8')),
    ));
    let blocked_entry = ok(project_case_to_queue(
        &fixture.policy,
        &fixture.base.case_contract,
        &blocked,
        &fixture.ownership,
        &fixture.base.role_instance,
        NOW,
        1,
        digest('c'),
        digest('a'),
        digest('b'),
        vec!["blocked-entry".to_owned()],
    ));
    let blocked_snapshot = ok(WorkQueueSnapshotV1::create(
        "blocked-snapshot".to_owned(),
        &fixture.policy,
        2,
        vec![blocked_entry],
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["blocked-snapshot".to_owned()],
    ));
    let blocked_tick = tick_for(&fixture.tick, "blocked-tick", &blocked_snapshot, None, None);
    let blocked_decision = ok(schedule_next_case(
        &fixture.policy,
        &blocked_snapshot,
        &blocked_tick,
        SchedulerEvaluationContextV1 {
            role_contract: &fixture.base.role_contract,
            case_contracts: std::slice::from_ref(&fixture.base.case_contract),
            case_instances: std::slice::from_ref(&blocked),
            ownership_states: std::slice::from_ref(&fixture.ownership),
            role_instances: std::slice::from_ref(&fixture.base.role_instance),
            leases: &[],
        },
    ));
    assert_eq!(blocked_decision.outcome, SchedulerOutcomeV1::NoEligibleCase);

    let suspended = ok(fixture
        .base
        .role_instance
        .transition(RoleInstanceStatusV1::Suspended, NOW - 1));
    let suspended_ownership = ok(fixture
        .ownership
        .refresh_role_binding(&suspended, digest('a')));
    let suspended_entry = ok(project_case_to_queue(
        &fixture.policy,
        &fixture.base.case_contract,
        &fixture.base.case_instance,
        &suspended_ownership,
        &suspended,
        NOW,
        1,
        digest('c'),
        digest('a'),
        digest('b'),
        vec!["suspended-owner-entry".to_owned()],
    ));
    let suspended_snapshot = ok(WorkQueueSnapshotV1::create(
        "suspended-owner-snapshot".to_owned(),
        &fixture.policy,
        2,
        vec![suspended_entry],
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["suspended-owner-snapshot".to_owned()],
    ));
    let suspended_tick = tick_for(
        &fixture.tick,
        "suspended-owner-tick",
        &suspended_snapshot,
        None,
        None,
    );
    let suspended_decision = ok(schedule_next_case(
        &fixture.policy,
        &suspended_snapshot,
        &suspended_tick,
        SchedulerEvaluationContextV1 {
            role_contract: &fixture.base.role_contract,
            case_contracts: std::slice::from_ref(&fixture.base.case_contract),
            case_instances: std::slice::from_ref(&fixture.base.case_instance),
            ownership_states: std::slice::from_ref(&suspended_ownership),
            role_instances: std::slice::from_ref(&suspended),
            leases: &[],
        },
    ));
    assert_eq!(
        suspended_decision.outcome,
        SchedulerOutcomeV1::OwnerReassignmentRequired
    );

    let leased_entry = ok(project_case_to_queue(
        &fixture.policy,
        &fixture.base.case_contract,
        &fixture.base.case_instance,
        &fixture.leased_ownership,
        &fixture.base.role_instance,
        NOW,
        1,
        digest('c'),
        digest('a'),
        digest('b'),
        vec!["active-lease-entry".to_owned()],
    ));
    let leased_snapshot = ok(WorkQueueSnapshotV1::create(
        "leased-snapshot".to_owned(),
        &fixture.policy,
        2,
        vec![leased_entry],
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["leased-snapshot".to_owned()],
    ));
    let leased_tick = tick_for(&fixture.tick, "leased-tick", &leased_snapshot, None, None);
    let leased_decision = ok(schedule_next_case(
        &fixture.policy,
        &leased_snapshot,
        &leased_tick,
        evaluation_context(
            &fixture,
            &fixture.leased_ownership,
            &fixture.base.role_instance,
            std::slice::from_ref(&fixture.lease),
        ),
    ));
    assert_eq!(leased_decision.outcome, SchedulerOutcomeV1::NoEligibleCase);

    let mut stale_tick = fixture.tick.clone();
    stale_tick.current_case_ledger_head = digest('9');
    stale_tick.tick_sha256 = ZERO_HASH.to_owned();
    let stale_tick = ok(stale_tick.seal());
    assert!(matches!(
        schedule_next_case(
            &fixture.policy,
            &fixture.snapshot,
            &stale_tick,
            evaluation_context(
                &fixture,
                &fixture.ownership,
                &fixture.base.role_instance,
                &[],
            ),
        ),
        Err(WorkQueueError::Integrity(_))
    ));
}

#[test]
fn opaque_cross_domain_ids_share_one_queue_contract_without_core_branches() {
    let reference = queue_fixture();
    for work_class_id in [
        "office.record.update",
        "hr.employee.record.review",
        "it.service.ticket.review",
        "safety.training.followup",
    ] {
        let mut policy = reference.policy.clone();
        policy.policy_id = format!("opaque-policy-{}", work_class_id.replace('.', "-"));
        policy.allowed_work_class_ids = vec![work_class_id.to_owned()];
        policy.policy_sha256 = ZERO_HASH.to_owned();
        let first = ok(policy.clone().seal());
        let second = ok(policy.seal());
        assert_eq!(first.policy_sha256, second.policy_sha256);
    }
    let core = concat!(
        include_str!("../src/contract.rs"),
        include_str!("../src/scheduler.rs")
    );
    for domain_id in [
        "office.record.update",
        "hr.employee",
        "it.service",
        "safety.training",
    ] {
        assert!(!core.contains(domain_id));
    }
}

#[test]
fn maximum_queue_128_cases_replays_100_times_with_identical_artifacts() {
    let bases = distinct_fixtures(128);
    let reference = queue_fixture();
    let mut unsigned_pool = reference.pool.clone();
    unsigned_pool.members[0].non_terminal_case_count = 128;
    unsigned_pool.approval_signature.clear();
    unsigned_pool.pool_sha256 = ZERO_HASH.to_owned();
    let signing_key = SigningKey::from_bytes(&[41_u8; 32]);
    let pool = ok(create_case_ownership_pool(unsigned_pool, &signing_key));
    ok(verify_case_ownership_pool(
        &pool,
        "ownership-pool-key-v1",
        &signing_key.verifying_key(),
        std::slice::from_ref(&bases[0].role_instance),
        NOW,
    ));

    let mut ownerships = Vec::with_capacity(128);
    let mut entries = Vec::with_capacity(128);
    for (index, base) in bases.iter().enumerate() {
        let ownership = ok(derive_initial_ownership(
            &base.case_contract,
            &base.case_instance,
            &base.role_instance,
            &reference.policy,
            &pool,
            NOW - 10,
            digest('a'),
            digest('b'),
            vec![format!("replay-origin-{index:03}")],
        ));
        let entry = ok(project_case_to_queue(
            &reference.policy,
            &base.case_contract,
            &base.case_instance,
            &ownership,
            &base.role_instance,
            NOW,
            index as u64 + 1,
            digest('c'),
            digest('a'),
            digest('b'),
            vec![format!("replay-entry-{index:03}")],
        ));
        ownerships.push(ownership);
        entries.push(entry);
    }
    entries.reverse();
    let snapshot = ok(WorkQueueSnapshotV1::create(
        "maximum-queue-snapshot".to_owned(),
        &reference.policy,
        1,
        entries,
        digest('b'),
        digest('a'),
        digest('d'),
        vec!["maximum-queue-replay".to_owned()],
    ));
    assert_eq!(snapshot.entries.len(), 128);
    let mut tick = reference.tick.clone();
    tick.tick_id = "maximum-queue-tick".to_owned();
    tick.queue_snapshot_sha256 = snapshot.snapshot_sha256.clone();
    tick.tick_sha256 = ZERO_HASH.to_owned();
    let tick = ok(tick.seal());
    let contracts = bases
        .iter()
        .map(|base| base.case_contract.clone())
        .collect::<Vec<_>>();
    let instances = bases
        .iter()
        .map(|base| base.case_instance.clone())
        .collect::<Vec<_>>();
    let roles = vec![bases[0].role_instance.clone()];
    let mut reports = Vec::with_capacity(100);
    for _ in 0..100 {
        let decision = ok(schedule_next_case(
            &reference.policy,
            &snapshot,
            &tick,
            SchedulerEvaluationContextV1 {
                role_contract: &bases[0].role_contract,
                case_contracts: &contracts,
                case_instances: &instances,
                ownership_states: &ownerships,
                role_instances: &roles,
                leases: &[],
            },
        ));
        let selected_case_id = required(decision.selected_case_id.as_ref(), "selected Case");
        let selected_index = contracts
            .iter()
            .position(|contract| &contract.case_id == selected_case_id)
            .unwrap_or_else(|| panic!("selected Case is absent"));
        let entry = &snapshot.entries[selected_index];
        let ownership = &ownerships[selected_index];
        let base = &bases[selected_index];
        let lease = ok(claim_case_lease(
            &reference.policy,
            &snapshot,
            &decision,
            entry,
            &base.case_contract,
            &base.case_instance,
            ownership,
            &base.role_instance,
            &[],
            1,
            1,
            NOW,
            digest('d'),
            digest('b'),
            digest('a'),
            vec!["maximum-queue-claim".to_owned()],
        ));
        let leased_ownership = ok(ownership.with_active_lease(Some(lease.lease_sha256.clone())));
        let grant = ok(create_case_work_grant(
            "maximum-queue-work-grant".to_owned(),
            1,
            &base.case_contract,
            &base.case_instance,
            &leased_ownership,
            &lease,
            NOW,
            vec!["maximum-queue-grant".to_owned()],
        ));
        reports.push(ok(NormalizedQueueReplayReportV1 {
            schema_version: 1,
            queue_entries: 128,
            eligible: decision.eligible_entry_count,
            waiting: decision.waiting_entry_count,
            blocked: 0,
            attention: decision.attention_entry_count,
            leased: 0,
            terminal_removed: decision.terminal_removed_count,
            examined_entries: decision.examined_entry_count,
            logical_operations: decision.logical_operations,
            input_bytes: ok(canonical_size(&snapshot)),
            output_bytes: ok(canonical_size(&decision)),
            peak_records: 128,
            queue_ordering_sha256: ok(queue_ordering_sha256(&snapshot)),
            queue_snapshot_sha256: snapshot.snapshot_sha256.clone(),
            scheduler_decision_sha256: decision.decision_sha256,
            lease_sha256: lease.lease_sha256,
            work_grant_sha256: grant.grant_sha256,
            ownership_state_sha256: leased_ownership.state_sha256,
            critical_error_count: 0,
            report_sha256: ZERO_HASH.to_owned(),
        }
        .seal()));
    }
    let report_hash = ok(verify_replay_reports(&reports, 100));
    assert_eq!(reports[0].eligible, 128);
    assert_eq!(reports[0].examined_entries, 128);
    assert_eq!(reports[0].critical_error_count, 0);
    assert!(report_hash.starts_with("sha256:"));
    println!(
        "D2I_MAXIMUM_QUEUE_SUMMARY={}",
        ok(serde_json::to_string(&serde_json::json!({
            "queue_size": reports[0].queue_entries,
            "replay_runs": reports.len(),
            "ordering_sha256": reports[0].queue_ordering_sha256,
            "snapshot_sha256": reports[0].queue_snapshot_sha256,
            "decision_sha256": reports[0].scheduler_decision_sha256,
            "lease_sha256": reports[0].lease_sha256,
            "grant_sha256": reports[0].work_grant_sha256,
            "ownership_sha256": reports[0].ownership_state_sha256,
            "logical_operations": reports[0].logical_operations,
            "critical_errors": reports[0].critical_error_count,
            "normalized_report_sha256": report_hash,
        })))
    );
}

fn required<'a, T>(value: Option<&'a T>, label: &str) -> &'a T {
    value.unwrap_or_else(|| panic!("{label} is absent"))
}

fn tick_for(
    template: &WorkSchedulerTickV1,
    tick_id: &str,
    snapshot: &WorkQueueSnapshotV1,
    local_minute_of_day: Option<u16>,
    logical_operation_budget: Option<u64>,
) -> WorkSchedulerTickV1 {
    let mut time = template.operational_time_context.clone();
    if let Some(minute) = local_minute_of_day {
        time.local_minute_of_day = minute;
    }
    time.context_sha256 = ZERO_HASH.to_owned();
    let mut tick = template.clone();
    tick.tick_id = tick_id.to_owned();
    tick.queue_snapshot_sha256 = snapshot.snapshot_sha256.clone();
    tick.operational_time_context = ok(time.seal());
    if let Some(budget) = logical_operation_budget {
        tick.logical_operation_budget = budget;
    }
    tick.tick_sha256 = ZERO_HASH.to_owned();
    ok(tick.seal())
}

fn evaluation_context<'a>(
    fixture: &'a QueueFixture,
    ownership: &'a CurrentCaseOwnershipStateV1,
    role: &'a d2i_role_contract::RoleInstanceV1,
    leases: &'a [CaseLeaseV1],
) -> SchedulerEvaluationContextV1<'a> {
    SchedulerEvaluationContextV1 {
        role_contract: &fixture.base.role_contract,
        case_contracts: std::slice::from_ref(&fixture.base.case_contract),
        case_instances: std::slice::from_ref(&fixture.base.case_instance),
        ownership_states: std::slice::from_ref(ownership),
        role_instances: std::slice::from_ref(role),
        leases,
    }
}
