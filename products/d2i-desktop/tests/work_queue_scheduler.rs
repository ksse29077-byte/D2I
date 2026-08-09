#![cfg(windows)]

#[allow(dead_code)]
#[path = "support/work_radar_intake_fixture.rs"]
mod work_radar_intake_fixture;

use d2i_desktop::{
    initialize_case_ledger, initialize_work_queue_ledger, persist_new_case,
    verify_work_queue_ledger, WorkQueueCoordinatorV1,
};
use d2i_role_contract::{
    create_role_delegation, RoleDelegationGrantV1, RoleInstanceStatusV1, RoleInstanceV1,
    RoleOperationalTimeContextV1,
};
use d2i_work_case::{CaseContractV1, WorkPriorityClassV1};
use d2i_work_intake::{RadarCheckpointV1, WorkIntakeDispositionV1, WorkIntakeReceiptV1};
use d2i_work_queue::*;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use work_radar_intake_fixture::{
    activate_governance, digest, evaluate, mapping, new_case_with_id, ok, registration, signal,
    source_approval, GovernanceFixture, NewCaseArtifacts, NOW,
};

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "d2i-work-queue-{label}-{}-{nonce}",
            std::process::id()
        ));
        ok(std::fs::create_dir_all(&root));
        Self(root)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct PersistedCase {
    artifacts: NewCaseArtifacts,
    intake_receipt_sha256: String,
}

#[test]
fn work_300_cases_queue_schedule_exclusive_lease_restart_reassign_and_grant() {
    let root = TempTree::new("general-office-e2e");
    let governance = activate_governance(&root.0.join("role"));
    let registration = registration(&governance);
    let source_approval = source_approval(&governance, &registration);
    let base_mapping = mapping(&governance, &registration);
    let mut checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["initial-queue-e2e-checkpoint".to_owned()],
    ));
    let mut case_ledger = ok(initialize_case_ledger(
        &root.0.join("case"),
        "case-ledger-work-400",
        &registration.organization_id,
        4096,
        (NOW - 100) * 1000,
    ));
    let priorities = [
        WorkPriorityClassV1::Urgent,
        WorkPriorityClassV1::Elevated,
        WorkPriorityClassV1::Normal,
        WorkPriorityClassV1::Routine,
    ];
    let semantics = ['1', '2', '3', '4'];
    let mut cases = Vec::new();
    for (index, priority) in priorities.into_iter().enumerate() {
        let sequence = index as u64 + 1;
        let mut intake_mapping = base_mapping.clone();
        intake_mapping.mapping_id = format!("mapping-office-record-update-{sequence}");
        intake_mapping.priority_class = priority;
        intake_mapping.mapping_sha256 = ZERO_HASH.to_owned();
        let intake_mapping = ok(intake_mapping.seal_against(
            &registration,
            &governance.contract,
            &governance.delegation,
        ));
        let work_signal = signal(
            &registration,
            &format!("internal-record-event-{sequence}"),
            sequence,
            semantics[index],
        );
        let evaluation = evaluate(
            &governance,
            &registration,
            &source_approval,
            &intake_mapping,
            &checkpoint,
            &work_signal,
            &case_ledger.verification().deduplication_entries,
        );
        assert!(evaluation.requires_case_creation());
        let artifacts = new_case_with_id(
            &governance,
            &evaluation,
            "case-ledger-work-400",
            &format!("case-office-record-update-{sequence}"),
        );
        let work_item = required(evaluation.work_item.as_ref(), "Work Item");
        let dedup = required(evaluation.deduplication_key.as_ref(), "deduplication key");
        let admission = required(evaluation.admission.as_ref(), "admission");
        ok(persist_new_case(
            &mut case_ledger,
            work_item,
            dedup,
            admission,
            &artifacts.contract,
            &artifacts.instance,
            &governance.role_ledger_head,
            &digest('5'),
            (NOW + sequence) * 1000,
        ));
        let next_checkpoint = ok(checkpoint.advance(
            &registration,
            &work_signal,
            sequence,
            digest(char::from_digit(u32::try_from(index + 10).unwrap_or(10), 16).unwrap_or('a')),
            vec![format!("checkpoint-{sequence}")],
        ));
        let receipt = intake_receipt(
            &source_approval.source_approval_sha256,
            &work_signal.signal_sha256,
            work_item.work_item_sha256.clone(),
            admission.decision_sha256.clone(),
            &artifacts,
            &checkpoint,
            &next_checkpoint,
            &governance.role_ledger_head,
            &case_ledger.verification().terminal_record_hash,
            sequence,
        );
        cases.push(PersistedCase {
            artifacts,
            intake_receipt_sha256: receipt.receipt_sha256,
        });
        checkpoint = next_checkpoint;
    }
    assert_eq!(case_ledger.verification().current_instances.len(), 4);
    let standby = standby_role(&governance);
    let policy = queue_policy(&governance, &standby);
    let pool_key = SigningKey::from_bytes(&[71_u8; 32]);
    let pool = ownership_pool(
        &governance,
        &standby,
        &cases[0].artifacts.contract,
        &pool_key,
    );
    let queue_root = root.0.join("queue");
    let ledger = ok(initialize_work_queue_ledger(
        &queue_root,
        "queue-ledger-general-office",
        &policy,
        &pool,
        4096,
        (NOW - 50) * 1000,
    ));
    drop(ledger);
    let mut coordinator = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    let case_head = case_ledger.verification().terminal_record_hash.clone();
    for (index, persisted) in cases.iter().enumerate() {
        ok(coordinator.reconcile_case(
            &persisted.artifacts.contract,
            &persisted.artifacts.instance,
            &governance.instance,
            persisted.intake_receipt_sha256.clone(),
            governance.role_ledger_head.clone(),
            case_head.clone(),
            digest('6'),
            (NOW + 20 + index as u64 * 2) * 1000,
        ));
    }
    assert_eq!(coordinator.verification().current_entries.len(), 4);
    let record_count_after_repair = coordinator.verification().record_count;
    ok(coordinator.reconcile_case(
        &cases[0].artifacts.contract,
        &cases[0].artifacts.instance,
        &governance.instance,
        cases[0].intake_receipt_sha256.clone(),
        governance.role_ledger_head.clone(),
        case_head.clone(),
        digest('6'),
        (NOW + 40) * 1000,
    ));
    assert_eq!(
        coordinator.verification().record_count,
        record_count_after_repair
    );
    let queue_head = coordinator.verification().terminal_record_hash.clone();
    let entries = coordinator
        .verification()
        .current_entries
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let ownerships = coordinator
        .verification()
        .current_ownership
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let mut stale_coordinator = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    let snapshot = ok(WorkQueueSnapshotV1::create(
        "general-office-snapshot-1".to_owned(),
        &policy,
        1,
        entries,
        case_head.clone(),
        governance.role_ledger_head.clone(),
        queue_head.clone(),
        vec!["protected-queue-snapshot".to_owned()],
    ));
    let tick = scheduler_tick(&governance, &policy, &snapshot, NOW + 100);
    let contracts = cases
        .iter()
        .map(|case| case.artifacts.contract.clone())
        .collect::<Vec<_>>();
    let instances = cases
        .iter()
        .map(|case| case.artifacts.instance.clone())
        .collect::<Vec<_>>();
    let decision = ok(schedule_next_case(
        &policy,
        &snapshot,
        &tick,
        SchedulerEvaluationContextV1 {
            role_contract: &governance.contract,
            case_contracts: &contracts,
            case_instances: &instances,
            ownership_states: &ownerships,
            role_instances: std::slice::from_ref(&governance.instance),
            leases: &[],
        },
    ));
    assert_eq!(decision.outcome, SchedulerOutcomeV1::CaseSelected);
    assert_eq!(
        decision.selected_case_id.as_deref(),
        Some("case-office-record-update-1")
    );
    let selected_index = 0;
    let selected = &cases[selected_index];
    let ownership = required(
        coordinator
            .verification()
            .current_ownership
            .get(&selected.artifacts.contract.case_id),
        "selected ownership",
    )
    .clone();
    let entry = required(
        coordinator
            .verification()
            .current_entries
            .get(&selected.artifacts.contract.case_id),
        "selected Queue entry",
    )
    .clone();
    ok(coordinator.record_scheduler_decision(
        &entry.case_id,
        &selected.intake_receipt_sha256,
        decision.clone(),
        digest('7'),
        (NOW + 101) * 1000,
    ));
    assert!(stale_coordinator
        .record_scheduler_decision(
            &entry.case_id,
            &selected.intake_receipt_sha256,
            decision.clone(),
            digest('7'),
            (NOW + 101) * 1000,
        )
        .is_err());
    drop(stale_coordinator);
    let lease = ok(claim_case_lease(
        &policy,
        &snapshot,
        &decision,
        &entry,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &ownership,
        &governance.instance,
        &[],
        1,
        1,
        NOW + 100,
        queue_head,
        case_head.clone(),
        governance.role_ledger_head.clone(),
        vec!["exclusive-general-office-lease".to_owned()],
    ));
    assert!(claim_case_lease(
        &policy,
        &snapshot,
        &decision,
        &entry,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &ownership,
        &governance.instance,
        std::slice::from_ref(&lease),
        2,
        2,
        NOW + 101,
        snapshot.queue_ledger_chain_head.clone(),
        case_head.clone(),
        governance.role_ledger_head.clone(),
        vec!["duplicate-claim".to_owned()],
    )
    .is_err());
    let leased_ownership = ok(ownership.with_active_lease(Some(lease.lease_sha256.clone())));
    let leased_entry = ok(project_case_to_queue(
        &policy,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &leased_ownership,
        &governance.instance,
        NOW + 100,
        entry.enqueue_sequence,
        selected.intake_receipt_sha256.clone(),
        governance.role_ledger_head.clone(),
        case_head.clone(),
        vec!["leased-queue-projection".to_owned()],
    ));
    ok(coordinator.record_lease(
        &selected.intake_receipt_sha256,
        lease.clone(),
        leased_ownership,
        leased_entry,
        digest('8'),
        (NOW + 102) * 1000,
    ));
    drop(coordinator);
    let mut coordinator = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    assert_eq!(
        coordinator
            .verification()
            .latest_leases
            .get(&entry.case_id)
            .map(|value| value.lease_sha256.as_str()),
        Some(lease.lease_sha256.as_str())
    );
    let expired = ok(terminate_case_lease(
        &lease,
        LeaseStatusV1::Expired,
        lease.expires_at_unix_seconds,
        coordinator.verification().terminal_record_hash.clone(),
    ));
    let released_ownership = ok(ownership.with_active_lease(None));
    let released_entry = ok(project_case_to_queue(
        &policy,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &released_ownership,
        &governance.instance,
        lease.expires_at_unix_seconds,
        entry.enqueue_sequence,
        selected.intake_receipt_sha256.clone(),
        governance.role_ledger_head.clone(),
        case_head.clone(),
        vec!["expired-queue-projection".to_owned()],
    ));
    ok(coordinator.record_lease(
        &selected.intake_receipt_sha256,
        expired,
        released_ownership,
        released_entry,
        digest('9'),
        lease.expires_at_unix_seconds * 1000,
    ));
    drop(coordinator);
    let mut coordinator = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    assert_eq!(
        coordinator.verification().latest_leases[&entry.case_id].lease_status,
        LeaseStatusV1::Expired
    );
    let suspended = ok(governance.instance.transition(
        RoleInstanceStatusV1::Suspended,
        lease.expires_at_unix_seconds + 1,
    ));
    let suspended_role_head = digest('a');
    let (suspended_ownership, unavailable_entry) = ok(coordinator.reconcile_case(
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &suspended,
        selected.intake_receipt_sha256.clone(),
        suspended_role_head.clone(),
        case_head.clone(),
        digest('b'),
        (lease.expires_at_unix_seconds + 2) * 1000,
    ));
    assert_eq!(unavailable_entry.queue_lane, QueueLaneV1::OwnerUnavailable);
    let consumed = coordinator.verification().consumed_transfer_ids.clone();
    let (transfer, next_ownership) = ok(transfer_case_ownership(
        "transfer-office-case-1".to_owned(),
        AutomaticReassignmentReasonV1::OwnerSuspended,
        &policy,
        &pool,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &unavailable_entry,
        &suspended_ownership,
        &suspended,
        &standby.instance,
        &standby.delegation,
        &consumed,
        lease.expires_at_unix_seconds + 3,
        coordinator.verification().terminal_record_hash.clone(),
        case_head.clone(),
        suspended_role_head.clone(),
        vec!["approved-owner-suspension-transfer".to_owned()],
    ));
    assert_eq!(next_ownership.ownership_generation, 2);
    let transferred_entry = ok(project_case_to_queue(
        &policy,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &next_ownership,
        &standby.instance,
        lease.expires_at_unix_seconds + 3,
        entry.enqueue_sequence,
        selected.intake_receipt_sha256.clone(),
        suspended_role_head.clone(),
        case_head.clone(),
        vec!["transferred-queue-projection".to_owned()],
    ));
    ok(coordinator.record_transfer(
        &selected.intake_receipt_sha256,
        transfer,
        next_ownership.clone(),
        transferred_entry.clone(),
        digest('c'),
        (lease.expires_at_unix_seconds + 4) * 1000,
    ));
    drop(coordinator);
    let mut coordinator = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    assert_eq!(
        coordinator.verification().current_ownership[&entry.case_id].ownership_generation,
        2
    );
    assert_eq!(
        coordinator.verification().current_entries[&entry.case_id].current_role_instance_id,
        standby.instance.role_instance_id
    );
    for (index, persisted) in cases.iter().enumerate().skip(1) {
        ok(coordinator.reconcile_case(
            &persisted.artifacts.contract,
            &persisted.artifacts.instance,
            &suspended,
            persisted.intake_receipt_sha256.clone(),
            suspended_role_head.clone(),
            case_head.clone(),
            digest('c'),
            (lease.expires_at_unix_seconds + 5 + index as u64) * 1000,
        ));
    }
    let post_snapshot = ok(WorkQueueSnapshotV1::create(
        "general-office-snapshot-2".to_owned(),
        &policy,
        2,
        coordinator
            .verification()
            .current_entries
            .values()
            .cloned()
            .collect(),
        case_head.clone(),
        suspended_role_head.clone(),
        coordinator.verification().terminal_record_hash.clone(),
        vec!["post-transfer-snapshot".to_owned()],
    ));
    let post_tick = scheduler_tick(
        &governance,
        &policy,
        &post_snapshot,
        lease.expires_at_unix_seconds + 9,
    );
    let current_ownerships = coordinator
        .verification()
        .current_ownership
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let post_decision = ok(schedule_next_case(
        &policy,
        &post_snapshot,
        &post_tick,
        SchedulerEvaluationContextV1 {
            role_contract: &governance.contract,
            case_contracts: &contracts,
            case_instances: &instances,
            ownership_states: &current_ownerships,
            role_instances: &[standby.instance.clone(), suspended.clone()],
            leases: &[],
        },
    ));
    assert_eq!(
        post_decision.selected_role_instance_id.as_ref(),
        Some(&standby.instance.role_instance_id)
    );
    assert!(claim_case_lease(
        &policy,
        &post_snapshot,
        &post_decision,
        &transferred_entry,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &next_ownership,
        &governance.instance,
        &[],
        2,
        2,
        lease.expires_at_unix_seconds + 9,
        post_snapshot.queue_ledger_chain_head.clone(),
        case_head.clone(),
        suspended_role_head.clone(),
        vec!["old-owner-substitution".to_owned()],
    )
    .is_err());
    let lease_history = coordinator
        .verification()
        .latest_leases
        .values()
        .cloned()
        .collect::<Vec<_>>();
    let standby_lease = ok(claim_case_lease(
        &policy,
        &post_snapshot,
        &post_decision,
        &transferred_entry,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &next_ownership,
        &standby.instance,
        &lease_history,
        2,
        2,
        lease.expires_at_unix_seconds + 9,
        post_snapshot.queue_ledger_chain_head.clone(),
        case_head.clone(),
        suspended_role_head.clone(),
        vec!["standby-exclusive-lease".to_owned()],
    ));
    let standby_leased_ownership =
        ok(next_ownership.with_active_lease(Some(standby_lease.lease_sha256.clone())));
    let standby_leased_entry = ok(project_case_to_queue(
        &policy,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &standby_leased_ownership,
        &standby.instance,
        lease.expires_at_unix_seconds + 9,
        transferred_entry.enqueue_sequence,
        selected.intake_receipt_sha256.clone(),
        suspended_role_head.clone(),
        case_head.clone(),
        vec!["standby-leased-queue-projection".to_owned()],
    ));
    ok(coordinator.record_lease(
        &selected.intake_receipt_sha256,
        standby_lease.clone(),
        standby_leased_ownership.clone(),
        standby_leased_entry.clone(),
        digest('d'),
        (lease.expires_at_unix_seconds + 10) * 1000,
    ));
    let grant = ok(create_case_work_grant(
        "case-work-grant-office-1".to_owned(),
        1,
        &selected.artifacts.contract,
        &selected.artifacts.instance,
        &standby_leased_ownership,
        &standby_lease,
        lease.expires_at_unix_seconds + 9,
        vec!["non-executable-planner-handoff".to_owned()],
    ));
    let grant_sha256 = grant.grant_sha256.clone();
    ok(coordinator.record_work_grant(
        &selected.intake_receipt_sha256,
        grant,
        digest('d'),
        (lease.expires_at_unix_seconds + 11) * 1000,
    ));
    let receipt = ok(WorkQueueOperationReceiptV1 {
        schema_version: 1,
        receipt_id: "receipt-work-grant-office-1".to_owned(),
        operation_kind: QueueOperationKindV1::WorkGrantCreated,
        queue_id: policy.queue_id.clone(),
        case_id: selected.artifacts.contract.case_id.clone(),
        source_intake_receipt_sha256: selected.intake_receipt_sha256.clone(),
        queue_entry_sha256: Some(standby_leased_entry.entry_sha256),
        scheduler_decision_sha256: Some(post_decision.decision_sha256),
        lease_sha256: Some(standby_lease.lease_sha256),
        ownership_state_sha256: Some(standby_leased_ownership.state_sha256),
        ownership_transfer_sha256: next_ownership.transfer_sha256.clone(),
        work_grant_sha256: Some(grant_sha256),
        role_ledger_chain_head: suspended_role_head.clone(),
        case_ledger_chain_head: case_head.clone(),
        queue_ledger_chain_head: coordinator.verification().terminal_record_hash.clone(),
        recorded_at_unix_seconds: lease.expires_at_unix_seconds + 12,
        evidence_ids: vec!["recovered-operation-receipt".to_owned()],
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(coordinator.record_operation_receipt(
        receipt,
        digest('e'),
        (lease.expires_at_unix_seconds + 12) * 1000,
    ));
    let verified = ok(verify_work_queue_ledger(&queue_root));
    assert_eq!(verified.current_entries.len(), 4);
    assert_eq!(
        verified.current_ownership[&entry.case_id].ownership_generation,
        2
    );
    assert!(verified.ownership_history[&entry.case_id].len() >= 3);
    assert_eq!(
        verified.consumed_transfer_ids,
        vec!["transfer-office-case-1"]
    );
    assert_eq!(verified.consumed_work_grant_hashes.len(), 1);
    assert_eq!(verified.operation_receipt_hashes.len(), 1);
}

#[test]
fn protected_queue_ledger_rejects_tamper_and_concurrent_writer() {
    let root = TempTree::new("tamper");
    let governance = activate_governance(&root.0.join("role"));
    let standby = standby_role(&governance);
    let dummy_contract = general_office_contract_stub(&governance);
    let policy = queue_policy(&governance, &standby);
    let key = SigningKey::from_bytes(&[71_u8; 32]);
    let pool = ownership_pool(&governance, &standby, &dummy_contract, &key);
    let queue_root = root.0.join("queue");
    let ledger = ok(initialize_work_queue_ledger(
        &queue_root,
        "queue-ledger-tamper",
        &policy,
        &pool,
        128,
        (NOW - 1) * 1000,
    ));
    drop(ledger);
    let first = ok(WorkQueueCoordinatorV1::open(
        &queue_root,
        policy.clone(),
        pool.clone(),
    ));
    let second = ok(WorkQueueCoordinatorV1::open(&queue_root, policy, pool));
    assert_eq!(first.verification(), second.verification());
    drop(first);
    drop(second);
    let state_path = queue_root.join("work-queue-ledger-state.json");
    let mut bytes = ok(std::fs::read(&state_path));
    if let Some(byte) = bytes.iter_mut().find(|byte| **byte == b'{') {
        *byte = b'[';
    }
    ok(std::fs::write(&state_path, bytes));
    assert!(verify_work_queue_ledger(&queue_root).is_err());
}

struct StandbyRole {
    delegation: RoleDelegationGrantV1,
    instance: RoleInstanceV1,
}

fn standby_role(governance: &GovernanceFixture) -> StandbyRole {
    let mut draft = governance.delegation.clone();
    draft.delegation_id = "delegation-general-office-standby".to_owned();
    draft.role_instance_id = "general-office-role-instance-standby".to_owned();
    draft.evidence_ids = vec!["standby-delegation".to_owned()];
    draft.delegation_signature = String::new();
    draft.delegation_sha256 = ZERO_HASH.to_owned();
    let delegation = ok(create_role_delegation(
        draft,
        &governance.contract,
        &governance.approval,
        &governance.delegation_key,
    ));
    let provisioned = ok(RoleInstanceV1::provision(
        delegation.role_instance_id.clone(),
        &governance.contract,
        &governance.approval,
        &delegation,
        "role-ledger-general-office".to_owned(),
        governance
            .instance
            .authority_projection_template_sha256
            .clone(),
        governance.instance.recovery_profile_template_sha256.clone(),
        vec!["standby-role-instance".to_owned()],
    ));
    let active = ok(provisioned.transition(RoleInstanceStatusV1::Active, NOW - 50));
    let instance = ok(active.bind_ledger_head(governance.role_ledger_head.clone()));
    StandbyRole {
        delegation,
        instance,
    }
}

fn queue_policy(governance: &GovernanceFixture, standby: &StandbyRole) -> WorkQueuePolicyV1 {
    ok(WorkQueuePolicyV1 {
        schema_version: 1,
        policy_id: "general-office-queue-policy".to_owned(),
        policy_version: "1.0.0".to_owned(),
        queue_id: "general-office-queue".to_owned(),
        organization_id: governance.instance.organization_id.clone(),
        role_contract_id: governance.contract.role_contract_id.clone(),
        role_version: governance.contract.role_version.clone(),
        role_contract_sha256: governance.contract.contract_sha256.clone(),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_role_instance_ids: vec![
            governance.instance.role_instance_id.clone(),
            standby.instance.role_instance_id.clone(),
        ],
        maximum_queue_entries: 128,
        maximum_entries_examined_per_tick: 128,
        claim_lease_duration_seconds: 300,
        minimum_lease_duration_seconds: 30,
        maximum_lease_duration_seconds: 900,
        maximum_lease_renewals: 2,
        maximum_concurrent_leases_per_role: 1,
        maximum_open_cases_per_role: 128,
        aging_interval_seconds: 300,
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
        evidence_ids: vec!["approved-general-office-queue-policy".to_owned()],
        policy_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn ownership_pool(
    governance: &GovernanceFixture,
    standby: &StandbyRole,
    contract: &CaseContractV1,
    key: &SigningKey,
) -> CaseOwnershipPoolV1 {
    let members = [
        (&governance.instance, &governance.delegation),
        (&standby.instance, &standby.delegation),
    ]
    .into_iter()
    .map(|(instance, delegation)| CaseOwnershipPoolMemberV1 {
        role_instance_id: instance.role_instance_id.clone(),
        role_instance_sha256: instance.instance_sha256.clone(),
        delegation_sha256: delegation.delegation_sha256.clone(),
        allowed_work_class_ids: vec![contract.work_class_id.clone()],
        allowed_responsibility_ids: vec![contract.responsibility_id.clone()],
        allowed_application_pack_ids: instance.application_pack_ids.clone(),
        allowed_integration_ids: instance.integration_ids.clone(),
        allowed_capability_ids: instance.capability_ids.clone(),
        active: true,
        expires_at_unix_seconds: instance.expires_at_unix_seconds,
        ownership_expires_at_unix_seconds: instance.expires_at_unix_seconds,
        active_lease_count: 0,
        non_terminal_case_count: 0,
    })
    .collect();
    let pool = ok(create_case_ownership_pool(
        CaseOwnershipPoolV1 {
            schema_version: 1,
            pool_id: "general-office-ownership-pool".to_owned(),
            pool_version: "1.0.0".to_owned(),
            organization_id: governance.instance.organization_id.clone(),
            role_contract_id: governance.contract.role_contract_id.clone(),
            role_version: governance.contract.role_version.clone(),
            role_contract_sha256: governance.contract.contract_sha256.clone(),
            members,
            allowed_work_class_ids: vec![contract.work_class_id.clone()],
            allowed_responsibility_ids: vec![contract.responsibility_id.clone()],
            allowed_application_pack_ids: governance.instance.application_pack_ids.clone(),
            allowed_integration_ids: governance.instance.integration_ids.clone(),
            allowed_capability_ids: governance.instance.capability_ids.clone(),
            maximum_risk: contract.risk_class,
            automatic_reassignment_reasons: vec![AutomaticReassignmentReasonV1::OwnerSuspended],
            maximum_concurrent_leases_per_role: 1,
            valid_from_unix_seconds: NOW - 100,
            expires_at_unix_seconds: governance.instance.expires_at_unix_seconds,
            signer_id: "organization-governance".to_owned(),
            signer_key_id: "ownership-pool-key-v1".to_owned(),
            evidence_ids: vec!["signed-general-office-ownership-pool".to_owned()],
            approval_signature: String::new(),
            pool_sha256: ZERO_HASH.to_owned(),
        },
        key,
    ));
    ok(verify_case_ownership_pool(
        &pool,
        "ownership-pool-key-v1",
        &key.verifying_key(),
        &[governance.instance.clone(), standby.instance.clone()],
        NOW,
    ));
    pool
}

fn scheduler_tick(
    governance: &GovernanceFixture,
    policy: &WorkQueuePolicyV1,
    snapshot: &WorkQueueSnapshotV1,
    now: u64,
) -> WorkSchedulerTickV1 {
    let time = ok(RoleOperationalTimeContextV1 {
        schema_version: 1,
        calendar_sha256: governance.contract.working_calendar.calendar_sha256.clone(),
        timezone_id: governance.contract.working_calendar.timezone_id.clone(),
        local_date: "2026-08-03".to_owned(),
        weekday: 0,
        local_minute_of_day: 600,
        utc_offset_minutes: 540,
        blackout_date_ids: Vec::new(),
        emergency_override_sha256: None,
        observed_at_unix_seconds: now,
        evidence_ids: vec!["trusted-work-400-clock".to_owned()],
        context_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(WorkSchedulerTickV1 {
        schema_version: 1,
        tick_id: format!("tick-{now}"),
        queue_id: policy.queue_id.clone(),
        queue_policy_sha256: policy.policy_sha256.clone(),
        queue_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        trusted_now_unix_seconds: now,
        operational_time_context: time,
        current_role_ledger_head: snapshot.role_ledger_chain_head.clone(),
        current_case_ledger_head: snapshot.case_ledger_chain_head.clone(),
        current_queue_ledger_head: snapshot.queue_ledger_chain_head.clone(),
        maximum_entries: 128,
        logical_operation_budget: 16_384,
        evidence_ids: vec!["bounded-scheduler-tick".to_owned()],
        tick_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[allow(clippy::too_many_arguments)]
fn intake_receipt(
    source_approval_sha256: &str,
    signal_sha256: &str,
    work_item_sha256: String,
    admission_sha256: String,
    artifacts: &NewCaseArtifacts,
    before: &RadarCheckpointV1,
    after: &RadarCheckpointV1,
    role_head: &str,
    case_head: &str,
    sequence: u64,
) -> WorkIntakeReceiptV1 {
    ok(WorkIntakeReceiptV1 {
        schema_version: 1,
        receipt_id: format!("work-400-intake-receipt-{sequence}"),
        cycle_id: format!("work-400-cycle-{sequence}"),
        cycle_sequence: sequence,
        signal_id: format!("signal-office-record-{sequence}"),
        signal_sha256: signal_sha256.to_owned(),
        source_approval_sha256: source_approval_sha256.to_owned(),
        source_envelope_sha256: Some(digest('e')),
        work_item_sha256: Some(work_item_sha256),
        admission_sha256: Some(admission_sha256),
        case_id: Some(artifacts.contract.case_id.clone()),
        case_contract_sha256: Some(artifacts.contract.contract_sha256.clone()),
        case_instance_sha256: Some(artifacts.instance.instance_sha256.clone()),
        duplicate_result: Some(d2i_work_case::WorkItemDeduplicationResultV1::New),
        disposition: WorkIntakeDispositionV1::AdmittedCaseCreated,
        reason_codes: vec!["intake-admitted".to_owned()],
        checkpoint_before_sha256: before.checkpoint_sha256.clone(),
        checkpoint_after_sha256: after.checkpoint_sha256.clone(),
        case_ledger_chain_head: case_head.to_owned(),
        role_ledger_chain_head: role_head.to_owned(),
        intake_ledger_chain_head: digest('f'),
        evidence_ids: vec!["protected-work-400-intake-receipt".to_owned()],
        decided_at_unix_seconds: NOW + sequence,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn required<'a, T>(value: Option<&'a T>, label: &str) -> &'a T {
    match value {
        Some(value) => value,
        None => panic!("{label} is absent"),
    }
}

fn general_office_contract_stub(governance: &GovernanceFixture) -> CaseContractV1 {
    let registration = registration(governance);
    let approval = source_approval(governance, &registration);
    let mapping = mapping(governance, &registration);
    let checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["stub-checkpoint".to_owned()],
    ));
    let work_signal = signal(&registration, "stub-event", 1, '1');
    let evaluation = evaluate(
        governance,
        &registration,
        &approval,
        &mapping,
        &checkpoint,
        &work_signal,
        &[],
    );
    new_case_with_id(governance, &evaluation, "stub-ledger", "stub-case")
        .contract
        .clone()
}
