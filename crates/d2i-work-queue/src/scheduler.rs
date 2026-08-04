use crate::contract::{contains, ensure_unique_ids, is_subset, normalize_ids, stale};
use crate::strict::{canonical_json_bytes, hash_without};
use crate::{
    authorization, integrity, invalid, replay, resource, AutomaticReassignmentReasonV1,
    CaseLeaseV1, CaseOwnershipPoolV1, CaseOwnershipTransferV1, CaseWorkGrantV1,
    CurrentCaseOwnershipStateV1, LeaseStatusV1, OwnershipAssignmentReasonV1, QueueLaneV1,
    SchedulerOutcomeV1, SchedulerReasonCodeV1, WorkQueueEntryV1, WorkQueueError, WorkQueuePolicyV1,
    WorkQueueSnapshotV1, WorkSchedulerDecisionV1, WorkSchedulerTickV1, MAX_QUEUE_ENTRIES,
    WORK_QUEUE_SCHEMA_VERSION, ZERO_HASH,
};
use d2i_role_contract::{
    RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1, RoleInstanceV1,
};
use d2i_work_case::{CaseContractV1, CaseInstanceV1, CaseLifecycleStatusV1, WorkPriorityClassV1};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

/// Exact current artifacts supplied to one pure Scheduler tick.
pub struct SchedulerEvaluationContextV1<'a> {
    pub role_contract: &'a RoleContractV1,
    pub case_contracts: &'a [CaseContractV1],
    pub case_instances: &'a [CaseInstanceV1],
    pub ownership_states: &'a [CurrentCaseOwnershipStateV1],
    pub role_instances: &'a [RoleInstanceV1],
    pub leases: &'a [CaseLeaseV1],
}

#[derive(Debug, Clone)]
struct EligibleCandidate<'a> {
    entry: &'a WorkQueueEntryV1,
    ownership: &'a CurrentCaseOwnershipStateV1,
    effective_priority: u32,
    resolve_breached: bool,
    begin_breached: bool,
    escalation_attention: bool,
}

/// Runs one bounded, deterministic, side-effect-free Scheduler tick.
pub fn schedule_next_case(
    policy: &WorkQueuePolicyV1,
    snapshot: &WorkQueueSnapshotV1,
    tick: &WorkSchedulerTickV1,
    context: SchedulerEvaluationContextV1<'_>,
) -> Result<WorkSchedulerDecisionV1, WorkQueueError> {
    policy.validate()?;
    snapshot.validate()?;
    tick.validate()?;
    context.role_contract.validate()?;
    if snapshot.queue_id != policy.queue_id
        || snapshot.queue_policy_sha256 != policy.policy_sha256
        || tick.queue_id != policy.queue_id
        || tick.queue_policy_sha256 != policy.policy_sha256
        || tick.queue_snapshot_sha256 != snapshot.snapshot_sha256
        || tick.current_case_ledger_head != snapshot.case_ledger_chain_head
        || tick.current_role_ledger_head != snapshot.role_ledger_chain_head
        || tick.current_queue_ledger_head != snapshot.queue_ledger_chain_head
        || context.role_contract.role_contract_id != policy.role_contract_id
        || context.role_contract.role_version != policy.role_version
        || context.role_contract.contract_sha256 != policy.role_contract_sha256
        || tick.maximum_entries > policy.maximum_entries_examined_per_tick
        || tick.logical_operation_budget > policy.logical_operation_budget
    {
        return integrity("Scheduler tick, snapshot, policy, contract, or ledger heads differ");
    }
    ensure_unique_ids(
        context
            .case_contracts
            .iter()
            .map(|value| value.case_id.as_str()),
        "Case contracts",
    )?;
    ensure_unique_ids(
        context
            .case_instances
            .iter()
            .map(|value| value.case_id.as_str()),
        "Case instances",
    )?;
    ensure_unique_ids(
        context
            .ownership_states
            .iter()
            .map(|value| value.case_id.as_str()),
        "ownership states",
    )?;
    ensure_unique_ids(
        context
            .role_instances
            .iter()
            .map(|value| value.role_instance_id.as_str()),
        "Role Instances",
    )?;

    let inside_window = operating_window_matches(context.role_contract, tick)?;
    if policy.require_inside_operating_calendar && !inside_window {
        return decision(
            tick,
            snapshot,
            SchedulerOutcomeV1::OutsideOperatingWindow,
            None,
            vec![SchedulerReasonCodeV1::OutsideOperatingWindow],
            0,
            0,
            0,
            0,
            1,
        );
    }
    if snapshot.entries.is_empty() {
        return decision(
            tick,
            snapshot,
            SchedulerOutcomeV1::QueueEmpty,
            None,
            vec![SchedulerReasonCodeV1::QueueEmpty],
            0,
            0,
            0,
            0,
            1,
        );
    }

    let examination_limit = usize::try_from(tick.maximum_entries).map_err(|_| {
        WorkQueueError::ResourceLimit("tick maximum entries overflowed usize".to_owned())
    })?;
    if snapshot.entries.len() > examination_limit {
        return decision(
            tick,
            snapshot,
            SchedulerOutcomeV1::ResourceLimit,
            None,
            vec![SchedulerReasonCodeV1::ResourceLimit],
            0,
            0,
            0,
            0,
            1,
        );
    }

    let mut candidates = Vec::new();
    let mut reasons = Vec::new();
    let mut waiting = 0_u32;
    let mut attention = 0_u32;
    let mut logical_operations = 1_u64;
    let mut owner_unavailable = false;

    for entry in &snapshot.entries {
        logical_operations = logical_operations.saturating_add(1);
        if logical_operations > tick.logical_operation_budget {
            return decision(
                tick,
                snapshot,
                SchedulerOutcomeV1::ResourceLimit,
                None,
                vec![SchedulerReasonCodeV1::ResourceLimit],
                candidates.len() as u32 + waiting + attention,
                candidates.len() as u32,
                waiting,
                attention,
                logical_operations,
            );
        }
        let contract = exact_case_contract(context.case_contracts, entry)?;
        let instance = exact_case_instance(context.case_instances, entry, contract)?;
        let ownership = exact_ownership(context.ownership_states, entry, contract)?;
        let role = exact_role(context.role_instances, entry, ownership, policy)?;
        if instance.current_status == CaseLifecycleStatusV1::Terminal {
            reasons.push(SchedulerReasonCodeV1::TerminalCase);
            waiting = waiting.saturating_add(1);
            continue;
        }
        if !matches!(role.current_status, RoleInstanceStatusV1::Active) {
            reasons.push(SchedulerReasonCodeV1::InactiveOwner);
            owner_unavailable = true;
            attention = attention.saturating_add(1);
            continue;
        }
        if tick.trusted_now_unix_seconds >= role.expires_at_unix_seconds
            || tick.trusted_now_unix_seconds >= ownership.ownership_expires_at_unix_seconds
        {
            reasons.push(SchedulerReasonCodeV1::OwnerExpired);
            owner_unavailable = true;
            attention = attention.saturating_add(1);
            continue;
        }
        if entry.active_lease_sha256.is_some()
            || context.leases.iter().any(|lease| {
                lease.case_id == entry.case_id && lease.is_active_at(tick.trusted_now_unix_seconds)
            })
        {
            reasons.push(SchedulerReasonCodeV1::ActiveLease);
            waiting = waiting.saturating_add(1);
            continue;
        }
        match entry.queue_lane {
            QueueLaneV1::Ready => {}
            QueueLaneV1::AwaitingVerification
                if policy.awaiting_verification_treatment
                    == crate::QueueStateTreatmentV1::Eligible => {}
            QueueLaneV1::AwaitingVerification => {
                reasons.push(SchedulerReasonCodeV1::AwaitingVerificationNotEligible);
                waiting = waiting.saturating_add(1);
                continue;
            }
            QueueLaneV1::WaitingClarification => {
                reasons.push(SchedulerReasonCodeV1::AwaitingClarification);
                waiting = waiting.saturating_add(1);
                continue;
            }
            QueueLaneV1::Blocked => {
                reasons.push(SchedulerReasonCodeV1::Blocked);
                waiting = waiting.saturating_add(1);
                continue;
            }
            QueueLaneV1::EscalationAttention => {
                reasons.push(SchedulerReasonCodeV1::EscalationAttention);
                attention = attention.saturating_add(1);
                continue;
            }
            QueueLaneV1::OwnerUnavailable => {
                reasons.push(SchedulerReasonCodeV1::InactiveOwner);
                owner_unavailable = true;
                attention = attention.saturating_add(1);
                continue;
            }
            QueueLaneV1::Leased => {
                reasons.push(SchedulerReasonCodeV1::ActiveLease);
                waiting = waiting.saturating_add(1);
                continue;
            }
            QueueLaneV1::TerminalRemoved => {
                reasons.push(SchedulerReasonCodeV1::TerminalCase);
                waiting = waiting.saturating_add(1);
                continue;
            }
        }
        let wait_seconds = tick
            .trusted_now_unix_seconds
            .saturating_sub(entry.received_at_unix_seconds);
        let aging_bucket = (wait_seconds / policy.aging_interval_seconds)
            .min(u64::from(policy.maximum_aging_buckets));
        let effective_priority = priority_rank(entry.priority_class)
            .saturating_add(u32::try_from(aging_bucket).unwrap_or(u32::MAX));
        candidates.push(EligibleCandidate {
            entry,
            ownership,
            effective_priority,
            resolve_breached: tick.trusted_now_unix_seconds >= entry.resolve_due_at_unix_seconds,
            begin_breached: tick.trusted_now_unix_seconds >= entry.begin_due_at_unix_seconds,
            escalation_attention: tick.trusted_now_unix_seconds
                >= entry.escalation_due_at_unix_seconds,
        });
    }

    candidates.sort_by(|left, right| {
        (
            Reverse(left.resolve_breached),
            Reverse(left.begin_breached),
            Reverse(left.escalation_attention),
            Reverse(left.effective_priority),
            left.entry.resolve_due_at_unix_seconds,
            left.entry.escalation_due_at_unix_seconds,
            left.entry.enqueue_sequence,
            &left.entry.case_id,
            &left.entry.case_contract_sha256,
        )
            .cmp(&(
                Reverse(right.resolve_breached),
                Reverse(right.begin_breached),
                Reverse(right.escalation_attention),
                Reverse(right.effective_priority),
                right.entry.resolve_due_at_unix_seconds,
                right.entry.escalation_due_at_unix_seconds,
                right.entry.enqueue_sequence,
                &right.entry.case_id,
                &right.entry.case_contract_sha256,
            ))
    });

    if let Some(selected) = candidates.first() {
        reasons.push(SchedulerReasonCodeV1::CaseSelected);
        let selected_fields = SelectedDecisionFields {
            case_id: selected.entry.case_id.clone(),
            queue_entry_sha256: selected.entry.entry_sha256.clone(),
            ownership_state_sha256: selected.ownership.state_sha256.clone(),
            role_instance_id: selected.ownership.current_role_instance_id.clone(),
            lease_duration_seconds: policy.claim_lease_duration_seconds,
        };
        return decision(
            tick,
            snapshot,
            SchedulerOutcomeV1::CaseSelected,
            Some(selected_fields),
            reasons,
            snapshot.entries.len() as u32,
            candidates.len() as u32,
            waiting,
            attention,
            logical_operations,
        );
    }
    let outcome = if owner_unavailable && policy.reassignment_allowed {
        SchedulerOutcomeV1::OwnerReassignmentRequired
    } else if attention > 0 {
        SchedulerOutcomeV1::EscalationAttentionRequired
    } else {
        SchedulerOutcomeV1::NoEligibleCase
    };
    reasons.push(SchedulerReasonCodeV1::NoEligibleCase);
    decision(
        tick,
        snapshot,
        outcome,
        None,
        reasons,
        snapshot.entries.len() as u32,
        0,
        waiting,
        attention,
        logical_operations,
    )
}

struct SelectedDecisionFields {
    case_id: String,
    queue_entry_sha256: String,
    ownership_state_sha256: String,
    role_instance_id: String,
    lease_duration_seconds: u64,
}

#[allow(clippy::too_many_arguments)]
fn decision(
    tick: &WorkSchedulerTickV1,
    snapshot: &WorkQueueSnapshotV1,
    outcome: SchedulerOutcomeV1,
    selected: Option<SelectedDecisionFields>,
    mut reasons: Vec<SchedulerReasonCodeV1>,
    examined: u32,
    eligible: u32,
    waiting: u32,
    attention: u32,
    logical_operations: u64,
) -> Result<WorkSchedulerDecisionV1, WorkQueueError> {
    if reasons.is_empty() {
        reasons.push(SchedulerReasonCodeV1::NoEligibleCase);
    }
    let (case_id, entry_hash, ownership_hash, role_id, lease_duration) =
        selected.map_or((None, None, None, None, None), |value| {
            (
                Some(value.case_id),
                Some(value.queue_entry_sha256),
                Some(value.ownership_state_sha256),
                Some(value.role_instance_id),
                Some(value.lease_duration_seconds),
            )
        });
    WorkSchedulerDecisionV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        decision_id: format!("scheduler-decision:{}", tick.tick_id),
        tick_sha256: tick.tick_sha256.clone(),
        queue_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        outcome,
        selected_case_id: case_id,
        selected_queue_entry_sha256: entry_hash,
        selected_ownership_state_sha256: ownership_hash,
        selected_role_instance_id: role_id,
        selected_lease_duration_seconds: lease_duration,
        ordered_reason_codes: reasons,
        examined_entry_count: examined,
        eligible_entry_count: eligible,
        waiting_entry_count: waiting,
        attention_entry_count: attention,
        terminal_removed_count: snapshot.terminal_removed_count,
        logical_operations,
        evidence_ids: vec!["deterministic-scheduler-v1".to_owned()],
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

#[allow(clippy::too_many_arguments)]
pub fn claim_case_lease(
    policy: &WorkQueuePolicyV1,
    snapshot: &WorkQueueSnapshotV1,
    decision: &WorkSchedulerDecisionV1,
    entry: &WorkQueueEntryV1,
    contract: &CaseContractV1,
    instance: &CaseInstanceV1,
    ownership: &CurrentCaseOwnershipStateV1,
    role: &RoleInstanceV1,
    lease_history: &[CaseLeaseV1],
    claim_sequence: u64,
    lease_epoch: u64,
    claimed_at_unix_seconds: u64,
    queue_ledger_chain_head: String,
    case_ledger_chain_head: String,
    role_ledger_chain_head: String,
    mut evidence_ids: Vec<String>,
) -> Result<CaseLeaseV1, WorkQueueError> {
    policy.validate()?;
    snapshot.validate()?;
    decision.validate()?;
    entry.validate()?;
    contract.validate()?;
    instance.validate_against(contract)?;
    ownership.validate()?;
    role.validate_shape()?;
    if decision.outcome != SchedulerOutcomeV1::CaseSelected
        || decision.queue_snapshot_sha256 != snapshot.snapshot_sha256
        || decision.selected_case_id.as_ref() != Some(&entry.case_id)
        || decision.selected_queue_entry_sha256.as_ref() != Some(&entry.entry_sha256)
        || decision.selected_ownership_state_sha256.as_ref() != Some(&ownership.state_sha256)
        || decision.selected_role_instance_id.as_ref() != Some(&role.role_instance_id)
        || entry.current_case_instance_sha256 != instance.instance_sha256
        || entry.case_contract_sha256 != contract.contract_sha256
        || entry.current_ownership_state_sha256 != ownership.state_sha256
        || ownership.active_lease_sha256.is_some()
        || role.current_status != RoleInstanceStatusV1::Active
        || claimed_at_unix_seconds >= role.expires_at_unix_seconds
        || instance.current_status == CaseLifecycleStatusV1::Terminal
        || queue_ledger_chain_head != snapshot.queue_ledger_chain_head
        || case_ledger_chain_head != snapshot.case_ledger_chain_head
        || role_ledger_chain_head != snapshot.role_ledger_chain_head
    {
        return stale("lease claim differs from current Scheduler, Case, owner, or ledger state");
    }
    if lease_history.iter().any(|lease| {
        lease.lease_epoch == lease_epoch
            || (lease.case_id == entry.case_id && lease.is_active_at(claimed_at_unix_seconds))
    }) {
        return replay("concurrent Case claim or lease epoch reuse");
    }
    let previous_lease = lease_history
        .iter()
        .filter(|lease| lease.case_id == entry.case_id)
        .max_by_key(|lease| lease.lease_epoch);
    if previous_lease.is_some_and(|lease| {
        lease_epoch != lease.lease_epoch.saturating_add(1) || claim_sequence <= lease.claim_sequence
    }) {
        return replay("Case claim does not advance the latest lease epoch and sequence");
    }
    let role_active_count = lease_history
        .iter()
        .filter(|lease| {
            lease.role_instance_id == role.role_instance_id
                && lease.is_active_at(claimed_at_unix_seconds)
        })
        .count();
    if role_active_count >= policy.maximum_concurrent_leases_per_role as usize {
        return resource("Role Instance active lease capacity is exhausted");
    }
    normalize_ids(&mut evidence_ids, "lease claim evidence", false)?;
    let duration = decision
        .selected_lease_duration_seconds
        .ok_or_else(|| WorkQueueError::Integrity("selected lease duration is absent".to_owned()))?;
    if duration < policy.minimum_lease_duration_seconds
        || duration > policy.maximum_lease_duration_seconds
    {
        return authorization("Scheduler-selected lease duration is outside policy");
    }
    let expiry = claimed_at_unix_seconds
        .checked_add(duration)
        .ok_or_else(|| WorkQueueError::ResourceLimit("lease expiry overflowed".to_owned()))?;
    let mut lease = CaseLeaseV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        claim_id: format!("claim:{}:{claim_sequence}", entry.case_id),
        lease_id: format!("lease:{}:{lease_epoch}", entry.case_id),
        case_id: entry.case_id.clone(),
        queue_entry_sha256: entry.entry_sha256.clone(),
        scheduler_decision_sha256: decision.decision_sha256.clone(),
        current_ownership_state_sha256: ownership.state_sha256.clone(),
        role_instance_id: role.role_instance_id.clone(),
        role_instance_sha256: role.instance_sha256.clone(),
        role_contract_sha256: role.contract_sha256.clone(),
        delegation_sha256: role.delegation_sha256.clone(),
        claim_sequence,
        lease_epoch,
        claimed_at_unix_seconds,
        expires_at_unix_seconds: expiry,
        renewal_count: 0,
        lease_status: LeaseStatusV1::Active,
        previous_lease_sha256: previous_lease.map(|lease| lease.lease_sha256.clone()),
        queue_ledger_chain_head,
        case_ledger_chain_head,
        role_ledger_chain_head,
        evidence_ids,
        lease_sha256: ZERO_HASH.to_owned(),
    };
    lease.lease_sha256 = hash_without(&lease, &["lease_sha256"])?;
    lease.validate()?;
    Ok(lease)
}

#[allow(clippy::too_many_arguments)]
pub fn renew_case_lease(
    policy: &WorkQueuePolicyV1,
    lease: &CaseLeaseV1,
    role: &RoleInstanceV1,
    renewed_at_unix_seconds: u64,
    duration_seconds: u64,
    queue_ledger_chain_head: String,
    case_ledger_chain_head: String,
    role_ledger_chain_head: String,
) -> Result<CaseLeaseV1, WorkQueueError> {
    policy.validate()?;
    lease.validate()?;
    role.validate_shape()?;
    if !lease.is_active_at(renewed_at_unix_seconds)
        || lease.renewal_count >= policy.maximum_lease_renewals
        || duration_seconds < policy.minimum_lease_duration_seconds
        || duration_seconds > policy.maximum_lease_duration_seconds
        || role.current_status != RoleInstanceStatusV1::Active
        || role.role_instance_id != lease.role_instance_id
        || role.instance_sha256 != lease.role_instance_sha256
        || renewed_at_unix_seconds >= role.expires_at_unix_seconds
    {
        return authorization("lease renewal is stale, exhausted, or owner-invalid");
    }
    let expiry = renewed_at_unix_seconds
        .checked_add(duration_seconds)
        .ok_or_else(|| {
            WorkQueueError::ResourceLimit("lease renewal expiry overflowed".to_owned())
        })?;
    let mut next = lease.clone();
    next.lease_epoch = lease.lease_epoch.saturating_add(1);
    next.lease_id = format!("lease:{}:{}", lease.case_id, next.lease_epoch);
    next.claimed_at_unix_seconds = renewed_at_unix_seconds;
    next.expires_at_unix_seconds = expiry.min(role.expires_at_unix_seconds);
    next.renewal_count = lease.renewal_count.saturating_add(1);
    next.lease_status = LeaseStatusV1::Renewed;
    next.previous_lease_sha256 = Some(lease.lease_sha256.clone());
    next.queue_ledger_chain_head = queue_ledger_chain_head;
    next.case_ledger_chain_head = case_ledger_chain_head;
    next.role_ledger_chain_head = role_ledger_chain_head;
    next.lease_sha256 = hash_without(&next, &["lease_sha256"])?;
    next.validate()?;
    Ok(next)
}

pub fn terminate_case_lease(
    lease: &CaseLeaseV1,
    status: LeaseStatusV1,
    at_unix_seconds: u64,
    queue_ledger_chain_head: String,
) -> Result<CaseLeaseV1, WorkQueueError> {
    lease.validate()?;
    if !matches!(
        status,
        LeaseStatusV1::Released | LeaseStatusV1::Expired | LeaseStatusV1::Revoked
    ) || !matches!(
        lease.lease_status,
        LeaseStatusV1::Active | LeaseStatusV1::Renewed
    ) || at_unix_seconds < lease.claimed_at_unix_seconds
        || (status == LeaseStatusV1::Expired && at_unix_seconds < lease.expires_at_unix_seconds)
    {
        return invalid("lease terminal transition or time is invalid");
    }
    let mut next = lease.clone();
    next.lease_status = status;
    next.previous_lease_sha256 = Some(lease.lease_sha256.clone());
    next.queue_ledger_chain_head = queue_ledger_chain_head;
    next.lease_sha256 = hash_without(&next, &["lease_sha256"])?;
    next.validate()?;
    Ok(next)
}

#[allow(clippy::too_many_arguments)]
pub fn transfer_case_ownership(
    transfer_id: String,
    reason: AutomaticReassignmentReasonV1,
    policy: &WorkQueuePolicyV1,
    pool: &CaseOwnershipPoolV1,
    contract: &CaseContractV1,
    instance: &CaseInstanceV1,
    entry: &WorkQueueEntryV1,
    current: &CurrentCaseOwnershipStateV1,
    source_role: &RoleInstanceV1,
    target_role: &RoleInstanceV1,
    target_delegation: &RoleDelegationGrantV1,
    consumed_transfer_ids: &[String],
    transfer_at_unix_seconds: u64,
    queue_ledger_chain_head: String,
    case_ledger_chain_head: String,
    role_ledger_chain_head: String,
    mut evidence_ids: Vec<String>,
) -> Result<(CaseOwnershipTransferV1, CurrentCaseOwnershipStateV1), WorkQueueError> {
    policy.validate()?;
    pool.validate()?;
    contract.validate()?;
    instance.validate_against(contract)?;
    entry.validate()?;
    current.validate()?;
    source_role.validate_shape()?;
    target_role.validate_shape()?;
    if consumed_transfer_ids.binary_search(&transfer_id).is_ok() {
        return replay("ownership transfer ID was already consumed");
    }
    if !policy.reassignment_allowed
        || !policy.automatic_reassignment_reasons.contains(&reason)
        || !pool.automatic_reassignment_reasons.contains(&reason)
        || current.active_lease_sha256.is_some()
        || entry.active_lease_sha256.is_some()
        || instance.current_status == CaseLifecycleStatusV1::Terminal
        || current.case_id != contract.case_id
        || entry.case_id != contract.case_id
        || entry.current_case_instance_sha256 != instance.instance_sha256
        || entry.current_ownership_state_sha256 != current.state_sha256
        || current.current_role_instance_id != source_role.role_instance_id
        || current.current_role_contract_sha256 != source_role.contract_sha256
        || current.current_delegation_sha256 != source_role.delegation_sha256
        || source_role.role_instance_id == target_role.role_instance_id
        || target_role.current_status != RoleInstanceStatusV1::Active
        || transfer_at_unix_seconds >= target_role.expires_at_unix_seconds
        || contract.organization_id != target_role.organization_id
        || contract.role_contract_sha256 != target_role.contract_sha256
        || contract.ownership_binding.role_contract_id != target_role.role_contract_id
        || contract.ownership_binding.role_version != target_role.role_version
        || target_delegation.role_instance_id != target_role.role_instance_id
        || target_delegation.delegation_sha256 != target_role.delegation_sha256
        || !contains(
            &target_delegation.delegated_work_class_ids,
            &contract.work_class_id,
        )
        || !is_subset(
            &contract.allowed_integration_ids,
            &target_delegation.delegated_integration_ids,
        )
        || !is_subset(
            &contract.allowed_capability_ids,
            &target_delegation.delegated_capability_ids,
        )
        || !contract
            .allowed_application_pack_refs
            .iter()
            .all(|reference| {
                contains(
                    &target_delegation.delegated_application_pack_ids,
                    &reference.application_pack_id,
                )
            })
        || case_ledger_chain_head != entry.last_reconciled_case_ledger_head
        || role_ledger_chain_head != entry.last_reconciled_role_ledger_head
    {
        return authorization("ownership transfer expands scope or uses stale/invalid state");
    }
    crate::contract::validate_hash(&queue_ledger_chain_head, "transfer Queue ledger head")?;
    let source_status_matches_reason = matches!(
        (reason, source_role.current_status),
        (
            AutomaticReassignmentReasonV1::OwnerSuspended,
            RoleInstanceStatusV1::Suspended
        ) | (
            AutomaticReassignmentReasonV1::OwnerRevoked,
            RoleInstanceStatusV1::Revoked
        ) | (
            AutomaticReassignmentReasonV1::OwnerExpired,
            RoleInstanceStatusV1::Expired
        ) | (
            AutomaticReassignmentReasonV1::OwnerCapacityExhausted,
            RoleInstanceStatusV1::Active
        ) | (
            AutomaticReassignmentReasonV1::LeaseRecovery,
            RoleInstanceStatusV1::Active
        ) | (
            AutomaticReassignmentReasonV1::CoordinatorRecovery,
            RoleInstanceStatusV1::Active
        )
    );
    if !source_status_matches_reason {
        return authorization("ownership transfer reason differs from source Role status");
    }
    if !risk_within(contract.risk_class, pool.maximum_risk) {
        return authorization("ownership transfer expands approved risk scope");
    }
    let member = pool
        .members
        .iter()
        .find(|member| member.role_instance_id == target_role.role_instance_id)
        .ok_or_else(|| {
            WorkQueueError::Authorization("target Role is outside ownership pool".to_owned())
        })?;
    if member.role_instance_sha256 != target_role.instance_sha256
        || member.delegation_sha256 != target_role.delegation_sha256
        || !member.active
        || transfer_at_unix_seconds >= member.expires_at_unix_seconds
        || member.active_lease_count >= pool.maximum_concurrent_leases_per_role
        || !contains(&member.allowed_work_class_ids, &contract.work_class_id)
        || !contains(
            &member.allowed_responsibility_ids,
            &contract.responsibility_id,
        )
    {
        return authorization("target Role pool membership or capacity differs");
    }
    normalize_ids(&mut evidence_ids, "ownership transfer evidence", false)?;
    let next_generation = current.ownership_generation.checked_add(1).ok_or_else(|| {
        WorkQueueError::ResourceLimit("ownership generation overflowed".to_owned())
    })?;
    if next_generation > policy.maximum_ownership_generations {
        return resource("ownership generation limit is exhausted");
    }
    let transfer = CaseOwnershipTransferV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        transfer_id,
        case_id: contract.case_id.clone(),
        case_contract_sha256: contract.contract_sha256.clone(),
        current_case_instance_sha256: instance.instance_sha256.clone(),
        current_queue_entry_sha256: entry.entry_sha256.clone(),
        previous_ownership_state_sha256: current.state_sha256.clone(),
        source_role_instance_id: source_role.role_instance_id.clone(),
        source_role_instance_sha256: source_role.instance_sha256.clone(),
        target_role_instance_id: target_role.role_instance_id.clone(),
        target_role_instance_sha256: target_role.instance_sha256.clone(),
        organization_id: contract.organization_id.clone(),
        role_contract_id: target_role.role_contract_id.clone(),
        role_version: target_role.role_version.clone(),
        role_contract_sha256: target_role.contract_sha256.clone(),
        responsibility_id: contract.responsibility_id.clone(),
        work_class_id: contract.work_class_id.clone(),
        ownership_pool_sha256: pool.pool_sha256.clone(),
        transfer_reason: reason,
        transfer_at_unix_seconds,
        current_case_ledger_head: case_ledger_chain_head.clone(),
        current_queue_ledger_head: queue_ledger_chain_head,
        current_role_ledger_head: role_ledger_chain_head.clone(),
        next_ownership_generation: next_generation,
        evidence_ids: evidence_ids.clone(),
        transfer_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let mut next = CurrentCaseOwnershipStateV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        ownership_state_id: format!("ownership-state:{}:{next_generation}", contract.case_id),
        case_id: contract.case_id.clone(),
        case_contract_sha256: contract.contract_sha256.clone(),
        origin_ownership_sha256: current.origin_ownership_sha256.clone(),
        ownership_generation: next_generation,
        current_role_instance_id: target_role.role_instance_id.clone(),
        current_role_instance_sha256: target_role.instance_sha256.clone(),
        current_role_contract_id: target_role.role_contract_id.clone(),
        current_role_version: target_role.role_version.clone(),
        current_role_contract_sha256: target_role.contract_sha256.clone(),
        current_delegation_sha256: target_role.delegation_sha256.clone(),
        organization_id: contract.organization_id.clone(),
        responsibility_id: contract.responsibility_id.clone(),
        work_class_id: contract.work_class_id.clone(),
        previous_ownership_state_sha256: Some(current.state_sha256.clone()),
        ownership_pool_sha256: pool.pool_sha256.clone(),
        queue_policy_sha256: policy.policy_sha256.clone(),
        assignment_reason: OwnershipAssignmentReasonV1::ApprovedTransfer,
        assigned_at_unix_seconds: transfer_at_unix_seconds,
        ownership_expires_at_unix_seconds: member
            .ownership_expires_at_unix_seconds
            .min(target_role.expires_at_unix_seconds),
        active_lease_sha256: None,
        transfer_sha256: Some(transfer.transfer_sha256.clone()),
        role_ledger_chain_head,
        case_ledger_chain_head,
        evidence_ids,
        state_sha256: ZERO_HASH.to_owned(),
    };
    next.state_sha256 = hash_without(&next, &["state_sha256"])?;
    next.validate()?;
    Ok((transfer, next))
}

#[allow(clippy::too_many_arguments)]
pub fn create_case_work_grant(
    grant_id: String,
    grant_sequence: u64,
    contract: &CaseContractV1,
    instance: &CaseInstanceV1,
    ownership: &CurrentCaseOwnershipStateV1,
    lease: &CaseLeaseV1,
    issued_at_unix_seconds: u64,
    mut evidence_ids: Vec<String>,
) -> Result<CaseWorkGrantV1, WorkQueueError> {
    contract.validate()?;
    instance.validate_against(contract)?;
    ownership.validate()?;
    lease.validate()?;
    if !lease.is_active_at(issued_at_unix_seconds)
        || lease.case_id != contract.case_id
        || ownership.active_lease_sha256.as_ref() != Some(&lease.lease_sha256)
        || lease.role_instance_id != ownership.current_role_instance_id
        || lease.role_instance_sha256 != ownership.current_role_instance_sha256
        || lease.role_contract_sha256 != ownership.current_role_contract_sha256
        || lease.delegation_sha256 != ownership.current_delegation_sha256
        || instance.current_status == CaseLifecycleStatusV1::Terminal
        || grant_sequence == 0
    {
        return authorization("Work Grant differs from active Case lease or owner");
    }
    let mut application_ids = contract
        .allowed_application_pack_refs
        .iter()
        .map(|reference| reference.application_pack_id.clone())
        .collect::<Vec<_>>();
    application_ids.sort();
    let mut unresolved = instance.unresolved_requirement_ids.clone();
    unresolved.sort();
    let mut integrations = contract.allowed_integration_ids.clone();
    integrations.sort();
    let mut capabilities = contract.allowed_capability_ids.clone();
    capabilities.sort();
    let mut targets = contract.allowed_semantic_target_ids.clone();
    targets.sort();
    normalize_ids(&mut evidence_ids, "Work Grant evidence", false)?;
    let mut grant = CaseWorkGrantV1 {
        schema_version: WORK_QUEUE_SCHEMA_VERSION,
        grant_id,
        case_id: contract.case_id.clone(),
        current_case_instance_sha256: instance.instance_sha256.clone(),
        case_contract_sha256: contract.contract_sha256.clone(),
        ownership_state_sha256: ownership.state_sha256.clone(),
        lease_sha256: lease.lease_sha256.clone(),
        selected_role_instance_id: ownership.current_role_instance_id.clone(),
        unresolved_requirement_ids: unresolved,
        allowed_application_pack_ids: application_ids,
        allowed_integration_ids: integrations,
        allowed_capability_ids: capabilities,
        semantic_target_ids: targets,
        valid_from_unix_seconds: issued_at_unix_seconds,
        expires_at_unix_seconds: lease.expires_at_unix_seconds,
        one_time_grant_sequence: grant_sequence,
        evidence_ids,
        grant_sha256: ZERO_HASH.to_owned(),
    };
    grant.grant_sha256 = hash_without(&grant, &["grant_sha256"])?;
    grant.validate()?;
    Ok(grant)
}

/// Stable replay evidence. Wall-clock timing is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedQueueReplayReportV1 {
    pub schema_version: u32,
    pub queue_entries: u32,
    pub eligible: u32,
    pub waiting: u32,
    pub blocked: u32,
    pub attention: u32,
    pub leased: u32,
    pub terminal_removed: u32,
    pub examined_entries: u32,
    pub logical_operations: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub peak_records: u32,
    pub queue_ordering_sha256: String,
    pub queue_snapshot_sha256: String,
    pub scheduler_decision_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
    pub ownership_state_sha256: String,
    pub critical_error_count: u32,
    pub report_sha256: String,
}

impl NormalizedQueueReplayReportV1 {
    pub fn seal(mut self) -> Result<Self, WorkQueueError> {
        for (value, label) in [
            (&self.queue_ordering_sha256, "replay ordering hash"),
            (&self.queue_snapshot_sha256, "replay snapshot hash"),
            (&self.scheduler_decision_sha256, "replay decision hash"),
            (&self.lease_sha256, "replay lease hash"),
            (&self.work_grant_sha256, "replay Work Grant hash"),
            (&self.ownership_state_sha256, "replay ownership hash"),
        ] {
            crate::contract::validate_hash(value, label)?;
        }
        self.report_sha256 = hash_without(&self, &["report_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), WorkQueueError> {
        if self.schema_version != WORK_QUEUE_SCHEMA_VERSION
            || self.queue_entries as usize > MAX_QUEUE_ENTRIES
            || self.examined_entries > self.queue_entries
            || self.peak_records < self.queue_entries
        {
            return invalid("normalized replay report counters are invalid");
        }
        for (value, label) in [
            (&self.queue_ordering_sha256, "replay ordering hash"),
            (&self.queue_snapshot_sha256, "replay snapshot hash"),
            (&self.scheduler_decision_sha256, "replay decision hash"),
            (&self.lease_sha256, "replay lease hash"),
            (&self.work_grant_sha256, "replay Work Grant hash"),
            (&self.ownership_state_sha256, "replay ownership hash"),
            (&self.report_sha256, "replay report hash"),
        ] {
            crate::contract::validate_hash(value, label)?;
        }
        if hash_without(self, &["report_sha256"])? != self.report_sha256 {
            return integrity("normalized replay report self-hash differs");
        }
        Ok(())
    }
}

fn exact_case_contract<'a>(
    values: &'a [CaseContractV1],
    entry: &WorkQueueEntryV1,
) -> Result<&'a CaseContractV1, WorkQueueError> {
    let value = values
        .iter()
        .find(|value| value.case_id == entry.case_id)
        .ok_or_else(|| {
            WorkQueueError::Integrity("Queue references an absent Case Contract".to_owned())
        })?;
    value.validate()?;
    if value.contract_sha256 != entry.case_contract_sha256 {
        return stale("Queue Case Contract hash is stale");
    }
    Ok(value)
}

fn exact_case_instance<'a>(
    values: &'a [CaseInstanceV1],
    entry: &WorkQueueEntryV1,
    contract: &CaseContractV1,
) -> Result<&'a CaseInstanceV1, WorkQueueError> {
    let value = values
        .iter()
        .find(|value| value.case_id == entry.case_id)
        .ok_or_else(|| {
            WorkQueueError::Integrity("Queue references an absent Case Instance".to_owned())
        })?;
    value.validate_against(contract)?;
    if value.instance_sha256 != entry.current_case_instance_sha256
        || value.lifecycle_generation != entry.case_lifecycle_generation
        || value.current_status != entry.current_lifecycle_status
        || value.active_block_sha256 != entry.active_block_sha256
    {
        return stale("Queue Case Instance projection is stale");
    }
    Ok(value)
}

fn exact_ownership<'a>(
    values: &'a [CurrentCaseOwnershipStateV1],
    entry: &WorkQueueEntryV1,
    contract: &CaseContractV1,
) -> Result<&'a CurrentCaseOwnershipStateV1, WorkQueueError> {
    let value = values
        .iter()
        .find(|value| value.case_id == entry.case_id)
        .ok_or_else(|| {
            WorkQueueError::Integrity("Queue references absent current ownership".to_owned())
        })?;
    value.validate()?;
    if value.state_sha256 != entry.current_ownership_state_sha256
        || value.case_contract_sha256 != contract.contract_sha256
        || value.current_role_instance_id != entry.current_role_instance_id
        || value.active_lease_sha256 != entry.active_lease_sha256
    {
        return stale("Queue current ownership projection is stale");
    }
    Ok(value)
}

fn exact_role<'a>(
    values: &'a [RoleInstanceV1],
    entry: &WorkQueueEntryV1,
    ownership: &CurrentCaseOwnershipStateV1,
    policy: &WorkQueuePolicyV1,
) -> Result<&'a RoleInstanceV1, WorkQueueError> {
    let value = values
        .iter()
        .find(|value| value.role_instance_id == entry.current_role_instance_id)
        .ok_or_else(|| {
            WorkQueueError::Integrity("Queue owner Role Instance is absent".to_owned())
        })?;
    value.validate_shape()?;
    if value.instance_sha256 != ownership.current_role_instance_sha256
        || value.contract_sha256 != policy.role_contract_sha256
        || value.organization_id != policy.organization_id
        || !contains(&policy.allowed_role_instance_ids, &value.role_instance_id)
        || !contains(&policy.allowed_work_class_ids, &entry.work_class_id)
    {
        return authorization("Queue owner differs from policy or ownership state");
    }
    Ok(value)
}

fn operating_window_matches(
    contract: &RoleContractV1,
    tick: &WorkSchedulerTickV1,
) -> Result<bool, WorkQueueError> {
    let time = &tick.operational_time_context;
    if time.calendar_sha256 != contract.working_calendar.calendar_sha256
        || time.timezone_id != contract.working_calendar.timezone_id
        || time.observed_at_unix_seconds != tick.trusted_now_unix_seconds
    {
        return integrity("Scheduler time context differs from Role calendar");
    }
    if contract
        .working_calendar
        .blackout_date_ids
        .binary_search(&time.local_date)
        .is_ok()
        || time.blackout_date_ids.iter().any(|id| {
            contract
                .working_calendar
                .blackout_date_ids
                .binary_search(id)
                .is_err()
        })
    {
        return Ok(false);
    }
    Ok(contract
        .working_calendar
        .weekly_windows
        .iter()
        .any(|window| {
            window.weekday == time.weekday
                && window.start_minute_local <= time.local_minute_of_day
                && time.local_minute_of_day < window.end_minute_local
        }))
}

const fn priority_rank(priority: WorkPriorityClassV1) -> u32 {
    match priority {
        WorkPriorityClassV1::Routine => 0,
        WorkPriorityClassV1::Normal => 1,
        WorkPriorityClassV1::Elevated => 2,
        WorkPriorityClassV1::Urgent => 3,
    }
}

const fn risk_rank(risk: d2i_cognitive_ir::CognitiveRiskClass) -> u8 {
    match risk {
        d2i_cognitive_ir::CognitiveRiskClass::ReadOnly => 0,
        d2i_cognitive_ir::CognitiveRiskClass::Reversible => 1,
        d2i_cognitive_ir::CognitiveRiskClass::BusinessStateChange => 2,
        d2i_cognitive_ir::CognitiveRiskClass::HighCriticality => 3,
    }
}

fn risk_within(
    value: d2i_cognitive_ir::CognitiveRiskClass,
    maximum: d2i_cognitive_ir::CognitiveRiskClass,
) -> bool {
    risk_rank(value) <= risk_rank(maximum)
}

/// Canonical hash of the ordered Queue entry identities.
pub fn queue_ordering_sha256(snapshot: &WorkQueueSnapshotV1) -> Result<String, WorkQueueError> {
    snapshot.validate()?;
    crate::canonical_sha256(
        &snapshot
            .entries
            .iter()
            .map(|entry| (&entry.case_id, &entry.entry_sha256))
            .collect::<Vec<_>>(),
    )
}

/// Ensures a replay bundle is finite and every report is byte-for-byte deterministic.
pub fn verify_replay_reports(
    reports: &[NormalizedQueueReplayReportV1],
    expected_runs: usize,
) -> Result<String, WorkQueueError> {
    if expected_runs == 0
        || expected_runs > crate::MAX_REPLAY_RECORDS
        || reports.len() != expected_runs
    {
        return resource("replay report count is incomplete or exceeds the bound");
    }
    let first = reports
        .first()
        .ok_or_else(|| WorkQueueError::ResourceLimit("replay report is empty".to_owned()))?;
    first.validate()?;
    for report in reports.iter().skip(1) {
        report.validate()?;
        if report != first {
            return integrity("deterministic replay report changed between runs");
        }
    }
    crate::canonical_sha256(first)
}

/// Rejects a second use of a one-time Work Grant sequence or hash.
pub fn consume_work_grant(
    grant: &CaseWorkGrantV1,
    consumed_grant_hashes: &[String],
    consumed_sequences: &[u64],
    now_unix_seconds: u64,
) -> Result<(), WorkQueueError> {
    grant.validate()?;
    if now_unix_seconds < grant.valid_from_unix_seconds
        || now_unix_seconds >= grant.expires_at_unix_seconds
    {
        return authorization("Work Grant is not active");
    }
    if consumed_grant_hashes
        .binary_search(&grant.grant_sha256)
        .is_ok()
        || consumed_sequences
            .binary_search(&grant.one_time_grant_sequence)
            .is_ok()
    {
        return replay("Work Grant hash or one-time sequence was already consumed");
    }
    Ok(())
}

/// Returns the canonical serialized byte count for bounded runner metrics.
pub fn canonical_size<T: Serialize>(value: &T) -> Result<u64, WorkQueueError> {
    u64::try_from(canonical_json_bytes(value)?.len()).map_err(|_| {
        WorkQueueError::ResourceLimit("serialized artifact size overflowed u64".to_owned())
    })
}
