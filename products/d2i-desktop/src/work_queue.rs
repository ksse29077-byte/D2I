use crate::{read_bounded, sha256_bytes, validate_hash, validate_token, write_new, DesktopError};
use d2i_role_contract::RoleInstanceV1;
use d2i_work_case::{CaseContractV1, CaseInstanceV1};
use d2i_work_queue::{
    canonical_sha256, derive_initial_ownership, parse_json_strict, project_case_to_queue,
    CaseLeaseV1, CaseOwnershipPoolV1, CaseOwnershipTransferV1, CaseWorkGrantV1,
    CurrentCaseOwnershipStateV1, LeaseStatusV1, QueueLaneV1, WorkQueueEntryV1,
    WorkQueueOperationReceiptV1, WorkQueuePolicyV1, WorkSchedulerDecisionV1, ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const LEDGER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "work-queue-ledger-manifest.json";
const STATE_FILE: &str = "work-queue-ledger-state.json";
const LOCK_FILE: &str = ".work-queue-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_RECORDS: u64 = 65_536;

/// Closed durable Queue and ownership event set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkQueueLedgerEventKindV1 {
    OwnershipInitialized,
    EntryEnqueued,
    EntryReconciled,
    SchedulerDecisionRecorded,
    LeaseClaimed,
    LeaseRenewed,
    LeaseTerminated,
    OwnershipTransferred,
    WorkGrantRecorded,
    OperationReceiptCommitted,
    RecoveryRepaired,
}

/// One protected hash-chain transition. It contains no executable authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueueLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub queue_id: String,
    pub organization_id: String,
    pub queue_policy_sha256: String,
    pub ownership_pool_sha256: String,
    pub event_kind: WorkQueueLedgerEventKindV1,
    pub case_id: String,
    pub source_intake_receipt_sha256: String,
    pub queue_entry_after: Option<WorkQueueEntryV1>,
    pub ownership_state_after: Option<CurrentCaseOwnershipStateV1>,
    pub scheduler_decision: Option<WorkSchedulerDecisionV1>,
    pub lease_after: Option<CaseLeaseV1>,
    pub ownership_transfer: Option<CaseOwnershipTransferV1>,
    pub work_grant: Option<CaseWorkGrantV1>,
    pub operation_receipt: Option<WorkQueueOperationReceiptV1>,
    pub role_ledger_chain_head: String,
    pub case_ledger_chain_head: String,
    pub protected_audit_record_sha256: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkQueueLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    queue_id: String,
    organization_id: String,
    queue_policy_sha256: String,
    ownership_pool_sha256: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    state_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkQueueLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    queue_id: String,
    organization_id: String,
    queue_policy_sha256: String,
    ownership_pool_sha256: String,
    records: Vec<WorkQueueLedgerRecordV1>,
}

/// Replayed Queue projection, ownership history, exclusive leases, and one-time indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkQueueLedgerVerificationV1 {
    pub ledger_id: String,
    pub queue_id: String,
    pub organization_id: String,
    pub queue_policy_sha256: String,
    pub ownership_pool_sha256: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub current_entries: BTreeMap<String, WorkQueueEntryV1>,
    pub current_ownership: BTreeMap<String, CurrentCaseOwnershipStateV1>,
    pub ownership_history: BTreeMap<String, Vec<String>>,
    pub latest_leases: BTreeMap<String, CaseLeaseV1>,
    pub scheduler_decision_hashes: Vec<String>,
    pub consumed_transfer_ids: Vec<String>,
    pub consumed_work_grant_hashes: Vec<String>,
    pub consumed_work_grant_sequences: Vec<u64>,
    pub operation_receipt_hashes: Vec<String>,
    pub latest_role_ledger_chain_head: String,
    pub latest_case_ledger_chain_head: String,
    pub latest_protected_audit_record_sha256: String,
    pub latest_recorded_at_unix_ms: u64,
}

/// Current-user protected, single-writer Queue and ownership ledger.
#[derive(Debug)]
pub struct WorkQueueLedgerV1 {
    root: PathBuf,
    manifest: WorkQueueLedgerManifestV1,
    verification: WorkQueueLedgerVerificationV1,
    poisoned: bool,
}

impl WorkQueueLedgerV1 {
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_work_queue_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
            poisoned: false,
        })
    }

    #[must_use]
    pub const fn verification(&self) -> &WorkQueueLedgerVerificationV1 {
        &self.verification
    }

    pub fn append(&mut self, mut record: WorkQueueLedgerRecordV1) -> Result<String, DesktopError> {
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "Queue ledger is poisoned after a durable-write failure".to_owned(),
            ));
        }
        let result = self.append_inner(&mut record);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_inner(
        &mut self,
        record: &mut WorkQueueLedgerRecordV1,
    ) -> Result<String, DesktopError> {
        let lock = WorkQueueLedgerLock::acquire(&self.root)?;
        let latest = verify_work_queue_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "Queue ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "Queue ledger record limit is exhausted".to_owned(),
            ));
        }
        record.schema_version = LEDGER_SCHEMA_VERSION;
        record.sequence = latest.record_count.saturating_add(1);
        record.ledger_id = self.manifest.ledger_id.clone();
        record.queue_id = self.manifest.queue_id.clone();
        record.organization_id = self.manifest.organization_id.clone();
        record.queue_policy_sha256 = self.manifest.queue_policy_sha256.clone();
        record.ownership_pool_sha256 = self.manifest.ownership_pool_sha256.clone();
        record.previous_record_hash = latest.terminal_record_hash.clone();
        record.record_hash = ZERO_HASH.to_owned();
        record.record_hash = record_hash(record)?;
        validate_record_transition(record, &latest)?;
        validate_record(record)?;
        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record.clone());
        atomic_replace_state(&self.root, &snapshot)?;
        let verified = verify_work_queue_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "Queue ledger append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        drop(lock);
        Ok(self.verification.terminal_record_hash.clone())
    }
}

/// Initializes one protected Queue ledger bound to exact policy and ownership pool hashes.
#[allow(clippy::too_many_arguments)]
pub fn initialize_work_queue_ledger(
    root: &Path,
    ledger_id: &str,
    policy: &WorkQueuePolicyV1,
    pool: &CaseOwnershipPoolV1,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<WorkQueueLedgerV1, DesktopError> {
    policy.validate().map_err(queue_error)?;
    pool.validate().map_err(queue_error)?;
    validate_token(ledger_id, "Queue ledger ID")?;
    if policy.organization_id != pool.organization_id
        || policy.role_contract_sha256 != pool.role_contract_sha256
        || maximum_records == 0
        || maximum_records > MAX_LEDGER_RECORDS
        || created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Queue ledger policy, pool, limits, or creation time is invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_hash = harden_and_hash(root, "Queue ledger root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_hash =
            harden_and_hash(&manifest_path, "Queue ledger manifest")?;
        let state_security_descriptor_hash = harden_and_hash(&state_path, "Queue ledger state")?;
        let snapshot = WorkQueueLedgerSnapshotV1 {
            schema_version: LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            queue_id: policy.queue_id.clone(),
            organization_id: policy.organization_id.clone(),
            queue_policy_sha256: policy.policy_sha256.clone(),
            ownership_pool_sha256: pool.pool_sha256.clone(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_ledger_json(&snapshot)?)?;
        let manifest = WorkQueueLedgerManifestV1 {
            schema_version: LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            queue_id: policy.queue_id.clone(),
            organization_id: policy.organization_id.clone(),
            queue_policy_sha256: policy.policy_sha256.clone(),
            ownership_pool_sha256: pool.pool_sha256.clone(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash,
            manifest_security_descriptor_hash,
            state_security_descriptor_hash,
        };
        overwrite_existing(&manifest_path, &pretty_ledger_json(&manifest)?)?;
        WorkQueueLedgerV1::open(root)
    })();
    if initialized.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    initialized
}

/// Verifies ACL fingerprints and replays the complete append-only Queue state.
pub fn verify_work_queue_ledger(
    root: &Path,
) -> Result<WorkQueueLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != LEDGER_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.queue_id != manifest.queue_id
        || snapshot.organization_id != manifest.organization_id
        || snapshot.queue_policy_sha256 != manifest.queue_policy_sha256
        || snapshot.ownership_pool_sha256 != manifest.ownership_pool_sha256
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "Queue ledger snapshot identity or bounds differ".to_owned(),
        ));
    }
    let mut verification = WorkQueueLedgerVerificationV1 {
        ledger_id: manifest.ledger_id,
        queue_id: manifest.queue_id,
        organization_id: manifest.organization_id,
        queue_policy_sha256: manifest.queue_policy_sha256,
        ownership_pool_sha256: manifest.ownership_pool_sha256,
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        current_entries: BTreeMap::new(),
        current_ownership: BTreeMap::new(),
        ownership_history: BTreeMap::new(),
        latest_leases: BTreeMap::new(),
        scheduler_decision_hashes: Vec::new(),
        consumed_transfer_ids: Vec::new(),
        consumed_work_grant_hashes: Vec::new(),
        consumed_work_grant_sequences: Vec::new(),
        operation_receipt_hashes: Vec::new(),
        latest_role_ledger_chain_head: ZERO_HASH.to_owned(),
        latest_case_ledger_chain_head: ZERO_HASH.to_owned(),
        latest_protected_audit_record_sha256: ZERO_HASH.to_owned(),
        latest_recorded_at_unix_ms: manifest.created_at_unix_ms,
    };
    for record in &snapshot.records {
        validate_record_transition(record, &verification)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.record_hash != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "Queue ledger sequence or hash chain differs".to_owned(),
            ));
        }
        apply_record(record, &mut verification)?;
    }
    Ok(verification)
}

fn validate_record_transition(
    record: &WorkQueueLedgerRecordV1,
    current: &WorkQueueLedgerVerificationV1,
) -> Result<(), DesktopError> {
    validate_record(record)?;
    if record.ledger_id != current.ledger_id
        || record.queue_id != current.queue_id
        || record.organization_id != current.organization_id
        || record.queue_policy_sha256 != current.queue_policy_sha256
        || record.ownership_pool_sha256 != current.ownership_pool_sha256
        || record.recorded_at_unix_ms < current.latest_recorded_at_unix_ms
    {
        return Err(DesktopError::Integrity(
            "Queue record identity, policy, pool, or monotonic time differs".to_owned(),
        ));
    }
    if let Some(entry) = &record.queue_entry_after {
        if entry.case_id != record.case_id
            || entry.queue_id != record.queue_id
            || entry.last_reconciled_case_ledger_head != record.case_ledger_chain_head
            || entry.last_reconciled_role_ledger_head != record.role_ledger_chain_head
            || entry.intake_receipt_sha256 != record.source_intake_receipt_sha256
        {
            return Err(DesktopError::Integrity(
                "Queue entry differs from durable record cross-bindings".to_owned(),
            ));
        }
        if record.event_kind == WorkQueueLedgerEventKindV1::EntryEnqueued
            && current.current_entries.contains_key(&record.case_id)
        {
            return Err(DesktopError::Replay(
                "duplicate Queue enqueue for one Case".to_owned(),
            ));
        }
    }
    if let Some(ownership) = &record.ownership_state_after {
        if ownership.case_id != record.case_id
            || ownership.queue_policy_sha256 != record.queue_policy_sha256
            || ownership.ownership_pool_sha256 != record.ownership_pool_sha256
            || ownership.role_ledger_chain_head != record.role_ledger_chain_head
            || ownership.case_ledger_chain_head != record.case_ledger_chain_head
        {
            return Err(DesktopError::Integrity(
                "ownership state differs from durable record cross-bindings".to_owned(),
            ));
        }
        if let Some(previous) = current.current_ownership.get(&record.case_id) {
            if ownership.ownership_generation < previous.ownership_generation
                || (ownership.ownership_generation > previous.ownership_generation
                    && (ownership.ownership_generation != previous.ownership_generation + 1
                        || ownership.previous_ownership_state_sha256.as_ref()
                            != Some(&previous.state_sha256)))
            {
                return Err(DesktopError::Integrity(
                    "ownership generation or history chain differs".to_owned(),
                ));
            }
        } else if ownership.ownership_generation != 1 {
            return Err(DesktopError::Integrity(
                "ownership history does not begin at generation one".to_owned(),
            ));
        }
    }
    if let Some(lease) = &record.lease_after {
        if lease.case_id != record.case_id
            || lease.case_ledger_chain_head != record.case_ledger_chain_head
            || lease.role_ledger_chain_head != record.role_ledger_chain_head
        {
            return Err(DesktopError::Integrity(
                "lease differs from durable record cross-bindings".to_owned(),
            ));
        }
        if let Some(previous) = current.latest_leases.get(&record.case_id) {
            if lease.lease_sha256 != previous.lease_sha256
                && lease.previous_lease_sha256.as_ref() != Some(&previous.lease_sha256)
            {
                return Err(DesktopError::Replay(
                    "lease history does not bind the latest epoch".to_owned(),
                ));
            }
            if lease.is_active_at(record.recorded_at_unix_ms / 1000)
                && previous.is_active_at(record.recorded_at_unix_ms / 1000)
                && lease.previous_lease_sha256.is_none()
            {
                return Err(DesktopError::Replay(
                    "two active Case leases would coexist".to_owned(),
                ));
            }
        }
        let lease_is_live = matches!(
            lease.lease_status,
            LeaseStatusV1::Active | LeaseStatusV1::Renewed
        );
        if record.queue_entry_after.as_ref().is_some_and(|entry| {
            entry.case_id != lease.case_id
                || entry.active_lease_sha256.as_ref()
                    != lease_is_live.then_some(&lease.lease_sha256)
        }) || record
            .ownership_state_after
            .as_ref()
            .is_some_and(|ownership| {
                ownership.case_id != lease.case_id
                    || ownership.active_lease_sha256.as_ref()
                        != lease_is_live.then_some(&lease.lease_sha256)
            })
        {
            return Err(DesktopError::Integrity(
                "lease durability record differs from Queue or ownership projection".to_owned(),
            ));
        }
    }
    if let Some(decision) = &record.scheduler_decision {
        if current
            .scheduler_decision_hashes
            .binary_search(&decision.decision_sha256)
            .is_ok()
        {
            return Err(DesktopError::Replay(
                "Scheduler decision was already recorded".to_owned(),
            ));
        }
    }
    if let Some(transfer) = &record.ownership_transfer {
        if current
            .consumed_transfer_ids
            .binary_search(&transfer.transfer_id)
            .is_ok()
            || current
                .latest_leases
                .get(&record.case_id)
                .is_some_and(|lease| lease.is_active_at(record.recorded_at_unix_ms / 1000))
        {
            return Err(DesktopError::Replay(
                "ownership transfer was replayed or has an active lease".to_owned(),
            ));
        }
        let previous = current.current_ownership.get(&record.case_id);
        if transfer.case_id != record.case_id
            || previous.map(|value| &value.state_sha256)
                != Some(&transfer.previous_ownership_state_sha256)
            || record
                .ownership_state_after
                .as_ref()
                .is_none_or(|ownership| {
                    ownership.transfer_sha256.as_ref() != Some(&transfer.transfer_sha256)
                        || ownership.previous_ownership_state_sha256.as_ref()
                            != Some(&transfer.previous_ownership_state_sha256)
                })
            || record.queue_entry_after.as_ref().is_some_and(|entry| {
                record
                    .ownership_state_after
                    .as_ref()
                    .is_none_or(|ownership| {
                        entry.current_ownership_state_sha256 != ownership.state_sha256
                            || entry.current_role_instance_id != ownership.current_role_instance_id
                    })
            })
        {
            return Err(DesktopError::Integrity(
                "ownership transfer differs from current history or Queue projection".to_owned(),
            ));
        }
    }
    if let Some(grant) = &record.work_grant {
        if current
            .consumed_work_grant_hashes
            .binary_search(&grant.grant_sha256)
            .is_ok()
            || current
                .consumed_work_grant_sequences
                .binary_search(&grant.one_time_grant_sequence)
                .is_ok()
        {
            return Err(DesktopError::Replay(
                "Work Grant hash or sequence was already recorded".to_owned(),
            ));
        }
        if grant.case_id != record.case_id
            || current
                .current_entries
                .get(&record.case_id)
                .is_none_or(|entry| {
                    entry.case_contract_sha256 != grant.case_contract_sha256
                        || entry.current_case_instance_sha256 != grant.current_case_instance_sha256
                })
            || current
                .current_ownership
                .get(&record.case_id)
                .is_none_or(|ownership| ownership.state_sha256 != grant.ownership_state_sha256)
            || current
                .latest_leases
                .get(&record.case_id)
                .is_none_or(|lease| {
                    lease.lease_sha256 != grant.lease_sha256
                        || !lease.is_active_at(record.recorded_at_unix_ms / 1000)
                })
        {
            return Err(DesktopError::Integrity(
                "Work Grant differs from the current Case, owner, or active lease".to_owned(),
            ));
        }
    }
    if let Some(receipt) = &record.operation_receipt {
        if current
            .operation_receipt_hashes
            .binary_search(&receipt.receipt_sha256)
            .is_ok()
        {
            return Err(DesktopError::Replay(
                "Queue operation receipt was already recorded".to_owned(),
            ));
        }
        if receipt.queue_id != record.queue_id
            || receipt.case_id != record.case_id
            || receipt.source_intake_receipt_sha256 != record.source_intake_receipt_sha256
            || receipt.role_ledger_chain_head != record.role_ledger_chain_head
            || receipt.case_ledger_chain_head != record.case_ledger_chain_head
            || receipt.queue_ledger_chain_head != current.terminal_record_hash
        {
            return Err(DesktopError::Integrity(
                "Queue operation receipt differs from protected ledger heads".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_record(record: &WorkQueueLedgerRecordV1) -> Result<(), DesktopError> {
    if record.schema_version != LEDGER_SCHEMA_VERSION
        || record.sequence == 0
        || record.recorded_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Queue ledger record schema, sequence, or time is invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&record.ledger_id, "Queue record ledger ID"),
        (&record.queue_id, "Queue record queue ID"),
        (&record.organization_id, "Queue record organization"),
        (&record.case_id, "Queue record Case ID"),
    ] {
        validate_token(value, label)?;
    }
    for (value, label) in [
        (&record.queue_policy_sha256, "Queue record policy hash"),
        (&record.ownership_pool_sha256, "Queue record pool hash"),
        (
            &record.source_intake_receipt_sha256,
            "Queue record Intake receipt hash",
        ),
        (
            &record.role_ledger_chain_head,
            "Queue record Role ledger head",
        ),
        (
            &record.case_ledger_chain_head,
            "Queue record Case ledger head",
        ),
        (
            &record.protected_audit_record_sha256,
            "Queue record audit hash",
        ),
        (&record.previous_record_hash, "Queue record previous hash"),
        (&record.record_hash, "Queue record hash"),
    ] {
        validate_hash(value, label)?;
    }
    if let Some(value) = &record.queue_entry_after {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.ownership_state_after {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.scheduler_decision {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.lease_after {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.ownership_transfer {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.work_grant {
        value.validate().map_err(queue_error)?;
    }
    if let Some(value) = &record.operation_receipt {
        value.validate().map_err(queue_error)?;
    }
    let shape_ok = match record.event_kind {
        WorkQueueLedgerEventKindV1::OwnershipInitialized => record.ownership_state_after.is_some(),
        WorkQueueLedgerEventKindV1::EntryEnqueued
        | WorkQueueLedgerEventKindV1::EntryReconciled
        | WorkQueueLedgerEventKindV1::RecoveryRepaired => record.queue_entry_after.is_some(),
        WorkQueueLedgerEventKindV1::SchedulerDecisionRecorded => {
            record.scheduler_decision.is_some()
        }
        WorkQueueLedgerEventKindV1::LeaseClaimed
        | WorkQueueLedgerEventKindV1::LeaseRenewed
        | WorkQueueLedgerEventKindV1::LeaseTerminated => record.lease_after.is_some(),
        WorkQueueLedgerEventKindV1::OwnershipTransferred => {
            record.ownership_transfer.is_some() && record.ownership_state_after.is_some()
        }
        WorkQueueLedgerEventKindV1::WorkGrantRecorded => record.work_grant.is_some(),
        WorkQueueLedgerEventKindV1::OperationReceiptCommitted => record.operation_receipt.is_some(),
    };
    if !shape_ok {
        return Err(DesktopError::Invalid(
            "Queue ledger event does not contain its required artifact".to_owned(),
        ));
    }
    if record_hash(record)? != record.record_hash {
        return Err(DesktopError::Integrity(
            "Queue ledger record self-hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn apply_record(
    record: &WorkQueueLedgerRecordV1,
    state: &mut WorkQueueLedgerVerificationV1,
) -> Result<(), DesktopError> {
    if let Some(entry) = &record.queue_entry_after {
        if entry.queue_lane == QueueLaneV1::TerminalRemoved {
            state.current_entries.remove(&record.case_id);
        } else {
            state
                .current_entries
                .insert(record.case_id.clone(), entry.clone());
        }
    }
    if let Some(ownership) = &record.ownership_state_after {
        let history = state
            .ownership_history
            .entry(record.case_id.clone())
            .or_default();
        if history.last() != Some(&ownership.state_sha256) {
            history.push(ownership.state_sha256.clone());
        }
        state
            .current_ownership
            .insert(record.case_id.clone(), ownership.clone());
    }
    if let Some(lease) = &record.lease_after {
        state
            .latest_leases
            .insert(record.case_id.clone(), lease.clone());
    }
    if let Some(decision) = &record.scheduler_decision {
        sorted_insert(
            &mut state.scheduler_decision_hashes,
            decision.decision_sha256.clone(),
        )?;
    }
    if let Some(transfer) = &record.ownership_transfer {
        sorted_insert(
            &mut state.consumed_transfer_ids,
            transfer.transfer_id.clone(),
        )?;
    }
    if let Some(grant) = &record.work_grant {
        sorted_insert(
            &mut state.consumed_work_grant_hashes,
            grant.grant_sha256.clone(),
        )?;
        sorted_insert(
            &mut state.consumed_work_grant_sequences,
            grant.one_time_grant_sequence,
        )?;
    }
    if let Some(receipt) = &record.operation_receipt {
        sorted_insert(
            &mut state.operation_receipt_hashes,
            receipt.receipt_sha256.clone(),
        )?;
    }
    state.record_count = record.sequence;
    state.terminal_record_hash = record.record_hash.clone();
    state.latest_role_ledger_chain_head = record.role_ledger_chain_head.clone();
    state.latest_case_ledger_chain_head = record.case_ledger_chain_head.clone();
    state.latest_protected_audit_record_sha256 = record.protected_audit_record_sha256.clone();
    state.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
    Ok(())
}

fn sorted_insert<T: Ord>(values: &mut Vec<T>, value: T) -> Result<(), DesktopError> {
    match values.binary_search(&value) {
        Ok(_) => Err(DesktopError::Replay(
            "Queue replay index already contains the value".to_owned(),
        )),
        Err(index) => {
            values.insert(index, value);
            Ok(())
        }
    }
}

/// Narrow coordinator that persists every authority-sensitive Queue transition first.
#[derive(Debug)]
pub struct WorkQueueCoordinatorV1 {
    ledger: WorkQueueLedgerV1,
    policy: WorkQueuePolicyV1,
    pool: CaseOwnershipPoolV1,
}

impl WorkQueueCoordinatorV1 {
    pub fn open(
        root: &Path,
        policy: WorkQueuePolicyV1,
        pool: CaseOwnershipPoolV1,
    ) -> Result<Self, DesktopError> {
        policy.validate().map_err(queue_error)?;
        pool.validate().map_err(queue_error)?;
        let ledger = WorkQueueLedgerV1::open(root)?;
        if ledger.verification.queue_policy_sha256 != policy.policy_sha256
            || ledger.verification.ownership_pool_sha256 != pool.pool_sha256
        {
            return Err(DesktopError::Integrity(
                "Queue coordinator policy or ownership pool differs from ledger".to_owned(),
            ));
        }
        Ok(Self {
            ledger,
            policy,
            pool,
        })
    }

    #[must_use]
    pub const fn verification(&self) -> &WorkQueueLedgerVerificationV1 {
        self.ledger.verification()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_case(
        &mut self,
        contract: &CaseContractV1,
        instance: &CaseInstanceV1,
        owner: &RoleInstanceV1,
        source_intake_receipt_sha256: String,
        role_ledger_chain_head: String,
        case_ledger_chain_head: String,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<(CurrentCaseOwnershipStateV1, WorkQueueEntryV1), DesktopError> {
        let mut ownership_refreshed = false;
        let ownership = if let Some(current) = self
            .ledger
            .verification
            .current_ownership
            .get(&contract.case_id)
            .cloned()
        {
            if current.current_role_instance_sha256 == owner.instance_sha256
                && current.role_ledger_chain_head == role_ledger_chain_head
            {
                current
            } else {
                ownership_refreshed = true;
                current
                    .refresh_role_binding(owner, role_ledger_chain_head.clone())
                    .map_err(queue_error)?
            }
        } else {
            let ownership = derive_initial_ownership(
                contract,
                instance,
                owner,
                &self.policy,
                &self.pool,
                recorded_at_unix_ms / 1000,
                role_ledger_chain_head.clone(),
                case_ledger_chain_head.clone(),
                vec!["protected-origin-ownership".to_owned()],
            )
            .map_err(queue_error)?;
            self.ledger.append(record_template(
                &self.ledger.verification,
                WorkQueueLedgerEventKindV1::OwnershipInitialized,
                &contract.case_id,
                &source_intake_receipt_sha256,
                None,
                Some(ownership.clone()),
                None,
                None,
                None,
                None,
                None,
                role_ledger_chain_head.clone(),
                case_ledger_chain_head.clone(),
                protected_audit_record_sha256.clone(),
                recorded_at_unix_ms,
            ))?;
            ownership
        };
        let existing = self
            .ledger
            .verification
            .current_entries
            .get(&contract.case_id);
        let enqueue_sequence = existing.map_or(
            self.ledger.verification.current_entries.len() as u64 + 1,
            |entry| entry.enqueue_sequence,
        );
        let entry = project_case_to_queue(
            &self.policy,
            contract,
            instance,
            &ownership,
            owner,
            recorded_at_unix_ms / 1000,
            enqueue_sequence,
            source_intake_receipt_sha256.clone(),
            role_ledger_chain_head.clone(),
            case_ledger_chain_head.clone(),
            vec!["protected-queue-reconciliation".to_owned()],
        )
        .map_err(queue_error)?;
        if existing.is_some_and(|current| current.entry_sha256 == entry.entry_sha256) {
            return Ok((ownership, entry));
        }
        let event = if existing.is_some() {
            WorkQueueLedgerEventKindV1::EntryReconciled
        } else {
            WorkQueueLedgerEventKindV1::EntryEnqueued
        };
        self.ledger.append(record_template(
            &self.ledger.verification,
            event,
            &contract.case_id,
            &source_intake_receipt_sha256,
            Some(entry.clone()),
            ownership_refreshed.then_some(ownership.clone()),
            None,
            None,
            None,
            None,
            None,
            role_ledger_chain_head,
            case_ledger_chain_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms.saturating_add(1),
        ))?;
        Ok((ownership, entry))
    }

    pub fn record_scheduler_decision(
        &mut self,
        case_id: &str,
        source_intake_receipt_sha256: &str,
        decision: WorkSchedulerDecisionV1,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let role_head = self
            .ledger
            .verification
            .latest_role_ledger_chain_head
            .clone();
        let case_head = self
            .ledger
            .verification
            .latest_case_ledger_chain_head
            .clone();
        let record = record_template(
            &self.ledger.verification,
            WorkQueueLedgerEventKindV1::SchedulerDecisionRecorded,
            case_id,
            source_intake_receipt_sha256,
            None,
            None,
            Some(decision),
            None,
            None,
            None,
            None,
            role_head,
            case_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms,
        );
        self.ledger.append(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_lease(
        &mut self,
        source_intake_receipt_sha256: &str,
        lease: CaseLeaseV1,
        ownership: CurrentCaseOwnershipStateV1,
        entry: WorkQueueEntryV1,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let event = match lease.lease_status {
            LeaseStatusV1::Active => WorkQueueLedgerEventKindV1::LeaseClaimed,
            LeaseStatusV1::Renewed => WorkQueueLedgerEventKindV1::LeaseRenewed,
            LeaseStatusV1::Released | LeaseStatusV1::Expired | LeaseStatusV1::Revoked => {
                WorkQueueLedgerEventKindV1::LeaseTerminated
            }
            LeaseStatusV1::Consumed => {
                return Err(DesktopError::AccessDenied(
                    "WORK-400 does not consume leases for execution".to_owned(),
                ));
            }
        };
        let role_head = ownership.role_ledger_chain_head.clone();
        let case_head = ownership.case_ledger_chain_head.clone();
        let case_id = lease.case_id.clone();
        let record = record_template(
            &self.ledger.verification,
            event,
            &case_id,
            source_intake_receipt_sha256,
            Some(entry),
            Some(ownership),
            None,
            Some(lease),
            None,
            None,
            None,
            role_head,
            case_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms,
        );
        self.ledger.append(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_transfer(
        &mut self,
        source_intake_receipt_sha256: &str,
        transfer: CaseOwnershipTransferV1,
        ownership: CurrentCaseOwnershipStateV1,
        entry: WorkQueueEntryV1,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let role_head = ownership.role_ledger_chain_head.clone();
        let case_head = ownership.case_ledger_chain_head.clone();
        let case_id = transfer.case_id.clone();
        let record = record_template(
            &self.ledger.verification,
            WorkQueueLedgerEventKindV1::OwnershipTransferred,
            &case_id,
            source_intake_receipt_sha256,
            Some(entry),
            Some(ownership),
            None,
            None,
            Some(transfer),
            None,
            None,
            role_head,
            case_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms,
        );
        self.ledger.append(record)
    }

    pub fn record_work_grant(
        &mut self,
        source_intake_receipt_sha256: &str,
        grant: CaseWorkGrantV1,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let role_head = self
            .ledger
            .verification
            .latest_role_ledger_chain_head
            .clone();
        let case_head = self
            .ledger
            .verification
            .latest_case_ledger_chain_head
            .clone();
        let case_id = grant.case_id.clone();
        let record = record_template(
            &self.ledger.verification,
            WorkQueueLedgerEventKindV1::WorkGrantRecorded,
            &case_id,
            source_intake_receipt_sha256,
            None,
            None,
            None,
            None,
            None,
            Some(grant),
            None,
            role_head,
            case_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms,
        );
        self.ledger.append(record)
    }

    pub fn record_operation_receipt(
        &mut self,
        receipt: WorkQueueOperationReceiptV1,
        protected_audit_record_sha256: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let record = record_template(
            &self.ledger.verification,
            WorkQueueLedgerEventKindV1::OperationReceiptCommitted,
            &receipt.case_id,
            &receipt.source_intake_receipt_sha256,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(receipt.clone()),
            receipt.role_ledger_chain_head,
            receipt.case_ledger_chain_head,
            protected_audit_record_sha256,
            recorded_at_unix_ms,
        );
        self.ledger.append(record)
    }
}

#[allow(clippy::too_many_arguments)]
fn record_template(
    verification: &WorkQueueLedgerVerificationV1,
    event_kind: WorkQueueLedgerEventKindV1,
    case_id: &str,
    source_intake_receipt_sha256: &str,
    queue_entry_after: Option<WorkQueueEntryV1>,
    ownership_state_after: Option<CurrentCaseOwnershipStateV1>,
    scheduler_decision: Option<WorkSchedulerDecisionV1>,
    lease_after: Option<CaseLeaseV1>,
    ownership_transfer: Option<CaseOwnershipTransferV1>,
    work_grant: Option<CaseWorkGrantV1>,
    operation_receipt: Option<WorkQueueOperationReceiptV1>,
    role_ledger_chain_head: String,
    case_ledger_chain_head: String,
    protected_audit_record_sha256: String,
    recorded_at_unix_ms: u64,
) -> WorkQueueLedgerRecordV1 {
    WorkQueueLedgerRecordV1 {
        schema_version: LEDGER_SCHEMA_VERSION,
        sequence: verification.record_count.saturating_add(1),
        ledger_id: verification.ledger_id.clone(),
        queue_id: verification.queue_id.clone(),
        organization_id: verification.organization_id.clone(),
        queue_policy_sha256: verification.queue_policy_sha256.clone(),
        ownership_pool_sha256: verification.ownership_pool_sha256.clone(),
        event_kind,
        case_id: case_id.to_owned(),
        source_intake_receipt_sha256: source_intake_receipt_sha256.to_owned(),
        queue_entry_after,
        ownership_state_after,
        scheduler_decision,
        lease_after,
        ownership_transfer,
        work_grant,
        operation_receipt,
        role_ledger_chain_head,
        case_ledger_chain_head,
        protected_audit_record_sha256,
        recorded_at_unix_ms,
        previous_record_hash: verification.terminal_record_hash.clone(),
        record_hash: ZERO_HASH.to_owned(),
    }
}

fn record_hash(record: &WorkQueueLedgerRecordV1) -> Result<String, DesktopError> {
    let mut value =
        serde_json::to_value(record).map_err(|error| DesktopError::Json(error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| DesktopError::Json("Queue record is not an object".to_owned()))?
        .remove("record_hash");
    canonical_sha256(&value).map_err(queue_error)
}

fn load_manifest(root: &Path) -> Result<WorkQueueLedgerManifestV1, DesktopError> {
    let bytes = read_bounded(&root.join(MANIFEST_FILE), MAX_LEDGER_BYTES)?;
    parse_json_strict(&bytes).map_err(queue_error)
}

fn load_snapshot(root: &Path) -> Result<WorkQueueLedgerSnapshotV1, DesktopError> {
    let bytes = read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?;
    parse_json_strict(&bytes).map_err(queue_error)
}

fn verify_storage_security(
    root: &Path,
    manifest: &WorkQueueLedgerManifestV1,
) -> Result<(), DesktopError> {
    for (path, expected, label) in [
        (
            root.to_path_buf(),
            &manifest.root_security_descriptor_hash,
            "root",
        ),
        (
            root.join(MANIFEST_FILE),
            &manifest.manifest_security_descriptor_hash,
            "manifest",
        ),
        (
            root.join(STATE_FILE),
            &manifest.state_security_descriptor_hash,
            "state",
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("Queue ledger {label} ACL read failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "Queue ledger {label} ACL changed"
            )));
        }
    }
    Ok(())
}

fn harden_and_hash(path: &Path, label: &str) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::harden_path_for_current_user(path).map_err(|error| {
        DesktopError::Integrity(format!("{label} ACL hardening failed: {error}"))
    })?;
    Ok(sha256_bytes(&descriptor))
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn atomic_replace_state(
    root: &Path,
    snapshot: &WorkQueueLedgerSnapshotV1,
) -> Result<(), DesktopError> {
    let temporary = root.join(format!(
        ".work-queue-state-{}-{}.tmp",
        std::process::id(),
        snapshot.records.len()
    ));
    let result = (|| {
        write_new(&temporary, &pretty_ledger_json(snapshot)?)?;
        let _ = d2i_windows_host::harden_path_for_current_user(&temporary).map_err(|error| {
            DesktopError::Integrity(format!("temporary Queue state ACL failed: {error}"))
        })?;
        d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
            DesktopError::Io {
                path: root.join(STATE_FILE).display().to_string(),
                message: format!("atomic Queue state replace failed: {error}"),
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn pretty_ledger_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_LEDGER_BYTES {
        return Err(DesktopError::AccessDenied(
            "Queue ledger exceeds the bounded file size".to_owned(),
        ));
    }
    Ok(bytes)
}

fn queue_error(error: d2i_work_queue::WorkQueueError) -> DesktopError {
    match error {
        d2i_work_queue::WorkQueueError::Invalid(message) => DesktopError::Invalid(message),
        d2i_work_queue::WorkQueueError::Integrity(message) => DesktopError::Integrity(message),
        d2i_work_queue::WorkQueueError::Authorization(message) => {
            DesktopError::AccessDenied(message)
        }
        d2i_work_queue::WorkQueueError::Replay(message) => DesktopError::Replay(message),
        d2i_work_queue::WorkQueueError::ResourceLimit(message) => {
            DesktopError::AccessDenied(message)
        }
        d2i_work_queue::WorkQueueError::Json(message) => DesktopError::Json(message),
        d2i_work_queue::WorkQueueError::Io(message) => DesktopError::Io {
            path: "work-queue".to_owned(),
            message,
        },
    }
}

struct WorkQueueLedgerLock(PathBuf);

impl WorkQueueLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("Queue ledger lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "Queue ledger lock ACL failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for WorkQueueLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
