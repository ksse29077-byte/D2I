use crate::{
    pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_token, write_new,
    DesktopError,
};
use d2i_work_intake::{
    canonical_sha256, parse_json_strict, RadarCheckpointV1, RadarCycleReportV1,
    WorkIntakeReceiptV1, ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const INTAKE_LEDGER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "work-intake-ledger-manifest.json";
const STATE_FILE: &str = "work-intake-ledger-state.json";
const LOCK_FILE: &str = ".work-intake-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_RECORDS: u64 = 65_536;

/// Closed durable Intake event set. No event grants execution authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkIntakeLedgerEventKindV1 {
    CheckpointInitialized,
    ReceiptCommitted,
    CheckpointAdvanced,
    CycleCommitted,
    RecoveryCheckpointRepaired,
}

/// One protected hash-chain record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIntakeLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub organization_id: String,
    pub role_instance_id: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub source_approval_sha256: String,
    pub event_kind: WorkIntakeLedgerEventKindV1,
    pub signal_id: Option<String>,
    pub event_id: Option<String>,
    pub signal_sha256: Option<String>,
    pub receipt: Option<WorkIntakeReceiptV1>,
    pub checkpoint: Option<RadarCheckpointV1>,
    pub cycle_report: Option<RadarCycleReportV1>,
    pub role_ledger_chain_head: String,
    pub case_ledger_chain_head: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct WorkIntakeLedgerRecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    organization_id: &'a str,
    role_instance_id: &'a str,
    registration_id: &'a str,
    registration_sha256: &'a str,
    source_approval_sha256: &'a str,
    event_kind: WorkIntakeLedgerEventKindV1,
    signal_id: &'a Option<String>,
    event_id: &'a Option<String>,
    signal_sha256: &'a Option<String>,
    receipt: &'a Option<WorkIntakeReceiptV1>,
    checkpoint: &'a Option<RadarCheckpointV1>,
    cycle_report: &'a Option<RadarCycleReportV1>,
    role_ledger_chain_head: &'a str,
    case_ledger_chain_head: &'a str,
    recorded_at_unix_ms: u64,
    previous_record_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkIntakeLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    role_instance_id: String,
    registration_id: String,
    registration_sha256: String,
    source_approval_sha256: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    state_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkIntakeLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    role_instance_id: String,
    registration_id: String,
    registration_sha256: String,
    source_approval_sha256: String,
    records: Vec<WorkIntakeLedgerRecordV1>,
}

/// Reconstructed Intake state and replay indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkIntakeLedgerVerificationV1 {
    pub ledger_id: String,
    pub organization_id: String,
    pub role_instance_id: String,
    pub registration_id: String,
    pub registration_sha256: String,
    pub source_approval_sha256: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub current_checkpoint: Option<RadarCheckpointV1>,
    pub pending_checkpoint_sha256: Option<String>,
    pub pending_checkpoint_ledger_head: Option<String>,
    pub processed_event_signals: BTreeMap<String, String>,
    pub consumed_signal_hashes: Vec<String>,
    pub consumed_receipt_hashes: Vec<String>,
    pub cycle_report_hashes: Vec<String>,
    pub latest_role_ledger_chain_head: String,
    pub latest_case_ledger_chain_head: String,
    pub latest_recorded_at_unix_ms: u64,
}

/// Current-user protected, single-writer Intake ledger.
#[derive(Debug)]
pub struct WorkIntakeLedgerV1 {
    root: PathBuf,
    manifest: WorkIntakeLedgerManifestV1,
    verification: WorkIntakeLedgerVerificationV1,
    poisoned: bool,
}

impl WorkIntakeLedgerV1 {
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_work_intake_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
            poisoned: false,
        })
    }

    #[must_use]
    pub const fn verification(&self) -> &WorkIntakeLedgerVerificationV1 {
        &self.verification
    }

    /// Persists the initial checkpoint before any source scan.
    pub fn initialize_checkpoint(
        &mut self,
        checkpoint: RadarCheckpointV1,
        role_ledger_chain_head: String,
        case_ledger_chain_head: String,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        if self.verification.current_checkpoint.is_some() {
            return Err(DesktopError::Replay(
                "Intake checkpoint is already initialized".to_owned(),
            ));
        }
        self.append(WorkIntakeLedgerRecordV1 {
            schema_version: 1,
            sequence: 1,
            ledger_id: self.manifest.ledger_id.clone(),
            organization_id: self.manifest.organization_id.clone(),
            role_instance_id: self.manifest.role_instance_id.clone(),
            registration_id: self.manifest.registration_id.clone(),
            registration_sha256: self.manifest.registration_sha256.clone(),
            source_approval_sha256: self.manifest.source_approval_sha256.clone(),
            event_kind: WorkIntakeLedgerEventKindV1::CheckpointInitialized,
            signal_id: None,
            event_id: None,
            signal_sha256: None,
            receipt: None,
            checkpoint: Some(checkpoint),
            cycle_report: None,
            role_ledger_chain_head,
            case_ledger_chain_head,
            recorded_at_unix_ms,
            previous_record_hash: ZERO_HASH.to_owned(),
            record_hash: ZERO_HASH.to_owned(),
        })
    }

    /// Commits a disposition receipt before advancing its source checkpoint.
    pub fn append_receipt(
        &mut self,
        signal_id: String,
        event_id: String,
        receipt: WorkIntakeReceiptV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let current = self
            .verification
            .current_checkpoint
            .as_ref()
            .ok_or_else(|| DesktopError::Precondition("Intake checkpoint is absent".to_owned()))?;
        if self.verification.pending_checkpoint_sha256.is_some() {
            return Err(DesktopError::Replay(
                "previous Intake receipt still awaits checkpoint commit".to_owned(),
            ));
        }
        self.append(WorkIntakeLedgerRecordV1 {
            schema_version: 1,
            sequence: 1,
            ledger_id: self.manifest.ledger_id.clone(),
            organization_id: self.manifest.organization_id.clone(),
            role_instance_id: self.manifest.role_instance_id.clone(),
            registration_id: self.manifest.registration_id.clone(),
            registration_sha256: self.manifest.registration_sha256.clone(),
            source_approval_sha256: self.manifest.source_approval_sha256.clone(),
            event_kind: WorkIntakeLedgerEventKindV1::ReceiptCommitted,
            signal_id: Some(signal_id),
            event_id: Some(event_id),
            signal_sha256: Some(receipt.signal_sha256.clone()),
            receipt: Some(receipt.clone()),
            checkpoint: None,
            cycle_report: None,
            role_ledger_chain_head: receipt.role_ledger_chain_head.clone(),
            case_ledger_chain_head: receipt.case_ledger_chain_head.clone(),
            recorded_at_unix_ms,
            previous_record_hash: current.intake_ledger_chain_head.clone(),
            record_hash: ZERO_HASH.to_owned(),
        })
    }

    /// Commits only the checkpoint named by the pending durable receipt.
    pub fn advance_checkpoint(
        &mut self,
        checkpoint: RadarCheckpointV1,
        repaired_after_restart: bool,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        let event_kind = if repaired_after_restart {
            WorkIntakeLedgerEventKindV1::RecoveryCheckpointRepaired
        } else {
            WorkIntakeLedgerEventKindV1::CheckpointAdvanced
        };
        self.append(WorkIntakeLedgerRecordV1 {
            schema_version: 1,
            sequence: 1,
            ledger_id: self.manifest.ledger_id.clone(),
            organization_id: self.manifest.organization_id.clone(),
            role_instance_id: self.manifest.role_instance_id.clone(),
            registration_id: self.manifest.registration_id.clone(),
            registration_sha256: self.manifest.registration_sha256.clone(),
            source_approval_sha256: self.manifest.source_approval_sha256.clone(),
            event_kind,
            signal_id: None,
            event_id: None,
            signal_sha256: None,
            receipt: None,
            checkpoint: Some(checkpoint),
            cycle_report: None,
            role_ledger_chain_head: self.verification.latest_role_ledger_chain_head.clone(),
            case_ledger_chain_head: self.verification.latest_case_ledger_chain_head.clone(),
            recorded_at_unix_ms,
            previous_record_hash: ZERO_HASH.to_owned(),
            record_hash: ZERO_HASH.to_owned(),
        })
    }

    /// Persists the deterministic terminal report after all receipt/checkpoint pairs.
    pub fn append_cycle_report(
        &mut self,
        report: RadarCycleReportV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.append(WorkIntakeLedgerRecordV1 {
            schema_version: 1,
            sequence: 1,
            ledger_id: self.manifest.ledger_id.clone(),
            organization_id: self.manifest.organization_id.clone(),
            role_instance_id: self.manifest.role_instance_id.clone(),
            registration_id: self.manifest.registration_id.clone(),
            registration_sha256: self.manifest.registration_sha256.clone(),
            source_approval_sha256: self.manifest.source_approval_sha256.clone(),
            event_kind: WorkIntakeLedgerEventKindV1::CycleCommitted,
            signal_id: None,
            event_id: None,
            signal_sha256: None,
            receipt: None,
            checkpoint: None,
            cycle_report: Some(report),
            role_ledger_chain_head: self.verification.latest_role_ledger_chain_head.clone(),
            case_ledger_chain_head: self.verification.latest_case_ledger_chain_head.clone(),
            recorded_at_unix_ms,
            previous_record_hash: ZERO_HASH.to_owned(),
            record_hash: ZERO_HASH.to_owned(),
        })
    }

    fn append(&mut self, mut record: WorkIntakeLedgerRecordV1) -> Result<String, DesktopError> {
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "Intake ledger is poisoned after a durable-write failure".to_owned(),
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
        record: &mut WorkIntakeLedgerRecordV1,
    ) -> Result<String, DesktopError> {
        let lock = WorkIntakeLedgerLock::acquire(&self.root)?;
        let latest = verify_work_intake_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "Intake ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "Intake ledger record limit is exhausted".to_owned(),
            ));
        }
        record.schema_version = INTAKE_LEDGER_SCHEMA_VERSION;
        record.sequence = latest.record_count.saturating_add(1);
        record.ledger_id = self.manifest.ledger_id.clone();
        record.organization_id = self.manifest.organization_id.clone();
        record.role_instance_id = self.manifest.role_instance_id.clone();
        record.registration_id = self.manifest.registration_id.clone();
        record.registration_sha256 = self.manifest.registration_sha256.clone();
        record.source_approval_sha256 = self.manifest.source_approval_sha256.clone();
        record.previous_record_hash = latest.terminal_record_hash.clone();
        record.record_hash = ZERO_HASH.to_owned();
        validate_record_transition(record, &latest)?;
        record.record_hash = record_hash(record)?;
        validate_record(record)?;
        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record.clone());
        atomic_replace_state(&self.root, &snapshot)?;
        let verified = verify_work_intake_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "Intake ledger atomic append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        drop(lock);
        Ok(self.verification.terminal_record_hash.clone())
    }
}

/// Initializes one protected Role/registration-scoped Intake ledger.
#[allow(clippy::too_many_arguments)]
pub fn initialize_work_intake_ledger(
    root: &Path,
    ledger_id: &str,
    organization_id: &str,
    role_instance_id: &str,
    registration_id: &str,
    registration_sha256: &str,
    source_approval_sha256: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<WorkIntakeLedgerV1, DesktopError> {
    for (value, label) in [
        (ledger_id, "Intake ledger ID"),
        (organization_id, "Intake organization"),
        (role_instance_id, "Intake Role Instance"),
        (registration_id, "Intake registration"),
    ] {
        validate_token(value, label)?;
    }
    validate_hash(registration_sha256, "Intake registration hash")?;
    validate_hash(source_approval_sha256, "Intake source approval hash")?;
    if maximum_records == 0 || maximum_records > MAX_LEDGER_RECORDS || created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "Intake ledger initialization bounds are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_hash = harden_and_hash(root, "Intake ledger root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_hash =
            harden_and_hash(&manifest_path, "Intake ledger manifest")?;
        let state_security_descriptor_hash = harden_and_hash(&state_path, "Intake ledger state")?;
        let snapshot = WorkIntakeLedgerSnapshotV1 {
            schema_version: INTAKE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            role_instance_id: role_instance_id.to_owned(),
            registration_id: registration_id.to_owned(),
            registration_sha256: registration_sha256.to_owned(),
            source_approval_sha256: source_approval_sha256.to_owned(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_json_bytes(&snapshot)?)?;
        let manifest = WorkIntakeLedgerManifestV1 {
            schema_version: INTAKE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            role_instance_id: role_instance_id.to_owned(),
            registration_id: registration_id.to_owned(),
            registration_sha256: registration_sha256.to_owned(),
            source_approval_sha256: source_approval_sha256.to_owned(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash,
            manifest_security_descriptor_hash,
            state_security_descriptor_hash,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        WorkIntakeLedgerV1::open(root)
    })();
    if initialized.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    initialized
}

/// Replays DACLs, exact identities, hash chain, receipts, and checkpoints.
pub fn verify_work_intake_ledger(
    root: &Path,
) -> Result<WorkIntakeLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != INTAKE_LEDGER_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.organization_id != manifest.organization_id
        || snapshot.role_instance_id != manifest.role_instance_id
        || snapshot.registration_id != manifest.registration_id
        || snapshot.registration_sha256 != manifest.registration_sha256
        || snapshot.source_approval_sha256 != manifest.source_approval_sha256
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "Intake ledger snapshot identity or bounds differ".to_owned(),
        ));
    }
    let mut verification = WorkIntakeLedgerVerificationV1 {
        ledger_id: manifest.ledger_id,
        organization_id: manifest.organization_id,
        role_instance_id: manifest.role_instance_id,
        registration_id: manifest.registration_id,
        registration_sha256: manifest.registration_sha256,
        source_approval_sha256: manifest.source_approval_sha256,
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        current_checkpoint: None,
        pending_checkpoint_sha256: None,
        pending_checkpoint_ledger_head: None,
        processed_event_signals: BTreeMap::new(),
        consumed_signal_hashes: Vec::new(),
        consumed_receipt_hashes: Vec::new(),
        cycle_report_hashes: Vec::new(),
        latest_role_ledger_chain_head: ZERO_HASH.to_owned(),
        latest_case_ledger_chain_head: ZERO_HASH.to_owned(),
        latest_recorded_at_unix_ms: manifest.created_at_unix_ms,
    };
    for record in &snapshot.records {
        validate_record_transition(record, &verification)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.record_hash != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "Intake ledger sequence or hash chain differs".to_owned(),
            ));
        }
        apply_record(record, &mut verification)?;
    }
    Ok(verification)
}

fn validate_record_transition(
    record: &WorkIntakeLedgerRecordV1,
    latest: &WorkIntakeLedgerVerificationV1,
) -> Result<(), DesktopError> {
    validate_record(record)?;
    if record.ledger_id != latest.ledger_id
        || record.organization_id != latest.organization_id
        || record.role_instance_id != latest.role_instance_id
        || record.registration_id != latest.registration_id
        || record.registration_sha256 != latest.registration_sha256
        || record.source_approval_sha256 != latest.source_approval_sha256
        || record.recorded_at_unix_ms < latest.latest_recorded_at_unix_ms
    {
        return Err(DesktopError::Integrity(
            "Intake record differs from durable identity or monotonic time".to_owned(),
        ));
    }
    match record.event_kind {
        WorkIntakeLedgerEventKindV1::CheckpointInitialized => {
            let checkpoint = record.checkpoint.as_ref().ok_or_else(|| {
                DesktopError::Integrity("initial Intake checkpoint is absent".to_owned())
            })?;
            if latest.record_count != 0
                || checkpoint.last_durable_sequence != 0
                || checkpoint.previous_checkpoint_sha256 != ZERO_HASH
                || checkpoint.intake_ledger_chain_head != ZERO_HASH
            {
                return Err(DesktopError::Integrity(
                    "initial Intake checkpoint shape differs".to_owned(),
                ));
            }
        }
        WorkIntakeLedgerEventKindV1::ReceiptCommitted => {
            let receipt = record
                .receipt
                .as_ref()
                .ok_or_else(|| DesktopError::Integrity("Intake receipt is absent".to_owned()))?;
            let checkpoint = latest
                .current_checkpoint
                .as_ref()
                .ok_or_else(|| DesktopError::Integrity("Intake checkpoint is absent".to_owned()))?;
            if latest.pending_checkpoint_sha256.is_some()
                || receipt.checkpoint_before_sha256 != checkpoint.checkpoint_sha256
                || receipt.source_approval_sha256 != latest.source_approval_sha256
                || receipt.intake_ledger_chain_head != record.previous_record_hash
                || record.signal_sha256.as_ref() != Some(&receipt.signal_sha256)
                || record.signal_id.as_ref() != Some(&receipt.signal_id)
            {
                return Err(DesktopError::Integrity(
                    "Intake receipt order or checkpoint binding differs".to_owned(),
                ));
            }
            let event_id = record.event_id.as_ref().ok_or_else(|| {
                DesktopError::Integrity("Intake source event ID is absent".to_owned())
            })?;
            if let Some(existing) = latest.processed_event_signals.get(event_id) {
                let message = if existing == &receipt.signal_sha256 {
                    "Intake source event replayed"
                } else {
                    "Intake source event content changed"
                };
                return Err(DesktopError::Replay(message.to_owned()));
            }
            if latest
                .consumed_signal_hashes
                .binary_search(&receipt.signal_sha256)
                .is_ok()
                || latest
                    .consumed_receipt_hashes
                    .binary_search(&receipt.receipt_sha256)
                    .is_ok()
            {
                return Err(DesktopError::Replay(
                    "Intake signal or receipt replayed".to_owned(),
                ));
            }
        }
        WorkIntakeLedgerEventKindV1::CheckpointAdvanced
        | WorkIntakeLedgerEventKindV1::RecoveryCheckpointRepaired => {
            let checkpoint = record.checkpoint.as_ref().ok_or_else(|| {
                DesktopError::Integrity("advanced Intake checkpoint is absent".to_owned())
            })?;
            let current = latest.current_checkpoint.as_ref().ok_or_else(|| {
                DesktopError::Integrity("prior Intake checkpoint is absent".to_owned())
            })?;
            if latest.pending_checkpoint_sha256.as_ref() != Some(&checkpoint.checkpoint_sha256)
                || latest.pending_checkpoint_ledger_head.as_ref()
                    != Some(&checkpoint.intake_ledger_chain_head)
                || checkpoint.previous_checkpoint_sha256 != current.checkpoint_sha256
                || checkpoint.last_durable_sequence <= current.last_durable_sequence
                || checkpoint.cycle_sequence != current.cycle_sequence.saturating_add(1)
            {
                return Err(DesktopError::Replay(
                    "Intake checkpoint rollback, substitution, or unreceipted advance".to_owned(),
                ));
            }
        }
        WorkIntakeLedgerEventKindV1::CycleCommitted => {
            let report = record.cycle_report.as_ref().ok_or_else(|| {
                DesktopError::Integrity("Intake cycle report is absent".to_owned())
            })?;
            let checkpoint = latest
                .current_checkpoint
                .as_ref()
                .ok_or_else(|| DesktopError::Integrity("cycle checkpoint is absent".to_owned()))?;
            if latest.pending_checkpoint_sha256.is_some()
                || report.checkpoint_after_sha256 != checkpoint.checkpoint_sha256
                || report.registration_id != latest.registration_id
                || report.registration_sha256 != latest.registration_sha256
                || report.source_approval_sha256 != latest.source_approval_sha256
                || report.role_instance_id != latest.role_instance_id
                || report
                    .receipt_hashes
                    .iter()
                    .any(|hash| latest.consumed_receipt_hashes.binary_search(hash).is_err())
                || latest
                    .cycle_report_hashes
                    .binary_search(&report.cycle_sha256)
                    .is_ok()
            {
                return Err(DesktopError::Integrity(
                    "Intake cycle report differs from durable receipts".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_record(record: &WorkIntakeLedgerRecordV1) -> Result<(), DesktopError> {
    if record.schema_version != INTAKE_LEDGER_SCHEMA_VERSION
        || record.sequence == 0
        || record.recorded_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Intake record schema, sequence, or time is invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&record.ledger_id, "Intake ledger ID"),
        (&record.organization_id, "Intake organization"),
        (&record.role_instance_id, "Intake Role Instance"),
        (&record.registration_id, "Intake registration"),
    ] {
        validate_token(value, label)?;
    }
    for (value, label) in [
        (&record.registration_sha256, "Intake registration hash"),
        (
            &record.source_approval_sha256,
            "Intake source approval hash",
        ),
        (&record.role_ledger_chain_head, "Intake Role ledger head"),
        (&record.case_ledger_chain_head, "Intake Case ledger head"),
        (&record.previous_record_hash, "Intake prior record hash"),
        (&record.record_hash, "Intake record hash"),
    ] {
        validate_hash(value, label)?;
    }
    if let Some(value) = &record.signal_id {
        validate_token(value, "Intake signal ID")?;
    }
    if let Some(value) = &record.event_id {
        validate_token(value, "Intake event ID")?;
    }
    if let Some(value) = &record.signal_sha256 {
        validate_hash(value, "Intake signal hash")?;
    }
    if let Some(receipt) = &record.receipt {
        receipt
            .validate()
            .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    }
    if let Some(checkpoint) = &record.checkpoint {
        checkpoint
            .validate()
            .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    }
    if let Some(report) = &record.cycle_report {
        report
            .validate()
            .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    }
    let shapes = usize::from(record.receipt.is_some())
        + usize::from(record.checkpoint.is_some())
        + usize::from(record.cycle_report.is_some());
    if shapes != 1 {
        return Err(DesktopError::Integrity(
            "Intake record shape or canonical hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn apply_record(
    record: &WorkIntakeLedgerRecordV1,
    verification: &mut WorkIntakeLedgerVerificationV1,
) -> Result<(), DesktopError> {
    match record.event_kind {
        WorkIntakeLedgerEventKindV1::CheckpointInitialized
        | WorkIntakeLedgerEventKindV1::CheckpointAdvanced
        | WorkIntakeLedgerEventKindV1::RecoveryCheckpointRepaired => {
            verification.current_checkpoint = record.checkpoint.clone();
            verification.pending_checkpoint_sha256 = None;
            verification.pending_checkpoint_ledger_head = None;
        }
        WorkIntakeLedgerEventKindV1::ReceiptCommitted => {
            let receipt = record.receipt.as_ref().ok_or_else(|| {
                DesktopError::Integrity("verified Intake receipt vanished".to_owned())
            })?;
            let event_id = record.event_id.as_ref().ok_or_else(|| {
                DesktopError::Integrity("verified Intake event vanished".to_owned())
            })?;
            verification
                .processed_event_signals
                .insert(event_id.clone(), receipt.signal_sha256.clone());
            insert_sorted(
                &mut verification.consumed_signal_hashes,
                receipt.signal_sha256.clone(),
            );
            insert_sorted(
                &mut verification.consumed_receipt_hashes,
                receipt.receipt_sha256.clone(),
            );
            verification.pending_checkpoint_sha256 = Some(receipt.checkpoint_after_sha256.clone());
            verification.pending_checkpoint_ledger_head =
                Some(receipt.intake_ledger_chain_head.clone());
        }
        WorkIntakeLedgerEventKindV1::CycleCommitted => {
            let report = record.cycle_report.as_ref().ok_or_else(|| {
                DesktopError::Integrity("verified Intake report vanished".to_owned())
            })?;
            insert_sorted(
                &mut verification.cycle_report_hashes,
                report.cycle_sha256.clone(),
            );
        }
    }
    verification.record_count = record.sequence;
    verification.terminal_record_hash = record.record_hash.clone();
    verification.latest_role_ledger_chain_head = record.role_ledger_chain_head.clone();
    verification.latest_case_ledger_chain_head = record.case_ledger_chain_head.clone();
    verification.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
    Ok(())
}

fn insert_sorted(values: &mut Vec<String>, value: String) {
    values.push(value);
    values.sort();
}

fn record_hash(record: &WorkIntakeLedgerRecordV1) -> Result<String, DesktopError> {
    canonical_sha256(&WorkIntakeLedgerRecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        organization_id: &record.organization_id,
        role_instance_id: &record.role_instance_id,
        registration_id: &record.registration_id,
        registration_sha256: &record.registration_sha256,
        source_approval_sha256: &record.source_approval_sha256,
        event_kind: record.event_kind,
        signal_id: &record.signal_id,
        event_id: &record.event_id,
        signal_sha256: &record.signal_sha256,
        receipt: &record.receipt,
        checkpoint: &record.checkpoint,
        cycle_report: &record.cycle_report,
        role_ledger_chain_head: &record.role_ledger_chain_head,
        case_ledger_chain_head: &record.case_ledger_chain_head,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        previous_record_hash: &record.previous_record_hash,
    })
    .map_err(|error| DesktopError::Json(error.to_string()))
}

fn load_manifest(root: &Path) -> Result<WorkIntakeLedgerManifestV1, DesktopError> {
    let bytes = read_bounded(&root.join(MANIFEST_FILE), MAX_LEDGER_BYTES)?;
    parse_json_strict(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}

fn load_snapshot(root: &Path) -> Result<WorkIntakeLedgerSnapshotV1, DesktopError> {
    let bytes = read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?;
    parse_json_strict(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}

fn verify_storage_security(
    root: &Path,
    manifest: &WorkIntakeLedgerManifestV1,
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
            DesktopError::Integrity(format!("Intake ledger {label} ACL read failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "Intake ledger {label} ACL changed"
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
    snapshot: &WorkIntakeLedgerSnapshotV1,
) -> Result<(), DesktopError> {
    let temporary = root.join(format!(
        ".work-intake-state-{}-{}.tmp",
        std::process::id(),
        snapshot.records.len()
    ));
    let result = (|| {
        write_new(&temporary, &pretty_json_bytes(snapshot)?)?;
        let _ = d2i_windows_host::harden_path_for_current_user(&temporary).map_err(|error| {
            DesktopError::Integrity(format!("temporary Intake state ACL failed: {error}"))
        })?;
        d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
            DesktopError::Io {
                path: root.join(STATE_FILE).display().to_string(),
                message: format!("atomic Intake state replace failed: {error}"),
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

struct WorkIntakeLedgerLock(PathBuf);

impl WorkIntakeLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("Intake ledger lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "Intake ledger lock ACL failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for WorkIntakeLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
