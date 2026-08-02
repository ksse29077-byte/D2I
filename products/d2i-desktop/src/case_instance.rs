use crate::{
    pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_token, write_new,
    DesktopError, FinalGoalVerificationV1, KernelFinalOutcomeV1, KernelTaskRunRecordV1, WorkReport,
};
use d2i_role_contract::{canonical_sha256, RoleInstanceStatusV1, RoleInstanceV1};
use d2i_work_case::{
    evaluate_case_closure, CaseBlockV1, CaseClosureContextV1, CaseClosureEvaluationOutcomeV1,
    CaseClosureEvaluationV1, CaseContractV1, CaseEscalationBindingV1, CaseEvidenceRefV1,
    CaseInstanceV1, CaseLifecycleStatusV1, CaseRefusalV1, CaseSlaStatusSnapshotV1,
    CaseTaskAttemptOutcomeV1, CaseTaskAttemptV1, CaseTaskRequestV1, CaseTerminalOutcomeV1,
    CaseTerminalRecordV1, EvidenceIndexV1, WorkCaseError, WorkItemAdmissionDecisionV1,
    WorkItemAdmissionOutcomeV1, WorkItemDeduplicationEntryV1, WorkItemDeduplicationKeyV1,
    WorkItemV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const CASE_LEDGER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "case-ledger-manifest.json";
const STATE_FILE: &str = "case-ledger-state.json";
const LOCK_FILE: &str = ".case-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_RECORDS: u64 = 65_536;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Closed persistent Case event set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseLedgerEventKindV1 {
    WorkItemReceived,
    WorkItemAdmitted,
    WorkItemDenied,
    WorkItemDuplicate,
    WorkItemClarificationRequired,
    WorkItemEscalationRequired,
    CaseContractCreated,
    CaseOpened,
    CaseOwnershipBound,
    CaseActivated,
    CaseTaskRequested,
    CaseTaskStarted,
    CaseTaskTerminal,
    CaseEvidenceAdded,
    CaseBlocked,
    CaseUnblocked,
    CaseClarificationRequested,
    CaseClarificationReceived,
    CaseVerificationStarted,
    CaseRequirementSatisfied,
    CaseEscalationBound,
    CaseRefusalBound,
    CaseVerifiedComplete,
    CaseTerminal,
    CaseAbortedBeforePersist,
}

/// One hash-only durable event with optional reconstructed Case state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub organization_id: String,
    pub event_kind: CaseLedgerEventKindV1,
    pub work_item_id: String,
    pub work_item_sha256: String,
    pub deduplication_key: Option<WorkItemDeduplicationKeyV1>,
    pub case_id: Option<String>,
    pub case_contract_sha256: Option<String>,
    pub case_instance_after: Option<CaseInstanceV1>,
    pub admission_sha256: Option<String>,
    pub task_request_sha256: Option<String>,
    pub task_attempt_sha256: Option<String>,
    pub kernel_task_run_record_sha256: Option<String>,
    pub evidence_index_sha256: Option<String>,
    pub terminal_record_sha256: Option<String>,
    pub role_ledger_chain_head: String,
    pub kernel_audit_chain_head: String,
    pub artifact_hashes: BTreeMap<String, String>,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct CaseLedgerRecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    organization_id: &'a str,
    event_kind: CaseLedgerEventKindV1,
    work_item_id: &'a str,
    work_item_sha256: &'a str,
    deduplication_key: &'a Option<WorkItemDeduplicationKeyV1>,
    case_id: &'a Option<String>,
    case_contract_sha256: &'a Option<String>,
    case_instance_after: &'a Option<CaseInstanceV1>,
    admission_sha256: &'a Option<String>,
    task_request_sha256: &'a Option<String>,
    task_attempt_sha256: &'a Option<String>,
    kernel_task_run_record_sha256: &'a Option<String>,
    evidence_index_sha256: &'a Option<String>,
    terminal_record_sha256: &'a Option<String>,
    role_ledger_chain_head: &'a str,
    kernel_audit_chain_head: &'a str,
    artifact_hashes: &'a BTreeMap<String, String>,
    recorded_at_unix_ms: u64,
    previous_record_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    state_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    organization_id: String,
    records: Vec<CaseLedgerRecordV1>,
}

/// Reconstructed Case identities, duplicate state, and one-time Task bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLedgerVerificationV1 {
    pub ledger_id: String,
    pub organization_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub work_items: BTreeMap<String, String>,
    pub deduplication_entries: Vec<WorkItemDeduplicationEntryV1>,
    pub case_contract_hashes: BTreeMap<String, String>,
    pub current_instances: BTreeMap<String, CaseInstanceV1>,
    pub consumed_task_request_hashes: Vec<String>,
    pub consumed_task_attempt_hashes: Vec<String>,
    pub consumed_kernel_run_hashes: Vec<String>,
    pub terminal_case_ids: Vec<String>,
    pub latest_role_ledger_chain_head: String,
    pub latest_kernel_audit_chain_head: String,
    pub latest_recorded_at_unix_ms: u64,
}

/// ACL-protected append-only Case ledger.
#[derive(Debug)]
pub struct CaseLedgerV1 {
    root: PathBuf,
    manifest: CaseLedgerManifestV1,
    verification: CaseLedgerVerificationV1,
}

impl CaseLedgerV1 {
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_case_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    #[must_use]
    pub const fn verification(&self) -> &CaseLedgerVerificationV1 {
        &self.verification
    }

    pub fn append(&mut self, mut record: CaseLedgerRecordV1) -> Result<String, DesktopError> {
        let lock = CaseLedgerLock::acquire(&self.root)?;
        let latest = verify_case_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "Case ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "Case ledger record limit is exhausted".to_owned(),
            ));
        }
        record.schema_version = CASE_LEDGER_SCHEMA_VERSION;
        record.sequence = latest.record_count.saturating_add(1);
        record.ledger_id = self.manifest.ledger_id.clone();
        record.organization_id = self.manifest.organization_id.clone();
        record.previous_record_hash = latest.terminal_record_hash.clone();
        record.record_hash = ZERO_HASH.to_owned();
        validate_record_transition(&record, &latest)?;
        record.record_hash = record_hash(&record)?;
        validate_record(&record)?;
        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record);
        atomic_replace_state(&self.root, &snapshot)?;
        let verified = verify_case_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "Case ledger atomic append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        drop(lock);
        Ok(self.verification.terminal_record_hash.clone())
    }
}

/// Initializes one protected organization-scoped Case ledger.
pub fn initialize_case_ledger(
    root: &Path,
    ledger_id: &str,
    organization_id: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<CaseLedgerV1, DesktopError> {
    validate_token(ledger_id, "Case ledger_id")?;
    validate_token(organization_id, "Case organization_id")?;
    if maximum_records == 0 || maximum_records > MAX_LEDGER_RECORDS || created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "Case ledger initialization bounds are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_hash = harden_and_hash(root, "Case ledger root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_hash =
            harden_and_hash(&manifest_path, "Case ledger manifest")?;
        let state_security_descriptor_hash = harden_and_hash(&state_path, "Case ledger state")?;
        let snapshot = CaseLedgerSnapshotV1 {
            schema_version: CASE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_json_bytes(&snapshot)?)?;
        let manifest = CaseLedgerManifestV1 {
            schema_version: CASE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            organization_id: organization_id.to_owned(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash,
            manifest_security_descriptor_hash,
            state_security_descriptor_hash,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        CaseLedgerV1::open(root)
    })();
    if initialized.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    initialized
}

/// Replays and verifies ACLs, identity, hash chain, deduplication, and terminal state.
pub fn verify_case_ledger(root: &Path) -> Result<CaseLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != CASE_LEDGER_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.organization_id != manifest.organization_id
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "Case ledger snapshot identity or bounds differ".to_owned(),
        ));
    }
    let mut verification = CaseLedgerVerificationV1 {
        ledger_id: manifest.ledger_id,
        organization_id: manifest.organization_id,
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        work_items: BTreeMap::new(),
        deduplication_entries: Vec::new(),
        case_contract_hashes: BTreeMap::new(),
        current_instances: BTreeMap::new(),
        consumed_task_request_hashes: Vec::new(),
        consumed_task_attempt_hashes: Vec::new(),
        consumed_kernel_run_hashes: Vec::new(),
        terminal_case_ids: Vec::new(),
        latest_role_ledger_chain_head: ZERO_HASH.to_owned(),
        latest_kernel_audit_chain_head: ZERO_HASH.to_owned(),
        latest_recorded_at_unix_ms: manifest.created_at_unix_ms,
    };
    for record in &snapshot.records {
        validate_record_transition(record, &verification)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.record_hash != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "Case ledger sequence or hash chain differs".to_owned(),
            ));
        }
        apply_record(record, &mut verification)?;
    }
    Ok(verification)
}

fn validate_record_transition(
    record: &CaseLedgerRecordV1,
    latest: &CaseLedgerVerificationV1,
) -> Result<(), DesktopError> {
    validate_record(record)?;
    if record.ledger_id != latest.ledger_id
        || record.organization_id != latest.organization_id
        || record.recorded_at_unix_ms < latest.latest_recorded_at_unix_ms
    {
        return Err(DesktopError::Integrity(
            "Case record differs from durable identity or monotonic time".to_owned(),
        ));
    }
    if latest
        .work_items
        .get(&record.work_item_id)
        .is_some_and(|hash| hash != &record.work_item_sha256)
    {
        return Err(DesktopError::Integrity(
            "Work Item ID was substituted in place".to_owned(),
        ));
    }
    if record.event_kind == CaseLedgerEventKindV1::WorkItemAdmitted
        && record.deduplication_key.as_ref().is_some_and(|key| {
            latest
                .deduplication_entries
                .iter()
                .any(|entry| entry.key.key_sha256 == key.key_sha256)
        })
    {
        return Err(DesktopError::Replay(
            "duplicate Work Item admission would create another Case".to_owned(),
        ));
    }
    if record.event_kind == CaseLedgerEventKindV1::CaseContractCreated
        && record
            .case_id
            .as_ref()
            .is_some_and(|case_id| latest.case_contract_hashes.contains_key(case_id))
    {
        return Err(DesktopError::Replay(
            "duplicate Case Contract creation is not allowed".to_owned(),
        ));
    }
    if record.case_id.as_ref().is_some_and(|case_id| {
        latest.terminal_case_ids.binary_search(case_id).is_ok()
            && record.event_kind != CaseLedgerEventKindV1::CaseTerminal
    }) {
        return Err(DesktopError::Replay(
            "terminal Case received an additional ledger mutation".to_owned(),
        ));
    }
    for (values, candidate, label) in [
        (
            &latest.consumed_task_request_hashes,
            &record.task_request_sha256,
            "Case Task request",
        ),
        (
            &latest.consumed_task_attempt_hashes,
            &record.task_attempt_sha256,
            "Case Task attempt",
        ),
        (
            &latest.consumed_kernel_run_hashes,
            &record.kernel_task_run_record_sha256,
            "Kernel Task run",
        ),
    ] {
        if candidate
            .as_ref()
            .is_some_and(|value| values.binary_search(value).is_ok())
        {
            return Err(DesktopError::Replay(format!("Case ledger reused {label}")));
        }
    }
    if let (Some(case_id), Some(contract_hash)) = (&record.case_id, &record.case_contract_sha256) {
        if latest
            .case_contract_hashes
            .get(case_id)
            .is_some_and(|hash| hash != contract_hash)
        {
            return Err(DesktopError::Integrity(
                "Case Contract was substituted in place".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_record(record: &CaseLedgerRecordV1) -> Result<(), DesktopError> {
    if record.schema_version != CASE_LEDGER_SCHEMA_VERSION
        || record.sequence == 0
        || record.recorded_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Case ledger record schema, sequence, or time is invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&record.ledger_id, "Case record ledger_id"),
        (&record.organization_id, "Case record organization"),
        (&record.work_item_id, "Case record Work Item"),
    ] {
        validate_token(value, label)?;
    }
    for (hash, label) in [
        (&record.work_item_sha256, "Case record Work Item hash"),
        (
            &record.role_ledger_chain_head,
            "Case record Role ledger head",
        ),
        (
            &record.kernel_audit_chain_head,
            "Case record Kernel audit head",
        ),
        (&record.previous_record_hash, "Case record previous hash"),
        (&record.record_hash, "Case record hash"),
    ] {
        validate_hash(hash, label)?;
    }
    if let Some(key) = &record.deduplication_key {
        key.validate().map_err(work_case_error)?;
    }
    if let Some(case_id) = &record.case_id {
        validate_token(case_id, "Case record case_id")?;
    }
    for (value, label) in [
        (&record.case_contract_sha256, "Case record contract"),
        (&record.admission_sha256, "Case record admission"),
        (&record.task_request_sha256, "Case record Task request"),
        (&record.task_attempt_sha256, "Case record Task attempt"),
        (
            &record.kernel_task_run_record_sha256,
            "Case record Kernel run",
        ),
        (&record.evidence_index_sha256, "Case record evidence index"),
        (&record.terminal_record_sha256, "Case terminal record"),
    ] {
        if let Some(hash) = value {
            validate_hash(hash, label)?;
        }
    }
    if let Some(instance) = &record.case_instance_after {
        instance.validate().map_err(work_case_error)?;
        if record.case_id.as_ref() != Some(&instance.case_id) {
            return Err(DesktopError::Integrity(
                "Case record instance belongs to another Case".to_owned(),
            ));
        }
    }
    if record.artifact_hashes.len() > 128 {
        return Err(DesktopError::Invalid(
            "Case record artifact map exceeds bounds".to_owned(),
        ));
    }
    for (key, value) in &record.artifact_hashes {
        validate_token(key, "Case artifact kind")?;
        validate_hash(value, "Case artifact hash")?;
    }
    Ok(())
}

fn apply_record(
    record: &CaseLedgerRecordV1,
    verification: &mut CaseLedgerVerificationV1,
) -> Result<(), DesktopError> {
    verification
        .work_items
        .insert(record.work_item_id.clone(), record.work_item_sha256.clone());
    if record.event_kind == CaseLedgerEventKindV1::WorkItemAdmitted {
        let key = record.deduplication_key.clone().ok_or_else(|| {
            DesktopError::Integrity("admitted Work Item lacks dedup key".to_owned())
        })?;
        if verification
            .deduplication_entries
            .iter()
            .any(|entry| entry.key.key_sha256 == key.key_sha256)
        {
            return Err(DesktopError::Replay(
                "duplicate admitted Work Item entered the Case ledger".to_owned(),
            ));
        }
        verification
            .deduplication_entries
            .push(WorkItemDeduplicationEntryV1 {
                key,
                work_item_id: record.work_item_id.clone(),
                work_item_sha256: record.work_item_sha256.clone(),
                case_id: record.case_id.clone(),
                terminal: false,
            });
        verification
            .deduplication_entries
            .sort_by(|left, right| left.key.key_sha256.cmp(&right.key.key_sha256));
    }
    if record.event_kind == CaseLedgerEventKindV1::CaseContractCreated {
        let case_id = record.case_id.as_ref().ok_or_else(|| {
            DesktopError::Integrity("Case Contract event lacks Case ID".to_owned())
        })?;
        let contract_hash = record.case_contract_sha256.as_ref().ok_or_else(|| {
            DesktopError::Integrity("Case Contract event lacks contract hash".to_owned())
        })?;
        verification
            .case_contract_hashes
            .insert(case_id.clone(), contract_hash.clone());
    }
    if let Some(instance) = &record.case_instance_after {
        verification
            .current_instances
            .insert(instance.case_id.clone(), instance.clone());
    }
    consume_once(
        &mut verification.consumed_task_request_hashes,
        &record.task_request_sha256,
        "Task request",
    )?;
    consume_once(
        &mut verification.consumed_task_attempt_hashes,
        &record.task_attempt_sha256,
        "Task attempt",
    )?;
    consume_once(
        &mut verification.consumed_kernel_run_hashes,
        &record.kernel_task_run_record_sha256,
        "Kernel run",
    )?;
    if record.event_kind == CaseLedgerEventKindV1::CaseTerminal {
        let case_id = record
            .case_id
            .clone()
            .ok_or_else(|| DesktopError::Integrity("terminal record lacks Case ID".to_owned()))?;
        insert_once(
            &mut verification.terminal_case_ids,
            case_id,
            "terminal Case",
        )?;
        for entry in &mut verification.deduplication_entries {
            if entry.case_id.as_ref() == record.case_id.as_ref() {
                entry.terminal = true;
            }
        }
    }
    verification.record_count = record.sequence;
    verification.terminal_record_hash = record.record_hash.clone();
    verification.latest_role_ledger_chain_head = record.role_ledger_chain_head.clone();
    verification.latest_kernel_audit_chain_head = record.kernel_audit_chain_head.clone();
    verification.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
    Ok(())
}

fn record_hash(record: &CaseLedgerRecordV1) -> Result<String, DesktopError> {
    canonical_sha256(&CaseLedgerRecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        organization_id: &record.organization_id,
        event_kind: record.event_kind,
        work_item_id: &record.work_item_id,
        work_item_sha256: &record.work_item_sha256,
        deduplication_key: &record.deduplication_key,
        case_id: &record.case_id,
        case_contract_sha256: &record.case_contract_sha256,
        case_instance_after: &record.case_instance_after,
        admission_sha256: &record.admission_sha256,
        task_request_sha256: &record.task_request_sha256,
        task_attempt_sha256: &record.task_attempt_sha256,
        kernel_task_run_record_sha256: &record.kernel_task_run_record_sha256,
        evidence_index_sha256: &record.evidence_index_sha256,
        terminal_record_sha256: &record.terminal_record_sha256,
        role_ledger_chain_head: &record.role_ledger_chain_head,
        kernel_audit_chain_head: &record.kernel_audit_chain_head,
        artifact_hashes: &record.artifact_hashes,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        previous_record_hash: &record.previous_record_hash,
    })
    .map_err(|error| DesktopError::Json(error.to_string()))
}

fn load_manifest(root: &Path) -> Result<CaseLedgerManifestV1, DesktopError> {
    let bytes = read_bounded(&root.join(MANIFEST_FILE), MAX_LEDGER_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}

fn load_snapshot(root: &Path) -> Result<CaseLedgerSnapshotV1, DesktopError> {
    let bytes = read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|error| DesktopError::Json(error.to_string()))
}

fn verify_storage_security(
    root: &Path,
    manifest: &CaseLedgerManifestV1,
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
            DesktopError::Integrity(format!("Case ledger {label} ACL read failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "Case ledger {label} ACL changed"
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

fn atomic_replace_state(root: &Path, snapshot: &CaseLedgerSnapshotV1) -> Result<(), DesktopError> {
    let temporary = root.join(format!(
        ".case-state-{}-{}.tmp",
        std::process::id(),
        snapshot.records.len()
    ));
    let result = (|| {
        write_new(&temporary, &pretty_json_bytes(snapshot)?)?;
        let _ = d2i_windows_host::harden_path_for_current_user(&temporary).map_err(|error| {
            DesktopError::Integrity(format!("temporary Case state ACL failed: {error}"))
        })?;
        d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
            DesktopError::Io {
                path: root.join(STATE_FILE).display().to_string(),
                message: format!("atomic Case state replace failed: {error}"),
            }
        })
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn consume_once(
    values: &mut Vec<String>,
    value: &Option<String>,
    label: &str,
) -> Result<(), DesktopError> {
    if let Some(value) = value {
        insert_once(values, value.clone(), label)?;
    }
    Ok(())
}

fn insert_once(values: &mut Vec<String>, value: String, label: &str) -> Result<(), DesktopError> {
    if values.binary_search(&value).is_ok() {
        return Err(DesktopError::Replay(format!(
            "Case ledger replayed {label}"
        )));
    }
    values.push(value);
    values.sort();
    Ok(())
}

fn work_case_error(error: WorkCaseError) -> DesktopError {
    match error {
        WorkCaseError::Invalid(message) => DesktopError::Invalid(message),
        WorkCaseError::Integrity(message) => DesktopError::Integrity(message),
        WorkCaseError::NotAdmissible(message) => DesktopError::AccessDenied(message),
        WorkCaseError::Replay(message) | WorkCaseError::Terminal(message) => {
            DesktopError::Replay(message)
        }
        WorkCaseError::Json(message) => DesktopError::Json(message),
        WorkCaseError::Io(message) => DesktopError::Io {
            path: "work-case".to_owned(),
            message,
        },
    }
}

struct CaseLedgerLock(PathBuf);

impl CaseLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("Case ledger lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "Case ledger lock ACL failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for CaseLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Validated output from one existing role-bound KRN-500 invocation.
pub struct CaseKernelArtifactsV1 {
    pub run_record: KernelTaskRunRecordV1,
    pub work_report: WorkReport,
    pub final_goal_verification: Option<FinalGoalVerificationV1>,
    pub terminal_role_instance: RoleInstanceV1,
    pub outcome: CaseTaskAttemptOutcomeV1,
    pub produced_evidence_refs: Vec<CaseEvidenceRefV1>,
    pub started_at_unix_seconds: u64,
    pub completed_at_unix_seconds: u64,
}

/// Durable single-Case coordinator layered around the existing Kernel task runtime.
#[derive(Debug)]
pub struct WorkCaseCoordinatorV1 {
    ledger: CaseLedgerV1,
    contract: CaseContractV1,
    instance: CaseInstanceV1,
    evidence_index: EvidenceIndexV1,
    attempts: Vec<CaseTaskAttemptV1>,
    role_ledger_chain_head: String,
    kernel_audit_chain_head: String,
    terminal: bool,
    poisoned: bool,
}

impl WorkCaseCoordinatorV1 {
    /// Opens a coordinator only when durable state exactly matches supplied artifacts.
    pub fn open(
        ledger: CaseLedgerV1,
        contract: CaseContractV1,
        evidence_index: EvidenceIndexV1,
        attempts: Vec<CaseTaskAttemptV1>,
        role_ledger_chain_head: String,
        kernel_audit_chain_head: String,
    ) -> Result<Self, DesktopError> {
        contract.validate().map_err(work_case_error)?;
        evidence_index.validate().map_err(work_case_error)?;
        validate_hash(&role_ledger_chain_head, "Case coordinator Role ledger")?;
        validate_hash(&kernel_audit_chain_head, "Case coordinator audit")?;
        let instance = ledger
            .verification()
            .current_instances
            .get(&contract.case_id)
            .cloned()
            .ok_or_else(|| DesktopError::Integrity("durable Case state is absent".to_owned()))?;
        instance
            .validate_against(&contract)
            .map_err(work_case_error)?;
        if instance.evidence_index_sha256 != evidence_index.index_sha256
            || ledger
                .verification()
                .case_contract_hashes
                .get(&contract.case_id)
                != Some(&contract.contract_sha256)
            || ledger.verification().latest_role_ledger_chain_head != role_ledger_chain_head
            || ledger.verification().latest_kernel_audit_chain_head != kernel_audit_chain_head
        {
            return Err(DesktopError::Integrity(
                "coordinator artifacts differ from durable Case ledger".to_owned(),
            ));
        }
        let terminal = instance.current_status == CaseLifecycleStatusV1::Terminal;
        Ok(Self {
            ledger,
            contract,
            instance,
            evidence_index,
            attempts,
            role_ledger_chain_head,
            kernel_audit_chain_head,
            terminal,
            poisoned: false,
        })
    }

    #[must_use]
    pub const fn instance(&self) -> &CaseInstanceV1 {
        &self.instance
    }

    #[must_use]
    pub const fn evidence_index(&self) -> &EvidenceIndexV1 {
        &self.evidence_index
    }

    #[must_use]
    pub fn attempts(&self) -> &[CaseTaskAttemptV1] {
        &self.attempts
    }

    /// Activates an opened Case after a fresh active-Role check.
    pub fn activate(
        &mut self,
        role_instance: &RoleInstanceV1,
        at_unix_seconds: u64,
    ) -> Result<(), DesktopError> {
        self.ensure_mutable()?;
        self.validate_fresh_owner_role(role_instance, at_unix_seconds)?;
        let next = self
            .instance
            .transition_non_terminal(CaseLifecycleStatusV1::Active, at_unix_seconds, None)
            .map_err(work_case_error)?;
        self.persist_state(
            CaseLedgerEventKindV1::CaseActivated,
            next,
            at_unix_seconds,
            None,
            None,
            None,
        )
    }

    /// Creates and persists a one-time Task request before Kernel invocation.
    pub fn begin_task(
        &mut self,
        request: CaseTaskRequestV1,
        role_instance: &RoleInstanceV1,
    ) -> Result<(), DesktopError> {
        self.ensure_mutable()?;
        self.validate_fresh_owner_role(role_instance, request.requested_at_unix_seconds)?;
        request
            .validate_against(&self.contract, &self.instance)
            .map_err(work_case_error)?;
        let record = self.record(
            CaseLedgerEventKindV1::CaseTaskRequested,
            request.requested_at_unix_seconds,
            Some(self.instance.clone()),
            Some(request.request_sha256),
            None,
            None,
        );
        self.append_record(record)
    }

    /// Executes a caller-supplied existing Kernel entrypoint and binds only validated artifacts.
    pub fn run_case_task<F>(
        &mut self,
        request: &CaseTaskRequestV1,
        run_role_bound_kernel_task: F,
    ) -> Result<CaseTaskAttemptV1, DesktopError>
    where
        F: FnOnce() -> Result<CaseKernelArtifactsV1, DesktopError>,
    {
        self.ensure_mutable()?;
        if self
            .ledger
            .verification()
            .consumed_task_request_hashes
            .binary_search(&request.request_sha256)
            .is_err()
        {
            return Err(DesktopError::AccessDenied(
                "Case Task request was not durably persisted".to_owned(),
            ));
        }
        let artifacts = run_role_bound_kernel_task()?;
        self.bind_kernel_artifacts(request, artifacts)
    }

    /// Verifies and appends one KRN Task terminal result without auto-closing the Case.
    pub fn bind_kernel_artifacts(
        &mut self,
        request: &CaseTaskRequestV1,
        artifacts: CaseKernelArtifactsV1,
    ) -> Result<CaseTaskAttemptV1, DesktopError> {
        self.ensure_mutable()?;
        artifacts.run_record.validate(&artifacts.work_report)?;
        artifacts
            .terminal_role_instance
            .validate_shape()
            .map_err(|error| {
                DesktopError::Integrity(format!("terminal owner Role Instance is invalid: {error}"))
            })?;
        let ownership = &self.contract.ownership_binding;
        if artifacts.terminal_role_instance.current_status != RoleInstanceStatusV1::Active
            || artifacts.terminal_role_instance.role_instance_id != ownership.role_instance_id
            || artifacts.terminal_role_instance.role_contract_id != ownership.role_contract_id
            || artifacts.terminal_role_instance.role_version != ownership.role_version
            || artifacts.terminal_role_instance.contract_sha256 != ownership.role_contract_sha256
            || artifacts.terminal_role_instance.delegation_sha256 != ownership.delegation_sha256
            || artifacts.terminal_role_instance.organization_id != ownership.organization_id
            || artifacts.terminal_role_instance.activated_at_unix_seconds
                > Some(artifacts.started_at_unix_seconds)
            || artifacts.completed_at_unix_seconds
                >= artifacts.terminal_role_instance.expires_at_unix_seconds
        {
            return Err(DesktopError::Integrity(
                "terminal Role Instance differs from exact Case ownership or KRN time".to_owned(),
            ));
        }
        if artifacts.run_record.role_context_sha256.as_ref()
            != Some(&request.role_bound_kernel_context_sha256)
            || artifacts.run_record.authenticated_instruction_sha256
                != request.authenticated_instruction_sha256
            || artifacts.run_record.goal_spec_sha256 != request.goal_spec_sha256
            || artifacts.run_record.application_pack_sha256 != request.application_pack_sha256
        {
            return Err(DesktopError::Integrity(
                "Kernel run differs from exact Case Task bindings".to_owned(),
            ));
        }
        if let Some(final_goal) = &artifacts.final_goal_verification {
            final_goal.validate()?;
            if final_goal.final_verification_sha256
                != artifacts.run_record.final_goal_verification_sha256
            {
                return Err(DesktopError::Integrity(
                    "Kernel final verification substitution detected".to_owned(),
                ));
            }
        }
        validate_attempt_outcome(&artifacts)?;
        let mut evidence_index = self.evidence_index.clone();
        let mut evidence_ref_ids = Vec::new();
        for evidence in artifacts.produced_evidence_refs {
            evidence_ref_ids.push(evidence.evidence_id.clone());
            evidence_index = evidence_index.append(evidence).map_err(work_case_error)?;
        }
        evidence_ref_ids.sort();
        let satisfied = if matches!(
            artifacts.outcome,
            CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
                | CaseTaskAttemptOutcomeV1::VerifiedPartial
        ) {
            request.addressed_requirement_ids.clone()
        } else {
            Vec::new()
        };
        let attempt = CaseTaskAttemptV1 {
            schema_version: 1,
            attempt_id: format!("attempt:{}:{}", request.case_id, request.task_sequence),
            case_id: request.case_id.clone(),
            case_task_request_sha256: request.request_sha256.clone(),
            task_sequence: request.task_sequence,
            role_task_admission_sha256: request.role_task_admission_sha256.clone(),
            role_bound_kernel_context_sha256: request.role_bound_kernel_context_sha256.clone(),
            kernel_task_run_record_sha256: artifacts.run_record.run_record_sha256.clone(),
            work_report_sha256: artifacts.run_record.work_report_sha256.clone(),
            final_goal_verification_sha256: artifacts
                .final_goal_verification
                .map(|value| value.final_verification_sha256),
            verified_action_result_hashes: artifacts
                .run_record
                .verified_action_result_hashes
                .clone(),
            recovery_result_hashes: artifacts.run_record.recovery_result_hashes.clone(),
            execution_receipt_hashes: artifacts.run_record.execution_receipt_hashes.clone(),
            outcome: artifacts.outcome,
            addressed_requirement_ids: request.addressed_requirement_ids.clone(),
            satisfied_requirement_ids: satisfied,
            produced_evidence_ref_ids: evidence_ref_ids,
            started_at_unix_seconds: artifacts.started_at_unix_seconds,
            completed_at_unix_seconds: artifacts.completed_at_unix_seconds,
            evidence_ids: vec![format!("case-attempt-evidence-{}", request.task_sequence)],
            attempt_sha256: ZERO_HASH.to_owned(),
        }
        .seal_against(request)
        .map_err(work_case_error)?;
        let next = self
            .instance
            .attach_attempt(
                &self.contract,
                &attempt,
                evidence_index.index_sha256.clone(),
            )
            .map_err(work_case_error)?
            .bind_ledger_head(self.ledger.verification().terminal_record_hash.clone())
            .map_err(work_case_error)?;
        let mut record = self.record(
            CaseLedgerEventKindV1::CaseTaskTerminal,
            artifacts.completed_at_unix_seconds,
            Some(next.clone()),
            None,
            Some(attempt.attempt_sha256.clone()),
            Some(attempt.kernel_task_run_record_sha256.clone()),
        );
        record.role_ledger_chain_head = artifacts.terminal_role_instance.ledger_chain_head.clone();
        record.evidence_index_sha256 = Some(evidence_index.index_sha256.clone());
        self.append_record(record)?;
        self.role_ledger_chain_head = artifacts.terminal_role_instance.ledger_chain_head;
        self.instance = next;
        self.evidence_index = evidence_index;
        self.attempts.push(attempt.clone());
        Ok(attempt)
    }

    /// Evaluates the current Case boundary without closing it.
    pub fn evaluate_current(
        &self,
        blocks: &[CaseBlockV1],
        unsafe_evidence_ids: &[String],
        ownership_role_valid: bool,
        evaluated_at_unix_seconds: u64,
    ) -> Result<CaseClosureEvaluationV1, DesktopError> {
        evaluate_case_closure(CaseClosureContextV1 {
            contract: &self.contract,
            instance: &self.instance,
            evidence_index: &self.evidence_index,
            attempts: &self.attempts,
            unresolved_blocks: blocks,
            unsafe_evidence_ids,
            refusal: None,
            escalation: None,
            ownership_role_valid,
            audit_integrity_valid: true,
            ledger_integrity_valid: true,
            evaluated_at_unix_seconds,
        })
        .map_err(work_case_error)
    }

    /// Moves the Case to one legal boundary state without inventing a terminal outcome.
    pub fn transition_boundary(
        &mut self,
        next_status: CaseLifecycleStatusV1,
        block: Option<&CaseBlockV1>,
        at_unix_seconds: u64,
    ) -> Result<(), DesktopError> {
        self.ensure_mutable()?;
        let block_hash = block.map(|value| value.block_sha256.clone());
        if let Some(value) = block {
            value.validate().map_err(work_case_error)?;
            if value.case_id != self.contract.case_id {
                return Err(DesktopError::Integrity(
                    "Case block belongs to another Case".to_owned(),
                ));
            }
        }
        let next = self
            .instance
            .transition_non_terminal(next_status, at_unix_seconds, block_hash)
            .map_err(work_case_error)?;
        let event = match next_status {
            CaseLifecycleStatusV1::Blocked => CaseLedgerEventKindV1::CaseBlocked,
            CaseLifecycleStatusV1::AwaitingClarification => {
                CaseLedgerEventKindV1::CaseClarificationRequested
            }
            CaseLifecycleStatusV1::AwaitingVerification => {
                CaseLedgerEventKindV1::CaseVerificationStarted
            }
            CaseLifecycleStatusV1::EscalationPending => CaseLedgerEventKindV1::CaseEscalationBound,
            CaseLifecycleStatusV1::Active => {
                if self.instance.current_status == CaseLifecycleStatusV1::Blocked {
                    CaseLedgerEventKindV1::CaseUnblocked
                } else {
                    CaseLedgerEventKindV1::CaseActivated
                }
            }
            CaseLifecycleStatusV1::Opened | CaseLifecycleStatusV1::Terminal => {
                return Err(DesktopError::Invalid(
                    "coordinator boundary transition target is invalid".to_owned(),
                ));
            }
        };
        self.persist_state(event, next, at_unix_seconds, None, None, None)
    }

    /// Persists a verified-complete terminal Case and immutable terminal inventory.
    pub fn close_verified(
        &mut self,
        evaluation: &CaseClosureEvaluationV1,
        terminal_at_unix_seconds: u64,
        sla_status_snapshot: CaseSlaStatusSnapshotV1,
        evidence_ids: Vec<String>,
    ) -> Result<CaseTerminalRecordV1, DesktopError> {
        if evaluation.outcome != CaseClosureEvaluationOutcomeV1::VerifiedComplete {
            return Err(DesktopError::AccessDenied(
                "only verified closure may use close_verified".to_owned(),
            ));
        }
        self.close_terminal(
            evaluation,
            CaseTerminalOutcomeV1::VerifiedComplete,
            None,
            None,
            terminal_at_unix_seconds,
            sla_status_snapshot,
            evidence_ids,
            CaseLedgerEventKindV1::CaseVerifiedComplete,
        )
    }

    /// Persists an authorized explicit refusal without disguising runtime failure as refusal.
    pub fn close_refusal(
        &mut self,
        evaluation: &CaseClosureEvaluationV1,
        refusal: &CaseRefusalV1,
        terminal_at_unix_seconds: u64,
        sla_status_snapshot: CaseSlaStatusSnapshotV1,
        evidence_ids: Vec<String>,
    ) -> Result<CaseTerminalRecordV1, DesktopError> {
        if evaluation.outcome != CaseClosureEvaluationOutcomeV1::ExplicitRefusalValid {
            return Err(DesktopError::AccessDenied(
                "explicit refusal closure requires an exact authorized refusal".to_owned(),
            ));
        }
        self.close_terminal(
            evaluation,
            CaseTerminalOutcomeV1::ExplicitRefusal,
            Some(refusal),
            None,
            terminal_at_unix_seconds,
            sla_status_snapshot,
            evidence_ids,
            CaseLedgerEventKindV1::CaseRefusalBound,
        )
    }

    /// Persists an exact Recovery escalation binding as the terminal Case outcome.
    pub fn close_escalated(
        &mut self,
        evaluation: &CaseClosureEvaluationV1,
        escalation: &CaseEscalationBindingV1,
        terminal_at_unix_seconds: u64,
        sla_status_snapshot: CaseSlaStatusSnapshotV1,
        evidence_ids: Vec<String>,
    ) -> Result<CaseTerminalRecordV1, DesktopError> {
        if evaluation.outcome != CaseClosureEvaluationOutcomeV1::EscalatedValid {
            return Err(DesktopError::AccessDenied(
                "escalated closure requires an exact Recovery escalation binding".to_owned(),
            ));
        }
        self.close_terminal(
            evaluation,
            CaseTerminalOutcomeV1::Escalated,
            None,
            Some(escalation),
            terminal_at_unix_seconds,
            sla_status_snapshot,
            evidence_ids,
            CaseLedgerEventKindV1::CaseEscalationBound,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn close_terminal(
        &mut self,
        evaluation: &CaseClosureEvaluationV1,
        outcome: CaseTerminalOutcomeV1,
        refusal: Option<&CaseRefusalV1>,
        escalation: Option<&CaseEscalationBindingV1>,
        terminal_at_unix_seconds: u64,
        sla_status_snapshot: CaseSlaStatusSnapshotV1,
        mut evidence_ids: Vec<String>,
        proof_event: CaseLedgerEventKindV1,
    ) -> Result<CaseTerminalRecordV1, DesktopError> {
        self.ensure_mutable()?;
        evidence_ids.sort();
        let escalation_sha256 = escalation.map(|value| value.binding_sha256.clone());
        let final_instance = self
            .instance
            .close(
                evaluation,
                outcome,
                terminal_at_unix_seconds,
                escalation_sha256.clone(),
            )
            .map_err(work_case_error)?
            .bind_ledger_head(self.ledger.verification().terminal_record_hash.clone())
            .map_err(work_case_error)?;
        let finalized_evidence = self.evidence_index.finalize().map_err(work_case_error)?;
        let mut verified_record = self.record(
            proof_event,
            terminal_at_unix_seconds,
            Some(final_instance.clone()),
            None,
            None,
            None,
        );
        verified_record.evidence_index_sha256 = Some(finalized_evidence.index_sha256.clone());
        self.append_record(verified_record)?;

        let mut verified_result_hashes = Vec::new();
        let mut recovery_result_hashes = Vec::new();
        for attempt in &self.attempts {
            if let Some(hash) = &attempt.final_goal_verification_sha256 {
                verified_result_hashes.push(hash.clone());
            }
            verified_result_hashes.extend(attempt.verified_action_result_hashes.clone());
            recovery_result_hashes.extend(attempt.recovery_result_hashes.clone());
        }
        let terminal_record = CaseTerminalRecordV1 {
            schema_version: 1,
            terminal_record_id: format!("terminal:{}", self.contract.case_id),
            case_id: self.contract.case_id.clone(),
            case_contract_sha256: self.contract.contract_sha256.clone(),
            final_case_instance_sha256: final_instance.instance_sha256.clone(),
            ownership_sha256: self.contract.ownership_binding.ownership_sha256.clone(),
            terminal_outcome: outcome,
            closure_evaluation_sha256: evaluation.evaluation_sha256.clone(),
            refusal_sha256: refusal.map(|value| value.refusal_sha256.clone()),
            escalation_binding_sha256: escalation_sha256,
            evidence_index_sha256: finalized_evidence.index_sha256.clone(),
            task_attempt_hashes: self
                .attempts
                .iter()
                .map(|attempt| attempt.attempt_sha256.clone())
                .collect(),
            kernel_task_run_record_hashes: self
                .attempts
                .iter()
                .map(|attempt| attempt.kernel_task_run_record_sha256.clone())
                .collect(),
            work_report_hashes: self
                .attempts
                .iter()
                .map(|attempt| attempt.work_report_sha256.clone())
                .collect(),
            verified_result_hashes,
            recovery_result_hashes,
            opened_at_unix_seconds: self.contract.opened_at_unix_seconds,
            terminal_at_unix_seconds,
            duration_seconds: terminal_at_unix_seconds
                .saturating_sub(self.contract.opened_at_unix_seconds),
            sla_binding_sha256: self.contract.sla_binding.binding_sha256.clone(),
            sla_status_snapshot,
            reporting_obligation_ids: self.contract.reporting_obligation_ids.clone(),
            audit_chain_head: self.kernel_audit_chain_head.clone(),
            case_ledger_chain_head: self.ledger.verification().terminal_record_hash.clone(),
            evidence_ids,
            terminal_record_sha256: ZERO_HASH.to_owned(),
        }
        .seal_against(
            &self.contract,
            &final_instance,
            evaluation,
            &finalized_evidence,
            &self.attempts,
            refusal,
            escalation,
        )
        .map_err(work_case_error)?;
        let mut terminal_event = self.record(
            CaseLedgerEventKindV1::CaseTerminal,
            terminal_at_unix_seconds,
            Some(final_instance.clone()),
            None,
            None,
            None,
        );
        terminal_event.evidence_index_sha256 = Some(finalized_evidence.index_sha256.clone());
        terminal_event.terminal_record_sha256 =
            Some(terminal_record.terminal_record_sha256.clone());
        self.append_record(terminal_event)?;
        self.instance = final_instance;
        self.evidence_index = finalized_evidence;
        self.terminal = true;
        Ok(terminal_record)
    }

    fn validate_fresh_owner_role(
        &self,
        role_instance: &RoleInstanceV1,
        at_unix_seconds: u64,
    ) -> Result<(), DesktopError> {
        role_instance.validate_shape().map_err(|error| {
            DesktopError::Integrity(format!("owner Role Instance is invalid: {error}"))
        })?;
        match role_instance.current_status {
            RoleInstanceStatusV1::Active => {}
            RoleInstanceStatusV1::Suspended => {
                return Err(DesktopError::AccessDenied(
                    "suspended Role blocks fresh Case execution".to_owned(),
                ));
            }
            RoleInstanceStatusV1::Provisioned => {
                return Err(DesktopError::AccessDenied(
                    "inactive Role cannot execute a Case".to_owned(),
                ));
            }
            RoleInstanceStatusV1::Revoked | RoleInstanceStatusV1::Expired => {
                return Err(DesktopError::AccessDenied(
                    "revoked or expired Role requires Case escalation".to_owned(),
                ));
            }
        }
        let ownership = &self.contract.ownership_binding;
        if at_unix_seconds == 0
            || at_unix_seconds >= role_instance.expires_at_unix_seconds
            || at_unix_seconds >= ownership.expires_at_unix_seconds
        {
            return Err(DesktopError::AccessDenied(
                "owner Role or Case ownership binding is expired".to_owned(),
            ));
        }
        if role_instance.role_instance_id != ownership.role_instance_id
            || role_instance.role_contract_id != ownership.role_contract_id
            || role_instance.role_version != ownership.role_version
            || role_instance.contract_sha256 != ownership.role_contract_sha256
            || role_instance.delegation_sha256 != ownership.delegation_sha256
            || role_instance.organization_id != ownership.organization_id
            || role_instance.ledger_chain_head != self.role_ledger_chain_head
        {
            return Err(DesktopError::Integrity(
                "fresh Role Instance differs from Case ownership or Role ledger".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_mutable(&self) -> Result<(), DesktopError> {
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "Case coordinator is poisoned after a durable write failure".to_owned(),
            ));
        }
        if self.terminal {
            return Err(DesktopError::Replay(
                "terminal Case cannot be mutated".to_owned(),
            ));
        }
        Ok(())
    }

    fn persist_state(
        &mut self,
        event: CaseLedgerEventKindV1,
        next: CaseInstanceV1,
        at_unix_seconds: u64,
        task_request: Option<String>,
        task_attempt: Option<String>,
        kernel_run: Option<String>,
    ) -> Result<(), DesktopError> {
        let next = next
            .bind_ledger_head(self.ledger.verification().terminal_record_hash.clone())
            .map_err(work_case_error)?;
        let record = self.record(
            event,
            at_unix_seconds,
            Some(next.clone()),
            task_request,
            task_attempt,
            kernel_run,
        );
        self.append_record(record)?;
        self.instance = next;
        Ok(())
    }

    fn append_record(&mut self, record: CaseLedgerRecordV1) -> Result<(), DesktopError> {
        match self.ledger.append(record) {
            Ok(_) => Ok(()),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }

    fn record(
        &self,
        event_kind: CaseLedgerEventKindV1,
        at_unix_seconds: u64,
        instance_after: Option<CaseInstanceV1>,
        task_request_sha256: Option<String>,
        task_attempt_sha256: Option<String>,
        kernel_task_run_record_sha256: Option<String>,
    ) -> CaseLedgerRecordV1 {
        CaseLedgerRecordV1 {
            schema_version: 1,
            sequence: 1,
            ledger_id: self.ledger.verification().ledger_id.clone(),
            organization_id: self.contract.organization_id.clone(),
            event_kind,
            work_item_id: self.contract.source_work_item_id.clone(),
            work_item_sha256: self.contract.source_work_item_sha256.clone(),
            deduplication_key: None,
            case_id: Some(self.contract.case_id.clone()),
            case_contract_sha256: Some(self.contract.contract_sha256.clone()),
            case_instance_after: instance_after,
            admission_sha256: Some(self.contract.work_item_admission_sha256.clone()),
            task_request_sha256,
            task_attempt_sha256,
            kernel_task_run_record_sha256,
            evidence_index_sha256: Some(self.evidence_index.index_sha256.clone()),
            terminal_record_sha256: None,
            role_ledger_chain_head: self.role_ledger_chain_head.clone(),
            kernel_audit_chain_head: self.kernel_audit_chain_head.clone(),
            artifact_hashes: BTreeMap::new(),
            recorded_at_unix_ms: at_unix_seconds.saturating_mul(1_000),
            previous_record_hash: ZERO_HASH.to_owned(),
            record_hash: ZERO_HASH.to_owned(),
        }
    }
}

fn validate_attempt_outcome(artifacts: &CaseKernelArtifactsV1) -> Result<(), DesktopError> {
    let expected = match artifacts.run_record.final_outcome {
        KernelFinalOutcomeV1::Completed => CaseTaskAttemptOutcomeV1::VerifiedGoalComplete,
        KernelFinalOutcomeV1::ClarificationRequired => {
            CaseTaskAttemptOutcomeV1::ClarificationRequired
        }
        KernelFinalOutcomeV1::Escalated => CaseTaskAttemptOutcomeV1::Escalated,
        KernelFinalOutcomeV1::Stopped | KernelFinalOutcomeV1::Failed => {
            CaseTaskAttemptOutcomeV1::Failed
        }
        KernelFinalOutcomeV1::InfrastructureError => CaseTaskAttemptOutcomeV1::InfrastructureError,
    };
    if artifacts.outcome != expected {
        return Err(DesktopError::Integrity(
            "Case attempt outcome lowers or elevates Kernel terminal semantics".to_owned(),
        ));
    }
    Ok(())
}

/// Builds the initial durable ledger records for one admitted Work Item and open Case.
#[allow(clippy::too_many_arguments)]
pub fn persist_new_case(
    ledger: &mut CaseLedgerV1,
    work_item: &WorkItemV1,
    dedup_key: &WorkItemDeduplicationKeyV1,
    admission: &WorkItemAdmissionDecisionV1,
    contract: &CaseContractV1,
    instance: &CaseInstanceV1,
    role_ledger_chain_head: &str,
    audit_chain_head: &str,
    recorded_at_unix_ms: u64,
) -> Result<(), DesktopError> {
    work_item.validate().map_err(work_case_error)?;
    dedup_key.validate().map_err(work_case_error)?;
    admission.validate().map_err(work_case_error)?;
    contract.validate().map_err(work_case_error)?;
    instance
        .validate_against(contract)
        .map_err(work_case_error)?;
    if admission.outcome != WorkItemAdmissionOutcomeV1::Admitted
        || ledger.verification().organization_id != work_item.organization_id
    {
        return Err(DesktopError::AccessDenied(
            "only an admitted organization-matched Work Item may persist a Case".to_owned(),
        ));
    }
    let ledger_id = ledger.verification().ledger_id.clone();
    let base = |event_kind, instance_after, key| CaseLedgerRecordV1 {
        schema_version: 1,
        sequence: 1,
        ledger_id: ledger_id.clone(),
        organization_id: work_item.organization_id.clone(),
        event_kind,
        work_item_id: work_item.work_item_id.clone(),
        work_item_sha256: work_item.work_item_sha256.clone(),
        deduplication_key: key,
        case_id: Some(contract.case_id.clone()),
        case_contract_sha256: Some(contract.contract_sha256.clone()),
        case_instance_after: instance_after,
        admission_sha256: Some(admission.decision_sha256.clone()),
        task_request_sha256: None,
        task_attempt_sha256: None,
        kernel_task_run_record_sha256: None,
        evidence_index_sha256: Some(instance.evidence_index_sha256.clone()),
        terminal_record_sha256: None,
        role_ledger_chain_head: role_ledger_chain_head.to_owned(),
        kernel_audit_chain_head: audit_chain_head.to_owned(),
        artifact_hashes: BTreeMap::new(),
        recorded_at_unix_ms,
        previous_record_hash: ZERO_HASH.to_owned(),
        record_hash: ZERO_HASH.to_owned(),
    };
    ledger.append(base(
        CaseLedgerEventKindV1::WorkItemAdmitted,
        None,
        Some(dedup_key.clone()),
    ))?;
    ledger.append(base(CaseLedgerEventKindV1::CaseContractCreated, None, None))?;
    ledger.append(base(
        CaseLedgerEventKindV1::CaseOpened,
        Some(instance.clone()),
        None,
    ))?;
    Ok(())
}
