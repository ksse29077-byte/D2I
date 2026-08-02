use crate::{
    pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_token, write_new,
    DesktopError,
};
use d2i_role_contract::{
    canonical_sha256, parse_json_strict, RoleInstanceStatusV1, RoleInstanceV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const ROLE_LEDGER_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "role-instance-ledger-manifest.json";
const STATE_FILE: &str = "role-instance-ledger-state.json";
const LOCK_FILE: &str = ".role-instance-ledger.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LEDGER_RECORDS: u64 = 16_384;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Closed event set for persistent Role governance and one-time task admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleInstanceLedgerEventKindV1 {
    RoleContractRegistered,
    RoleContractApproved,
    RoleInstanceProvisioned,
    RoleInstanceActivated,
    RoleInstanceSuspended,
    RoleInstanceResumed,
    RoleInstanceRevoked,
    RoleInstanceExpired,
    RoleInstanceUpgraded,
    RoleTaskAdmitted,
    RoleTaskDenied,
    RoleTaskEscalationRequired,
    RoleBoundTaskStarted,
    RoleBoundTaskTerminal,
}

/// One immutable, audit-cross-referenced Role ledger record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleInstanceLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub role_instance_id: String,
    pub event_kind: RoleInstanceLedgerEventKindV1,
    pub role_contract_id: String,
    pub role_version: String,
    pub contract_sha256: String,
    pub instance_after: Option<RoleInstanceV1>,
    pub task_request_sha256: Option<String>,
    pub task_admission_sha256: Option<String>,
    pub role_context_sha256: Option<String>,
    pub artifact_hashes: BTreeMap<String, String>,
    pub audit_record_hash: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_hash: String,
    pub record_hash: String,
}

#[derive(Serialize)]
struct RoleInstanceLedgerRecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    role_instance_id: &'a str,
    event_kind: RoleInstanceLedgerEventKindV1,
    role_contract_id: &'a str,
    role_version: &'a str,
    contract_sha256: &'a str,
    instance_after: &'a Option<RoleInstanceV1>,
    task_request_sha256: &'a Option<String>,
    task_admission_sha256: &'a Option<String>,
    role_context_sha256: &'a Option<String>,
    artifact_hashes: &'a BTreeMap<String, String>,
    audit_record_hash: &'a str,
    recorded_at_unix_ms: u64,
    previous_record_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInstanceLedgerManifestV1 {
    schema_version: u32,
    ledger_id: String,
    role_instance_id: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    state_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleInstanceLedgerSnapshotV1 {
    schema_version: u32,
    ledger_id: String,
    role_instance_id: String,
    records: Vec<RoleInstanceLedgerRecordV1>,
}

/// Reconstructed Role identity, version registry, and one-time consumption sets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleInstanceLedgerVerificationV1 {
    pub ledger_id: String,
    pub role_instance_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub current_instance: Option<RoleInstanceV1>,
    pub registered_contract_versions: BTreeMap<String, String>,
    pub approved_contract_versions: Vec<String>,
    pub consumed_task_request_hashes: Vec<String>,
    pub consumed_task_admission_hashes: Vec<String>,
    pub started_role_context_hashes: Vec<String>,
    pub terminal_role_context_hashes: Vec<String>,
    pub latest_recorded_at_unix_ms: u64,
}

/// Protected append handle for one persistent Role Instance identity.
#[derive(Debug)]
pub struct RoleInstanceLedgerV1 {
    root: PathBuf,
    manifest: RoleInstanceLedgerManifestV1,
    verification: RoleInstanceLedgerVerificationV1,
}

impl RoleInstanceLedgerV1 {
    /// Opens and fully verifies ACLs, all records, lifecycle, and replay sets.
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_role_instance_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    /// Returns the current verified state restored from disk.
    #[must_use]
    pub const fn verification(&self) -> &RoleInstanceLedgerVerificationV1 {
        &self.verification
    }

    /// Appends one bounded record through a crash-safe atomic snapshot replace.
    pub fn append(
        &mut self,
        mut record: RoleInstanceLedgerRecordV1,
    ) -> Result<String, DesktopError> {
        let lock = RoleLedgerLock::acquire(&self.root)?;
        let latest = verify_role_instance_ledger(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "Role ledger changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "Role ledger record limit is exhausted".to_owned(),
            ));
        }
        record.schema_version = ROLE_LEDGER_SCHEMA_VERSION;
        record.sequence = latest.record_count.saturating_add(1);
        record.ledger_id = self.manifest.ledger_id.clone();
        record.role_instance_id = self.manifest.role_instance_id.clone();
        record.previous_record_hash = latest.terminal_record_hash.clone();
        record.record_hash = ZERO_HASH.to_owned();
        validate_record_transition(&record, &latest)?;
        record.record_hash = record_hash(&record)?;
        validate_record(&record)?;

        let mut snapshot = load_snapshot(&self.root)?;
        snapshot.records.push(record);
        atomic_replace_state(&self.root, &snapshot)?;
        let verified = verify_role_instance_ledger(&self.root)?;
        if verified.record_count != latest.record_count.saturating_add(1) {
            return Err(DesktopError::Integrity(
                "Role ledger atomic append did not advance exactly once".to_owned(),
            ));
        }
        self.verification = verified;
        drop(lock);
        Ok(self.verification.terminal_record_hash.clone())
    }
}

/// Initializes one ACL-protected persistent Role ledger.
pub fn initialize_role_instance_ledger(
    root: &Path,
    ledger_id: &str,
    role_instance_id: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<RoleInstanceLedgerV1, DesktopError> {
    validate_token(ledger_id, "Role ledger_id")?;
    validate_token(role_instance_id, "Role role_instance_id")?;
    if maximum_records == 0 || maximum_records > MAX_LEDGER_RECORDS || created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "Role ledger initialization bounds are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let initialized = (|| {
        let root_security_descriptor_hash = harden_and_hash(root, "Role ledger root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let state_path = root.join(STATE_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&state_path, b"")?;
        let manifest_security_descriptor_hash =
            harden_and_hash(&manifest_path, "Role ledger manifest")?;
        let state_security_descriptor_hash = harden_and_hash(&state_path, "Role ledger state")?;
        let snapshot = RoleInstanceLedgerSnapshotV1 {
            schema_version: ROLE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            role_instance_id: role_instance_id.to_owned(),
            records: Vec::new(),
        };
        overwrite_existing(&state_path, &pretty_json_bytes(&snapshot)?)?;
        let manifest = RoleInstanceLedgerManifestV1 {
            schema_version: ROLE_LEDGER_SCHEMA_VERSION,
            ledger_id: ledger_id.to_owned(),
            role_instance_id: role_instance_id.to_owned(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash,
            manifest_security_descriptor_hash,
            state_security_descriptor_hash,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        RoleInstanceLedgerV1::open(root)
    })();
    if initialized.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    initialized
}

/// Verifies protected storage and reconstructs the latest Role state.
pub fn verify_role_instance_ledger(
    root: &Path,
) -> Result<RoleInstanceLedgerVerificationV1, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let snapshot = load_snapshot(root)?;
    if snapshot.schema_version != ROLE_LEDGER_SCHEMA_VERSION
        || snapshot.ledger_id != manifest.ledger_id
        || snapshot.role_instance_id != manifest.role_instance_id
        || snapshot.records.len() as u64 > manifest.maximum_records
    {
        return Err(DesktopError::Integrity(
            "Role ledger snapshot identity or bounds differ".to_owned(),
        ));
    }
    let mut verification = RoleInstanceLedgerVerificationV1 {
        ledger_id: manifest.ledger_id,
        role_instance_id: manifest.role_instance_id,
        record_count: 0,
        terminal_record_hash: ZERO_HASH.to_owned(),
        current_instance: None,
        registered_contract_versions: BTreeMap::new(),
        approved_contract_versions: Vec::new(),
        consumed_task_request_hashes: Vec::new(),
        consumed_task_admission_hashes: Vec::new(),
        started_role_context_hashes: Vec::new(),
        terminal_role_context_hashes: Vec::new(),
        latest_recorded_at_unix_ms: manifest.created_at_unix_ms,
    };
    for record in &snapshot.records {
        validate_record_transition(record, &verification)?;
        if record.sequence != verification.record_count.saturating_add(1)
            || record.previous_record_hash != verification.terminal_record_hash
            || record.record_hash != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "Role ledger sequence or hash chain differs".to_owned(),
            ));
        }
        apply_record(record, &mut verification)?;
    }
    Ok(verification)
}

fn validate_record_transition(
    record: &RoleInstanceLedgerRecordV1,
    latest: &RoleInstanceLedgerVerificationV1,
) -> Result<(), DesktopError> {
    validate_record(record)?;
    if record.ledger_id != latest.ledger_id
        || record.role_instance_id != latest.role_instance_id
        || record.recorded_at_unix_ms < latest.latest_recorded_at_unix_ms
    {
        return Err(DesktopError::Integrity(
            "Role record differs from durable identity or monotonic time".to_owned(),
        ));
    }
    let contract_key = format!("{}@{}", record.role_contract_id, record.role_version);
    if latest
        .registered_contract_versions
        .get(&contract_key)
        .is_some_and(|hash| hash != &record.contract_sha256)
    {
        return Err(DesktopError::Integrity(
            "Role contract version collision or in-place mutation detected".to_owned(),
        ));
    }
    validate_event_shape(record, latest)?;
    if matches!(
        record.event_kind,
        RoleInstanceLedgerEventKindV1::RoleTaskAdmitted
            | RoleInstanceLedgerEventKindV1::RoleTaskDenied
            | RoleInstanceLedgerEventKindV1::RoleTaskEscalationRequired
    ) {
        for (values, candidate, label) in [
            (
                &latest.consumed_task_request_hashes,
                &record.task_request_sha256,
                "task request",
            ),
            (
                &latest.consumed_task_admission_hashes,
                &record.task_admission_sha256,
                "task admission",
            ),
        ] {
            if candidate
                .as_ref()
                .is_some_and(|value| values.binary_search(value).is_ok())
            {
                return Err(DesktopError::Replay(format!("Role ledger reused {label}")));
            }
        }
    }
    Ok(())
}

fn validate_event_shape(
    record: &RoleInstanceLedgerRecordV1,
    latest: &RoleInstanceLedgerVerificationV1,
) -> Result<(), DesktopError> {
    use RoleInstanceLedgerEventKindV1 as Event;
    let no_task = record.task_request_sha256.is_none()
        && record.task_admission_sha256.is_none()
        && record.role_context_sha256.is_none();
    match record.event_kind {
        Event::RoleContractRegistered => {
            if record.instance_after.is_some() || !no_task {
                return invalid_event("contract governance event contains instance or task state");
            }
            let key = format!("{}@{}", record.role_contract_id, record.role_version);
            if latest.registered_contract_versions.contains_key(&key) {
                return Err(DesktopError::Replay(
                    "Role contract version was already registered".to_owned(),
                ));
            }
        }
        Event::RoleContractApproved => {
            if record.instance_after.is_some() || !no_task {
                return invalid_event("contract approval event contains instance or task state");
            }
            let key = format!("{}@{}", record.role_contract_id, record.role_version);
            if latest.registered_contract_versions.get(&key) != Some(&record.contract_sha256)
                || latest
                    .approved_contract_versions
                    .binary_search(&key)
                    .is_ok()
            {
                return invalid_event("Role contract approval is unregistered or duplicated");
            }
        }
        Event::RoleInstanceProvisioned => {
            let instance = require_instance(record)?;
            let key = format!("{}@{}", record.role_contract_id, record.role_version);
            if latest.current_instance.is_some()
                || latest
                    .approved_contract_versions
                    .binary_search(&key)
                    .is_err()
                || instance.current_status != RoleInstanceStatusV1::Provisioned
                || instance.ledger_chain_head != record.previous_record_hash
                || !no_task
            {
                return invalid_event("Role provision event is not an initial provisioned state");
            }
        }
        Event::RoleInstanceActivated
        | Event::RoleInstanceSuspended
        | Event::RoleInstanceResumed
        | Event::RoleInstanceRevoked
        | Event::RoleInstanceExpired => {
            let before = require_current(latest)?;
            let after = require_instance(record)?;
            let expected_status = match record.event_kind {
                Event::RoleInstanceActivated | Event::RoleInstanceResumed => {
                    RoleInstanceStatusV1::Active
                }
                Event::RoleInstanceSuspended => RoleInstanceStatusV1::Suspended,
                Event::RoleInstanceRevoked => RoleInstanceStatusV1::Revoked,
                Event::RoleInstanceExpired => RoleInstanceStatusV1::Expired,
                _ => unreachable!(),
            };
            let expected = before
                .transition(expected_status, record.recorded_at_unix_ms / 1_000)
                .map_err(role_error)?;
            if after != &expected || !no_task {
                return invalid_event("Role lifecycle event is not the exact legal transition");
            }
        }
        Event::RoleInstanceUpgraded => {
            let before = require_current(latest)?;
            let after = require_instance(record)?;
            let key = format!("{}@{}", record.role_contract_id, record.role_version);
            if matches!(
                before.current_status,
                RoleInstanceStatusV1::Revoked | RoleInstanceStatusV1::Expired
            ) || latest
                .approved_contract_versions
                .binary_search(&key)
                .is_err()
                || after.role_instance_id != before.role_instance_id
                || after.ledger_id != before.ledger_id
                || after.instance_generation != before.instance_generation.saturating_add(1)
                || after.current_status != RoleInstanceStatusV1::Provisioned
                || after.contract_sha256 == before.contract_sha256
                || after.ledger_chain_head != record.previous_record_hash
                || !no_task
            {
                return invalid_event("Role upgrade is not a bounded new generation");
            }
        }
        Event::RoleTaskAdmitted => {
            require_unchanged_instance(record, latest)?;
            if record.task_request_sha256.is_none()
                || record.task_admission_sha256.is_none()
                || record.role_context_sha256.is_none()
            {
                return invalid_event("Role task decision event has invalid one-time bindings");
            }
        }
        Event::RoleTaskDenied | Event::RoleTaskEscalationRequired => {
            require_preserved_instance(record, latest)?;
            if record.task_request_sha256.is_none()
                || record.task_admission_sha256.is_none()
                || record.role_context_sha256.is_some()
            {
                return invalid_event("Role task rejection contains invalid one-time bindings");
            }
        }
        Event::RoleBoundTaskStarted => {
            require_unchanged_instance(record, latest)?;
            let context = record
                .role_context_sha256
                .as_ref()
                .ok_or_else(|| DesktopError::Invalid("Role task start lacks context".to_owned()))?;
            let admission = record.task_admission_sha256.as_deref().ok_or_else(|| {
                DesktopError::Invalid("Role task start lacks admission".to_owned())
            })?;
            if record.task_request_sha256.is_some()
                || latest
                    .started_role_context_hashes
                    .binary_search(context)
                    .is_ok()
                || latest
                    .consumed_task_admission_hashes
                    .binary_search(&admission.to_owned())
                    .is_err()
            {
                return invalid_event("Role task start is unadmitted or replayed");
            }
        }
        Event::RoleBoundTaskTerminal => {
            require_unchanged_instance(record, latest)?;
            let context = record.role_context_sha256.as_ref().ok_or_else(|| {
                DesktopError::Invalid("Role task terminal lacks context".to_owned())
            })?;
            if record.task_request_sha256.is_some()
                || record.task_admission_sha256.is_some()
                || latest
                    .started_role_context_hashes
                    .binary_search(context)
                    .is_err()
                || latest
                    .terminal_role_context_hashes
                    .binary_search(context)
                    .is_ok()
            {
                return invalid_event("Role task terminal is missing a unique started context");
            }
        }
    }
    Ok(())
}

fn require_instance(record: &RoleInstanceLedgerRecordV1) -> Result<&RoleInstanceV1, DesktopError> {
    let instance = record
        .instance_after
        .as_ref()
        .ok_or_else(|| DesktopError::Invalid("Role event lacks instance state".to_owned()))?;
    instance.validate_shape().map_err(role_error)?;
    if instance.role_instance_id != record.role_instance_id
        || instance.role_contract_id != record.role_contract_id
        || instance.role_version != record.role_version
        || instance.contract_sha256 != record.contract_sha256
        || instance.ledger_id != record.ledger_id
    {
        return Err(DesktopError::Integrity(
            "Role event instance binding differs".to_owned(),
        ));
    }
    Ok(instance)
}

fn require_current(
    latest: &RoleInstanceLedgerVerificationV1,
) -> Result<&RoleInstanceV1, DesktopError> {
    latest
        .current_instance
        .as_ref()
        .ok_or_else(|| DesktopError::Invalid("Role lifecycle event precedes provision".to_owned()))
}

fn require_unchanged_instance(
    record: &RoleInstanceLedgerRecordV1,
    latest: &RoleInstanceLedgerVerificationV1,
) -> Result<(), DesktopError> {
    let current = require_current(latest)?;
    let after = require_instance(record)?;
    if after != current || current.current_status != RoleInstanceStatusV1::Active {
        return invalid_event("Role task event does not preserve one active Role Instance");
    }
    Ok(())
}

fn require_preserved_instance(
    record: &RoleInstanceLedgerRecordV1,
    latest: &RoleInstanceLedgerVerificationV1,
) -> Result<(), DesktopError> {
    let current = require_current(latest)?;
    if require_instance(record)? != current {
        return invalid_event("Role task event changed the Role Instance");
    }
    Ok(())
}

fn apply_record(
    record: &RoleInstanceLedgerRecordV1,
    verification: &mut RoleInstanceLedgerVerificationV1,
) -> Result<(), DesktopError> {
    use RoleInstanceLedgerEventKindV1 as Event;
    if record.event_kind == Event::RoleContractRegistered {
        let key = format!("{}@{}", record.role_contract_id, record.role_version);
        verification
            .registered_contract_versions
            .insert(key, record.contract_sha256.clone());
    }
    if record.event_kind == Event::RoleContractApproved {
        let key = format!("{}@{}", record.role_contract_id, record.role_version);
        verification.approved_contract_versions.push(key);
        verification.approved_contract_versions.sort();
    }
    if matches!(
        record.event_kind,
        Event::RoleTaskAdmitted | Event::RoleTaskDenied | Event::RoleTaskEscalationRequired
    ) {
        consume_once(
            &mut verification.consumed_task_request_hashes,
            &record.task_request_sha256,
            "task request",
        )?;
        consume_once(
            &mut verification.consumed_task_admission_hashes,
            &record.task_admission_sha256,
            "task admission",
        )?;
    }
    if record.event_kind == Event::RoleBoundTaskStarted {
        consume_once(
            &mut verification.started_role_context_hashes,
            &record.role_context_sha256,
            "started Role context",
        )?;
    } else if record.event_kind == Event::RoleBoundTaskTerminal {
        consume_once(
            &mut verification.terminal_role_context_hashes,
            &record.role_context_sha256,
            "terminal Role context",
        )?;
    }
    if let Some(instance) = &record.instance_after {
        verification.current_instance = Some(
            instance
                .bind_ledger_head(record.record_hash.clone())
                .map_err(role_error)?,
        );
    }
    verification.record_count = record.sequence;
    verification.terminal_record_hash = record.record_hash.clone();
    verification.latest_recorded_at_unix_ms = record.recorded_at_unix_ms;
    Ok(())
}

fn validate_record(record: &RoleInstanceLedgerRecordV1) -> Result<(), DesktopError> {
    if record.schema_version != ROLE_LEDGER_SCHEMA_VERSION
        || record.sequence == 0
        || record.recorded_at_unix_ms == 0
        || record.artifact_hashes.len() > 32
    {
        return Err(DesktopError::Invalid(
            "Role ledger record bounds are invalid".to_owned(),
        ));
    }
    for (value, label) in [
        (&record.ledger_id, "Role record ledger_id"),
        (&record.role_instance_id, "Role record role_instance_id"),
        (&record.role_contract_id, "Role record role_contract_id"),
        (&record.role_version, "Role record role_version"),
    ] {
        validate_token(value, label)?;
    }
    for (value, label) in [
        (Some(&record.contract_sha256), "Role contract hash"),
        (
            record.task_request_sha256.as_ref(),
            "Role task request hash",
        ),
        (
            record.task_admission_sha256.as_ref(),
            "Role task admission hash",
        ),
        (record.role_context_sha256.as_ref(), "Role context hash"),
        (
            Some(&record.audit_record_hash),
            "Role audit cross-reference",
        ),
        (
            Some(&record.previous_record_hash),
            "previous Role record hash",
        ),
        (Some(&record.record_hash), "Role record hash"),
    ] {
        if let Some(value) = value {
            validate_hash(value, label)?;
        }
    }
    for (name, hash) in &record.artifact_hashes {
        validate_token(name, "Role artifact name")?;
        validate_hash(hash, "Role artifact hash")?;
    }
    reject_forbidden_record_content(record)
}

fn record_hash(record: &RoleInstanceLedgerRecordV1) -> Result<String, DesktopError> {
    canonical_sha256(&RoleInstanceLedgerRecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        role_instance_id: &record.role_instance_id,
        event_kind: record.event_kind,
        role_contract_id: &record.role_contract_id,
        role_version: &record.role_version,
        contract_sha256: &record.contract_sha256,
        instance_after: &record.instance_after,
        task_request_sha256: &record.task_request_sha256,
        task_admission_sha256: &record.task_admission_sha256,
        role_context_sha256: &record.role_context_sha256,
        artifact_hashes: &record.artifact_hashes,
        audit_record_hash: &record.audit_record_hash,
        recorded_at_unix_ms: record.recorded_at_unix_ms,
        previous_record_hash: &record.previous_record_hash,
    })
    .map_err(role_error)
}

fn reject_forbidden_record_content(
    record: &RoleInstanceLedgerRecordV1,
) -> Result<(), DesktopError> {
    fn forbidden(value: &Value) -> bool {
        match value {
            Value::String(value) => {
                let lower = value.to_ascii_lowercase();
                value.contains(":\\")
                    || value.starts_with('/')
                    || [
                        "password",
                        "credential",
                        "bearer ",
                        "api_key",
                        "access_token",
                        "raw_locator",
                        "raw_payload",
                        "private_key",
                    ]
                    .iter()
                    .any(|marker| lower.contains(marker))
            }
            Value::Array(values) => values.iter().any(forbidden),
            Value::Object(values) => values.iter().any(|(key, value)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "raw_locator" | "raw_payload" | "credential" | "secret" | "token"
                ) || forbidden(value)
            }),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    let value =
        serde_json::to_value(record).map_err(|error| DesktopError::Json(error.to_string()))?;
    if forbidden(&value) {
        return Err(DesktopError::AccessDenied(
            "Role ledger record contains forbidden raw or secret material".to_owned(),
        ));
    }
    Ok(())
}

fn load_manifest(root: &Path) -> Result<RoleInstanceLedgerManifestV1, DesktopError> {
    validate_root(root)?;
    let bytes = read_bounded(&root.join(MANIFEST_FILE), 1024 * 1024)?;
    let manifest: RoleInstanceLedgerManifestV1 = parse_json_strict(&bytes).map_err(role_error)?;
    if manifest.schema_version != ROLE_LEDGER_SCHEMA_VERSION
        || manifest.maximum_records == 0
        || manifest.maximum_records > MAX_LEDGER_RECORDS
        || manifest.created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Role ledger manifest bounds are invalid".to_owned(),
        ));
    }
    validate_token(&manifest.ledger_id, "Role manifest ledger_id")?;
    validate_token(&manifest.role_instance_id, "Role manifest role_instance_id")?;
    for hash in [
        &manifest.root_security_descriptor_hash,
        &manifest.manifest_security_descriptor_hash,
        &manifest.state_security_descriptor_hash,
    ] {
        validate_hash(hash, "Role ledger security descriptor hash")?;
    }
    Ok(manifest)
}

fn load_snapshot(root: &Path) -> Result<RoleInstanceLedgerSnapshotV1, DesktopError> {
    parse_json_strict(&read_bounded(&root.join(STATE_FILE), MAX_LEDGER_BYTES)?).map_err(role_error)
}

fn validate_root(root: &Path) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "Role ledger root must be a regular directory".to_owned(),
        ));
    }
    for path in [root.join(MANIFEST_FILE), root.join(STATE_FILE)] {
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DesktopError::Integrity(
                "Role ledger artifacts must be regular files".to_owned(),
            ));
        }
    }
    Ok(())
}

fn verify_storage_security(
    root: &Path,
    manifest: &RoleInstanceLedgerManifestV1,
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
            DesktopError::Integrity(format!("Role ledger {label} ACL read failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "Role ledger {label} ACL changed"
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
    snapshot: &RoleInstanceLedgerSnapshotV1,
) -> Result<(), DesktopError> {
    let temporary = root.join(format!(
        ".role-state-{}-{}.tmp",
        std::process::id(),
        snapshot.records.len()
    ));
    let result = (|| {
        write_new(&temporary, &pretty_json_bytes(snapshot)?)?;
        let _ = d2i_windows_host::harden_path_for_current_user(&temporary).map_err(|error| {
            DesktopError::Integrity(format!("temporary Role state ACL failed: {error}"))
        })?;
        d2i_windows_host::atomic_move(&temporary, &root.join(STATE_FILE), true).map_err(|error| {
            DesktopError::Io {
                path: root.join(STATE_FILE).display().to_string(),
                message: format!("atomic Role state replace failed: {error}"),
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
        if values.binary_search(value).is_ok() {
            return Err(DesktopError::Replay(format!(
                "Role ledger replayed {label}"
            )));
        }
        values.push(value.clone());
        values.sort();
    }
    Ok(())
}

fn invalid_event<T>(message: &str) -> Result<T, DesktopError> {
    Err(DesktopError::Invalid(message.to_owned()))
}

fn role_error(error: d2i_role_contract::RoleContractError) -> DesktopError {
    match error {
        d2i_role_contract::RoleContractError::Invalid(message) => DesktopError::Invalid(message),
        d2i_role_contract::RoleContractError::Integrity(message) => {
            DesktopError::Integrity(message)
        }
        d2i_role_contract::RoleContractError::NotAdmissible(message) => {
            DesktopError::AccessDenied(message)
        }
        d2i_role_contract::RoleContractError::Replay(message) => DesktopError::Replay(message),
        d2i_role_contract::RoleContractError::Json(message) => DesktopError::Json(message),
        d2i_role_contract::RoleContractError::Io(message) => DesktopError::Io {
            path: "role-contract".to_owned(),
            message,
        },
    }
}

struct RoleLedgerLock(PathBuf);

impl RoleLedgerLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("Role ledger lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "Role ledger lock ACL failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for RoleLedgerLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
