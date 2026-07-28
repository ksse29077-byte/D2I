use crate::{
    hash_value, pretty_json_bytes, read_bounded, validate_hash, validate_token, write_new,
    DesktopError,
};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "audit-manifest.json";
const RECORDS_FILE: &str = "audit-records.jsonl";
const MAX_AUDIT_LINE_BYTES: usize = 64 * 1024;
const MAX_AUDIT_MANIFEST_BYTES: u64 = 64 * 1024;

/// Lifecycle event persisted by the desktop executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    Denied,
    Cancelled,
    Prepared,
    Succeeded,
    Failed,
}

/// Payload-free event submitted to the append-only ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub kind: AuditEventKind,
    pub action_id: String,
    pub action_sequence: u64,
    pub action_hash: String,
    pub policy_decision_hash: String,
    pub adapter_descriptor_hash: String,
    pub preparation_hash: Option<String>,
    pub permit_hash: Option<String>,
    pub approval_id: Option<String>,
    pub output_hash: Option<String>,
    pub message_hash: String,
    pub recorded_at_unix_ms: u64,
}

impl AuditEvent {
    /// Validates event hashes and required lifecycle fields.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.action_id, "audit action_id")?;
        if self.action_sequence == 0 {
            return Err(DesktopError::Invalid(
                "audit action_sequence must be nonzero".to_owned(),
            ));
        }
        validate_hash(&self.action_hash, "audit action_hash")?;
        validate_hash(&self.policy_decision_hash, "audit policy_decision_hash")?;
        validate_hash(
            &self.adapter_descriptor_hash,
            "audit adapter_descriptor_hash",
        )?;
        validate_hash(&self.message_hash, "audit message_hash")?;
        for (value, field) in [
            (&self.preparation_hash, "audit preparation_hash"),
            (&self.permit_hash, "audit permit_hash"),
            (&self.output_hash, "audit output_hash"),
        ] {
            if let Some(hash) = value {
                validate_hash(hash, field)?;
            }
        }
        if let Some(approval_id) = &self.approval_id {
            validate_token(approval_id, "audit approval_id")?;
        }
        match self.kind {
            AuditEventKind::Prepared => {
                if self.preparation_hash.is_none() || self.permit_hash.is_none() {
                    return Err(DesktopError::Invalid(
                        "prepared audit event requires preparation and permit hashes".to_owned(),
                    ));
                }
            }
            AuditEventKind::Succeeded => {
                if self.preparation_hash.is_none()
                    || self.permit_hash.is_none()
                    || self.output_hash.is_none()
                {
                    return Err(DesktopError::Invalid(
                        "successful audit event is missing execution hashes".to_owned(),
                    ));
                }
            }
            AuditEventKind::Denied | AuditEventKind::Cancelled | AuditEventKind::Failed => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditManifest {
    schema_version: u32,
    session_id: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    storage_security: Option<AuditStorageSecurity>,
    manifest_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditStorageSecurity {
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    records_security_descriptor_hash: String,
}

#[derive(Serialize)]
struct ManifestDigest<'a> {
    schema_version: u32,
    session_id: &'a str,
    maximum_records: u64,
    created_at_unix_ms: u64,
    storage_security: &'a Option<AuditStorageSecurity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditRecord {
    schema_version: u32,
    sequence: u64,
    session_id: String,
    event: AuditEvent,
    previous_record_hash: String,
    record_hash: String,
}

#[derive(Serialize)]
struct RecordDigest<'a> {
    schema_version: u32,
    sequence: u64,
    session_id: &'a str,
    event: &'a AuditEvent,
    previous_record_hash: &'a str,
}

/// Verification summary for a durable desktop audit ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditVerification {
    pub session_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub pending_prepared_actions: Vec<String>,
}

/// Expected immutable identity for an offline audit replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReplayExpectation {
    pub session_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
    pub require_no_pending_actions: bool,
}

/// Deterministic comparison of a verified audit ledger with an expected run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReplayReport {
    pub matched: bool,
    pub actual: AuditVerification,
    pub reasons: Vec<String>,
}

/// Open append handle. Each record is synced before control returns.
#[derive(Debug)]
pub struct AuditLedger {
    root: PathBuf,
    manifest: AuditManifest,
    record_count: u64,
    terminal_record_hash: String,
}

impl AuditLedger {
    /// Opens an existing verified ledger for append.
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_audit_ledger(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            record_count: verification.record_count,
            terminal_record_hash: verification.terminal_record_hash,
        })
    }

    /// Returns the session identity pinned by the manifest.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.manifest.session_id
    }

    /// Returns the number of durably appended records.
    #[must_use]
    pub fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Appends and durably syncs one hash-chained event.
    pub fn append(&mut self, event: AuditEvent) -> Result<String, DesktopError> {
        event.validate()?;
        verify_storage_security(&self.root, &self.manifest.storage_security)?;
        if self.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "audit ledger record limit is exhausted".to_owned(),
            ));
        }
        let sequence = self.record_count + 1;
        let digest = RecordDigest {
            schema_version: 1,
            sequence,
            session_id: &self.manifest.session_id,
            event: &event,
            previous_record_hash: &self.terminal_record_hash,
        };
        let record_hash = hash_value(&digest)?;
        let record = AuditRecord {
            schema_version: 1,
            sequence,
            session_id: self.manifest.session_id.clone(),
            event,
            previous_record_hash: self.terminal_record_hash.clone(),
            record_hash: record_hash.clone(),
        };
        let mut line =
            serde_json::to_vec(&record).map_err(|error| DesktopError::Json(error.to_string()))?;
        if line.len() > MAX_AUDIT_LINE_BYTES {
            return Err(DesktopError::Invalid(
                "audit record exceeds line bound".to_owned(),
            ));
        }
        line.push(b'\n');
        let records_path = self.root.join(RECORDS_FILE);
        reject_symlink_regular_file(&records_path)?;
        let mut file = OpenOptions::new()
            .append(true)
            .open(&records_path)
            .map_err(|error| DesktopError::Io {
                path: records_path.display().to_string(),
                message: error.to_string(),
            })?;
        file.write_all(&line)
            .and_then(|()| file.sync_all())
            .map_err(|error| DesktopError::Io {
                path: records_path.display().to_string(),
                message: error.to_string(),
            })?;
        self.record_count = sequence;
        self.terminal_record_hash = record_hash.clone();
        Ok(record_hash)
    }
}

/// Creates an empty ledger in a new directory.
pub fn initialize_audit_ledger(
    root: &Path,
    session_id: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<AuditLedger, DesktopError> {
    validate_token(session_id, "audit session_id")?;
    if maximum_records == 0 || maximum_records > 1_000_000 {
        return Err(DesktopError::Invalid(
            "maximum audit records is outside 1..=1000000".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        let root_security_descriptor_hash = initialize_root_storage_security(root)?;
        let manifest_path = root.join(MANIFEST_FILE);
        let records_path = root.join(RECORDS_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&records_path, b"")?;
        let storage_security = initialize_storage_security(root, root_security_descriptor_hash)?;
        let digest = ManifestDigest {
            schema_version: 1,
            session_id,
            maximum_records,
            created_at_unix_ms,
            storage_security: &storage_security,
        };
        let manifest_hash = hash_value(&digest)?;
        let manifest = AuditManifest {
            schema_version: 1,
            session_id: session_id.to_owned(),
            maximum_records,
            created_at_unix_ms,
            storage_security,
            manifest_hash,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        AuditLedger::open(root)
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    result
}

/// Verifies manifest identity, sequence, full hash chain, and lifecycle balance.
pub fn verify_audit_ledger(root: &Path) -> Result<AuditVerification, DesktopError> {
    let manifest = load_manifest(root)?;
    let records_path = root.join(RECORDS_FILE);
    reject_symlink_regular_file(&records_path)?;
    let file = std::fs::File::open(&records_path).map_err(|error| DesktopError::Io {
        path: records_path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut previous = sha256_empty();
    let mut count = 0_u64;
    let mut next_action_sequence = 1_u64;
    let mut pending = std::collections::BTreeSet::new();
    let mut approval_actions = std::collections::BTreeMap::new();
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|error| DesktopError::Io {
            path: records_path.display().to_string(),
            message: error.to_string(),
        })?;
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_AUDIT_LINE_BYTES {
            return Err(DesktopError::Integrity(
                "audit record exceeds line bound".to_owned(),
            ));
        }
        let record: AuditRecord =
            serde_json::from_slice(&line).map_err(|error| DesktopError::Json(error.to_string()))?;
        record.event.validate()?;
        count += 1;
        if count > manifest.maximum_records
            || record.schema_version != 1
            || record.sequence != count
            || record.session_id != manifest.session_id
            || record.previous_record_hash != previous
        {
            return Err(DesktopError::Integrity(
                "audit sequence, session, or previous hash mismatch".to_owned(),
            ));
        }
        let digest = RecordDigest {
            schema_version: record.schema_version,
            sequence: record.sequence,
            session_id: &record.session_id,
            event: &record.event,
            previous_record_hash: &record.previous_record_hash,
        };
        if hash_value(&digest)? != record.record_hash {
            return Err(DesktopError::Integrity(
                "audit record digest mismatch".to_owned(),
            ));
        }
        if record.event.action_sequence != next_action_sequence {
            return Err(DesktopError::Integrity(
                "audit action sequence is duplicated, skipped, or rolled back".to_owned(),
            ));
        }
        if let Some(approval_id) = &record.event.approval_id {
            match approval_actions.get(approval_id) {
                Some(action_hash) if action_hash != &record.event.action_hash => {
                    return Err(DesktopError::Integrity(
                        "approval_id is bound to multiple actions".to_owned(),
                    ));
                }
                Some(_) => {}
                None => {
                    approval_actions.insert(approval_id.clone(), record.event.action_hash.clone());
                }
            }
        }
        match record.event.kind {
            AuditEventKind::Prepared => {
                if !pending.insert(record.event.action_hash.clone()) {
                    return Err(DesktopError::Integrity(
                        "action has multiple pending prepared records".to_owned(),
                    ));
                }
            }
            AuditEventKind::Succeeded | AuditEventKind::Failed => {
                if !pending.remove(&record.event.action_hash) {
                    return Err(DesktopError::Integrity(
                        "terminal action record has no prepared predecessor".to_owned(),
                    ));
                }
                next_action_sequence = next_action_sequence.saturating_add(1);
            }
            AuditEventKind::Denied | AuditEventKind::Cancelled => {
                next_action_sequence = next_action_sequence.saturating_add(1);
            }
        }
        previous = record.record_hash;
    }
    Ok(AuditVerification {
        session_id: manifest.session_id,
        record_count: count,
        terminal_record_hash: previous,
        pending_prepared_actions: pending.into_iter().collect(),
    })
}

/// Replays ledger verification and compares timing-independent terminal identity.
pub fn replay_audit(
    root: &Path,
    expectation: &AuditReplayExpectation,
) -> Result<AuditReplayReport, DesktopError> {
    validate_token(&expectation.session_id, "replay session_id")?;
    validate_hash(
        &expectation.terminal_record_hash,
        "replay terminal_record_hash",
    )?;
    let actual = verify_audit_ledger(root)?;
    let mut reasons = Vec::new();
    if actual.session_id != expectation.session_id {
        reasons.push("session identity mismatch".to_owned());
    }
    if actual.record_count != expectation.record_count {
        reasons.push("record count mismatch".to_owned());
    }
    if actual.terminal_record_hash != expectation.terminal_record_hash {
        reasons.push("terminal record hash mismatch".to_owned());
    }
    if expectation.require_no_pending_actions && !actual.pending_prepared_actions.is_empty() {
        reasons.push("audit replay has pending prepared actions".to_owned());
    }
    Ok(AuditReplayReport {
        matched: reasons.is_empty(),
        actual,
        reasons,
    })
}

fn load_manifest(root: &Path) -> Result<AuditManifest, DesktopError> {
    let root_metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "audit root must be a non-symlink directory".to_owned(),
        ));
    }
    let manifest_path = root.join(MANIFEST_FILE);
    let bytes = read_bounded(&manifest_path, MAX_AUDIT_MANIFEST_BYTES)?;
    let manifest: AuditManifest =
        serde_json::from_slice(&bytes).map_err(|error| DesktopError::Json(error.to_string()))?;
    validate_token(&manifest.session_id, "audit manifest session_id")?;
    validate_hash(&manifest.manifest_hash, "audit manifest_hash")?;
    let digest = ManifestDigest {
        schema_version: manifest.schema_version,
        session_id: &manifest.session_id,
        maximum_records: manifest.maximum_records,
        created_at_unix_ms: manifest.created_at_unix_ms,
        storage_security: &manifest.storage_security,
    };
    if manifest.schema_version != 1
        || manifest.maximum_records == 0
        || manifest.maximum_records > 1_000_000
        || hash_value(&digest)? != manifest.manifest_hash
    {
        return Err(DesktopError::Integrity(
            "audit manifest is invalid or tampered".to_owned(),
        ));
    }
    verify_storage_security(root, &manifest.storage_security)?;
    Ok(manifest)
}

fn reject_symlink_regular_file(path: &Path) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DesktopError::Integrity(
            "audit records path must be a non-symlink regular file".to_owned(),
        ));
    }
    Ok(())
}

fn sha256_empty() -> String {
    crate::sha256_bytes(&[])
}

#[cfg(windows)]
fn initialize_root_storage_security(root: &Path) -> Result<Option<String>, DesktopError> {
    d2i_windows_host::harden_path_for_current_user(root)
        .map(|descriptor| Some(crate::sha256_bytes(&descriptor)))
        .map_err(|error| {
            DesktopError::Integrity(format!("audit root ACL hardening failed: {error}"))
        })
}

#[cfg(not(windows))]
fn initialize_root_storage_security(_root: &Path) -> Result<Option<String>, DesktopError> {
    Ok(None)
}

#[cfg(windows)]
fn initialize_storage_security(
    root: &Path,
    root_security_descriptor_hash: Option<String>,
) -> Result<Option<AuditStorageSecurity>, DesktopError> {
    let harden = |path: &Path, label: &str| {
        d2i_windows_host::harden_path_for_current_user(path)
            .map(|descriptor| crate::sha256_bytes(&descriptor))
            .map_err(|error| {
                DesktopError::Integrity(format!("audit {label} ACL hardening failed: {error}"))
            })
    };
    Ok(Some(AuditStorageSecurity {
        root_security_descriptor_hash: root_security_descriptor_hash.ok_or_else(|| {
            DesktopError::Integrity("audit root security descriptor hash is absent".to_owned())
        })?,
        manifest_security_descriptor_hash: harden(&root.join(MANIFEST_FILE), "manifest")?,
        records_security_descriptor_hash: harden(&root.join(RECORDS_FILE), "records")?,
    }))
}

#[cfg(not(windows))]
fn initialize_storage_security(
    _root: &Path,
    root_security_descriptor_hash: Option<String>,
) -> Result<Option<AuditStorageSecurity>, DesktopError> {
    if root_security_descriptor_hash.is_some() {
        return Err(DesktopError::Integrity(
            "non-Windows audit root has a Windows security descriptor".to_owned(),
        ));
    }
    Ok(None)
}

#[cfg(windows)]
fn verify_storage_security(
    root: &Path,
    expected: &Option<AuditStorageSecurity>,
) -> Result<(), DesktopError> {
    let expected = expected.as_ref().ok_or_else(|| {
        DesktopError::Integrity(
            "Windows audit manifest lacks protected storage identity".to_owned(),
        )
    })?;
    for (path, expected_hash, label) in [
        (
            root.to_path_buf(),
            &expected.root_security_descriptor_hash,
            "root",
        ),
        (
            root.join(MANIFEST_FILE),
            &expected.manifest_security_descriptor_hash,
            "manifest",
        ),
        (
            root.join(RECORDS_FILE),
            &expected.records_security_descriptor_hash,
            "records",
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("audit {label} security descriptor failed: {error}"))
        })?;
        if crate::sha256_bytes(&descriptor) != *expected_hash {
            return Err(DesktopError::Integrity(format!(
                "audit {label} security descriptor changed"
            )));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_storage_security(
    _root: &Path,
    expected: &Option<AuditStorageSecurity>,
) -> Result<(), DesktopError> {
    if expected.is_some() {
        return Err(DesktopError::Integrity(
            "non-Windows audit manifest contains Windows storage identity".to_owned(),
        ));
    }
    Ok(())
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    reject_symlink_regular_file(path)?;
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
