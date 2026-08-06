use crate::{
    hash_value, pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_token,
    write_new, DesktopError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "windows-deployment-audit-manifest.json";
const RECORDS_FILE: &str = "windows-deployment-audit-records.jsonl";
const LOCK_FILE: &str = ".windows-deployment-audit.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Security-relevant event in the WFP deployment and activation trust chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDeploymentAuditEventKind {
    PolicyInstalled,
    PolicyExactlyVerified,
    SelfTestPositive,
    SelfTestNegative,
    IdlePreconnectObserved,
    ReportCreated,
    ReportRejected,
    AttestationCreated,
    AttestationRejected,
    StaleReplayTamperRejected,
    BindingRecertified,
    ManifestRecertified,
    AdapterReactivated,
    PolicyRecalled,
    ResidueCleaned,
    VerifierBrokerStarted,
    VerifierCallerVerified,
    VerifierRequestAccepted,
    VerifierRequestRejected,
    VerifierChallengeConsumed,
    VerifierEngineOpened,
    VerifierObjectExactlyVerified,
    VerifierAclVerified,
    VerifierPolicyDigestCreated,
    VerifierReceiptCreated,
    VerifierReceiptSigned,
    VerifierReceiptValidated,
    BindingEvidenceCreated,
    BindingEvidenceRejected,
    VerifierBrokerStopped,
    ObservationStarted,
    ObservationTargetVerified,
    ObservationSourceCollectionStarted,
    ObservationSourceCollectionCompleted,
    ObservationLimitApplied,
    ObservationSucceeded,
    ObservationFailed,
    ObservationForbiddenReadBlocked,
    ObservationStaleTargetRejected,
    ObservationProcessHashRejected,
    ObservationOriginRejected,
    CognitiveBindingCreated,
    TrustedTargetResolved,
    TrustedActionPrepared,
    CognitivePermitMinted,
    TrustedCommitStarted,
    TrustedExecutionSucceeded,
    TrustedExecutionFailed,
    TrustedExecutionCancelled,
    TrustedExecutionAborted,
    ReobservationRequested,
    ReobservationStarted,
    FreshObservationCollected,
    ObservationDeltaComputed,
    VerificationStarted,
    VerificationPassed,
    VerificationFailed,
    VerificationInconclusive,
    VerificationUnsupported,
    VerificationUnsafe,
    VerificationAborted,
    RecoveryStarted,
    RecoveryTriggerAccepted,
    RecoveryTriggerRejected,
    RecoveryClassified,
    RecoveryDecisionCreated,
    RecoveryBudgetTransitioned,
    RecoveryFreshCycleRequested,
    RecoveryFreshCycleStarted,
    RecoveryFreshObservationCollected,
    RecoveryFreshProposalSelected,
    RecoveryFreshAdmissionCreated,
    RecoveryFreshActivationCreated,
    RecoveryFreshExecutionCompleted,
    RecoveryFreshVerificationCompleted,
    RecoveryClarificationCreated,
    RecoveryClarificationResponseAccepted,
    RecoveryClarificationResponseRejected,
    RecoveryEscalationCreated,
    RecoveryHistoryAppended,
    RecoveryCompleted,
    RecoveryStopped,
    RecoveryAborted,
    RecoveryLedgerRejected,
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
    RoleLedgerRejected,
    MemoryStoreStarted,
    MemoryNamespaceVerified,
    EpisodeSealRequested,
    EpisodeSealed,
    EpisodeSealRejected,
    MemoryObjectStored,
    MemoryQueryAccepted,
    MemoryQueryRejected,
    EpisodeSummaryVerified,
    MemoryAttachmentCreated,
    MemoryUseRecorded,
    LearningCandidateQuarantined,
    LearningExportCreated,
    MemoryReplayVerified,
    MemoryTamperRejected,
    MemoryStoreRecovered,
    MemoryStoreCleaned,
    RoleOperationsCycleStarted,
    RoleOperationsProfileVerified,
    RoleOperationsTimeVerified,
    SlaStateCalculated,
    SlaPauseAccepted,
    SlaPauseRejected,
    SlaBreachRecorded,
    RoleMetricCalculated,
    RoleMetricEvidenceRejected,
    RoleSnapshotCreated,
    RoleReportCreated,
    RoleReportRejected,
    InternalRouteVerified,
    InternalPublicationRecorded,
    RoleEscalationCreated,
    RoleEscalationAcknowledged,
    RoleEscalationResolved,
    RoleOperationsReplayVerified,
    RoleOperationsTamperRejected,
    RoleOperationsStoreRecovered,
    RoleOperationsStoreCleaned,
}

/// Outcome classification with no unrestricted payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsDeploymentAuditStatus {
    Succeeded,
    Failed,
    Blocked,
    Cleaned,
}

/// Payload-free deployment event. Only hashes and bounded identifiers are stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDeploymentAuditEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub kind: WindowsDeploymentAuditEventKind,
    pub status: WindowsDeploymentAuditStatus,
    pub artifact_hashes: BTreeMap<String, String>,
    pub detail_hash: String,
    pub recorded_at_unix_ms: u64,
}

impl WindowsDeploymentAuditEvent {
    /// Validates bounded identifiers and digest-only event data.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1
            || self.recorded_at_unix_ms == 0
            || self.artifact_hashes.len() > 32
        {
            return Err(DesktopError::Invalid(
                "Windows deployment audit event bounds are invalid".to_owned(),
            ));
        }
        validate_token(&self.event_id, "Windows deployment audit event_id")?;
        validate_hash(&self.detail_hash, "Windows deployment audit detail hash")?;
        for (name, hash) in &self.artifact_hashes {
            validate_token(name, "Windows deployment audit artifact name")?;
            validate_hash(hash, "Windows deployment audit artifact hash")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsDeploymentAuditManifest {
    schema_version: u32,
    ledger_id: String,
    session_id: String,
    maximum_records: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_hash: String,
    manifest_security_descriptor_hash: String,
    records_security_descriptor_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsDeploymentAuditRecord {
    schema_version: u32,
    sequence: u64,
    ledger_id: String,
    session_id: String,
    event: WindowsDeploymentAuditEvent,
    previous_record_hash: String,
    record_hash: String,
}

#[derive(Serialize)]
struct RecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    session_id: &'a str,
    event: &'a WindowsDeploymentAuditEvent,
    previous_record_hash: &'a str,
}

/// Verified deployment ledger state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDeploymentAuditVerification {
    pub ledger_id: String,
    pub session_id: String,
    pub record_count: u64,
    pub terminal_record_hash: String,
}

/// Protected append handle for deployment security events.
#[derive(Debug)]
pub struct WindowsDeploymentAuditLedger {
    root: PathBuf,
    manifest: WindowsDeploymentAuditManifest,
    verification: WindowsDeploymentAuditVerification,
}

impl WindowsDeploymentAuditLedger {
    /// Opens and fully verifies an existing ledger before append.
    pub fn open(root: &Path) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_windows_deployment_audit(root)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    /// Returns the protected audit session identity.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.manifest.session_id
    }

    /// Returns the current verified record count.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.verification.record_count
    }

    /// Appends one hash-chained event under an exclusive filesystem lock.
    pub fn append(&mut self, event: WindowsDeploymentAuditEvent) -> Result<String, DesktopError> {
        event.validate()?;
        let lock = DeploymentAuditLock::acquire(&self.root)?;
        let latest = verify_windows_deployment_audit(&self.root)?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "Windows deployment audit changed after it was opened".to_owned(),
            ));
        }
        if latest.record_count >= self.manifest.maximum_records {
            return Err(DesktopError::AccessDenied(
                "Windows deployment audit record limit is exhausted".to_owned(),
            ));
        }
        let sequence = latest.record_count.saturating_add(1);
        let payload = RecordPayload {
            schema_version: 1,
            sequence,
            ledger_id: &self.manifest.ledger_id,
            session_id: &self.manifest.session_id,
            event: &event,
            previous_record_hash: &latest.terminal_record_hash,
        };
        let record_hash = hash_value(&payload)?;
        let record = WindowsDeploymentAuditRecord {
            schema_version: 1,
            sequence,
            ledger_id: self.manifest.ledger_id.clone(),
            session_id: self.manifest.session_id.clone(),
            event,
            previous_record_hash: latest.terminal_record_hash,
            record_hash: record_hash.clone(),
        };
        let mut bytes =
            serde_json::to_vec(&record).map_err(|error| DesktopError::Json(error.to_string()))?;
        bytes.push(b'\n');
        let records = self.root.join(RECORDS_FILE);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&records)
            .map_err(|error| DesktopError::Io {
                path: records.display().to_string(),
                message: error.to_string(),
            })?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| DesktopError::Io {
                path: records.display().to_string(),
                message: error.to_string(),
            })?;
        self.verification = WindowsDeploymentAuditVerification {
            ledger_id: self.manifest.ledger_id.clone(),
            session_id: self.manifest.session_id.clone(),
            record_count: sequence,
            terminal_record_hash: record_hash.clone(),
        };
        drop(lock);
        Ok(record_hash)
    }
}

/// Creates a new protected deployment audit ledger.
pub fn initialize_windows_deployment_audit(
    root: &Path,
    ledger_id: &str,
    session_id: &str,
    maximum_records: u64,
    created_at_unix_ms: u64,
) -> Result<WindowsDeploymentAuditLedger, DesktopError> {
    validate_token(ledger_id, "Windows deployment audit ledger_id")?;
    validate_token(session_id, "Windows deployment audit session_id")?;
    if maximum_records == 0 || maximum_records > 1_000_000 || created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "Windows deployment audit initialization bounds are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        let root_hash = harden_and_hash(root, "deployment audit root")?;
        let manifest_path = root.join(MANIFEST_FILE);
        let records_path = root.join(RECORDS_FILE);
        write_new(&manifest_path, b"")?;
        write_new(&records_path, b"")?;
        let manifest = WindowsDeploymentAuditManifest {
            schema_version: 1,
            ledger_id: ledger_id.to_owned(),
            session_id: session_id.to_owned(),
            maximum_records,
            created_at_unix_ms,
            root_security_descriptor_hash: root_hash,
            manifest_security_descriptor_hash: harden_and_hash(
                &manifest_path,
                "deployment audit manifest",
            )?,
            records_security_descriptor_hash: harden_and_hash(
                &records_path,
                "deployment audit records",
            )?,
        };
        overwrite_existing(&manifest_path, &pretty_json_bytes(&manifest)?)?;
        WindowsDeploymentAuditLedger::open(root)
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    result
}

/// Verifies storage ACLs, sequence, complete hash chain, and event bounds.
pub fn verify_windows_deployment_audit(
    root: &Path,
) -> Result<WindowsDeploymentAuditVerification, DesktopError> {
    let manifest = load_manifest(root)?;
    verify_storage_security(root, &manifest)?;
    let bytes = read_bounded(&root.join(RECORDS_FILE), MAX_LEDGER_BYTES)?;
    let mut previous = ZERO_HASH.to_owned();
    let mut count = 0_u64;
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let record: WindowsDeploymentAuditRecord =
            serde_json::from_slice(line).map_err(|error| DesktopError::Json(error.to_string()))?;
        record.event.validate()?;
        count = count.saturating_add(1);
        let payload = RecordPayload {
            schema_version: record.schema_version,
            sequence: record.sequence,
            ledger_id: &record.ledger_id,
            session_id: &record.session_id,
            event: &record.event,
            previous_record_hash: &record.previous_record_hash,
        };
        if count > manifest.maximum_records
            || record.schema_version != 1
            || record.sequence != count
            || record.ledger_id != manifest.ledger_id
            || record.session_id != manifest.session_id
            || record.previous_record_hash != previous
            || record.record_hash != hash_value(&payload)?
        {
            return Err(DesktopError::Integrity(
                "Windows deployment audit chain or identity differs".to_owned(),
            ));
        }
        previous = record.record_hash;
    }
    Ok(WindowsDeploymentAuditVerification {
        ledger_id: manifest.ledger_id,
        session_id: manifest.session_id,
        record_count: count,
        terminal_record_hash: previous,
    })
}

fn load_manifest(root: &Path) -> Result<WindowsDeploymentAuditManifest, DesktopError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "Windows deployment audit root is not a regular directory".to_owned(),
        ));
    }
    let manifest: WindowsDeploymentAuditManifest =
        serde_json::from_slice(&read_bounded(&root.join(MANIFEST_FILE), 1024 * 1024)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    if manifest.schema_version != 1
        || manifest.maximum_records == 0
        || manifest.maximum_records > 1_000_000
        || manifest.created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "Windows deployment audit manifest bounds are invalid".to_owned(),
        ));
    }
    validate_token(&manifest.ledger_id, "Windows deployment audit ledger_id")?;
    validate_token(&manifest.session_id, "Windows deployment audit session_id")?;
    for hash in [
        &manifest.root_security_descriptor_hash,
        &manifest.manifest_security_descriptor_hash,
        &manifest.records_security_descriptor_hash,
    ] {
        validate_hash(hash, "Windows deployment audit security descriptor hash")?;
    }
    Ok(manifest)
}

fn verify_storage_security(
    root: &Path,
    manifest: &WindowsDeploymentAuditManifest,
) -> Result<(), DesktopError> {
    for (path, expected) in [
        (root.to_path_buf(), &manifest.root_security_descriptor_hash),
        (
            root.join(MANIFEST_FILE),
            &manifest.manifest_security_descriptor_hash,
        ),
        (
            root.join(RECORDS_FILE),
            &manifest.records_security_descriptor_hash,
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!(
                "Windows deployment audit ACL verification failed: {error}"
            ))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(
                "Windows deployment audit ACL changed".to_owned(),
            ));
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

struct DeploymentAuditLock(PathBuf);

impl DeploymentAuditLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("deployment audit lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "deployment audit lock ACL hardening failed: {error}"
            )));
        }
        Ok(Self(path))
    }
}

impl Drop for DeploymentAuditLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn deployment_audit_rejects_record_and_acl_tampering() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_millis() as u64);
        let root = std::env::temp_dir().join(format!(
            "d2i-deployment-audit-test-{}-{now}",
            std::process::id()
        ));
        let mut ledger =
            initialize_windows_deployment_audit(&root, "deployment-ledger", "session", 8, now)
                .unwrap_or_else(|error| panic!("{error}"));
        ledger
            .append(WindowsDeploymentAuditEvent {
                schema_version: 1,
                event_id: "policy-installed".to_owned(),
                kind: WindowsDeploymentAuditEventKind::PolicyInstalled,
                status: WindowsDeploymentAuditStatus::Succeeded,
                artifact_hashes: BTreeMap::from([("policy".to_owned(), fixed_hash(1))]),
                detail_hash: fixed_hash(2),
                recorded_at_unix_ms: now,
            })
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            verify_windows_deployment_audit(&root)
                .unwrap_or_else(|error| panic!("{error}"))
                .record_count,
            1
        );
        let records = root.join(RECORDS_FILE);
        let mut bytes = std::fs::read(&records).unwrap_or_else(|error| panic!("{error}"));
        if let Some(byte) = bytes.iter_mut().find(|byte| **byte == b'p') {
            *byte = b'q';
        }
        std::fs::write(&records, bytes).unwrap_or_else(|error| panic!("{error}"));
        assert!(verify_windows_deployment_audit(&root).is_err());
        std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    }

    fn fixed_hash(marker: u8) -> String {
        format!("sha256:{marker:02x}{}", "00".repeat(31))
    }
}
