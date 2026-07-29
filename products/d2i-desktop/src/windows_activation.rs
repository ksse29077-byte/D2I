use crate::windows_binding::CertifiedWindowsBinding;
use crate::{
    hash_value, json_bytes, pretty_json_bytes, read_bounded, sha256_bytes, validate_hash,
    validate_token, write_new, DesktopAdapterDescriptor, DesktopError,
    SignedWindowsWfpFunctionalAttestationV2, WindowsAdapterKind, WindowsRuntimeManifest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const POLICY_FILE: &str = "windows-activation-policy.json";
const RECORDS_FILE: &str = "windows-activation-records.jsonl";
const LOCK_FILE: &str = ".windows-activation.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Immutable local replay policy pinned to one Windows runtime manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsActivationLedgerPolicy {
    pub schema_version: u32,
    pub ledger_id: String,
    pub integration_id: String,
    pub manifest_hash: String,
    pub allowed_activator_ids: BTreeSet<String>,
    pub maximum_entries: u64,
    pub root_security_descriptor_hash: String,
    pub policy_security_descriptor_hash: String,
    pub records_security_descriptor_hash: String,
}

/// One certificate consumed before an adapter can be constructed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsActivationRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub integration_id: String,
    pub binding_id: String,
    pub certification_id: String,
    pub manifest_hash: String,
    pub evidence_hash: String,
    pub certification_hash: String,
    pub activation_challenge: Option<String>,
    pub self_test_report_hash: Option<String>,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub activated_at_unix_seconds: u64,
    pub activator_id: String,
    pub previous_record_hash: String,
    pub record_hash: String,
}

/// Verified append-only ledger state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsActivationLedgerVerification {
    pub ledger_id: String,
    pub integration_id: String,
    pub manifest_hash: String,
    pub entry_count: u64,
    pub chain_head: String,
    pub latest_observed_at_unix_seconds: Option<u64>,
}

/// One-shot runtime authority consumed by a capability-specific constructor.
#[derive(Debug)]
pub struct ActivatedWindowsBinding {
    pub(crate) integration_id: String,
    pub(crate) binding_id: String,
    pub(crate) activation_record_hash: String,
    pub(crate) configuration_hash: String,
    pub(crate) adapter_kind: WindowsAdapterKind,
    pub(crate) adapter_descriptor: DesktopAdapterDescriptor,
    pub(crate) observed_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) wfp_functional_attestation: Option<SignedWindowsWfpFunctionalAttestationV2>,
}

impl ActivatedWindowsBinding {
    /// Returns the reviewed integration identity.
    pub fn integration_id(&self) -> &str {
        &self.integration_id
    }

    /// Returns the consumed binding identity.
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the durable replay-guard record hash.
    pub fn activation_record_hash(&self) -> &str {
        &self.activation_record_hash
    }

    /// Returns the capability group authorized by this one-shot binding.
    pub const fn adapter_kind(&self) -> WindowsAdapterKind {
        self.adapter_kind
    }
}

/// Persistent admission result and its one-shot adapter authority.
#[derive(Debug)]
pub struct WindowsActivationAdmission {
    pub verification: WindowsActivationLedgerVerification,
    pub activation: ActivatedWindowsBinding,
}

#[derive(Serialize)]
struct RecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    integration_id: &'a str,
    binding_id: &'a str,
    certification_id: &'a str,
    manifest_hash: &'a str,
    evidence_hash: &'a str,
    certification_hash: &'a str,
    activation_challenge: &'a Option<String>,
    self_test_report_hash: &'a Option<String>,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    activated_at_unix_seconds: u64,
    activator_id: &'a str,
    previous_record_hash: &'a str,
}

/// Creates a new replay ledger pinned to the exact reviewed manifest.
pub fn initialize_windows_activation_ledger(
    root: &Path,
    ledger_id: &str,
    manifest: &WindowsRuntimeManifest,
    allowed_activator_ids: BTreeSet<String>,
    maximum_entries: u64,
) -> Result<WindowsActivationLedgerVerification, DesktopError> {
    manifest.validate()?;
    let mut policy = WindowsActivationLedgerPolicy {
        schema_version: 2,
        ledger_id: ledger_id.to_owned(),
        integration_id: manifest.integration_id.clone(),
        manifest_hash: manifest.manifest_hash()?,
        allowed_activator_ids,
        maximum_entries,
        root_security_descriptor_hash: ZERO_HASH.to_owned(),
        policy_security_descriptor_hash: ZERO_HASH.to_owned(),
        records_security_descriptor_hash: ZERO_HASH.to_owned(),
    };
    validate_policy(&policy)?;
    if root.exists() {
        return Err(DesktopError::Invalid(
            "Windows activation ledger path already exists".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let root_security_descriptor_hash =
        match harden_and_hash_security_descriptor(root, "activation ledger root") {
            Ok(value) => value,
            Err(error) => {
                let _ = std::fs::remove_dir(root);
                return Err(error);
            }
        };
    let result = (|| {
        let policy_path = root.join(POLICY_FILE);
        let records_path = root.join(RECORDS_FILE);
        write_new(&policy_path, b"")?;
        write_new(&records_path, b"")?;
        policy.root_security_descriptor_hash = root_security_descriptor_hash;
        policy.policy_security_descriptor_hash =
            harden_and_hash_security_descriptor(&policy_path, "activation ledger policy")?;
        policy.records_security_descriptor_hash =
            harden_and_hash_security_descriptor(&records_path, "activation ledger records")?;
        validate_policy(&policy)?;
        overwrite_existing(&policy_path, &pretty_json_bytes(&policy)?)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(root);
        return Err(error);
    }
    Ok(verification(&policy, &[]))
}

/// Atomically consumes a fresh certificate and mints one adapter constructor token.
pub fn activate_certified_windows_binding(
    root: &Path,
    activator_id: &str,
    certified: CertifiedWindowsBinding,
    now_unix_seconds: u64,
) -> Result<WindowsActivationAdmission, DesktopError> {
    validate_token(activator_id, "Windows activator_id")?;
    validate_root(root)?;
    let lock = ActivationLock::acquire(root)?;
    let (policy, records) = load_verified(root)?;
    if !policy.allowed_activator_ids.contains(activator_id) {
        return Err(DesktopError::AccessDenied(
            "Windows activator is not allowlisted".to_owned(),
        ));
    }
    if policy.integration_id != certified.integration_id
        || policy.manifest_hash != certified.manifest_hash
    {
        return Err(DesktopError::Integrity(
            "certified Windows binding differs from ledger policy".to_owned(),
        ));
    }
    if now_unix_seconds < certified.observed_at_unix_seconds
        || now_unix_seconds >= certified.expires_at_unix_seconds
    {
        return Err(DesktopError::AdapterUnavailable(
            "certified Windows binding expired before activation".to_owned(),
        ));
    }
    if u64::try_from(records.len()).unwrap_or(u64::MAX) >= policy.maximum_entries {
        return Err(DesktopError::Invalid(
            "Windows activation ledger entry limit reached".to_owned(),
        ));
    }
    if records.iter().any(|record| {
        record.binding_id == certified.binding_id
            || record.evidence_hash == certified.evidence_hash
            || record.certification_id == certified.certification_id
            || record.certification_hash == certified.certification_hash
            || certified
                .activation_challenge
                .as_ref()
                .is_some_and(|challenge| record.activation_challenge.as_ref() == Some(challenge))
            || certified
                .self_test_report_hash
                .as_ref()
                .is_some_and(|report_hash| {
                    record.self_test_report_hash.as_ref() == Some(report_hash)
                })
    }) {
        return Err(DesktopError::Replay(
            "Windows binding or certification was already consumed".to_owned(),
        ));
    }
    if records
        .last()
        .is_some_and(|record| certified.observed_at_unix_seconds <= record.observed_at_unix_seconds)
    {
        return Err(DesktopError::Replay(
            "Windows binding observation would roll back ledger time".to_owned(),
        ));
    }

    let sequence = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let previous_record_hash = records
        .last()
        .map_or(ZERO_HASH, |record| record.record_hash.as_str())
        .to_owned();
    let payload = RecordPayload {
        schema_version: 2,
        sequence,
        ledger_id: &policy.ledger_id,
        integration_id: &certified.integration_id,
        binding_id: &certified.binding_id,
        certification_id: &certified.certification_id,
        manifest_hash: &certified.manifest_hash,
        evidence_hash: &certified.evidence_hash,
        certification_hash: &certified.certification_hash,
        activation_challenge: &certified.activation_challenge,
        self_test_report_hash: &certified.self_test_report_hash,
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        activated_at_unix_seconds: now_unix_seconds,
        activator_id,
        previous_record_hash: &previous_record_hash,
    };
    let record_hash = hash_value(&payload)?;
    let record = WindowsActivationRecord {
        schema_version: payload.schema_version,
        sequence,
        ledger_id: policy.ledger_id.clone(),
        integration_id: certified.integration_id.clone(),
        binding_id: certified.binding_id.clone(),
        certification_id: certified.certification_id.clone(),
        manifest_hash: certified.manifest_hash.clone(),
        evidence_hash: certified.evidence_hash.clone(),
        certification_hash: certified.certification_hash.clone(),
        activation_challenge: certified.activation_challenge.clone(),
        self_test_report_hash: certified.self_test_report_hash.clone(),
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        activated_at_unix_seconds: now_unix_seconds,
        activator_id: activator_id.to_owned(),
        previous_record_hash,
        record_hash: record_hash.clone(),
    };
    append_record(root, &record)?;
    let verification = WindowsActivationLedgerVerification {
        ledger_id: policy.ledger_id,
        integration_id: policy.integration_id,
        manifest_hash: policy.manifest_hash,
        entry_count: sequence.saturating_add(1),
        chain_head: record_hash.clone(),
        latest_observed_at_unix_seconds: Some(certified.observed_at_unix_seconds),
    };
    let activation = ActivatedWindowsBinding {
        integration_id: certified.integration_id,
        binding_id: certified.binding_id,
        activation_record_hash: record_hash,
        configuration_hash: certified.configuration_hash,
        adapter_kind: certified.adapter_kind,
        adapter_descriptor: certified.adapter_descriptor,
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        wfp_functional_attestation: certified.wfp_functional_attestation,
    };
    drop(lock);
    Ok(WindowsActivationAdmission {
        verification,
        activation,
    })
}

/// Verifies bounds, identity, uniqueness, ordering, and the complete hash chain.
pub fn verify_windows_activation_ledger(
    root: &Path,
) -> Result<WindowsActivationLedgerVerification, DesktopError> {
    let (policy, records) = load_verified(root)?;
    Ok(verification(&policy, &records))
}

fn append_record(root: &Path, record: &WindowsActivationRecord) -> Result<(), DesktopError> {
    let policy = load_policy(root)?;
    verify_storage_security(root, &policy)?;
    let path = root.join(RECORDS_FILE);
    let mut bytes = json_bytes(record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn load_verified(
    root: &Path,
) -> Result<(WindowsActivationLedgerPolicy, Vec<WindowsActivationRecord>), DesktopError> {
    validate_root(root)?;
    let policy = load_policy(root)?;
    verify_storage_security(root, &policy)?;
    let bytes = read_bounded(&root.join(RECORDS_FILE), MAX_LEDGER_BYTES)?;
    let mut records = Vec::new();
    let mut previous = ZERO_HASH.to_owned();
    let mut latest_observed = None;
    let mut binding_ids = BTreeSet::new();
    let mut certification_ids = BTreeSet::new();
    let mut evidence_hashes = BTreeSet::new();
    let mut certification_hashes = BTreeSet::new();
    let mut activation_challenges = BTreeSet::new();
    let mut self_test_report_hashes = BTreeSet::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let record: WindowsActivationRecord =
            serde_json::from_slice(line).map_err(|error| DesktopError::Json(error.to_string()))?;
        validate_record(&record)?;
        let sequence = u64::try_from(records.len()).unwrap_or(u64::MAX);
        if record.sequence != sequence
            || record.ledger_id != policy.ledger_id
            || record.integration_id != policy.integration_id
            || record.manifest_hash != policy.manifest_hash
            || record.previous_record_hash != previous
            || record.record_hash != hash_value(&record_payload(&record))?
            || !binding_ids.insert(record.binding_id.clone())
            || !certification_ids.insert(record.certification_id.clone())
            || !evidence_hashes.insert(record.evidence_hash.clone())
            || !certification_hashes.insert(record.certification_hash.clone())
            || record
                .activation_challenge
                .as_ref()
                .is_some_and(|value| !activation_challenges.insert(value.clone()))
            || record
                .self_test_report_hash
                .as_ref()
                .is_some_and(|value| !self_test_report_hashes.insert(value.clone()))
            || latest_observed.is_some_and(|latest| record.observed_at_unix_seconds <= latest)
        {
            return Err(DesktopError::Integrity(
                "Windows activation ledger chain, order, or uniqueness failed".to_owned(),
            ));
        }
        latest_observed = Some(record.observed_at_unix_seconds);
        previous = record.record_hash.clone();
        records.push(record);
        if u64::try_from(records.len()).unwrap_or(u64::MAX) > policy.maximum_entries {
            return Err(DesktopError::Integrity(
                "Windows activation ledger exceeds its entry limit".to_owned(),
            ));
        }
    }
    Ok((policy, records))
}

fn validate_policy(policy: &WindowsActivationLedgerPolicy) -> Result<(), DesktopError> {
    if policy.schema_version != 2
        || policy.maximum_entries == 0
        || policy.maximum_entries > 1_000_000
        || policy.allowed_activator_ids.is_empty()
        || policy.allowed_activator_ids.len() > 256
    {
        return Err(DesktopError::Invalid(
            "Windows activation ledger policy bounds are invalid".to_owned(),
        ));
    }
    validate_token(&policy.ledger_id, "Windows ledger_id")?;
    validate_token(&policy.integration_id, "Windows integration_id")?;
    validate_hash(&policy.manifest_hash, "Windows manifest_hash")?;
    validate_hash(
        &policy.root_security_descriptor_hash,
        "Windows activation root security descriptor hash",
    )?;
    validate_hash(
        &policy.policy_security_descriptor_hash,
        "Windows activation policy security descriptor hash",
    )?;
    validate_hash(
        &policy.records_security_descriptor_hash,
        "Windows activation records security descriptor hash",
    )?;
    for activator in &policy.allowed_activator_ids {
        validate_token(activator, "Windows activator_id")?;
    }
    Ok(())
}

fn validate_record(record: &WindowsActivationRecord) -> Result<(), DesktopError> {
    if record.schema_version != 2
        || record.observed_at_unix_seconds == 0
        || record.expires_at_unix_seconds <= record.observed_at_unix_seconds
        || record.activated_at_unix_seconds < record.observed_at_unix_seconds
        || record.activated_at_unix_seconds >= record.expires_at_unix_seconds
    {
        return Err(DesktopError::Invalid(
            "Windows activation record version or time bounds are invalid".to_owned(),
        ));
    }
    for (value, field) in [
        (&record.ledger_id, "Windows ledger_id"),
        (&record.integration_id, "Windows integration_id"),
        (&record.binding_id, "Windows binding_id"),
        (&record.certification_id, "Windows certification_id"),
        (&record.activator_id, "Windows activator_id"),
    ] {
        validate_token(value, field)?;
    }
    for (value, field) in [
        (&record.manifest_hash, "Windows manifest_hash"),
        (&record.evidence_hash, "Windows evidence_hash"),
        (&record.certification_hash, "Windows certification_hash"),
        (&record.previous_record_hash, "Windows previous_record_hash"),
        (&record.record_hash, "Windows record_hash"),
    ] {
        validate_hash(value, field)?;
    }
    if record.activation_challenge.is_some() != record.self_test_report_hash.is_some() {
        return Err(DesktopError::Invalid(
            "Windows activation record must consume challenge and report hash together".to_owned(),
        ));
    }
    if let Some(challenge) = &record.activation_challenge {
        validate_token(challenge, "Windows activation challenge")?;
    }
    if let Some(report_hash) = &record.self_test_report_hash {
        validate_hash(report_hash, "Windows self-test report hash")?;
    }
    Ok(())
}

fn record_payload(record: &WindowsActivationRecord) -> RecordPayload<'_> {
    RecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        integration_id: &record.integration_id,
        binding_id: &record.binding_id,
        certification_id: &record.certification_id,
        manifest_hash: &record.manifest_hash,
        evidence_hash: &record.evidence_hash,
        certification_hash: &record.certification_hash,
        activation_challenge: &record.activation_challenge,
        self_test_report_hash: &record.self_test_report_hash,
        observed_at_unix_seconds: record.observed_at_unix_seconds,
        expires_at_unix_seconds: record.expires_at_unix_seconds,
        activated_at_unix_seconds: record.activated_at_unix_seconds,
        activator_id: &record.activator_id,
        previous_record_hash: &record.previous_record_hash,
    }
}

fn verification(
    policy: &WindowsActivationLedgerPolicy,
    records: &[WindowsActivationRecord],
) -> WindowsActivationLedgerVerification {
    WindowsActivationLedgerVerification {
        ledger_id: policy.ledger_id.clone(),
        integration_id: policy.integration_id.clone(),
        manifest_hash: policy.manifest_hash.clone(),
        entry_count: u64::try_from(records.len()).unwrap_or(u64::MAX),
        chain_head: records
            .last()
            .map_or(ZERO_HASH, |record| record.record_hash.as_str())
            .to_owned(),
        latest_observed_at_unix_seconds: records
            .last()
            .map(|record| record.observed_at_unix_seconds),
    }
}

fn validate_root(root: &Path) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "Windows activation ledger root must be a non-symlink directory".to_owned(),
        ));
    }
    for file in [POLICY_FILE, RECORDS_FILE] {
        let path = root.join(file);
        let metadata = std::fs::symlink_metadata(&path).map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(DesktopError::Integrity(
                "Windows activation ledger files must be regular non-symlink files".to_owned(),
            ));
        }
    }
    Ok(())
}

struct ActivationLock {
    path: PathBuf,
}

impl ActivationLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        let _ = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("activation lock unavailable: {error}"),
            })?;
        if let Err(error) = d2i_windows_host::harden_path_for_current_user(&path) {
            let _ = std::fs::remove_file(&path);
            return Err(DesktopError::Integrity(format!(
                "activation lock ACL hardening failed: {error}"
            )));
        }
        Ok(Self { path })
    }
}

fn load_policy(root: &Path) -> Result<WindowsActivationLedgerPolicy, DesktopError> {
    let policy: WindowsActivationLedgerPolicy =
        serde_json::from_slice(&read_bounded(&root.join(POLICY_FILE), 1024 * 1024)?)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
    validate_policy(&policy)?;
    Ok(policy)
}

fn harden_and_hash_security_descriptor(path: &Path, label: &str) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::harden_path_for_current_user(path).map_err(|error| {
        DesktopError::Integrity(format!("{label} ACL hardening failed: {error}"))
    })?;
    Ok(sha256_bytes(&descriptor))
}

fn verify_storage_security(
    root: &Path,
    policy: &WindowsActivationLedgerPolicy,
) -> Result<(), DesktopError> {
    for (path, expected, label) in [
        (
            root.to_path_buf(),
            &policy.root_security_descriptor_hash,
            "root",
        ),
        (
            root.join(POLICY_FILE),
            &policy.policy_security_descriptor_hash,
            "policy",
        ),
        (
            root.join(RECORDS_FILE),
            &policy.records_security_descriptor_hash,
            "records",
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!(
                "Windows activation {label} security descriptor failed: {error}"
            ))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(format!(
                "Windows activation {label} security descriptor changed"
            )));
        }
    }
    Ok(())
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DesktopError::Integrity(
            "activation policy target must be a regular non-symlink file".to_owned(),
        ));
    }
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

impl Drop for ActivationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{current_windows_host_binding, DesktopCapability, WindowsBrowserEgressRequirement};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixed_hash(marker: u8) -> String {
        format!("sha256:{marker:02x}{}", "00".repeat(31))
    }

    fn certified(
        descriptor: &DesktopAdapterDescriptor,
        observed: u64,
        marker: u8,
        challenge: &str,
        report_hash: &str,
    ) -> CertifiedWindowsBinding {
        CertifiedWindowsBinding {
            integration_id: "ledger-v2-integration".to_owned(),
            binding_id: format!("binding-{marker}"),
            certification_id: format!("certification-{marker}"),
            manifest_hash: fixed_hash(1),
            evidence_hash: fixed_hash(marker),
            certification_hash: fixed_hash(marker.saturating_add(20)),
            configuration_hash: fixed_hash(2),
            adapter_kind: WindowsAdapterKind::FileWrite,
            adapter_descriptor: descriptor.clone(),
            observed_at_unix_seconds: observed,
            expires_at_unix_seconds: observed + 120,
            activation_challenge: Some(challenge.to_owned()),
            self_test_report_hash: Some(report_hash.to_owned()),
            wfp_functional_attestation: None,
        }
    }

    #[test]
    fn ledger_v2_rejects_challenge_report_and_time_replay_independently() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_secs());
        let descriptor = DesktopAdapterDescriptor {
            schema_version: 1,
            adapter_id: "windows-file-write.desktop".to_owned(),
            adapter_version: "1.0.0".to_owned(),
            platform: "windows".to_owned(),
            capabilities: BTreeSet::from([DesktopCapability::WriteFile]),
            concrete_host_adapter: true,
            process_isolated: true,
            network_capable: false,
        };
        let manifest = WindowsRuntimeManifest {
            schema_version: 1,
            integration_id: "ledger-v2-integration".to_owned(),
            adapter_kind: WindowsAdapterKind::FileWrite,
            adapter_descriptor: descriptor.clone(),
            configuration_hash: fixed_hash(2),
            worker_executable_hash: fixed_hash(3),
            process_isolation: None,
            browser_egress_requirement: None::<WindowsBrowserEgressRequirement>,
            host: current_windows_host_binding().unwrap_or_else(|error| panic!("{error}")),
            interactive_session_required: false,
            binding_attestor_id: "attestor".to_owned(),
            binding_attestor_public_key: "00".repeat(32),
            certifier_id: "certifier".to_owned(),
            certifier_public_key: "11".repeat(32),
        };
        let root = std::env::temp_dir().join(format!(
            "d2i-activation-v2-test-{}-{now}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        initialize_windows_activation_ledger(
            &root,
            "ledger-v2",
            &manifest,
            BTreeSet::from(["activator".to_owned()]),
            8,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let manifest_hash = manifest
            .manifest_hash()
            .unwrap_or_else(|error| panic!("{error}"));
        let mut first = certified(&descriptor, now, 40, "challenge-00000001", &fixed_hash(70));
        first.manifest_hash = manifest_hash.clone();
        activate_certified_windows_binding(&root, "activator", first, now + 1)
            .unwrap_or_else(|error| panic!("{error}"));

        let mut same_challenge = certified(
            &descriptor,
            now + 2,
            41,
            "challenge-00000001",
            &fixed_hash(71),
        );
        same_challenge.manifest_hash = manifest_hash.clone();
        assert!(
            activate_certified_windows_binding(&root, "activator", same_challenge, now + 3)
                .is_err()
        );

        let mut same_report = certified(
            &descriptor,
            now + 2,
            42,
            "challenge-00000002",
            &fixed_hash(70),
        );
        same_report.manifest_hash = manifest_hash.clone();
        assert!(
            activate_certified_windows_binding(&root, "activator", same_report, now + 3).is_err()
        );

        let mut rollback = certified(&descriptor, now, 43, "challenge-00000003", &fixed_hash(72));
        rollback.manifest_hash = manifest_hash;
        assert!(activate_certified_windows_binding(&root, "activator", rollback, now + 1).is_err());
        std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    }
}
