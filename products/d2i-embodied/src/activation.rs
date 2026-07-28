use crate::{
    check_integration_readiness, json_bytes, pretty_json_bytes, read_bounded, sha256_bytes,
    validate_hash, validate_token, write_new, CertifiedIntegration, EmbodiedError,
    IntegrationManifest, Ros2Adapter, Ros2TopicMap, Ros2Transport,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const POLICY_FILE: &str = "activation-policy.json";
const RECORDS_FILE: &str = "activation-records.jsonl";
const LOCK_FILE: &str = ".activation.lock";
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Immutable policy for one local runtime-activation ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationLedgerPolicy {
    pub schema_version: u32,
    pub ledger_id: String,
    pub integration_id: String,
    pub manifest_hash: String,
    pub allowed_activator_ids: BTreeSet<String>,
    pub maximum_entries: u64,
}

/// One consumed runtime binding recorded before adapter construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRecord {
    pub schema_version: u32,
    pub sequence: u64,
    pub ledger_id: String,
    pub integration_id: String,
    pub binding_id: String,
    pub manifest_hash: String,
    pub evidence_hash: String,
    pub observed_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub activated_at_unix_seconds: u64,
    pub activator_id: String,
    pub previous_record_hash: String,
    pub record_hash: String,
}

/// Verified state of a local activation ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationLedgerVerification {
    pub ledger_id: String,
    pub integration_id: String,
    pub manifest_hash: String,
    pub entry_count: u64,
    pub chain_head: String,
    pub latest_observed_at_unix_seconds: Option<u64>,
}

/// One-shot integration activation admitted by the persistent replay guard.
#[derive(Debug)]
pub struct ActivatedIntegration {
    integration_id: String,
    binding_id: String,
    activation_record_hash: String,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    topic_map: Ros2TopicMap,
}

impl ActivatedIntegration {
    /// Returns the admitted integration identity.
    pub fn integration_id(&self) -> &str {
        &self.integration_id
    }

    /// Returns the consumed runtime binding identity.
    pub fn binding_id(&self) -> &str {
        &self.binding_id
    }

    /// Returns the hash-chain record that admitted this activation.
    pub fn activation_record_hash(&self) -> &str {
        &self.activation_record_hash
    }

    /// Consumes this one-shot activation and binds the certified topic map.
    pub fn bind_ros2<T: Ros2Transport>(
        self,
        transport: T,
        now_unix_seconds: u64,
    ) -> Result<Ros2Adapter<T>, EmbodiedError> {
        if now_unix_seconds < self.observed_at_unix_seconds
            || now_unix_seconds >= self.expires_at_unix_seconds
        {
            return Err(EmbodiedError::AdapterUnavailable(
                "admitted runtime binding is not currently valid".to_owned(),
            ));
        }
        Ros2Adapter::new(self.topic_map, transport)
    }
}

/// Ledger result and one-shot activation admitted by the replay guard.
#[derive(Debug)]
pub struct ActivationAdmission {
    pub verification: ActivationLedgerVerification,
    pub activation: ActivatedIntegration,
}

#[derive(Serialize)]
struct RecordPayload<'a> {
    schema_version: u32,
    sequence: u64,
    ledger_id: &'a str,
    integration_id: &'a str,
    binding_id: &'a str,
    manifest_hash: &'a str,
    evidence_hash: &'a str,
    observed_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    activated_at_unix_seconds: u64,
    activator_id: &'a str,
    previous_record_hash: &'a str,
}

/// Creates a new ledger pinned to the exact reviewed manifest.
pub fn initialize_activation_ledger(
    root: &Path,
    ledger_id: &str,
    manifest: &IntegrationManifest,
    allowed_activator_ids: BTreeSet<String>,
    maximum_entries: u64,
) -> Result<ActivationLedgerVerification, EmbodiedError> {
    if !check_integration_readiness(manifest)?.ready {
        return Err(EmbodiedError::Invalid(
            "activation ledger requires a ready integration manifest".to_owned(),
        ));
    }
    let policy = ActivationLedgerPolicy {
        schema_version: 1,
        ledger_id: ledger_id.to_owned(),
        integration_id: manifest.integration_id.clone(),
        manifest_hash: sha256_bytes(&json_bytes(manifest)?),
        allowed_activator_ids,
        maximum_entries,
    };
    validate_policy(&policy)?;
    if root.exists() {
        return Err(EmbodiedError::Invalid(
            "activation ledger path already exists".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| EmbodiedError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        write_new(&root.join(POLICY_FILE), &pretty_json_bytes(&policy)?)?;
        write_new(&root.join(RECORDS_FILE), b"")
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_dir_all(root);
        return Err(error);
    }
    Ok(verification(&policy, &[]))
}

/// Atomically consumes a certified binding after replay and rollback checks.
pub fn activate_certified_integration(
    root: &Path,
    activator_id: &str,
    certified: CertifiedIntegration,
    now_unix_seconds: u64,
) -> Result<ActivationAdmission, EmbodiedError> {
    validate_token(activator_id, "activator_id")?;
    validate_root(root)?;
    let lock = ActivationLock::acquire(root)?;
    let (policy, records) = load_verified(root)?;
    if !policy.allowed_activator_ids.contains(activator_id) {
        return Err(EmbodiedError::AccessDenied(
            "activator is not allowlisted by the activation policy".to_owned(),
        ));
    }
    if policy.integration_id != certified.integration_id
        || policy.manifest_hash != certified.manifest_hash
    {
        return Err(EmbodiedError::Integrity(
            "certified integration does not match the activation policy".to_owned(),
        ));
    }
    if now_unix_seconds < certified.observed_at_unix_seconds
        || now_unix_seconds >= certified.expires_at_unix_seconds
    {
        return Err(EmbodiedError::AdapterUnavailable(
            "certified integration expired before activation".to_owned(),
        ));
    }
    if u64::try_from(records.len()).unwrap_or(u64::MAX) >= policy.maximum_entries {
        return Err(EmbodiedError::Invalid(
            "activation ledger entry limit has been reached".to_owned(),
        ));
    }
    if records.iter().any(|record| {
        record.binding_id == certified.binding_id || record.evidence_hash == certified.evidence_hash
    }) {
        return Err(EmbodiedError::Integrity(
            "runtime binding evidence has already been consumed".to_owned(),
        ));
    }
    if records
        .last()
        .is_some_and(|record| certified.observed_at_unix_seconds <= record.observed_at_unix_seconds)
    {
        return Err(EmbodiedError::Integrity(
            "runtime binding observation would roll back ledger time".to_owned(),
        ));
    }

    let sequence = u64::try_from(records.len()).unwrap_or(u64::MAX);
    let previous_record_hash = records
        .last()
        .map_or(ZERO_HASH, |record| record.record_hash.as_str())
        .to_owned();
    let payload = RecordPayload {
        schema_version: 1,
        sequence,
        ledger_id: &policy.ledger_id,
        integration_id: &certified.integration_id,
        binding_id: &certified.binding_id,
        manifest_hash: &certified.manifest_hash,
        evidence_hash: &certified.evidence_hash,
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        activated_at_unix_seconds: now_unix_seconds,
        activator_id,
        previous_record_hash: &previous_record_hash,
    };
    let record_hash = sha256_bytes(&json_bytes(&payload)?);
    let record = ActivationRecord {
        schema_version: payload.schema_version,
        sequence,
        ledger_id: policy.ledger_id.clone(),
        integration_id: certified.integration_id.clone(),
        binding_id: certified.binding_id.clone(),
        manifest_hash: certified.manifest_hash.clone(),
        evidence_hash: certified.evidence_hash.clone(),
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        activated_at_unix_seconds: now_unix_seconds,
        activator_id: activator_id.to_owned(),
        previous_record_hash,
        record_hash: record_hash.clone(),
    };
    append_record(root, &record)?;
    let verification = ActivationLedgerVerification {
        ledger_id: policy.ledger_id,
        integration_id: policy.integration_id,
        manifest_hash: policy.manifest_hash,
        entry_count: sequence.saturating_add(1),
        chain_head: record_hash.clone(),
        latest_observed_at_unix_seconds: Some(certified.observed_at_unix_seconds),
    };
    let activation = ActivatedIntegration {
        integration_id: certified.integration_id,
        binding_id: certified.binding_id,
        activation_record_hash: record_hash,
        observed_at_unix_seconds: certified.observed_at_unix_seconds,
        expires_at_unix_seconds: certified.expires_at_unix_seconds,
        topic_map: certified.topic_map,
    };
    drop(lock);
    Ok(ActivationAdmission {
        verification,
        activation,
    })
}

/// Verifies policy, bounds, and the complete append-only activation chain.
pub fn verify_activation_ledger(
    root: &Path,
) -> Result<ActivationLedgerVerification, EmbodiedError> {
    let (policy, records) = load_verified(root)?;
    Ok(verification(&policy, &records))
}

fn append_record(root: &Path, record: &ActivationRecord) -> Result<(), EmbodiedError> {
    let path = root.join(RECORDS_FILE);
    let mut bytes = json_bytes(record)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn load_verified(
    root: &Path,
) -> Result<(ActivationLedgerPolicy, Vec<ActivationRecord>), EmbodiedError> {
    validate_root(root)?;
    let policy: ActivationLedgerPolicy =
        serde_json::from_slice(&read_bounded(&root.join(POLICY_FILE), 1024 * 1024)?)
            .map_err(|error| EmbodiedError::Json(error.to_string()))?;
    validate_policy(&policy)?;
    let bytes = read_bounded(&root.join(RECORDS_FILE), MAX_LEDGER_BYTES)?;
    let mut records = Vec::new();
    let mut previous = ZERO_HASH.to_owned();
    let mut latest_observed = None;
    let mut binding_ids = BTreeSet::new();
    let mut evidence_hashes = BTreeSet::new();
    for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let record: ActivationRecord =
            serde_json::from_slice(line).map_err(|error| EmbodiedError::Json(error.to_string()))?;
        validate_record(&record)?;
        let sequence = u64::try_from(records.len()).unwrap_or(u64::MAX);
        let expected_hash = sha256_bytes(&json_bytes(&record_payload(&record))?);
        if record.sequence != sequence
            || record.ledger_id != policy.ledger_id
            || record.integration_id != policy.integration_id
            || record.manifest_hash != policy.manifest_hash
            || record.previous_record_hash != previous
            || record.record_hash != expected_hash
            || !policy.allowed_activator_ids.contains(&record.activator_id)
            || !binding_ids.insert(record.binding_id.clone())
            || !evidence_hashes.insert(record.evidence_hash.clone())
            || latest_observed.is_some_and(|latest| record.observed_at_unix_seconds <= latest)
        {
            return Err(EmbodiedError::Integrity(format!(
                "activation ledger chain is invalid at line {}",
                line_index + 1
            )));
        }
        latest_observed = Some(record.observed_at_unix_seconds);
        previous = record.record_hash.clone();
        records.push(record);
        if u64::try_from(records.len()).unwrap_or(u64::MAX) > policy.maximum_entries {
            return Err(EmbodiedError::Integrity(
                "activation ledger exceeds its entry limit".to_owned(),
            ));
        }
    }
    Ok((policy, records))
}

fn validate_policy(policy: &ActivationLedgerPolicy) -> Result<(), EmbodiedError> {
    validate_token(&policy.ledger_id, "activation ledger_id")?;
    validate_token(&policy.integration_id, "activation integration_id")?;
    validate_hash(&policy.manifest_hash, "activation manifest_hash")?;
    if policy.schema_version != 1
        || policy.allowed_activator_ids.is_empty()
        || policy.allowed_activator_ids.len() > 10_000
        || policy.maximum_entries == 0
        || policy.maximum_entries > 1_000_000
    {
        return Err(EmbodiedError::Invalid(
            "activation ledger policy is incomplete or outside bounds".to_owned(),
        ));
    }
    for activator_id in &policy.allowed_activator_ids {
        validate_token(activator_id, "allowed activator_id")?;
    }
    Ok(())
}

fn validate_record(record: &ActivationRecord) -> Result<(), EmbodiedError> {
    validate_token(&record.ledger_id, "activation record ledger_id")?;
    validate_token(&record.integration_id, "activation record integration_id")?;
    validate_token(&record.binding_id, "activation record binding_id")?;
    validate_token(&record.activator_id, "activation record activator_id")?;
    for (hash, field) in [
        (&record.manifest_hash, "activation record manifest_hash"),
        (&record.evidence_hash, "activation record evidence_hash"),
        (
            &record.previous_record_hash,
            "activation record previous_record_hash",
        ),
        (&record.record_hash, "activation record_hash"),
    ] {
        validate_hash(hash, field)?;
    }
    if record.schema_version != 1
        || record.observed_at_unix_seconds == 0
        || record.expires_at_unix_seconds <= record.observed_at_unix_seconds
        || record.activated_at_unix_seconds < record.observed_at_unix_seconds
        || record.activated_at_unix_seconds >= record.expires_at_unix_seconds
    {
        return Err(EmbodiedError::Invalid(
            "activation record time or schema is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn record_payload(record: &ActivationRecord) -> RecordPayload<'_> {
    RecordPayload {
        schema_version: record.schema_version,
        sequence: record.sequence,
        ledger_id: &record.ledger_id,
        integration_id: &record.integration_id,
        binding_id: &record.binding_id,
        manifest_hash: &record.manifest_hash,
        evidence_hash: &record.evidence_hash,
        observed_at_unix_seconds: record.observed_at_unix_seconds,
        expires_at_unix_seconds: record.expires_at_unix_seconds,
        activated_at_unix_seconds: record.activated_at_unix_seconds,
        activator_id: &record.activator_id,
        previous_record_hash: &record.previous_record_hash,
    }
}

fn verification(
    policy: &ActivationLedgerPolicy,
    records: &[ActivationRecord],
) -> ActivationLedgerVerification {
    ActivationLedgerVerification {
        ledger_id: policy.ledger_id.clone(),
        integration_id: policy.integration_id.clone(),
        manifest_hash: policy.manifest_hash.clone(),
        entry_count: u64::try_from(records.len()).unwrap_or(u64::MAX),
        chain_head: records
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |record| record.record_hash.clone()),
        latest_observed_at_unix_seconds: records
            .last()
            .map(|record| record.observed_at_unix_seconds),
    }
}

fn validate_root(root: &Path) -> Result<(), EmbodiedError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| EmbodiedError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EmbodiedError::Integrity(
            "activation ledger must be a regular directory".to_owned(),
        ));
    }
    Ok(())
}

struct ActivationLock {
    path: PathBuf,
}

impl ActivationLock {
    fn acquire(root: &Path) -> Result<Self, EmbodiedError> {
        let path = root.join(LOCK_FILE);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| EmbodiedError::Io {
                path: path.display().to_string(),
                message: format!("cannot acquire activation-ledger lock: {error}"),
            })?;
        Ok(Self { path })
    }
}

impl Drop for ActivationLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
