use crate::{read_bounded, sha256_bytes, write_new, DesktopError};
use d2i_limited_autonomy::{
    canonical_json_bytes, hash_without, parse_json_strict, AutonomousCaseTaskBindingV1,
    AutonomousRoleDutyCycleRequestV1, AutonomousRoleDutyCycleResultV1, AutonomyCaseAdmissionV1,
    AutonomyCaseEligibilityV1, AutonomyControlCommandV1, AutonomyDeploymentApprovalV1,
    AutonomyHealthSnapshotV1, AutonomyHealthTripV1, AutonomyReadinessBindingV1,
    AutonomyRoleRuntimeStateV1, AutonomyRolloutCohortV1, HumanExceptionHandoffV1,
    HumanExceptionResponseV1, LimitedAutonomyCertificationV1, LimitedAutonomyCompletionReportV1,
    LimitedAutonomyError, LimitedAutonomyProfileV1, LimitedAutonomyReplayReportV1, ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const STORE_SCHEMA_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const LEDGER_FILE: &str = "ledger.json";
const INDEX_FILE: &str = "index.json";
const OBJECTS_DIRECTORY: &str = "objects";
const LOCK_FILE: &str = "coordinator.lock";
const MAX_STORE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_LEDGER_RECORDS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", content = "artifact", rename_all = "snake_case")]
pub enum AutonomyStoreArtifactV1 {
    Readiness(AutonomyReadinessBindingV1),
    Profile(Box<LimitedAutonomyProfileV1>),
    Deployment(AutonomyDeploymentApprovalV1),
    State(AutonomyRoleRuntimeStateV1),
    Control(AutonomyControlCommandV1),
    Eligibility(AutonomyCaseEligibilityV1),
    Admission(AutonomyCaseAdmissionV1),
    TaskBinding(AutonomousCaseTaskBindingV1),
    Cohort(AutonomyRolloutCohortV1),
    Health(AutonomyHealthSnapshotV1),
    HealthTrip(AutonomyHealthTripV1),
    Handoff(HumanExceptionHandoffV1),
    Response(HumanExceptionResponseV1),
    DutyRequest(AutonomousRoleDutyCycleRequestV1),
    DutyResult(AutonomousRoleDutyCycleResultV1),
    Completion(LimitedAutonomyCompletionReportV1),
    Replay(LimitedAutonomyReplayReportV1),
    Certification(LimitedAutonomyCertificationV1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyStoreRecordKindV1 {
    ReadinessStored,
    ProfileStored,
    DeploymentStored,
    StateStored,
    ControlStored,
    EligibilityStored,
    AdmissionStored,
    TaskBindingStored,
    CohortStored,
    HealthStored,
    HealthTripStored,
    HandoffStored,
    ResponseStored,
    DutyRequestStored,
    DutyResultStored,
    CompletionStored,
    ReplayStored,
    CertificationStored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyStoreRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub record_kind: AutonomyStoreRecordKindV1,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyStoreLedgerV1 {
    schema_version: u32,
    records: Vec<AutonomyStoreRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyStoreIndexV1 {
    schema_version: u32,
    generation: u64,
    ledger_record_count: u64,
    ledger_terminal_sha256: String,
    artifacts_by_id: BTreeMap<String, String>,
    index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomyStoreManifestV1 {
    schema_version: u32,
    organization_id: String,
    role_contract_sha256: String,
    autonomy_profile_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_sha256: String,
    manifest_security_descriptor_sha256: String,
    ledger_security_descriptor_sha256: String,
    index_security_descriptor_sha256: String,
    objects_security_descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyStoreVerificationV1 {
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub autonomy_profile_sha256: String,
    pub ledger_record_count: u64,
    pub ledger_terminal_sha256: String,
    pub index_sha256: String,
    pub object_count: u32,
    pub orphan_object_count: u32,
    pub total_store_bytes: u64,
    pub stale_index: bool,
    pub index_repaired: bool,
    pub rollback_detected: bool,
    pub residual_lock_present: bool,
}

#[derive(Debug)]
pub struct AutonomyStoreV1 {
    root: PathBuf,
    manifest: AutonomyStoreManifestV1,
    verification: AutonomyStoreVerificationV1,
}

pub fn initialize_autonomy_store(
    root: &Path,
    organization_id: String,
    role_contract_sha256: String,
    autonomy_profile_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_ms: u64,
) -> Result<AutonomyStoreV1, DesktopError> {
    validate_id(&organization_id, "autonomy organization")?;
    validate_hash(&role_contract_sha256, "autonomy Role")?;
    validate_hash(&autonomy_profile_sha256, "autonomy profile")?;
    if maximum_store_bytes == 0 || maximum_store_bytes > MAX_STORE_BYTES || created_at_unix_ms == 0
    {
        return Err(DesktopError::Invalid(
            "autonomy store bounds or creation time are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| io_error(root, error))?;
    reject_reparse(root, "autonomy store root")?;
    let objects = root.join(OBJECTS_DIRECTORY);
    std::fs::create_dir(&objects).map_err(|error| io_error(&objects, error))?;
    write_new(
        &root.join(LEDGER_FILE),
        &pretty_json(&AutonomyStoreLedgerV1 {
            schema_version: STORE_SCHEMA_VERSION,
            records: Vec::new(),
        })?,
    )?;
    write_new(&root.join(INDEX_FILE), &pretty_json(&empty_index()?)?)?;
    let placeholder = AutonomyStoreManifestV1 {
        schema_version: STORE_SCHEMA_VERSION,
        organization_id,
        role_contract_sha256,
        autonomy_profile_sha256,
        maximum_store_bytes,
        created_at_unix_ms,
        root_security_descriptor_sha256: ZERO_HASH.to_owned(),
        manifest_security_descriptor_sha256: ZERO_HASH.to_owned(),
        ledger_security_descriptor_sha256: ZERO_HASH.to_owned(),
        index_security_descriptor_sha256: ZERO_HASH.to_owned(),
        objects_security_descriptor_sha256: ZERO_HASH.to_owned(),
    };
    write_new(&root.join(MANIFEST_FILE), &pretty_json(&placeholder)?)?;
    let manifest = AutonomyStoreManifestV1 {
        root_security_descriptor_sha256: harden_and_hash(root)?,
        manifest_security_descriptor_sha256: harden_and_hash(&root.join(MANIFEST_FILE))?,
        ledger_security_descriptor_sha256: harden_and_hash(&root.join(LEDGER_FILE))?,
        index_security_descriptor_sha256: harden_and_hash(&root.join(INDEX_FILE))?,
        objects_security_descriptor_sha256: harden_and_hash(&objects)?,
        ..placeholder
    };
    overwrite_existing(&root.join(MANIFEST_FILE), &pretty_json(&manifest)?)?;
    AutonomyStoreV1::open(root, None)
}

impl AutonomyStoreV1 {
    pub fn open(root: &Path, expected_terminal_sha256: Option<&str>) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let mut verification = verify_autonomy_store(root, expected_terminal_sha256)?;
        if verification.stale_index {
            let _lock = AutonomyStoreLock::acquire(root)?;
            let rebuilt = rebuild_index(root, &load_ledger(root)?)?;
            atomic_replace(root, INDEX_FILE, &pretty_json(&rebuilt)?)?;
            verification = verify_autonomy_store(root, expected_terminal_sha256)?;
            verification.index_repaired = true;
        }
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    pub const fn verification(&self) -> &AutonomyStoreVerificationV1 {
        &self.verification
    }

    pub fn store(
        &mut self,
        artifact: AutonomyStoreArtifactV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        if recorded_at_unix_ms == 0 {
            return Err(DesktopError::Invalid(
                "autonomy store time is zero".to_owned(),
            ));
        }
        let _lock = AutonomyStoreLock::acquire(&self.root)?;
        let current =
            verify_autonomy_store(&self.root, Some(&self.verification.ledger_terminal_sha256))?;
        if current.stale_index {
            return Err(DesktopError::Integrity(
                "autonomy store index changed while open".to_owned(),
            ));
        }
        let metadata = artifact_metadata(&artifact)?;
        let mut ledger = load_ledger(&self.root)?;
        let mut index = load_index(&self.root)?;
        if let Some(existing) = index.artifacts_by_id.get(&metadata.id) {
            if existing == &metadata.hash {
                return Ok(metadata.hash);
            }
            return Err(DesktopError::Integrity(
                "autonomy artifact identity changed immutable content".to_owned(),
            ));
        }
        persist_object(&self.root, &artifact, &metadata.hash)?;
        append_record(
            &mut ledger,
            metadata.kind,
            &metadata.id,
            &metadata.hash,
            recorded_at_unix_ms,
        )?;
        atomic_replace(&self.root, LEDGER_FILE, &pretty_json(&ledger)?)?;
        index
            .artifacts_by_id
            .insert(metadata.id, metadata.hash.clone());
        index.generation = index.generation.saturating_add(1);
        index.ledger_record_count = ledger.records.len() as u64;
        index.ledger_terminal_sha256 = ledger_terminal(&ledger);
        index.index_sha256 = index_hash(&index)?;
        atomic_replace(&self.root, INDEX_FILE, &pretty_json(&index)?)?;
        let mut verification = verify_autonomy_store(&self.root, Some(&ledger_terminal(&ledger)))?;
        if verification.total_store_bytes > self.manifest.maximum_store_bytes {
            return Err(DesktopError::Integrity(
                "autonomy store byte limit exceeded".to_owned(),
            ));
        }
        verification.residual_lock_present = false;
        self.verification = verification;
        Ok(metadata.hash)
    }
}

pub fn verify_autonomy_store(
    root: &Path,
    expected_terminal_sha256: Option<&str>,
) -> Result<AutonomyStoreVerificationV1, DesktopError> {
    reject_reparse(root, "autonomy store root")?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    verify_ledger(&ledger)?;
    let terminal = ledger_terminal(&ledger);
    if expected_terminal_sha256.is_some_and(|expected| expected != terminal) {
        return Err(DesktopError::Integrity(
            "autonomy ledger rollback or unexpected advance detected".to_owned(),
        ));
    }
    let rebuilt = rebuild_index(root, &ledger)?;
    let stale_index = load_index(root).ok().as_ref() != Some(&rebuilt);
    let referenced = ledger
        .records
        .iter()
        .map(|record| record.artifact_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let object_hashes = list_object_hashes(root)?;
    let orphan_count = object_hashes
        .iter()
        .filter(|hash| !referenced.contains(hash.as_str()))
        .count();
    let (object_count, total_store_bytes) = store_size(root)?;
    if total_store_bytes > manifest.maximum_store_bytes {
        return Err(DesktopError::Integrity(
            "autonomy store exceeds its manifest byte bound".to_owned(),
        ));
    }
    Ok(AutonomyStoreVerificationV1 {
        organization_id: manifest.organization_id,
        role_contract_sha256: manifest.role_contract_sha256,
        autonomy_profile_sha256: manifest.autonomy_profile_sha256,
        ledger_record_count: ledger.records.len() as u64,
        ledger_terminal_sha256: terminal,
        index_sha256: rebuilt.index_sha256,
        object_count,
        orphan_object_count: u32::try_from(orphan_count).map_err(|_| {
            DesktopError::Integrity("autonomy orphan object count overflow".to_owned())
        })?,
        total_store_bytes,
        stale_index,
        index_repaired: false,
        rollback_detected: false,
        residual_lock_present: root.join(LOCK_FILE).exists(),
    })
}

pub fn recover_autonomy_store(root: &Path) -> Result<AutonomyStoreVerificationV1, DesktopError> {
    let _lock = AutonomyStoreLock::acquire(root)?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    verify_ledger(&ledger)?;
    let referenced = ledger
        .records
        .iter()
        .map(|record| record.artifact_sha256.clone())
        .collect::<BTreeSet<_>>();
    for hash in list_object_hashes(root)? {
        if !referenced.contains(&hash) {
            std::fs::remove_file(object_path(root, &hash)?)
                .map_err(|error| io_error(root, error))?;
        }
    }
    let rebuilt = rebuild_index(root, &ledger)?;
    atomic_replace(root, INDEX_FILE, &pretty_json(&rebuilt)?)?;
    let mut verification = verify_autonomy_store(root, Some(&ledger_terminal(&ledger)))?;
    verification.index_repaired = true;
    verification.residual_lock_present = false;
    Ok(verification)
}

struct ArtifactMetadata {
    kind: AutonomyStoreRecordKindV1,
    id: String,
    hash: String,
}

fn artifact_metadata(artifact: &AutonomyStoreArtifactV1) -> Result<ArtifactMetadata, DesktopError> {
    macro_rules! metadata {
        ($value:expr, $kind:expr, $id:expr, $hash:expr) => {{
            $value.validate_integrity().map_err(autonomy_error)?;
            ArtifactMetadata {
                kind: $kind,
                id: $id.clone(),
                hash: $hash.clone(),
            }
        }};
    }
    let metadata = match artifact {
        AutonomyStoreArtifactV1::Readiness(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::ReadinessStored,
            value.binding_id,
            value.binding_sha256
        ),
        AutonomyStoreArtifactV1::Profile(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::ProfileStored,
            value.profile_id,
            value.profile_sha256
        ),
        AutonomyStoreArtifactV1::Deployment(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::DeploymentStored,
            value.approval_id,
            value.approval_sha256
        ),
        AutonomyStoreArtifactV1::State(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::StateStored,
            value.state_id,
            value.state_sha256
        ),
        AutonomyStoreArtifactV1::Control(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::ControlStored,
            value.command_id,
            value.command_sha256
        ),
        AutonomyStoreArtifactV1::Eligibility(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::EligibilityStored,
            value.eligibility_id,
            value.eligibility_sha256
        ),
        AutonomyStoreArtifactV1::Admission(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::AdmissionStored,
            value.admission_id,
            value.admission_sha256
        ),
        AutonomyStoreArtifactV1::TaskBinding(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::TaskBindingStored,
            value.autonomy_case_admission_sha256,
            value.binding_sha256
        ),
        AutonomyStoreArtifactV1::Cohort(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::CohortStored,
            value.cohort_id,
            value.cohort_sha256
        ),
        AutonomyStoreArtifactV1::Health(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::HealthStored,
            value.window_id,
            value.snapshot_sha256
        ),
        AutonomyStoreArtifactV1::HealthTrip(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::HealthTripStored,
            value.trip_id,
            value.trip_sha256
        ),
        AutonomyStoreArtifactV1::Handoff(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::HandoffStored,
            value.handoff_id,
            value.handoff_sha256
        ),
        AutonomyStoreArtifactV1::Response(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::ResponseStored,
            value.response_id,
            value.response_sha256
        ),
        AutonomyStoreArtifactV1::DutyRequest(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::DutyRequestStored,
            value.cycle_id,
            value.request_sha256
        ),
        AutonomyStoreArtifactV1::DutyResult(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::DutyResultStored,
            format!("duty-result:{}", value.cycle_id),
            value.result_sha256
        ),
        AutonomyStoreArtifactV1::Completion(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::CompletionStored,
            value.report_id,
            value.report_sha256
        ),
        AutonomyStoreArtifactV1::Replay(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::ReplayStored,
            value.report_id,
            value.report_sha256
        ),
        AutonomyStoreArtifactV1::Certification(value) => metadata!(
            value,
            AutonomyStoreRecordKindV1::CertificationStored,
            value.certification_id,
            value.certification_sha256
        ),
    };
    validate_id(&metadata.id, "autonomy artifact")?;
    validate_hash(&metadata.hash, "autonomy artifact")?;
    Ok(metadata)
}

fn empty_index() -> Result<AutonomyStoreIndexV1, DesktopError> {
    let mut index = AutonomyStoreIndexV1 {
        schema_version: STORE_SCHEMA_VERSION,
        generation: 0,
        ledger_record_count: 0,
        ledger_terminal_sha256: ZERO_HASH.to_owned(),
        artifacts_by_id: BTreeMap::new(),
        index_sha256: ZERO_HASH.to_owned(),
    };
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn rebuild_index(
    root: &Path,
    ledger: &AutonomyStoreLedgerV1,
) -> Result<AutonomyStoreIndexV1, DesktopError> {
    let mut index = empty_index()?;
    for record in &ledger.records {
        let metadata = artifact_metadata(&load_object(root, &record.artifact_sha256)?)?;
        if metadata.kind != record.record_kind
            || metadata.id != record.artifact_id
            || metadata.hash != record.artifact_sha256
            || index
                .artifacts_by_id
                .insert(metadata.id, metadata.hash)
                .is_some()
        {
            return Err(DesktopError::Integrity(
                "autonomy ledger/object/index identity differs".to_owned(),
            ));
        }
    }
    index.generation = ledger.records.len() as u64;
    index.ledger_record_count = ledger.records.len() as u64;
    index.ledger_terminal_sha256 = ledger_terminal(ledger);
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn append_record(
    ledger: &mut AutonomyStoreLedgerV1,
    kind: AutonomyStoreRecordKindV1,
    id: &str,
    hash: &str,
    time: u64,
) -> Result<(), DesktopError> {
    if ledger.records.len() >= MAX_LEDGER_RECORDS
        || ledger
            .records
            .last()
            .is_some_and(|record| time < record.recorded_at_unix_ms)
    {
        return Err(DesktopError::Integrity(
            "autonomy ledger bound or monotonic time violated".to_owned(),
        ));
    }
    let mut record = AutonomyStoreRecordV1 {
        schema_version: STORE_SCHEMA_VERSION,
        sequence: ledger.records.len() as u64 + 1,
        record_kind: kind,
        artifact_id: id.to_owned(),
        artifact_sha256: hash.to_owned(),
        recorded_at_unix_ms: time,
        previous_record_sha256: ledger.records.last().map_or_else(
            || ZERO_HASH.to_owned(),
            |record| record.record_sha256.clone(),
        ),
        record_sha256: ZERO_HASH.to_owned(),
    };
    record.record_sha256 = record_hash(&record)?;
    ledger.records.push(record);
    Ok(())
}

fn verify_ledger(ledger: &AutonomyStoreLedgerV1) -> Result<(), DesktopError> {
    if ledger.schema_version != STORE_SCHEMA_VERSION || ledger.records.len() > MAX_LEDGER_RECORDS {
        return Err(DesktopError::Integrity(
            "autonomy ledger version or bound differs".to_owned(),
        ));
    }
    let mut previous = ZERO_HASH.to_owned();
    let mut prior_time = 0;
    for (index, record) in ledger.records.iter().enumerate() {
        if record.schema_version != STORE_SCHEMA_VERSION
            || record.sequence != index as u64 + 1
            || record.previous_record_sha256 != previous
            || record.recorded_at_unix_ms == 0
            || record.recorded_at_unix_ms < prior_time
            || record.record_sha256 != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "autonomy ledger chain, time, or hash differs".to_owned(),
            ));
        }
        validate_id(&record.artifact_id, "autonomy ledger artifact")?;
        validate_hash(&record.artifact_sha256, "autonomy ledger artifact")?;
        previous.clone_from(&record.record_sha256);
        prior_time = record.recorded_at_unix_ms;
    }
    Ok(())
}

fn record_hash(record: &AutonomyStoreRecordV1) -> Result<String, DesktopError> {
    hash_without(record, &["record_sha256"]).map_err(autonomy_error)
}

fn index_hash(index: &AutonomyStoreIndexV1) -> Result<String, DesktopError> {
    hash_without(index, &["index_sha256"]).map_err(autonomy_error)
}

fn ledger_terminal(ledger: &AutonomyStoreLedgerV1) -> String {
    ledger.records.last().map_or_else(
        || ZERO_HASH.to_owned(),
        |record| record.record_sha256.clone(),
    )
}

fn persist_object(
    root: &Path,
    artifact: &AutonomyStoreArtifactV1,
    hash: &str,
) -> Result<(), DesktopError> {
    let path = object_path(root, hash)?;
    let bytes = pretty_json(artifact)?;
    if path.exists() {
        if read_bounded(&path, MAX_STORE_FILE_BYTES)? == bytes {
            return Ok(());
        }
        return Err(DesktopError::Integrity(
            "autonomy content-addressed object collision".to_owned(),
        ));
    }
    write_new(&path, &bytes)?;
    harden_and_hash(&path)?;
    Ok(())
}

fn load_object(root: &Path, hash: &str) -> Result<AutonomyStoreArtifactV1, DesktopError> {
    parse_json_strict(&read_bounded(
        &object_path(root, hash)?,
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(autonomy_error)
}

fn object_path(root: &Path, hash: &str) -> Result<PathBuf, DesktopError> {
    validate_hash(hash, "autonomy object")?;
    let hex = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| DesktopError::Invalid("autonomy object hash is invalid".to_owned()))?;
    Ok(root.join(OBJECTS_DIRECTORY).join(format!("{hex}.json")))
}

fn list_object_hashes(root: &Path) -> Result<BTreeSet<String>, DesktopError> {
    let mut hashes = BTreeSet::new();
    let objects = root.join(OBJECTS_DIRECTORY);
    for entry in std::fs::read_dir(&objects).map_err(|error| io_error(&objects, error))? {
        let entry = entry.map_err(|error| io_error(&objects, error))?;
        let path = entry.path();
        reject_reparse(&path, "autonomy object")?;
        if !entry
            .file_type()
            .map_err(|error| io_error(&path, error))?
            .is_file()
        {
            return Err(DesktopError::Integrity(
                "autonomy object store contains a non-file".to_owned(),
            ));
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let hex = name.strip_suffix(".json").ok_or_else(|| {
            DesktopError::Integrity("autonomy object file name is invalid".to_owned())
        })?;
        let hash = format!("sha256:{hex}");
        validate_hash(&hash, "autonomy object file")?;
        hashes.insert(hash);
    }
    Ok(hashes)
}

fn load_manifest(root: &Path) -> Result<AutonomyStoreManifestV1, DesktopError> {
    let manifest: AutonomyStoreManifestV1 = parse_json_strict(&read_bounded(
        &root.join(MANIFEST_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(autonomy_error)?;
    if manifest.schema_version != STORE_SCHEMA_VERSION
        || manifest.maximum_store_bytes == 0
        || manifest.maximum_store_bytes > MAX_STORE_BYTES
        || manifest.created_at_unix_ms == 0
    {
        return Err(DesktopError::Integrity(
            "autonomy manifest version or bounds differ".to_owned(),
        ));
    }
    validate_id(&manifest.organization_id, "autonomy organization")?;
    validate_hash(&manifest.role_contract_sha256, "autonomy Role")?;
    validate_hash(&manifest.autonomy_profile_sha256, "autonomy profile")?;
    Ok(manifest)
}

fn load_ledger(root: &Path) -> Result<AutonomyStoreLedgerV1, DesktopError> {
    parse_json_strict(&read_bounded(
        &root.join(LEDGER_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(autonomy_error)
}

fn load_index(root: &Path) -> Result<AutonomyStoreIndexV1, DesktopError> {
    let index: AutonomyStoreIndexV1 =
        parse_json_strict(&read_bounded(&root.join(INDEX_FILE), MAX_STORE_FILE_BYTES)?)
            .map_err(autonomy_error)?;
    if index.schema_version != STORE_SCHEMA_VERSION || index.index_sha256 != index_hash(&index)? {
        return Err(DesktopError::Integrity(
            "autonomy index version or hash differs".to_owned(),
        ));
    }
    Ok(index)
}

fn verify_security(root: &Path, manifest: &AutonomyStoreManifestV1) -> Result<(), DesktopError> {
    for (path, expected) in [
        (
            root.to_path_buf(),
            &manifest.root_security_descriptor_sha256,
        ),
        (
            root.join(MANIFEST_FILE),
            &manifest.manifest_security_descriptor_sha256,
        ),
        (
            root.join(LEDGER_FILE),
            &manifest.ledger_security_descriptor_sha256,
        ),
        (
            root.join(INDEX_FILE),
            &manifest.index_security_descriptor_sha256,
        ),
        (
            root.join(OBJECTS_DIRECTORY),
            &manifest.objects_security_descriptor_sha256,
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("autonomy DACL query failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(
                "autonomy owner or DACL drifted".to_owned(),
            ));
        }
    }
    for hash in list_object_hashes(root)? {
        let path = object_path(root, &hash)?;
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("autonomy object DACL query failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != manifest.objects_security_descriptor_sha256 {
            return Err(DesktopError::Integrity(
                "autonomy object DACL drifted".to_owned(),
            ));
        }
    }
    Ok(())
}

fn harden_and_hash(path: &Path) -> Result<String, DesktopError> {
    let descriptor = d2i_windows_host::harden_path_for_current_user(path)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?;
    Ok(sha256_bytes(&descriptor))
}

fn reject_reparse(path: &Path, label: &str) -> Result<(), DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
    if metadata.file_type().is_symlink()
        || d2i_windows_host::is_reparse_point(path)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(format!(
            "{label} cannot be a symlink or reparse point"
        )));
    }
    Ok(())
}

fn pretty_json<T: Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let canonical = canonical_json_bytes(value).map_err(autonomy_error)?;
    let parsed: serde_json::Value = serde_json::from_slice(&canonical)
        .map_err(|error| DesktopError::Json(error.to_string()))?;
    serde_json::to_vec_pretty(&parsed).map_err(|error| DesktopError::Json(error.to_string()))
}

fn atomic_replace(root: &Path, file: &str, bytes: &[u8]) -> Result<(), DesktopError> {
    let temporary = root.join(format!("{file}.next"));
    write_new(&temporary, bytes)?;
    harden_and_hash(&temporary)?;
    d2i_windows_host::atomic_move(&temporary, &root.join(file), true).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        DesktopError::Io {
            path: root.join(file).display().to_string(),
            message: error.to_string(),
        }
    })
}

fn overwrite_existing(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io_error(path, error))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

fn store_size(root: &Path) -> Result<(u32, u64), DesktopError> {
    fn walk(path: &Path, count: &mut u32, bytes: &mut u64) -> Result<(), DesktopError> {
        for entry in std::fs::read_dir(path).map_err(|error| io_error(path, error))? {
            let entry = entry.map_err(|error| io_error(path, error))?;
            let child = entry.path();
            reject_reparse(&child, "autonomy store entry")?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == LOCK_FILE || name.ends_with(".next") {
                continue;
            }
            let metadata = entry.metadata().map_err(|error| io_error(&child, error))?;
            if metadata.is_dir() {
                walk(&child, count, bytes)?;
            } else if metadata.is_file() {
                *count = count.saturating_add(1);
                *bytes = bytes.saturating_add(metadata.len());
            } else {
                return Err(DesktopError::Integrity(
                    "autonomy store contains a non-regular entry".to_owned(),
                ));
            }
        }
        Ok(())
    }
    let mut count = 0;
    let mut bytes = 0;
    walk(root, &mut count, &mut bytes)?;
    Ok((count, bytes))
}

fn validate_hash(value: &str, label: &str) -> Result<(), DesktopError> {
    d2i_limited_autonomy::validate_hash(value, label).map_err(autonomy_error)
}

fn validate_id(value: &str, label: &str) -> Result<(), DesktopError> {
    d2i_limited_autonomy::validate_id(value, label).map_err(autonomy_error)
}

fn autonomy_error(error: LimitedAutonomyError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn io_error(path: &Path, error: std::io::Error) -> DesktopError {
    DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

struct AutonomyStoreLock {
    path: PathBuf,
}

impl AutonomyStoreLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("autonomy single-writer lock failed: {error}"),
            })?;
        harden_and_hash(&path)?;
        Ok(Self { path })
    }
}

impl Drop for AutonomyStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
