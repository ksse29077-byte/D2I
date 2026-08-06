use crate::{read_bounded, sha256_bytes, write_new, DesktopError};
use d2i_role_operations::{
    canonical_json_bytes, hash_without, parse_json_strict, verify_escalation_acknowledgement,
    verify_escalation_resolution, CaseSlaRuntimeStateV1, EscalationAcknowledgementV1,
    EscalationResolutionV1, ReportPublicationEnvelopeV1, ReportPublicationReceiptV1,
    RoleEscalationItemV1, RoleOperationsReportV1, RoleOperationsSnapshotV1, SlaBreachRecordV1,
    MAX_LEDGER_RECORDS, MAX_STORE_BYTES, ZERO_HASH,
};
use ed25519_dalek::VerifyingKey;
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

/// Closed set of immutable WORK-700 artifacts accepted by the Desktop store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", content = "artifact", rename_all = "snake_case")]
pub enum RoleOperationsArtifactV1 {
    SlaState(CaseSlaRuntimeStateV1),
    SlaBreach(SlaBreachRecordV1),
    Snapshot(RoleOperationsSnapshotV1),
    Report(RoleOperationsReportV1),
    Publication(ReportPublicationEnvelopeV1),
    PublicationReceipt(ReportPublicationReceiptV1),
    Escalation(RoleEscalationItemV1),
    Acknowledgement(EscalationAcknowledgementV1),
    Resolution(EscalationResolutionV1),
}

/// Append-only store event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleOperationsStoreRecordKindV1 {
    SlaStateStored,
    SlaBreachStored,
    SnapshotStored,
    ReportStored,
    PublicationStored,
    PublicationReceiptStored,
    EscalationStored,
    AcknowledgementStored,
    ResolutionStored,
}

/// One hash-chained durable store event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsStoreRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub record_kind: RoleOperationsStoreRecordKindV1,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub recorded_at_unix_seconds: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleOperationsStoreLedgerV1 {
    schema_version: u32,
    records: Vec<RoleOperationsStoreRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleOperationsStoreIndexV1 {
    schema_version: u32,
    generation: u64,
    ledger_record_count: u64,
    ledger_terminal_sha256: String,
    sla_states_by_case: BTreeMap<String, String>,
    breaches_by_key: BTreeMap<String, String>,
    snapshots_by_id: BTreeMap<String, String>,
    reports_by_id: BTreeMap<String, String>,
    publications_by_report: BTreeMap<String, String>,
    receipts_by_publication: BTreeMap<String, String>,
    escalations_by_trigger: BTreeMap<String, String>,
    acknowledgements_by_item: BTreeMap<String, String>,
    resolutions_by_item: BTreeMap<String, String>,
    index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleOperationsStoreManifestV1 {
    schema_version: u32,
    organization_id: String,
    role_contract_sha256: String,
    operations_profile_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_seconds: u64,
    root_security_descriptor_sha256: String,
    manifest_security_descriptor_sha256: String,
    ledger_security_descriptor_sha256: String,
    index_security_descriptor_sha256: String,
    objects_security_descriptor_sha256: String,
}

/// Verified store state after chain, object, index, DACL, and rollback checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleOperationsStoreVerificationV1 {
    pub organization_id: String,
    pub role_contract_sha256: String,
    pub operations_profile_sha256: String,
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

/// Single-process facade over the protected Role Operations store.
#[derive(Debug)]
pub struct RoleOperationsStoreV1 {
    root: PathBuf,
    manifest: RoleOperationsStoreManifestV1,
    verification: RoleOperationsStoreVerificationV1,
}

/// Creates a new current-user protected operations store.
pub fn initialize_role_operations_store(
    root: &Path,
    organization_id: String,
    role_contract_sha256: String,
    operations_profile_sha256: String,
    maximum_store_bytes: u64,
    created_at_unix_seconds: u64,
) -> Result<RoleOperationsStoreV1, DesktopError> {
    validate_id(&organization_id, "organization")?;
    validate_hash(&role_contract_sha256, "Role Contract")?;
    validate_hash(&operations_profile_sha256, "operations profile")?;
    if maximum_store_bytes == 0
        || maximum_store_bytes > MAX_STORE_BYTES
        || created_at_unix_seconds == 0
    {
        return Err(DesktopError::Invalid(
            "operations store bounds or creation time are invalid".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| io_error(root, error))?;
    reject_reparse(root, "operations store root")?;
    let objects = root.join(OBJECTS_DIRECTORY);
    std::fs::create_dir(&objects).map_err(|error| io_error(&objects, error))?;
    write_new(
        &root.join(LEDGER_FILE),
        &pretty_json(&RoleOperationsStoreLedgerV1 {
            schema_version: STORE_SCHEMA_VERSION,
            records: Vec::new(),
        })?,
    )?;
    let index = empty_index()?;
    write_new(&root.join(INDEX_FILE), &pretty_json(&index)?)?;
    let placeholder = RoleOperationsStoreManifestV1 {
        schema_version: STORE_SCHEMA_VERSION,
        organization_id,
        role_contract_sha256,
        operations_profile_sha256,
        maximum_store_bytes,
        created_at_unix_seconds,
        root_security_descriptor_sha256: ZERO_HASH.to_owned(),
        manifest_security_descriptor_sha256: ZERO_HASH.to_owned(),
        ledger_security_descriptor_sha256: ZERO_HASH.to_owned(),
        index_security_descriptor_sha256: ZERO_HASH.to_owned(),
        objects_security_descriptor_sha256: ZERO_HASH.to_owned(),
    };
    write_new(&root.join(MANIFEST_FILE), &pretty_json(&placeholder)?)?;
    let manifest = RoleOperationsStoreManifestV1 {
        root_security_descriptor_sha256: harden_and_hash(root)?,
        manifest_security_descriptor_sha256: harden_and_hash(&root.join(MANIFEST_FILE))?,
        ledger_security_descriptor_sha256: harden_and_hash(&root.join(LEDGER_FILE))?,
        index_security_descriptor_sha256: harden_and_hash(&root.join(INDEX_FILE))?,
        objects_security_descriptor_sha256: harden_and_hash(&objects)?,
        ..placeholder
    };
    overwrite_existing(&root.join(MANIFEST_FILE), &pretty_json(&manifest)?)?;
    RoleOperationsStoreV1::open(root, None)
}

impl RoleOperationsStoreV1 {
    /// Opens, verifies, and deterministically repairs only a stale derived index.
    pub fn open(root: &Path, expected_terminal_sha256: Option<&str>) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let mut verification = verify_role_operations_store(root, expected_terminal_sha256)?;
        if verification.stale_index {
            let _lock = OperationsStoreLock::acquire(root)?;
            let ledger = load_ledger(root)?;
            let rebuilt = rebuild_index(root, &ledger)?;
            atomic_replace(root, INDEX_FILE, &pretty_json(&rebuilt)?)?;
            verification = verify_role_operations_store(root, expected_terminal_sha256)?;
            verification.index_repaired = true;
        }
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
        })
    }

    /// Returns the most recent complete verification result.
    pub const fn verification(&self) -> &RoleOperationsStoreVerificationV1 {
        &self.verification
    }

    /// Stores one immutable artifact exactly once and returns its semantic hash.
    pub fn store(
        &mut self,
        artifact: RoleOperationsArtifactV1,
        recorded_at_unix_seconds: u64,
    ) -> Result<String, DesktopError> {
        if matches!(
            artifact,
            RoleOperationsArtifactV1::Acknowledgement(_) | RoleOperationsArtifactV1::Resolution(_)
        ) {
            return Err(DesktopError::AccessDenied(
                "signed escalation records require the verified store entry points".to_owned(),
            ));
        }
        self.store_verified(artifact, recorded_at_unix_seconds)
    }

    /// Verifies and stores a signed acknowledgement without granting execution authority.
    pub fn store_acknowledgement(
        &mut self,
        acknowledgement: EscalationAcknowledgementV1,
        item: &RoleEscalationItemV1,
        expected_signer_key_id: &str,
        verifying_key: &VerifyingKey,
        recorded_at_unix_seconds: u64,
    ) -> Result<String, DesktopError> {
        verify_escalation_acknowledgement(
            &acknowledgement,
            item,
            expected_signer_key_id,
            verifying_key,
        )
        .map_err(operations_error)?;
        self.store_verified(
            RoleOperationsArtifactV1::Acknowledgement(acknowledgement),
            recorded_at_unix_seconds,
        )
    }

    /// Verifies and stores a signed resolution chained to its acknowledgement.
    pub fn store_resolution(
        &mut self,
        resolution: EscalationResolutionV1,
        item: &RoleEscalationItemV1,
        acknowledgement: &EscalationAcknowledgementV1,
        expected_signer_key_id: &str,
        verifying_key: &VerifyingKey,
        recorded_at_unix_seconds: u64,
    ) -> Result<String, DesktopError> {
        verify_escalation_resolution(
            &resolution,
            item,
            acknowledgement,
            expected_signer_key_id,
            verifying_key,
        )
        .map_err(operations_error)?;
        self.store_verified(
            RoleOperationsArtifactV1::Resolution(resolution),
            recorded_at_unix_seconds,
        )
    }

    fn store_verified(
        &mut self,
        artifact: RoleOperationsArtifactV1,
        recorded_at_unix_seconds: u64,
    ) -> Result<String, DesktopError> {
        if recorded_at_unix_seconds == 0 {
            return Err(DesktopError::Invalid(
                "operations store time is zero".to_owned(),
            ));
        }
        let _lock = OperationsStoreLock::acquire(&self.root)?;
        let current = verify_role_operations_store(
            &self.root,
            Some(&self.verification.ledger_terminal_sha256),
        )?;
        if current.stale_index {
            return Err(DesktopError::Integrity(
                "operations index became stale while store was open".to_owned(),
            ));
        }
        let mut ledger = load_ledger(&self.root)?;
        let mut index = load_index(&self.root)?;
        let metadata = artifact_metadata(&artifact)?;
        if let Some(existing) = index_value(&index, &metadata) {
            if existing == &metadata.hash {
                return Ok(metadata.hash);
            }
            if metadata.kind != RoleOperationsStoreRecordKindV1::SlaStateStored
                || metadata.predecessor_sha256.as_ref() != Some(existing)
            {
                return Err(DesktopError::Integrity(
                    "operations artifact identity changed immutable content".to_owned(),
                ));
            }
        }
        persist_object(&self.root, &artifact, &metadata.hash)?;
        append_record(
            &mut ledger,
            metadata.kind,
            &metadata.id,
            &metadata.hash,
            recorded_at_unix_seconds,
        )?;
        if ledger.records.len() > MAX_LEDGER_RECORDS {
            return Err(DesktopError::Integrity(
                "operations ledger record limit exceeded".to_owned(),
            ));
        }
        atomic_replace(&self.root, LEDGER_FILE, &pretty_json(&ledger)?)?;
        apply_index(&mut index, &metadata)?;
        index.generation = index.generation.saturating_add(1);
        index.ledger_record_count = ledger.records.len() as u64;
        index.ledger_terminal_sha256 = ledger_terminal(&ledger);
        index.index_sha256 = index_hash(&index)?;
        atomic_replace(&self.root, INDEX_FILE, &pretty_json(&index)?)?;
        let mut verification =
            verify_role_operations_store(&self.root, Some(&ledger_terminal(&ledger)))?;
        if verification.total_store_bytes > self.manifest.maximum_store_bytes {
            return Err(DesktopError::Integrity(
                "operations store byte limit exceeded".to_owned(),
            ));
        }
        // This method owns the coordinator lock, and `Drop` removes it on return.
        verification.residual_lock_present = false;
        self.verification = verification;
        Ok(metadata.hash)
    }
}

/// Verifies protected storage, chain, objects, derived index, and rollback pin.
pub fn verify_role_operations_store(
    root: &Path,
    expected_terminal_sha256: Option<&str>,
) -> Result<RoleOperationsStoreVerificationV1, DesktopError> {
    reject_reparse(root, "operations store root")?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    verify_ledger(&ledger)?;
    let terminal = ledger_terminal(&ledger);
    if expected_terminal_sha256.is_some_and(|expected| expected != terminal) {
        return Err(DesktopError::Integrity(
            "operations ledger rollback or unexpected advance detected".to_owned(),
        ));
    }
    let rebuilt = rebuild_index(root, &ledger)?;
    let loaded_index = load_index(root).ok();
    let stale_index = loaded_index.as_ref() != Some(&rebuilt);
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
            "operations store exceeds its manifest byte bound".to_owned(),
        ));
    }
    Ok(RoleOperationsStoreVerificationV1 {
        organization_id: manifest.organization_id,
        role_contract_sha256: manifest.role_contract_sha256,
        operations_profile_sha256: manifest.operations_profile_sha256,
        ledger_record_count: ledger.records.len() as u64,
        ledger_terminal_sha256: terminal,
        index_sha256: rebuilt.index_sha256,
        object_count,
        orphan_object_count: u32::try_from(orphan_count).map_err(|_| {
            DesktopError::Integrity("operations orphan object count overflow".to_owned())
        })?,
        total_store_bytes,
        stale_index,
        index_repaired: false,
        rollback_detected: false,
        residual_lock_present: root.join(LOCK_FILE).exists(),
    })
}

struct ArtifactMetadata {
    kind: RoleOperationsStoreRecordKindV1,
    id: String,
    key: String,
    hash: String,
    predecessor_sha256: Option<String>,
}

fn artifact_metadata(
    artifact: &RoleOperationsArtifactV1,
) -> Result<ArtifactMetadata, DesktopError> {
    let metadata = match artifact {
        RoleOperationsArtifactV1::SlaState(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::SlaStateStored,
                id: value.sla_state_id.clone(),
                key: value.case_id.clone(),
                hash: value.state_sha256.clone(),
                predecessor_sha256: value.previous_state_sha256.clone(),
            }
        }
        RoleOperationsArtifactV1::SlaBreach(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::SlaBreachStored,
                id: value.breach_id.clone(),
                key: format!(
                    "{}:{}:{:?}",
                    value.case_id, value.sla_binding_sha256, value.milestone
                )
                .to_ascii_lowercase(),
                hash: value.breach_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::Snapshot(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::SnapshotStored,
                id: value.snapshot_id.clone(),
                key: value.snapshot_id.clone(),
                hash: value.snapshot_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::Report(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::ReportStored,
                id: value.report_id.clone(),
                key: value.report_id.clone(),
                hash: value.report_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::Publication(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::PublicationStored,
                id: value.publication_id.clone(),
                key: value.report_sha256.clone(),
                hash: value.publication_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::PublicationReceipt(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::PublicationReceiptStored,
                id: format!("receipt:{}", value.publication_sha256),
                key: value.publication_sha256.clone(),
                hash: value.receipt_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::Escalation(value) => {
            value.validate().map_err(operations_error)?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::EscalationStored,
                id: value.escalation_item_id.clone(),
                key: value.source_trigger_sha256.clone(),
                hash: value.item_sha256.clone(),
                predecessor_sha256: value.previous_escalation_sha256.clone(),
            }
        }
        RoleOperationsArtifactV1::Acknowledgement(value) => {
            verify_signed_hash(
                value,
                &value.acknowledgement_sha256,
                &["acknowledgement_sha256", "signature_hex"],
            )?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::AcknowledgementStored,
                id: value.acknowledgement_id.clone(),
                key: value.escalation_item_sha256.clone(),
                hash: value.acknowledgement_sha256.clone(),
                predecessor_sha256: None,
            }
        }
        RoleOperationsArtifactV1::Resolution(value) => {
            verify_signed_hash(
                value,
                &value.resolution_sha256,
                &["resolution_sha256", "signature_hex"],
            )?;
            ArtifactMetadata {
                kind: RoleOperationsStoreRecordKindV1::ResolutionStored,
                id: value.resolution_id.clone(),
                key: value.escalation_item_sha256.clone(),
                hash: value.resolution_sha256.clone(),
                predecessor_sha256: None,
            }
        }
    };
    validate_id(&metadata.id, "operations artifact")?;
    validate_hash(&metadata.hash, "operations artifact")?;
    Ok(metadata)
}

fn verify_signed_hash<T: Serialize>(
    value: &T,
    declared: &str,
    omissions: &[&str],
) -> Result<(), DesktopError> {
    validate_hash(declared, "signed operations artifact")?;
    if hash_without(value, omissions).map_err(operations_error)? != declared {
        return Err(DesktopError::Integrity(
            "signed operations artifact hash differs".to_owned(),
        ));
    }
    Ok(())
}

fn index_value<'a>(
    index: &'a RoleOperationsStoreIndexV1,
    metadata: &ArtifactMetadata,
) -> Option<&'a String> {
    match metadata.kind {
        RoleOperationsStoreRecordKindV1::SlaStateStored => {
            index.sla_states_by_case.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::SlaBreachStored => {
            index.breaches_by_key.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::SnapshotStored => index.snapshots_by_id.get(&metadata.key),
        RoleOperationsStoreRecordKindV1::ReportStored => index.reports_by_id.get(&metadata.key),
        RoleOperationsStoreRecordKindV1::PublicationStored => {
            index.publications_by_report.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::PublicationReceiptStored => {
            index.receipts_by_publication.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::EscalationStored => {
            index.escalations_by_trigger.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::AcknowledgementStored => {
            index.acknowledgements_by_item.get(&metadata.key)
        }
        RoleOperationsStoreRecordKindV1::ResolutionStored => {
            index.resolutions_by_item.get(&metadata.key)
        }
    }
}

fn apply_index(
    index: &mut RoleOperationsStoreIndexV1,
    metadata: &ArtifactMetadata,
) -> Result<(), DesktopError> {
    let map = match metadata.kind {
        RoleOperationsStoreRecordKindV1::SlaStateStored => &mut index.sla_states_by_case,
        RoleOperationsStoreRecordKindV1::SlaBreachStored => &mut index.breaches_by_key,
        RoleOperationsStoreRecordKindV1::SnapshotStored => &mut index.snapshots_by_id,
        RoleOperationsStoreRecordKindV1::ReportStored => &mut index.reports_by_id,
        RoleOperationsStoreRecordKindV1::PublicationStored => &mut index.publications_by_report,
        RoleOperationsStoreRecordKindV1::PublicationReceiptStored => {
            &mut index.receipts_by_publication
        }
        RoleOperationsStoreRecordKindV1::EscalationStored => &mut index.escalations_by_trigger,
        RoleOperationsStoreRecordKindV1::AcknowledgementStored => {
            &mut index.acknowledgements_by_item
        }
        RoleOperationsStoreRecordKindV1::ResolutionStored => &mut index.resolutions_by_item,
    };
    if let Some(existing) = map.get(&metadata.key) {
        if existing == &metadata.hash {
            return Ok(());
        }
        if metadata.kind != RoleOperationsStoreRecordKindV1::SlaStateStored
            || metadata.predecessor_sha256.as_ref() != Some(existing)
        {
            return Err(DesktopError::Integrity(
                "operations index identity collision".to_owned(),
            ));
        }
    }
    map.insert(metadata.key.clone(), metadata.hash.clone());
    Ok(())
}

fn empty_index() -> Result<RoleOperationsStoreIndexV1, DesktopError> {
    let mut index = RoleOperationsStoreIndexV1 {
        schema_version: STORE_SCHEMA_VERSION,
        generation: 0,
        ledger_record_count: 0,
        ledger_terminal_sha256: ZERO_HASH.to_owned(),
        sla_states_by_case: BTreeMap::new(),
        breaches_by_key: BTreeMap::new(),
        snapshots_by_id: BTreeMap::new(),
        reports_by_id: BTreeMap::new(),
        publications_by_report: BTreeMap::new(),
        receipts_by_publication: BTreeMap::new(),
        escalations_by_trigger: BTreeMap::new(),
        acknowledgements_by_item: BTreeMap::new(),
        resolutions_by_item: BTreeMap::new(),
        index_sha256: ZERO_HASH.to_owned(),
    };
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn rebuild_index(
    root: &Path,
    ledger: &RoleOperationsStoreLedgerV1,
) -> Result<RoleOperationsStoreIndexV1, DesktopError> {
    let mut index = empty_index()?;
    for record in &ledger.records {
        let artifact = load_object(root, &record.artifact_sha256)?;
        let metadata = artifact_metadata(&artifact)?;
        if metadata.kind != record.record_kind
            || metadata.id != record.artifact_id
            || metadata.hash != record.artifact_sha256
        {
            return Err(DesktopError::Integrity(
                "operations ledger/object/index identity differs".to_owned(),
            ));
        }
        apply_index(&mut index, &metadata)?;
    }
    index.generation = ledger.records.len() as u64;
    index.ledger_record_count = ledger.records.len() as u64;
    index.ledger_terminal_sha256 = ledger_terminal(ledger);
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn append_record(
    ledger: &mut RoleOperationsStoreLedgerV1,
    kind: RoleOperationsStoreRecordKindV1,
    id: &str,
    hash: &str,
    time: u64,
) -> Result<(), DesktopError> {
    if ledger
        .records
        .last()
        .is_some_and(|record| time < record.recorded_at_unix_seconds)
    {
        return Err(DesktopError::Integrity(
            "operations ledger time moved backward".to_owned(),
        ));
    }
    let mut record = RoleOperationsStoreRecordV1 {
        schema_version: STORE_SCHEMA_VERSION,
        sequence: ledger.records.len() as u64 + 1,
        record_kind: kind,
        artifact_id: id.to_owned(),
        artifact_sha256: hash.to_owned(),
        recorded_at_unix_seconds: time,
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

fn verify_ledger(ledger: &RoleOperationsStoreLedgerV1) -> Result<(), DesktopError> {
    if ledger.schema_version != STORE_SCHEMA_VERSION || ledger.records.len() > MAX_LEDGER_RECORDS {
        return Err(DesktopError::Integrity(
            "operations ledger version or bounds differ".to_owned(),
        ));
    }
    let mut previous = ZERO_HASH.to_owned();
    let mut prior_time = 0;
    for (index, record) in ledger.records.iter().enumerate() {
        if record.schema_version != STORE_SCHEMA_VERSION
            || record.sequence != index as u64 + 1
            || record.previous_record_sha256 != previous
            || record.recorded_at_unix_seconds == 0
            || record.recorded_at_unix_seconds < prior_time
            || record.record_sha256 != record_hash(record)?
        {
            return Err(DesktopError::Integrity(
                "operations ledger chain, time, or record hash differs".to_owned(),
            ));
        }
        validate_id(&record.artifact_id, "operations ledger artifact")?;
        validate_hash(&record.artifact_sha256, "operations ledger artifact")?;
        previous.clone_from(&record.record_sha256);
        prior_time = record.recorded_at_unix_seconds;
    }
    Ok(())
}

fn record_hash(record: &RoleOperationsStoreRecordV1) -> Result<String, DesktopError> {
    hash_without(record, &["record_sha256"]).map_err(operations_error)
}

fn index_hash(index: &RoleOperationsStoreIndexV1) -> Result<String, DesktopError> {
    hash_without(index, &["index_sha256"]).map_err(operations_error)
}

fn ledger_terminal(ledger: &RoleOperationsStoreLedgerV1) -> String {
    ledger.records.last().map_or_else(
        || ZERO_HASH.to_owned(),
        |record| record.record_sha256.clone(),
    )
}

fn persist_object(
    root: &Path,
    artifact: &RoleOperationsArtifactV1,
    hash: &str,
) -> Result<(), DesktopError> {
    let path = object_path(root, hash)?;
    let bytes = pretty_json(artifact)?;
    if path.exists() {
        if read_bounded(&path, MAX_STORE_FILE_BYTES)? == bytes {
            return Ok(());
        }
        return Err(DesktopError::Integrity(
            "operations content-addressed object collision".to_owned(),
        ));
    }
    write_new(&path, &bytes)?;
    harden_and_hash(&path)?;
    Ok(())
}

fn load_object(root: &Path, hash: &str) -> Result<RoleOperationsArtifactV1, DesktopError> {
    parse_json_strict(&read_bounded(
        &object_path(root, hash)?,
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(operations_error)
}

fn object_path(root: &Path, hash: &str) -> Result<PathBuf, DesktopError> {
    validate_hash(hash, "operations object")?;
    let hex = hash
        .strip_prefix("sha256:")
        .ok_or_else(|| DesktopError::Invalid("operations object hash is invalid".to_owned()))?;
    Ok(root.join(OBJECTS_DIRECTORY).join(format!("{hex}.json")))
}

fn list_object_hashes(root: &Path) -> Result<BTreeSet<String>, DesktopError> {
    let mut hashes = BTreeSet::new();
    for entry in
        std::fs::read_dir(root.join(OBJECTS_DIRECTORY)).map_err(|error| io_error(root, error))?
    {
        let entry = entry.map_err(|error| io_error(root, error))?;
        let path = entry.path();
        reject_reparse(&path, "operations object")?;
        if !entry
            .file_type()
            .map_err(|error| io_error(&path, error))?
            .is_file()
        {
            return Err(DesktopError::Integrity(
                "operations object store contains a non-file".to_owned(),
            ));
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let hex = name.strip_suffix(".json").ok_or_else(|| {
            DesktopError::Integrity("operations object file name is invalid".to_owned())
        })?;
        let hash = format!("sha256:{hex}");
        validate_hash(&hash, "operations object file")?;
        hashes.insert(hash);
    }
    Ok(hashes)
}

fn load_manifest(root: &Path) -> Result<RoleOperationsStoreManifestV1, DesktopError> {
    let manifest: RoleOperationsStoreManifestV1 = parse_json_strict(&read_bounded(
        &root.join(MANIFEST_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(operations_error)?;
    if manifest.schema_version != STORE_SCHEMA_VERSION
        || manifest.maximum_store_bytes == 0
        || manifest.maximum_store_bytes > MAX_STORE_BYTES
        || manifest.created_at_unix_seconds == 0
    {
        return Err(DesktopError::Integrity(
            "operations manifest version or bounds differ".to_owned(),
        ));
    }
    validate_id(&manifest.organization_id, "operations organization")?;
    validate_hash(&manifest.role_contract_sha256, "operations Role")?;
    validate_hash(&manifest.operations_profile_sha256, "operations profile")?;
    Ok(manifest)
}

fn load_ledger(root: &Path) -> Result<RoleOperationsStoreLedgerV1, DesktopError> {
    parse_json_strict(&read_bounded(
        &root.join(LEDGER_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(operations_error)
}

fn load_index(root: &Path) -> Result<RoleOperationsStoreIndexV1, DesktopError> {
    let index: RoleOperationsStoreIndexV1 =
        parse_json_strict(&read_bounded(&root.join(INDEX_FILE), MAX_STORE_FILE_BYTES)?)
            .map_err(operations_error)?;
    if index.schema_version != STORE_SCHEMA_VERSION || index.index_sha256 != index_hash(&index)? {
        return Err(DesktopError::Integrity(
            "operations index version or hash differs".to_owned(),
        ));
    }
    Ok(index)
}

fn verify_security(
    root: &Path,
    manifest: &RoleOperationsStoreManifestV1,
) -> Result<(), DesktopError> {
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
            DesktopError::Integrity(format!("operations DACL query failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(
                "operations owner or DACL drifted".to_owned(),
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
    let canonical = canonical_json_bytes(value).map_err(operations_error)?;
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
            reject_reparse(&child, "operations store entry")?;
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
                    "operations store contains a non-regular entry".to_owned(),
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
    let valid = value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(DesktopError::Invalid(format!(
            "{label} is not lowercase SHA-256"
        )))
    }
}

fn validate_id(value: &str, label: &str) -> Result<(), DesktopError> {
    if value.is_empty()
        || value.len() > 512
        || value.contains('*')
        || value.contains('@')
        || value.contains("..")
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        Err(DesktopError::Invalid(format!("{label} ID is invalid")))
    } else {
        Ok(())
    }
}

fn operations_error(error: d2i_role_operations::RoleOperationsError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn io_error(path: &Path, error: std::io::Error) -> DesktopError {
    DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

struct OperationsStoreLock {
    path: PathBuf,
}

impl OperationsStoreLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("operations single-writer lock failed: {error}"),
            })?;
        harden_and_hash(&path)?;
        Ok(Self { path })
    }
}

impl Drop for OperationsStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
