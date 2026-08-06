use crate::{read_bounded, sha256_bytes, write_new, DesktopError};
use d2i_case_learning::{validate_candidate, LearningCandidateV1};
use d2i_episodic_memory::{
    canonical_json_bytes, hash_without, parse_json_strict, ApprovedEpisodeSummaryV1, CaseEpisodeV1,
    EpisodeIndexEntryV1, EpisodeMemoryNamespaceV1, EpisodeRetentionStatusV1, EpisodeTombstoneV1,
    EpisodicMemoryError, ZERO_HASH,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "manifest.json";
const LEDGER_FILE: &str = "ledger.json";
const INDEX_FILE: &str = "index.json";
const OBJECTS_DIRECTORY: &str = "objects";
const TOMBSTONES_DIRECTORY: &str = "tombstones";
const LOCK_FILE: &str = ".episodic-memory.lock";
const MAX_STORE_FILE_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStoreRecordKindV1 {
    EpisodeStored,
    SummaryPublished,
    CandidateQuarantined,
    TombstoneRecorded,
    IndexRepaired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryStoreLedgerRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub record_kind: MemoryStoreRecordKindV1,
    pub namespace_sha256: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryStoreLedgerV1 {
    schema_version: u32,
    records: Vec<MemoryStoreLedgerRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryStoreIndexV1 {
    schema_version: u32,
    generation: u64,
    ledger_record_count: u64,
    ledger_terminal_sha256: String,
    episodes: Vec<EpisodeIndexEntryV1>,
    summaries_by_episode: BTreeMap<String, String>,
    candidate_hashes: Vec<String>,
    tombstoned_episode_hashes: Vec<String>,
    index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryStoreManifestV1 {
    schema_version: u32,
    organization_id: String,
    namespace_id: String,
    namespace_sha256: String,
    namespace: EpisodeMemoryNamespaceV1,
    maximum_objects: u32,
    maximum_store_bytes: u64,
    created_at_unix_ms: u64,
    root_security_descriptor_sha256: String,
    manifest_security_descriptor_sha256: String,
    ledger_security_descriptor_sha256: String,
    index_security_descriptor_sha256: String,
    objects_security_descriptor_sha256: String,
    tombstones_security_descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodicMemoryStoreVerificationV1 {
    pub organization_id: String,
    pub namespace_id: String,
    pub namespace_sha256: String,
    pub ledger_record_count: u64,
    pub ledger_terminal_sha256: String,
    pub index_sha256: String,
    pub episode_count: u32,
    pub summary_count: u32,
    pub candidate_count: u32,
    pub tombstone_count: u32,
    pub object_count: u32,
    pub total_store_bytes: u64,
    pub stale_index: bool,
    pub rollback_detected: bool,
}

#[derive(Debug)]
pub struct EpisodicMemoryStoreV1 {
    root: PathBuf,
    manifest: MemoryStoreManifestV1,
    verification: EpisodicMemoryStoreVerificationV1,
    poisoned: bool,
}

pub fn initialize_episodic_memory_store(
    root: &Path,
    namespace: EpisodeMemoryNamespaceV1,
    created_at_unix_ms: u64,
) -> Result<EpisodicMemoryStoreV1, DesktopError> {
    namespace.validate().map_err(memory_error)?;
    if created_at_unix_ms == 0 {
        return Err(DesktopError::Invalid(
            "memory store creation time is zero".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| io_error(root, error))?;
    reject_reparse(root, "memory store root")?;
    let objects = root.join(OBJECTS_DIRECTORY);
    let tombstones = root.join(TOMBSTONES_DIRECTORY);
    std::fs::create_dir(&objects).map_err(|error| io_error(&objects, error))?;
    std::fs::create_dir(&tombstones).map_err(|error| io_error(&tombstones, error))?;
    write_new(
        &root.join(LEDGER_FILE),
        &pretty_json(&MemoryStoreLedgerV1 {
            schema_version: 1,
            records: Vec::new(),
        })?,
    )?;
    let mut index = MemoryStoreIndexV1 {
        schema_version: 1,
        generation: 0,
        ledger_record_count: 0,
        ledger_terminal_sha256: ZERO_HASH.to_owned(),
        episodes: Vec::new(),
        summaries_by_episode: BTreeMap::new(),
        candidate_hashes: Vec::new(),
        tombstoned_episode_hashes: Vec::new(),
        index_sha256: ZERO_HASH.to_owned(),
    };
    index.index_sha256 = index_hash(&index)?;
    write_new(&root.join(INDEX_FILE), &pretty_json(&index)?)?;
    let placeholder = MemoryStoreManifestV1 {
        schema_version: 1,
        organization_id: namespace.organization_id.clone(),
        namespace_id: namespace.namespace_id.clone(),
        namespace_sha256: namespace.namespace_sha256.clone(),
        maximum_objects: namespace.maximum_episodes.saturating_mul(4),
        maximum_store_bytes: namespace.maximum_store_bytes,
        namespace,
        created_at_unix_ms,
        root_security_descriptor_sha256: ZERO_HASH.to_owned(),
        manifest_security_descriptor_sha256: ZERO_HASH.to_owned(),
        ledger_security_descriptor_sha256: ZERO_HASH.to_owned(),
        index_security_descriptor_sha256: ZERO_HASH.to_owned(),
        objects_security_descriptor_sha256: ZERO_HASH.to_owned(),
        tombstones_security_descriptor_sha256: ZERO_HASH.to_owned(),
    };
    write_new(&root.join(MANIFEST_FILE), &pretty_json(&placeholder)?)?;
    let manifest = MemoryStoreManifestV1 {
        root_security_descriptor_sha256: harden_and_hash(root)?,
        manifest_security_descriptor_sha256: harden_and_hash(&root.join(MANIFEST_FILE))?,
        ledger_security_descriptor_sha256: harden_and_hash(&root.join(LEDGER_FILE))?,
        index_security_descriptor_sha256: harden_and_hash(&root.join(INDEX_FILE))?,
        objects_security_descriptor_sha256: harden_and_hash(&objects)?,
        tombstones_security_descriptor_sha256: harden_and_hash(&tombstones)?,
        ..placeholder
    };
    overwrite_existing(&root.join(MANIFEST_FILE), &pretty_json(&manifest)?)?;
    EpisodicMemoryStoreV1::open(root, None)
}

impl EpisodicMemoryStoreV1 {
    pub fn open(root: &Path, expected_terminal_sha256: Option<&str>) -> Result<Self, DesktopError> {
        let manifest = load_manifest(root)?;
        let verification = verify_episodic_memory_store(root, expected_terminal_sha256)?;
        Ok(Self {
            root: root.to_path_buf(),
            manifest,
            verification,
            poisoned: false,
        })
    }

    pub const fn verification(&self) -> &EpisodicMemoryStoreVerificationV1 {
        &self.verification
    }

    pub fn store_episode(
        &mut self,
        episode: &CaseEpisodeV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.mutate(|root, manifest, ledger, index| {
            episode.validate().map_err(memory_error)?;
            if episode.organization_id != manifest.organization_id
                || episode.memory_namespace_sha256 != manifest.namespace_sha256
            {
                return Err(DesktopError::AccessDenied(
                    "Episode crosses memory namespace".to_owned(),
                ));
            }
            if let Some(existing) = index
                .episodes
                .iter()
                .find(|entry| entry.episode_id == episode.episode_id)
            {
                if existing.episode_sha256 == episode.canonical_episode_sha256 {
                    return Ok(existing.episode_sha256.clone());
                }
                return Err(DesktopError::Integrity(
                    "Case Episode ID has changed terminal semantics".to_owned(),
                ));
            }
            persist_object(root, &episode.canonical_episode_sha256, "episode", episode)?;
            append_record(
                ledger,
                MemoryStoreRecordKindV1::EpisodeStored,
                &manifest.namespace_sha256,
                &episode.episode_id,
                &episode.canonical_episode_sha256,
                recorded_at_unix_ms,
            )?;
            index.episodes.push(index_entry(episode)?);
            Ok(episode.canonical_episode_sha256.clone())
        })
    }

    pub fn publish_summary(
        &mut self,
        summary: &ApprovedEpisodeSummaryV1,
        verifying_key: &VerifyingKey,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.mutate(|root, manifest, ledger, index| {
            summary
                .validate(verifying_key, recorded_at_unix_ms)
                .map_err(memory_error)?;
            if summary.organization_id != manifest.organization_id
                || summary.namespace_sha256 != manifest.namespace_sha256
            {
                return Err(DesktopError::AccessDenied(
                    "summary crosses memory namespace".to_owned(),
                ));
            }
            if !index
                .episodes
                .iter()
                .any(|entry| entry.episode_sha256 == summary.episode_sha256)
            {
                return Err(DesktopError::Integrity(
                    "summary Episode is absent".to_owned(),
                ));
            }
            if let Some(existing) = index.summaries_by_episode.get(&summary.episode_sha256) {
                if existing == &summary.summary_sha256 {
                    return Ok(existing.clone());
                }
                return Err(DesktopError::Integrity(
                    "Episode already has a different summary".to_owned(),
                ));
            }
            persist_object(root, &summary.summary_sha256, "summary", summary)?;
            append_record(
                ledger,
                MemoryStoreRecordKindV1::SummaryPublished,
                &manifest.namespace_sha256,
                &summary.summary_id,
                &summary.summary_sha256,
                recorded_at_unix_ms,
            )?;
            index.summaries_by_episode.insert(
                summary.episode_sha256.clone(),
                summary.summary_sha256.clone(),
            );
            if let Some(entry) = index
                .episodes
                .iter_mut()
                .find(|entry| entry.episode_sha256 == summary.episode_sha256)
            {
                entry.approved_summary_sha256 = Some(summary.summary_sha256.clone());
                entry.entry_sha256 = index_entry_hash(entry)?;
            }
            Ok(summary.summary_sha256.clone())
        })
    }

    pub fn quarantine_candidate(
        &mut self,
        candidate: &LearningCandidateV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.mutate(|root, manifest, ledger, index| {
            validate_candidate(candidate)
                .map_err(|error| DesktopError::AccessDenied(error.to_string()))?;
            if candidate.organization_id != manifest.organization_id
                || candidate.namespace_sha256 != manifest.namespace_sha256
            {
                return Err(DesktopError::AccessDenied(
                    "candidate crosses memory namespace".to_owned(),
                ));
            }
            if index.candidate_hashes.contains(&candidate.candidate_sha256) {
                return Ok(candidate.candidate_sha256.clone());
            }
            persist_object(root, &candidate.candidate_sha256, "candidate", candidate)?;
            append_record(
                ledger,
                MemoryStoreRecordKindV1::CandidateQuarantined,
                &manifest.namespace_sha256,
                &candidate.candidate_id,
                &candidate.candidate_sha256,
                recorded_at_unix_ms,
            )?;
            index
                .candidate_hashes
                .push(candidate.candidate_sha256.clone());
            Ok(candidate.candidate_sha256.clone())
        })
    }

    pub fn tombstone_episode(
        &mut self,
        tombstone: &EpisodeTombstoneV1,
        recorded_at_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        self.mutate(|root, manifest, ledger, index| {
            let verified = tombstone.clone().seal().map_err(memory_error)?;
            if verified != *tombstone || tombstone.namespace_sha256 != manifest.namespace_sha256 {
                return Err(DesktopError::Integrity(
                    "tombstone hash or namespace mismatch".to_owned(),
                ));
            }
            if !index
                .episodes
                .iter()
                .any(|entry| entry.episode_sha256 == tombstone.episode_sha256)
            {
                return Err(DesktopError::Integrity(
                    "tombstone Episode is absent".to_owned(),
                ));
            }
            let path = tombstone_path(root, &tombstone.episode_id)?;
            if path.exists() {
                let bytes = read_bounded(&path, MAX_STORE_FILE_BYTES)?;
                let existing: EpisodeTombstoneV1 =
                    parse_json_strict(&bytes).map_err(memory_error)?;
                if existing == *tombstone {
                    return Ok(tombstone.tombstone_sha256.clone());
                }
                return Err(DesktopError::Integrity(
                    "Episode tombstone changed".to_owned(),
                ));
            }
            write_new(&path, &pretty_json(tombstone)?)?;
            harden_and_hash(&path)?;
            append_record(
                ledger,
                MemoryStoreRecordKindV1::TombstoneRecorded,
                &manifest.namespace_sha256,
                &tombstone.episode_id,
                &tombstone.tombstone_sha256,
                recorded_at_unix_ms,
            )?;
            index
                .tombstoned_episode_hashes
                .push(tombstone.episode_sha256.clone());
            if let Some(entry) = index
                .episodes
                .iter_mut()
                .find(|entry| entry.episode_sha256 == tombstone.episode_sha256)
            {
                entry.retention_status = EpisodeRetentionStatusV1::Tombstoned;
                entry.approved_summary_sha256 = None;
                entry.entry_sha256 = index_entry_hash(entry)?;
            }
            index.summaries_by_episode.remove(&tombstone.episode_sha256);
            Ok(tombstone.tombstone_sha256.clone())
        })
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(
            &Path,
            &MemoryStoreManifestV1,
            &mut MemoryStoreLedgerV1,
            &mut MemoryStoreIndexV1,
        ) -> Result<T, DesktopError>,
    ) -> Result<T, DesktopError> {
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "memory store is poisoned after a durable-write failure".to_owned(),
            ));
        }
        let result = self.mutate_inner(operation);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn mutate_inner<T>(
        &mut self,
        operation: impl FnOnce(
            &Path,
            &MemoryStoreManifestV1,
            &mut MemoryStoreLedgerV1,
            &mut MemoryStoreIndexV1,
        ) -> Result<T, DesktopError>,
    ) -> Result<T, DesktopError> {
        let _lock = MemoryStoreLock::acquire(&self.root)?;
        let latest = verify_episodic_memory_store(
            &self.root,
            Some(&self.verification.ledger_terminal_sha256),
        )?;
        if latest != self.verification {
            return Err(DesktopError::Replay(
                "memory store changed after coordinator open".to_owned(),
            ));
        }
        let mut ledger = load_ledger(&self.root)?;
        let mut index = load_index(&self.root)?;
        let value = operation(&self.root, &self.manifest, &mut ledger, &mut index)?;
        if ledger.records.len() > self.manifest.maximum_objects as usize
            || count_objects(&self.root)? > self.manifest.maximum_objects
        {
            return Err(DesktopError::AccessDenied(
                "memory object or ledger limit is exhausted".to_owned(),
            ));
        }
        index.generation = index.generation.saturating_add(1);
        normalize_index(&mut index)?;
        index.ledger_record_count = ledger.records.len() as u64;
        index.ledger_terminal_sha256 = ledger.records.last().map_or_else(
            || ZERO_HASH.to_owned(),
            |record| record.record_sha256.clone(),
        );
        index.index_sha256 = index_hash(&index)?;
        atomic_replace(&self.root, LEDGER_FILE, &pretty_json(&ledger)?)?;
        atomic_replace(&self.root, INDEX_FILE, &pretty_json(&index)?)?;
        let verified =
            verify_episodic_memory_store(&self.root, Some(&index.ledger_terminal_sha256))?;
        if verified.total_store_bytes > self.manifest.maximum_store_bytes {
            return Err(DesktopError::AccessDenied(
                "memory store byte limit is exhausted".to_owned(),
            ));
        }
        self.verification = verified;
        Ok(value)
    }
}

pub fn verify_episodic_memory_store(
    root: &Path,
    expected_terminal_sha256: Option<&str>,
) -> Result<EpisodicMemoryStoreVerificationV1, DesktopError> {
    reject_reparse(root, "memory store root")?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let ledger = load_ledger(root)?;
    let index = load_index(root)?;
    let mut previous = ZERO_HASH.to_owned();
    let mut last_time = 0;
    for (offset, record) in ledger.records.iter().enumerate() {
        if record.schema_version != 1
            || record.sequence as usize != offset + 1
            || record.previous_record_sha256 != previous
            || record.namespace_sha256 != manifest.namespace_sha256
            || record.recorded_at_unix_ms < last_time
            || record_hash(record)? != record.record_sha256
        {
            return Err(DesktopError::Integrity(
                "memory ledger sequence, chain, time, or namespace is invalid".to_owned(),
            ));
        }
        previous = record.record_sha256.clone();
        last_time = record.recorded_at_unix_ms;
    }
    let rollback = expected_terminal_sha256.is_some_and(|expected| expected != previous);
    if rollback {
        return Err(DesktopError::Replay(
            "memory ledger rollback or unexpected advance detected".to_owned(),
        ));
    }
    if index_hash(&index)? != index.index_sha256 {
        return Err(DesktopError::Integrity(
            "memory index hash mismatch".to_owned(),
        ));
    }
    let stale = index.ledger_record_count != ledger.records.len() as u64
        || index.ledger_terminal_sha256 != previous;
    if stale {
        return Err(DesktopError::Integrity("memory index is stale".to_owned()));
    }
    verify_index_objects(root, &manifest, &ledger, &index)?;
    let (object_count, total_store_bytes) = store_size(root)?;
    Ok(EpisodicMemoryStoreVerificationV1 {
        organization_id: manifest.organization_id,
        namespace_id: manifest.namespace_id,
        namespace_sha256: manifest.namespace_sha256,
        ledger_record_count: ledger.records.len() as u64,
        ledger_terminal_sha256: previous,
        index_sha256: index.index_sha256,
        episode_count: index.episodes.len() as u32,
        summary_count: index.summaries_by_episode.len() as u32,
        candidate_count: index.candidate_hashes.len() as u32,
        tombstone_count: index.tombstoned_episode_hashes.len() as u32,
        object_count,
        total_store_bytes,
        stale_index: false,
        rollback_detected: false,
    })
}

/// Repairs only durable reference objects and indexes. It never replays an action or provider.
pub fn recover_episodic_memory_store(
    root: &Path,
    trusted_now_unix_ms: u64,
) -> Result<EpisodicMemoryStoreVerificationV1, DesktopError> {
    let _lock = MemoryStoreLock::acquire(root)?;
    let manifest = load_manifest(root)?;
    verify_security(root, &manifest)?;
    let mut ledger = load_ledger(root)?;
    let mut index = rebuild_index_from_objects(root, &manifest)?;
    let recorded = ledger
        .records
        .iter()
        .map(|record| record.artifact_sha256.clone())
        .collect::<BTreeSet<_>>();
    let objects = list_objects(root)?;
    for object in objects {
        if !recorded.contains(&object.hash) {
            append_record(
                &mut ledger,
                object.kind,
                &manifest.namespace_sha256,
                &object.id,
                &object.hash,
                trusted_now_unix_ms,
            )?;
        }
    }
    append_record(
        &mut ledger,
        MemoryStoreRecordKindV1::IndexRepaired,
        &manifest.namespace_sha256,
        "memory-index",
        &index.index_sha256,
        trusted_now_unix_ms,
    )?;
    index.generation = index.generation.saturating_add(1);
    index.ledger_record_count = ledger.records.len() as u64;
    index.ledger_terminal_sha256 = ledger.records.last().map_or_else(
        || ZERO_HASH.to_owned(),
        |record| record.record_sha256.clone(),
    );
    normalize_index(&mut index)?;
    index.index_sha256 = index_hash(&index)?;
    atomic_replace(root, LEDGER_FILE, &pretty_json(&ledger)?)?;
    atomic_replace(root, INDEX_FILE, &pretty_json(&index)?)?;
    verify_episodic_memory_store(root, Some(&index.ledger_terminal_sha256))
}

#[derive(Debug)]
struct RecoveredObject {
    kind: MemoryStoreRecordKindV1,
    id: String,
    hash: String,
}

fn list_objects(root: &Path) -> Result<Vec<RecoveredObject>, DesktopError> {
    let mut output = Vec::new();
    for entry in
        std::fs::read_dir(root.join(OBJECTS_DIRECTORY)).map_err(|error| io_error(root, error))?
    {
        let entry = entry.map_err(|error| io_error(root, error))?;
        let path = entry.path();
        reject_reparse(&path, "memory object")?;
        let name = entry.file_name().to_string_lossy().to_string();
        let (hex, suffix, kind) = if let Some(hex) = name.strip_suffix(".episode.json") {
            (hex, "episode", MemoryStoreRecordKindV1::EpisodeStored)
        } else if let Some(hex) = name.strip_suffix(".summary.json") {
            (hex, "summary", MemoryStoreRecordKindV1::SummaryPublished)
        } else if let Some(hex) = name.strip_suffix(".candidate.json") {
            (
                hex,
                "candidate",
                MemoryStoreRecordKindV1::CandidateQuarantined,
            )
        } else {
            return Err(DesktopError::Integrity(
                "unknown memory object filename".to_owned(),
            ));
        };
        let hash = format!("sha256:{hex}");
        let bytes = read_bounded(&path, MAX_STORE_FILE_BYTES)?;
        let (id, actual) = match suffix {
            "episode" => {
                let value: CaseEpisodeV1 = parse_json_strict(&bytes).map_err(memory_error)?;
                (value.episode_id, value.canonical_episode_sha256)
            }
            "summary" => {
                let value: ApprovedEpisodeSummaryV1 =
                    parse_json_strict(&bytes).map_err(memory_error)?;
                (value.summary_id, value.summary_sha256)
            }
            _ => {
                let value: LearningCandidateV1 = parse_json_strict(&bytes).map_err(memory_error)?;
                (value.candidate_id, value.candidate_sha256)
            }
        };
        if actual != hash {
            return Err(DesktopError::Integrity(
                "content-addressed object filename mismatch".to_owned(),
            ));
        }
        output.push(RecoveredObject { kind, id, hash });
    }
    output.sort_by(|left, right| left.hash.cmp(&right.hash));
    Ok(output)
}

fn rebuild_index_from_objects(
    root: &Path,
    manifest: &MemoryStoreManifestV1,
) -> Result<MemoryStoreIndexV1, DesktopError> {
    let old = load_index(root)?;
    let mut episodes = Vec::new();
    let mut summaries = BTreeMap::new();
    let mut candidates = Vec::new();
    for object in list_objects(root)? {
        match object.kind {
            MemoryStoreRecordKindV1::EpisodeStored => {
                let value: CaseEpisodeV1 = parse_json_strict(&read_bounded(
                    &object_path(root, &object.hash, "episode")?,
                    MAX_STORE_FILE_BYTES,
                )?)
                .map_err(memory_error)?;
                episodes.push(index_entry(&value)?);
            }
            MemoryStoreRecordKindV1::SummaryPublished => {
                let value: ApprovedEpisodeSummaryV1 = parse_json_strict(&read_bounded(
                    &object_path(root, &object.hash, "summary")?,
                    MAX_STORE_FILE_BYTES,
                )?)
                .map_err(memory_error)?;
                summaries.insert(value.episode_sha256, value.summary_sha256);
            }
            MemoryStoreRecordKindV1::CandidateQuarantined => candidates.push(object.hash),
            _ => {}
        }
    }
    for entry in &mut episodes {
        if let Some(summary) = summaries.get(&entry.episode_sha256) {
            entry.approved_summary_sha256 = Some(summary.clone());
            entry.entry_sha256 = index_entry_hash(entry)?;
        }
    }
    let mut index = MemoryStoreIndexV1 {
        schema_version: 1,
        generation: old.generation,
        ledger_record_count: 0,
        ledger_terminal_sha256: ZERO_HASH.to_owned(),
        episodes,
        summaries_by_episode: summaries,
        candidate_hashes: candidates,
        tombstoned_episode_hashes: old.tombstoned_episode_hashes,
        index_sha256: ZERO_HASH.to_owned(),
    };
    if manifest.namespace_sha256 != manifest.namespace.namespace_sha256 {
        return Err(DesktopError::Integrity(
            "manifest namespace drift".to_owned(),
        ));
    }
    normalize_index(&mut index)?;
    index.index_sha256 = index_hash(&index)?;
    Ok(index)
}

fn verify_index_objects(
    root: &Path,
    manifest: &MemoryStoreManifestV1,
    ledger: &MemoryStoreLedgerV1,
    index: &MemoryStoreIndexV1,
) -> Result<(), DesktopError> {
    let records = ledger
        .records
        .iter()
        .map(|record| record.artifact_sha256.as_str())
        .collect::<BTreeSet<_>>();
    for entry in &index.episodes {
        if entry.entry_sha256 != index_entry_hash(entry)?
            || !records.contains(entry.episode_sha256.as_str())
            || !object_path(root, &entry.episode_sha256, "episode")?.is_file()
        {
            return Err(DesktopError::Integrity(
                "Episode index/object/ledger mismatch".to_owned(),
            ));
        }
        if index
            .tombstoned_episode_hashes
            .contains(&entry.episode_sha256)
            && entry.retention_status != EpisodeRetentionStatusV1::Tombstoned
        {
            return Err(DesktopError::Integrity(
                "tombstone index state mismatch".to_owned(),
            ));
        }
    }
    for hash in index.summaries_by_episode.values() {
        if !records.contains(hash.as_str()) || !object_path(root, hash, "summary")?.is_file() {
            return Err(DesktopError::Integrity(
                "summary index/object/ledger mismatch".to_owned(),
            ));
        }
    }
    for hash in &index.candidate_hashes {
        if !records.contains(hash.as_str()) || !object_path(root, hash, "candidate")?.is_file() {
            return Err(DesktopError::Integrity(
                "candidate index/object/ledger mismatch".to_owned(),
            ));
        }
    }
    if index.episodes.len() > manifest.namespace.maximum_episodes as usize {
        return Err(DesktopError::Integrity(
            "namespace Episode limit exceeded".to_owned(),
        ));
    }
    Ok(())
}

fn append_record(
    ledger: &mut MemoryStoreLedgerV1,
    kind: MemoryStoreRecordKindV1,
    namespace: &str,
    id: &str,
    hash: &str,
    time: u64,
) -> Result<(), DesktopError> {
    if time == 0
        || ledger
            .records
            .last()
            .is_some_and(|record| time < record.recorded_at_unix_ms)
    {
        return Err(DesktopError::Invalid(
            "memory ledger time is zero or moves backward".to_owned(),
        ));
    }
    let mut record = MemoryStoreLedgerRecordV1 {
        schema_version: 1,
        sequence: ledger.records.len() as u64 + 1,
        record_kind: kind,
        namespace_sha256: namespace.to_owned(),
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

fn record_hash(record: &MemoryStoreLedgerRecordV1) -> Result<String, DesktopError> {
    hash_without(record, &["record_sha256"]).map_err(memory_error)
}
fn index_hash(index: &MemoryStoreIndexV1) -> Result<String, DesktopError> {
    hash_without(index, &["index_sha256"]).map_err(memory_error)
}
fn index_entry_hash(entry: &EpisodeIndexEntryV1) -> Result<String, DesktopError> {
    hash_without(entry, &["entry_sha256"]).map_err(memory_error)
}

fn index_entry(episode: &CaseEpisodeV1) -> Result<EpisodeIndexEntryV1, DesktopError> {
    let mut entry = EpisodeIndexEntryV1 {
        episode_id: episode.episode_id.clone(),
        episode_sha256: episode.canonical_episode_sha256.clone(),
        terminal_outcome: episode.terminal_outcome,
        work_class_id: episode.work_class_id.clone(),
        responsibility_id: episode.responsibility_id.clone(),
        terminal_at_unix_ms: episode.terminal_at_unix_ms,
        data_class_ids: episode.data_class_ids.clone(),
        evidence_sha256: episode.terminal_evidence_index_sha256.clone(),
        retention_status: EpisodeRetentionStatusV1::Active,
        approved_summary_sha256: None,
        entry_sha256: ZERO_HASH.to_owned(),
    };
    entry.entry_sha256 = index_entry_hash(&entry)?;
    Ok(entry)
}

fn normalize_index(index: &mut MemoryStoreIndexV1) -> Result<(), DesktopError> {
    index.episodes.sort_by(|left, right| {
        right
            .terminal_at_unix_ms
            .cmp(&left.terminal_at_unix_ms)
            .then_with(|| left.episode_id.cmp(&right.episode_id))
            .then_with(|| left.episode_sha256.cmp(&right.episode_sha256))
    });
    index.candidate_hashes.sort();
    index.candidate_hashes.dedup();
    index.tombstoned_episode_hashes.sort();
    index.tombstoned_episode_hashes.dedup();
    let mut ids = BTreeSet::new();
    if index
        .episodes
        .iter()
        .any(|entry| !ids.insert(entry.episode_id.as_str()))
    {
        return Err(DesktopError::Integrity(
            "duplicate Episode ID in index".to_owned(),
        ));
    }
    Ok(())
}

fn persist_object<T: Serialize>(
    root: &Path,
    hash: &str,
    suffix: &str,
    value: &T,
) -> Result<(), DesktopError> {
    let bytes = pretty_json(value)?;
    if sha256_bytes(&canonical_json_bytes(value).map_err(memory_error)?) != hash {
        let omitted = match suffix {
            "episode" => &["canonical_episode_sha256"][..],
            "summary" => &["summary_sha256", "signature_hex"][..],
            _ => &["candidate_sha256"][..],
        };
        let declared = hash_without(value, omitted).map_err(memory_error)?;
        if declared != hash {
            return Err(DesktopError::Integrity(
                "object content hash mismatch".to_owned(),
            ));
        }
    }
    let path = object_path(root, hash, suffix)?;
    if path.exists() {
        let existing = read_bounded(&path, MAX_STORE_FILE_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(DesktopError::Integrity(
            "content-addressed object collision".to_owned(),
        ));
    }
    write_new(&path, &bytes)?;
    harden_and_hash(&path)?;
    Ok(())
}

fn object_path(root: &Path, hash: &str, suffix: &str) -> Result<PathBuf, DesktopError> {
    let hex = hash
        .strip_prefix("sha256:")
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| DesktopError::Invalid("object hash syntax is invalid".to_owned()))?;
    Ok(root
        .join(OBJECTS_DIRECTORY)
        .join(format!("{hex}.{suffix}.json")))
}

fn tombstone_path(root: &Path, episode_id: &str) -> Result<PathBuf, DesktopError> {
    if episode_id.is_empty()
        || !episode_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(DesktopError::Invalid(
            "tombstone Episode ID is unsafe for a path".to_owned(),
        ));
    }
    Ok(root
        .join(TOMBSTONES_DIRECTORY)
        .join(format!("{episode_id}.json")))
}

fn load_manifest(root: &Path) -> Result<MemoryStoreManifestV1, DesktopError> {
    let manifest: MemoryStoreManifestV1 = parse_json_strict(&read_bounded(
        &root.join(MANIFEST_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(memory_error)?;
    manifest.namespace.validate().map_err(memory_error)?;
    if manifest.schema_version != 1
        || manifest.maximum_objects == 0
        || manifest.maximum_store_bytes == 0
        || manifest.namespace_sha256 != manifest.namespace.namespace_sha256
    {
        return Err(DesktopError::Integrity(
            "memory manifest bounds or namespace are invalid".to_owned(),
        ));
    }
    Ok(manifest)
}

fn load_ledger(root: &Path) -> Result<MemoryStoreLedgerV1, DesktopError> {
    parse_json_strict(&read_bounded(
        &root.join(LEDGER_FILE),
        MAX_STORE_FILE_BYTES,
    )?)
    .map_err(memory_error)
}
fn load_index(root: &Path) -> Result<MemoryStoreIndexV1, DesktopError> {
    parse_json_strict(&read_bounded(&root.join(INDEX_FILE), MAX_STORE_FILE_BYTES)?)
        .map_err(memory_error)
}

fn verify_security(root: &Path, manifest: &MemoryStoreManifestV1) -> Result<(), DesktopError> {
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
        (
            root.join(TOMBSTONES_DIRECTORY),
            &manifest.tombstones_security_descriptor_sha256,
        ),
    ] {
        let descriptor = d2i_windows_host::path_security_descriptor(&path).map_err(|error| {
            DesktopError::Integrity(format!("memory DACL query failed: {error}"))
        })?;
        if sha256_bytes(&descriptor) != *expected {
            return Err(DesktopError::Integrity(
                "memory owner or DACL drifted".to_owned(),
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
    let canonical = canonical_json_bytes(value).map_err(memory_error)?;
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

fn count_objects(root: &Path) -> Result<u32, DesktopError> {
    let count = std::fs::read_dir(root.join(OBJECTS_DIRECTORY))
        .map_err(|error| io_error(root, error))?
        .count();
    u32::try_from(count).map_err(|_| DesktopError::Integrity("object count overflow".to_owned()))
}

fn store_size(root: &Path) -> Result<(u32, u64), DesktopError> {
    fn walk(path: &Path, count: &mut u32, bytes: &mut u64) -> Result<(), DesktopError> {
        for entry in std::fs::read_dir(path).map_err(|error| io_error(path, error))? {
            let entry = entry.map_err(|error| io_error(path, error))?;
            let child = entry.path();
            reject_reparse(&child, "memory store entry")?;
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
                    "memory store contains a non-regular entry".to_owned(),
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

fn memory_error(error: EpisodicMemoryError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}
fn io_error(path: &Path, error: std::io::Error) -> DesktopError {
    DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

struct MemoryStoreLock {
    path: PathBuf,
}
impl MemoryStoreLock {
    fn acquire(root: &Path) -> Result<Self, DesktopError> {
        let path = root.join(LOCK_FILE);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| DesktopError::Io {
                path: path.display().to_string(),
                message: format!("memory single-writer lock failed: {error}"),
            })?;
        harden_and_hash(&path)?;
        Ok(Self { path })
    }
}
impl Drop for MemoryStoreLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_order_is_terminal_descending_then_id() {
        let mut index = MemoryStoreIndexV1 {
            schema_version: 1,
            generation: 0,
            ledger_record_count: 0,
            ledger_terminal_sha256: ZERO_HASH.to_owned(),
            episodes: vec![
                EpisodeIndexEntryV1 {
                    episode_id: "b".to_owned(),
                    episode_sha256: format!("sha256:{:064x}", 2),
                    terminal_outcome: d2i_episodic_memory::TerminalCaseOutcomeV1::VerifiedComplete,
                    work_class_id: "opaque".to_owned(),
                    responsibility_id: "opaque".to_owned(),
                    terminal_at_unix_ms: 10,
                    data_class_ids: Vec::new(),
                    evidence_sha256: format!("sha256:{:064x}", 3),
                    retention_status: EpisodeRetentionStatusV1::Active,
                    approved_summary_sha256: None,
                    entry_sha256: ZERO_HASH.to_owned(),
                },
                EpisodeIndexEntryV1 {
                    episode_id: "a".to_owned(),
                    episode_sha256: format!("sha256:{:064x}", 1),
                    terminal_outcome: d2i_episodic_memory::TerminalCaseOutcomeV1::VerifiedComplete,
                    work_class_id: "opaque".to_owned(),
                    responsibility_id: "opaque".to_owned(),
                    terminal_at_unix_ms: 11,
                    data_class_ids: Vec::new(),
                    evidence_sha256: format!("sha256:{:064x}", 3),
                    retention_status: EpisodeRetentionStatusV1::Active,
                    approved_summary_sha256: None,
                    entry_sha256: ZERO_HASH.to_owned(),
                },
            ],
            summaries_by_episode: BTreeMap::new(),
            candidate_hashes: Vec::new(),
            tombstoned_episode_hashes: Vec::new(),
            index_sha256: ZERO_HASH.to_owned(),
        };
        normalize_index(&mut index).unwrap_or_else(|error| panic!("normalize: {error}"));
        assert_eq!(index.episodes[0].episode_id, "a");
    }
}
