use crate::{
    json_bytes, pretty_json_bytes, read_bounded, sha256_bytes, write_new, Episode, LearningError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_FILE: &str = "store-policy.json";
const EPISODES_FILE: &str = "episodes.jsonl";
const APPEND_LOCK: &str = ".append.lock";
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Role allowlists for append, export, and candidate-building operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RolePolicy {
    pub append: BTreeSet<String>,
    pub export: BTreeSet<String>,
    pub build_candidate: BTreeSet<String>,
}

/// Immutable store policy and retention bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperienceStorePolicy {
    pub schema_version: u32,
    pub store_id: String,
    pub roles: RolePolicy,
    pub allowed_build_ids: BTreeSet<String>,
    pub maximum_entries: u64,
    pub maximum_age_seconds: u64,
}

/// Caller identity evaluated against the store role policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub actor_id: String,
    pub roles: BTreeSet<String>,
}

/// Verified hash-chain state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreVerification {
    pub store_id: String,
    pub entry_count: u64,
    pub chain_head: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEpisode {
    sequence: u64,
    previous_hash: String,
    episode_hash: String,
    entry_hash: String,
    episode: Episode,
}

#[derive(Serialize)]
struct EntryPayload<'a> {
    sequence: u64,
    previous_hash: &'a str,
    episode_hash: &'a str,
    episode: &'a Episode,
}

/// Creates a new empty store. Existing paths are never reused.
pub fn initialize_store(root: &Path, policy: &ExperienceStorePolicy) -> Result<(), LearningError> {
    validate_policy(policy)?;
    if root.exists() {
        return Err(LearningError::Invalid(
            "experience store path already exists".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        write_new(&root.join(POLICY_FILE), &pretty_json_bytes(policy)?)?;
        write_new(&root.join(EPISODES_FILE), b"")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    result
}

/// Verifies policy, every episode, and the complete append-only hash chain.
pub fn verify_store(root: &Path) -> Result<StoreVerification, LearningError> {
    let (policy, entries) = load_verified(root)?;
    Ok(StoreVerification {
        store_id: policy.store_id,
        entry_count: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        chain_head: entries
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |entry| entry.entry_hash.clone()),
    })
}

/// Appends one episode after full-chain, access, retention, and duplicate checks.
pub fn append_episode(
    root: &Path,
    actor: &Actor,
    episode: Episode,
) -> Result<StoreVerification, LearningError> {
    episode.validate()?;
    validate_store_root(root)?;
    let lock = AppendLock::acquire(root)?;
    let (policy, entries) = load_verified(root)?;
    authorize(actor, &policy.roles.append, "append")?;
    if !policy.allowed_build_ids.contains(&episode.build_id) {
        return Err(LearningError::AccessDenied(
            "episode build ID is not allowlisted by the store".to_owned(),
        ));
    }
    if u64::try_from(entries.len()).unwrap_or(u64::MAX) >= policy.maximum_entries {
        return Err(LearningError::Invalid(
            "experience store retention entry limit is reached".to_owned(),
        ));
    }
    if entries
        .iter()
        .any(|entry| entry.episode.episode_id == episode.episode_id)
    {
        return Err(LearningError::Invalid(
            "episode_id is already present".to_owned(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    if episode.recorded_at_unix_seconds > now
        || now.saturating_sub(episode.recorded_at_unix_seconds) > policy.maximum_age_seconds
    {
        return Err(LearningError::Invalid(
            "episode timestamp is outside retention policy".to_owned(),
        ));
    }
    let sequence = u64::try_from(entries.len()).unwrap_or(u64::MAX);
    let previous_hash = entries
        .last()
        .map_or(ZERO_HASH, |entry| entry.entry_hash.as_str())
        .to_owned();
    let episode_hash = sha256_bytes(&json_bytes(&episode)?);
    let entry_hash = sha256_bytes(&json_bytes(&EntryPayload {
        sequence,
        previous_hash: &previous_hash,
        episode_hash: &episode_hash,
        episode: &episode,
    })?);
    let stored = StoredEpisode {
        sequence,
        previous_hash,
        episode_hash,
        entry_hash: entry_hash.clone(),
        episode,
    };
    let path = root.join(EPISODES_FILE);
    let mut bytes = json_bytes(&stored)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| LearningError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    drop(lock);
    Ok(StoreVerification {
        store_id: policy.store_id,
        entry_count: sequence.saturating_add(1),
        chain_head: entry_hash,
    })
}

/// Returns verified episodes to an actor allowed to build candidates.
pub fn read_verified_episodes(root: &Path, actor: &Actor) -> Result<Vec<Episode>, LearningError> {
    let (policy, entries) = load_verified(root)?;
    authorize(actor, &policy.roles.build_candidate, "build_candidate")?;
    Ok(entries.into_iter().map(|entry| entry.episode).collect())
}

/// Exports verified episodes without chain metadata into a new JSONL file.
pub fn export_store(root: &Path, output: &Path, actor: &Actor) -> Result<String, LearningError> {
    let (policy, entries) = load_verified(root)?;
    authorize(actor, &policy.roles.export, "export")?;
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&json_bytes(&entry.episode)?);
        bytes.push(b'\n');
        if bytes.len() > usize::try_from(MAX_STORE_BYTES).unwrap_or(usize::MAX) {
            return Err(LearningError::Invalid(
                "experience export exceeds size limit".to_owned(),
            ));
        }
    }
    let hash = sha256_bytes(&bytes);
    write_new(output, &bytes)?;
    Ok(hash)
}

fn load_verified(
    root: &Path,
) -> Result<(ExperienceStorePolicy, Vec<StoredEpisode>), LearningError> {
    validate_store_root(root)?;
    let policy_bytes = read_bounded(&root.join(POLICY_FILE), 1024 * 1024)?;
    let policy: ExperienceStorePolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|error| LearningError::Json(error.to_string()))?;
    validate_policy(&policy)?;
    let episode_bytes = read_bounded(&root.join(EPISODES_FILE), MAX_STORE_BYTES)?;
    let mut entries = Vec::new();
    let mut previous = ZERO_HASH.to_owned();
    for (index, line) in episode_bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let entry: StoredEpisode =
            serde_json::from_slice(line).map_err(|error| LearningError::Json(error.to_string()))?;
        entry.episode.validate()?;
        let sequence = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        if entry.sequence != sequence || entry.previous_hash != previous {
            return Err(LearningError::Integrity(format!(
                "episode chain is discontinuous at line {}",
                index + 1
            )));
        }
        let episode_hash = sha256_bytes(&json_bytes(&entry.episode)?);
        if entry.episode_hash != episode_hash {
            return Err(LearningError::Integrity(format!(
                "episode payload hash mismatch at line {}",
                index + 1
            )));
        }
        let expected_entry_hash = sha256_bytes(&json_bytes(&EntryPayload {
            sequence: entry.sequence,
            previous_hash: &entry.previous_hash,
            episode_hash: &entry.episode_hash,
            episode: &entry.episode,
        })?);
        if entry.entry_hash != expected_entry_hash {
            return Err(LearningError::Integrity(format!(
                "episode chain hash mismatch at line {}",
                index + 1
            )));
        }
        if !policy.allowed_build_ids.contains(&entry.episode.build_id) {
            return Err(LearningError::Integrity(
                "stored episode build is no longer allowlisted".to_owned(),
            ));
        }
        previous = entry.entry_hash.clone();
        entries.push(entry);
        if u64::try_from(entries.len()).unwrap_or(u64::MAX) > policy.maximum_entries {
            return Err(LearningError::Integrity(
                "store exceeds retention entry limit".to_owned(),
            ));
        }
    }
    Ok((policy, entries))
}

fn validate_store_root(root: &Path) -> Result<(), LearningError> {
    let root_metadata = std::fs::symlink_metadata(root).map_err(|error| LearningError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(LearningError::Integrity(
            "experience store must be a regular directory".to_owned(),
        ));
    }
    Ok(())
}

fn validate_policy(policy: &ExperienceStorePolicy) -> Result<(), LearningError> {
    if policy.schema_version != 1
        || policy.store_id.is_empty()
        || policy.allowed_build_ids.is_empty()
        || policy.maximum_entries == 0
        || policy.maximum_entries > 1_000_000
        || policy.maximum_age_seconds == 0
        || policy.roles.append.is_empty()
        || policy.roles.export.is_empty()
        || policy.roles.build_candidate.is_empty()
    {
        return Err(LearningError::Invalid(
            "experience store policy is incomplete or outside bounds".to_owned(),
        ));
    }
    Ok(())
}

fn authorize(
    actor: &Actor,
    allowed_roles: &BTreeSet<String>,
    operation: &str,
) -> Result<(), LearningError> {
    if actor.actor_id.is_empty() || actor.roles.is_disjoint(allowed_roles) {
        return Err(LearningError::AccessDenied(format!(
            "actor is not allowed to {operation}"
        )));
    }
    Ok(())
}

struct AppendLock {
    path: PathBuf,
}

impl AppendLock {
    fn acquire(root: &Path) -> Result<Self, LearningError> {
        let path = root.join(APPEND_LOCK);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| LearningError::Io {
                path: path.display().to_string(),
                message: format!("cannot acquire append lock: {error}"),
            })?;
        Ok(Self { path })
    }
}

impl Drop for AppendLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
