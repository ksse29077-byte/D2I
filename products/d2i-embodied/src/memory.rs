use crate::{
    json_bytes, pretty_json_bytes, read_bounded, sha256_bytes, validate_hash, validate_text,
    validate_token, write_new, ActionIntent, EmbodiedError, SafetyAssessment, SafetyDecisionStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const POLICY_FILE: &str = "memory-policy.json";
const EPISODES_FILE: &str = "robot-episodes.jsonl";
const LOCK_FILE: &str = ".append.lock";
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024;
const ZERO_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Robot-specific terminal outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RobotOutcome {
    Completed,
    Corrected,
    Failed,
    NearMiss,
    EmergencyStop,
}

/// Robot episode retained for later offline candidate generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobotEpisode {
    pub schema_version: u32,
    pub episode_id: String,
    pub robot_id: String,
    pub recorded_at_unix_seconds: u64,
    pub build_id: String,
    pub package_content_hash: String,
    pub sensor_event_ids: Vec<String>,
    pub action_intent: Option<ActionIntent>,
    pub safety_assessment: Option<SafetyAssessment>,
    pub outcome: RobotOutcome,
    pub correction: Option<String>,
    pub simulation_id: Option<String>,
    pub provenance_hashes: Vec<String>,
}

impl RobotEpisode {
    fn validate(&self) -> Result<(), EmbodiedError> {
        if self.schema_version != 1 || self.recorded_at_unix_seconds == 0 {
            return Err(EmbodiedError::Invalid(
                "robot episode schema or timestamp is invalid".to_owned(),
            ));
        }
        validate_token(&self.episode_id, "episode_id")?;
        validate_token(&self.robot_id, "robot_id")?;
        validate_token(&self.build_id, "build_id")?;
        validate_hash(&self.package_content_hash, "package_content_hash")?;
        if self.sensor_event_ids.is_empty()
            || self.sensor_event_ids.len() > 10_000
            || self.provenance_hashes.is_empty()
            || self.provenance_hashes.len() > 256
        {
            return Err(EmbodiedError::Invalid(
                "robot episode event or provenance count is outside bounds".to_owned(),
            ));
        }
        for event_id in &self.sensor_event_ids {
            validate_token(event_id, "sensor_event_id")?;
        }
        for hash in &self.provenance_hashes {
            validate_hash(hash, "provenance_hash")?;
        }
        if let Some(simulation_id) = &self.simulation_id {
            validate_token(simulation_id, "simulation_id")?;
        }
        if matches!(
            self.outcome,
            RobotOutcome::Corrected
                | RobotOutcome::Failed
                | RobotOutcome::NearMiss
                | RobotOutcome::EmergencyStop
        ) && self.correction.is_none()
        {
            return Err(EmbodiedError::Invalid(
                "non-success robot outcomes require a reviewed correction".to_owned(),
            ));
        }
        if let Some(correction) = &self.correction {
            validate_text(correction, "correction")?;
        }
        match (&self.action_intent, &self.safety_assessment) {
            (Some(intent), Some(assessment)) => {
                intent.validate()?;
                if intent.robot_id != self.robot_id
                    || intent.source_build_id != self.build_id
                    || intent.source_package_content_hash != self.package_content_hash
                    || assessment.intent_hash != intent.content_hash()?
                {
                    return Err(EmbodiedError::Integrity(
                        "robot episode action/safety identity is inconsistent".to_owned(),
                    ));
                }
                if self.outcome == RobotOutcome::EmergencyStop
                    && assessment.status != SafetyDecisionStatus::EmergencyStop
                {
                    return Err(EmbodiedError::Integrity(
                        "emergency-stop outcome requires an emergency-stop assessment".to_owned(),
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(EmbodiedError::Invalid(
                    "action intent and safety assessment must appear together".to_owned(),
                ));
            }
        }
        let _ = json_bytes(self)?;
        Ok(())
    }
}

/// Access and retention policy for one robot-memory store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobotMemoryPolicy {
    pub schema_version: u32,
    pub memory_id: String,
    pub allowed_robot_ids: BTreeSet<String>,
    pub append_roles: BTreeSet<String>,
    pub read_roles: BTreeSet<String>,
    pub maximum_entries: u64,
    pub maximum_age_seconds: u64,
}

/// Actor evaluated against robot-memory policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryActor {
    pub actor_id: String,
    pub roles: BTreeSet<String>,
}

/// Verified append-only memory state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RobotMemoryVerification {
    pub memory_id: String,
    pub entry_count: u64,
    pub chain_head: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRobotEpisode {
    sequence: u64,
    previous_hash: String,
    episode_hash: String,
    entry_hash: String,
    episode: RobotEpisode,
}

#[derive(Serialize)]
struct EntryPayload<'a> {
    sequence: u64,
    previous_hash: &'a str,
    episode_hash: &'a str,
    episode: &'a RobotEpisode,
}

/// Creates a new robot-memory store. Existing paths are rejected.
pub fn initialize_robot_memory(
    root: &Path,
    policy: &RobotMemoryPolicy,
) -> Result<(), EmbodiedError> {
    validate_policy(policy)?;
    if root.exists() {
        return Err(EmbodiedError::Invalid(
            "robot memory path already exists".to_owned(),
        ));
    }
    std::fs::create_dir(root).map_err(|error| EmbodiedError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        write_new(&root.join(POLICY_FILE), &pretty_json_bytes(policy)?)?;
        write_new(&root.join(EPISODES_FILE), b"")
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(root);
    }
    result
}

/// Appends one fully validated robot episode after verifying the complete chain.
pub fn append_robot_episode(
    root: &Path,
    actor: &MemoryActor,
    episode: RobotEpisode,
) -> Result<RobotMemoryVerification, EmbodiedError> {
    episode.validate()?;
    validate_root(root)?;
    let lock = MemoryLock::acquire(root)?;
    let (policy, entries) = load_verified(root)?;
    authorize(actor, &policy.append_roles, "append")?;
    if !policy.allowed_robot_ids.contains(&episode.robot_id) {
        return Err(EmbodiedError::Invalid(
            "robot ID is not allowlisted by memory policy".to_owned(),
        ));
    }
    if u64::try_from(entries.len()).unwrap_or(u64::MAX) >= policy.maximum_entries
        || entries
            .iter()
            .any(|stored| stored.episode.episode_id == episode.episode_id)
    {
        return Err(EmbodiedError::Invalid(
            "robot memory limit or duplicate episode ID rejected append".to_owned(),
        ));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    if episode.recorded_at_unix_seconds > now
        || now.saturating_sub(episode.recorded_at_unix_seconds) > policy.maximum_age_seconds
    {
        return Err(EmbodiedError::Invalid(
            "robot episode is outside retention policy".to_owned(),
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
    let stored = StoredRobotEpisode {
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
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_data())
        .map_err(|error| EmbodiedError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    drop(lock);
    Ok(RobotMemoryVerification {
        memory_id: policy.memory_id,
        entry_count: sequence.saturating_add(1),
        chain_head: entry_hash,
    })
}

/// Verifies the policy and every append-only robot-memory record.
pub fn verify_robot_memory(root: &Path) -> Result<RobotMemoryVerification, EmbodiedError> {
    let (policy, entries) = load_verified(root)?;
    Ok(RobotMemoryVerification {
        memory_id: policy.memory_id,
        entry_count: u64::try_from(entries.len()).unwrap_or(u64::MAX),
        chain_head: entries
            .last()
            .map_or_else(|| ZERO_HASH.to_owned(), |entry| entry.entry_hash.clone()),
    })
}

/// Returns verified robot episodes to an actor with a configured read role.
pub fn read_robot_episodes(
    root: &Path,
    actor: &MemoryActor,
) -> Result<Vec<RobotEpisode>, EmbodiedError> {
    let (policy, entries) = load_verified(root)?;
    authorize(actor, &policy.read_roles, "read")?;
    Ok(entries.into_iter().map(|entry| entry.episode).collect())
}

fn load_verified(
    root: &Path,
) -> Result<(RobotMemoryPolicy, Vec<StoredRobotEpisode>), EmbodiedError> {
    validate_root(root)?;
    let policy: RobotMemoryPolicy =
        serde_json::from_slice(&read_bounded(&root.join(POLICY_FILE), 1024 * 1024)?)
            .map_err(|error| EmbodiedError::Json(error.to_string()))?;
    validate_policy(&policy)?;
    let bytes = read_bounded(&root.join(EPISODES_FILE), MAX_MEMORY_BYTES)?;
    let mut entries = Vec::new();
    let mut previous = ZERO_HASH.to_owned();
    for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let entry: StoredRobotEpisode =
            serde_json::from_slice(line).map_err(|error| EmbodiedError::Json(error.to_string()))?;
        entry.episode.validate()?;
        let sequence = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        let episode_hash = sha256_bytes(&json_bytes(&entry.episode)?);
        let entry_hash = sha256_bytes(&json_bytes(&EntryPayload {
            sequence,
            previous_hash: &entry.previous_hash,
            episode_hash: &entry.episode_hash,
            episode: &entry.episode,
        })?);
        if entry.sequence != sequence
            || entry.previous_hash != previous
            || entry.episode_hash != episode_hash
            || entry.entry_hash != entry_hash
            || !policy.allowed_robot_ids.contains(&entry.episode.robot_id)
        {
            return Err(EmbodiedError::Integrity(format!(
                "robot memory chain is invalid at line {}",
                line_index + 1
            )));
        }
        previous = entry.entry_hash.clone();
        entries.push(entry);
        if u64::try_from(entries.len()).unwrap_or(u64::MAX) > policy.maximum_entries {
            return Err(EmbodiedError::Integrity(
                "robot memory exceeds retention entry limit".to_owned(),
            ));
        }
    }
    Ok((policy, entries))
}

fn validate_policy(policy: &RobotMemoryPolicy) -> Result<(), EmbodiedError> {
    validate_token(&policy.memory_id, "memory_id")?;
    if policy.schema_version != 1
        || policy.allowed_robot_ids.is_empty()
        || policy.append_roles.is_empty()
        || policy.read_roles.is_empty()
        || policy.maximum_entries == 0
        || policy.maximum_entries > 1_000_000
        || policy.maximum_age_seconds == 0
    {
        return Err(EmbodiedError::Invalid(
            "robot memory policy is incomplete or outside bounds".to_owned(),
        ));
    }
    for robot_id in &policy.allowed_robot_ids {
        validate_token(robot_id, "allowed_robot_id")?;
    }
    Ok(())
}

fn authorize(
    actor: &MemoryActor,
    allowed_roles: &BTreeSet<String>,
    operation: &str,
) -> Result<(), EmbodiedError> {
    validate_token(&actor.actor_id, "actor_id")?;
    if actor.roles.is_disjoint(allowed_roles) {
        return Err(EmbodiedError::AccessDenied(format!(
            "actor is not allowed to {operation} robot memory"
        )));
    }
    Ok(())
}

fn validate_root(root: &Path) -> Result<(), EmbodiedError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|error| EmbodiedError::Io {
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EmbodiedError::Integrity(
            "robot memory must be a regular directory".to_owned(),
        ));
    }
    Ok(())
}

struct MemoryLock {
    path: PathBuf,
}

impl MemoryLock {
    fn acquire(root: &Path) -> Result<Self, EmbodiedError> {
        let path = root.join(LOCK_FILE);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| EmbodiedError::Io {
                path: path.display().to_string(),
                message: format!("cannot acquire robot-memory lock: {error}"),
            })?;
        Ok(Self { path })
    }
}

impl Drop for MemoryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
