use d2i_office_capability::{
    canonical_sha256, parse_json_strict, sha256_bytes, validate_hash, validate_id,
    validate_relative_path_token, OfficeArtifactReferenceV1, OfficeWorkspaceProfileV1,
    WorkingCopyStateV1, WorkspaceActivationLedgerV1, WorkspaceObservationSnapshotV1,
    WorkspaceOperationBindingV1, WorkspaceOperationClassV1, WorkspaceOperationIntentV1,
    WorkspaceOperationReceiptV1, WorkspaceOperationStatusV1, WorkspaceRootBindingV1, ZERO_HASH,
};
use d2i_policy_admission::{AdapterKindV1, CognitiveActivationAdmissionV1};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const OFFICE_WORKSPACE_STORE_SCHEMA_VERSION: u32 = 1;
const MAX_WORKER_BYTES: usize = 2 * 1024 * 1024;
const MAX_STORE_BYTES: u64 = 128 * 1024 * 1024;
const WORKER_TIMEOUT_MS: u64 = 10_000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeFileWorkerOperationV1 {
    Copy,
    Rename,
    Move,
    CommitVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeFileWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub workspace_root: String,
    pub workspace_root_binding_sha256: String,
    pub operation: OfficeFileWorkerOperationV1,
    pub source_relative_path: String,
    pub destination_relative_path: String,
    pub expected_source_sha256: String,
    pub expected_source_generation: u64,
    pub approved_content_hex: Option<String>,
    pub approved_content_sha256: Option<String>,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeFileWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_sha256: String,
    pub destination_sha256: String,
    pub bytes_processed: u64,
    pub atomic_commit: bool,
    pub old_identity_sha256: String,
    pub new_identity_sha256: String,
    pub response_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeWorkspaceAuthorityContextV1 {
    pub role_scope_id: String,
    pub role_contract_sha256: String,
    pub role_instance_id: String,
    pub role_instance_sha256: String,
    pub case_id: String,
    pub case_sha256: String,
    pub lease_sha256: String,
    pub work_grant_sha256: String,
}

pub struct OfficeWorkspaceDispatchV1<'a> {
    pub intent: &'a WorkspaceOperationIntentV1,
    pub binding: &'a WorkspaceOperationBindingV1,
    pub admission: &'a CognitiveActivationAdmissionV1,
    pub source: &'a OfficeArtifactReferenceV1,
    pub authority: &'a OfficeWorkspaceAuthorityContextV1,
    pub destination_relative_path: &'a str,
    pub approved_content: Option<&'a [u8]>,
    pub now_unix_ms: u64,
}

pub struct ArtifactReferenceInputV1<'a> {
    pub root: &'a Path,
    pub workspace_id: &'a str,
    pub artifact_id: &'a str,
    pub relative_path: &'a str,
    pub generation: u64,
    pub source_artifact_id: Option<String>,
    pub parent_version_id: Option<String>,
    pub immutable_original: bool,
    pub working_copy_state: WorkingCopyStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfficeWorkspaceStoreRecordV1 {
    pub schema_version: u32,
    pub sequence: u64,
    pub artifact_kind: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub object_relative_path: String,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OfficeWorkspaceStoreIndexV1 {
    schema_version: u32,
    record_count: u64,
    terminal_sha256: String,
    object_count: u64,
    total_bytes: u64,
    index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficeWorkspaceStoreVerificationV1 {
    pub record_count: u64,
    pub terminal_sha256: String,
    pub object_count: u64,
    pub total_bytes: u64,
    pub orphan_temporary_files_removed: u64,
    pub orphan_objects_removed: u64,
    pub index_repaired: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRecoveryDispositionV1 {
    NotStarted,
    AppliedVerified,
    Stale,
    Locked,
    Ambiguous,
}

pub struct WorkspaceRecoveryProbeV1<'a> {
    pub root: &'a Path,
    pub operation: OfficeFileWorkerOperationV1,
    pub source_relative_path: &'a str,
    pub destination_relative_path: &'a str,
    pub expected_source_sha256: &'a str,
    pub expected_destination_sha256: &'a str,
    pub maximum_bytes: u64,
}

#[derive(Debug)]
pub struct OfficeWorkspaceStore {
    root: PathBuf,
    verification: OfficeWorkspaceStoreVerificationV1,
}

pub fn create_workspace_root_binding(
    root: &Path,
    workspace_id: &str,
    valid_from_unix_ms: u64,
    valid_until_unix_ms: u64,
) -> Result<WorkspaceRootBindingV1, String> {
    validate_id(workspace_id, "workspace_id").map_err(|error| error.to_string())?;
    if !root.is_dir() {
        return Err("workspace root must already be a directory".to_owned());
    }
    reject_reparse_path(root, root)?;
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    let root_text = canonical_text(&canonical);
    if root_text.starts_with("//") {
        return Err("network workspace roots are prohibited".to_owned());
    }
    let descriptor = d2i_windows_host::harden_path_for_current_user(&canonical)
        .map_err(|error| error.to_string())?;
    WorkspaceRootBindingV1 {
        schema_version: 1,
        workspace_id: workspace_id.to_owned(),
        canonical_root: root_text.clone(),
        root_identity: sha256_bytes(root_text.to_ascii_lowercase().as_bytes()),
        volume_identity: volume_identity(&canonical),
        security_descriptor_sha256: sha256_bytes(&descriptor),
        reparse_forbidden: true,
        symlink_forbidden: true,
        network_share_allowed: false,
        removable_media_allowed: false,
        valid_from_unix_ms,
        valid_until_unix_ms,
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

pub fn initialize_office_workspace_store(root: &Path) -> Result<OfficeWorkspaceStore, String> {
    if root.exists() {
        return Err("office workspace store already exists".to_owned());
    }
    for directory in [
        "objects",
        "ledger",
        "workspace-bindings",
        "artifacts",
        "versions",
        "operations",
        "provenance",
        "observations",
    ] {
        fs::create_dir_all(root.join(directory)).map_err(|error| error.to_string())?;
    }
    d2i_windows_host::harden_path_for_current_user(root).map_err(|error| error.to_string())?;
    let mut store = OfficeWorkspaceStore {
        root: root.to_path_buf(),
        verification: empty_store_verification(),
    };
    store.persist_index()?;
    Ok(store)
}

pub fn recover_office_workspace_store(root: &Path) -> Result<OfficeWorkspaceStore, String> {
    if !root.join("objects").is_dir() || !root.join("ledger").is_dir() {
        return Err("office workspace store layout is incomplete".to_owned());
    }
    reject_reparse_path(root, root)?;
    let mut verification = empty_store_verification();
    for directory in ["objects", "ledger"] {
        for entry in fs::read_dir(root.join(directory))
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') && name.ends_with(".tmp") {
                fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
                verification.orphan_temporary_files_removed = verification
                    .orphan_temporary_files_removed
                    .saturating_add(1);
            }
        }
    }
    let mut referenced_objects = BTreeSet::new();
    let mut entries = fs::read_dir(root.join("ledger"))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let metadata = entry.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_file() {
            return Err("workspace ledger contains a non-file object".to_owned());
        }
        let bytes = read_bounded_file(&entry.path(), MAX_WORKER_BYTES as u64)?;
        let record: OfficeWorkspaceStoreRecordV1 =
            parse_json_strict(&bytes).map_err(|error| error.to_string())?;
        if record.sequence != verification.record_count
            || record.previous_record_sha256 != verification.terminal_sha256
            || hash_without(&record, &["record_sha256"])? != record.record_sha256
        {
            return Err("workspace ledger chain differs".to_owned());
        }
        validate_relative_path_token(&record.object_relative_path)
            .map_err(|error| error.to_string())?;
        let object = resolve_workspace_path(root, &record.object_relative_path, false)?;
        referenced_objects.insert(record.object_relative_path.clone());
        let object_bytes = read_bounded_file(&object, MAX_WORKER_BYTES as u64)?;
        if sha256_bytes(&object_bytes) != record.artifact_sha256 {
            return Err("workspace content-addressed object differs".to_owned());
        }
        verification.record_count = verification.record_count.saturating_add(1);
        verification.terminal_sha256 = record.record_sha256;
        verification.object_count = verification.object_count.saturating_add(1);
        verification.total_bytes = verification
            .total_bytes
            .saturating_add(object_bytes.len() as u64);
    }
    for entry in fs::read_dir(root.join("objects"))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?
    {
        let relative = format!("objects/{}", entry.file_name().to_string_lossy());
        if !referenced_objects.contains(&relative) {
            let metadata = entry.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("workspace object store contains an unsafe orphan".to_owned());
            }
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
            verification.orphan_objects_removed =
                verification.orphan_objects_removed.saturating_add(1);
        }
    }
    let mut store = OfficeWorkspaceStore {
        root: root.to_path_buf(),
        verification,
    };
    let expected = store.index()?;
    let index_path = root.join("index.json");
    let index_matches = fs::read(&index_path)
        .ok()
        .and_then(|bytes| parse_json_strict::<OfficeWorkspaceStoreIndexV1>(&bytes).ok())
        .is_some_and(|actual| actual == expected);
    if !index_matches {
        store.verification.index_repaired = true;
        store.persist_index()?;
    }
    Ok(store)
}

impl OfficeWorkspaceStore {
    pub fn append<T: Serialize>(
        &mut self,
        artifact_kind: &str,
        artifact_id: &str,
        artifact: &T,
        now_unix_ms: u64,
    ) -> Result<OfficeWorkspaceStoreRecordV1, String> {
        validate_store_label(artifact_kind)?;
        validate_store_label(artifact_id)?;
        let bytes = d2i_office_capability::canonical_json_bytes(artifact)
            .map_err(|error| error.to_string())?;
        reject_sensitive_artifact(&bytes)?;
        if self
            .verification
            .total_bytes
            .saturating_add(bytes.len() as u64)
            > MAX_STORE_BYTES
        {
            return Err("office workspace store exceeds bounded bytes".to_owned());
        }
        let artifact_sha256 = sha256_bytes(&bytes);
        let name = artifact_sha256.trim_start_matches("sha256:");
        let relative = format!("objects/{name}.json");
        let object_path = self.root.join(&relative);
        if object_path.exists() {
            return Err("office workspace store rejects duplicate object append".to_owned());
        }
        atomic_write_new(&object_path, &bytes, artifact_id)?;
        let mut record = OfficeWorkspaceStoreRecordV1 {
            schema_version: OFFICE_WORKSPACE_STORE_SCHEMA_VERSION,
            sequence: self.verification.record_count,
            artifact_kind: artifact_kind.to_owned(),
            artifact_id: artifact_id.to_owned(),
            artifact_sha256,
            object_relative_path: relative,
            recorded_at_unix_ms: now_unix_ms,
            previous_record_sha256: self.verification.terminal_sha256.clone(),
            record_sha256: ZERO_HASH.to_owned(),
        };
        record.record_sha256 = hash_without(&record, &["record_sha256"])?;
        let ledger = self
            .root
            .join("ledger")
            .join(format!("{:020}.json", record.sequence));
        atomic_write_new(
            &ledger,
            &d2i_office_capability::canonical_json_bytes(&record)
                .map_err(|error| error.to_string())?,
            artifact_id,
        )?;
        self.verification.record_count = self.verification.record_count.saturating_add(1);
        self.verification.terminal_sha256 = record.record_sha256.clone();
        self.verification.object_count = self.verification.object_count.saturating_add(1);
        self.verification.total_bytes = self
            .verification
            .total_bytes
            .saturating_add(bytes.len() as u64);
        self.persist_index()?;
        Ok(record)
    }

    pub fn verification(&self) -> &OfficeWorkspaceStoreVerificationV1 {
        &self.verification
    }

    fn index(&self) -> Result<OfficeWorkspaceStoreIndexV1, String> {
        let mut index = OfficeWorkspaceStoreIndexV1 {
            schema_version: 1,
            record_count: self.verification.record_count,
            terminal_sha256: self.verification.terminal_sha256.clone(),
            object_count: self.verification.object_count,
            total_bytes: self.verification.total_bytes,
            index_sha256: ZERO_HASH.to_owned(),
        };
        index.index_sha256 = hash_without(&index, &["index_sha256"])?;
        Ok(index)
    }

    fn persist_index(&mut self) -> Result<(), String> {
        let bytes = d2i_office_capability::canonical_json_bytes(&self.index()?)
            .map_err(|error| error.to_string())?;
        atomic_write_replace(&self.root.join("index.json"), &bytes, "index")
    }
}

pub struct OfficeWorkspaceKrnDispatcherV1 {
    worker_executable: PathBuf,
    worker_executable_sha256: String,
    root: PathBuf,
    root_binding: WorkspaceRootBindingV1,
    profile: OfficeWorkspaceProfileV1,
    activation_ledger: WorkspaceActivationLedgerV1,
    spawned_worker_count: u32,
}

impl OfficeWorkspaceKrnDispatcherV1 {
    pub fn new(
        worker_executable: PathBuf,
        expected_worker_sha256: String,
        root: PathBuf,
        root_binding: WorkspaceRootBindingV1,
        profile: OfficeWorkspaceProfileV1,
        profile_key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<Self, String> {
        profile
            .validate_signature(profile_key)
            .map_err(|error| error.to_string())?;
        root_binding
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        if profile.workspace_root_binding_sha256 != root_binding.binding_sha256
            || profile.workspace_id != root_binding.workspace_id
            || !(profile.valid_from_unix_ms <= now_unix_ms
                && now_unix_ms < profile.valid_until_unix_ms)
            || !(root_binding.valid_from_unix_ms <= now_unix_ms
                && now_unix_ms < root_binding.valid_until_unix_ms)
        {
            return Err("workspace profile and root binding are stale or differ".to_owned());
        }
        verify_root_binding(&root, &root_binding)?;
        let metadata =
            fs::symlink_metadata(&worker_executable).map_err(|error| error.to_string())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("office file worker is not a regular executable".to_owned());
        }
        let actual =
            sha256_bytes(&fs::read(&worker_executable).map_err(|error| error.to_string())?);
        if actual != expected_worker_sha256 {
            return Err("office file worker executable hash differs".to_owned());
        }
        Ok(Self {
            worker_executable,
            worker_executable_sha256: expected_worker_sha256,
            root,
            root_binding,
            profile,
            activation_ledger: WorkspaceActivationLedgerV1::default(),
            spawned_worker_count: 0,
        })
    }

    pub fn execute(
        &mut self,
        dispatch: OfficeWorkspaceDispatchV1<'_>,
    ) -> Result<(OfficeFileWorkerResponseV1, WorkspaceOperationReceiptV1), String> {
        let OfficeWorkspaceDispatchV1 {
            intent,
            binding,
            admission,
            source,
            authority,
            destination_relative_path,
            approved_content,
            now_unix_ms,
        } = dispatch;
        intent
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        binding
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        source
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        admission.validate().map_err(|error| error.to_string())?;
        validate_authority_context(authority)?;
        if admission.adapter_kind != AdapterKindV1::OfficeWorkspace
            || admission.capability_id != operation_capability(intent.operation)
            || admission.policy_decision_sha256 != binding.policy_decision_sha256
            || admission.admission_sha256 != binding.cognitive_activation_admission_sha256
            || intent.intent_sha256 != binding.operation_intent_sha256
            || binding.workspace_profile_sha256 != self.profile.profile_sha256
            || binding.workspace_root_binding_sha256 != self.root_binding.binding_sha256
            || Some(source.artifact_sha256.as_str()) != binding.source_artifact_sha256.as_deref()
            || Some(source.current_generation) != binding.source_generation
            || intent.source_artifact_id.as_deref() != Some(source.artifact_id.as_str())
            || intent.expected_source_content_sha256.as_deref()
                != Some(source.content_sha256.as_str())
            || intent.expected_source_generation != Some(source.current_generation)
            || intent.workspace_id != self.profile.workspace_id
            || source.workspace_id != self.profile.workspace_id
            || !self
                .profile
                .role_scope_ids
                .contains(&authority.role_scope_id)
            || intent.role_instance_id != authority.role_instance_id
            || intent.case_id != authority.case_id
            || binding.role_contract_sha256 != authority.role_contract_sha256
            || binding.role_instance_sha256 != authority.role_instance_sha256
            || binding.case_sha256 != authority.case_sha256
            || binding.lease_sha256 != authority.lease_sha256
            || binding.work_grant_sha256 != authority.work_grant_sha256
            || !self.profile.allowed_operations.contains(&intent.operation)
            || admission.admitted_at_unix_seconds > now_unix_ms / 1_000
            || now_unix_ms / 1_000 >= admission.expires_at_unix_seconds
        {
            return Err(
                "office mutation differs from policy, activation, or artifact binding".to_owned(),
            );
        }
        if source.immutable_original
            && matches!(
                intent.operation,
                WorkspaceOperationClassV1::RenameArtifact
                    | WorkspaceOperationClassV1::MoveArtifact
                    | WorkspaceOperationClassV1::CommitVersion
            )
        {
            return Err("immutable original mutation is prohibited".to_owned());
        }
        self.activation_ledger
            .consume(
                binding,
                &admission.policy_decision_sha256,
                &admission.admission_sha256,
                now_unix_ms,
            )
            .map_err(|error| error.to_string())?;
        verify_root_binding(&self.root, &self.root_binding)?;
        let operation = match intent.operation {
            WorkspaceOperationClassV1::CreateWorkingCopy
            | WorkspaceOperationClassV1::CopyArtifact
            | WorkspaceOperationClassV1::ExportCopy
            | WorkspaceOperationClassV1::RestoreVersion => OfficeFileWorkerOperationV1::Copy,
            WorkspaceOperationClassV1::RenameArtifact => OfficeFileWorkerOperationV1::Rename,
            WorkspaceOperationClassV1::MoveArtifact => OfficeFileWorkerOperationV1::Move,
            WorkspaceOperationClassV1::CommitVersion => OfficeFileWorkerOperationV1::CommitVersion,
            _ => return Err("operation is not a trusted file mutation".to_owned()),
        };
        let destination = Path::new(destination_relative_path);
        let destination_filename = destination
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "workspace destination filename is missing".to_owned())?;
        let destination_folder = destination
            .parent()
            .and_then(|value| value.to_str())
            .ok_or_else(|| "workspace destination folder is missing".to_owned())?
            .replace('\\', "/");
        if intent.destination_filename.as_deref() != Some(destination_filename)
            || intent.destination_folder_id.as_deref()
                != Some(format!("folder.{destination_folder}").as_str())
            || binding.expected_output_scope_token != format!("folder.{destination_folder}")
            || intent.approved_content_sha256.as_deref()
                != approved_content.map(sha256_bytes).as_deref()
        {
            return Err("workspace destination or approved content differs from intent".to_owned());
        }
        let request = OfficeFileWorkerRequestV1 {
            schema_version: 1,
            request_id: binding.one_time_use_id.clone(),
            workspace_root: self.root_binding.canonical_root.clone(),
            workspace_root_binding_sha256: self.root_binding.binding_sha256.clone(),
            operation,
            source_relative_path: source.relative_path_token.clone(),
            destination_relative_path: destination_relative_path.to_owned(),
            expected_source_sha256: source.content_sha256.clone(),
            expected_source_generation: source.current_generation,
            approved_content_hex: approved_content.map(hex_encode),
            approved_content_sha256: approved_content.map(sha256_bytes),
            maximum_bytes: self.profile.maximum_file_bytes,
        };
        let started = now_unix_ms;
        let response = spawn_file_worker(&self.worker_executable, &request)?;
        self.spawned_worker_count = self.spawned_worker_count.saturating_add(1);
        let verification = verify_worker_result(&self.root, &request, &response)?;
        let receipt = WorkspaceOperationReceiptV1 {
            schema_version: 1,
            receipt_id: format!("receipt.{}", binding.one_time_use_id),
            operation_intent_sha256: intent.intent_sha256.clone(),
            binding_sha256: binding.binding_sha256.clone(),
            source_artifact_sha256: Some(source.artifact_sha256.clone()),
            source_generation: Some(source.current_generation),
            destination_artifact_sha256: Some(response.destination_sha256.clone()),
            destination_generation: Some(
                if operation == OfficeFileWorkerOperationV1::CommitVersion {
                    source.current_generation.saturating_add(1)
                } else {
                    1
                },
            ),
            operation_class: intent.operation,
            status: WorkspaceOperationStatusV1::Verified,
            structured_result_code: "verified-file-operation".to_owned(),
            bytes_processed: response.bytes_processed,
            atomic_commit: response.atomic_commit,
            old_identity_sha256: Some(response.old_identity_sha256.clone()),
            new_identity_sha256: Some(response.new_identity_sha256.clone()),
            started_at_unix_ms: started,
            completed_at_unix_ms: started.saturating_add(1),
            verification_sha256: verification,
            receipt_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        Ok((response, receipt))
    }

    pub fn spawned_worker_count(&self) -> u32 {
        self.spawned_worker_count
    }

    pub fn worker_executable_sha256(&self) -> &str {
        &self.worker_executable_sha256
    }
}

pub fn observe_artifacts(
    root: &Path,
    workspace_id: &str,
    artifacts: &[OfficeArtifactReferenceV1],
    observation_id: &str,
    now_unix_ms: u64,
    freshness_ms: u64,
) -> Result<WorkspaceObservationSnapshotV1, String> {
    validate_id(observation_id, "observation_id").map_err(|error| error.to_string())?;
    if artifacts.is_empty() || artifacts.len() > 512 {
        return Err("artifact observation count is outside bounds".to_owned());
    }
    let mut artifact_ids = Vec::with_capacity(artifacts.len());
    let mut generations = Vec::with_capacity(artifacts.len());
    let mut hashes = Vec::with_capacity(artifacts.len());
    let mut sizes = Vec::with_capacity(artifacts.len());
    let mut formats = Vec::with_capacity(artifacts.len());
    let mut locks = Vec::with_capacity(artifacts.len());
    let mut write_states = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        artifact
            .validate_integrity()
            .map_err(|error| error.to_string())?;
        if artifact.workspace_id != workspace_id {
            return Err("cross-workspace artifact observation is prohibited".to_owned());
        }
        let path = resolve_workspace_path(root, &artifact.relative_path_token, false)?;
        let bytes = read_bounded_file(&path, 64 * 1024 * 1024)?;
        artifact_ids.push(artifact.artifact_id.clone());
        generations.push(artifact.current_generation);
        hashes.push(sha256_bytes(&bytes));
        sizes.push(bytes.len() as u64);
        formats.push(artifact.file_format_id.clone());
        locks.push(if office_lock_path(&path).exists() {
            d2i_office_capability::ArtifactLockStateV1::OfficeLockPresent
        } else {
            d2i_office_capability::ArtifactLockStateV1::Unlocked
        });
        write_states.push(if artifact.immutable_original {
            "immutable-original".to_owned()
        } else {
            "policy-bound-working-copy".to_owned()
        });
    }
    WorkspaceObservationSnapshotV1 {
        schema_version: 1,
        observation_id: observation_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        artifact_ids,
        artifact_generations: generations,
        content_sha256s: hashes,
        sizes,
        formats,
        lock_states: locks,
        write_states,
        observed_at_unix_ms: now_unix_ms,
        freshness_expires_at_unix_ms: now_unix_ms.saturating_add(freshness_ms),
        observation_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

pub fn classify_workspace_operation_recovery(
    probe: WorkspaceRecoveryProbeV1<'_>,
) -> Result<WorkspaceRecoveryDispositionV1, String> {
    validate_hash(probe.expected_source_sha256, "recovery source")
        .map_err(|error| error.to_string())?;
    validate_hash(probe.expected_destination_sha256, "recovery destination")
        .map_err(|error| error.to_string())?;
    let source = resolve_workspace_path(probe.root, probe.source_relative_path, true)?;
    let destination = resolve_workspace_path(probe.root, probe.destination_relative_path, true)?;
    if source.exists() && office_lock_path(&source).exists() {
        return Ok(WorkspaceRecoveryDispositionV1::Locked);
    }
    let source_hash = if source.exists() {
        Some(sha256_bytes(&read_bounded_file(
            &source,
            probe.maximum_bytes,
        )?))
    } else {
        None
    };
    let destination_hash = if destination.exists() {
        Some(sha256_bytes(&read_bounded_file(
            &destination,
            probe.maximum_bytes,
        )?))
    } else {
        None
    };
    if destination_hash.as_deref() == Some(probe.expected_destination_sha256) {
        return Ok(match probe.operation {
            OfficeFileWorkerOperationV1::Rename | OfficeFileWorkerOperationV1::Move
                if source_hash.is_none() =>
            {
                WorkspaceRecoveryDispositionV1::AppliedVerified
            }
            OfficeFileWorkerOperationV1::Copy | OfficeFileWorkerOperationV1::CommitVersion => {
                WorkspaceRecoveryDispositionV1::AppliedVerified
            }
            _ => WorkspaceRecoveryDispositionV1::Ambiguous,
        });
    }
    if source_hash.as_deref() == Some(probe.expected_source_sha256) && destination_hash.is_none() {
        return Ok(WorkspaceRecoveryDispositionV1::NotStarted);
    }
    if source_hash.is_some() && source_hash.as_deref() != Some(probe.expected_source_sha256) {
        return Ok(WorkspaceRecoveryDispositionV1::Stale);
    }
    Ok(WorkspaceRecoveryDispositionV1::Ambiguous)
}

pub fn artifact_reference_from_file(
    input: ArtifactReferenceInputV1<'_>,
) -> Result<OfficeArtifactReferenceV1, String> {
    let ArtifactReferenceInputV1 {
        root,
        workspace_id,
        artifact_id,
        relative_path,
        generation,
        source_artifact_id,
        parent_version_id,
        immutable_original,
        working_copy_state,
    } = input;
    let path = resolve_workspace_path(root, relative_path, false)?;
    let bytes = read_bounded_file(&path, 64 * 1024 * 1024)?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "artifact file extension is missing".to_owned())?
        .to_ascii_lowercase();
    let artifact_class = match extension.as_str() {
        "xlsx" | "xls" | "xlsm" | "csv" => "office.spreadsheet",
        "ppt" | "pptx" => "office.presentation",
        "hwp" | "hwpx" | "doc" | "docx" | "txt" | "md" => "office.document",
        "pdf" => "office.pdf",
        "png" | "jpg" | "jpeg" | "webp" => "office.image",
        _ => return Err("artifact file format is not approved".to_owned()),
    };
    OfficeArtifactReferenceV1 {
        schema_version: 1,
        artifact_id: artifact_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        relative_path_token: relative_path.to_owned(),
        artifact_class: artifact_class.to_owned(),
        file_format_id: extension,
        content_sha256: sha256_bytes(&bytes),
        byte_length: bytes.len() as u64,
        creation_generation: 1,
        current_generation: generation,
        source_artifact_id,
        parent_version_id,
        immutable_original,
        working_copy_state,
        data_class_ids: vec!["synthetic-internal".to_owned()],
        evidence_ids: vec!["fresh-filesystem-observation".to_owned()],
        artifact_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

pub fn office_file_worker_main() -> Result<(), String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_WORKER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_WORKER_BYTES {
        return Err("office file worker request exceeds limit".to_owned());
    }
    let request: OfficeFileWorkerRequestV1 =
        parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    let response = execute_file_worker_request(&request)?;
    serde_json::to_writer(std::io::stdout(), &response).map_err(|error| error.to_string())
}

pub fn execute_file_worker_request(
    request: &OfficeFileWorkerRequestV1,
) -> Result<OfficeFileWorkerResponseV1, String> {
    validate_worker_request(request)?;
    let root = PathBuf::from(&request.workspace_root);
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    if canonical_text(&canonical) != request.workspace_root {
        return Err("worker root differs from canonical binding".to_owned());
    }
    reject_reparse_path(&canonical, &canonical)?;
    let source = resolve_workspace_path(&canonical, &request.source_relative_path, false)?;
    let destination = resolve_workspace_path(&canonical, &request.destination_relative_path, true)?;
    if office_lock_path(&source).exists() {
        return Err("office-style lock is present".to_owned());
    }
    let source_bytes = read_bounded_file(&source, request.maximum_bytes)?;
    let source_sha256 = sha256_bytes(&source_bytes);
    if source_sha256 != request.expected_source_sha256 {
        return Err("source artifact is stale".to_owned());
    }
    if destination.exists() {
        return Err("destination already exists".to_owned());
    }
    let old_identity_sha256 = file_identity(&canonical, &source, &source_bytes)?;
    let output_bytes = match request.operation {
        OfficeFileWorkerOperationV1::Copy => {
            atomic_write_new(&destination, &source_bytes, &request.request_id)?;
            source_bytes.clone()
        }
        OfficeFileWorkerOperationV1::Rename | OfficeFileWorkerOperationV1::Move => {
            d2i_windows_host::atomic_move(&source, &destination, false)
                .map_err(|error| error.to_string())?;
            source_bytes.clone()
        }
        OfficeFileWorkerOperationV1::CommitVersion => {
            let content_hex = request
                .approved_content_hex
                .as_deref()
                .ok_or_else(|| "version content is missing".to_owned())?;
            let content = hex_decode(content_hex)?;
            if content.is_empty() || content.len() as u64 > request.maximum_bytes {
                return Err("version content size is outside bounds".to_owned());
            }
            let expected = request
                .approved_content_sha256
                .as_deref()
                .ok_or_else(|| "version content hash is missing".to_owned())?;
            if sha256_bytes(&content) != expected {
                return Err("version content hash differs".to_owned());
            }
            atomic_write_new(&destination, &content, &request.request_id)?;
            content
        }
    };
    let fresh = read_bounded_file(&destination, request.maximum_bytes)?;
    if fresh != output_bytes {
        return Err("post-operation destination verification differs".to_owned());
    }
    if matches!(
        request.operation,
        OfficeFileWorkerOperationV1::Rename | OfficeFileWorkerOperationV1::Move
    ) && source.exists()
    {
        return Err("post-operation source still exists".to_owned());
    }
    let destination_sha256 = sha256_bytes(&fresh);
    let new_identity_sha256 = file_identity(&canonical, &destination, &fresh)?;
    let mut response = OfficeFileWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id.clone(),
        source_sha256,
        destination_sha256,
        bytes_processed: fresh.len() as u64,
        atomic_commit: true,
        old_identity_sha256,
        new_identity_sha256,
        response_sha256: ZERO_HASH.to_owned(),
    };
    response.response_sha256 = hash_without(&response, &["response_sha256"])?;
    Ok(response)
}

fn spawn_file_worker(
    executable: &Path,
    request: &OfficeFileWorkerRequestV1,
) -> Result<OfficeFileWorkerResponseV1, String> {
    let mut command = Command::new(executable);
    command
        .arg("--file-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        command.env_remove(variable);
    }
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    serde_json::to_writer(
        child
            .stdin
            .as_mut()
            .ok_or_else(|| "worker stdin is unavailable".to_owned())?,
        request,
    )
    .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_millis(WORKER_TIMEOUT_MS);
    loop {
        if child
            .try_wait()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("office file worker exceeded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "office file worker failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let response: OfficeFileWorkerResponseV1 =
        parse_json_strict(&output.stdout).map_err(|error| error.to_string())?;
    if response.response_sha256 != hash_without(&response, &["response_sha256"])?
        || response.request_id != request.request_id
    {
        return Err("office file worker response binding differs".to_owned());
    }
    Ok(response)
}

fn verify_worker_result(
    root: &Path,
    request: &OfficeFileWorkerRequestV1,
    response: &OfficeFileWorkerResponseV1,
) -> Result<String, String> {
    let destination = resolve_workspace_path(root, &request.destination_relative_path, false)?;
    let bytes = read_bounded_file(&destination, request.maximum_bytes)?;
    let hash = sha256_bytes(&bytes);
    if hash != response.destination_sha256 || bytes.len() as u64 != response.bytes_processed {
        return Err("fresh dispatcher verification differs from worker receipt".to_owned());
    }
    canonical_sha256(&serde_json::json!({
        "destination_relative_path": request.destination_relative_path,
        "destination_sha256": hash,
        "bytes": bytes.len(),
        "source_absent": matches!(request.operation, OfficeFileWorkerOperationV1::Rename | OfficeFileWorkerOperationV1::Move),
    }))
    .map_err(|error| error.to_string())
}

fn verify_root_binding(root: &Path, binding: &WorkspaceRootBindingV1) -> Result<(), String> {
    binding
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    let canonical = root.canonicalize().map_err(|error| error.to_string())?;
    if canonical_text(&canonical) != binding.canonical_root {
        return Err("workspace canonical root differs from binding".to_owned());
    }
    reject_reparse_path(&canonical, &canonical)?;
    let descriptor = d2i_windows_host::path_security_descriptor(&canonical)
        .map_err(|error| error.to_string())?;
    if sha256_bytes(&descriptor) != binding.security_descriptor_sha256 {
        return Err("workspace security descriptor differs from binding".to_owned());
    }
    Ok(())
}

fn validate_worker_request(request: &OfficeFileWorkerRequestV1) -> Result<(), String> {
    if request.schema_version != 1 || request.expected_source_generation == 0 {
        return Err("worker request version or generation is invalid".to_owned());
    }
    validate_id(&request.request_id, "request_id").map_err(|error| error.to_string())?;
    validate_hash(
        &request.workspace_root_binding_sha256,
        "workspace root binding",
    )
    .map_err(|error| error.to_string())?;
    validate_hash(&request.expected_source_sha256, "source").map_err(|error| error.to_string())?;
    validate_relative_path_token(&request.source_relative_path)
        .map_err(|error| error.to_string())?;
    validate_relative_path_token(&request.destination_relative_path)
        .map_err(|error| error.to_string())?;
    if request
        .source_relative_path
        .eq_ignore_ascii_case(&request.destination_relative_path)
        || request.maximum_bytes == 0
        || request.maximum_bytes > 64 * 1024 * 1024
    {
        return Err("worker source, destination, or byte bound is invalid".to_owned());
    }
    match request.operation {
        OfficeFileWorkerOperationV1::CommitVersion => {
            if request.approved_content_hex.is_none() || request.approved_content_sha256.is_none() {
                return Err("version commit requires exact approved bytes and hash".to_owned());
            }
        }
        _ if request.approved_content_hex.is_some()
            || request.approved_content_sha256.is_some() =>
        {
            return Err("non-version operation cannot carry content".to_owned());
        }
        _ => {}
    }
    Ok(())
}

fn validate_authority_context(context: &OfficeWorkspaceAuthorityContextV1) -> Result<(), String> {
    for (value, label) in [
        (&context.role_scope_id, "role_scope_id"),
        (&context.role_instance_id, "role_instance_id"),
        (&context.case_id, "case_id"),
    ] {
        validate_id(value, label).map_err(|error| error.to_string())?;
    }
    for (value, label) in [
        (&context.role_contract_sha256, "role contract"),
        (&context.role_instance_sha256, "role instance"),
        (&context.case_sha256, "Case"),
        (&context.lease_sha256, "lease"),
        (&context.work_grant_sha256, "Work Grant"),
    ] {
        validate_hash(value, label).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn resolve_workspace_path(
    root: &Path,
    token: &str,
    allow_missing_leaf: bool,
) -> Result<PathBuf, String> {
    validate_relative_path_token(token).map_err(|error| error.to_string())?;
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    let relative = Path::new(token);
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("workspace path token has a non-normal component".to_owned());
    }
    let mut current = canonical_root.clone();
    let components = relative.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(segment) = component else {
            return Err("workspace path component is invalid".to_owned());
        };
        current.push(segment);
        let is_leaf = index + 1 == components.len();
        if current.exists() {
            reject_reparse_path(&canonical_root, &current)?;
            if !is_leaf && !current.is_dir() {
                return Err("workspace path parent is not a directory".to_owned());
            }
        } else if !is_leaf || !allow_missing_leaf {
            return Err("workspace path does not exist".to_owned());
        }
    }
    let parent = current
        .parent()
        .ok_or_else(|| "workspace path has no parent".to_owned())?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !path_starts_with_case_insensitive(&parent, &canonical_root) {
        return Err("workspace path escapes the approved root".to_owned());
    }
    Ok(current)
}

fn reject_reparse_path(root: &Path, path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Err("symbolic links are prohibited in workspace paths".to_owned());
    }
    #[cfg(windows)]
    if d2i_windows_host::is_reparse_point(path).map_err(|error| error.to_string())? {
        return Err("reparse points and junctions are prohibited".to_owned());
    }
    let canonical = path.canonicalize().map_err(|error| error.to_string())?;
    let canonical_root = root.canonicalize().map_err(|error| error.to_string())?;
    if !path_starts_with_case_insensitive(&canonical, &canonical_root) {
        return Err("resolved workspace path escapes the approved root".to_owned());
    }
    Ok(())
}

fn path_starts_with_case_insensitive(path: &Path, root: &Path) -> bool {
    let path = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let root = root
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    path == root
        || path
            .strip_prefix(&root)
            .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn office_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    path.with_file_name(format!("~${name}"))
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err("workspace artifact is not a bounded regular file".to_owned());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn atomic_write_new(path: &Path, bytes: &[u8], marker: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "destination parent is missing".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    reject_reparse_path(parent, parent)?;
    let safe_marker = marker
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .take(24)
        .map(char::from)
        .collect::<String>();
    let temp = parent.join(format!(".{safe_marker}.tmp"));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    d2i_windows_host::atomic_move(&temp, path, false).map_err(|error| error.to_string())
}

fn atomic_write_replace(path: &Path, bytes: &[u8], marker: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "destination parent is missing".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = parent.join(format!(".{marker}.tmp"));
    if temp.exists() {
        fs::remove_file(&temp).map_err(|error| error.to_string())?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    d2i_windows_host::atomic_move(&temp, path, true).map_err(|error| error.to_string())
}

fn file_identity(root: &Path, path: &Path, bytes: &[u8]) -> Result<String, String> {
    let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
    canonical_sha256(&serde_json::json!({
        "relative_path": relative.to_string_lossy().replace('\\', "/"),
        "content_sha256": sha256_bytes(bytes),
        "size": bytes.len(),
        "root_identity": sha256_bytes(root.to_string_lossy().to_ascii_lowercase().as_bytes()),
    }))
    .map_err(|error| error.to_string())
}

fn volume_identity(path: &Path) -> String {
    let prefix = path.components().next().map_or_else(String::new, |value| {
        value.as_os_str().to_string_lossy().to_ascii_lowercase()
    });
    sha256_bytes(prefix.as_bytes())
}

pub(crate) fn canonical_text(path: &Path) -> String {
    let text = path.to_string_lossy();
    let normalized = if let Some(value) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{value}")
    } else if let Some(value) = text.strip_prefix(r"\\?\") {
        value.to_owned()
    } else {
        text.into_owned()
    };
    normalized.replace('\\', "/")
}

fn operation_capability(operation: WorkspaceOperationClassV1) -> &'static str {
    match operation {
        WorkspaceOperationClassV1::ListArtifacts
        | WorkspaceOperationClassV1::InspectArtifact
        | WorkspaceOperationClassV1::CompareIdentity => "workspace.read",
        _ => "workspace.write",
    }
}

fn hash_without<T: Serialize>(value: &T, fields: &[&str]) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "hashed artifact is not an object".to_owned())?;
    for field in fields {
        object.remove(*field);
    }
    canonical_sha256(&value).map_err(|error| error.to_string())
}

fn validate_store_label(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err("workspace store label is not bounded".to_owned());
    }
    Ok(())
}

fn reject_sensitive_artifact(bytes: &[u8]) -> Result<(), String> {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    for marker in [
        "password",
        "api_key",
        "client_secret",
        "refresh_token",
        "authorization",
        "bearer ",
        "raw_absolute_path",
        "command_line",
        "powershell",
        "run_python",
    ] {
        if lower.contains(marker) {
            return Err("workspace store rejects sensitive or executable material".to_owned());
        }
    }
    Ok(())
}

fn empty_store_verification() -> OfficeWorkspaceStoreVerificationV1 {
    OfficeWorkspaceStoreVerificationV1 {
        record_count: 0,
        terminal_sha256: ZERO_HASH.to_owned(),
        object_count: 0,
        total_bytes: 0,
        orphan_temporary_files_removed: 0,
        orphan_objects_removed: 0,
        index_repaired: false,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0
        || value.len() > MAX_WORKER_BYTES * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("approved content hex is invalid".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos());
        std::env::temp_dir().join(format!(
            "d2i-office100-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn direct_worker_copy_is_atomic_and_rejects_stale_lock_and_traversal() {
        let root = temporary_root("worker");
        fs::create_dir_all(root.join("incoming"))
            .unwrap_or_else(|error| panic!("create root: {error}"));
        fs::create_dir_all(root.join("working"))
            .unwrap_or_else(|error| panic!("create working: {error}"));
        fs::write(root.join("incoming/report.hwpx"), b"synthetic-hwpx")
            .unwrap_or_else(|error| panic!("write fixture: {error}"));
        let canonical = root
            .canonicalize()
            .unwrap_or_else(|error| panic!("canonical root: {error}"));
        let request = OfficeFileWorkerRequestV1 {
            schema_version: 1,
            request_id: "worker-copy-1".to_owned(),
            workspace_root: canonical_text(&canonical),
            workspace_root_binding_sha256: sha256_bytes(b"binding"),
            operation: OfficeFileWorkerOperationV1::Copy,
            source_relative_path: "incoming/report.hwpx".to_owned(),
            destination_relative_path: "working/report.hwpx".to_owned(),
            expected_source_sha256: sha256_bytes(b"synthetic-hwpx"),
            expected_source_generation: 1,
            approved_content_hex: None,
            approved_content_sha256: None,
            maximum_bytes: 4096,
        };
        execute_file_worker_request(&request)
            .unwrap_or_else(|error| panic!("worker copy: {error}"));
        assert_eq!(
            fs::read(root.join("working/report.hwpx"))
                .unwrap_or_else(|error| panic!("read output: {error}")),
            b"synthetic-hwpx"
        );
        let mut stale = request.clone();
        stale.request_id = "worker-copy-2".to_owned();
        stale.destination_relative_path = "working/stale.hwpx".to_owned();
        stale.expected_source_sha256 = sha256_bytes(b"stale");
        assert!(execute_file_worker_request(&stale).is_err());
        let mut traversal = stale;
        traversal.destination_relative_path = "../outside.hwpx".to_owned();
        assert!(execute_file_worker_request(&traversal).is_err());
        fs::write(root.join("incoming/~$report.hwpx"), b"lock")
            .unwrap_or_else(|error| panic!("write lock: {error}"));
        let mut locked = request;
        locked.request_id = "worker-copy-3".to_owned();
        locked.destination_relative_path = "working/locked.hwpx".to_owned();
        assert!(execute_file_worker_request(&locked).is_err());
        fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }

    #[test]
    fn protected_store_recovers_orphans_and_repairs_index() {
        let root = temporary_root("store");
        let mut store = initialize_office_workspace_store(&root)
            .unwrap_or_else(|error| panic!("initialize store: {error}"));
        for window in 'a'..='h' {
            store
                .append(
                    "crash-window",
                    &format!("window-{window}"),
                    &serde_json::json!({"window": window.to_string(), "outcome": "recovered"}),
                    u64::from(window as u32),
                )
                .unwrap_or_else(|error| panic!("append {window}: {error}"));
        }
        fs::write(root.join("objects/.orphan.tmp"), b"orphan")
            .unwrap_or_else(|error| panic!("orphan: {error}"));
        fs::write(root.join("objects/uncommitted.json"), b"uncommitted")
            .unwrap_or_else(|error| panic!("uncommitted object: {error}"));
        fs::write(root.join("index.json"), b"{}")
            .unwrap_or_else(|error| panic!("damage index: {error}"));
        drop(store);
        let recovered = recover_office_workspace_store(&root)
            .unwrap_or_else(|error| panic!("recover store: {error}"));
        assert_eq!(recovered.verification().record_count, 8);
        assert_eq!(recovered.verification().orphan_temporary_files_removed, 1);
        assert_eq!(recovered.verification().orphan_objects_removed, 1);
        assert!(recovered.verification().index_repaired);
        fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }

    #[test]
    fn recovery_probe_resolves_windows_a_d_e_f_g_h_without_blind_replay() {
        let root = temporary_root("operation-recovery");
        fs::create_dir_all(root.join("working")).unwrap_or_else(|error| panic!("working: {error}"));
        fs::create_dir_all(root.join("output")).unwrap_or_else(|error| panic!("output: {error}"));
        fs::create_dir_all(root.join("versions"))
            .unwrap_or_else(|error| panic!("versions: {error}"));
        fs::write(root.join("working/report.hwpx"), b"version-one")
            .unwrap_or_else(|error| panic!("source: {error}"));
        let source_hash = sha256_bytes(b"version-one");
        let not_started = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::Rename,
            source_relative_path: "working/report.hwpx",
            destination_relative_path: "working/renamed.hwpx",
            expected_source_sha256: &source_hash,
            expected_destination_sha256: &source_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window A: {error}"));
        assert_eq!(not_started, WorkspaceRecoveryDispositionV1::NotStarted);
        d2i_windows_host::atomic_move(
            &root.join("working/report.hwpx"),
            &root.join("working/renamed.hwpx"),
            false,
        )
        .unwrap_or_else(|error| panic!("rename crash fixture: {error}"));
        let renamed = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::Rename,
            source_relative_path: "working/report.hwpx",
            destination_relative_path: "working/renamed.hwpx",
            expected_source_sha256: &source_hash,
            expected_destination_sha256: &source_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window D: {error}"));
        assert_eq!(renamed, WorkspaceRecoveryDispositionV1::AppliedVerified);

        fs::write(root.join("versions/report-v2.hwpx"), b"version-two")
            .unwrap_or_else(|error| panic!("version crash fixture: {error}"));
        let version_hash = sha256_bytes(b"version-two");
        let versioned = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::CommitVersion,
            source_relative_path: "working/renamed.hwpx",
            destination_relative_path: "versions/report-v2.hwpx",
            expected_source_sha256: &source_hash,
            expected_destination_sha256: &version_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window E: {error}"));
        assert_eq!(versioned, WorkspaceRecoveryDispositionV1::AppliedVerified);

        d2i_windows_host::atomic_move(
            &root.join("versions/report-v2.hwpx"),
            &root.join("output/report-v2.hwpx"),
            false,
        )
        .unwrap_or_else(|error| panic!("move crash fixture: {error}"));
        let moved = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::Move,
            source_relative_path: "versions/report-v2.hwpx",
            destination_relative_path: "output/report-v2.hwpx",
            expected_source_sha256: &version_hash,
            expected_destination_sha256: &version_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window F: {error}"));
        assert_eq!(moved, WorkspaceRecoveryDispositionV1::AppliedVerified);

        fs::write(root.join("working/renamed.hwpx"), b"external-change")
            .unwrap_or_else(|error| panic!("stale fixture: {error}"));
        let stale = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::Copy,
            source_relative_path: "working/renamed.hwpx",
            destination_relative_path: "working/copy.hwpx",
            expected_source_sha256: &source_hash,
            expected_destination_sha256: &source_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window G: {error}"));
        assert_eq!(stale, WorkspaceRecoveryDispositionV1::Stale);
        fs::write(root.join("working/~$renamed.hwpx"), b"lock")
            .unwrap_or_else(|error| panic!("lock fixture: {error}"));
        let locked = classify_workspace_operation_recovery(WorkspaceRecoveryProbeV1 {
            root: &root,
            operation: OfficeFileWorkerOperationV1::Copy,
            source_relative_path: "working/renamed.hwpx",
            destination_relative_path: "working/copy.hwpx",
            expected_source_sha256: &source_hash,
            expected_destination_sha256: &source_hash,
            maximum_bytes: 1024,
        })
        .unwrap_or_else(|error| panic!("window H: {error}"));
        assert_eq!(locked, WorkspaceRecoveryDispositionV1::Locked);
        fs::remove_dir_all(root).unwrap_or_else(|error| panic!("cleanup: {error}"));
    }
}
