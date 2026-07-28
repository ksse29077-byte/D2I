use crate::{
    hash_value, json_bytes, sha256_bytes, validate_hash, validate_text, validate_token,
    DesktopActionIntent, DesktopCapability, DesktopError, DesktopOperation, ExecutionPermit,
    MAX_ACTION_PAYLOAD_BYTES,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Immutable identity and capability claim for one adapter implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopAdapterDescriptor {
    pub schema_version: u32,
    pub adapter_id: String,
    pub adapter_version: String,
    pub platform: String,
    pub capabilities: BTreeSet<DesktopCapability>,
    pub concrete_host_adapter: bool,
    pub process_isolated: bool,
    pub network_capable: bool,
}

impl DesktopAdapterDescriptor {
    /// Validates descriptor identity and bounded capability claims.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 {
            return Err(DesktopError::Invalid(
                "adapter descriptor schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.adapter_id, "adapter_id")?;
        validate_token(&self.adapter_version, "adapter_version")?;
        validate_token(&self.platform, "adapter platform")?;
        if self.network_capable
            && !self
                .capabilities
                .contains(&DesktopCapability::BrowserNavigate)
            && !self
                .capabilities
                .contains(&DesktopCapability::BrowserInteract)
            && !self
                .capabilities
                .contains(&DesktopCapability::LaunchProcess)
        {
            return Err(DesktopError::Invalid(
                "network-capable adapter declares no network-relevant capability".to_owned(),
            ));
        }
        Ok(())
    }

    /// Computes the descriptor identity pinned by policy.
    pub fn descriptor_hash(&self) -> Result<String, DesktopError> {
        self.validate()?;
        hash_value(self)
    }
}

/// Side-effect-free adapter preparation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAction {
    pub schema_version: u32,
    pub action_hash: String,
    pub adapter_descriptor_hash: String,
    pub precondition_hash: String,
    pub prepared_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub reversible: bool,
    pub preparation_hash: String,
}

#[derive(Serialize)]
struct PreparationDigest<'a> {
    schema_version: u32,
    action_hash: &'a str,
    adapter_descriptor_hash: &'a str,
    precondition_hash: &'a str,
    prepared_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    reversible: bool,
}

impl PreparedAction {
    pub(crate) fn create(
        intent: &DesktopActionIntent,
        descriptor: &DesktopAdapterDescriptor,
        precondition_hash: String,
        prepared_at_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        validate_hash(&precondition_hash, "precondition_hash")?;
        if prepared_at_unix_ms < intent.generated_at_unix_ms
            || prepared_at_unix_ms > intent.expires_at_unix_ms
        {
            return Err(DesktopError::Precondition(
                "preparation time is outside action lifetime".to_owned(),
            ));
        }
        let action_hash = intent.action_hash()?;
        let adapter_descriptor_hash = descriptor.descriptor_hash()?;
        let reversible = !matches!(
            intent.operation,
            DesktopOperation::DeletePath { .. } | DesktopOperation::TerminateProcess { .. }
        );
        let digest = PreparationDigest {
            schema_version: 1,
            action_hash: &action_hash,
            adapter_descriptor_hash: &adapter_descriptor_hash,
            precondition_hash: &precondition_hash,
            prepared_at_unix_ms,
            expires_at_unix_ms: intent.expires_at_unix_ms,
            reversible,
        };
        let preparation_hash = hash_value(&digest)?;
        Ok(Self {
            schema_version: 1,
            action_hash,
            adapter_descriptor_hash,
            precondition_hash,
            prepared_at_unix_ms,
            expires_at_unix_ms: intent.expires_at_unix_ms,
            reversible,
            preparation_hash,
        })
    }

    /// Recomputes and validates the preparation digest.
    pub fn validate(&self) -> Result<(), DesktopError> {
        if self.schema_version != 1 || self.prepared_at_unix_ms > self.expires_at_unix_ms {
            return Err(DesktopError::Invalid(
                "prepared action version or lifetime is invalid".to_owned(),
            ));
        }
        validate_hash(&self.action_hash, "prepared action_hash")?;
        validate_hash(
            &self.adapter_descriptor_hash,
            "prepared adapter_descriptor_hash",
        )?;
        validate_hash(&self.precondition_hash, "prepared precondition_hash")?;
        validate_hash(&self.preparation_hash, "preparation_hash")?;
        let digest = PreparationDigest {
            schema_version: self.schema_version,
            action_hash: &self.action_hash,
            adapter_descriptor_hash: &self.adapter_descriptor_hash,
            precondition_hash: &self.precondition_hash,
            prepared_at_unix_ms: self.prepared_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            reversible: self.reversible,
        };
        if hash_value(&digest)? != self.preparation_hash {
            return Err(DesktopError::Integrity(
                "prepared action digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Terminal adapter outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionOutcomeStatus {
    Succeeded,
    Failed,
}

/// Payload-free outcome metadata safe for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionOutcome {
    pub action_hash: String,
    pub adapter_descriptor_hash: String,
    pub status: ActionOutcomeStatus,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub output_hash: String,
    pub output_bytes: u64,
    pub message: String,
}

/// Adapter result with a bounded payload that must not be copied into audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterExecution {
    pub outcome: ActionOutcome,
    pub payload: Vec<u8>,
}

/// Narrow two-phase boundary implemented by reviewed desktop integrations.
pub trait DesktopAdapter {
    /// Returns the immutable descriptor used by policy.
    fn descriptor(&self) -> &DesktopAdapterDescriptor;
    /// Captures preconditions without changing host or external state.
    fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError>;
    /// Commits exactly one permit-bound action.
    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError>;
}

/// Fail-closed default used when no reviewed desktop API is bound.
#[derive(Debug, Clone)]
pub struct UnavailableDesktopAdapter {
    descriptor: DesktopAdapterDescriptor,
}

impl Default for UnavailableDesktopAdapter {
    fn default() -> Self {
        Self {
            descriptor: DesktopAdapterDescriptor {
                schema_version: 1,
                adapter_id: "unavailable.desktop".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                platform: std::env::consts::OS.to_owned(),
                capabilities: BTreeSet::new(),
                concrete_host_adapter: false,
                process_isolated: false,
                network_capable: false,
            },
        }
    }
}

impl DesktopAdapter for UnavailableDesktopAdapter {
    fn descriptor(&self) -> &DesktopAdapterDescriptor {
        &self.descriptor
    }

    fn prepare(
        &mut self,
        _intent: &DesktopActionIntent,
        _now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "no reviewed desktop adapter is configured".to_owned(),
        ))
    }

    fn execute(
        &mut self,
        _intent: &DesktopActionIntent,
        _prepared: &PreparedAction,
        _permit: &ExecutionPermit,
        _payload: Option<&[u8]>,
        _now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "no reviewed desktop adapter is configured".to_owned(),
        ))
    }
}

/// Concrete host adapter limited to bounded reads beneath canonical roots.
#[derive(Debug, Clone)]
pub struct LocalReadOnlyDesktopAdapter {
    descriptor: DesktopAdapterDescriptor,
    canonical_roots: Vec<PathBuf>,
}

impl LocalReadOnlyDesktopAdapter {
    /// Creates a read-only adapter after canonicalizing non-symlink directories.
    pub fn new(roots: &[PathBuf]) -> Result<Self, DesktopError> {
        if roots.is_empty() || roots.len() > 256 {
            return Err(DesktopError::Invalid(
                "local read roots must contain 1..=256 directories".to_owned(),
            ));
        }
        let mut canonical_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let metadata = std::fs::symlink_metadata(root).map_err(|error| DesktopError::Io {
                path: root.display().to_string(),
                message: error.to_string(),
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(DesktopError::Integrity(
                    "local read root must be a non-symlink directory".to_owned(),
                ));
            }
            let canonical = std::fs::canonicalize(root).map_err(|error| DesktopError::Io {
                path: root.display().to_string(),
                message: error.to_string(),
            })?;
            if !canonical_roots.contains(&canonical) {
                canonical_roots.push(canonical);
            }
        }
        Ok(Self {
            descriptor: DesktopAdapterDescriptor {
                schema_version: 1,
                adapter_id: "local-readonly.desktop".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                platform: std::env::consts::OS.to_owned(),
                capabilities: BTreeSet::from([
                    DesktopCapability::ReadFile,
                    DesktopCapability::ListDirectory,
                ]),
                concrete_host_adapter: true,
                process_isolated: false,
                network_capable: false,
            },
            canonical_roots,
        })
    }

    fn confined(&self, path: &str) -> Result<PathBuf, DesktopError> {
        let input = Path::new(path);
        let metadata = std::fs::symlink_metadata(input).map_err(|error| DesktopError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink() {
            return Err(DesktopError::Integrity(
                "symlink desktop targets are rejected".to_owned(),
            ));
        }
        let canonical = std::fs::canonicalize(input).map_err(|error| DesktopError::Io {
            path: path.to_owned(),
            message: error.to_string(),
        })?;
        if !self
            .canonical_roots
            .iter()
            .any(|root| canonical.starts_with(root))
        {
            return Err(DesktopError::AccessDenied(
                "desktop target escapes canonical read roots".to_owned(),
            ));
        }
        Ok(canonical)
    }

    fn snapshot(&self, operation: &DesktopOperation) -> Result<String, DesktopError> {
        match operation {
            DesktopOperation::ReadFile {
                path,
                maximum_bytes,
            } => {
                let canonical = self.confined(path)?;
                let bytes = read_local_file(&canonical, *maximum_bytes)?;
                Ok(sha256_bytes(&bytes))
            }
            DesktopOperation::ListDirectory {
                path,
                maximum_entries,
            } => {
                let canonical = self.confined(path)?;
                let entries = list_local_directory(&canonical, *maximum_entries)?;
                hash_value(&entries)
            }
            _ => Err(DesktopError::AdapterUnavailable(
                "local read-only adapter does not implement this capability".to_owned(),
            )),
        }
    }
}

impl DesktopAdapter for LocalReadOnlyDesktopAdapter {
    fn descriptor(&self) -> &DesktopAdapterDescriptor {
        &self.descriptor
    }

    fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError> {
        intent.validate()?;
        if !self
            .descriptor
            .capabilities
            .contains(&intent.operation.capability())
        {
            return Err(DesktopError::AdapterUnavailable(
                "local read-only adapter capability mismatch".to_owned(),
            ));
        }
        PreparedAction::create(
            intent,
            &self.descriptor,
            self.snapshot(&intent.operation)?,
            now_unix_ms,
        )
    }

    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        if payload.is_some() {
            return Err(DesktopError::Invalid(
                "read-only action does not accept an input payload".to_owned(),
            ));
        }
        let action_hash = intent.action_hash()?;
        permit.validate_binding(&action_hash, prepared, now_unix_ms)?;
        let output = match &intent.operation {
            DesktopOperation::ReadFile {
                path,
                maximum_bytes,
            } => {
                let bytes = read_local_file(&self.confined(path)?, *maximum_bytes)?;
                if sha256_bytes(&bytes) != prepared.precondition_hash {
                    return Err(DesktopError::Precondition(
                        "desktop file changed after preparation".to_owned(),
                    ));
                }
                bytes
            }
            DesktopOperation::ListDirectory {
                path,
                maximum_entries,
            } => {
                let entries = list_local_directory(&self.confined(path)?, *maximum_entries)?;
                if hash_value(&entries)? != prepared.precondition_hash {
                    return Err(DesktopError::Precondition(
                        "desktop directory changed after preparation".to_owned(),
                    ));
                }
                json_bytes(&entries)?
            }
            _ => {
                return Err(DesktopError::AdapterUnavailable(
                    "local read-only adapter capability mismatch".to_owned(),
                ));
            }
        };
        outcome(
            action_hash,
            &self.descriptor,
            output,
            now_unix_ms,
            "bounded local read completed",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DirectoryEntry {
    name: String,
    kind: String,
    bytes: u64,
}

fn read_local_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum_bytes {
        return Err(DesktopError::Integrity(
            "read target must be a bounded non-symlink regular file".to_owned(),
        ));
    }
    std::fs::read(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn list_local_directory(
    path: &Path,
    maximum_entries: u32,
) -> Result<Vec<DirectoryEntry>, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DesktopError::Integrity(
            "list target must be a non-symlink directory".to_owned(),
        ));
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })? {
        if entries.len() >= maximum_entries as usize {
            return Err(DesktopError::Invalid(
                "directory contains more than maximum_entries".to_owned(),
            ));
        }
        let entry = entry.map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let metadata =
            std::fs::symlink_metadata(entry.path()).map_err(|error| DesktopError::Io {
                path: entry.path().display().to_string(),
                message: error.to_string(),
            })?;
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_file() {
            "file"
        } else if metadata.is_dir() {
            "directory"
        } else {
            "other"
        };
        entries.push(DirectoryEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            kind: kind.to_owned(),
            bytes: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
        });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

/// Deterministic virtual adapter for policy, approval, audit, and replay tests.
#[derive(Debug, Clone)]
pub struct OfflineConformanceDesktopAdapter {
    descriptor: DesktopAdapterDescriptor,
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeSet<String>,
    clipboard: Vec<u8>,
}

impl OfflineConformanceDesktopAdapter {
    /// Creates an offline adapter. It never reads or changes host state.
    pub fn new(files: BTreeMap<String, Vec<u8>>, directories: BTreeSet<String>) -> Self {
        Self {
            descriptor: DesktopAdapterDescriptor {
                schema_version: 1,
                adapter_id: "offline-conformance.desktop".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                platform: "virtual".to_owned(),
                capabilities: all_capabilities(),
                concrete_host_adapter: false,
                process_isolated: true,
                network_capable: true,
            },
            files,
            directories,
            clipboard: Vec::new(),
        }
    }

    fn snapshot(&self, operation: &DesktopOperation) -> Result<String, DesktopError> {
        let state = match operation {
            DesktopOperation::ReadFile { path, .. }
            | DesktopOperation::WriteFile { path, .. }
            | DesktopOperation::DeletePath { path, .. } => {
                json!({"path": path, "content_hash": self.files.get(path).map(|v| sha256_bytes(v))})
            }
            DesktopOperation::ListDirectory { path, .. }
            | DesktopOperation::CreateDirectory { path } => {
                json!({"path": path, "exists": self.directories.contains(path)})
            }
            DesktopOperation::MovePath {
                source,
                destination,
                ..
            } => json!({
                "source": source,
                "source_hash": self.files.get(source).map(|v| sha256_bytes(v)),
                "destination_exists": self.files.contains_key(destination)
            }),
            DesktopOperation::ClipboardRead | DesktopOperation::ClipboardWrite { .. } => {
                json!({"clipboard_hash": sha256_bytes(&self.clipboard)})
            }
            _ => serde_json::to_value(operation)
                .map_err(|error| DesktopError::Json(error.to_string()))?,
        };
        hash_value(&state)
    }

    fn run(
        &mut self,
        operation: &DesktopOperation,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>, DesktopError> {
        validate_operation_payload(operation, payload)?;
        match operation {
            DesktopOperation::ReadFile {
                path,
                maximum_bytes,
            } => {
                let content = self.files.get(path).ok_or_else(|| {
                    DesktopError::Precondition("virtual file does not exist".to_owned())
                })?;
                if content.len() as u64 > *maximum_bytes {
                    return Err(DesktopError::Invalid(
                        "virtual file exceeds requested maximum".to_owned(),
                    ));
                }
                Ok(content.clone())
            }
            DesktopOperation::ListDirectory {
                path,
                maximum_entries,
            } => {
                if !self.directories.contains(path) {
                    return Err(DesktopError::Precondition(
                        "virtual directory does not exist".to_owned(),
                    ));
                }
                let prefix = format!("{}{}", path.trim_end_matches(['/', '\\']), '/');
                let mut names: Vec<&str> = self
                    .files
                    .keys()
                    .filter_map(|candidate| candidate.strip_prefix(&prefix))
                    .filter(|remainder| !remainder.contains(['/', '\\']))
                    .collect();
                names.sort_unstable();
                if names.len() > *maximum_entries as usize {
                    return Err(DesktopError::Invalid(
                        "virtual directory exceeds maximum_entries".to_owned(),
                    ));
                }
                json_bytes(&names)
            }
            DesktopOperation::WriteFile {
                path,
                expected_current_hash,
                create_new,
                ..
            } => {
                if *create_new && self.files.contains_key(path) {
                    return Err(DesktopError::Precondition(
                        "virtual create_new target exists".to_owned(),
                    ));
                }
                if let Some(expected) = expected_current_hash {
                    let actual = self.files.get(path).map(|value| sha256_bytes(value));
                    if actual.as_deref() != Some(expected) {
                        return Err(DesktopError::Precondition(
                            "virtual file hash changed".to_owned(),
                        ));
                    }
                }
                let bytes = payload.unwrap_or_default().to_vec();
                self.files.insert(path.clone(), bytes);
                json_bytes(&json!({"written": path}))
            }
            DesktopOperation::CreateDirectory { path } => {
                if !self.directories.insert(path.clone()) {
                    return Err(DesktopError::Precondition(
                        "virtual directory already exists".to_owned(),
                    ));
                }
                json_bytes(&json!({"created": path}))
            }
            DesktopOperation::MovePath {
                source,
                destination,
                expected_source_hash,
            } => {
                let content = self.files.get(source).ok_or_else(|| {
                    DesktopError::Precondition("virtual move source does not exist".to_owned())
                })?;
                if sha256_bytes(content) != *expected_source_hash
                    || self.files.contains_key(destination)
                {
                    return Err(DesktopError::Precondition(
                        "virtual move precondition failed".to_owned(),
                    ));
                }
                let moved = self.files.remove(source).ok_or_else(|| {
                    DesktopError::Precondition("virtual move source disappeared".to_owned())
                })?;
                self.files.insert(destination.clone(), moved);
                json_bytes(&json!({"moved": source, "destination": destination}))
            }
            DesktopOperation::DeletePath {
                path,
                expected_hash,
            } => {
                let content = self.files.get(path).ok_or_else(|| {
                    DesktopError::Precondition("virtual delete target does not exist".to_owned())
                })?;
                if sha256_bytes(content) != *expected_hash {
                    return Err(DesktopError::Precondition(
                        "virtual delete hash changed".to_owned(),
                    ));
                }
                self.files.remove(path);
                json_bytes(&json!({"deleted": path}))
            }
            DesktopOperation::ClipboardRead => Ok(self.clipboard.clone()),
            DesktopOperation::ClipboardWrite { .. } => {
                self.clipboard = payload.unwrap_or_default().to_vec();
                json_bytes(&json!({"clipboard_updated": true}))
            }
            _ => json_bytes(&json!({
                "offline_conformance_only": true,
                "capability": operation.capability()
            })),
        }
    }
}

impl DesktopAdapter for OfflineConformanceDesktopAdapter {
    fn descriptor(&self) -> &DesktopAdapterDescriptor {
        &self.descriptor
    }

    fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError> {
        intent.validate()?;
        PreparedAction::create(
            intent,
            &self.descriptor,
            self.snapshot(&intent.operation)?,
            now_unix_ms,
        )
    }

    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        let action_hash = intent.action_hash()?;
        permit.validate_binding(&action_hash, prepared, now_unix_ms)?;
        if self.snapshot(&intent.operation)? != prepared.precondition_hash {
            return Err(DesktopError::Precondition(
                "virtual target changed after preparation".to_owned(),
            ));
        }
        let output = self.run(&intent.operation, payload)?;
        outcome(
            action_hash,
            &self.descriptor,
            output,
            now_unix_ms,
            "offline conformance action completed",
        )
    }
}

pub(crate) fn validate_operation_payload(
    operation: &DesktopOperation,
    payload: Option<&[u8]>,
) -> Result<(), DesktopError> {
    if payload.is_some_and(|bytes| bytes.len() > MAX_ACTION_PAYLOAD_BYTES) {
        return Err(DesktopError::Invalid(format!(
            "action payload exceeds {MAX_ACTION_PAYLOAD_BYTES} bytes"
        )));
    }
    let expected = match operation {
        DesktopOperation::WriteFile { payload_hash, .. }
        | DesktopOperation::ClipboardWrite { payload_hash, .. } => Some(payload_hash),
        crate::DesktopOperation::BrowserInteract {
            interaction:
                crate::BrowserInteraction::TypeText {
                    text_hash,
                    secret_ref: None,
                    ..
                },
            ..
        }
        | crate::DesktopOperation::UiInteract {
            interaction:
                crate::UiInteraction::SetText {
                    text_hash,
                    secret_ref: None,
                    ..
                },
            ..
        } => Some(text_hash),
        crate::DesktopOperation::BrowserInteract {
            interaction: crate::BrowserInteraction::Select { value_hash, .. },
            ..
        } => Some(value_hash),
        _ => None,
    };
    match (expected, payload) {
        (Some(hash), Some(bytes)) if sha256_bytes(bytes) == *hash => Ok(()),
        (Some(_), _) => Err(DesktopError::Integrity(
            "action payload is absent or does not match its hash".to_owned(),
        )),
        (None, Some(_)) => Err(DesktopError::Invalid(
            "operation does not accept a direct payload".to_owned(),
        )),
        (None, None) => Ok(()),
    }
}

pub(crate) fn outcome(
    action_hash: String,
    descriptor: &DesktopAdapterDescriptor,
    payload: Vec<u8>,
    now_unix_ms: u64,
    message: &str,
) -> Result<AdapterExecution, DesktopError> {
    validate_text(message, "outcome message")?;
    if payload.len() > MAX_ACTION_PAYLOAD_BYTES {
        return Err(DesktopError::Invalid(
            "adapter output exceeds payload bound".to_owned(),
        ));
    }
    let output_hash = sha256_bytes(&payload);
    Ok(AdapterExecution {
        outcome: ActionOutcome {
            action_hash,
            adapter_descriptor_hash: descriptor.descriptor_hash()?,
            status: ActionOutcomeStatus::Succeeded,
            started_at_unix_ms: now_unix_ms,
            completed_at_unix_ms: now_unix_ms,
            output_hash,
            output_bytes: payload.len() as u64,
            message: message.to_owned(),
        },
        payload,
    })
}

fn all_capabilities() -> BTreeSet<DesktopCapability> {
    [
        DesktopCapability::ObserveDesktop,
        DesktopCapability::ListWindows,
        DesktopCapability::ReadFile,
        DesktopCapability::ListDirectory,
        DesktopCapability::WriteFile,
        DesktopCapability::CreateDirectory,
        DesktopCapability::MovePath,
        DesktopCapability::DeletePath,
        DesktopCapability::LaunchProcess,
        DesktopCapability::TerminateProcess,
        DesktopCapability::BrowserNavigate,
        DesktopCapability::BrowserInteract,
        DesktopCapability::UiInteract,
        DesktopCapability::ClipboardRead,
        DesktopCapability::ClipboardWrite,
    ]
    .into_iter()
    .collect()
}
