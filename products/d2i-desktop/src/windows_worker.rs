use crate::windows_observation::{ReadOnlyObservationPayload, ReadOnlyObservationRequest};
use crate::{
    json_bytes, read_bounded, sha256_bytes, validate_hash, BrowserInteraction, DesktopError,
    DesktopOperation, SignedWindowsWfpFunctionalAttestationV2, UiInteraction,
    WfpReceiptReplayLedger, WindowIdentity, WindowsAdapterConfiguration, WindowsAdapterKind,
    WindowsCapabilityObservation, MAX_ACTION_PAYLOAD_BYTES,
};
use d2i_windows_host::{
    appcontainer_profile, spawn_zero_capability_appcontainer, WindowsAppContainerChild, WindowsJob,
    WindowsJobLimits,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const MAX_PROTOCOL_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_HTTP_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILE_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_WINDOWS: usize = 512;
const MAX_SELECT_OPTIONS: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerCommand {
    Probe,
    VerifyBrowserEgress {
        functional_attestation: Option<Box<SignedWindowsWfpFunctionalAttestationV2>>,
        now_unix_seconds: u64,
    },
    Observe {
        request: Box<ReadOnlyObservationRequest>,
    },
    Snapshot {
        operation: DesktopOperation,
    },
    Commit {
        operation: DesktopOperation,
        expected_snapshot_hash: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerRequest {
    schema_version: u32,
    request_id: u64,
    configuration: WindowsAdapterConfiguration,
    payload_present: bool,
    payload_bytes: u64,
    command: WorkerCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorkerResponseStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponse {
    schema_version: u32,
    request_id: u64,
    status: WorkerResponseStatus,
    payload_bytes: u64,
    message: String,
}

struct WorkerReply {
    header: WorkerResponse,
    payload: Vec<u8>,
}

pub(crate) struct IsolatedWindowsWorker {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Arc<Mutex<BufReader<ChildStdout>>>,
    job: WindowsJob,
    configuration: WindowsAdapterConfiguration,
    next_request_id: u64,
    failed: bool,
}

impl IsolatedWindowsWorker {
    pub(crate) fn start(configuration: WindowsAdapterConfiguration) -> Result<Self, DesktopError> {
        configuration.validate()?;
        if !cfg!(windows) {
            return Err(DesktopError::AdapterUnavailable(
                "Windows worker is unavailable on this platform".to_owned(),
            ));
        }
        let worker_path = canonical_regular_file(
            Path::new(&configuration.worker_executable),
            "Windows worker executable",
        )?;
        let actual_hash = sha256_bytes(&read_bounded(&worker_path, 64 * 1024 * 1024)?);
        if actual_hash != configuration.worker_executable_hash {
            return Err(DesktopError::Integrity(
                "Windows worker hash changed before launch".to_owned(),
            ));
        }
        let mut command = Command::new(&worker_path);
        command
            .arg("__windows-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn().map_err(|error| DesktopError::Io {
            path: worker_path.display().to_string(),
            message: error.to_string(),
        })?;
        let job = WindowsJob::create(WindowsJobLimits {
            active_process_limit: configuration.active_process_limit,
            per_process_memory_bytes: configuration.per_process_memory_bytes,
        })
        .map_err(|error| {
            let _ = child.kill();
            DesktopError::AdapterUnavailable(format!("Windows Job Object failed: {error}"))
        })?;
        if let Err(error) = job.assign_child(&child) {
            let _ = child.kill();
            return Err(DesktopError::AdapterUnavailable(format!(
                "Windows worker isolation failed: {error}"
            )));
        }
        let stdin = child.stdin.take().ok_or_else(|| {
            DesktopError::AdapterUnavailable("Windows worker stdin was not created".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            DesktopError::AdapterUnavailable("Windows worker stdout was not created".to_owned())
        })?;
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout: Arc::new(Mutex::new(BufReader::new(stdout))),
            job,
            configuration,
            next_request_id: 1,
            failed: false,
        })
    }

    pub(crate) fn process_id(&self) -> u32 {
        self.child.id()
    }

    pub(crate) fn probe(&mut self) -> Result<Vec<u8>, DesktopError> {
        self.request(WorkerCommand::Probe, None)
    }

    pub(crate) fn snapshot(
        &mut self,
        operation: &DesktopOperation,
    ) -> Result<String, DesktopError> {
        let payload = self.request(
            WorkerCommand::Snapshot {
                operation: operation.clone(),
            },
            None,
        )?;
        Ok(sha256_bytes(&payload))
    }

    pub(crate) fn observe(
        &mut self,
        request: &ReadOnlyObservationRequest,
    ) -> Result<ReadOnlyObservationPayload, DesktopError> {
        let payload = self.request(
            WorkerCommand::Observe {
                request: Box::new(request.clone()),
            },
            None,
        )?;
        let observation: ReadOnlyObservationPayload = serde_json::from_slice(&payload)
            .map_err(|error| DesktopError::Json(error.to_string()))?;
        observation.validate(request)?;
        Ok(observation)
    }

    pub(crate) fn commit(
        &mut self,
        operation: &DesktopOperation,
        expected_snapshot_hash: &str,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>, DesktopError> {
        validate_hash(expected_snapshot_hash, "worker expected_snapshot_hash")?;
        self.request(
            WorkerCommand::Commit {
                operation: operation.clone(),
                expected_snapshot_hash: expected_snapshot_hash.to_owned(),
            },
            payload,
        )
    }

    fn request(
        &mut self,
        command: WorkerCommand,
        payload: Option<&[u8]>,
    ) -> Result<Vec<u8>, DesktopError> {
        if self.failed {
            return Err(DesktopError::AdapterUnavailable(
                "Windows worker is unavailable after a prior protocol failure".to_owned(),
            ));
        }
        let payload_present = payload.is_some();
        let payload = payload.unwrap_or_default();
        if payload.len() > MAX_ACTION_PAYLOAD_BYTES {
            return Err(DesktopError::Invalid(
                "Windows worker payload exceeds the action bound".to_owned(),
            ));
        }
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let request = WorkerRequest {
            schema_version: 1,
            request_id,
            configuration: self.configuration.clone(),
            payload_present,
            payload_bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
            command,
        };
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            DesktopError::AdapterUnavailable("Windows worker stdin is closed".to_owned())
        })?;
        if let Err(error) = write_frame(stdin, &request, payload) {
            self.failed = true;
            let _ = self.job.terminate();
            return Err(error);
        }
        let stdout = Arc::clone(&self.stdout);
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let reply = match stdout.lock() {
                Ok(mut reader) => read_response_frame(&mut *reader),
                Err(_) => Err(DesktopError::Integrity(
                    "Windows worker response lock is poisoned".to_owned(),
                )),
            };
            let _ = sender.send(reply);
        });
        let timeout = Duration::from_millis(self.configuration.request_timeout_ms);
        let reply = match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => {
                self.failed = true;
                let _ = self.job.terminate();
                let _ = self.child.kill();
                return Err(DesktopError::AdapterUnavailable(
                    "Windows worker request exceeded its certified timeout".to_owned(),
                ));
            }
        }?;
        if reply.header.request_id != request_id {
            self.failed = true;
            let _ = self.job.terminate();
            return Err(DesktopError::Integrity(
                "Windows worker response request_id mismatch".to_owned(),
            ));
        }
        match reply.header.status {
            WorkerResponseStatus::Succeeded => Ok(reply.payload),
            WorkerResponseStatus::Failed => Err(DesktopError::Precondition(reply.header.message)),
        }
    }
}

pub(crate) fn verify_browser_egress_with_approved_relay(
    configuration: &WindowsAdapterConfiguration,
    functional_attestation: Option<&SignedWindowsWfpFunctionalAttestationV2>,
    now_unix_seconds: u64,
) -> Result<Option<crate::SignedWfpVerificationReceipt>, DesktopError> {
    configuration.validate()?;
    let worker_path = canonical_regular_file(
        Path::new(&configuration.worker_executable),
        "Windows egress relay executable",
    )?;
    let actual_hash = sha256_bytes(&read_bounded(&worker_path, 64 * 1024 * 1024)?);
    if actual_hash != configuration.worker_executable_hash {
        return Err(DesktopError::Integrity(
            "Windows egress relay hash changed before launch".to_owned(),
        ));
    }
    let mut command = Command::new(&worker_path);
    command
        .arg("__windows-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().map_err(|error| DesktopError::Io {
        path: worker_path.display().to_string(),
        message: error.to_string(),
    })?;
    let result = (|| {
        let mut stdin = child.stdin.take().ok_or_else(|| {
            DesktopError::AdapterUnavailable(
                "Windows egress relay stdin was not created".to_owned(),
            )
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            DesktopError::AdapterUnavailable(
                "Windows egress relay stdout was not created".to_owned(),
            )
        })?;
        let request_id = 1;
        let request = WorkerRequest {
            schema_version: 1,
            request_id,
            configuration: configuration.clone(),
            payload_present: false,
            payload_bytes: 0,
            command: WorkerCommand::VerifyBrowserEgress {
                functional_attestation: functional_attestation.cloned().map(Box::new),
                now_unix_seconds,
            },
        };
        write_frame(&mut stdin, &request, &[])?;
        drop(stdin);
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let _ = sender.send(read_response_frame(&mut reader));
        });
        let timeout = Duration::from_millis(configuration.request_timeout_ms);
        let reply = receiver.recv_timeout(timeout).map_err(|_| {
            DesktopError::AdapterUnavailable(
                "Windows egress relay exceeded its certified timeout".to_owned(),
            )
        })??;
        if reply.header.request_id != request_id {
            return Err(DesktopError::Integrity(
                "Windows egress relay response request_id mismatch".to_owned(),
            ));
        }
        match reply.header.status {
            WorkerResponseStatus::Succeeded => serde_json::from_slice(&reply.payload)
                .map_err(|error| DesktopError::Json(error.to_string())),
            WorkerResponseStatus::Failed => Err(DesktopError::Precondition(reply.header.message)),
        }
    })();
    let _ = child.kill();
    let _ = child.wait();
    result
}

impl Drop for IsolatedWindowsWorker {
    fn drop(&mut self) {
        if let Some(mut stdin) = self.stdin.take() {
            let request = WorkerRequest {
                schema_version: 1,
                request_id: self.next_request_id,
                configuration: self.configuration.clone(),
                payload_present: false,
                payload_bytes: 0,
                command: WorkerCommand::Shutdown,
            };
            let _ = write_frame(&mut stdin, &request, &[]);
        }
        let _ = self.job.terminate();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn probe_worker(
    configuration: &WindowsAdapterConfiguration,
) -> Result<WindowsCapabilityObservation, DesktopError> {
    let mut worker = IsolatedWindowsWorker::start(configuration.clone())?;
    let details = worker.probe()?;
    let parsed: Value =
        serde_json::from_slice(&details).map_err(|error| DesktopError::Json(error.to_string()))?;
    if parsed.get("ready").and_then(Value::as_bool) != Some(true) {
        return Err(DesktopError::AdapterUnavailable(
            "Windows worker capability probe did not report ready".to_owned(),
        ));
    }
    Ok(WindowsCapabilityObservation {
        adapter_kind: configuration.adapter_kind,
        ready: true,
        process_isolated: true,
        job_kill_on_close: true,
        active_process_limit: configuration.active_process_limit,
        per_process_memory_bytes: configuration.per_process_memory_bytes,
        process_appcontainer_sid: configuration
            .process_isolation
            .as_ref()
            .map(|isolation| isolation.profile_sid.clone()),
        network_isolation_enforced: configuration.adapter_kind == WindowsAdapterKind::Process,
        details_hash: sha256_bytes(&details),
    })
}

/// Runs the private framed worker protocol on standard input and output.
pub(crate) fn run_windows_worker_stdio() -> Result<(), DesktopError> {
    if !cfg!(windows) {
        return Err(DesktopError::AdapterUnavailable(
            "Windows worker is unavailable on this platform".to_owned(),
        ));
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    let mut state = WorkerState::default();
    let mut configuration_hash: Option<String> = None;
    loop {
        let Some((request, payload)) = read_request_frame(&mut reader)? else {
            return Ok(());
        };
        let request_configuration_hash = request.configuration.configuration_hash()?;
        if configuration_hash
            .as_ref()
            .is_some_and(|expected| expected != &request_configuration_hash)
        {
            write_worker_error(
                &mut writer,
                request.request_id,
                "worker configuration changed after startup",
            )?;
            continue;
        }
        configuration_hash = Some(request_configuration_hash);
        if matches!(request.command, WorkerCommand::Shutdown) {
            write_worker_success(&mut writer, request.request_id, b"{}")?;
            return Ok(());
        }
        let result = dispatch_worker(
            &request.configuration,
            &mut state,
            request.command,
            request.payload_present,
            &payload,
        );
        match result {
            Ok(output) => write_worker_success(&mut writer, request.request_id, &output)?,
            Err(error) => write_worker_error(&mut writer, request.request_id, &error.to_string())?,
        }
    }
}

#[derive(Default)]
struct WorkerState {
    processes: BTreeMap<u32, WindowsAppContainerChild>,
}

fn dispatch_worker(
    configuration: &WindowsAdapterConfiguration,
    state: &mut WorkerState,
    command: WorkerCommand,
    payload_present: bool,
    payload: &[u8],
) -> Result<Vec<u8>, DesktopError> {
    configuration.validate()?;
    match command {
        WorkerCommand::Probe => {
            if payload_present {
                return Err(DesktopError::Invalid(
                    "worker probe does not accept payload".to_owned(),
                ));
            }
            probe_capability(configuration)
        }
        WorkerCommand::VerifyBrowserEgress {
            functional_attestation,
            now_unix_seconds,
        } => {
            if payload_present {
                return Err(DesktopError::Invalid(
                    "worker egress verification does not accept payload".to_owned(),
                ));
            }
            let mut replay = WfpReceiptReplayLedger::default();
            let receipt = verify_worker_browser_egress(
                configuration,
                functional_attestation.as_deref(),
                &mut replay,
                now_unix_seconds,
            )?;
            json_bytes(&receipt)
        }
        WorkerCommand::Observe { request } => {
            if payload_present {
                return Err(DesktopError::Invalid(
                    "worker observation does not accept payload".to_owned(),
                ));
            }
            let observation = crate::windows_observation_worker::collect(configuration, &request)?;
            observation.validate(&request)?;
            json_bytes(&observation)
        }
        WorkerCommand::Snapshot { operation } => {
            if payload_present {
                return Err(DesktopError::Invalid(
                    "worker snapshot does not accept payload".to_owned(),
                ));
            }
            validate_worker_operation(configuration, &operation)?;
            snapshot_operation(configuration, state, &operation)
        }
        WorkerCommand::Commit {
            operation,
            expected_snapshot_hash,
        } => {
            validate_worker_operation(configuration, &operation)?;
            crate::adapter::validate_operation_payload(
                &operation,
                payload_present.then_some(payload),
            )?;
            let actual_snapshot = snapshot_operation(configuration, state, &operation)?;
            if sha256_bytes(&actual_snapshot) != expected_snapshot_hash {
                return Err(DesktopError::Precondition(
                    "Windows worker precondition changed after preparation".to_owned(),
                ));
            }
            commit_operation(configuration, state, &operation, payload)
        }
        WorkerCommand::Shutdown => Ok(Vec::new()),
    }
}

fn verify_worker_browser_egress(
    configuration: &WindowsAdapterConfiguration,
    functional_attestation: Option<&SignedWindowsWfpFunctionalAttestationV2>,
    replay: &mut WfpReceiptReplayLedger,
    now_unix_seconds: u64,
) -> Result<Option<crate::SignedWfpVerificationReceipt>, DesktopError> {
    let host = crate::current_windows_host_binding()?;
    crate::windows_egress::verify_configured_windows_browser_egress(
        configuration,
        &host,
        functional_attestation,
        replay,
        now_unix_seconds,
    )
}

fn validate_worker_operation(
    configuration: &WindowsAdapterConfiguration,
    operation: &DesktopOperation,
) -> Result<(), DesktopError> {
    operation.validate()?;
    if !configuration
        .descriptor()?
        .capabilities
        .contains(&operation.capability())
    {
        return Err(DesktopError::AdapterUnavailable(
            "operation does not belong to this isolated worker".to_owned(),
        ));
    }
    match operation {
        DesktopOperation::BrowserNavigate {
            browser_session_id,
            origin,
            ..
        }
        | DesktopOperation::BrowserInteract {
            browser_session_id,
            origin,
            ..
        } => {
            validate_webdriver_segment(browser_session_id, "browser_session_id")?;
            if !configuration
                .browser_session_ids
                .contains(browser_session_id)
                || !configuration.browser_allowed_origins.contains(origin)
            {
                return Err(DesktopError::AccessDenied(
                    "browser session or origin is not certified by worker configuration".to_owned(),
                ));
            }
        }
        DesktopOperation::UiInteract { window, .. } => {
            if !configuration
                .ui_allowed_executable_hashes
                .contains(&window.executable_hash)
            {
                return Err(DesktopError::AccessDenied(
                    "window executable is not certified by worker configuration".to_owned(),
                ));
            }
        }
        DesktopOperation::LaunchProcess {
            network_requested: true,
            ..
        } => {
            return Err(DesktopError::AccessDenied(
                "zero-capability AppContainer process adapter cannot grant network access"
                    .to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn probe_capability(configuration: &WindowsAdapterConfiguration) -> Result<Vec<u8>, DesktopError> {
    let details = match configuration.adapter_kind {
        WindowsAdapterKind::UiAutomation => platform_ui::probe()?,
        WindowsAdapterKind::WebDriver => {
            let endpoint = configuration
                .webdriver_endpoint
                .as_deref()
                .ok_or_else(|| DesktopError::Invalid("WebDriver endpoint is absent".to_owned()))?;
            let response = webdriver_request(
                endpoint,
                configuration.request_timeout_ms,
                "GET",
                "/status",
                None,
            )?;
            if response.pointer("/value/ready").and_then(Value::as_bool) != Some(true) {
                return Err(DesktopError::AdapterUnavailable(
                    "WebDriver status is not ready".to_owned(),
                ));
            }
            json!({"ready": true, "protocol": "w3c-webdriver", "endpoint": endpoint})
        }
        WindowsAdapterKind::FileWrite => {
            let roots = canonical_write_roots(&configuration.write_roots)?;
            json!({"ready": true, "canonical_root_count": roots.len(), "atomic_replace": true})
        }
        WindowsAdapterKind::Process => {
            let isolation = verified_process_isolation(configuration)?;
            json!({
                "ready": true,
                "launch": "zero_capability_appcontainer",
                "managed_children_only": true,
                "network_denied": true,
                "profile_sid": isolation.profile_sid
            })
        }
    };
    json_bytes(&details)
}

fn snapshot_operation(
    configuration: &WindowsAdapterConfiguration,
    state: &mut WorkerState,
    operation: &DesktopOperation,
) -> Result<Vec<u8>, DesktopError> {
    match configuration.adapter_kind {
        WindowsAdapterKind::UiAutomation => platform_ui::snapshot(configuration, operation),
        WindowsAdapterKind::WebDriver => browser_snapshot(configuration, operation),
        WindowsAdapterKind::FileWrite => file_snapshot(configuration, operation),
        WindowsAdapterKind::Process => process_snapshot(configuration, state, operation),
    }
}

fn commit_operation(
    configuration: &WindowsAdapterConfiguration,
    state: &mut WorkerState,
    operation: &DesktopOperation,
    payload: &[u8],
) -> Result<Vec<u8>, DesktopError> {
    match configuration.adapter_kind {
        WindowsAdapterKind::UiAutomation => platform_ui::commit(configuration, operation, payload),
        WindowsAdapterKind::WebDriver => browser_commit(configuration, operation, payload),
        WindowsAdapterKind::FileWrite => file_commit(configuration, operation, payload),
        WindowsAdapterKind::Process => process_commit(configuration, state, operation),
    }
}

fn file_snapshot(
    configuration: &WindowsAdapterConfiguration,
    operation: &DesktopOperation,
) -> Result<Vec<u8>, DesktopError> {
    let DesktopOperation::WriteFile {
        path,
        expected_current_hash,
        create_new,
        ..
    } = operation
    else {
        return Err(DesktopError::AdapterUnavailable(
            "file-write worker received a different operation".to_owned(),
        ));
    };
    let roots = canonical_write_roots(&configuration.write_roots)?;
    let target = confined_write_target(path, &roots)?;
    let metadata = std::fs::symlink_metadata(&target);
    let (exists, current_hash, size_bytes) = match metadata {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || d2i_windows_host::is_reparse_point(&target)
                    .map_err(|error| DesktopError::Integrity(error.to_string()))?
            {
                return Err(DesktopError::Integrity(
                    "write target must be a non-reparse regular file".to_owned(),
                ));
            }
            if metadata.len() > MAX_FILE_SNAPSHOT_BYTES {
                return Err(DesktopError::Invalid(
                    "write target exceeds snapshot hashing bound".to_owned(),
                ));
            }
            let hash = sha256_bytes(&read_bounded(&target, MAX_FILE_SNAPSHOT_BYTES)?);
            (true, Some(hash), metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, None, 0),
        Err(error) => {
            return Err(DesktopError::Io {
                path: target.display().to_string(),
                message: error.to_string(),
            });
        }
    };
    if *create_new && exists {
        return Err(DesktopError::Precondition(
            "create_new write target already exists".to_owned(),
        ));
    }
    if let Some(expected) = expected_current_hash {
        if current_hash.as_deref() != Some(expected) {
            return Err(DesktopError::Precondition(
                "write target hash differs from expected_current_hash".to_owned(),
            ));
        }
    }
    json_bytes(&json!({
        "target": target,
        "exists": exists,
        "current_hash": current_hash,
        "size_bytes": size_bytes,
        "create_new": create_new
    }))
}

fn file_commit(
    configuration: &WindowsAdapterConfiguration,
    operation: &DesktopOperation,
    payload: &[u8],
) -> Result<Vec<u8>, DesktopError> {
    let DesktopOperation::WriteFile {
        path,
        payload_hash,
        create_new,
        ..
    } = operation
    else {
        return Err(DesktopError::AdapterUnavailable(
            "file-write worker received a different operation".to_owned(),
        ));
    };
    if sha256_bytes(payload) != *payload_hash {
        return Err(DesktopError::Integrity(
            "file-write payload hash mismatch".to_owned(),
        ));
    }
    let roots = canonical_write_roots(&configuration.write_roots)?;
    let target = confined_write_target(path, &roots)?;
    let parent = target
        .parent()
        .ok_or_else(|| DesktopError::Invalid("write target has no parent directory".to_owned()))?;
    let temp = parent.join(format!(
        ".d2i-write-{}-{}.tmp",
        std::process::id(),
        &payload_hash[7..23]
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| DesktopError::Io {
                path: temp.display().to_string(),
                message: error.to_string(),
            })?;
        file.write_all(payload)
            .and_then(|()| file.sync_all())
            .map_err(|error| DesktopError::Io {
                path: temp.display().to_string(),
                message: error.to_string(),
            })?;
        d2i_windows_host::atomic_move(&temp, &target, !create_new).map_err(|error| {
            DesktopError::Io {
                path: target.display().to_string(),
                message: error.to_string(),
            }
        })?;
        if sha256_bytes(&read_bounded(&target, MAX_FILE_SNAPSHOT_BYTES)?) != *payload_hash {
            return Err(DesktopError::Integrity(
                "written file failed post-commit hash verification".to_owned(),
            ));
        }
        json_bytes(&json!({
            "path_hash": sha256_bytes(target.display().to_string().as_bytes()),
            "content_hash": payload_hash,
            "bytes_written": payload.len()
        }))
    })();
    if temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn canonical_write_roots(roots: &[String]) -> Result<Vec<PathBuf>, DesktopError> {
    let mut canonical = Vec::with_capacity(roots.len());
    for root in roots {
        let path = Path::new(root);
        let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
            path: root.clone(),
            message: error.to_string(),
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || d2i_windows_host::is_reparse_point(path)
                .map_err(|error| DesktopError::Integrity(error.to_string()))?
        {
            return Err(DesktopError::Integrity(
                "write root must be a non-reparse directory".to_owned(),
            ));
        }
        let root = std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
            path: root.clone(),
            message: error.to_string(),
        })?;
        if !canonical.contains(&root) {
            canonical.push(root);
        }
    }
    Ok(canonical)
}

fn confined_write_target(path: &str, roots: &[PathBuf]) -> Result<PathBuf, DesktopError> {
    let target = Path::new(path);
    let parent = target
        .parent()
        .ok_or_else(|| DesktopError::Invalid("write target has no parent".to_owned()))?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|error| DesktopError::Io {
        path: parent.display().to_string(),
        message: error.to_string(),
    })?;
    if d2i_windows_host::is_reparse_point(parent)
        .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(
            "write target parent is a reparse point".to_owned(),
        ));
    }
    let root = roots
        .iter()
        .find(|root| canonical_parent.starts_with(root))
        .ok_or_else(|| {
            DesktopError::AccessDenied("write target escapes certified roots".to_owned())
        })?;
    reject_existing_reparse_components(root, &canonical_parent)?;
    let name = target
        .file_name()
        .ok_or_else(|| DesktopError::Invalid("write target has no filename".to_owned()))?;
    Ok(canonical_parent.join(name))
}

fn reject_existing_reparse_components(root: &Path, parent: &Path) -> Result<(), DesktopError> {
    let relative = parent.strip_prefix(root).map_err(|_| {
        DesktopError::AccessDenied("write target is outside canonical root".to_owned())
    })?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if d2i_windows_host::is_reparse_point(&current)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
        {
            return Err(DesktopError::Integrity(
                "write path contains a reparse-point component".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct ProcessSnapshot {
    operation: &'static str,
    process_id: Option<u32>,
    executable: String,
    executable_hash: String,
    working_directory: Option<String>,
}

fn process_snapshot(
    configuration: &WindowsAdapterConfiguration,
    state: &mut WorkerState,
    operation: &DesktopOperation,
) -> Result<Vec<u8>, DesktopError> {
    let _ = verified_process_isolation(configuration)?;
    reap_children(state);
    match operation {
        DesktopOperation::LaunchProcess {
            executable,
            executable_hash,
            working_directory,
            ..
        } => {
            let executable = canonical_regular_file(Path::new(executable), "process executable")?;
            let actual_hash = sha256_bytes(&read_bounded(&executable, MAX_FILE_SNAPSHOT_BYTES)?);
            if actual_hash != *executable_hash {
                return Err(DesktopError::Integrity(
                    "process executable hash differs from intent".to_owned(),
                ));
            }
            let working_directory = canonical_non_reparse_directory(Path::new(working_directory))?;
            json_bytes(&ProcessSnapshot {
                operation: "launch",
                process_id: None,
                executable: executable.display().to_string(),
                executable_hash: actual_hash,
                working_directory: Some(working_directory.display().to_string()),
            })
        }
        DesktopOperation::TerminateProcess {
            process_id,
            expected_executable_hash,
        } => {
            if !state.processes.contains_key(process_id) {
                return Err(DesktopError::AccessDenied(
                    "process adapter may terminate only its managed children".to_owned(),
                ));
            }
            let executable = d2i_windows_host::process_image_path(*process_id)
                .map_err(|error| DesktopError::Precondition(error.to_string()))?;
            let executable = canonical_regular_file(&executable, "managed process executable")?;
            let actual_hash = sha256_bytes(&read_bounded(&executable, MAX_FILE_SNAPSHOT_BYTES)?);
            if actual_hash != *expected_executable_hash {
                return Err(DesktopError::Integrity(
                    "managed process executable hash differs from intent".to_owned(),
                ));
            }
            json_bytes(&ProcessSnapshot {
                operation: "terminate",
                process_id: Some(*process_id),
                executable: executable.display().to_string(),
                executable_hash: actual_hash,
                working_directory: None,
            })
        }
        _ => Err(DesktopError::AdapterUnavailable(
            "process worker received a different operation".to_owned(),
        )),
    }
}

fn process_commit(
    configuration: &WindowsAdapterConfiguration,
    state: &mut WorkerState,
    operation: &DesktopOperation,
) -> Result<Vec<u8>, DesktopError> {
    match operation {
        DesktopOperation::LaunchProcess {
            executable,
            arguments,
            working_directory,
            ..
        } => {
            let executable = canonical_regular_file(Path::new(executable), "process executable")?;
            let working_directory = canonical_non_reparse_directory(Path::new(working_directory))?;
            let isolation = verified_process_isolation(configuration)?;
            let child = spawn_zero_capability_appcontainer(
                &isolation.profile_name,
                &isolation.profile_sid,
                &executable,
                arguments,
                &working_directory,
            )
            .map_err(|error| DesktopError::Io {
                path: executable.display().to_string(),
                message: error.to_string(),
            })?;
            let process_id = child.id();
            if state.processes.insert(process_id, child).is_some() {
                return Err(DesktopError::Integrity(
                    "managed process ID collision".to_owned(),
                ));
            }
            json_bytes(&json!({"process_id": process_id, "managed": true}))
        }
        DesktopOperation::TerminateProcess { process_id, .. } => {
            let child = state.processes.remove(process_id).ok_or_else(|| {
                DesktopError::AccessDenied(
                    "process adapter may terminate only its managed children".to_owned(),
                )
            })?;
            child.terminate().map_err(|error| DesktopError::Io {
                path: format!("process:{process_id}"),
                message: error.to_string(),
            })?;
            json_bytes(&json!({"process_id": process_id, "terminated": true}))
        }
        _ => Err(DesktopError::AdapterUnavailable(
            "process worker received a different operation".to_owned(),
        )),
    }
}

fn verified_process_isolation(
    configuration: &WindowsAdapterConfiguration,
) -> Result<&crate::WindowsProcessIsolation, DesktopError> {
    let expected = configuration.process_isolation.as_ref().ok_or_else(|| {
        DesktopError::Invalid("process AppContainer isolation is absent".to_owned())
    })?;
    let observed = appcontainer_profile(&expected.profile_name).map_err(|error| {
        DesktopError::AdapterUnavailable(format!(
            "reviewed AppContainer profile is unavailable: {error}"
        ))
    })?;
    if observed.profile_sid != expected.profile_sid {
        return Err(DesktopError::Integrity(
            "AppContainer profile SID differs from certified configuration".to_owned(),
        ));
    }
    Ok(expected)
}

fn reap_children(state: &mut WorkerState) {
    state.processes.retain(|_, child| match child.try_wait() {
        Ok(Some(_)) => false,
        Ok(None) | Err(_) => true,
    });
}

fn browser_snapshot(
    configuration: &WindowsAdapterConfiguration,
    operation: &DesktopOperation,
) -> Result<Vec<u8>, DesktopError> {
    let endpoint = configuration
        .webdriver_endpoint
        .as_deref()
        .ok_or_else(|| DesktopError::Invalid("WebDriver endpoint is absent".to_owned()))?;
    match operation {
        DesktopOperation::BrowserNavigate {
            browser_session_id, ..
        } => {
            let current_url = webdriver_current_url(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
            )?;
            json_bytes(&json!({
                "session_id": browser_session_id,
                "current_url_hash": sha256_bytes(current_url.as_bytes())
            }))
        }
        DesktopOperation::BrowserInteract {
            browser_session_id,
            origin,
            interaction,
        } => {
            let current_url = webdriver_current_url(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
            )?;
            ensure_url_origin(&current_url, origin)?;
            let locator = interaction_locator(interaction);
            let selector = parse_css_locator(locator)?;
            let element_id = webdriver_find_element(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
                None,
                selector,
                false,
            )?
            .into_iter()
            .next()
            .ok_or_else(|| DesktopError::Precondition("WebDriver element not found".to_owned()))?;
            json_bytes(&json!({
                "session_id": browser_session_id,
                "current_url": current_url,
                "locator_hash": sha256_bytes(locator.as_bytes()),
                "element_id": element_id
            }))
        }
        _ => Err(DesktopError::AdapterUnavailable(
            "WebDriver worker received a different operation".to_owned(),
        )),
    }
}

fn browser_commit(
    configuration: &WindowsAdapterConfiguration,
    operation: &DesktopOperation,
    payload: &[u8],
) -> Result<Vec<u8>, DesktopError> {
    let endpoint = configuration
        .webdriver_endpoint
        .as_deref()
        .ok_or_else(|| DesktopError::Invalid("WebDriver endpoint is absent".to_owned()))?;
    match operation {
        DesktopOperation::BrowserNavigate {
            browser_session_id,
            url,
            origin,
        } => {
            webdriver_request(
                endpoint,
                configuration.request_timeout_ms,
                "POST",
                &format!("/session/{browser_session_id}/url"),
                Some(&json!({"url": url})),
            )?;
            let current_url = webdriver_current_url(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
            )?;
            ensure_url_origin(&current_url, origin)?;
            Ok(json_bytes(&json!({
                "current_url_hash": sha256_bytes(current_url.as_bytes()),
                "origin": origin
            }))?)
        }
        DesktopOperation::BrowserInteract {
            browser_session_id,
            origin,
            interaction,
        } => {
            let current_url = webdriver_current_url(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
            )?;
            ensure_url_origin(&current_url, origin)?;
            let selector = parse_css_locator(interaction_locator(interaction))?;
            let element_id = webdriver_find_element(
                endpoint,
                configuration.request_timeout_ms,
                browser_session_id,
                None,
                selector,
                false,
            )?
            .into_iter()
            .next()
            .ok_or_else(|| DesktopError::Precondition("WebDriver element not found".to_owned()))?;
            match interaction {
                BrowserInteraction::Click { .. } => {
                    webdriver_element_command(
                        endpoint,
                        configuration.request_timeout_ms,
                        browser_session_id,
                        &element_id,
                        "click",
                        &json!({}),
                    )?;
                }
                BrowserInteraction::TypeText { secret_ref, .. } => {
                    if secret_ref.is_some() {
                        return Err(DesktopError::AdapterUnavailable(
                            "credential-provider integration is not implemented".to_owned(),
                        ));
                    }
                    let text = std::str::from_utf8(payload).map_err(|error| {
                        DesktopError::Invalid(format!("browser text is not UTF-8: {error}"))
                    })?;
                    webdriver_element_command(
                        endpoint,
                        configuration.request_timeout_ms,
                        browser_session_id,
                        &element_id,
                        "value",
                        &json!({"text": text}),
                    )?;
                }
                BrowserInteraction::Select { .. } => {
                    let requested = std::str::from_utf8(payload).map_err(|error| {
                        DesktopError::Invalid(format!("browser select value is not UTF-8: {error}"))
                    })?;
                    let options = webdriver_find_element(
                        endpoint,
                        configuration.request_timeout_ms,
                        browser_session_id,
                        Some(&element_id),
                        "option",
                        true,
                    )?;
                    if options.len() > MAX_SELECT_OPTIONS {
                        return Err(DesktopError::Invalid(
                            "select element exceeds option bound".to_owned(),
                        ));
                    }
                    let mut selected = None;
                    for option_id in options {
                        let response = webdriver_request(
                            endpoint,
                            configuration.request_timeout_ms,
                            "GET",
                            &format!(
                                "/session/{browser_session_id}/element/{option_id}/attribute/value"
                            ),
                            None,
                        )?;
                        if response.get("value").and_then(Value::as_str) == Some(requested) {
                            selected = Some(option_id);
                            break;
                        }
                    }
                    let option_id = selected.ok_or_else(|| {
                        DesktopError::Precondition(
                            "requested select option was not found".to_owned(),
                        )
                    })?;
                    webdriver_element_command(
                        endpoint,
                        configuration.request_timeout_ms,
                        browser_session_id,
                        &option_id,
                        "click",
                        &json!({}),
                    )?;
                }
            }
            json_bytes(&json!({
                "element_id_hash": sha256_bytes(element_id.as_bytes()),
                "origin": origin,
                "completed": true
            }))
        }
        _ => Err(DesktopError::AdapterUnavailable(
            "WebDriver worker received a different operation".to_owned(),
        )),
    }
}

fn webdriver_current_url(
    endpoint: &str,
    timeout_ms: u64,
    session_id: &str,
) -> Result<String, DesktopError> {
    let response = webdriver_request(
        endpoint,
        timeout_ms,
        "GET",
        &format!("/session/{session_id}/url"),
        None,
    )?;
    response
        .get("value")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| DesktopError::Integrity("WebDriver URL response is malformed".to_owned()))
}

fn webdriver_find_element(
    endpoint: &str,
    timeout_ms: u64,
    session_id: &str,
    parent_element: Option<&str>,
    selector: &str,
    multiple: bool,
) -> Result<Vec<String>, DesktopError> {
    let suffix = if multiple { "elements" } else { "element" };
    let path = if let Some(parent) = parent_element {
        validate_webdriver_segment(parent, "WebDriver parent element ID")?;
        format!("/session/{session_id}/element/{parent}/{suffix}")
    } else {
        format!("/session/{session_id}/{suffix}")
    };
    let response = webdriver_request(
        endpoint,
        timeout_ms,
        "POST",
        &path,
        Some(&json!({"using": "css selector", "value": selector})),
    )?;
    if multiple {
        let values = response
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                DesktopError::Integrity("WebDriver elements response is malformed".to_owned())
            })?;
        values.iter().map(webdriver_element_id).collect()
    } else {
        Ok(vec![webdriver_element_id(
            response.get("value").ok_or_else(|| {
                DesktopError::Integrity("WebDriver element response has no value".to_owned())
            })?,
        )?])
    }
}

fn webdriver_element_id(value: &Value) -> Result<String, DesktopError> {
    let id = value
        .get("element-6066-11e4-a52e-4f735466cecf")
        .and_then(Value::as_str)
        .ok_or_else(|| DesktopError::Integrity("WebDriver element ID is missing".to_owned()))?;
    validate_webdriver_segment(id, "WebDriver element ID")?;
    Ok(id.to_owned())
}

fn webdriver_element_command(
    endpoint: &str,
    timeout_ms: u64,
    session_id: &str,
    element_id: &str,
    command: &str,
    body: &Value,
) -> Result<(), DesktopError> {
    validate_webdriver_segment(element_id, "WebDriver element ID")?;
    let _ = webdriver_request(
        endpoint,
        timeout_ms,
        "POST",
        &format!("/session/{session_id}/element/{element_id}/{command}"),
        Some(body),
    )?;
    Ok(())
}

pub(crate) fn webdriver_request(
    endpoint: &str,
    timeout_ms: u64,
    method: &str,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, DesktopError> {
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err(DesktopError::Invalid(
            "WebDriver request path is invalid".to_owned(),
        ));
    }
    let (authority, address) = resolve_loopback_endpoint(endpoint)?;
    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
        DesktopError::AdapterUnavailable(format!("WebDriver connection failed: {error}"))
    })?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("WebDriver timeout setup failed: {error}"))
        })?;
    let body = body.map(json_bytes).transpose()?.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|error| {
            DesktopError::AdapterUnavailable(format!("WebDriver request failed: {error}"))
        })?;
    let mut response = Vec::new();
    let mut response_buffer = [0_u8; 16 * 1024];
    loop {
        match stream.read(&mut response_buffer) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&response_buffer[..read]);
                if response.len() > MAX_HTTP_BYTES {
                    return Err(DesktopError::Invalid(
                        "WebDriver response exceeds bound".to_owned(),
                    ));
                }
                if let Some(total) = complete_http_response_length(&response)? {
                    response.truncate(total);
                    break;
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset && !response.is_empty() =>
            {
                break;
            }
            Err(error) => {
                return Err(DesktopError::AdapterUnavailable(format!(
                    "WebDriver response failed: {error}"
                )));
            }
        }
    }
    if response.len() > MAX_HTTP_BYTES {
        return Err(DesktopError::Invalid(
            "WebDriver response exceeds bound".to_owned(),
        ));
    }
    parse_http_json(&response)
}

fn parse_http_json(response: &[u8]) -> Result<Value, DesktopError> {
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            DesktopError::Integrity("WebDriver HTTP response is malformed".to_owned())
        })?;
    let header_bytes = &response[..separator];
    let body = &response[separator + 4..];
    let headers = std::str::from_utf8(header_bytes)
        .map_err(|error| DesktopError::Integrity(format!("HTTP headers are not UTF-8: {error}")))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| DesktopError::Integrity("WebDriver HTTP status is invalid".to_owned()))?;
    let (chunked, content_length) = http_body_framing(lines.clone())?;
    let body = if chunked {
        decode_chunked(body)?
    } else if let Some(content_length) = content_length {
        if body.len() != content_length {
            return Err(DesktopError::Integrity(
                "WebDriver HTTP body length differs from Content-Length".to_owned(),
            ));
        }
        body.to_vec()
    } else {
        body.to_vec()
    };
    let value: Value =
        serde_json::from_slice(&body).map_err(|error| DesktopError::Json(error.to_string()))?;
    if !(200..300).contains(&status) {
        let message = value
            .pointer("/value/message")
            .and_then(Value::as_str)
            .unwrap_or("WebDriver command failed");
        return Err(DesktopError::Precondition(message.to_owned()));
    }
    Ok(value)
}

fn complete_http_response_length(response: &[u8]) -> Result<Option<usize>, DesktopError> {
    let Some(separator) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|error| DesktopError::Integrity(format!("HTTP headers are not UTF-8: {error}")))?;
    let (_, content_length) = http_body_framing(headers.split("\r\n").skip(1))?;
    let Some(content_length) = content_length else {
        return Ok(None);
    };
    let total = separator
        .checked_add(4)
        .and_then(|length| length.checked_add(content_length))
        .ok_or_else(|| DesktopError::Invalid("WebDriver response length overflow".to_owned()))?;
    if total > MAX_HTTP_BYTES {
        return Err(DesktopError::Invalid(
            "WebDriver Content-Length exceeds response bound".to_owned(),
        ));
    }
    Ok((response.len() >= total).then_some(total))
}

fn http_body_framing<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> Result<(bool, Option<usize>), DesktopError> {
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(DesktopError::Integrity(
                "WebDriver HTTP header is malformed".to_owned(),
            ));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") || chunked {
                return Err(DesktopError::Integrity(
                    "WebDriver Transfer-Encoding is unsupported or duplicated".to_owned(),
                ));
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(DesktopError::Integrity(
                    "WebDriver Content-Length is duplicated".to_owned(),
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|_| {
                DesktopError::Integrity("WebDriver Content-Length is invalid".to_owned())
            })?);
        }
    }
    if chunked && content_length.is_some() {
        return Err(DesktopError::Integrity(
            "WebDriver response contains conflicting body framing".to_owned(),
        ));
    }
    Ok((chunked, content_length))
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, DesktopError> {
    let mut input = body;
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| DesktopError::Integrity("chunked response is malformed".to_owned()))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| DesktopError::Integrity("chunk size is not UTF-8".to_owned()))?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or_default(), 16)
            .map_err(|_| DesktopError::Integrity("chunk size is invalid".to_owned()))?;
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(DesktopError::Integrity(
                "chunk body is truncated".to_owned(),
            ));
        }
        if output.len().saturating_add(size) > MAX_HTTP_BYTES {
            return Err(DesktopError::Invalid(
                "chunked WebDriver response exceeds bound".to_owned(),
            ));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(output)
}

fn resolve_loopback_endpoint(endpoint: &str) -> Result<(String, SocketAddr), DesktopError> {
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| DesktopError::Invalid("WebDriver endpoint must use HTTP".to_owned()))?;
    let mut addresses = authority.to_socket_addrs().map_err(|error| {
        DesktopError::Invalid(format!("WebDriver endpoint cannot resolve: {error}"))
    })?;
    let address = addresses
        .find(|address| address.ip().is_loopback())
        .ok_or_else(|| {
            DesktopError::AccessDenied("WebDriver endpoint did not resolve to loopback".to_owned())
        })?;
    Ok((authority.to_owned(), address))
}

pub(crate) fn ensure_url_origin(url: &str, expected_origin: &str) -> Result<(), DesktopError> {
    let actual = url_origin(url)?;
    if actual != expected_origin {
        return Err(DesktopError::AccessDenied(
            "browser current URL escaped the certified origin".to_owned(),
        ));
    }
    Ok(())
}

fn url_origin(url: &str) -> Result<String, DesktopError> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(DesktopError::Invalid(
            "browser URL must use HTTP or HTTPS".to_owned(),
        ));
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty() && !value.contains('@'))
        .ok_or_else(|| DesktopError::Invalid("browser URL authority is invalid".to_owned()))?;
    Ok(format!("{scheme}://{authority}"))
}

fn interaction_locator(interaction: &BrowserInteraction) -> &str {
    match interaction {
        BrowserInteraction::Click { locator }
        | BrowserInteraction::TypeText { locator, .. }
        | BrowserInteraction::Select { locator, .. } => locator,
    }
}

fn parse_css_locator(locator: &str) -> Result<&str, DesktopError> {
    let selector = locator.strip_prefix("css:").ok_or_else(|| {
        DesktopError::Invalid("browser locator must use the css: prefix".to_owned())
    })?;
    if selector.is_empty() || selector.len() > 2048 || selector.contains('\0') {
        return Err(DesktopError::Invalid(
            "CSS selector is empty, contains NUL, or exceeds 2048 bytes".to_owned(),
        ));
    }
    Ok(selector)
}

pub(crate) fn validate_webdriver_segment(value: &str, field: &str) -> Result<(), DesktopError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(DesktopError::Invalid(format!(
            "{field} is not a safe WebDriver path segment"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod http_framing_tests {
    use super::{complete_http_response_length, parse_http_json};

    #[test]
    fn content_length_completes_without_connection_close() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"value\":{\"ready\":true}}trailing";
        assert_eq!(
            complete_http_response_length(response).ok(),
            Some(Some(response.len() - b"trailing".len()))
        );
        let complete = &response[..response.len() - b"trailing".len()];
        assert_eq!(
            parse_http_json(complete).ok().and_then(|value| value
                .pointer("/value/ready")
                .and_then(|value| value.as_bool())),
            Some(true)
        );
    }

    #[test]
    fn conflicting_http_framing_is_rejected() {
        let response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}";
        assert!(complete_http_response_length(response).is_err());
    }
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || d2i_windows_host::is_reparse_point(path)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(format!(
            "{label} must be a non-reparse regular file"
        )));
    }
    std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn canonical_non_reparse_directory(path: &Path) -> Result<PathBuf, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || d2i_windows_host::is_reparse_point(path)
            .map_err(|error| DesktopError::Integrity(error.to_string()))?
    {
        return Err(DesktopError::Integrity(
            "working directory must be a non-reparse directory".to_owned(),
        ));
    }
    std::fs::canonicalize(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn write_frame<T: Serialize>(
    writer: &mut impl Write,
    header: &T,
    payload: &[u8],
) -> Result<(), DesktopError> {
    let header = json_bytes(header)?;
    if header.len() > MAX_PROTOCOL_JSON_BYTES {
        return Err(DesktopError::Invalid(
            "Windows worker protocol header exceeds bound".to_owned(),
        ));
    }
    let length = u32::try_from(header.len())
        .map_err(|_| DesktopError::Invalid("worker header length overflow".to_owned()))?;
    writer
        .write_all(&length.to_le_bytes())
        .and_then(|()| writer.write_all(&header))
        .and_then(|()| writer.write_all(payload))
        .and_then(|()| writer.flush())
        .map_err(|error| DesktopError::Io {
            path: "windows-worker-pipe".to_owned(),
            message: error.to_string(),
        })
}

fn read_request_frame(
    reader: &mut impl Read,
) -> Result<Option<(WorkerRequest, Vec<u8>)>, DesktopError> {
    let Some(header) = read_header_bytes(reader)? else {
        return Ok(None);
    };
    let request: WorkerRequest =
        serde_json::from_slice(&header).map_err(|error| DesktopError::Json(error.to_string()))?;
    if request.schema_version != 1
        || request.payload_bytes > u64::try_from(MAX_ACTION_PAYLOAD_BYTES).unwrap_or(u64::MAX)
    {
        return Err(DesktopError::Invalid(
            "Windows worker request version or payload bound is invalid".to_owned(),
        ));
    }
    let payload_length = usize::try_from(request.payload_bytes)
        .map_err(|_| DesktopError::Invalid("worker payload length overflow".to_owned()))?;
    let mut payload = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| DesktopError::Io {
            path: "windows-worker-stdin".to_owned(),
            message: error.to_string(),
        })?;
    Ok(Some((request, payload)))
}

fn read_response_frame(reader: &mut impl Read) -> Result<WorkerReply, DesktopError> {
    let header = read_header_bytes(reader)?.ok_or_else(|| {
        DesktopError::AdapterUnavailable("Windows worker closed its output".to_owned())
    })?;
    let response: WorkerResponse =
        serde_json::from_slice(&header).map_err(|error| DesktopError::Json(error.to_string()))?;
    if response.schema_version != 1
        || response.payload_bytes > u64::try_from(MAX_ACTION_PAYLOAD_BYTES).unwrap_or(u64::MAX)
    {
        return Err(DesktopError::Integrity(
            "Windows worker response version or payload bound is invalid".to_owned(),
        ));
    }
    let payload_length = usize::try_from(response.payload_bytes)
        .map_err(|_| DesktopError::Integrity("worker response length overflow".to_owned()))?;
    let mut payload = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| DesktopError::Io {
            path: "windows-worker-stdout".to_owned(),
            message: error.to_string(),
        })?;
    Ok(WorkerReply {
        header: response,
        payload,
    })
}

fn read_header_bytes(reader: &mut impl Read) -> Result<Option<Vec<u8>>, DesktopError> {
    let mut length = [0_u8; 4];
    let mut read = 0;
    while read < length.len() {
        match reader.read(&mut length[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => {
                return Err(DesktopError::Integrity(
                    "Windows worker frame length is truncated".to_owned(),
                ));
            }
            Ok(count) => read += count,
            Err(error) => {
                return Err(DesktopError::Io {
                    path: "windows-worker-pipe".to_owned(),
                    message: error.to_string(),
                });
            }
        }
    }
    let length = usize::try_from(u32::from_le_bytes(length))
        .map_err(|_| DesktopError::Invalid("worker header length overflow".to_owned()))?;
    if length == 0 || length > MAX_PROTOCOL_JSON_BYTES {
        return Err(DesktopError::Invalid(
            "Windows worker header length is outside bounds".to_owned(),
        ));
    }
    let mut header = vec![0_u8; length];
    reader
        .read_exact(&mut header)
        .map_err(|error| DesktopError::Io {
            path: "windows-worker-pipe".to_owned(),
            message: error.to_string(),
        })?;
    Ok(Some(header))
}

fn write_worker_success(
    writer: &mut impl Write,
    request_id: u64,
    payload: &[u8],
) -> Result<(), DesktopError> {
    write_frame(
        writer,
        &WorkerResponse {
            schema_version: 1,
            request_id,
            status: WorkerResponseStatus::Succeeded,
            payload_bytes: u64::try_from(payload.len()).unwrap_or(u64::MAX),
            message: "completed".to_owned(),
        },
        payload,
    )
}

fn write_worker_error(
    writer: &mut impl Write,
    request_id: u64,
    message: &str,
) -> Result<(), DesktopError> {
    let bounded = if message.len() > 4096 {
        "Windows worker operation failed with an oversized diagnostic"
    } else {
        message
    };
    write_frame(
        writer,
        &WorkerResponse {
            schema_version: 1,
            request_id,
            status: WorkerResponseStatus::Failed,
            payload_bytes: 0,
            message: bounded.to_owned(),
        },
        &[],
    )
}

#[cfg(windows)]
mod platform_ui {
    use super::*;
    use uiautomation::patterns::{UIInvokePattern, UITogglePattern, UIValuePattern};
    use uiautomation::types::{ToggleState, TreeScope, UIProperty};
    use uiautomation::variants::Variant;
    use uiautomation::UIAutomation;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
    struct UiElementSnapshot {
        window: WindowIdentity,
        automation_id: String,
        runtime_id: Vec<i32>,
        enabled: bool,
        pattern: String,
        state_hash: Option<String>,
    }

    pub(super) fn probe() -> Result<Value, DesktopError> {
        let automation = UIAutomation::new()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let root = automation
            .get_root_element()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let _ = root
            .get_runtime_id()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        Ok(json!({"ready": true, "api": "Windows UI Automation", "root_accessible": true}))
    }

    pub(super) fn snapshot(
        configuration: &WindowsAdapterConfiguration,
        operation: &DesktopOperation,
    ) -> Result<Vec<u8>, DesktopError> {
        match operation {
            DesktopOperation::ListWindows => json_bytes(&list_windows(configuration)?),
            DesktopOperation::UiInteract {
                window,
                interaction,
            } => json_bytes(&element_snapshot(window, interaction)?),
            _ => Err(DesktopError::AdapterUnavailable(
                "UI Automation worker received a different operation".to_owned(),
            )),
        }
    }

    pub(super) fn commit(
        configuration: &WindowsAdapterConfiguration,
        operation: &DesktopOperation,
        payload: &[u8],
    ) -> Result<Vec<u8>, DesktopError> {
        match operation {
            DesktopOperation::ListWindows => json_bytes(&list_windows(configuration)?),
            DesktopOperation::UiInteract {
                window,
                interaction,
            } => {
                let element = find_element(window, interaction_automation_id(interaction))?;
                match interaction {
                    UiInteraction::Invoke { .. } => {
                        let pattern: UIInvokePattern = element
                            .get_pattern()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                        pattern
                            .invoke()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                    }
                    UiInteraction::SetText { secret_ref, .. } => {
                        if secret_ref.is_some() {
                            return Err(DesktopError::AdapterUnavailable(
                                "credential-provider integration is not implemented".to_owned(),
                            ));
                        }
                        let value = std::str::from_utf8(payload).map_err(|error| {
                            DesktopError::Invalid(format!("UI text is not UTF-8: {error}"))
                        })?;
                        let pattern: UIValuePattern = element
                            .get_pattern()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                        if pattern
                            .is_readonly()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?
                        {
                            return Err(DesktopError::Precondition(
                                "UI value pattern is read-only".to_owned(),
                            ));
                        }
                        pattern
                            .set_value(value)
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                    }
                    UiInteraction::Toggle { desired, .. } => {
                        let pattern: UITogglePattern = element
                            .get_pattern()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                        for _ in 0..3 {
                            let state = pattern
                                .get_toggle_state()
                                .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                            if (state == ToggleState::On) == *desired
                                && state != ToggleState::Indeterminate
                            {
                                return json_bytes(&json!({"desired": desired, "matched": true}));
                            }
                            pattern
                                .toggle()
                                .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                        }
                        let state = pattern
                            .get_toggle_state()
                            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                        if (state == ToggleState::On) != *desired
                            || state == ToggleState::Indeterminate
                        {
                            return Err(DesktopError::Precondition(
                                "UI toggle did not reach requested state".to_owned(),
                            ));
                        }
                    }
                }
                json_bytes(&json!({
                    "window_process_id": window.process_id,
                    "automation_id_hash": sha256_bytes(
                        interaction_automation_id(interaction).as_bytes()
                    ),
                    "completed": true
                }))
            }
            _ => Err(DesktopError::AdapterUnavailable(
                "UI Automation worker received a different operation".to_owned(),
            )),
        }
    }

    fn list_windows(
        configuration: &WindowsAdapterConfiguration,
    ) -> Result<Vec<WindowIdentity>, DesktopError> {
        let automation = UIAutomation::new()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let root = automation
            .get_root_element()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let condition = automation
            .create_true_condition()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let elements = root
            .find_all(TreeScope::Children, &condition)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        if elements.len() > MAX_WINDOWS {
            return Err(DesktopError::Invalid(
                "UI Automation top-level window count exceeds bound".to_owned(),
            ));
        }
        let mut windows = Vec::new();
        let mut executable_hashes: BTreeMap<PathBuf, String> = BTreeMap::new();
        for element in elements {
            let process_id = match element.get_process_id() {
                Ok(0) | Err(_) => continue,
                Ok(value) => value,
            };
            let executable = match d2i_windows_host::process_image_path(process_id) {
                Ok(path) => path,
                Err(_) => continue,
            };
            let executable = match canonical_regular_file(&executable, "window executable") {
                Ok(path) => path,
                Err(_) => continue,
            };
            let executable_hash = match executable_hashes.get(&executable) {
                Some(hash) => hash.clone(),
                None => {
                    let hash = match read_bounded(&executable, MAX_FILE_SNAPSHOT_BYTES) {
                        Ok(bytes) => sha256_bytes(&bytes),
                        Err(_) => continue,
                    };
                    executable_hashes.insert(executable, hash.clone());
                    hash
                }
            };
            if !configuration
                .ui_allowed_executable_hashes
                .contains(&executable_hash)
            {
                continue;
            }
            let title = element.get_name().unwrap_or_default();
            windows.push(WindowIdentity {
                process_id,
                executable_hash,
                title_hash: sha256_bytes(title.as_bytes()),
            });
        }
        windows.sort_by(|left, right| {
            (left.process_id, &left.executable_hash, &left.title_hash).cmp(&(
                right.process_id,
                &right.executable_hash,
                &right.title_hash,
            ))
        });
        windows.dedup();
        Ok(windows)
    }

    fn element_snapshot(
        window: &WindowIdentity,
        interaction: &UiInteraction,
    ) -> Result<UiElementSnapshot, DesktopError> {
        let automation_id = interaction_automation_id(interaction);
        let element = find_element(window, automation_id)?;
        let enabled = element
            .is_enabled()
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        if !enabled {
            return Err(DesktopError::Precondition(
                "UI Automation element is disabled".to_owned(),
            ));
        }
        let runtime_id = element
            .get_runtime_id()
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        let (pattern, state_hash) = match interaction {
            UiInteraction::Invoke { .. } => {
                let _: UIInvokePattern = element
                    .get_pattern()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                ("invoke".to_owned(), None)
            }
            UiInteraction::SetText { .. } => {
                let pattern: UIValuePattern = element
                    .get_pattern()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                if pattern
                    .is_readonly()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?
                {
                    return Err(DesktopError::Precondition(
                        "UI value pattern is read-only".to_owned(),
                    ));
                }
                let current = pattern
                    .get_value()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                ("value".to_owned(), Some(sha256_bytes(current.as_bytes())))
            }
            UiInteraction::Toggle { .. } => {
                let pattern: UITogglePattern = element
                    .get_pattern()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                let current = pattern
                    .get_toggle_state()
                    .map_err(|error| DesktopError::Precondition(error.to_string()))?;
                (
                    "toggle".to_owned(),
                    Some(sha256_bytes(format!("{current:?}").as_bytes())),
                )
            }
        };
        Ok(UiElementSnapshot {
            window: window.clone(),
            automation_id: automation_id.to_owned(),
            runtime_id,
            enabled,
            pattern,
            state_hash,
        })
    }

    fn find_element(
        window: &WindowIdentity,
        automation_id: &str,
    ) -> Result<uiautomation::UIElement, DesktopError> {
        let actual_path = d2i_windows_host::process_image_path(window.process_id)
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        let actual_path = canonical_regular_file(&actual_path, "window executable")?;
        let actual_hash = sha256_bytes(&read_bounded(&actual_path, MAX_FILE_SNAPSHOT_BYTES)?);
        if actual_hash != window.executable_hash {
            return Err(DesktopError::Integrity(
                "window executable hash changed".to_owned(),
            ));
        }
        let automation = UIAutomation::new()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let root = automation
            .get_root_element()
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let process_id = i32::try_from(window.process_id).map_err(|_| {
            DesktopError::Invalid("window process_id exceeds UI Automation range".to_owned())
        })?;
        let process_condition = automation
            .create_property_condition(UIProperty::ProcessId, Variant::from(process_id), None)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let candidates = root
            .find_all(TreeScope::Children, &process_condition)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let mut matching_windows = Vec::new();
        for candidate in candidates {
            let title = candidate
                .get_name()
                .map_err(|error| DesktopError::Precondition(error.to_string()))?;
            if sha256_bytes(title.as_bytes()) == window.title_hash {
                matching_windows.push(candidate);
            }
        }
        if matching_windows.len() != 1 {
            return Err(DesktopError::Precondition(
                "window identity did not resolve uniquely".to_owned(),
            ));
        }
        let window_element = matching_windows.remove(0);
        let condition = automation
            .create_property_condition(UIProperty::AutomationId, Variant::from(automation_id), None)
            .map_err(|error| DesktopError::AdapterUnavailable(error.to_string()))?;
        let mut elements = window_element
            .find_all(TreeScope::Descendants, &condition)
            .map_err(|error| DesktopError::Precondition(error.to_string()))?;
        if elements.len() != 1 {
            return Err(DesktopError::Precondition(
                "automation_id did not resolve uniquely in the target window".to_owned(),
            ));
        }
        Ok(elements.remove(0))
    }

    fn interaction_automation_id(interaction: &UiInteraction) -> &str {
        match interaction {
            UiInteraction::Invoke { automation_id }
            | UiInteraction::SetText { automation_id, .. }
            | UiInteraction::Toggle { automation_id, .. } => automation_id,
        }
    }
}

#[cfg(not(windows))]
mod platform_ui {
    use super::*;

    pub(super) fn probe() -> Result<Value, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "Windows UI Automation is unavailable on this platform".to_owned(),
        ))
    }

    pub(super) fn snapshot(
        _configuration: &WindowsAdapterConfiguration,
        _operation: &DesktopOperation,
    ) -> Result<Vec<u8>, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "Windows UI Automation is unavailable on this platform".to_owned(),
        ))
    }

    pub(super) fn commit(
        _configuration: &WindowsAdapterConfiguration,
        _operation: &DesktopOperation,
        _payload: &[u8],
    ) -> Result<Vec<u8>, DesktopError> {
        Err(DesktopError::AdapterUnavailable(
            "Windows UI Automation is unavailable on this platform".to_owned(),
        ))
    }
}
