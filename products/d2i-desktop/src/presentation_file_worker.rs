use crate::{mutate_pptx_presentation, PptxPresentationMutationV1};
use d2i_presentation_capability::{
    parse_presentation_json_strict, PresentationFactBindingV1, PresentationMutationV1,
    PresentationResourceLimitsV1, PresentationSemanticSnapshotV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationFileWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub workspace_root: String,
    pub expected_source_sha256: String,
    pub presentation_id: String,
    pub artifact_id: String,
    pub generation: u64,
    pub backend_id: String,
    pub observed_at_unix_ms: u64,
    pub mutation: PresentationMutationV1,
    pub facts: PresentationFactBindingV1,
    pub limits: PresentationResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationFileWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub snapshot: PresentationSemanticSnapshotV1,
}

pub fn presentation_file_worker_main() -> i32 {
    match run_worker() {
        Ok(response) => match d2i_office_capability::canonical_json_bytes(&response) {
            Ok(bytes) if std::io::stdout().write_all(&bytes).is_ok() => 0,
            Ok(_) | Err(_) => 1,
        },
        Err(error) => {
            eprintln!("{}", bounded_error(&error));
            1
        }
    }
}

fn run_worker() -> Result<PresentationFileWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let request: PresentationFileWorkerRequestV1 =
        parse_presentation_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate_request(&request)?;
    let snapshot = mutate_pptx_presentation(PptxPresentationMutationV1 {
        source: Path::new(&request.source_path),
        destination: Path::new(&request.destination_path),
        workspace_root: Path::new(&request.workspace_root),
        expected_source_sha256: &request.expected_source_sha256,
        presentation_id: &request.presentation_id,
        artifact_id: &request.artifact_id,
        generation: request.generation,
        backend_id: &request.backend_id,
        observed_at_unix_ms: request.observed_at_unix_ms,
        mutation: &request.mutation,
        facts: &request.facts,
        limits: &request.limits,
    })?;
    Ok(PresentationFileWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        snapshot,
    })
}

pub fn spawn_presentation_file_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    request: &PresentationFileWorkerRequestV1,
    timeout: Duration,
) -> Result<PresentationFileWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
        || d2i_office_capability::sha256_bytes(
            &fs::read(worker_executable).map_err(|error| error.to_string())?,
        ) != expected_worker_sha256
    {
        return Err("presentation file worker executable binding differs".to_owned());
    }
    validate_request(request)?;
    let bytes =
        d2i_office_capability::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let mut command = Command::new(worker_executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "presentation worker stdin is unavailable".to_owned())?
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "presentation worker stdout is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "presentation worker stderr is unavailable".to_owned())?;
    let out_reader = std::thread::spawn(move || read_bounded(stdout, 4 * 1024 * 1024));
    let err_reader = std::thread::spawn(move || read_bounded(stderr, 8 * 1024));
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("presentation file worker exceeded its bounded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = out_reader
        .join()
        .map_err(|_| "presentation stdout reader panicked".to_owned())??;
    let error = err_reader
        .join()
        .map_err(|_| "presentation stderr reader panicked".to_owned())??;
    if !status.success() {
        return Err(format!(
            "presentation file worker failed: {}",
            String::from_utf8_lossy(&error).trim()
        ));
    }
    let response: PresentationFileWorkerResponseV1 =
        parse_presentation_json_strict(&output).map_err(|error| error.to_string())?;
    response
        .snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.snapshot.artifact_generation != request.generation
    {
        return Err("presentation file worker response binding differs".to_owned());
    }
    Ok(response)
}

fn validate_request(value: &PresentationFileWorkerRequestV1) -> Result<(), String> {
    if value.schema_version != 1
        || value.request_id.is_empty()
        || value.request_id.len() > 512
        || value.generation < 2
        || !Path::new(&value.source_path).is_file()
        || Path::new(&value.destination_path).exists()
        || value.source_path == value.destination_path
        || !Path::new(&value.workspace_root).is_dir()
    {
        return Err("presentation file worker request is invalid".to_owned());
    }
    value.facts.validate().map_err(|error| error.to_string())
}

fn read_bounded<T: Read>(pipe: T, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    pipe.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("presentation worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn bounded_error(value: &str) -> String {
    if value.len() <= 512
        && !value.contains("\\\\")
        && !value.contains(":\\")
        && !value.contains("file://")
    {
        value.to_owned()
    } else {
        "presentation_file_worker_bounded_failure".to_owned()
    }
}
