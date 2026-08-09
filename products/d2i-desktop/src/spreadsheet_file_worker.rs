use crate::{mutate_xlsx_workbook, ResolvedSpreadsheetOperationV1};
use d2i_office_capability::sha256_bytes;
use d2i_spreadsheet_capability::{
    parse_spreadsheet_json_strict, SpreadsheetResourceLimitsV1, SpreadsheetSemanticSnapshotV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetFileWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub expected_source_sha256: String,
    pub workbook_id: String,
    pub artifact_id: String,
    pub generation: u64,
    pub backend_id: String,
    pub observed_at_unix_ms: u64,
    pub operation: ResolvedSpreadsheetOperationV1,
    pub limits: SpreadsheetResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetFileWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_content_sha256: String,
    pub destination_content_sha256: String,
    pub bytes_written: u64,
    pub snapshot: SpreadsheetSemanticSnapshotV1,
}

pub fn spreadsheet_file_worker_main() -> i32 {
    match run_spreadsheet_file_worker() {
        Ok(response) => {
            let bytes = match d2i_office_capability::canonical_json_bytes(&response) {
                Ok(bytes) => bytes,
                Err(_) => return 1,
            };
            if std::io::stdout().write_all(&bytes).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            eprintln!("{}", bounded_error(&error));
            1
        }
    }
}

fn run_spreadsheet_file_worker() -> Result<SpreadsheetFileWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let request: SpreadsheetFileWorkerRequestV1 =
        parse_spreadsheet_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate_request(&request)?;
    let source = Path::new(&request.source_path);
    let destination = Path::new(&request.destination_path);
    let source_content_sha256 = file_sha256(source)?;
    if source_content_sha256 != request.expected_source_sha256 {
        return Err("spreadsheet file worker source hash differs".to_owned());
    }
    let index = mutate_xlsx_workbook(
        source,
        destination,
        &request.operation,
        &request.workbook_id,
        &request.artifact_id,
        request.generation,
        &request.backend_id,
        request.observed_at_unix_ms,
        &request.limits,
    )?;
    let destination_content_sha256 = file_sha256(destination)?;
    let bytes_written = destination
        .metadata()
        .map_err(|error| format!("spreadsheet worker output metadata: {error}"))?
        .len();
    Ok(SpreadsheetFileWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        source_content_sha256,
        destination_content_sha256,
        bytes_written,
        snapshot: index.snapshot,
    })
}

pub fn spawn_spreadsheet_file_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    request: &SpreadsheetFileWorkerRequestV1,
    timeout: Duration,
) -> Result<SpreadsheetFileWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
        || file_sha256(worker_executable)? != expected_worker_sha256
    {
        return Err("spreadsheet file worker executable binding differs".to_owned());
    }
    validate_request(request)?;
    let request_bytes =
        d2i_office_capability::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let mut command = Command::new(worker_executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let worker_process_id = child.id();
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "spreadsheet worker stdin unavailable".to_owned())?
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "spreadsheet worker stdout unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "spreadsheet worker stderr unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_child_pipe(Some(stdout), 4 * 1024 * 1024));
    let stderr_reader = std::thread::spawn(move || read_child_pipe(Some(stderr), 4_096));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            remove_owned_temporary(request, worker_process_id)?;
            return Err("spreadsheet file worker exceeded its deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = join_reader(stdout_reader)?;
    let error = join_reader(stderr_reader)?;
    if !status.success() {
        remove_owned_temporary(request, worker_process_id)?;
        return Err(format!(
            "spreadsheet file worker failed: {}",
            String::from_utf8_lossy(&error).trim()
        ));
    }
    let response: SpreadsheetFileWorkerResponseV1 =
        parse_spreadsheet_json_strict(&output).map_err(|error| error.to_string())?;
    response
        .snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.source_content_sha256 != request.expected_source_sha256
        || response.snapshot.workbook_id != request.workbook_id
        || response.snapshot.artifact_id != request.artifact_id
        || response.snapshot.artifact_generation != request.generation
        || response.snapshot.backend_id != request.backend_id
        || response.snapshot.source_content_sha256 != response.destination_content_sha256
        || file_sha256(Path::new(&request.destination_path))? != response.destination_content_sha256
    {
        return Err("spreadsheet file worker response differs from request".to_owned());
    }
    Ok(response)
}

fn validate_request(request: &SpreadsheetFileWorkerRequestV1) -> Result<(), String> {
    let source = Path::new(&request.source_path);
    let destination = Path::new(&request.destination_path);
    if request.schema_version != 1
        || request.request_id.is_empty()
        || request.request_id.len() > 512
        || !source.is_file()
        || destination.exists()
        || request.generation < 2
        || source == destination
    {
        return Err("spreadsheet file worker request is invalid".to_owned());
    }
    Ok(())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn read_child_pipe<T: Read>(pipe: Option<T>, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    pipe.ok_or_else(|| "spreadsheet worker pipe unavailable".to_owned())?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err("spreadsheet worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn join_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| "spreadsheet worker pipe reader panicked".to_owned())?
}

fn remove_owned_temporary(
    request: &SpreadsheetFileWorkerRequestV1,
    worker_process_id: u32,
) -> Result<(), String> {
    let destination = Path::new(&request.destination_path);
    let parent = destination
        .parent()
        .ok_or_else(|| "spreadsheet destination parent unavailable".to_owned())?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "spreadsheet destination filename invalid".to_owned())?;
    let temporary = parent.join(format!(".{name}.d2i-office300-{worker_process_id}.tmp"));
    if temporary.is_file() {
        fs::remove_file(temporary).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn bounded_error(error: &str) -> String {
    if error.len() <= 512
        && !error.contains("\\\\")
        && !error.contains(":\\")
        && !error.contains("file://")
    {
        error.to_owned()
    } else {
        "spreadsheet_file_worker_bounded_failure".to_owned()
    }
}
