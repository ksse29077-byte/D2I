use crate::{
    inspect_docx_document, inspect_hwpx_document, mutate_docx_document, mutate_hwpx_document,
    ResolvedDocumentOperationV1,
};
use d2i_document_capability::{
    DocumentFormatV1, DocumentResourceLimitsV1, DocumentSemanticSnapshotV1,
};
use d2i_office_capability::sha256_bytes;
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
pub struct DocumentFileWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub expected_source_sha256: String,
    pub format_id: DocumentFormatV1,
    pub document_id: String,
    pub artifact_id: String,
    pub generation: u64,
    pub backend_id: String,
    pub observed_at_unix_ms: u64,
    pub operation: ResolvedDocumentOperationV1,
    pub limits: DocumentResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentFileWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_content_sha256: String,
    pub destination_content_sha256: String,
    pub bytes_written: u64,
    pub snapshot: DocumentSemanticSnapshotV1,
}

pub fn document_file_worker_main() -> i32 {
    match run_document_file_worker() {
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

fn run_document_file_worker() -> Result<DocumentFileWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let request: DocumentFileWorkerRequestV1 =
        d2i_document_capability::parse_document_json_strict(&bytes)
            .map_err(|error| error.to_string())?;
    validate_request(&request)?;
    let source = Path::new(&request.source_path);
    let destination = Path::new(&request.destination_path);
    let source_content_sha256 = file_sha256(source)?;
    if source_content_sha256 != request.expected_source_sha256 {
        return Err("document file worker source hash differs".to_owned());
    }
    let bytes_written = match request.format_id {
        DocumentFormatV1::Hwpx => {
            mutate_hwpx_document(source, destination, &request.operation, &request.limits)?
        }
        DocumentFormatV1::Docx => {
            mutate_docx_document(source, destination, &request.operation, &request.limits)?
        }
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => {
            return Err("legacy binary document format requires an approved conversion".to_owned())
        }
    };
    let snapshot = match request.format_id {
        DocumentFormatV1::Hwpx => inspect_hwpx_document(
            destination,
            &request.document_id,
            &request.artifact_id,
            request.generation,
            &request.backend_id,
            request.observed_at_unix_ms,
            &request.limits,
        )?,
        DocumentFormatV1::Docx => inspect_docx_document(
            destination,
            &request.document_id,
            &request.artifact_id,
            request.generation,
            &request.backend_id,
            request.observed_at_unix_ms,
            &request.limits,
        )?,
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => {
            return Err("legacy binary document cannot produce a file-worker snapshot".to_owned())
        }
    };
    Ok(DocumentFileWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        source_content_sha256,
        destination_content_sha256: file_sha256(destination)?,
        bytes_written,
        snapshot,
    })
}

pub fn spawn_document_file_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    request: &DocumentFileWorkerRequestV1,
    timeout: Duration,
) -> Result<DocumentFileWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
        || file_sha256(worker_executable)? != expected_worker_sha256
    {
        return Err("document file worker executable binding differs".to_owned());
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
        .ok_or_else(|| "document worker stdin unavailable".to_owned())?
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "document worker stdout unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "document worker stderr unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_child_pipe(Some(stdout), 2 * 1024 * 1024));
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
            return Err("document file worker exceeded its deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = join_reader(stdout_reader)?;
    let error = join_reader(stderr_reader)?;
    if !status.success() {
        remove_owned_temporary(request, worker_process_id)?;
        return Err(format!(
            "document file worker failed: {}",
            String::from_utf8_lossy(&error).trim()
        ));
    }
    let response: DocumentFileWorkerResponseV1 =
        d2i_document_capability::parse_document_json_strict(&output)
            .map_err(|error| error.to_string())?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.source_content_sha256 != request.expected_source_sha256
        || response.snapshot.document_id != request.document_id
        || response.snapshot.artifact_id != request.artifact_id
        || response.snapshot.artifact_generation != request.generation
        || response.snapshot.format_id != request.format_id
        || response.snapshot.backend_id != request.backend_id
        || response.snapshot.source_content_sha256 != response.destination_content_sha256
        || file_sha256(Path::new(&request.destination_path))? != response.destination_content_sha256
    {
        return Err("document file worker response differs from request".to_owned());
    }
    Ok(response)
}

fn join_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| "document worker pipe reader panicked".to_owned())?
}

fn validate_request(request: &DocumentFileWorkerRequestV1) -> Result<(), String> {
    if request.schema_version != 1
        || request.request_id.is_empty()
        || request.request_id.len() > 512
        || !Path::new(&request.source_path).is_file()
        || Path::new(&request.destination_path).exists()
        || !matches!(
            request.format_id,
            DocumentFormatV1::Hwpx | DocumentFormatV1::Docx
        )
    {
        return Err("document file worker request is invalid".to_owned());
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
    pipe.ok_or_else(|| "document worker pipe unavailable".to_owned())?
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err("document worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn remove_owned_temporary(
    request: &DocumentFileWorkerRequestV1,
    worker_process_id: u32,
) -> Result<(), String> {
    let destination = Path::new(&request.destination_path);
    let parent = destination
        .parent()
        .ok_or_else(|| "document destination parent unavailable".to_owned())?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "document destination filename invalid".to_owned())?;
    let temporary = parent.join(format!(".{name}.d2i-office200-{worker_process_id}.tmp"));
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
        "document_file_worker_bounded_failure".to_owned()
    }
}
