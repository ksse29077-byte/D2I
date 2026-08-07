use crate::document_work::validate_resolved_operation;
use crate::{inspect_docx_document, ResolvedDocumentOperationV1};
use d2i_document_capability::{DocumentResourceLimitsV1, DocumentSemanticSnapshotV1};
use d2i_office_capability::sha256_bytes;
use d2i_windows_host::{
    execute_word_document_operation, WordAutomationOperationV1, WordAutomationReceiptV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordDocumentMutationReceiptV1 {
    pub schema_version: u32,
    pub source_content_sha256: String,
    pub destination_content_sha256: String,
    pub destination_semantic_sha256: String,
    pub word_process_id: u32,
    pub word_visible: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub temporary_files_remaining: u32,
}

pub struct WordDocumentMutationV1<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub expected_source_sha256: &'a str,
    pub document_id: &'a str,
    pub artifact_id: &'a str,
    pub generation: u64,
    pub backend_id: &'a str,
    pub observed_at_unix_ms: u64,
    pub operation: &'a ResolvedDocumentOperationV1,
    pub limits: &'a DocumentResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordDocumentWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub expected_source_sha256: String,
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
pub struct WordDocumentWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub snapshot: DocumentSemanticSnapshotV1,
    pub mutation_receipt: WordDocumentMutationReceiptV1,
}

pub fn mutate_docx_with_word(
    request: WordDocumentMutationV1<'_>,
) -> Result<(DocumentSemanticSnapshotV1, WordDocumentMutationReceiptV1), String> {
    validate_resolved_operation(request.operation, request.limits)?;
    if !request.source.is_file() || request.destination.exists() {
        return Err("Word mutation requires an existing source and a new destination".to_owned());
    }
    let source_bytes = fs::read(request.source).map_err(|error| error.to_string())?;
    let source_sha256 = sha256_bytes(&source_bytes);
    if source_sha256 != request.expected_source_sha256 {
        return Err("Word mutation source hash differs".to_owned());
    }
    let destination_parent = request
        .destination
        .parent()
        .ok_or_else(|| "Word destination parent is missing".to_owned())?;
    if !destination_parent.is_dir()
        || d2i_windows_host::is_reparse_point(destination_parent)
            .map_err(|error| error.to_string())?
    {
        return Err("Word destination parent is unsafe".to_owned());
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let staging = destination_parent.join(format!(".d2i-word-{}-{nonce}.docx", std::process::id()));
    fs::write(&staging, &source_bytes).map_err(|error| error.to_string())?;
    let mut image_staging = None;
    let operation = match request.operation {
        ResolvedDocumentOperationV1::AppendParagraph { text, .. } => {
            WordAutomationOperationV1::AppendParagraph { text: text.clone() }
        }
        ResolvedDocumentOperationV1::InsertTable { cells, .. } => {
            WordAutomationOperationV1::InsertTable {
                cells: cells.clone(),
            }
        }
        ResolvedDocumentOperationV1::InsertImage {
            media_type, bytes, ..
        } => {
            let extension = match media_type.as_str() {
                "image/png" => "png",
                "image/jpeg" => "jpg",
                _ => return cleanup_error(&staging, None, "unsupported Word image type"),
            };
            let path = destination_parent.join(format!(
                ".d2i-word-image-{}-{nonce}.{extension}",
                std::process::id()
            ));
            if let Err(error) = fs::write(&path, bytes) {
                let _ = cleanup_temporary(&staging, None);
                return Err(error.to_string());
            }
            image_staging = Some(path.clone());
            WordAutomationOperationV1::InsertImage { image_path: path }
        }
        _ => {
            return cleanup_error(
                &staging,
                image_staging.as_deref(),
                "operation is not supported by the Word live backend",
            )
        }
    };
    let word_receipt = match execute_word_document_operation(&staging, &operation) {
        Ok(receipt) => receipt,
        Err(error) => {
            let _ = cleanup_temporary(&staging, image_staging.as_deref());
            return Err(error.to_string());
        }
    };
    if let Some(image) = image_staging.as_deref() {
        fs::remove_file(image).map_err(|error| error.to_string())?;
    }
    let snapshot = match inspect_docx_document(
        &staging,
        request.document_id,
        request.artifact_id,
        request.generation,
        request.backend_id,
        request.observed_at_unix_ms,
        request.limits,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => return cleanup_error(&staging, None, &error),
    };
    if let Err(error) = d2i_windows_host::atomic_move(&staging, request.destination, false) {
        let _ = cleanup_temporary(&staging, None);
        return Err(error.to_string());
    }
    let destination_bytes = fs::read(request.destination).map_err(|error| error.to_string())?;
    let receipt = mutation_receipt(
        source_sha256,
        sha256_bytes(&destination_bytes),
        snapshot.semantic_state_sha256.clone(),
        word_receipt,
    );
    Ok((snapshot, receipt))
}

fn mutation_receipt(
    source_content_sha256: String,
    destination_content_sha256: String,
    destination_semantic_sha256: String,
    word: WordAutomationReceiptV1,
) -> WordDocumentMutationReceiptV1 {
    WordDocumentMutationReceiptV1 {
        schema_version: 1,
        source_content_sha256,
        destination_content_sha256,
        destination_semantic_sha256,
        word_process_id: word.word_process_id,
        word_visible: word.visible,
        display_alerts: word.display_alerts,
        automation_security: word.automation_security,
        temporary_files_remaining: 0,
    }
}

fn cleanup_error<T>(staging: &Path, image: Option<&Path>, message: &str) -> Result<T, String> {
    cleanup_temporary(staging, image)?;
    Err(message.to_owned())
}

fn cleanup_temporary(staging: &Path, image: Option<&Path>) -> Result<(), String> {
    for path in [Some(staging), image].into_iter().flatten() {
        if path.exists() {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub fn word_document_worker_main() -> i32 {
    match run_word_document_worker() {
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
            eprintln!("{}", bounded_worker_error(&error));
            1
        }
    }
}

pub fn spawn_word_document_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    word_executable: &Path,
    request: &WordDocumentWorkerRequestV1,
    timeout: Duration,
) -> Result<WordDocumentWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
    {
        return Err("Word worker executable is not a regular bound file".to_owned());
    }
    let worker_bytes = fs::read(worker_executable).map_err(|error| error.to_string())?;
    if sha256_bytes(&worker_bytes) != expected_worker_sha256 {
        return Err("Word worker executable hash differs".to_owned());
    }
    if !word_executable.is_file() {
        return Err("bound WINWORD executable is unavailable".to_owned());
    }
    let before_word_processes =
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?;
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
        .ok_or_else(|| "Word worker stdin is unavailable".to_owned())?
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Word worker stdout is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Word worker stderr is unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_bounded_pipe(stdout, 2 * 1024 * 1024));
    let stderr_reader = std::thread::spawn(move || read_bounded_pipe(stderr, 4_096));
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            cleanup_timed_out_worker(
                request,
                worker_process_id,
                &before_word_processes,
                word_executable,
            )?;
            return Err("Word worker exceeded its bounded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = join_pipe_reader(stdout_reader)?;
    let error_output = join_pipe_reader(stderr_reader)?;
    if !status.success() || output.len() > 2 * 1024 * 1024 {
        cleanup_timed_out_worker(
            request,
            worker_process_id,
            &before_word_processes,
            word_executable,
        )?;
        let summary = String::from_utf8_lossy(&error_output);
        return Err(format!(
            "Word worker failed without a verified response: {}",
            summary.trim()
        ));
    }
    let response: WordDocumentWorkerResponseV1 =
        d2i_document_capability::parse_document_json_strict(&output)
            .map_err(|error| error.to_string())?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.snapshot.document_id != request.document_id
        || response.snapshot.artifact_id != request.artifact_id
        || response.snapshot.artifact_generation != request.generation
        || response.snapshot.backend_id != request.backend_id
        || response.mutation_receipt.word_visible
        || response.mutation_receipt.display_alerts != 0
        || response.mutation_receipt.automation_security != 3
        || response.mutation_receipt.temporary_files_remaining != 0
    {
        return Err("Word worker response differs from the bound request".to_owned());
    }
    Ok(response)
}

fn read_bounded_pipe<T: Read>(pipe: T, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    pipe.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err("Word worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn join_pipe_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| "Word worker pipe reader panicked".to_owned())?
}

fn cleanup_timed_out_worker(
    request: &WordDocumentWorkerRequestV1,
    worker_process_id: u32,
    before_word_processes: &[u32],
    word_executable: &Path,
) -> Result<(), String> {
    for process_id in
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?
    {
        if !before_word_processes.contains(&process_id) {
            match d2i_windows_host::process_image_path(process_id) {
                Ok(actual)
                    if actual
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&word_executable.to_string_lossy()) =>
                {
                    if let Err(error) = d2i_windows_host::terminate_process_if_exact_image(
                        process_id,
                        word_executable,
                    ) {
                        let still_word = d2i_windows_host::installed_word_process_ids()
                            .map_err(|inventory_error| inventory_error.to_string())?
                            .contains(&process_id);
                        if still_word {
                            return Err(error.to_string());
                        }
                    }
                }
                Ok(actual)
                    if actual
                        .file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.eq_ignore_ascii_case("WINWORD.EXE")) =>
                {
                    return Err("new Word PID uses an unexpected executable path".to_owned());
                }
                Ok(_) | Err(_) => {}
            }
        }
    }
    let destination = Path::new(&request.destination_path);
    if let Some(parent) = destination.parent() {
        let document_prefix = format!(".d2i-word-{worker_process_id}-");
        let image_prefix = format!(".d2i-word-image-{worker_process_id}-");
        for entry in fs::read_dir(parent)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
        {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(&document_prefix) || name.starts_with(&image_prefix) {
                let metadata = entry.metadata().map_err(|error| error.to_string())?;
                if metadata.is_file() && !metadata.file_type().is_symlink() {
                    fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
                }
            }
        }
    }
    Ok(())
}

fn bounded_worker_error(error: &str) -> String {
    if error.len() <= 512
        && !error.contains("\\\\")
        && !error.contains(":\\")
        && !error.contains("file://")
    {
        error.to_owned()
    } else {
        "word_worker_bounded_failure".to_owned()
    }
}

fn run_word_document_worker() -> Result<WordDocumentWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("Word worker request exceeds 2 MiB".to_owned());
    }
    let request: WordDocumentWorkerRequestV1 =
        d2i_document_capability::parse_document_json_strict(&bytes)
            .map_err(|error| error.to_string())?;
    if request.schema_version != 1
        || request.request_id.is_empty()
        || request.request_id.len() > 512
    {
        return Err("Word worker request header is invalid".to_owned());
    }
    let (snapshot, mutation_receipt) = mutate_docx_with_word(WordDocumentMutationV1 {
        source: Path::new(&request.source_path),
        destination: Path::new(&request.destination_path),
        expected_source_sha256: &request.expected_source_sha256,
        document_id: &request.document_id,
        artifact_id: &request.artifact_id,
        generation: request.generation,
        backend_id: &request.backend_id,
        observed_at_unix_ms: request.observed_at_unix_ms,
        operation: &request.operation,
        limits: &request.limits,
    })?;
    Ok(WordDocumentWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        snapshot,
        mutation_receipt,
    })
}
