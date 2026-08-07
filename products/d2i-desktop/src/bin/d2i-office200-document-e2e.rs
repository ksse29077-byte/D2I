#[cfg(windows)]
use d2i_desktop::{
    create_docx_document, default_document_resource_limits, spawn_word_document_worker,
    ResolvedDocumentOperationV1, WordDocumentWorkerRequestV1,
};
#[cfg(windows)]
use d2i_document_capability::DocumentStyleRoleV1;
#[cfg(windows)]
use d2i_office_capability::sha256_bytes;
#[cfg(windows)]
use serde::Serialize;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0xf0,
    0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

#[cfg(windows)]
#[derive(Serialize)]
struct WordLiveE2eReportV1 {
    schema_version: u32,
    word_mutations: u32,
    fresh_reopens: u32,
    hidden_sessions: u32,
    macro_security_forced: u32,
    residual_word_processes: u32,
    immutable_original: bool,
    final_snapshot_sha256: String,
    final_content_sha256: String,
}

#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-200 Word live E2E failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err(
            "usage: d2i-office200-document-e2e <output-root> <word-worker> <winword>".to_owned(),
        );
    }
    let output_root = PathBuf::from(&arguments[0]);
    let worker = PathBuf::from(&arguments[1]);
    let word = PathBuf::from(&arguments[2]);
    if output_root.exists() {
        return Err("Word E2E output root must be new".to_owned());
    }
    std::fs::create_dir_all(&output_root).map_err(|error| error.to_string())?;
    let worker_sha256 = file_sha256(&worker)?;
    let limits = default_document_resource_limits();
    let original = output_root.join("word-original.docx");
    create_docx_document(&original, &limits)?;
    let original_sha256 = file_sha256(&original)?;
    let operations = vec![
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "2026년 7월 교육 개요".to_owned(),
            style_role: DocumentStyleRoleV1::Body,
        },
        ResolvedDocumentOperationV1::InsertTable {
            table_id: "table.word-live-1".to_owned(),
            cells: vec![
                vec!["항목".to_owned(), "결과".to_owned()],
                vec!["교육 이수".to_owned(), "완료".to_owned()],
            ],
            header_rows: 1,
        },
        ResolvedDocumentOperationV1::InsertImage {
            image_id: "image.word-live-1".to_owned(),
            media_type: "image/png".to_owned(),
            content_sha256: sha256_bytes(PNG_1X1),
            bytes: PNG_1X1.to_vec(),
        },
    ];
    let before_processes =
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?;
    let mut source = original.clone();
    let mut final_snapshot_sha256 = String::new();
    let mut hidden_sessions = 0_u32;
    let mut secured_sessions = 0_u32;
    for (index, operation) in operations.iter().enumerate() {
        let generation = u64::try_from(index + 1).map_err(|_| "generation overflow")?;
        let destination = output_root.join(format!("word-generation-{generation}.docx"));
        let request = WordDocumentWorkerRequestV1 {
            schema_version: 1,
            request_id: format!("request.word-live-{generation}"),
            source_path: source.to_string_lossy().to_string(),
            destination_path: destination.to_string_lossy().to_string(),
            expected_source_sha256: file_sha256(&source)?,
            document_id: "document.word-live".to_owned(),
            artifact_id: "artifact.word-live".to_owned(),
            generation,
            backend_id: "backend.word-com".to_owned(),
            observed_at_unix_ms: 1_000 + generation,
            operation: operation.clone(),
            limits: limits.clone(),
        };
        let response = spawn_word_document_worker(
            &worker,
            &worker_sha256,
            &word,
            &request,
            Duration::from_secs(120),
        )?;
        if !response.mutation_receipt.word_visible {
            hidden_sessions = hidden_sessions.saturating_add(1);
        }
        if response.mutation_receipt.automation_security == 3 {
            secured_sessions = secured_sessions.saturating_add(1);
        }
        final_snapshot_sha256 = response.snapshot.snapshot_sha256;
        source = destination;
    }
    let after_processes =
        d2i_windows_host::installed_word_process_ids().map_err(|error| error.to_string())?;
    let residual = after_processes
        .iter()
        .filter(|process_id| !before_processes.contains(process_id))
        .count();
    let report = WordLiveE2eReportV1 {
        schema_version: 1,
        word_mutations: 3,
        fresh_reopens: 3,
        hidden_sessions,
        macro_security_forced: secured_sessions,
        residual_word_processes: u32::try_from(residual).map_err(|_| "residual overflow")?,
        immutable_original: file_sha256(&original)? == original_sha256,
        final_snapshot_sha256,
        final_content_sha256: file_sha256(&source)?,
    };
    if report.hidden_sessions != 3
        || report.macro_security_forced != 3
        || report.residual_word_processes != 0
        || !report.immutable_original
    {
        return Err("Word live E2E lifecycle gate failed".to_owned());
    }
    let bytes =
        d2i_office_capability::canonical_json_bytes(&report).map_err(|error| error.to_string())?;
    std::fs::write(output_root.join("word-live-report.json"), bytes)
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn file_sha256(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("d2i-office200-document-e2e requires Windows");
    std::process::exit(1);
}
