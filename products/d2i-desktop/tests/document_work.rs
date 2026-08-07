use d2i_desktop::{
    create_docx_document, create_hwpx_from_template, default_document_resource_limits,
    inspect_docx_document, inspect_hwpx_document, mutate_docx_document, mutate_hwpx_document,
    spawn_document_file_worker, DocumentFileWorkerRequestV1, ResolvedDocumentOperationV1,
};
use d2i_document_capability::{
    DocumentNodeKindV1, DocumentPageLayoutSpecV1, DocumentStyleRoleV1, PageOrientationV1, ZERO_HASH,
};
use d2i_office_capability::sha256_bytes;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("repository root: {error}"))
}

fn test_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("test time: {error}"))
        .as_nanos();
    let root = repository_root()
        .join("target/document-work-tests")
        .join(format!("{label}-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap_or_else(|error| panic!("test root: {error}"));
    root
}

fn snapshot_hwpx(
    path: &Path,
    generation: u64,
) -> d2i_document_capability::DocumentSemanticSnapshotV1 {
    inspect_hwpx_document(
        path,
        "document.hwpx.fixture",
        "artifact.hwpx.fixture",
        generation,
        "backend.hwpx-file",
        1_000 + generation,
        &default_document_resource_limits(),
    )
    .unwrap_or_else(|error| panic!("inspect HWPX generation {generation}: {error}"))
}

fn snapshot_docx(
    path: &Path,
    generation: u64,
) -> d2i_document_capability::DocumentSemanticSnapshotV1 {
    inspect_docx_document(
        path,
        "document.docx.fixture",
        "artifact.docx.fixture",
        generation,
        "backend.docx-file",
        2_000 + generation,
        &default_document_resource_limits(),
    )
    .unwrap_or_else(|error| panic!("inspect DOCX generation {generation}: {error}"))
}

fn next_generation(root: &Path, extension: &str, generation: u64) -> PathBuf {
    root.join(format!("working-generation-{generation}.{extension}"))
}

#[test]
fn hwpx_mutations_are_new_generations_with_fresh_semantic_reopen() {
    let root = test_root("hwpx-positive");
    let template = repository_root().join("fixtures/office/document/hwpx-report-template.hwpx");
    let original_hash = sha256_bytes(
        &std::fs::read(&template).unwrap_or_else(|error| panic!("template read: {error}")),
    );
    let limits = default_document_resource_limits();
    let generation_zero = next_generation(&root, "hwpx", 0);
    create_hwpx_from_template(&template, &generation_zero, &limits)
        .unwrap_or_else(|error| panic!("create HWPX: {error}"));
    let mut source = generation_zero;
    let operations = vec![
        ResolvedDocumentOperationV1::InsertHeading {
            text: "2026년 7월 안전교육 결과보고서".to_owned(),
            level: 1,
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "교육 개요".to_owned(),
            style_role: DocumentStyleRoleV1::Heading1,
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "승인된 계획에 따라 교육을 실시하였다.".to_owned(),
            style_role: DocumentStyleRoleV1::Body,
        },
        ResolvedDocumentOperationV1::InsertTable {
            table_id: "table.education-results".to_owned(),
            cells: vec![
                vec!["과정".to_owned(), "인원".to_owned()],
                vec!["관리감독자교육".to_owned(), "55".to_owned()],
                vec!["근로자 정기교육".to_owned(), "120".to_owned()],
                vec!["신규채용자교육".to_owned(), "18".to_owned()],
            ],
            header_rows: 1,
        },
        ResolvedDocumentOperationV1::InsertImage {
            image_id: "image.approved-logo".to_owned(),
            media_type: "image/png".to_owned(),
            content_sha256: sha256_bytes(PNG_1X1),
            bytes: PNG_1X1.to_vec(),
        },
        ResolvedDocumentOperationV1::SetPageLayout {
            layout: DocumentPageLayoutSpecV1 {
                schema_version: 1,
                page_layout_spec_id: "layout.report-a4".to_owned(),
                page_size_id: "a4".to_owned(),
                orientation: PageOrientationV1::Portrait,
                top_margin_millimeters: 20,
                bottom_margin_millimeters: 20,
                left_margin_millimeters: 20,
                right_margin_millimeters: 20,
                page_layout_spec_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .unwrap_or_else(|error| panic!("layout: {error}")),
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "주요 특이사항".to_owned(),
            style_role: DocumentStyleRoleV1::Heading1,
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "향후 계획".to_owned(),
            style_role: DocumentStyleRoleV1::Heading1,
        },
    ];
    let mut snapshots = Vec::new();
    snapshots.push(snapshot_hwpx(&source, 0));
    for (index, operation) in operations.iter().enumerate() {
        let generation =
            u64::try_from(index + 1).unwrap_or_else(|error| panic!("generation: {error}"));
        let destination = next_generation(&root, "hwpx", generation);
        mutate_hwpx_document(&source, &destination, operation, &limits)
            .unwrap_or_else(|error| panic!("mutate HWPX {generation}: {error}"));
        snapshots.push(snapshot_hwpx(&destination, generation));
        source = destination;
    }
    let final_snapshot = snapshots
        .last()
        .unwrap_or_else(|| panic!("final HWPX snapshot missing"));
    assert!(final_snapshot
        .content_summary
        .contains("2026년 7월 안전교육 결과보고서"));
    assert!(final_snapshot.content_summary.contains("신규채용자교육"));
    assert!(final_snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.node_kind == DocumentNodeKindV1::Table));
    assert!(final_snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.node_kind == DocumentNodeKindV1::Image));
    assert_eq!(
        original_hash,
        sha256_bytes(
            &std::fs::read(&template).unwrap_or_else(|error| panic!("template reread: {error}"))
        )
    );
    assert_eq!(snapshots.len(), 9);
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn docx_mutations_are_reopened_and_semantically_verified() {
    let root = test_root("docx-positive");
    let limits = default_document_resource_limits();
    let generation_zero = next_generation(&root, "docx", 0);
    create_docx_document(&generation_zero, &limits)
        .unwrap_or_else(|error| panic!("create DOCX: {error}"));
    let mut source = generation_zero;
    let operations = vec![
        ResolvedDocumentOperationV1::InsertHeading {
            text: "2026년 7월 안전교육 결과보고서".to_owned(),
            level: 1,
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "교육 개요".to_owned(),
            style_role: DocumentStyleRoleV1::Heading1,
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "교육은 승인된 일정과 범위에서 실시되었다.".to_owned(),
            style_role: DocumentStyleRoleV1::Body,
        },
        ResolvedDocumentOperationV1::InsertTable {
            table_id: "table.education-results".to_owned(),
            cells: vec![
                vec!["과정".to_owned(), "인원".to_owned()],
                vec!["관리감독자교육".to_owned(), "55".to_owned()],
                vec!["근로자 정기교육".to_owned(), "120".to_owned()],
                vec!["신규채용자교육".to_owned(), "18".to_owned()],
            ],
            header_rows: 1,
        },
        ResolvedDocumentOperationV1::InsertImage {
            image_id: "image.approved-logo".to_owned(),
            media_type: "image/png".to_owned(),
            content_sha256: sha256_bytes(PNG_1X1),
            bytes: PNG_1X1.to_vec(),
        },
        ResolvedDocumentOperationV1::AppendParagraph {
            text: "향후 계획".to_owned(),
            style_role: DocumentStyleRoleV1::Heading1,
        },
    ];
    let mut snapshots = vec![snapshot_docx(&source, 0)];
    for (index, operation) in operations.iter().enumerate() {
        let generation =
            u64::try_from(index + 1).unwrap_or_else(|error| panic!("generation: {error}"));
        let destination = next_generation(&root, "docx", generation);
        mutate_docx_document(&source, &destination, operation, &limits)
            .unwrap_or_else(|error| panic!("mutate DOCX {generation}: {error}"));
        snapshots.push(snapshot_docx(&destination, generation));
        source = destination;
    }
    let final_snapshot = snapshots
        .last()
        .unwrap_or_else(|| panic!("final DOCX snapshot missing"));
    assert!(final_snapshot.content_summary.contains("향후 계획"));
    assert!(final_snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.node_kind == DocumentNodeKindV1::Table));
    assert!(final_snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.node_kind == DocumentNodeKindV1::Image));
    assert_eq!(snapshots.len(), 7);
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn package_attacks_are_rejected_before_semantic_observation() {
    let root = test_root("package-negative");
    let traversal = root.join("traversal.docx");
    write_malicious_docx(&traversal, "../evil.xml", b"<evil/>", SAFE_DOCUMENT_XML);
    assert!(snapshot_docx_result(&traversal).is_err());

    let xxe = root.join("xxe.docx");
    write_malicious_docx(
        &xxe,
        "word/document.xml",
        b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///secret'>]><w:document xmlns:w='x'><w:body><w:p><w:r><w:t>&e;</w:t></w:r></w:p></w:body></w:document>",
        SAFE_DOCUMENT_XML,
    );
    assert!(snapshot_docx_result(&xxe).is_err());

    let external = root.join("external.docx");
    write_malicious_docx(
        &external,
        "word/_rels/document.xml.rels",
        br#"<Relationships><Relationship TargetMode="External" Target="https://example.test"/></Relationships>"#,
        SAFE_DOCUMENT_XML,
    );
    assert!(snapshot_docx_result(&external).is_err());

    let valid = root.join("valid.docx");
    create_docx_document(&valid, &default_document_resource_limits())
        .unwrap_or_else(|error| panic!("valid DOCX: {error}"));
    let mut tiny = default_document_resource_limits();
    tiny.maximum_document_bytes = 1_024;
    assert!(inspect_docx_document(
        &valid,
        "document.fixture",
        "artifact.fixture",
        0,
        "backend.docx-file",
        1_000,
        &tiny,
    )
    .is_err());
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn package_attack_matrix_rejects_duplicates_bombs_missing_parts_and_active_content() {
    let root = test_root("package-attack-matrix");

    let duplicate = root.join("duplicate.docx");
    write_duplicate_docx(&duplicate);
    assert!(snapshot_docx_result(&duplicate).is_err());

    let missing = root.join("missing-part.docx");
    write_minimal_zip(&missing, &[("word/document.xml", SAFE_DOCUMENT_XML)]);
    assert!(snapshot_docx_result(&missing).is_err());

    let malformed = root.join("malformed.docx");
    write_malicious_docx(
        &malformed,
        "word/document.xml",
        b"<w:document><w:body>",
        SAFE_DOCUMENT_XML,
    );
    assert!(snapshot_docx_result(&malformed).is_err());

    let relationship_escape = root.join("relationship-escape.docx");
    write_malicious_docx(
        &relationship_escape,
        "word/_rels/document.xml.rels",
        br#"<Relationships><Relationship Target="../../outside.xml"/></Relationships>"#,
        SAFE_DOCUMENT_XML,
    );
    assert!(snapshot_docx_result(&relationship_escape).is_err());

    for (name, active_part) in [
        ("macro", "word/vbaProject.bin"),
        ("ole", "word/embeddings/oleObject1.bin"),
        ("activex", "word/activeX/activeX1.bin"),
    ] {
        let path = root.join(format!("{name}.docx"));
        write_malicious_docx(&path, active_part, b"active", SAFE_DOCUMENT_XML);
        assert!(snapshot_docx_result(&path).is_err(), "{name}");
    }

    let valid = root.join("bounded.docx");
    create_docx_document(&valid, &default_document_resource_limits())
        .unwrap_or_else(|error| panic!("bounded DOCX: {error}"));
    let mut excessive_entries = default_document_resource_limits();
    excessive_entries.maximum_package_entries = 3;
    assert!(inspect_docx_document(
        &valid,
        "document.entries",
        "artifact.entries",
        0,
        "backend.docx-file",
        1_000,
        &excessive_entries,
    )
    .is_err());
    let mut unsafe_ratio = default_document_resource_limits();
    unsafe_ratio.maximum_compression_ratio = 1;
    assert!(inspect_docx_document(
        &valid,
        "document.ratio",
        "artifact.ratio",
        0,
        "backend.docx-file",
        1_000,
        &unsafe_ratio,
    )
    .is_err());

    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

fn snapshot_docx_result(
    path: &Path,
) -> Result<d2i_document_capability::DocumentSemanticSnapshotV1, String> {
    inspect_docx_document(
        path,
        "document.attack",
        "artifact.attack",
        0,
        "backend.docx-file",
        1_000,
        &default_document_resource_limits(),
    )
}

fn write_malicious_docx(path: &Path, malicious_name: &str, malicious: &[u8], document: &[u8]) {
    let file = File::create(path).unwrap_or_else(|error| panic!("malicious file: {error}"));
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default();
    for (name, bytes) in [
        ("[Content_Types].xml", b"<Types/>".as_slice()),
        ("_rels/.rels", b"<Relationships/>".as_slice()),
        ("word/document.xml", document),
        (
            "word/_rels/document.xml.rels",
            b"<Relationships/>".as_slice(),
        ),
    ] {
        let bytes = if name == malicious_name {
            malicious
        } else {
            bytes
        };
        writer
            .start_file(name, options)
            .unwrap_or_else(|error| panic!("malicious ZIP entry {name}: {error}"));
        writer
            .write_all(bytes)
            .unwrap_or_else(|error| panic!("malicious ZIP bytes {name}: {error}"));
    }
    if !matches!(
        malicious_name,
        "[Content_Types].xml"
            | "_rels/.rels"
            | "word/document.xml"
            | "word/_rels/document.xml.rels"
    ) {
        writer
            .start_file(malicious_name, options)
            .unwrap_or_else(|error| panic!("malicious extra entry: {error}"));
        writer
            .write_all(malicious)
            .unwrap_or_else(|error| panic!("malicious extra bytes: {error}"));
    }
    writer
        .finish()
        .unwrap_or_else(|error| panic!("malicious ZIP finish: {error}"));
}

fn write_duplicate_docx(path: &Path) {
    let entries = [
        ("[Content_Types].xml", b"<Types/>".as_slice()),
        ("_rels/.rels", b"<Relationships/>".as_slice()),
        ("word/document.xml", SAFE_DOCUMENT_XML),
        ("word/document.xml", SAFE_DOCUMENT_XML),
        (
            "word/_rels/document.xml.rels",
            b"<Relationships/>".as_slice(),
        ),
    ];
    write_raw_stored_zip(path, &entries);
}

fn write_raw_stored_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let mut output = Vec::new();
    let mut central = Vec::new();
    for (name, bytes) in entries {
        let name = name.as_bytes();
        let offset =
            u32::try_from(output.len()).unwrap_or_else(|error| panic!("ZIP offset: {error}"));
        let size = u32::try_from(bytes.len()).unwrap_or_else(|error| panic!("ZIP size: {error}"));
        let name_len =
            u16::try_from(name.len()).unwrap_or_else(|error| panic!("ZIP name: {error}"));
        let crc = test_crc32(bytes);
        push_u32(&mut output, 0x0403_4b50);
        push_u16(&mut output, 20);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u16(&mut output, 0);
        push_u32(&mut output, crc);
        push_u32(&mut output, size);
        push_u32(&mut output, size);
        push_u16(&mut output, name_len);
        push_u16(&mut output, 0);
        output.extend_from_slice(name);
        output.extend_from_slice(bytes);

        push_u32(&mut central, 0x0201_4b50);
        push_u16(&mut central, 20);
        push_u16(&mut central, 20);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, crc);
        push_u32(&mut central, size);
        push_u32(&mut central, size);
        push_u16(&mut central, name_len);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, offset);
        central.extend_from_slice(name);
    }
    let central_offset =
        u32::try_from(output.len()).unwrap_or_else(|error| panic!("central offset: {error}"));
    let central_size =
        u32::try_from(central.len()).unwrap_or_else(|error| panic!("central size: {error}"));
    output.extend_from_slice(&central);
    let count = u16::try_from(entries.len()).unwrap_or_else(|error| panic!("ZIP count: {error}"));
    push_u32(&mut output, 0x0605_4b50);
    push_u16(&mut output, 0);
    push_u16(&mut output, 0);
    push_u16(&mut output, count);
    push_u16(&mut output, count);
    push_u32(&mut output, central_size);
    push_u32(&mut output, central_offset);
    push_u16(&mut output, 0);
    std::fs::write(path, output).unwrap_or_else(|error| panic!("raw ZIP write: {error}"));
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn test_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn write_minimal_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap_or_else(|error| panic!("minimal file: {error}"));
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default();
    for (name, bytes) in entries {
        writer
            .start_file(*name, options)
            .unwrap_or_else(|error| panic!("minimal ZIP entry {name}: {error}"));
        writer
            .write_all(bytes)
            .unwrap_or_else(|error| panic!("minimal ZIP bytes {name}: {error}"));
    }
    writer
        .finish()
        .unwrap_or_else(|error| panic!("minimal ZIP finish: {error}"));
}

const SAFE_DOCUMENT_XML: &[u8] = br#"<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>safe</w:t></w:r></w:p></w:body></w:document>"#;
const PNG_1X1: &[u8] = &[
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
    0x89, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0xf0,
    0x1f, 0x00, 0x05, 0x00, 0x01, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45,
    0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
];

#[test]
fn bound_file_worker_executes_one_fresh_hwpx_generation() {
    let root = test_root("file-worker");
    let source = root.join("source.hwpx");
    let destination = root.join("destination.hwpx");
    let template = repository_root().join("fixtures/office/document/hwpx-report-template.hwpx");
    create_hwpx_from_template(&template, &source, &default_document_resource_limits())
        .unwrap_or_else(|error| panic!("worker source: {error}"));
    let worker = PathBuf::from(env!("CARGO_BIN_EXE_d2i-office200-document-worker"));
    let worker_sha256 = sha256_bytes(
        &std::fs::read(&worker).unwrap_or_else(|error| panic!("worker bytes: {error}")),
    );
    let source_sha256 = sha256_bytes(
        &std::fs::read(&source).unwrap_or_else(|error| panic!("source bytes: {error}")),
    );
    let request = DocumentFileWorkerRequestV1 {
        schema_version: 1,
        request_id: "request.file-worker-1".to_owned(),
        source_path: source.to_string_lossy().to_string(),
        destination_path: destination.to_string_lossy().to_string(),
        expected_source_sha256: source_sha256.clone(),
        format_id: d2i_document_capability::DocumentFormatV1::Hwpx,
        document_id: "document.file-worker".to_owned(),
        artifact_id: "artifact.file-worker".to_owned(),
        generation: 1,
        backend_id: "backend.hwpx-file".to_owned(),
        observed_at_unix_ms: 1_000,
        operation: ResolvedDocumentOperationV1::AppendParagraph {
            text: "worker verified paragraph".to_owned(),
            style_role: DocumentStyleRoleV1::Body,
        },
        limits: default_document_resource_limits(),
    };
    let response =
        spawn_document_file_worker(&worker, &worker_sha256, &request, Duration::from_secs(10))
            .unwrap_or_else(|error| panic!("file worker: {error}"));
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.source_content_sha256, source_sha256);
    assert!(destination.is_file());
    assert!(response
        .snapshot
        .ordered_nodes
        .iter()
        .any(|node| node.text_excerpt.as_deref() == Some("worker verified paragraph")));

    let mut tampered = request;
    tampered.request_id = "request.file-worker-2".to_owned();
    tampered.destination_path = root.join("rejected.hwpx").to_string_lossy().to_string();
    tampered.expected_source_sha256 = ZERO_HASH.to_owned();
    assert!(spawn_document_file_worker(
        &worker,
        &worker_sha256,
        &tampered,
        Duration::from_secs(10),
    )
    .is_err());
    assert!(!Path::new(&tampered.destination_path).exists());
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}
