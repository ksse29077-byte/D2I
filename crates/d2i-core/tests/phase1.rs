use d2i_core::{
    build_inventory, validate_source_pack, write_source_lock, SourceFormat, MAX_SOURCE_FILE_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase1-{label}-{}-{sequence}",
            std::process::id()
        ));
        if let Err(error) = fs::create_dir_all(&path) {
            panic!("cannot create test directory {}: {error}", path.display());
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/phase1")
        .join(name)
}

fn has_code(report: &d2i_core::ValidationReport, code: &str) -> bool {
    report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code() == code)
}

#[test]
fn good_fixture_parses_every_phase1_format() {
    let report = validate_source_pack(&fixture("good"));
    assert!(
        !report.has_errors(),
        "good fixture diagnostics: {:?}",
        report.diagnostics
    );
    let formats = report
        .documents
        .iter()
        .map(|document| document.format())
        .collect::<Vec<_>>();
    for expected in [
        SourceFormat::Markdown,
        SourceFormat::Text,
        SourceFormat::Csv,
        SourceFormat::Json,
        SourceFormat::JsonLines,
        SourceFormat::Yaml,
    ] {
        assert!(formats.contains(&expected), "missing format {expected:?}");
    }
}

#[test]
fn unknown_manifest_fields_are_rejected() {
    let report = validate_source_pack(&fixture("bad-unknown-field"));
    assert!(report.has_errors());
    assert!(has_code(&report, "D2I1002"));
}

#[test]
fn traversal_and_broken_references_are_aggregated() {
    let report = validate_source_pack(&fixture("malicious-traversal"));
    assert!(report.has_errors());
    let reference_errors = report
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code() == "D2I1303")
        .count();
    assert!(reference_errors >= 5);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message()
            .contains("path traversal is not allowed")
    }));
}

#[test]
fn duplicate_ids_and_structural_targets_are_rejected_together() {
    let report = validate_source_pack(&fixture("bad-references"));
    for code in [
        "D2I1301", "D2I1307", "D2I1308", "D2I1309", "D2I1311", "D2I1312",
    ] {
        assert!(
            has_code(&report, code),
            "missing expected diagnostic {code}"
        );
    }
}

#[test]
fn inventory_hash_and_lock_ignore_timestamp_only_rewrites() {
    let temporary = TempDirectory::new("reproducible");
    copy_tree(&fixture("good"), temporary.path());
    let (first, first_diagnostics) = build_inventory(temporary.path());
    assert!(first_diagnostics.is_empty());
    let first = match first {
        Some(inventory) => inventory,
        None => panic!("first inventory was not created"),
    };
    let first_hash = first.inventory_hash().to_string();
    let first_lock_path = match write_source_lock(&first) {
        Ok(path) => path,
        Err(error) => panic!("cannot write first lock: {error}"),
    };
    let first_lock = match fs::read(&first_lock_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read first lock: {error}"),
    };

    let text_path = temporary.path().join("data/plain.txt");
    let unchanged = match fs::read(&text_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read timestamp test source: {error}"),
    };
    if let Err(error) = fs::write(&text_path, unchanged) {
        panic!("cannot rewrite timestamp test source: {error}");
    }

    let (second, second_diagnostics) = build_inventory(temporary.path());
    assert!(second_diagnostics.is_empty());
    let second = match second {
        Some(inventory) => inventory,
        None => panic!("second inventory was not created"),
    };
    assert_eq!(first_hash, second.inventory_hash().to_string());
    let second_lock_path = match write_source_lock(&second) {
        Ok(path) => path,
        Err(error) => panic!("cannot write second lock: {error}"),
    };
    let second_lock = match fs::read(second_lock_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read second lock: {error}"),
    };
    assert_eq!(first_lock, second_lock);
}

#[test]
fn oversized_files_are_rejected_without_reading_them() {
    let temporary = TempDirectory::new("oversized");
    let path = temporary.path().join("large.txt");
    let file = match fs::File::create(&path) {
        Ok(file) => file,
        Err(error) => panic!("cannot create sparse test file: {error}"),
    };
    if let Err(error) = file.set_len(MAX_SOURCE_FILE_BYTES + 1) {
        panic!("cannot resize sparse test file: {error}");
    }
    let (_, diagnostics) = build_inventory(temporary.path());
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code() == "D2I1107"));
}

#[test]
fn symlink_escape_is_rejected_when_platform_allows_symlink_creation() {
    let temporary = TempDirectory::new("symlink");
    let outside = temporary.path().with_extension("outside.txt");
    if let Err(error) = fs::write(&outside, b"outside") {
        panic!("cannot write symlink target: {error}");
    }
    let link = temporary.path().join("escape.txt");

    #[cfg(unix)]
    let created = std::os::unix::fs::symlink(&outside, &link);
    #[cfg(windows)]
    let created = std::os::windows::fs::symlink_file(&outside, &link);

    if created.is_err() {
        let _ = fs::remove_file(&outside);
        return;
    }
    let (_, diagnostics) = build_inventory(temporary.path());
    let _ = fs::remove_file(&outside);
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code() == "D2I1105"));
}

fn copy_tree(source: &Path, destination: &Path) {
    let entries = match fs::read_dir(source) {
        Ok(entries) => entries,
        Err(error) => panic!(
            "cannot read fixture directory {}: {error}",
            source.display()
        ),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("cannot read fixture entry: {error}"),
        };
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) => panic!("cannot inspect fixture entry: {error}"),
        };
        if metadata.is_dir() {
            if let Err(error) = fs::create_dir_all(&destination_path) {
                panic!("cannot create fixture directory: {error}");
            }
            copy_tree(&source_path, &destination_path);
        } else if let Err(error) = fs::copy(&source_path, &destination_path) {
            panic!("cannot copy fixture file: {error}");
        }
    }
}
