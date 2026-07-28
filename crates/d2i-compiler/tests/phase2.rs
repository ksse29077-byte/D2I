use d2i_compiler::{build_ir, compile_package, diff_packages, verify_package, PackageError};
use d2i_core::NodeKind;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-phase2-{label}-{}-{sequence}",
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

fn example_pack() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/equipment-maintenance")
}

#[test]
fn lowering_connects_provenance_and_inserts_safety_nodes() {
    let report = build_ir(&example_pack());
    assert!(
        !report.has_errors(),
        "IR diagnostics: {:?}",
        report.diagnostics
    );
    let ir = match report.ir {
        Some(ir) => ir,
        None => panic!("IR was not produced"),
    };
    assert!(!ir.domain.entities.is_empty());
    assert!(!ir.domain.procedures.is_empty());
    assert!(!ir.domain.rules.is_empty());
    assert!(!ir.domain.examples.is_empty());
    assert!(!ir.domain.outcomes.is_empty());
    assert!(!ir.provenance.is_empty());
    assert!(ir.validate().is_empty());
    let kinds = ir
        .execution
        .graphs
        .iter()
        .flat_map(|graph| graph.nodes.iter().map(|node| node.kind))
        .collect::<Vec<_>>();
    assert!(kinds.contains(&NodeKind::PolicyGate));
    assert!(kinds.contains(&NodeKind::HumanReview));
}

#[test]
fn deterministic_package_round_trip_and_diff() {
    let temporary = TempDirectory::new("roundtrip");
    let first = temporary.path().join("first.d2ip");
    let second = temporary.path().join("second.d2ip");
    let first_report = compile_package(&example_pack(), &first);
    assert!(
        !first_report.has_errors(),
        "first compile failed: {:?} {:?}",
        first_report.diagnostics,
        first_report.package_error
    );
    let second_report = compile_package(&example_pack(), &second);
    assert!(
        !second_report.has_errors(),
        "second compile failed: {:?} {:?}",
        second_report.diagnostics,
        second_report.package_error
    );
    let first_build = match first_report.build {
        Some(build) => build,
        None => panic!("first build report missing"),
    };
    let second_build = match second_report.build {
        Some(build) => build,
        None => panic!("second build report missing"),
    };
    assert_eq!(first_build.build_id, second_build.build_id);
    assert_eq!(
        first_build.package_content_hash,
        second_build.package_content_hash
    );
    assert_eq!(
        read_tree(&first),
        read_tree(&second),
        "deterministic packages differ byte-for-byte"
    );

    let summary = match verify_package(&first) {
        Ok(summary) => summary,
        Err(error) => panic!("round-trip verification failed: {error}"),
    };
    assert_eq!(summary.build_id, first_build.build_id);
    assert!(summary.entity_count > 0);
    assert!(summary.graph_count > 0);
    let diff = match diff_packages(&first, &second) {
        Ok(diff) => diff,
        Err(error) => panic!("identical package diff failed: {error}"),
    };
    assert!(diff.identical);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
    assert!(diff.changed.is_empty());
}

#[test]
fn equipment_maintenance_matches_golden_build_identity() {
    let temporary = TempDirectory::new("golden");
    let output = temporary.path().join("package.d2ip");
    let report = compile_package(&example_pack(), &output);
    assert!(
        !report.has_errors(),
        "golden compile failed: {:?} {:?}",
        report.diagnostics,
        report.package_error
    );
    let build = match report.build {
        Some(build) => build,
        None => panic!("golden build report missing"),
    };
    let actual = serde_json::json!({
        "artifact_count": build.artifact_count,
        "build_id": build.build_id,
        "domain_id": build.domain_id,
        "package_content_hash": build.package_content_hash,
        "payload_hash": build.payload_hash,
        "source_inventory_hash": build.source_inventory_hash,
    });
    let expected: serde_json::Value =
        match serde_json::from_str(include_str!("golden/equipment-maintenance.json")) {
            Ok(expected) => expected,
            Err(error) => panic!("golden snapshot is invalid JSON: {error}"),
        };
    assert_eq!(actual, expected);
}

#[test]
fn corruption_and_version_mismatch_are_detected() {
    let temporary = TempDirectory::new("corruption");
    let corrupted = temporary.path().join("corrupted.d2ip");
    let report = compile_package(&example_pack(), &corrupted);
    assert!(!report.has_errors());
    let domain_path = corrupted.join("ir/domain.fb");
    let mut bytes = match fs::read(&domain_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read domain artifact: {error}"),
    };
    if let Some(byte) = bytes.last_mut() {
        *byte ^= 0x5a;
    } else {
        panic!("domain artifact is empty");
    }
    if let Err(error) = fs::write(&domain_path, bytes) {
        panic!("cannot corrupt domain artifact: {error}");
    }
    assert!(matches!(
        verify_package(&corrupted),
        Err(PackageError::HashMismatch { .. })
    ));

    let versioned = temporary.path().join("versioned.d2ip");
    let report = compile_package(&example_pack(), &versioned);
    assert!(!report.has_errors());
    let manifest_path = versioned.join("manifest.fb");
    let mut manifest = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) => panic!("cannot read manifest: {error}"),
    };
    let version_offset = manifest.windows(5).position(|window| window == b"1.0.0");
    let Some(version_offset) = version_offset else {
        panic!("manifest did not contain a version string");
    };
    manifest[version_offset..version_offset + 5].copy_from_slice(b"9.0.0");
    if let Err(error) = fs::write(&manifest_path, &manifest) {
        panic!("cannot write version-mismatched manifest: {error}");
    }
    replace_manifest_hash(&versioned, &manifest);
    assert!(matches!(
        verify_package(&versioned),
        Err(PackageError::VersionMismatch { .. })
    ));
}

#[test]
fn package_hash_paths_reject_traversal() {
    let temporary = TempDirectory::new("traversal");
    let output = temporary.path().join("package.d2ip");
    let report = compile_package(&example_pack(), &output);
    assert!(!report.has_errors());
    let hashes = output.join("hashes.sha256");
    let mut text = match fs::read_to_string(&hashes) {
        Ok(text) => text,
        Err(error) => panic!("cannot read hashes: {error}"),
    };
    text.push_str(&format!("{}  ../outside\n", "0".repeat(64)));
    if let Err(error) = fs::write(hashes, text) {
        panic!("cannot write traversal hash: {error}");
    }
    assert!(matches!(
        verify_package(&output),
        Err(PackageError::UnsafePath(_))
    ));
}

fn replace_manifest_hash(root: &Path, manifest: &[u8]) {
    let hashes_path = root.join("hashes.sha256");
    let text = match fs::read_to_string(&hashes_path) {
        Ok(text) => text,
        Err(error) => panic!("cannot read hashes for version test: {error}"),
    };
    let replacement = format!("{:x}", Sha256::digest(manifest));
    let updated = text
        .lines()
        .map(|line| {
            if line.ends_with("  manifest.fb") {
                format!("{replacement}  manifest.fb")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    if let Err(error) = fs::write(hashes_path, updated) {
        panic!("cannot update manifest hash: {error}");
    }
}

fn read_tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => panic!("cannot read package directory: {error}"),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => panic!("cannot read package entry: {error}"),
            };
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .map_or_else(
                        |_| path.display().to_string(),
                        |path| path.display().to_string(),
                    )
                    .replace('\\', "/");
                let bytes = match fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(error) => panic!("cannot read package artifact: {error}"),
                };
                files.push((relative, bytes));
            }
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}
