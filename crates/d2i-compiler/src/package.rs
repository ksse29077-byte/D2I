use crate::{build_ir, Phase4BuildData};
use d2i_core::{
    CompiledIr, Criticality, Diagnostic, DomainManifest, EdgeKind, EvidenceRef, NodeKind,
    SemanticVersion, Severity, SourceLock,
};
use d2i_schema::d2i::package as fb;
use planus::ReadAsRoot;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

pub const PACKAGE_FORMAT_VERSION: &str = "1.0.0";
pub const RUNTIME_ABI_VERSION: &str = "1.0.0";
pub const COMPILER_VERSION: &str = env!("CARGO_PKG_VERSION");
const SCHEMA_VERSION: u32 = 1;
const MAX_PACKAGE_FILE_BYTES: u64 = 64 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Machine-readable build summary returned by `compile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildReport {
    pub build_id: String,
    pub domain_id: String,
    pub domain_version: String,
    pub compiler_version: String,
    pub package_format_version: String,
    pub runtime_abi_version: String,
    pub source_inventory_hash: String,
    pub payload_hash: String,
    pub package_content_hash: String,
    pub artifact_count: usize,
    pub package_path: String,
    pub selected_executors: BTreeMap<String, String>,
}

/// Compilation result that preserves source diagnostics separately from package errors.
#[derive(Debug)]
pub struct CompileReport {
    pub build: Option<BuildReport>,
    pub diagnostics: Vec<Diagnostic>,
    pub package_error: Option<PackageError>,
}

impl CompileReport {
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.package_error.is_some()
            || self
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.severity() == Severity::Error)
    }
}

/// Verified package metadata and section counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageSummary {
    pub package_path: String,
    pub domain_id: String,
    pub domain_version: String,
    pub build_id: String,
    pub compiler_version: String,
    pub package_format_version: String,
    pub runtime_abi_version: String,
    pub source_inventory_hash: String,
    pub payload_hash: String,
    pub package_content_hash: String,
    pub artifact_count: usize,
    pub entity_count: usize,
    pub skill_count: usize,
    pub graph_count: usize,
    pub policy_count: usize,
    pub evaluation_case_count: usize,
}

/// Fully verified package sections and their immutable artifact bytes.
///
/// Consumers must obtain package data through this type so verification and
/// decoding happen before runtime state is constructed.
#[derive(Debug)]
pub struct VerifiedPackage {
    pub summary: PackageSummary,
    pub manifest: fb::PackageManifest,
    pub domain: fb::DomainBundle,
    pub skills: fb::SkillBundle,
    pub execution: fb::ExecutionBundle,
    pub policies: fb::PolicyBundle,
    pub evaluation: fb::EvaluationBundle,
    artifacts: BTreeMap<String, Vec<u8>>,
}

impl VerifiedPackage {
    /// Returns one hash-verified artifact without reopening the package path.
    #[must_use]
    pub fn artifact(&self, path: &str) -> Option<&[u8]> {
        self.artifacts.get(path).map(Vec::as_slice)
    }

    /// Returns the sorted paths retained by the verified package image.
    pub fn artifact_paths(&self) -> impl Iterator<Item = &str> {
        self.artifacts.keys().map(String::as_str)
    }
}

/// Deterministic artifact-level package comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageDiff {
    pub identical: bool,
    pub old_content_hash: String,
    pub new_content_hash: String,
    pub old_build_id: String,
    pub new_build_id: String,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Package creation or verification failure.
#[derive(Debug)]
pub enum PackageError {
    Io {
        path: String,
        message: String,
    },
    UnsafePath(String),
    MissingArtifact(String),
    UnexpectedArtifact(String),
    CorruptFlatbuffer {
        path: String,
        message: String,
    },
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    VersionMismatch {
        name: &'static str,
        expected: String,
        actual: String,
    },
    InvalidFormat(String),
}

impl Display for PackageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, message } => write!(f, "I/O error at {path}: {message}"),
            Self::UnsafePath(path) => write!(f, "unsafe package path '{path}'"),
            Self::MissingArtifact(path) => write!(f, "missing package artifact '{path}'"),
            Self::UnexpectedArtifact(path) => write!(f, "unexpected package artifact '{path}'"),
            Self::CorruptFlatbuffer { path, message } => {
                write!(f, "corrupt FlatBuffer '{path}': {message}")
            }
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "hash mismatch for '{path}': expected {expected}, got {actual}"
            ),
            Self::VersionMismatch {
                name,
                expected,
                actual,
            } => write!(f, "unsupported {name}: expected {expected}, got {actual}"),
            Self::InvalidFormat(message) => f.write_str(message),
        }
    }
}

impl Error for PackageError {}

/// Compiles a validated source pack into a deterministic package directory.
#[must_use]
pub fn compile_package(source: &Path, output: &Path) -> CompileReport {
    let ir_report = build_ir(source);
    if ir_report.has_errors() {
        return CompileReport {
            build: None,
            diagnostics: ir_report.diagnostics,
            package_error: None,
        };
    }
    let (Some(ir), Some(manifest), Some(source_lock), Some(phase4)) = (
        ir_report.ir,
        ir_report.manifest,
        ir_report.source_lock,
        ir_report.phase4,
    ) else {
        return CompileReport {
            build: None,
            diagnostics: ir_report.diagnostics,
            package_error: Some(PackageError::InvalidFormat(
                "validated IR report is incomplete".to_owned(),
            )),
        };
    };

    let result = write_package(source, output, &manifest, &source_lock, &ir, &phase4);
    match result {
        Ok(build) => CompileReport {
            build: Some(build),
            diagnostics: ir_report.diagnostics,
            package_error: None,
        },
        Err(error) => CompileReport {
            build: None,
            diagnostics: ir_report.diagnostics,
            package_error: Some(error),
        },
    }
}

/// Verifies hashes, paths, versions, and every FlatBuffer section.
pub fn verify_package(root: &Path) -> Result<PackageSummary, PackageError> {
    read_package(root)
}

/// Reads a package only after complete verification.
pub fn read_package(root: &Path) -> Result<PackageSummary, PackageError> {
    load_verified_package(root).map(|package| package.summary)
}

/// Verifies and decodes a package into an immutable runtime package image.
pub fn load_verified_package(root: &Path) -> Result<VerifiedPackage, PackageError> {
    let canonical_root = fs::canonicalize(root).map_err(|error| io_error(root, error))?;
    if !canonical_root.is_dir() {
        return Err(PackageError::InvalidFormat(
            "package root must be a directory".to_owned(),
        ));
    }
    let hashes_path = canonical_root.join("hashes.sha256");
    let hashes_bytes = read_bounded(&hashes_path)?;
    let hashes_text = std::str::from_utf8(&hashes_bytes).map_err(|error| {
        PackageError::InvalidFormat(format!("hashes.sha256 is not UTF-8: {error}"))
    })?;
    let declared_hashes = parse_hashes(hashes_text)?;
    let actual_paths = inventory_package_paths(&canonical_root)?;
    let expected_paths = declared_hashes
        .keys()
        .cloned()
        .chain(std::iter::once("hashes.sha256".to_owned()))
        .collect::<BTreeSet<_>>();
    if let Some(path) = expected_paths.difference(&actual_paths).next() {
        return Err(PackageError::MissingArtifact(path.clone()));
    }
    if let Some(path) = actual_paths.difference(&expected_paths).next() {
        return Err(PackageError::UnexpectedArtifact(path.clone()));
    }

    let mut verified_bytes = BTreeMap::new();
    for (path, expected) in &declared_hashes {
        let bytes = read_package_artifact(&canonical_root, path)?;
        let actual = sha256_hex(&bytes);
        if &actual != expected {
            return Err(PackageError::HashMismatch {
                path: path.clone(),
                expected: expected.clone(),
                actual,
            });
        }
        verified_bytes.insert(path.clone(), bytes);
    }

    let manifest_bytes = required_bytes(&verified_bytes, "manifest.fb")?;
    let manifest: fb::PackageManifest = decode_flatbuffer(
        manifest_bytes,
        *b"D2PM",
        "manifest.fb",
        fb::PackageManifestRef::read_as_root,
    )?;
    check_version(
        "package format version",
        PACKAGE_FORMAT_VERSION,
        &manifest.package_format_version,
    )?;
    check_version(
        "runtime ABI version",
        RUNTIME_ABI_VERSION,
        &manifest.runtime_abi_version,
    )?;
    SemanticVersion::from_str(&manifest.compiler_version).map_err(|error| {
        PackageError::VersionMismatch {
            name: "compiler version syntax",
            expected: "major.minor.patch".to_owned(),
            actual: format!("{} ({error})", manifest.compiler_version),
        }
    })?;
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(PackageError::VersionMismatch {
            name: "manifest schema version",
            expected: SCHEMA_VERSION.to_string(),
            actual: manifest.schema_version.to_string(),
        });
    }

    let domain: fb::DomainBundle = decode_flatbuffer(
        required_bytes(&verified_bytes, "ir/domain.fb")?,
        *b"D2DM",
        "ir/domain.fb",
        fb::DomainBundleRef::read_as_root,
    )?;
    let skills: fb::SkillBundle = decode_flatbuffer(
        required_bytes(&verified_bytes, "ir/skills.fb")?,
        *b"D2SK",
        "ir/skills.fb",
        fb::SkillBundleRef::read_as_root,
    )?;
    let execution: fb::ExecutionBundle = decode_flatbuffer(
        required_bytes(&verified_bytes, "ir/execution.fb")?,
        *b"D2EX",
        "ir/execution.fb",
        fb::ExecutionBundleRef::read_as_root,
    )?;
    let policies: fb::PolicyBundle = decode_flatbuffer(
        required_bytes(&verified_bytes, "ir/policies.fb")?,
        *b"D2PL",
        "ir/policies.fb",
        fb::PolicyBundleRef::read_as_root,
    )?;
    let evaluation: fb::EvaluationBundle = decode_flatbuffer(
        required_bytes(&verified_bytes, "ir/evaluation.fb")?,
        *b"D2EV",
        "ir/evaluation.fb",
        fb::EvaluationBundleRef::read_as_root,
    )?;
    for (name, version) in [
        ("domain schema version", domain.schema_version),
        ("skills schema version", skills.schema_version),
        ("execution schema version", execution.schema_version),
        ("policy schema version", policies.schema_version),
        ("evaluation schema version", evaluation.schema_version),
    ] {
        if version != SCHEMA_VERSION {
            return Err(PackageError::VersionMismatch {
                name,
                expected: SCHEMA_VERSION.to_string(),
                actual: version.to_string(),
            });
        }
    }

    let payload_files = manifest
        .files
        .iter()
        .map(|file| (file.path.clone(), file.content_hash.clone()))
        .collect::<BTreeMap<_, _>>();
    let expected_payload = declared_hashes
        .iter()
        .filter(|(path, _)| path.as_str() != "manifest.fb")
        .map(|(path, hash)| (path.clone(), format!("sha256:{hash}")))
        .collect::<BTreeMap<_, _>>();
    if payload_files != expected_payload {
        return Err(PackageError::InvalidFormat(
            "manifest file table does not match hashes.sha256".to_owned(),
        ));
    }
    for file in &manifest.files {
        let actual_size = verified_bytes
            .get(&file.path)
            .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if actual_size != file.size {
            return Err(PackageError::InvalidFormat(format!(
                "manifest size mismatch for '{}': expected {}, got {actual_size}",
                file.path, file.size
            )));
        }
    }
    let payload_hash = hash_entries(&expected_payload);
    if payload_hash != manifest.payload_hash {
        return Err(PackageError::HashMismatch {
            path: "<payload>".to_owned(),
            expected: manifest.payload_hash,
            actual: payload_hash,
        });
    }
    let package_content_hash = format!("sha256:{}", sha256_hex(&hashes_bytes));
    let policy_count = policies.access_labels.len()
        + policies.confidence_thresholds.len()
        + policies.action_permissions.len();

    let summary = PackageSummary {
        package_path: root.display().to_string(),
        domain_id: manifest.domain_id.clone(),
        domain_version: manifest.domain_version.clone(),
        build_id: manifest.build_id.clone(),
        compiler_version: manifest.compiler_version.clone(),
        package_format_version: manifest.package_format_version.clone(),
        runtime_abi_version: manifest.runtime_abi_version.clone(),
        source_inventory_hash: manifest.source_inventory_hash.clone(),
        payload_hash: manifest.payload_hash.clone(),
        package_content_hash,
        artifact_count: declared_hashes.len() + 1,
        entity_count: domain.entities.len(),
        skill_count: skills.skills.len(),
        graph_count: execution.graphs.len(),
        policy_count,
        evaluation_case_count: evaluation.cases.len(),
    };
    Ok(VerifiedPackage {
        summary,
        manifest,
        domain,
        skills,
        execution,
        policies,
        evaluation,
        artifacts: verified_bytes,
    })
}

/// Verifies and compares two packages at the artifact hash level.
pub fn diff_packages(old: &Path, new: &Path) -> Result<PackageDiff, PackageError> {
    let old_summary = read_package(old)?;
    let new_summary = read_package(new)?;
    let old_hashes = read_hash_map(old)?;
    let new_hashes = read_hash_map(new)?;
    let old_paths = old_hashes.keys().cloned().collect::<BTreeSet<_>>();
    let new_paths = new_hashes.keys().cloned().collect::<BTreeSet<_>>();
    let added = new_paths.difference(&old_paths).cloned().collect();
    let removed = old_paths.difference(&new_paths).cloned().collect();
    let changed = old_paths
        .intersection(&new_paths)
        .filter(|path| old_hashes.get(*path) != new_hashes.get(*path))
        .cloned()
        .collect::<Vec<_>>();
    Ok(PackageDiff {
        identical: old_summary.package_content_hash == new_summary.package_content_hash,
        old_content_hash: old_summary.package_content_hash,
        new_content_hash: new_summary.package_content_hash,
        old_build_id: old_summary.build_id,
        new_build_id: new_summary.build_id,
        added,
        removed,
        changed,
    })
}

fn write_package(
    source: &Path,
    output: &Path,
    manifest: &DomainManifest,
    source_lock: &SourceLock,
    ir: &CompiledIr,
    phase4: &Phase4BuildData,
) -> Result<BuildReport, PackageError> {
    validate_output_boundary(source, output)?;
    if output.exists() {
        return Err(PackageError::Io {
            path: output.display().to_string(),
            message: "output path already exists".to_owned(),
        });
    }

    let source_inventory_hash = source_lock.inventory_hash.clone();
    let build_id = deterministic_build_id(
        &manifest.domain.id,
        &manifest.domain.version,
        &source_inventory_hash,
    );
    let mut artifacts = BTreeMap::<String, Vec<u8>>::new();
    artifacts.insert("ir/domain.fb".to_owned(), encode_domain(ir));
    artifacts.insert("ir/skills.fb".to_owned(), encode_skills(ir));
    artifacts.insert("ir/execution.fb".to_owned(), encode_execution(ir));
    artifacts.insert("ir/policies.fb".to_owned(), encode_policies(ir));
    artifacts.insert("ir/evaluation.fb".to_owned(), encode_evaluation(ir));
    artifacts.insert(
        "provenance/sources.lock".to_owned(),
        json_bytes(source_lock)?,
    );
    artifacts.insert(
        "executors/descriptors.json".to_owned(),
        json_bytes(&phase4.descriptors)?,
    );
    artifacts.insert(
        "eval/benchmark-profiles.json".to_owned(),
        json_bytes(&phase4.benchmark_profiles)?,
    );
    artifacts.insert(
        "reports/selection.json".to_owned(),
        json_bytes(&phase4.selections)?,
    );
    artifacts.insert(
        "reports/optimization.json".to_owned(),
        json_bytes(&phase4.optimizations)?,
    );
    let selected_executors = phase4
        .selections
        .iter()
        .filter_map(|(binding_key, report)| {
            report
                .selected
                .as_ref()
                .map(|selected| (binding_key.clone(), selected.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    let provenance_report = BuildProvenance {
        build_id: &build_id,
        compiler_version: COMPILER_VERSION,
        package_format_version: PACKAGE_FORMAT_VERSION,
        runtime_abi_version: RUNTIME_ABI_VERSION,
        source_inventory_hash: &source_inventory_hash,
        domain_id: &manifest.domain.id,
        domain_version: &manifest.domain.version,
        entity_count: ir.domain.entities.len(),
        skill_count: ir.skills.len(),
        graph_count: ir.execution.graphs.len(),
        evaluation_case_count: ir.evaluation.cases.len(),
        selected_executors: &selected_executors,
        pareto_candidate_count: phase4
            .selections
            .values()
            .map(|report| report.pareto_front.len())
            .sum(),
    };
    artifacts.insert(
        "provenance/build.json".to_owned(),
        json_bytes(&provenance_report)?,
    );
    let evaluation_report = EvaluationReport {
        status: "not_executed",
        case_count: ir.evaluation.cases.len(),
        metric_count: ir.evaluation.metrics.len(),
        critical_error_condition_count: ir.evaluation.critical_errors.len(),
    };
    artifacts.insert(
        "eval/report.json".to_owned(),
        json_bytes(&evaluation_report)?,
    );

    copy_referenced_sources(source, manifest, source_lock, &mut artifacts)?;

    let payload_hashes = artifacts
        .iter()
        .map(|(path, bytes)| (path.clone(), format!("sha256:{}", sha256_hex(bytes))))
        .collect::<BTreeMap<_, _>>();
    let payload_hash = hash_entries(&payload_hashes);
    let manifest_fb = fb::PackageManifest {
        schema_version: SCHEMA_VERSION,
        package_format_version: PACKAGE_FORMAT_VERSION.to_owned(),
        compiler_version: COMPILER_VERSION.to_owned(),
        runtime_abi_version: RUNTIME_ABI_VERSION.to_owned(),
        domain_id: manifest.domain.id.clone(),
        domain_version: manifest.domain.version.clone(),
        build_id: build_id.clone(),
        source_inventory_hash: source_inventory_hash.clone(),
        payload_hash: payload_hash.clone(),
        target_os: manifest.target.os.clone(),
        target_arch: manifest.target.arch.clone(),
        network_policy: manifest.target.network_policy.clone(),
        files: payload_hashes
            .iter()
            .map(|(path, hash)| fb::PackageFile {
                path: path.clone(),
                size: artifacts
                    .get(path)
                    .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
                content_hash: hash.clone(),
            })
            .collect(),
    };
    artifacts.insert(
        "manifest.fb".to_owned(),
        encode_flatbuffer(&manifest_fb, *b"D2PM"),
    );

    let all_hashes = artifacts
        .iter()
        .map(|(path, bytes)| (path.clone(), sha256_hex(bytes)))
        .collect::<BTreeMap<_, _>>();
    let hashes_bytes = render_hashes(&all_hashes);
    let package_content_hash = format!("sha256:{}", sha256_hex(&hashes_bytes));

    let staging = staging_path(output)?;
    fs::create_dir(&staging).map_err(|error| io_error(&staging, error))?;
    for (path, bytes) in &artifacts {
        if let Err(error) = write_artifact(&staging, path, bytes) {
            cleanup_staging(&staging);
            return Err(error);
        }
    }
    if let Err(error) = write_artifact(&staging, "hashes.sha256", &hashes_bytes) {
        cleanup_staging(&staging);
        return Err(error);
    }

    let summary = match read_package(&staging) {
        Ok(summary) => summary,
        Err(error) => {
            cleanup_staging(&staging);
            return Err(error);
        }
    };
    if summary.package_content_hash != package_content_hash {
        cleanup_staging(&staging);
        return Err(PackageError::HashMismatch {
            path: "<package>".to_owned(),
            expected: package_content_hash,
            actual: summary.package_content_hash,
        });
    }
    fs::rename(&staging, output).map_err(|error| {
        cleanup_staging(&staging);
        io_error(output, error)
    })?;
    Ok(BuildReport {
        build_id,
        domain_id: manifest.domain.id.clone(),
        domain_version: manifest.domain.version.clone(),
        compiler_version: COMPILER_VERSION.to_owned(),
        package_format_version: PACKAGE_FORMAT_VERSION.to_owned(),
        runtime_abi_version: RUNTIME_ABI_VERSION.to_owned(),
        source_inventory_hash,
        payload_hash,
        package_content_hash: summary.package_content_hash,
        artifact_count: summary.artifact_count,
        package_path: output.display().to_string(),
        selected_executors,
    })
}

fn staging_path(output: &Path) -> Result<PathBuf, PackageError> {
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| PackageError::UnsafePath(output.display().to_string()))?;
    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging = parent.join(format!(
        ".{name}.d2i-stage-{}-{sequence}",
        std::process::id()
    ));
    if staging.exists() {
        return Err(PackageError::Io {
            path: staging.display().to_string(),
            message: "staging path already exists".to_owned(),
        });
    }
    Ok(staging)
}

fn cleanup_staging(staging: &Path) {
    if staging.is_dir() {
        let _ = fs::remove_dir_all(staging);
    }
}

#[derive(Serialize)]
struct BuildProvenance<'a> {
    build_id: &'a str,
    compiler_version: &'a str,
    package_format_version: &'a str,
    runtime_abi_version: &'a str,
    source_inventory_hash: &'a str,
    domain_id: &'a str,
    domain_version: &'a str,
    entity_count: usize,
    skill_count: usize,
    graph_count: usize,
    evaluation_case_count: usize,
    selected_executors: &'a BTreeMap<String, String>,
    pareto_candidate_count: usize,
}

#[derive(Serialize)]
struct EvaluationReport {
    status: &'static str,
    case_count: usize,
    metric_count: usize,
    critical_error_condition_count: usize,
}

fn encode_domain(ir: &CompiledIr) -> Vec<u8> {
    let provenance = ir
        .provenance
        .iter()
        .map(to_fb_provenance)
        .collect::<Vec<_>>();
    let mut entities = Vec::new();
    for entity in &ir.domain.entities {
        entities.push(record(
            &entity.id,
            "entity",
            &entity.entity_type,
            "",
            "",
            entity.provenance_id.as_str(),
        ));
        for (key, value) in &entity.attributes {
            entities.push(record(
                &format!("{}-{key}", entity.id),
                "attribute",
                &entity.id,
                key,
                value,
                entity.provenance_id.as_str(),
            ));
        }
    }
    let relations = ir
        .domain
        .relations
        .iter()
        .map(|item| {
            record(
                &item.id,
                &item.relation_type,
                &item.source,
                "target",
                &item.target,
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let mut terms = Vec::new();
    for term in &ir.domain.terms {
        terms.push(record(
            &term.id,
            "term",
            &term.canonical,
            "",
            "",
            term.provenance_id.as_str(),
        ));
        for (index, alias) in term.aliases.iter().enumerate() {
            terms.push(record(
                &format!("{}-alias-{index:04}", term.id),
                "alias",
                &term.id,
                "alias",
                alias,
                term.provenance_id.as_str(),
            ));
        }
    }
    let facts = ir
        .domain
        .facts
        .iter()
        .map(|item| {
            record(
                &item.id,
                "fact",
                &item.subject,
                &item.predicate,
                &item.object,
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let documents = ir
        .domain
        .documents
        .iter()
        .map(|item| {
            record(
                &item.id,
                "document",
                &item.path,
                "title",
                item.title.as_deref().unwrap_or(""),
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let mut procedures = Vec::new();
    for procedure in &ir.domain.procedures {
        procedures.push(record(
            &procedure.id,
            "procedure",
            &procedure.version,
            "",
            "",
            procedure.provenance_id.as_str(),
        ));
        for step in &procedure.steps {
            procedures.push(record(
                &step.id,
                "procedure_step",
                &procedure.id,
                &step.kind,
                step.next.as_deref().unwrap_or(""),
                step.provenance_id.as_str(),
            ));
        }
    }
    let rules = ir
        .domain
        .rules
        .iter()
        .map(|item| {
            record(
                &item.id,
                if item.exception {
                    "exception_rule"
                } else {
                    "rule"
                },
                &canonical_json(&item.condition),
                "then",
                &canonical_json(&item.action),
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let examples = ir
        .domain
        .examples
        .iter()
        .map(|item| {
            record(
                &item.id,
                if item.positive {
                    "positive_example"
                } else {
                    "negative_example"
                },
                item.skill_id.as_str(),
                "request",
                &canonical_json(&item.request),
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let outcomes = ir
        .domain
        .outcomes
        .iter()
        .map(|item| {
            record(
                &item.id,
                "outcome",
                "",
                "expected",
                &canonical_json(&item.expected),
                item.provenance_id.as_str(),
            )
        })
        .collect();
    let bundle = fb::DomainBundle {
        schema_version: SCHEMA_VERSION,
        domain_id: ir.domain.domain_id.to_string(),
        domain_version: ir.domain.version.clone(),
        name: ir.domain.name.clone(),
        languages: ir.domain.languages.clone(),
        entities,
        relations,
        terms,
        facts,
        documents,
        procedures,
        rules,
        examples,
        outcomes,
        provenance,
    };
    encode_flatbuffer(&bundle, *b"D2DM")
}

fn encode_skills(ir: &CompiledIr) -> Vec<u8> {
    let skills = ir
        .skills
        .iter()
        .map(|skill| fb::Skill {
            id: skill.id.to_string(),
            version: skill.version.clone(),
            input_schema: skill.input_schema.clone(),
            output_schema: skill.output_schema.clone(),
            preconditions: skill.preconditions.clone(),
            postconditions: skill.postconditions.clone(),
            criticality: match skill.criticality {
                Criticality::Low => fb::Criticality::Low,
                Criticality::Medium => fb::Criticality::Medium,
                Criticality::High => fb::Criticality::High,
                Criticality::Critical => fb::Criticality::Critical,
            },
            fallback: skill.fallback.clone(),
            evidence_required: skill.evidence_required,
            evaluation_dataset: skill.evaluation_dataset.clone(),
            evaluation_thresholds: skill.evaluation_thresholds.clone(),
            candidate_executors: skill
                .candidate_executors
                .iter()
                .map(ToString::to_string)
                .collect(),
            provenance_id: skill.provenance_id.to_string(),
        })
        .collect();
    encode_flatbuffer(
        &fb::SkillBundle {
            schema_version: SCHEMA_VERSION,
            skills,
        },
        *b"D2SK",
    )
}

fn encode_execution(ir: &CompiledIr) -> Vec<u8> {
    let graphs = ir
        .execution
        .graphs
        .iter()
        .map(|graph| fb::ExecutionGraph {
            schema_version: SCHEMA_VERSION,
            skill_id: graph.skill_id.to_string(),
            entry_node: graph.entry_node.to_string(),
            nodes: graph
                .nodes
                .iter()
                .map(|node| fb::ExecutionNode {
                    id: node.id.to_string(),
                    kind: to_fb_node_kind(node.kind),
                    input_type: node.input_type.clone(),
                    output_type: node.output_type.clone(),
                    timeout_ms: node.timeout_ms,
                    expected_memory_bytes: node.expected_memory_bytes,
                    executor_id: node.executor_id.as_ref().map(ToString::to_string),
                    min_confidence: node.min_confidence,
                    failure_target: node.failure_target.as_ref().map(ToString::to_string),
                    retry_limit: node.retry.limit,
                    cacheable: node.cache.cacheable,
                    side_effect: node.side_effect,
                    parallel_group: node.parallel_group.clone(),
                    evidence_required: node.evidence_required,
                    loop_max_iterations: node.loop_max_iterations.unwrap_or(0),
                    provenance_id: node.provenance_id.to_string(),
                })
                .collect(),
            edges: graph
                .edges
                .iter()
                .map(|edge| fb::ExecutionEdge {
                    from: edge.from.to_string(),
                    to: edge.to.to_string(),
                    kind: match edge.kind {
                        EdgeKind::Success => fb::EdgeKind::Success,
                        EdgeKind::Failure => fb::EdgeKind::Failure,
                        EdgeKind::BranchTrue => fb::EdgeKind::BranchTrue,
                        EdgeKind::BranchFalse => fb::EdgeKind::BranchFalse,
                        EdgeKind::Parallel => fb::EdgeKind::Parallel,
                        EdgeKind::Join => fb::EdgeKind::Join,
                    },
                    condition: edge.condition.clone(),
                    provenance_id: edge.provenance_id.to_string(),
                })
                .collect(),
        })
        .collect();
    encode_flatbuffer(
        &fb::ExecutionBundle {
            schema_version: SCHEMA_VERSION,
            graphs,
        },
        *b"D2EX",
    )
}

fn encode_policies(ir: &CompiledIr) -> Vec<u8> {
    let bundle = fb::PolicyBundle {
        schema_version: SCHEMA_VERSION,
        default_action: ir.policy.default_action.clone(),
        network_allowed: ir.policy.network_allowed,
        access_labels: ir
            .policy
            .access_labels
            .iter()
            .map(|item| fb::AccessLabel {
                resource: item.resource.clone(),
                label: item.label.clone(),
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
        confidence_thresholds: ir
            .policy
            .confidence_thresholds
            .iter()
            .map(|item| fb::ConfidenceThreshold {
                skill_id: item.skill_id.to_string(),
                minimum: item.minimum,
                fallback: item.fallback.clone(),
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
        action_permissions: ir
            .policy
            .action_permissions
            .iter()
            .map(|item| fb::ActionPermission {
                action: item.action.clone(),
                allowed: item.allowed,
                requires_human_review: item.requires_human_review,
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
        allowed_executors: ir
            .policy
            .allowed_executors
            .iter()
            .map(ToString::to_string)
            .collect(),
    };
    encode_flatbuffer(&bundle, *b"D2PL")
}

fn encode_evaluation(ir: &CompiledIr) -> Vec<u8> {
    let bundle = fb::EvaluationBundle {
        schema_version: SCHEMA_VERSION,
        cases: ir
            .evaluation
            .cases
            .iter()
            .map(|item| fb::EvaluationCase {
                id: item.id.clone(),
                skill_id: item.skill_id.to_string(),
                request_json: canonical_json(&item.request),
                expected_json: canonical_json(&item.expected),
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
        metrics: ir
            .evaluation
            .metrics
            .iter()
            .map(|item| fb::MetricSpec {
                id: item.id.clone(),
                threshold: item.threshold,
                higher_is_better: item.higher_is_better,
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
        critical_errors: ir
            .evaluation
            .critical_errors
            .iter()
            .map(|item| fb::CriticalErrorCondition {
                id: item.id.clone(),
                expression: item.expression.clone(),
                maximum_rate: item.maximum_rate,
                provenance_id: item.provenance_id.to_string(),
            })
            .collect(),
    };
    encode_flatbuffer(&bundle, *b"D2EV")
}

fn to_fb_provenance(item: &EvidenceRef) -> fb::Provenance {
    fb::Provenance {
        id: item.id.to_string(),
        source_path: item.source_path.clone(),
        line: item.line.unwrap_or(0),
        field: item.field.clone(),
        content_hash: item.content_hash.clone(),
    }
}

fn record(
    id: &str,
    kind: &str,
    subject: &str,
    predicate: &str,
    object: &str,
    provenance_id: &str,
) -> fb::StringRecord {
    fb::StringRecord {
        id: id.to_owned(),
        kind: kind.to_owned(),
        subject: (!subject.is_empty()).then(|| subject.to_owned()),
        predicate: (!predicate.is_empty()).then(|| predicate.to_owned()),
        object: (!object.is_empty()).then(|| object.to_owned()),
        provenance_id: provenance_id.to_owned(),
    }
}

fn to_fb_node_kind(kind: NodeKind) -> fb::NodeKind {
    match kind {
        NodeKind::ReadInput => fb::NodeKind::ReadInput,
        NodeKind::Normalize => fb::NodeKind::Normalize,
        NodeKind::Lookup => fb::NodeKind::Lookup,
        NodeKind::Retrieve => fb::NodeKind::Retrieve,
        NodeKind::RuleEval => fb::NodeKind::RuleEval,
        NodeKind::NativeCall => fb::NodeKind::NativeCall,
        NodeKind::ModelCall => fb::NodeKind::ModelCall,
        NodeKind::Parallel => fb::NodeKind::Parallel,
        NodeKind::Join => fb::NodeKind::Join,
        NodeKind::Branch => fb::NodeKind::Branch,
        NodeKind::LoopBounded => fb::NodeKind::LoopBounded,
        NodeKind::Validate => fb::NodeKind::Validate,
        NodeKind::PolicyGate => fb::NodeKind::PolicyGate,
        NodeKind::HumanReview => fb::NodeKind::HumanReview,
        NodeKind::Return => fb::NodeKind::Return,
    }
}

fn encode_flatbuffer<T>(value: impl planus::WriteAsOffset<T>, identifier: [u8; 4]) -> Vec<u8> {
    let mut builder = planus::Builder::new();
    let planus_bytes = builder.finish(value, Some(identifier));
    if planus_bytes.len() < 8 {
        return planus_bytes.to_vec();
    }

    // Planus 1.x emits `[identifier][root offset][body]`. Normalize that
    // header to the FlatBuffers wire order `[root offset][identifier][body]`.
    let mut offset_bytes = [0_u8; 4];
    offset_bytes.copy_from_slice(&planus_bytes[4..8]);
    let root_offset = u32::from_le_bytes(offset_bytes).saturating_add(4);
    let mut bytes = Vec::with_capacity(planus_bytes.len());
    bytes.extend_from_slice(&root_offset.to_le_bytes());
    bytes.extend_from_slice(&planus_bytes[..4]);
    bytes.extend_from_slice(&planus_bytes[8..]);
    bytes
}

fn decode_flatbuffer<'a, Ref, Owned>(
    bytes: &'a [u8],
    identifier: [u8; 4],
    path: &str,
    read: impl Fn(&'a [u8]) -> planus::Result<Ref>,
) -> Result<Owned, PackageError>
where
    Ref: TryInto<Owned>,
    <Ref as TryInto<Owned>>::Error: Display,
{
    if bytes.len() < 8 || bytes[4..8] != identifier {
        return Err(PackageError::CorruptFlatbuffer {
            path: path.to_owned(),
            message: format!(
                "missing or incorrect file identifier (header {:02x?})",
                bytes.get(..8).unwrap_or(bytes)
            ),
        });
    }
    let reference = read(bytes).map_err(|error| PackageError::CorruptFlatbuffer {
        path: path.to_owned(),
        message: error.to_string(),
    })?;
    reference
        .try_into()
        .map_err(|error| PackageError::CorruptFlatbuffer {
            path: path.to_owned(),
            message: error.to_string(),
        })
}

fn copy_referenced_sources(
    source: &Path,
    manifest: &DomainManifest,
    source_lock: &SourceLock,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), PackageError> {
    let lock_hashes = source_lock
        .files
        .iter()
        .map(|entry| (entry.path().to_owned(), entry.content_hash().to_owned()))
        .collect::<BTreeMap<_, _>>();
    let mut references = manifest
        .skills
        .iter()
        .flat_map(|skill| [skill.input_schema.as_str(), skill.output_schema.as_str()])
        .collect::<BTreeSet<_>>();
    if manifest.package.include_eval_data {
        references.insert(&manifest.evaluation.dataset);
        references.insert(&manifest.evaluation.thresholds);
    }
    for reference in references {
        validate_relative_path(reference)?;
        let bytes = read_bounded(&source.join(reference))?;
        let actual = format!("sha256:{}", sha256_hex(&bytes));
        let Some(expected) = lock_hashes.get(reference) else {
            return Err(PackageError::MissingArtifact(reference.to_owned()));
        };
        if &actual != expected {
            return Err(PackageError::HashMismatch {
                path: reference.to_owned(),
                expected: expected.clone(),
                actual,
            });
        }
        let target = if reference.starts_with("schemas/") {
            reference.to_owned()
        } else {
            format!("eval/source/{reference}")
        };
        artifacts.insert(target, bytes);
    }
    Ok(())
}

fn validate_output_boundary(source: &Path, output: &Path) -> Result<(), PackageError> {
    let source = fs::canonicalize(source).map_err(|error| io_error(source, error))?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|error| io_error(parent, error))?;
    let file_name = output
        .file_name()
        .ok_or_else(|| PackageError::UnsafePath(output.display().to_string()))?;
    let candidate = parent.join(file_name);
    if candidate.starts_with(&source) {
        return Err(PackageError::UnsafePath(format!(
            "{} (output must not be inside the source pack)",
            output.display()
        )));
    }
    Ok(())
}

fn write_artifact(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), PackageError> {
    validate_relative_path(relative)?;
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error(parent, error))?;
    }
    fs::write(&path, bytes).map_err(|error| io_error(&path, error))
}

fn read_package_artifact(root: &Path, relative: &str) -> Result<Vec<u8>, PackageError> {
    validate_relative_path(relative)?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(PackageError::UnsafePath(relative.to_owned()));
    }
    let canonical = fs::canonicalize(&path).map_err(|error| io_error(&path, error))?;
    if !canonical.starts_with(root) {
        return Err(PackageError::UnsafePath(relative.to_owned()));
    }
    read_bounded(&canonical)
}

fn inventory_package_paths(root: &Path) -> Result<BTreeSet<String>, PackageError> {
    let mut result = BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| io_error(&directory, error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| io_error(&directory, error))?;
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| io_error(&path, error))?;
            if metadata.file_type().is_symlink() {
                return Err(PackageError::UnsafePath(relative_display(root, &path)));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                result.insert(relative_display(root, &path));
            }
        }
    }
    Ok(result)
}

fn parse_hashes(text: &str) -> Result<BTreeMap<String, String>, PackageError> {
    let mut hashes = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let (hash, path) = line.split_once("  ").ok_or_else(|| {
            PackageError::InvalidFormat(format!(
                "invalid hashes.sha256 record at line {}",
                index + 1
            ))
        })?;
        validate_hash(hash)?;
        validate_relative_path(path)?;
        if hashes.insert(path.to_owned(), hash.to_owned()).is_some() {
            return Err(PackageError::InvalidFormat(format!(
                "duplicate hash record for '{path}'"
            )));
        }
    }
    if hashes.is_empty() {
        return Err(PackageError::InvalidFormat(
            "hashes.sha256 must not be empty".to_owned(),
        ));
    }
    Ok(hashes)
}

fn render_hashes(hashes: &BTreeMap<String, String>) -> Vec<u8> {
    let mut output = String::new();
    for (path, hash) in hashes {
        output.push_str(hash);
        output.push_str("  ");
        output.push_str(path);
        output.push('\n');
    }
    output.into_bytes()
}

fn read_hash_map(root: &Path) -> Result<BTreeMap<String, String>, PackageError> {
    let bytes = read_bounded(&root.join("hashes.sha256"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| PackageError::InvalidFormat(error.to_string()))?;
    parse_hashes(text)
}

fn hash_entries(entries: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"d2i-package-payload-v1\0");
    for (path, hash) in entries {
        hash_length_prefixed(&mut hasher, path.as_bytes());
        hash_length_prefixed(&mut hasher, hash.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn deterministic_build_id(domain_id: &str, domain_version: &str, source_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"d2i-build-v1\0");
    for value in [
        domain_id,
        domain_version,
        source_hash,
        COMPILER_VERSION,
        PACKAGE_FORMAT_VERSION,
        RUNTIME_ABI_VERSION,
    ] {
        hash_length_prefixed(&mut hasher, value.as_bytes());
    }
    format!("b{:x}", hasher.finalize())
}

fn hash_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PackageError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| PackageError::InvalidFormat(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn required_bytes<'a>(
    files: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a [u8], PackageError> {
    files
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| PackageError::MissingArtifact(path.to_owned()))
}

fn check_version(name: &'static str, expected: &str, actual: &str) -> Result<(), PackageError> {
    if actual == expected {
        Ok(())
    } else {
        Err(PackageError::VersionMismatch {
            name,
            expected: expected.to_owned(),
            actual: actual.to_owned(),
        })
    }
}

fn validate_relative_path(path: &str) -> Result<(), PackageError> {
    if path.is_empty() || path.contains('\\') {
        return Err(PackageError::UnsafePath(path.to_owned()));
    }
    let candidate = Path::new(path);
    if candidate.is_absolute()
        || candidate.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PackageError::UnsafePath(path.to_owned()));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), PackageError> {
    if hash.len() == 64
        && hash
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(PackageError::InvalidFormat(format!(
            "invalid SHA-256 digest '{hash}'"
        )))
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, PackageError> {
    let file = fs::File::open(path).map_err(|error| io_error(path, error))?;
    let mut bytes = Vec::new();
    file.take(MAX_PACKAGE_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageError::InvalidFormat(format!(
            "package file '{}' exceeds {} bytes",
            path.display(),
            MAX_PACKAGE_FILE_BYTES
        )));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn io_error(path: &Path, error: io::Error) -> PackageError {
    PackageError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}
