use crate::contract::{
    canonical_sha256, ModuleError, ModuleErrorCode, ModuleInvocationEnvelope, ModuleResultStatus,
};
use crate::manifest::{load_module_manifest, read_bounded};
use crate::sdk::{
    invoke_module, validate_result_binding, InvocationContext, Module, SchemaCatalog,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Successful conformance exit code.
pub const CONFORMANCE_EXIT_PASSED: i32 = 0;
/// Contract or fixture failure exit code.
pub const CONFORMANCE_EXIT_FAILED: i32 = 10;
/// No executable reference path exists.
pub const CONFORMANCE_EXIT_UNSUPPORTED: i32 = 11;
/// Conformance harness internal failure.
pub const CONFORMANCE_EXIT_INTERNAL: i32 = 12;
const MAX_FIXTURE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_FIXTURES: usize = 1_024;

/// Check or suite result. Skipped is never counted as pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStatus {
    Pass,
    Fail,
    Unsupported,
    Skipped,
}

/// One structured conformance check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCheck {
    pub check_id: String,
    pub status: ConformanceStatus,
    pub message: String,
}

/// Expected fixture terminal state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureExpectation {
    pub status: ModuleResultStatus,
    pub error_code: Option<ModuleErrorCode>,
    pub output_hash: Option<String>,
    pub output_payload: Option<Value>,
}

/// Deterministic module fixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureSpec {
    pub schema_version: u32,
    pub fixture_id: String,
    pub fixture_kind: String,
    pub invocation: ModuleInvocationEnvelope,
    pub context: InvocationContext,
    pub expected: FixtureExpectation,
    pub replay_count: u32,
}

/// Per-fixture result and deterministic replay evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureReport {
    pub fixture_id: String,
    pub status: ConformanceStatus,
    pub result_status: Option<ModuleResultStatus>,
    pub result_hash: Option<String>,
    pub replay_hashes: Vec<String>,
    pub message: String,
}

/// Stable machine-readable conformance report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceReport {
    pub schema_version: u32,
    pub module_id: String,
    pub module_version: String,
    pub manifest_sha256: String,
    pub status: ConformanceStatus,
    pub checks: Vec<ConformanceCheck>,
    pub fixtures: Vec<FixtureReport>,
    pub passed: u32,
    pub failed: u32,
    pub unsupported: u32,
    pub skipped: u32,
    pub exit_code: i32,
    pub report_hash: String,
}

impl ConformanceReport {
    /// Computes the canonical report hash with the self-hash omitted.
    pub fn stable_hash(&self) -> Result<String, ModuleError> {
        let mut unhashed = serde_json::to_value(self).map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InternalFailure,
                format!("cannot serialize conformance report: {error}"),
            )
        })?;
        let object = unhashed.as_object_mut().ok_or_else(|| {
            ModuleError::new(
                ModuleErrorCode::InternalFailure,
                "conformance report did not serialize as an object",
            )
        })?;
        object.remove("report_hash");
        canonical_sha256(&unhashed)
    }

    /// True only when every check and fixture passed.
    #[must_use]
    pub const fn is_pass(&self) -> bool {
        matches!(self.status, ConformanceStatus::Pass)
    }
}

/// Loads a module and runs every JSON fixture in deterministic path order.
pub fn run_fixture_suite<M: Module>(
    module: &M,
    module_root: &Path,
) -> Result<ConformanceReport, ModuleError> {
    let loaded = load_module_manifest(module_root)?;
    let schemas = SchemaCatalog::from_loaded(&loaded)?;
    let fixture_root = loaded.root.join("fixtures");
    let fixture_paths = fixture_paths(&fixture_root)?;
    let mut checks = vec![
        ConformanceCheck {
            check_id: "manifest.valid".to_owned(),
            status: ConformanceStatus::Pass,
            message: "manifest, schemas, artifact, and hashes are valid".to_owned(),
        },
        ConformanceCheck {
            check_id: "security.network-denied".to_owned(),
            status: ConformanceStatus::Pass,
            message: "network is denied by the validated manifest".to_owned(),
        },
        ConformanceCheck {
            check_id: "security.side-effect-false".to_owned(),
            status: ConformanceStatus::Pass,
            message: "side effects are disabled by the validated manifest".to_owned(),
        },
    ];
    let self_check = module.self_check();
    checks.push(ConformanceCheck {
        check_id: "module.self-check".to_owned(),
        status: if self_check.healthy {
            ConformanceStatus::Pass
        } else {
            ConformanceStatus::Fail
        },
        message: if self_check.details.is_empty() {
            "module self-check returned no detail".to_owned()
        } else {
            self_check.details.join("; ")
        },
    });

    let mut fixture_reports = Vec::new();
    for path in fixture_paths {
        let bytes = read_bounded(&path, MAX_FIXTURE_BYTES)?;
        let fixture: FixtureSpec = crate::parse_json_strict(&bytes)?;
        fixture_reports.push(run_fixture(module, &loaded, &schemas, &fixture)?);
    }
    if fixture_reports.is_empty() {
        checks.push(ConformanceCheck {
            check_id: "fixtures.present".to_owned(),
            status: ConformanceStatus::Fail,
            message: "no fixture JSON files were found".to_owned(),
        });
    } else {
        checks.push(ConformanceCheck {
            check_id: "fixtures.present".to_owned(),
            status: ConformanceStatus::Pass,
            message: format!("{} fixture files loaded", fixture_reports.len()),
        });
    }

    let mut passed = 0_u32;
    let mut failed = 0_u32;
    let mut unsupported = 0_u32;
    let mut skipped = 0_u32;
    for status in checks
        .iter()
        .map(|check| check.status)
        .chain(fixture_reports.iter().map(|fixture| fixture.status))
    {
        match status {
            ConformanceStatus::Pass => passed = passed.saturating_add(1),
            ConformanceStatus::Fail => failed = failed.saturating_add(1),
            ConformanceStatus::Unsupported => unsupported = unsupported.saturating_add(1),
            ConformanceStatus::Skipped => skipped = skipped.saturating_add(1),
        }
    }
    let status = if failed > 0 || skipped > 0 {
        ConformanceStatus::Fail
    } else if unsupported > 0 {
        ConformanceStatus::Unsupported
    } else {
        ConformanceStatus::Pass
    };
    let exit_code = match status {
        ConformanceStatus::Pass => CONFORMANCE_EXIT_PASSED,
        ConformanceStatus::Fail | ConformanceStatus::Skipped => CONFORMANCE_EXIT_FAILED,
        ConformanceStatus::Unsupported => CONFORMANCE_EXIT_UNSUPPORTED,
    };
    let mut report = ConformanceReport {
        schema_version: 1,
        module_id: loaded.identifier.module_id.clone(),
        module_version: loaded.identifier.module_version.clone(),
        manifest_sha256: loaded.manifest_sha256,
        status,
        checks,
        fixtures: fixture_reports,
        passed,
        failed,
        unsupported,
        skipped,
        exit_code,
        report_hash: String::new(),
    };
    report.report_hash = report.stable_hash()?;
    Ok(report)
}

fn run_fixture<M: Module>(
    module: &M,
    loaded: &crate::LoadedModuleManifest,
    schemas: &SchemaCatalog,
    fixture: &FixtureSpec,
) -> Result<FixtureReport, ModuleError> {
    if fixture.schema_version != 1 || fixture.replay_count == 0 || fixture.replay_count > 10 {
        return Ok(FixtureReport {
            fixture_id: fixture.fixture_id.clone(),
            status: ConformanceStatus::Fail,
            result_status: None,
            result_hash: None,
            replay_hashes: Vec::new(),
            message: "fixture version or replay_count is invalid".to_owned(),
        });
    }
    let first = invoke_module(
        module,
        loaded,
        schemas,
        &fixture.invocation,
        &fixture.context,
    )?;
    validate_result_binding(&fixture.invocation, &first)?;
    let first_hash = canonical_sha256(&first)?;
    let mut replay_hashes = vec![first_hash.clone()];
    for _ in 1..fixture.replay_count {
        let replay = invoke_module(
            module,
            loaded,
            schemas,
            &fixture.invocation,
            &fixture.context,
        )?;
        validate_result_binding(&fixture.invocation, &replay)?;
        replay_hashes.push(canonical_sha256(&replay)?);
    }
    let deterministic = replay_hashes.iter().all(|hash| hash == &first_hash);
    let status_match = first.status == fixture.expected.status;
    let error_match = fixture.expected.error_code.is_none()
        || first.error.as_ref().map(|error| error.code) == fixture.expected.error_code;
    let hash_match = fixture
        .expected
        .output_hash
        .as_ref()
        .is_none_or(|expected| expected == &first.output_hash);
    let payload_match = fixture
        .expected
        .output_payload
        .as_ref()
        .is_none_or(|expected| first.payload.as_ref() == Some(expected));
    let passed = deterministic && status_match && error_match && hash_match && payload_match;
    Ok(FixtureReport {
        fixture_id: fixture.fixture_id.clone(),
        status: if passed {
            ConformanceStatus::Pass
        } else {
            ConformanceStatus::Fail
        },
        result_status: Some(first.status),
        result_hash: Some(first.output_hash),
        replay_hashes,
        message: if passed {
            "fixture and deterministic replay matched expectation".to_owned()
        } else {
            format!(
                "fixture mismatch: deterministic={deterministic}, status={status_match}, error={error_match}, hash={hash_match}, payload={payload_match}"
            )
        },
    })
}

fn fixture_paths(root: &Path) -> Result<Vec<PathBuf>, ModuleError> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let root = fs::canonicalize(root).map_err(|error| {
        ModuleError::new(
            ModuleErrorCode::DependencyUnavailable,
            format!("cannot canonicalize fixture root: {error}"),
        )
    })?;
    let mut pending = vec![root.clone()];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::DependencyUnavailable,
                format!("cannot read fixture directory: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::DependencyUnavailable,
                    format!("cannot read fixture entry: {error}"),
                )
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::DependencyUnavailable,
                    format!("cannot inspect fixture entry: {error}"),
                )
            })?;
            if metadata.file_type().is_symlink() {
                return Err(ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "fixture suite rejects symbolic links",
                ));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                let canonical = fs::canonicalize(&path).map_err(|error| {
                    ModuleError::new(
                        ModuleErrorCode::DependencyUnavailable,
                        format!("cannot canonicalize fixture: {error}"),
                    )
                })?;
                if !canonical.starts_with(&root) {
                    return Err(ModuleError::new(
                        ModuleErrorCode::InvalidInput,
                        "fixture path escapes fixture root",
                    ));
                }
                paths.push(canonical);
            }
            if paths.len() > MAX_FIXTURES {
                return Err(ModuleError::new(
                    ModuleErrorCode::ResourceExhausted,
                    "fixture suite exceeds maximum fixture count",
                ));
            }
        }
    }
    paths.sort();
    Ok(paths)
}
