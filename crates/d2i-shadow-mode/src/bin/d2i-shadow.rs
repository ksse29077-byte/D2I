use d2i_shadow_mode::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

const MAX_BUNDLE_FILES: usize = 4_096;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [kind, operation, flag, path] if operation == "verify" && flag == "--input" => {
            verify_artifact(kind, Path::new(path))
        }
        [kind, operation, flag, path]
            if kind == "export" && operation == "verify" && flag == "--bundle" =>
        {
            verify_export_bundle(Path::new(path))
        }
        [operation, flag, path] if operation == "replay" && flag == "--bundle" => {
            verify_replay_bundle(Path::new(path))
        }
        _ => Err("usage: d2i-shadow <profile|cohort|session|proposal|reference|comparison|readiness|report> verify --input <json> | export verify --bundle <directory> | replay --bundle <directory>".to_owned()),
    }
}

fn verify_artifact(kind: &str, path: &Path) -> Result<(), String> {
    match kind {
        "profile" => parse_and_validate::<ShadowModeProfileV1>(path, |value| value.validate()),
        "cohort" => parse_and_validate::<ShadowEvaluationCohortV1>(path, |value| value.validate()),
        "session" => parse_and_validate::<ShadowSessionV1>(path, |value| value.validate()),
        "proposal" => parse_and_validate::<ShadowProposalV1>(path, |value| value.validate()),
        "reference" => {
            parse_and_validate::<HumanReferenceStepV1>(path, |value| value.validate_integrity())
        }
        "comparison" => {
            parse_and_validate::<ShadowStepComparisonV1>(path, |value| value.validate())
        }
        "readiness" => parse_and_validate::<ShadowReadinessAssessmentV1>(path, |value| {
            value.validate_integrity()
        }),
        "report" => parse_and_validate::<ShadowEvaluationReportV1>(path, |value| value.validate()),
        _ => Err("unsupported Shadow artifact kind".to_owned()),
    }
}

fn parse_and_validate<T>(
    path: &Path,
    validate: impl FnOnce(&T) -> Result<(), ShadowModeError>,
) -> Result<(), String>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_regular_file(path)?;
    let value: T = parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    println!(
        "{}",
        canonical_sha256(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn verify_export_bundle(path: &Path) -> Result<(), String> {
    let root = canonical_directory(path)?;
    let manifest = root.join("shadow-evaluation-export-bundle.json");
    let bytes = read_regular_file(&manifest)?;
    let bundle: ShadowEvaluationExportBundleV1 =
        parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    bundle.validate().map_err(|error| error.to_string())?;
    let files = bounded_files(&root)?;
    if files
        .iter()
        .any(|file| is_reparse_or_symlink(file).unwrap_or(true))
    {
        return Err("export bundle contains a symlink or reparse point".to_owned());
    }
    println!("{}", bundle.bundle_sha256);
    Ok(())
}

fn verify_replay_bundle(path: &Path) -> Result<(), String> {
    let root = canonical_directory(path)?;
    let report = root.join("shadow-replay-report.json");
    parse_and_validate::<ShadowReplayReportV1>(&report, |value| value.validate())
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("input is not a regular non-symlink file".to_owned());
    }
    if metadata.len() > MAX_JSON_BYTES as u64 {
        return Err("input exceeds byte limit".to_owned());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn canonical_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("bundle root is not a regular directory".to_owned());
    }
    fs::canonicalize(path).map_err(|error| error.to_string())
}

fn bounded_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if is_reparse_or_symlink(&path)? {
                return Err("bundle traversal encountered a symlink or reparse point".to_owned());
            }
            let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
                if files.len() > MAX_BUNDLE_FILES {
                    return Err("bundle exceeds file count limit".to_owned());
                }
            } else {
                return Err("bundle contains a non-regular entry".to_owned());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn is_reparse_or_symlink(path: &Path) -> Result<bool, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}
