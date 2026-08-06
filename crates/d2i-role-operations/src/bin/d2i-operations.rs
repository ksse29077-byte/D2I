use d2i_role_operations::{
    parse_json_strict, CaseSlaRuntimeStateV1, RoleEscalationItemV1, RoleMetricResultV1,
    RoleOperationsProfileV1, RoleOperationsReplayReportV1, RoleOperationsReportV1,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("d2i-operations failed closed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [kind, command, flag, input]
            if command == "verify" && flag == "--input" && kind == "profile" =>
        {
            verify_file::<RoleOperationsProfileV1>(Path::new(input), |value| value.validate())
        }
        [kind, command, flag, input]
            if command == "verify" && flag == "--input" && kind == "sla" =>
        {
            verify_file::<CaseSlaRuntimeStateV1>(Path::new(input), |value| value.validate())
        }
        [kind, command, flag, input]
            if command == "verify" && flag == "--input" && kind == "metric" =>
        {
            verify_file::<RoleMetricResultV1>(Path::new(input), |value| value.validate())
        }
        [kind, command, flag, input]
            if command == "verify" && flag == "--input" && kind == "report" =>
        {
            verify_file::<RoleOperationsReportV1>(Path::new(input), |value| value.validate())
        }
        [kind, command, flag, input]
            if command == "verify" && flag == "--input" && kind == "escalation" =>
        {
            verify_file::<RoleEscalationItemV1>(Path::new(input), |value| value.validate())
        }
        [command, flag, bundle] if command == "replay" && flag == "--bundle" => {
            verify_replay_bundle(PathBuf::from(bundle))
        }
        _ => Err("usage: d2i-operations <profile|sla|metric|report|escalation> verify --input <json> | replay --bundle <directory>".to_owned()),
    }
}

fn verify_file<T>(
    path: &Path,
    validate: impl FnOnce(&T) -> Result<(), d2i_role_operations::RoleOperationsError>,
) -> Result<(), String>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_bounded(path)?;
    let value: T = parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    let output = serde_json::json!({
        "schema_version": 1,
        "valid": true,
        "input": path.display().to_string()
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn verify_replay_bundle(root: PathBuf) -> Result<(), String> {
    if !root.is_dir() {
        return Err("replay bundle is not a directory".to_owned());
    }
    verify_file::<RoleOperationsReplayReportV1>(&root.join("replay-report.json"), |value| {
        value.validate()
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_INPUT_BYTES
    {
        return Err("input must be a bounded regular file".to_owned());
    }
    std::fs::read(path).map_err(|error| error.to_string())
}
