use d2i_limited_autonomy::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs;
use std::path::Path;

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
        _ => Err("usage: d2i-autonomy <readiness|profile|deployment|state|control|eligibility|admission|task-binding|cohort|health|health-trip|handoff|response|duty-request|duty-result|completion|replay|certification> verify --input <json>".to_owned()),
    }
}

fn verify_artifact(kind: &str, path: &Path) -> Result<(), String> {
    match kind {
        "readiness" => parse_and_validate::<AutonomyReadinessBindingV1>(path, |value| {
            value.validate_integrity()
        }),
        "profile" => {
            parse_and_validate::<LimitedAutonomyProfileV1>(path, |value| value.validate_integrity())
        }
        "deployment" => parse_and_validate::<AutonomyDeploymentApprovalV1>(path, |value| {
            value.validate_integrity()
        }),
        "state" => parse_and_validate::<AutonomyRoleRuntimeStateV1>(path, |value| {
            value.validate_integrity()
        }),
        "control" => {
            parse_and_validate::<AutonomyControlCommandV1>(path, |value| value.validate_integrity())
        }
        "eligibility" => parse_and_validate::<AutonomyCaseEligibilityV1>(path, |value| {
            value.validate_integrity()
        }),
        "admission" => {
            parse_and_validate::<AutonomyCaseAdmissionV1>(path, |value| value.validate_integrity())
        }
        "task-binding" => parse_and_validate::<AutonomousCaseTaskBindingV1>(path, |value| {
            value.validate_integrity()
        }),
        "cohort" => {
            parse_and_validate::<AutonomyRolloutCohortV1>(path, |value| value.validate_integrity())
        }
        "health" => {
            parse_and_validate::<AutonomyHealthSnapshotV1>(path, |value| value.validate_integrity())
        }
        "health-trip" => parse_and_validate::<AutonomyHealthTripV1>(path, validate_health_trip),
        "handoff" => parse_and_validate::<HumanExceptionHandoffV1>(path, validate_handoff),
        "response" => {
            parse_and_validate::<HumanExceptionResponseV1>(path, |value| value.validate_integrity())
        }
        "duty-request" => parse_and_validate::<AutonomousRoleDutyCycleRequestV1>(path, |value| {
            value.validate_integrity()
        }),
        "duty-result" => parse_and_validate::<AutonomousRoleDutyCycleResultV1>(path, |value| {
            value.validate_integrity()
        }),
        "completion" => parse_and_validate::<LimitedAutonomyCompletionReportV1>(path, |value| {
            value.validate_integrity()
        }),
        "replay" => parse_and_validate::<LimitedAutonomyReplayReportV1>(path, |value| {
            value.validate_integrity()
        }),
        "certification" => parse_and_validate::<LimitedAutonomyCertificationV1>(path, |value| {
            value.validate_integrity()
        }),
        _ => Err("unsupported limited autonomy artifact kind".to_owned()),
    }
}

fn parse_and_validate<T>(
    path: &Path,
    validate: impl FnOnce(&T) -> Result<(), LimitedAutonomyError>,
) -> Result<(), String>
where
    T: DeserializeOwned + Serialize,
{
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("input is not a regular non-symlink file".to_owned());
    }
    if metadata.len() > MAX_JSON_BYTES as u64 {
        return Err("input exceeds byte limit".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let value: T = parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    println!(
        "{}",
        canonical_sha256(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}
