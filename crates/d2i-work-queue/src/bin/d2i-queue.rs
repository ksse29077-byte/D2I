use d2i_work_queue::{
    parse_json_strict, verify_replay_reports, CaseLeaseV1, CurrentCaseOwnershipStateV1,
    NormalizedQueueReplayReportV1, WorkQueueEntryV1, WorkQueuePolicyV1, WorkQueueSnapshotV1,
    WorkSchedulerDecisionV1,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct CliResult<'a> {
    status: &'a str,
    artifact: &'a str,
    hash: Option<String>,
    error: Option<String>,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(result) => {
            emit(&result);
        }
        Err((code, artifact, message)) => {
            emit(&CliResult {
                status: "invalid",
                artifact,
                hash: None,
                error: Some(message),
            });
            std::process::exit(code);
        }
    }
}

fn run(args: &[String]) -> Result<CliResult<'static>, (i32, &'static str, String)> {
    if args.len() < 4 || args[2] != "--input" {
        if args.len() == 3 && args[0] == "replay" && args[1] == "--bundle" {
            return replay_bundle(Path::new(&args[2]));
        }
        return Err((
            2,
            "usage",
            "expected <policy|ownership|entry|snapshot|decision|lease> <validate|verify> --input <path>, or replay --bundle <directory>".to_owned(),
        ));
    }
    let path = Path::new(&args[3]);
    let bytes = read_input(path).map_err(|message| (3, "input", message))?;
    let (artifact, hash) = match (args[0].as_str(), args[1].as_str()) {
        ("policy", "validate") => {
            let value: WorkQueuePolicyV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "policy", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "policy", error.to_string()))?;
            ("policy", value.policy_sha256)
        }
        ("ownership", "verify") => {
            let value: CurrentCaseOwnershipStateV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "ownership", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "ownership", error.to_string()))?;
            ("ownership", value.state_sha256)
        }
        ("entry", "verify") => {
            let value: WorkQueueEntryV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "entry", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "entry", error.to_string()))?;
            ("entry", value.entry_sha256)
        }
        ("snapshot", "verify") => {
            let value: WorkQueueSnapshotV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "snapshot", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "snapshot", error.to_string()))?;
            ("snapshot", value.snapshot_sha256)
        }
        ("decision", "verify") => {
            let value: WorkSchedulerDecisionV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "decision", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "decision", error.to_string()))?;
            ("decision", value.decision_sha256)
        }
        ("lease", "verify") => {
            let value: CaseLeaseV1 =
                parse_json_strict(&bytes).map_err(|error| (3, "lease", error.to_string()))?;
            value
                .validate()
                .map_err(|error| (3, "lease", error.to_string()))?;
            ("lease", value.lease_sha256)
        }
        _ => return Err((2, "usage", "unsupported inspection command".to_owned())),
    };
    Ok(CliResult {
        status: "valid",
        artifact,
        hash: Some(hash),
        error: None,
    })
}

fn replay_bundle(path: &Path) -> Result<CliResult<'static>, (i32, &'static str, String)> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| (3, "replay", format!("{}: {error}", path.display())))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err((
            3,
            "replay",
            "replay bundle must be a regular directory".to_owned(),
        ));
    }
    let mut paths = std::fs::read_dir(path)
        .map_err(|error| (3, "replay", error.to_string()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<PathBuf>>();
    paths.sort();
    let mut reports = Vec::with_capacity(paths.len());
    for report_path in paths {
        let bytes = read_input(&report_path).map_err(|message| (3, "replay", message))?;
        let report: NormalizedQueueReplayReportV1 =
            parse_json_strict(&bytes).map_err(|error| (3, "replay", error.to_string()))?;
        reports.push(report);
    }
    let hash = verify_replay_reports(&reports, reports.len())
        .map_err(|error| (3, "replay", error.to_string()))?;
    Ok(CliResult {
        status: "valid",
        artifact: "replay",
        hash: Some(hash),
        error: None,
    })
}

fn read_input(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular non-symlink file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > d2i_work_queue::MAX_JSON_BYTES as u64 {
        return Err("input file is empty or oversized".to_owned());
    }
    std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn emit(value: &CliResult<'_>) {
    match serde_json::to_string(value) {
        Ok(serialized) => println!("{serialized}"),
        Err(error) => {
            println!("{{\"status\":\"invalid\",\"error\":\"serialization failed: {error}\"}}")
        }
    }
}
