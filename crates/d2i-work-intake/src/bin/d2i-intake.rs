use d2i_work_intake::{
    canonical_sha256, parse_json_strict, ApprovedRadarSourceRegistrationV1, RadarCheckpointV1,
    RadarCycleReportV1, WorkIntakeMappingProfileV1, WorkIntakeReceiptV1, WorkSignalV1,
    WorkSourceApprovalV1,
};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("d2i-intake: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 || !matches!(args[2].as_str(), "--input" | "--bundle") {
        return Err(
            "usage: d2i-intake <registration|source-approval|profile|signal|checkpoint|receipt> validate|verify --input <json>; or d2i-intake cycle replay --bundle <dir>".to_owned(),
        );
    }
    if args[0] == "cycle" && args[1] == "replay" && args[2] == "--bundle" {
        return replay_cycle_bundle(&args[3]);
    }
    if args[2] != "--input" {
        return Err("--bundle is supported only by cycle replay".to_owned());
    }
    let bytes = fs::read(&args[3]).map_err(|error| error.to_string())?;
    let artifact_kind = args[0].as_str();
    let artifact_sha256 = match (args[0].as_str(), args[1].as_str()) {
        ("source-approval", "validate") => {
            let value: WorkSourceApprovalV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            value.source_approval_sha256
        }
        ("cycle", "verify") => {
            let value: RadarCycleReportV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            value.cycle_sha256.clone()
        }
        _ => validate_artifact(&args, &bytes)?,
    };
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "status": "valid",
            "artifact_kind": artifact_kind,
            "artifact_sha256": artifact_sha256
        })
    );
    Ok(())
}

fn validate_artifact(args: &[String], bytes: &[u8]) -> Result<String, String> {
    match (args[0].as_str(), args[1].as_str()) {
        ("profile", "validate") => {
            let value: WorkIntakeMappingProfileV1 =
                parse_json_strict(bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            canonical_sha256(&value).map_err(|error| error.to_string())
        }
        ("signal", "validate") => {
            let value: WorkSignalV1 =
                parse_json_strict(bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            Ok(value.signal_sha256)
        }
        ("checkpoint", "verify") => {
            let value: RadarCheckpointV1 =
                parse_json_strict(bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            Ok(value.checkpoint_sha256)
        }
        ("receipt", "verify") => {
            let value: WorkIntakeReceiptV1 =
                parse_json_strict(bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            Ok(value.receipt_sha256)
        }
        ("registration", "validate") => {
            let value: ApprovedRadarSourceRegistrationV1 =
                parse_json_strict(bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            Ok(value.registration_sha256)
        }
        _ => Err("unsupported inspection operation".to_owned()),
    }
}

fn replay_cycle_bundle(path: &str) -> Result<(), String> {
    let root = std::path::Path::new(path);
    if !root.is_dir() {
        return Err("cycle bundle is not a directory".to_owned());
    }
    let bytes = fs::read(root.join("cycle-report.json")).map_err(|error| error.to_string())?;
    let report: RadarCycleReportV1 =
        parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    report.validate().map_err(|error| error.to_string())?;
    let receipts_root = root.join("receipts");
    let mut receipt_hashes = Vec::new();
    if receipts_root.exists() {
        if !receipts_root.is_dir() {
            return Err("cycle receipt bundle is not a directory".to_owned());
        }
        let mut paths = fs::read_dir(&receipts_root)
            .map_err(|error| error.to_string())?
            .map(|entry| entry.map(|value| value.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        paths.sort();
        if paths.len() > 128 {
            return Err("cycle receipt bundle exceeds v1 bounds".to_owned());
        }
        for receipt_path in paths {
            let metadata =
                fs::symlink_metadata(&receipt_path).map_err(|error| error.to_string())?;
            if !metadata.file_type().is_file()
                || receipt_path.extension().and_then(|value| value.to_str()) != Some("json")
                || metadata.len() > d2i_work_intake::MAX_RECORD_BYTES
            {
                return Err("cycle receipt entry is not a bounded regular JSON file".to_owned());
            }
            let receipt_bytes = fs::read(&receipt_path).map_err(|error| error.to_string())?;
            let receipt: WorkIntakeReceiptV1 =
                parse_json_strict(&receipt_bytes).map_err(|error| error.to_string())?;
            receipt.validate().map_err(|error| error.to_string())?;
            receipt_hashes.push(receipt.receipt_sha256);
        }
    }
    receipt_hashes.sort();
    if receipt_hashes != report.receipt_hashes {
        return Err("cycle receipt hashes differ from the report".to_owned());
    }
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "status": "replayed",
            "cycle_id": report.cycle_id,
            "cycle_sha256": report.cycle_sha256,
            "receipt_count": receipt_hashes.len()
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_work_intake::{RadarCycleReportV1, ZERO_HASH};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("unexpected error: {error:?}"),
        }
    }

    #[test]
    fn cycle_replay_reads_one_strict_bundle_without_mutation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "d2i-intake-cli-cycle-{}-{nonce}",
            std::process::id()
        ));
        ok(fs::create_dir(&root));
        let report = ok(RadarCycleReportV1 {
            schema_version: 1,
            cycle_id: "cycle-cli-replay".to_owned(),
            cycle_sequence: 1,
            role_instance_id: "role-cli-replay".to_owned(),
            role_instance_sha256: ZERO_HASH.to_owned(),
            registration_id: "registration-cli-replay".to_owned(),
            registration_sha256: ZERO_HASH.to_owned(),
            source_approval_sha256: ZERO_HASH.to_owned(),
            checkpoint_before_sha256: ZERO_HASH.to_owned(),
            checkpoint_after_sha256: ZERO_HASH.to_owned(),
            observed_signals: 0,
            accepted_signals: 0,
            cases_created: 0,
            duplicate_open: 0,
            duplicate_terminal: 0,
            denied: 0,
            clarification_required: 0,
            escalation_required: 0,
            quarantined: 0,
            logical_operations: 1,
            ticks_consumed: 1,
            retries: 0,
            receipt_hashes: Vec::new(),
            cycle_sha256: ZERO_HASH.to_owned(),
        }
        .seal());
        ok(fs::write(
            root.join("cycle-report.json"),
            ok(serde_json::to_vec_pretty(&report)),
        ));
        assert!(replay_cycle_bundle(&root.display().to_string()).is_ok());
        ok(fs::remove_dir_all(root));
    }
}
