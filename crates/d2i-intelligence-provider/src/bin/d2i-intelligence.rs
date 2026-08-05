use d2i_intelligence_provider::{
    parse_strict_provider_json, GoalUnderstandingResultV1, IntelligenceProviderDescriptorV1,
    IntelligenceProviderResultV1, ModelE2eReportV1, ModelEvaluationReportV1,
    MAX_PROVIDER_OUTPUT_BYTES,
};
use d2i_situation_model::canonical_sha256;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct Output<'a> {
    status: &'a str,
    artifact: &'a str,
    hash: Option<String>,
    count: Option<usize>,
    error: Option<String>,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let output = run(&args);
    let failed = output.status != "valid";
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(error) => println!("{{\"status\":\"invalid\",\"error\":\"{error}\"}}"),
    }
    if failed {
        std::process::exit(2);
    }
}

fn run(args: &[String]) -> Output<'static> {
    if args.len() == 4 && args[1] == "verify" && args[2] == "--input" {
        let bytes = match read_file(Path::new(&args[3])) {
            Ok(bytes) => bytes,
            Err(error) => return invalid("input", error),
        };
        return match args[0].as_str() {
            "descriptor" => verify_descriptor(&bytes),
            "result" => verify_result(&bytes),
            "goal-result" => verify_goal_result(&bytes),
            "evaluation" => verify_evaluation(&bytes),
            "model-e2e" => verify_model_e2e(&bytes),
            _ => invalid(
                "usage",
                "unsupported provider verification artifact".to_owned(),
            ),
        };
    }
    if args.len() == 3 && args[1] == "--bundle" {
        return match args[0].as_str() {
            "evaluate" => verify_report_bundle(Path::new(&args[2])),
            "replay" => replay_bundle(Path::new(&args[2])),
            _ => invalid("usage", "unsupported provider bundle command".to_owned()),
        };
    }
    invalid(
        "usage",
        "expected <descriptor|result|goal-result|evaluation|model-e2e> verify --input <path>, evaluate --bundle <dir>, or replay --bundle <dir>".to_owned(),
    )
}

fn verify_descriptor(bytes: &[u8]) -> Output<'static> {
    match parse_strict_provider_json::<IntelligenceProviderDescriptorV1>(bytes)
        .and_then(|value| value.validate().map(|()| value.descriptor_sha256))
    {
        Ok(hash) => valid("descriptor", hash, None),
        Err(error) => invalid("descriptor", error.to_string()),
    }
}

fn verify_result(bytes: &[u8]) -> Output<'static> {
    match parse_strict_provider_json::<IntelligenceProviderResultV1>(bytes)
        .and_then(|value| value.validate().map(|()| value.result_sha256))
    {
        Ok(hash) => valid("result", hash, None),
        Err(error) => invalid("result", error.to_string()),
    }
}

fn verify_goal_result(bytes: &[u8]) -> Output<'static> {
    match parse_strict_provider_json::<GoalUnderstandingResultV1>(bytes)
        .and_then(|value| value.validate().map(|()| value.result_sha256().to_owned()))
    {
        Ok(hash) => valid("goal-result", hash, None),
        Err(error) => invalid("goal-result", error.to_string()),
    }
}

fn verify_evaluation(bytes: &[u8]) -> Output<'static> {
    match parse_strict_provider_json::<ModelEvaluationReportV1>(bytes)
        .and_then(|value| value.validate().map(|()| value.report_sha256))
    {
        Ok(hash) => valid("evaluation", hash, None),
        Err(error) => invalid("evaluation", error.to_string()),
    }
}

fn verify_model_e2e(bytes: &[u8]) -> Output<'static> {
    match parse_strict_provider_json::<ModelE2eReportV1>(bytes)
        .and_then(|value| value.validate().map(|()| value.report_sha256))
    {
        Ok(hash) => valid("model-e2e", hash, None),
        Err(error) => invalid("model-e2e", error.to_string()),
    }
}

fn verify_report_bundle(path: &Path) -> Output<'static> {
    let files = match regular_json_files(path) {
        Ok(files) => files,
        Err(error) => return invalid("evaluation-bundle", error),
    };
    if files.len() != 2 {
        return invalid(
            "evaluation-bundle",
            "evaluation bundle must contain exactly evaluation and model E2E reports".to_owned(),
        );
    }
    let mut hashes = Vec::new();
    for file in &files {
        let bytes = match read_file(file) {
            Ok(bytes) => bytes,
            Err(error) => return invalid("evaluation-bundle", error),
        };
        if file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("model-e2e"))
        {
            let report = match parse_strict_provider_json::<ModelE2eReportV1>(&bytes) {
                Ok(value) => value,
                Err(error) => return invalid("evaluation-bundle", error.to_string()),
            };
            if let Err(error) = report.validate() {
                return invalid("evaluation-bundle", error.to_string());
            }
            hashes.push(report.report_sha256);
        } else {
            let report = match parse_strict_provider_json::<ModelEvaluationReportV1>(&bytes) {
                Ok(value) => value,
                Err(error) => return invalid("evaluation-bundle", error.to_string()),
            };
            if let Err(error) = report.validate() {
                return invalid("evaluation-bundle", error.to_string());
            }
            hashes.push(report.report_sha256);
        }
    }
    hashes.sort();
    match canonical_sha256(&hashes) {
        Ok(hash) => valid("evaluation-bundle", hash, Some(files.len())),
        Err(error) => invalid("evaluation-bundle", error.to_string()),
    }
}

fn replay_bundle(path: &Path) -> Output<'static> {
    let files = match regular_json_files(path) {
        Ok(files) => files,
        Err(error) => return invalid("replay", error),
    };
    if files.is_empty() || files.len() > 1_000 {
        return invalid(
            "replay",
            "replay bundle file count must be within 1..=1000".to_owned(),
        );
    }
    let mut result_hashes = Vec::with_capacity(files.len());
    for file in &files {
        let bytes = match read_file(file) {
            Ok(bytes) => bytes,
            Err(error) => return invalid("replay", error),
        };
        let result = match parse_strict_provider_json::<IntelligenceProviderResultV1>(&bytes) {
            Ok(value) => value,
            Err(error) => return invalid("replay", error.to_string()),
        };
        if let Err(error) = result.validate() {
            return invalid("replay", error.to_string());
        }
        result_hashes.push(result.result_sha256);
    }
    result_hashes.sort();
    match canonical_sha256(&result_hashes) {
        Ok(hash) => valid("replay", hash, Some(files.len())),
        Err(error) => invalid("replay", error.to_string()),
    }
}

fn regular_json_files(path: &Path) -> Result<Vec<PathBuf>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("bundle must be a regular directory".to_owned());
    }
    let mut files = std::fs::read_dir(path)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|value| value == "json"))
        .collect::<Vec<_>>();
    files.sort();
    Ok(files)
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular non-symlink file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > MAX_PROVIDER_OUTPUT_BYTES {
        return Err("input is empty or exceeds 64 KiB".to_owned());
    }
    std::fs::read(path).map_err(|error| error.to_string())
}

fn valid(artifact: &'static str, hash: String, count: Option<usize>) -> Output<'static> {
    Output {
        status: "valid",
        artifact,
        hash: Some(hash),
        count,
        error: None,
    }
}

fn invalid(artifact: &'static str, error: String) -> Output<'static> {
    Output {
        status: "invalid",
        artifact,
        hash: None,
        count: None,
        error: Some(error),
    }
}
