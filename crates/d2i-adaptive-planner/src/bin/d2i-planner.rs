use d2i_adaptive_planner::{
    parse_strict_planner_json, AdaptivePlanV1, AdaptivePlanningRequestV1, AdaptivePlanningResultV1,
    NextStepDecisionV1, PlannerCycleRecordV1,
};
use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Output<'a> {
    status: &'a str,
    artifact: &'a str,
    hash: Option<String>,
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
    if args.len() != 4 || args[1] != "validate" || args[2] != "--input" {
        return invalid(
            "usage",
            "expected <plan|request|result|decision|cycle> validate --input <path>",
        );
    }
    let bytes = match read_bounded(Path::new(&args[3])) {
        Ok(bytes) => bytes,
        Err(error) => return invalid("input", &error),
    };
    match args[0].as_str() {
        "plan" => parse_strict_planner_json::<AdaptivePlanV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.plan_sha256))
            .map_or_else(
                |error| invalid("plan", &error.to_string()),
                |hash| valid("plan", hash),
            ),
        "request" => parse_strict_planner_json::<AdaptivePlanningRequestV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.request_sha256))
            .map_or_else(
                |error| invalid("request", &error.to_string()),
                |hash| valid("request", hash),
            ),
        "result" => parse_strict_planner_json::<AdaptivePlanningResultV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.result_sha256))
            .map_or_else(
                |error| invalid("result", &error.to_string()),
                |hash| valid("result", hash),
            ),
        "decision" => parse_strict_planner_json::<NextStepDecisionV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.decision_sha256))
            .map_or_else(
                |error| invalid("decision", &error.to_string()),
                |hash| valid("decision", hash),
            ),
        "cycle" => parse_strict_planner_json::<PlannerCycleRecordV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.record_sha256))
            .map_or_else(
                |error| invalid("cycle", &error.to_string()),
                |hash| valid("cycle", hash),
            ),
        _ => invalid("usage", "unsupported planner inspection command"),
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("input must be a regular non-symlink file".to_owned());
    }
    if metadata.len() == 0 || metadata.len() > d2i_situation_model::MAX_JSON_BYTES as u64 {
        return Err("input is empty or oversized".to_owned());
    }
    std::fs::read(path).map_err(|error| error.to_string())
}

fn valid(artifact: &'static str, hash: String) -> Output<'static> {
    Output {
        status: "valid",
        artifact,
        hash: Some(hash),
        error: None,
    }
}

fn invalid(artifact: &'static str, error: &str) -> Output<'static> {
    Output {
        status: "invalid",
        artifact,
        hash: None,
        error: Some(error.to_owned()),
    }
}
