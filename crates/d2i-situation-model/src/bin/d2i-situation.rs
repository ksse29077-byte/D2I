use d2i_situation_model::{parse_json_strict, ApprovedCaseContextBundleV1, CaseSituationModelV1};
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
    let result = run(&args);
    let failed = result.status != "valid";
    match serde_json::to_string(&result) {
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
            "expected <context|situation> validate --input <path>",
        );
    }
    let path = Path::new(&args[3]);
    let bytes = match read_bounded(path) {
        Ok(bytes) => bytes,
        Err(error) => return invalid("input", &error),
    };
    match args[0].as_str() {
        "context" => match parse_json_strict::<ApprovedCaseContextBundleV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.context_sha256))
        {
            Ok(hash) => valid("context", hash),
            Err(error) => invalid("context", &error.to_string()),
        },
        "situation" => match parse_json_strict::<CaseSituationModelV1>(&bytes)
            .and_then(|value| value.validate().map(|()| value.situation_sha256))
        {
            Ok(hash) => valid("situation", hash),
            Err(error) => invalid("situation", &error.to_string()),
        },
        _ => invalid("usage", "unsupported situation inspection command"),
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
