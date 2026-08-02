use d2i_work_case::{
    canonical_sha256, parse_json_strict, CaseClosureEvaluationV1, CaseContractV1, CaseInstanceV1,
    CaseTerminalRecordV1, WorkItemV1,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Serialize)]
struct CliResult<'a> {
    schema_version: u32,
    command: &'a str,
    status: &'a str,
    artifact_sha256: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(result) => match serde_json::to_string(&result) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("d2i-case JSON error: {error}");
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!("d2i-case: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<CliResult<'static>, String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [group, command, flag, path]
            if group == "work-item" && command == "validate" && flag == "--input" =>
        {
            let item: WorkItemV1 = read_strict(Path::new(path))?;
            item.validate().map_err(|error| error.to_string())?;
            result("work-item.validate", &item)
        }
        [group, command, flag, path]
            if group == "case" && command == "inspect" && flag == "--case" =>
        {
            let contract: CaseContractV1 = read_strict(Path::new(path))?;
            contract.validate().map_err(|error| error.to_string())?;
            result("case.inspect", &contract)
        }
        [group, command, flag, path]
            if group == "case" && command == "verify" && flag == "--bundle" =>
        {
            let root = PathBuf::from(path);
            let contract: CaseContractV1 = read_strict(&root.join("case-contract.json"))?;
            contract.validate().map_err(|error| error.to_string())?;
            if root.join("case-instance.json").is_file() {
                let instance: CaseInstanceV1 = read_strict(&root.join("case-instance.json"))?;
                instance
                    .validate_against(&contract)
                    .map_err(|error| error.to_string())?;
            }
            result("case.verify", &contract)
        }
        [group, command, input_flag, input, output_flag, output]
            if group == "case"
                && command == "create"
                && input_flag == "--contract"
                && output_flag == "--output" =>
        {
            let contract: CaseContractV1 = read_strict(Path::new(input))?;
            contract.validate().map_err(|error| error.to_string())?;
            let output = PathBuf::from(output);
            if output.exists() {
                return Err("output already exists".to_owned());
            }
            std::fs::create_dir(&output).map_err(|error| error.to_string())?;
            let bytes = serde_json::to_vec_pretty(&contract).map_err(|error| error.to_string())?;
            std::fs::write(output.join("case-contract.json"), bytes)
                .map_err(|error| error.to_string())?;
            result("case.create", &contract)
        }
        [group, command, flag, path]
            if group == "case" && command == "evaluate" && flag == "--evaluation" =>
        {
            let evaluation: CaseClosureEvaluationV1 = read_strict(Path::new(path))?;
            evaluation.validate().map_err(|error| error.to_string())?;
            result("case.evaluate", &evaluation)
        }
        [group, command, flag, path]
            if group == "terminal" && command == "verify" && flag == "--input" =>
        {
            let terminal: CaseTerminalRecordV1 = read_strict(Path::new(path))?;
            terminal.validate().map_err(|error| error.to_string())?;
            result("terminal.verify", &terminal)
        }
        _ => Err(
            "usage: d2i-case work-item validate --input <file> | case inspect --case <file> | case verify --bundle <dir> | case create --contract <file> --output <dir> | case evaluate --evaluation <file> | terminal verify --input <file>"
                .to_owned(),
        ),
    }
}

fn read_strict<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("input must be a bounded regular non-symlink file".to_owned());
    }
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    parse_json_strict(&bytes).map_err(|error| error.to_string())
}

fn result<T: Serialize>(command: &'static str, value: &T) -> Result<CliResult<'static>, String> {
    Ok(CliResult {
        schema_version: 1,
        command,
        status: "pass",
        artifact_sha256: canonical_sha256(value).map_err(|error| error.to_string())?,
    })
}
