use crate::ReferenceRuntime;
use d2i_runtime_api::{ReplayRecord, Runtime, RuntimeError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Command completed successfully.
pub const EXIT_SUCCESS: i32 = 0;
/// Command-line usage was invalid.
pub const EXIT_USAGE: i32 = 2;
/// Local input or output failed.
pub const EXIT_IO: i32 = 4;
/// Package verification or compatibility failed.
pub const EXIT_PACKAGE: i32 = 5;
/// Request execution failed.
pub const EXIT_RUNTIME: i32 = 6;
/// Replay completed but the decision hash differed.
pub const EXIT_REPLAY_MISMATCH: i32 = 7;

const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 60_000;
const HELP: &str = "\
d2i-runtime - offline D2I reference runtime

Usage:
  d2i-runtime run --package PACKAGE_DIR --request FILE [options]
  d2i-runtime replay --package PACKAGE_DIR --record FILE [--json]
  d2i-runtime --help

Options:
  --skill ID          Skill to execute; inferred when the package has one skill.
  --request-id ID     Stable request identifier; derived from input when omitted.
  --timeout-ms N      Task deadline in milliseconds (default: 5000, max: 60000).
  --record FILE       Write a replay record after a successful run.
  --json              Emit compact machine-readable JSON.

FILE may be '-' to read request JSON from standard input. The runtime is local
only and rejects packages that permit network access.
";

#[derive(Debug)]
struct RunOptions {
    package: PathBuf,
    request: PathBuf,
    skill: Option<String>,
    request_id: Option<String>,
    timeout_ms: u64,
    record: Option<PathBuf>,
    json: bool,
}

#[derive(Debug)]
struct ReplayOptions {
    package: PathBuf,
    record: PathBuf,
    json: bool,
}

/// Runs the runtime CLI against process standard streams.
pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_with_io(
        args,
        &mut stdin.lock(),
        &mut stdout.lock(),
        &mut stderr.lock(),
    )
}

/// Runs the runtime CLI with injectable streams for tests and embedding.
pub fn run_with_io<I, S, R, O, E>(args: I, input: &mut R, output: &mut O, error: &mut E) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    R: Read,
    O: Write,
    E: Write,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let command = args
        .get(1)
        .and_then(|value| value.to_str())
        .unwrap_or("--help");
    match command {
        "--help" | "-h" | "help" => write_text(output, HELP),
        "run" => match parse_run(&args[2..]) {
            Ok(options) => execute_run(options, input, output, error),
            Err(message) => usage_error(error, &message),
        },
        "replay" => match parse_replay(&args[2..]) {
            Ok(options) => execute_replay(options, output, error),
            Err(message) => usage_error(error, &message),
        },
        other => usage_error(error, &format!("unknown command '{other}'")),
    }
}

fn parse_run(args: &[OsString]) -> Result<RunOptions, String> {
    let values = unicode_args(args)?;
    let mut package = None;
    let mut request = None;
    let mut skill = None;
    let mut request_id = None;
    let mut timeout_ms = 5_000_u64;
    let mut record = None;
    let mut json = false;
    let mut index = 0;
    while index < values.len() {
        let value = &values[index];
        match value.as_str() {
            "--json" => json = true,
            "--package" => package = Some(next_path(&values, &mut index, "--package")?),
            "--request" => request = Some(next_path(&values, &mut index, "--request")?),
            "--skill" => skill = Some(next_value(&values, &mut index, "--skill")?),
            "--request-id" => request_id = Some(next_value(&values, &mut index, "--request-id")?),
            "--record" => record = Some(next_path(&values, &mut index, "--record")?),
            "--timeout-ms" => {
                let raw = next_value(&values, &mut index, "--timeout-ms")?;
                timeout_ms = raw
                    .parse::<u64>()
                    .map_err(|_| "--timeout-ms must be an integer".to_owned())?;
                if !(1..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
                    return Err(format!("--timeout-ms must be 1..={MAX_TIMEOUT_MS}"));
                }
            }
            option if option.starts_with('-') => {
                return Err(format!("unknown option '{option}'"));
            }
            extra => return Err(format!("unexpected argument '{extra}'")),
        }
        index += 1;
    }
    Ok(RunOptions {
        package: package.ok_or_else(|| "run requires --package".to_owned())?,
        request: request.ok_or_else(|| "run requires --request".to_owned())?,
        skill,
        request_id,
        timeout_ms,
        record,
        json,
    })
}

fn parse_replay(args: &[OsString]) -> Result<ReplayOptions, String> {
    let values = unicode_args(args)?;
    let mut package = None;
    let mut record = None;
    let mut json = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--json" => json = true,
            "--package" => package = Some(next_path(&values, &mut index, "--package")?),
            "--record" => record = Some(next_path(&values, &mut index, "--record")?),
            option if option.starts_with('-') => {
                return Err(format!("unknown option '{option}'"));
            }
            extra => return Err(format!("unexpected argument '{extra}'")),
        }
        index += 1;
    }
    Ok(ReplayOptions {
        package: package.ok_or_else(|| "replay requires --package".to_owned())?,
        record: record.ok_or_else(|| "replay requires --record".to_owned())?,
        json,
    })
}

fn execute_run<R: Read, O: Write, E: Write>(
    options: RunOptions,
    input: &mut R,
    output: &mut O,
    error: &mut E,
) -> i32 {
    let request = match read_json(&options.request, input) {
        Ok(value) => value,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    let runtime = match ReferenceRuntime::load(&options.package) {
        Ok(runtime) => runtime,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    let skill = match options.skill {
        Some(skill) => skill,
        None => {
            let skills = runtime.package().skill_ids().collect::<Vec<_>>();
            if skills.len() != 1 {
                return usage_error(error, "--skill is required for multi-skill packages");
            }
            skills[0].to_owned()
        }
    };
    let request_id = options
        .request_id
        .unwrap_or_else(|| default_request_id(&request));
    let envelope = match runtime.run(
        &skill,
        request_id,
        request.clone(),
        Duration::from_millis(options.timeout_ms),
    ) {
        Ok(envelope) => envelope,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    if let Some(path) = options.record {
        let record = ReplayRecord {
            request,
            envelope: envelope.clone(),
        };
        if let Err(runtime_error) = write_json_file(&path, &record) {
            return render_error(error, &runtime_error);
        }
    }
    write_json(output, &envelope, options.json)
}

fn execute_replay<O: Write, E: Write>(
    options: ReplayOptions,
    output: &mut O,
    error: &mut E,
) -> i32 {
    let bytes = match read_bounded_file(&options.record) {
        Ok(bytes) => bytes,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    let record: ReplayRecord = match serde_json::from_slice(&bytes) {
        Ok(record) => record,
        Err(parse_error) => {
            return render_error(
                error,
                &RuntimeError::InvalidRequest(format!("invalid replay record: {parse_error}")),
            )
        }
    };
    let runtime = match ReferenceRuntime::load(&options.package) {
        Ok(runtime) => runtime,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    let report = match runtime.replay(&record) {
        Ok(report) => report,
        Err(runtime_error) => return render_error(error, &runtime_error),
    };
    let code = if report.matched {
        EXIT_SUCCESS
    } else {
        EXIT_REPLAY_MISMATCH
    };
    if write_json_value(output, &json!(report), options.json).is_err() {
        EXIT_IO
    } else {
        code
    }
}

fn read_json<R: Read>(path: &Path, input: &mut R) -> Result<Value, RuntimeError> {
    let bytes = if path == Path::new("-") {
        let mut bytes = Vec::new();
        input
            .take(MAX_REQUEST_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| RuntimeError::Io {
                path: "<stdin>".to_owned(),
                message: error.to_string(),
            })?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
            return Err(RuntimeError::InvalidRequest(
                "request exceeds 1 MiB".to_owned(),
            ));
        }
        bytes
    } else {
        read_bounded_file(path)?
    };
    serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::InvalidRequest(format!("invalid request JSON: {error}")))
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, RuntimeError> {
    let file = fs::File::open(path).map_err(|error| RuntimeError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_REQUEST_BYTES {
        return Err(RuntimeError::InvalidRequest(format!(
            "'{}' exceeds 1 MiB",
            path.display()
        )));
    }
    Ok(bytes)
}

fn write_json_file(path: &Path, value: &impl serde::Serialize) -> Result<(), RuntimeError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RuntimeError::InvalidRequest(error.to_string()))?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|error| RuntimeError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn default_request_id(request: &Value) -> String {
    let bytes = serde_json::to_vec(request).unwrap_or_default();
    let digest = format!("{:x}", Sha256::digest(bytes));
    format!("req-{}", &digest[..16])
}

fn next_value(values: &[String], index: &mut usize, option: &str) -> Result<String, String> {
    *index += 1;
    values
        .get(*index)
        .cloned()
        .ok_or_else(|| format!("{option} requires a value"))
}

fn next_path(values: &[String], index: &mut usize, option: &str) -> Result<PathBuf, String> {
    next_value(values, index, option).map(PathBuf::from)
}

fn unicode_args(args: &[OsString]) -> Result<Vec<String>, String> {
    args.iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| "arguments must be valid Unicode".to_owned())
        })
        .collect()
}

fn write_json(output: &mut impl Write, value: &impl serde::Serialize, compact: bool) -> i32 {
    let serialized = if compact {
        serde_json::to_vec(value)
    } else {
        serde_json::to_vec_pretty(value)
    };
    match serialized {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            if output.write_all(&bytes).is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_IO
            }
        }
        Err(_) => EXIT_IO,
    }
}

fn write_json_value(output: &mut impl Write, value: &Value, compact: bool) -> io::Result<()> {
    let mut bytes = if compact {
        serde_json::to_vec(value)
    } else {
        serde_json::to_vec_pretty(value)
    }
    .map_err(io::Error::other)?;
    bytes.push(b'\n');
    output.write_all(&bytes)
}

fn write_text(output: &mut impl Write, value: &str) -> i32 {
    if output.write_all(value.as_bytes()).is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_IO
    }
}

fn usage_error(error: &mut impl Write, message: &str) -> i32 {
    let _ = writeln!(error, "error: {message}\n\n{HELP}");
    EXIT_USAGE
}

fn render_error(error: &mut impl Write, runtime_error: &RuntimeError) -> i32 {
    let _ = writeln!(error, "error: {runtime_error}");
    match runtime_error {
        RuntimeError::Package(_) | RuntimeError::IncompatibleTarget(_) => EXIT_PACKAGE,
        RuntimeError::Io { .. } => EXIT_IO,
        RuntimeError::ReplayMismatch(_) => EXIT_REPLAY_MISMATCH,
        _ => EXIT_RUNTIME,
    }
}
