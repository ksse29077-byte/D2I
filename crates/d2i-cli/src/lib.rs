//! Command-line presentation for D2I source validation and package tooling.

use d2i_compiler::{
    build_ir, compile_package, diff_packages, load_verified_package, verify_package, PackageError,
};
use d2i_core::{validate_source_pack, write_source_lock, Diagnostic, Severity, ValidationReport};
use d2i_eval::{benchmark_runtime, BenchmarkMetadata, RuntimeBenchmarkReport};
use d2i_module_sdk::load_module_manifest;
use d2i_runtime_adapter::{
    check_package_compatibility, phase5_abi_mapping, run_conformance, AdapterContract,
    ConformanceOptions, MockRuntimeAdapter,
};
use d2i_runtime_ref::ReferenceRuntime;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Successful command.
pub const EXIT_SUCCESS: i32 = 0;
/// Invalid command-line usage.
pub const EXIT_USAGE: i32 = 2;
/// Source-pack validation or lowering failed.
pub const EXIT_VALIDATION: i32 = 3;
/// CLI output, lock, or package I/O failed.
pub const EXIT_IO: i32 = 4;
/// Package integrity, format, or version verification failed.
pub const EXIT_PACKAGE: i32 = 5;
/// Evaluation or benchmark threshold regression.
pub const EXIT_EVALUATION: i32 = 6;
/// Cognitive module validation or conformance failure.
pub const EXIT_MODULE: i32 = 7;

const HELP: &str = "\
d2ic - Domain-to-Intelligence Compiler

Usage:
  d2ic validate [--json] [--write-lock] [SOURCE_PACK]
  d2ic inspect [--json] [SOURCE_PACK]
  d2ic compile [--json] SOURCE_PACK --out PACKAGE_DIR
  d2ic eval [--json] SOURCE_PACK
  d2ic benchmark [--json] [--iterations N] PACKAGE_DIR
  d2ic explain [--json] PACKAGE_DIR
  d2ic adapter-check [--json] PACKAGE_DIR
  d2ic adapter-conformance [--json] [--iterations N] PACKAGE_DIR
  d2ic adapter-abi [--json]
  d2ic module validate [--json] MODULE_DIR
  d2ic module conformance [--json] MODULE_DIR
  d2ic verify [--json] PACKAGE_DIR
  d2ic diff [--json] OLD_PACKAGE NEW_PACKAGE
  d2ic version
  d2ic --help

Commands:
  validate    Validate a source pack; optionally write sources.lock.
  inspect     Validate and print the deterministic source inventory.
  compile     Lower typed IR and write a deterministic D2I package.
  eval        Evaluate executor candidates and graph optimization at compile time.
  benchmark   Measure bundled evaluation cases with the offline reference runtime.
  explain     Print retained executor selection and optimization rationale.
  adapter-check
              Check package compatibility with the Phase 5 mock contract.
  adapter-conformance
              Compare reference and mock adapter vectors, errors, and timings.
  adapter-abi Print the safe-Rust mapping and unresolved proprietary contracts.
  module validate
              Validate Module Manifest v1, schemas, paths, and artifact hashes.
  module conformance
              Run deterministic fixtures for a built-in Rust reference module.
  verify      Verify package paths, versions, FlatBuffers, and hashes.
  diff        Compare two verified packages by artifact hash.
  version     Print the compiler version.

Options:
  --json          Emit one machine-readable JSON object.
  --write-lock    Write sources.lock after successful source validation.
  --out DIR       Required output directory for compile.
  --iterations N  Measured benchmark iterations (default: 3, maximum: 1000).

Exit codes:
  0  success
  2  invalid command-line usage
  3  source validation or IR lowering failed
  4  output, lock, or package I/O failed
  5  package integrity, format, or version failure
  6  evaluation or benchmark threshold regression
  7  cognitive module validation or conformance failure
";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceCommand {
    Validate,
    Inspect,
}

#[derive(Debug)]
struct SourceOptions {
    command: SourceCommand,
    root: PathBuf,
    json: bool,
    write_lock: bool,
}

#[derive(Debug)]
struct CompileOptions {
    source: PathBuf,
    output: PathBuf,
    json: bool,
}

#[derive(Debug)]
struct VerifyOptions {
    package: PathBuf,
    json: bool,
}

#[derive(Debug)]
struct DiffOptions {
    old: PathBuf,
    new: PathBuf,
    json: bool,
}

#[derive(Debug)]
struct EvalOptions {
    source: PathBuf,
    json: bool,
}

#[derive(Debug)]
struct BenchmarkOptions {
    package: PathBuf,
    json: bool,
    iterations: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleCommand {
    Validate,
    Conformance,
}

#[derive(Debug)]
struct ModuleOptions {
    command: ModuleCommand,
    root: PathBuf,
    json: bool,
}

/// Runs the CLI against the process standard streams.
#[must_use]
pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_with_io(args, &mut stdout.lock(), &mut stderr.lock())
}

/// Runs the CLI with injectable streams for deterministic tests and embedding.
#[must_use]
pub fn run_with_io<I, S, O, E>(args: I, out: &mut O, err: &mut E) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
    O: Write,
    E: Write,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let command = args
        .get(1)
        .and_then(|argument| argument.to_str())
        .unwrap_or("--help");

    match command {
        "--help" | "-h" | "help" => write_text(out, HELP),
        "version" | "--version" | "-V" => {
            write_text(out, &format!("d2ic {}\n", env!("CARGO_PKG_VERSION")))
        }
        "validate" | "inspect" => {
            let command = if command == "validate" {
                SourceCommand::Validate
            } else {
                SourceCommand::Inspect
            };
            match parse_source_options(command, &args[2..]) {
                Ok(options) => execute_source(options, out, err),
                Err(message) => usage_error(err, &message),
            }
        }
        "compile" => match parse_compile_options(&args[2..]) {
            Ok(options) => execute_compile(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "eval" => match parse_eval_options(&args[2..]) {
            Ok(options) => execute_eval(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "benchmark" => match parse_benchmark_options(&args[2..]) {
            Ok(options) => execute_benchmark(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "explain" => match parse_verify_options(&args[2..]) {
            Ok(options) => execute_explain(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "adapter-check" => match parse_verify_options(&args[2..]) {
            Ok(options) => execute_adapter_check(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "adapter-conformance" => {
            match parse_iterations_options(&args[2..], "adapter-conformance") {
                Ok(options) => execute_adapter_conformance(options, out, err),
                Err(message) => usage_error(err, &message),
            }
        }
        "adapter-abi" => match parse_flag_only_json(&args[2..], "adapter-abi") {
            Ok(json) => execute_adapter_abi(json, out),
            Err(message) => usage_error(err, &message),
        },
        "module" => match parse_module_options(&args[2..]) {
            Ok(options) => execute_module(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "verify" => match parse_verify_options(&args[2..]) {
            Ok(options) => execute_verify(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        "diff" => match parse_diff_options(&args[2..]) {
            Ok(options) => execute_diff(options, out, err),
            Err(message) => usage_error(err, &message),
        },
        other => usage_error(err, &format!("unknown command '{other}'")),
    }
}

fn parse_module_options(args: &[OsString]) -> Result<ModuleOptions, String> {
    let values = unicode_args(args)?;
    let Some(command) = values.first() else {
        return Err("module requires 'validate' or 'conformance'".to_owned());
    };
    let command = match command.as_str() {
        "validate" => ModuleCommand::Validate,
        "conformance" => ModuleCommand::Conformance,
        other => return Err(format!("unknown module command '{other}'")),
    };
    let (json, paths) = split_json_and_paths(values.into_iter().skip(1).collect())?;
    if paths.len() != 1 {
        return Err(format!(
            "module {} requires exactly one MODULE_DIR",
            match command {
                ModuleCommand::Validate => "validate",
                ModuleCommand::Conformance => "conformance",
            }
        ));
    }
    Ok(ModuleOptions {
        command,
        root: PathBuf::from(&paths[0]),
        json,
    })
}

fn parse_source_options(
    command: SourceCommand,
    args: &[OsString],
) -> Result<SourceOptions, String> {
    let values = unicode_args(args)?;
    let mut root = None;
    let mut json = false;
    let mut write_lock = false;
    for value in values {
        match value.as_str() {
            "--json" => json = true,
            "--write-lock" if command == SourceCommand::Validate => write_lock = true,
            "--write-lock" => {
                return Err("--write-lock is only valid with 'validate'".to_owned());
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option '{value}'"));
            }
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected extra source-pack path '{value}'")),
        }
    }
    Ok(SourceOptions {
        command,
        root: root.unwrap_or_else(|| PathBuf::from(".")),
        json,
        write_lock,
    })
}

fn parse_compile_options(args: &[OsString]) -> Result<CompileOptions, String> {
    let values = unicode_args(args)?;
    let mut source = None;
    let mut output = None;
    let mut json = false;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--json" => json = true,
            "--out" => {
                index += 1;
                let Some(value) = values.get(index) else {
                    return Err("--out requires a directory".to_owned());
                };
                if output.replace(PathBuf::from(value)).is_some() {
                    return Err("--out may be specified only once".to_owned());
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option '{value}'"));
            }
            value if source.is_none() => source = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected extra source-pack path '{value}'")),
        }
        index += 1;
    }
    Ok(CompileOptions {
        source: source.ok_or_else(|| "compile requires SOURCE_PACK".to_owned())?,
        output: output.ok_or_else(|| "compile requires --out PACKAGE_DIR".to_owned())?,
        json,
    })
}

fn parse_verify_options(args: &[OsString]) -> Result<VerifyOptions, String> {
    let values = unicode_args(args)?;
    let (json, paths) = split_json_and_paths(values)?;
    if paths.len() != 1 {
        return Err("verify requires exactly one PACKAGE_DIR".to_owned());
    }
    Ok(VerifyOptions {
        package: PathBuf::from(&paths[0]),
        json,
    })
}

fn parse_diff_options(args: &[OsString]) -> Result<DiffOptions, String> {
    let values = unicode_args(args)?;
    let (json, paths) = split_json_and_paths(values)?;
    if paths.len() != 2 {
        return Err("diff requires OLD_PACKAGE and NEW_PACKAGE".to_owned());
    }
    Ok(DiffOptions {
        old: PathBuf::from(&paths[0]),
        new: PathBuf::from(&paths[1]),
        json,
    })
}

fn parse_eval_options(args: &[OsString]) -> Result<EvalOptions, String> {
    let values = unicode_args(args)?;
    let (json, paths) = split_json_and_paths(values)?;
    if paths.len() != 1 {
        return Err("eval requires exactly one SOURCE_PACK".to_owned());
    }
    Ok(EvalOptions {
        source: PathBuf::from(&paths[0]),
        json,
    })
}

fn parse_benchmark_options(args: &[OsString]) -> Result<BenchmarkOptions, String> {
    parse_iterations_options(args, "benchmark")
}

fn parse_iterations_options(args: &[OsString], command: &str) -> Result<BenchmarkOptions, String> {
    let values = unicode_args(args)?;
    let mut package = None;
    let mut json = false;
    let mut iterations = 3_u32;
    let mut index = 0;
    while index < values.len() {
        match values[index].as_str() {
            "--json" => json = true,
            "--iterations" => {
                index += 1;
                let Some(value) = values.get(index) else {
                    return Err("--iterations requires an integer".to_owned());
                };
                iterations = value
                    .parse()
                    .map_err(|_| "--iterations must be an integer".to_owned())?;
                if !(1..=1_000).contains(&iterations) {
                    return Err("--iterations must be between 1 and 1000".to_owned());
                }
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option '{value}'"));
            }
            value if package.is_none() => package = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected extra package path '{value}'")),
        }
        index += 1;
    }
    Ok(BenchmarkOptions {
        package: package.ok_or_else(|| format!("{command} requires PACKAGE_DIR"))?,
        json,
        iterations,
    })
}

fn parse_flag_only_json(args: &[OsString], command: &str) -> Result<bool, String> {
    let values = unicode_args(args)?;
    let mut json = false;
    for value in values {
        if value == "--json" {
            json = true;
        } else {
            return Err(format!("{command} accepts only --json"));
        }
    }
    Ok(json)
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

fn split_json_and_paths(values: Vec<String>) -> Result<(bool, Vec<String>), String> {
    let mut json = false;
    let mut paths = Vec::new();
    for value in values {
        if value == "--json" {
            json = true;
        } else if value.starts_with('-') {
            return Err(format!("unknown option '{value}'"));
        } else {
            paths.push(value);
        }
    }
    Ok((json, paths))
}

fn execute_source<O: Write, E: Write>(options: SourceOptions, out: &mut O, err: &mut E) -> i32 {
    let report = validate_source_pack(&options.root);
    let valid = !report.has_errors();
    let lock_path = if valid && options.write_lock {
        match report.inventory.as_ref().map(write_source_lock) {
            Some(Ok(path)) => Some(path),
            Some(Err(error)) => {
                return write_command_error(
                    options.json,
                    out,
                    err,
                    "D2I9000",
                    &format!("cannot write sources.lock: {error}"),
                    EXIT_IO,
                );
            }
            None => {
                return write_command_error(
                    options.json,
                    out,
                    err,
                    "D2I9000",
                    "cannot write sources.lock without a source inventory",
                    EXIT_IO,
                );
            }
        }
    } else {
        None
    };

    let output_result = if options.json {
        write_source_json(
            out,
            options.command,
            &options.root,
            &report,
            lock_path.as_deref(),
        )
    } else {
        write_source_human(
            out,
            err,
            options.command,
            &options.root,
            &report,
            lock_path.as_deref(),
        )
    };
    if output_result.is_err() {
        EXIT_IO
    } else if valid {
        EXIT_SUCCESS
    } else {
        EXIT_VALIDATION
    }
}

fn execute_compile<O: Write, E: Write>(options: CompileOptions, out: &mut O, err: &mut E) -> i32 {
    let report = compile_package(&options.source, &options.output);
    if options.json {
        let value = json!({
            "command": "compile",
            "success": !report.has_errors(),
            "build": report.build,
            "diagnostics": report.diagnostics.iter().map(diagnostic_json).collect::<Vec<_>>(),
            "error": report.package_error.as_ref().map(package_error_json),
        });
        if write_json(out, &value).is_err() {
            return EXIT_IO;
        }
    } else {
        for diagnostic in &report.diagnostics {
            let _ = writeln!(err, "{diagnostic}");
        }
        if let Some(error) = &report.package_error {
            let _ = writeln!(err, "error[D2I9001]: {error}");
        }
        if let Some(build) = &report.build {
            if writeln!(out, "build id: {}", build.build_id).is_err()
                || writeln!(out, "package: {}", build.package_path).is_err()
                || writeln!(out, "content hash: {}", build.package_content_hash).is_err()
                || writeln!(out, "artifacts: {}", build.artifact_count).is_err()
            {
                return EXIT_IO;
            }
        }
    }
    if let Some(error) = &report.package_error {
        package_exit(error)
    } else if report.has_errors() {
        EXIT_VALIDATION
    } else {
        EXIT_SUCCESS
    }
}

fn execute_eval<O: Write, E: Write>(options: EvalOptions, out: &mut O, err: &mut E) -> i32 {
    let report = build_ir(&options.source);
    let success = !report.has_errors();
    if options.json {
        let value = json!({
            "command": "eval",
            "success": success,
            "source_pack": options.source.display().to_string(),
            "phase4": report.phase4,
            "diagnostics": report.diagnostics.iter().map(diagnostic_json).collect::<Vec<_>>(),
        });
        if write_json(out, &value).is_err() {
            return EXIT_IO;
        }
    } else {
        for diagnostic in &report.diagnostics {
            let _ = writeln!(err, "{diagnostic}");
        }
        if let Some(phase4) = &report.phase4 {
            if writeln!(out, "executor descriptors: {}", phase4.descriptors.len()).is_err() {
                return EXIT_IO;
            }
            for (binding, selection) in &phase4.selections {
                let selected = selection
                    .selected
                    .as_deref()
                    .or(selection.fallback.as_deref())
                    .unwrap_or("<none>");
                if writeln!(out, "{binding}: {selected}").is_err()
                    || writeln!(out, "  {}", selection.explanation).is_err()
                {
                    return EXIT_IO;
                }
            }
            let actions = phase4
                .optimizations
                .iter()
                .map(|report| report.actions.len())
                .sum::<usize>();
            if writeln!(out, "optimization actions: {actions}").is_err() {
                return EXIT_IO;
            }
        }
    }
    if success {
        EXIT_SUCCESS
    } else {
        EXIT_VALIDATION
    }
}

fn execute_explain<O: Write, E: Write>(options: VerifyOptions, out: &mut O, err: &mut E) -> i32 {
    let verified = match load_verified_package(&options.package) {
        Ok(verified) => verified,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I9001",
                &error.to_string(),
                package_exit(&error),
            );
        }
    };
    let selection = match verified
        .artifact("reports/selection.json")
        .ok_or_else(|| "selection report is missing".to_owned())
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).map_err(|error| error.to_string()))
    {
        Ok(selection) => selection,
        Err(message) => {
            return write_command_error(options.json, out, err, "D2I9001", &message, EXIT_PACKAGE);
        }
    };
    let optimization = match verified
        .artifact("reports/optimization.json")
        .ok_or_else(|| "optimization report is missing".to_owned())
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).map_err(|error| error.to_string()))
    {
        Ok(optimization) => optimization,
        Err(message) => {
            return write_command_error(options.json, out, err, "D2I9001", &message, EXIT_PACKAGE);
        }
    };
    let result = if options.json {
        write_json(
            out,
            &json!({
                "command": "explain",
                "build_id": verified.summary.build_id,
                "selection": selection,
                "optimization": optimization,
            }),
        )
    } else {
        writeln!(out, "build id: {}", verified.summary.build_id)
            .and_then(|()| write_selection_human(out, &selection))
            .and_then(|()| {
                let count = optimization.as_array().map_or(0, |reports| {
                    reports
                        .iter()
                        .map(|report| report["actions"].as_array().map_or(0, Vec::len))
                        .sum::<usize>()
                });
                writeln!(out, "optimization actions: {count}")
            })
    };
    if result.is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_IO
    }
}

fn write_selection_human<O: Write>(out: &mut O, selection: &Value) -> io::Result<()> {
    let Some(bindings) = selection.as_object() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selection report must be an object",
        ));
    };
    for (binding, report) in bindings {
        let selected = report["selected"]
            .as_str()
            .or_else(|| report["fallback"].as_str())
            .unwrap_or("<none>");
        writeln!(out, "{binding}: {selected}")?;
        if let Some(explanation) = report["explanation"].as_str() {
            writeln!(out, "  {explanation}")?;
        }
    }
    Ok(())
}

fn execute_benchmark<O: Write, E: Write>(
    options: BenchmarkOptions,
    out: &mut O,
    err: &mut E,
) -> i32 {
    let runtime = match ReferenceRuntime::load(&options.package) {
        Ok(runtime) => runtime,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I9001",
                &error.to_string(),
                EXIT_PACKAGE,
            );
        }
    };
    let cases = match runtime.package().benchmark_cases() {
        Ok(cases) => cases,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I2400",
                &error.to_string(),
                EXIT_EVALUATION,
            );
        }
    };
    let summary = runtime.package().summary();
    let (dataset_id, dataset_hash) = runtime
        .package()
        .evaluation_dataset_identity()
        .unwrap_or(("<unknown>", "<unknown>"));
    let benchmark = benchmark_runtime(
        BenchmarkMetadata {
            benchmark_id: &format!("{}-reference-runtime", summary.build_id),
            build_id: &summary.build_id,
            dataset_id,
            dataset_hash,
            compiler_version: &summary.compiler_version,
        },
        &cases,
        options.iterations,
        |case| {
            runtime.run(
                &case.skill_id,
                format!("benchmark:{}", case.id),
                case.request.clone(),
                Duration::from_secs(30),
            )
        },
    );
    let report = match benchmark {
        Ok(report) => report,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I2400",
                &error.to_string(),
                EXIT_EVALUATION,
            );
        }
    };
    let regressions = benchmark_regressions(runtime.package(), &report);
    let result = if options.json {
        write_json(
            out,
            &json!({
                "command": "benchmark",
                "success": regressions.is_empty(),
                "report": report,
                "regressions": regressions,
            }),
        )
    } else {
        writeln!(out, "benchmark: {}", report.benchmark_id)
            .and_then(|()| writeln!(out, "cases: {}", report.case_count))
            .and_then(|()| writeln!(out, "task success: {:.4}", report.task_success_rate))
            .and_then(|()| writeln!(out, "field accuracy: {:.4}", report.field_accuracy))
            .and_then(|()| writeln!(out, "critical error: {:.6}", report.critical_error_rate))
            .and_then(|()| {
                writeln!(
                    out,
                    "p50/p95/p99 us: {}/{}/{}",
                    report.p50_latency_us, report.p95_latency_us, report.p99_latency_us
                )
            })
            .and_then(|()| writeln!(out, "repeatability: {:.4}", report.repeatability_rate))
            .and_then(|()| writeln!(out, "peak RSS: unavailable"))
            .and_then(|()| writeln!(out, "allocated bytes: unavailable"))
            .and_then(|()| {
                for regression in &regressions {
                    writeln!(err, "error[D2I2401]: {regression}")?;
                }
                Ok(())
            })
    };
    if result.is_err() {
        EXIT_IO
    } else if regressions.is_empty() {
        EXIT_SUCCESS
    } else {
        EXIT_EVALUATION
    }
}

fn benchmark_regressions(
    package: &d2i_runtime_ref::RuntimePackage,
    report: &RuntimeBenchmarkReport,
) -> Vec<String> {
    [
        ("task_success_rate", report.task_success_rate),
        ("field_accuracy", report.field_accuracy),
        ("critical_error_rate", report.critical_error_rate),
        ("deterministic_replay_rate", report.repeatability_rate),
    ]
    .into_iter()
    .filter_map(|(metric, measured)| {
        package
            .evaluation_threshold(metric)
            .and_then(|(threshold, higher_is_better)| {
                let failed = if higher_is_better {
                    measured < threshold
                } else {
                    measured > threshold
                };
                failed.then(|| {
                    format!("{metric} measured {measured:.6} failed threshold {threshold:.6}")
                })
            })
    })
    .collect()
}

fn execute_adapter_check<O: Write, E: Write>(
    options: VerifyOptions,
    out: &mut O,
    err: &mut E,
) -> i32 {
    let contract = AdapterContract::mock();
    let report = match check_package_compatibility(&options.package, &contract) {
        Ok(report) => report,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I5000",
                &error.to_string(),
                EXIT_PACKAGE,
            );
        }
    };
    let result = if options.json {
        write_json(
            out,
            &json!({
                "command": "adapter-check",
                "contract": contract,
                "report": report,
            }),
        )
    } else {
        writeln!(out, "adapter: {}", report.adapter_id)
            .and_then(|()| writeln!(out, "build id: {}", report.build_id))
            .and_then(|()| writeln!(out, "compatible: {}", report.compatible))
            .and_then(|()| {
                for issue in &report.issues {
                    writeln!(err, "error[{}]: {}", issue.code, issue.message)?;
                }
                Ok(())
            })
    };
    if result.is_err() {
        EXIT_IO
    } else if report.compatible {
        EXIT_SUCCESS
    } else {
        EXIT_PACKAGE
    }
}

fn execute_adapter_conformance<O: Write, E: Write>(
    options: BenchmarkOptions,
    out: &mut O,
    err: &mut E,
) -> i32 {
    let mut adapter = MockRuntimeAdapter::new();
    let report = match run_conformance(
        &options.package,
        &mut adapter,
        ConformanceOptions {
            iterations: options.iterations,
            timeout: Duration::from_secs(30),
        },
    ) {
        Ok(report) => report,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2I5100",
                &error.to_string(),
                EXIT_EVALUATION,
            );
        }
    };
    let result = if options.json {
        write_json(
            out,
            &json!({
                "command": "adapter-conformance",
                "report": report,
            }),
        )
    } else {
        writeln!(out, "adapter: {}", report.adapter_id)
            .and_then(|()| writeln!(out, "vectors: {}", report.vectors.len()))
            .and_then(|()| writeln!(out, "output schema match: {}", report.output_schema_match))
            .and_then(|()| writeln!(out, "error mapping match: {}", report.error_mapping_match))
            .and_then(|()| {
                writeln!(
                    out,
                    "reference p95 us: {}",
                    report.reference_performance.p95_latency_us
                )
            })
            .and_then(|()| {
                writeln!(
                    out,
                    "adapter p95 us: {}",
                    report.adapter_performance.p95_latency_us
                )
            })
    };
    if result.is_err() {
        EXIT_IO
    } else if report.success {
        EXIT_SUCCESS
    } else {
        EXIT_EVALUATION
    }
}

fn execute_adapter_abi<O: Write>(json_output: bool, out: &mut O) -> i32 {
    let mapping = phase5_abi_mapping();
    let result = if json_output {
        write_json(
            out,
            &json!({
                "command": "adapter-abi",
                "mapping": mapping,
            }),
        )
    } else {
        writeln!(
            out,
            "adapter contract: {}",
            mapping.adapter_contract_version
        )
        .and_then(|()| {
            writeln!(
                out,
                "package runtime ABI: {}",
                mapping.package_runtime_abi_version
            )
        })
        .and_then(|()| {
            writeln!(
                out,
                "unresolved proprietary contracts: {}",
                mapping.unresolved_external_contracts.len()
            )
        })
    };
    if result.is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_IO
    }
}

fn execute_module<O: Write, E: Write>(options: ModuleOptions, out: &mut O, err: &mut E) -> i32 {
    let loaded = match load_module_manifest(&options.root) {
        Ok(loaded) => loaded,
        Err(error) => {
            return write_command_error(
                options.json,
                out,
                err,
                "D2IM9000",
                &error.to_string(),
                EXIT_MODULE,
            )
        }
    };
    match options.command {
        ModuleCommand::Validate => {
            let value = json!({
                "command": "module validate",
                "status": "pass",
                "module": loaded.identifier,
                "manifest_sha256": loaded.manifest_sha256,
                "manifest_path": loaded.manifest_path,
                "execution_mode": loaded.manifest.execution.mode,
                "network_requirement": loaded.manifest.execution.network_requirement,
                "side_effect": loaded.manifest.execution.side_effect
            });
            let written = if options.json {
                write_json(out, &value)
            } else {
                writeln!(
                    out,
                    "module validation: pass\nmodule: {} {}\nmanifest: {}\nnetwork: denied\nside effect: false",
                    value["module"]["module_id"].as_str().unwrap_or("<unknown>"),
                    value["module"]["module_version"]
                        .as_str()
                        .unwrap_or("<unknown>"),
                    value["manifest_sha256"].as_str().unwrap_or("<unknown>")
                )
            };
            if written.is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_IO
            }
        }
        ModuleCommand::Conformance => {
            let script = "scripts/modules/check-module.ps1";
            let written = if options.json {
                write_json(
                    out,
                    &json!({
                        "command": "module conformance",
                        "status": "unsupported",
                        "module": loaded.identifier,
                        "reason": "Core CLI does not link standalone module implementations",
                        "module_local_command": script
                    }),
                )
            } else {
                writeln!(
                    out,
                    "module conformance: unsupported\nreason: Core CLI does not link standalone modules\nrun: {script} -ModulePath {}",
                    options.root.display()
                )
            };
            if written.is_err() {
                EXIT_IO
            } else {
                EXIT_MODULE
            }
        }
    }
}

fn execute_verify<O: Write, E: Write>(options: VerifyOptions, out: &mut O, err: &mut E) -> i32 {
    match verify_package(&options.package) {
        Ok(summary) => {
            let result = if options.json {
                write_json(
                    out,
                    &json!({
                        "command": "verify",
                        "valid": true,
                        "package": summary,
                    }),
                )
            } else {
                writeln!(out, "package: {}", summary.package_path)
                    .and_then(|()| writeln!(out, "build id: {}", summary.build_id))
                    .and_then(|()| writeln!(out, "content hash: {}", summary.package_content_hash))
                    .and_then(|()| writeln!(out, "verification: ok"))
            };
            if result.is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_IO
            }
        }
        Err(error) => write_command_error(
            options.json,
            out,
            err,
            "D2I9001",
            &error.to_string(),
            package_exit(&error),
        ),
    }
}

fn execute_diff<O: Write, E: Write>(options: DiffOptions, out: &mut O, err: &mut E) -> i32 {
    match diff_packages(&options.old, &options.new) {
        Ok(diff) => {
            let result = if options.json {
                write_json(
                    out,
                    &json!({
                        "command": "diff",
                        "diff": diff,
                    }),
                )
            } else {
                writeln!(out, "identical: {}", diff.identical)
                    .and_then(|()| writeln!(out, "old: {}", diff.old_content_hash))
                    .and_then(|()| writeln!(out, "new: {}", diff.new_content_hash))
                    .and_then(|()| writeln!(out, "added: {}", diff.added.len()))
                    .and_then(|()| writeln!(out, "removed: {}", diff.removed.len()))
                    .and_then(|()| writeln!(out, "changed: {}", diff.changed.len()))
            };
            if result.is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_IO
            }
        }
        Err(error) => write_command_error(
            options.json,
            out,
            err,
            "D2I9001",
            &error.to_string(),
            package_exit(&error),
        ),
    }
}

fn write_source_human<O: Write, E: Write>(
    out: &mut O,
    err: &mut E,
    command: SourceCommand,
    root: &Path,
    report: &ValidationReport,
    lock_path: Option<&Path>,
) -> io::Result<()> {
    for diagnostic in &report.diagnostics {
        writeln!(err, "{diagnostic}")?;
    }
    if report.has_errors() {
        writeln!(
            err,
            "validation failed: {} error(s)",
            error_count(&report.diagnostics)
        )?;
        return Ok(());
    }
    let domain = report
        .manifest
        .as_ref()
        .map_or("<unknown>", |manifest| manifest.domain.id.as_str());
    let file_count = report
        .inventory
        .as_ref()
        .map_or(0, |inventory| inventory.entries().len());
    let inventory_hash = report.inventory.as_ref().map_or_else(
        || "<unavailable>".to_owned(),
        |inventory| inventory.inventory_hash().to_string(),
    );
    writeln!(out, "source pack: {}", root.display())?;
    writeln!(out, "domain: {domain}")?;
    writeln!(out, "files: {file_count}")?;
    writeln!(out, "inventory hash: {inventory_hash}")?;
    if command == SourceCommand::Inspect {
        if let Some(inventory) = &report.inventory {
            writeln!(out)?;
            for entry in inventory.entries() {
                writeln!(
                    out,
                    "{}\t{}\t{}",
                    entry.path(),
                    entry.size(),
                    entry.content_hash()
                )?;
            }
        }
    }
    if let Some(path) = lock_path {
        writeln!(out, "lock file: {}", path.display())?;
    }
    writeln!(out, "validation: ok")
}

fn write_source_json<O: Write>(
    out: &mut O,
    command: SourceCommand,
    root: &Path,
    report: &ValidationReport,
    lock_path: Option<&Path>,
) -> io::Result<()> {
    let command_name = match command {
        SourceCommand::Validate => "validate",
        SourceCommand::Inspect => "inspect",
    };
    let manifest = report.manifest.as_ref().map(|manifest| {
        json!({
            "d2i_version": manifest.d2i_version,
            "domain": {
                "id": manifest.domain.id,
                "version": manifest.domain.version,
                "name": manifest.domain.name,
                "languages": manifest.domain.languages,
            },
            "skills": manifest.skills.iter().map(|skill| {
                json!({
                    "id": skill.id,
                    "version": skill.version,
                    "criticality": skill.criticality,
                })
            }).collect::<Vec<_>>(),
        })
    });
    let inventory = report.inventory.as_ref().map(|inventory| {
        let files = if command == SourceCommand::Inspect {
            inventory
                .entries()
                .iter()
                .map(|entry| {
                    json!({
                        "path": entry.path(),
                        "size": entry.size(),
                        "content_hash": entry.content_hash(),
                    })
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        json!({
            "file_count": inventory.entries().len(),
            "inventory_hash": inventory.inventory_hash().to_string(),
            "files": files,
        })
    });
    write_json(
        out,
        &json!({
            "command": command_name,
            "source_pack": root.display().to_string(),
            "valid": !report.has_errors(),
            "manifest": manifest,
            "inventory": inventory,
            "diagnostics": report.diagnostics.iter().map(diagnostic_json).collect::<Vec<_>>(),
            "lock_file": lock_path.map(|path| path.display().to_string()),
        }),
    )
}

fn diagnostic_json(diagnostic: &Diagnostic) -> Value {
    let location = diagnostic.location().map(|location| {
        json!({
            "path": location.path(),
            "line": location.line(),
            "column": location.column(),
        })
    });
    json!({
        "severity": diagnostic.severity().to_string(),
        "code": diagnostic.code(),
        "message": diagnostic.message(),
        "location": location,
        "field": diagnostic.field(),
        "help": diagnostic.help(),
    })
}

fn package_error_json(error: &PackageError) -> Value {
    json!({
        "code": "D2I9001",
        "message": error.to_string(),
    })
}

fn write_command_error<O: Write, E: Write>(
    json_output: bool,
    out: &mut O,
    err: &mut E,
    code: &str,
    message: &str,
    exit: i32,
) -> i32 {
    let result = if json_output {
        write_json(
            out,
            &json!({
                "success": false,
                "error": {
                    "code": code,
                    "message": message,
                }
            }),
        )
    } else {
        writeln!(err, "error[{code}]: {message}")
    };
    if result.is_ok() {
        exit
    } else {
        EXIT_IO
    }
}

fn write_json<O: Write>(out: &mut O, value: &Value) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)
}

fn package_exit(error: &PackageError) -> i32 {
    if matches!(error, PackageError::Io { .. }) {
        EXIT_IO
    } else {
        EXIT_PACKAGE
    }
}

fn error_count(diagnostics: &[Diagnostic]) -> usize {
    diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity() == Severity::Error)
        .count()
}

fn usage_error<E: Write>(err: &mut E, message: &str) -> i32 {
    let _ = writeln!(err, "error: {message}");
    let _ = writeln!(err, "Run 'd2ic --help' for usage.");
    EXIT_USAGE
}

fn write_text<O: Write>(out: &mut O, text: &str) -> i32 {
    if out.write_all(text.as_bytes()).is_ok() {
        EXIT_SUCCESS
    } else {
        EXIT_IO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("d2i-cli-phase2-{}-{sequence}", std::process::id()));
            if let Err(error) = fs::create_dir_all(&path) {
                panic!("cannot create CLI test directory: {error}");
            }
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn example_pack() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/equipment-maintenance")
    }

    fn phase1_fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/phase1")
            .join(name)
    }

    fn parse_json(bytes: &[u8], label: &str) -> Value {
        match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(error) => panic!("{label} did not emit JSON: {error}"),
        }
    }

    #[test]
    fn help_and_version_succeed() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_with_io(["d2ic", "--help"], &mut out, &mut err),
            EXIT_SUCCESS
        );
        assert!(String::from_utf8_lossy(&out).contains("d2ic compile"));
        out.clear();
        assert_eq!(
            run_with_io(["d2ic", "version"], &mut out, &mut err),
            EXIT_SUCCESS
        );
        assert!(String::from_utf8_lossy(&out).contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn usage_and_validation_exit_codes_are_stable() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_with_io(["d2ic", "compile"], &mut out, &mut err),
            EXIT_USAGE
        );
        out.clear();
        err.clear();
        let root = phase1_fixture("malicious-traversal");
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("validate"),
                    root.into_os_string(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_VALIDATION
        );
    }

    #[test]
    fn validate_and_inspect_json_are_machine_readable() {
        for command in ["validate", "inspect"] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let exit = run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from(command),
                    example_pack().into_os_string(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            );
            assert_eq!(exit, EXIT_SUCCESS);
            let value: Value = match serde_json::from_slice(&out) {
                Ok(value) => value,
                Err(error) => panic!("{command} did not emit JSON: {error}"),
            };
            assert_eq!(value["valid"], true);
        }
    }

    #[test]
    fn compile_verify_and_diff_json_succeed() {
        let temporary = TempDirectory::new();
        let first = temporary.0.join("first.d2ip");
        let second = temporary.0.join("second.d2ip");
        for output in [&first, &second] {
            let mut out = Vec::new();
            let mut err = Vec::new();
            let exit = run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("compile"),
                    example_pack().into_os_string(),
                    OsString::from("--out"),
                    output.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            );
            assert_eq!(exit, EXIT_SUCCESS, "compile stderr: {err:?}");
            let value: Value = match serde_json::from_slice(&out) {
                Ok(value) => value,
                Err(error) => panic!("compile did not emit JSON: {error}"),
            };
            assert_eq!(value["success"], true);
        }

        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("verify"),
                    first.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        out.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("diff"),
                    first.into_os_string(),
                    second.into_os_string(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        let value: Value = match serde_json::from_slice(&out) {
            Ok(value) => value,
            Err(error) => panic!("diff did not emit JSON: {error}"),
        };
        assert_eq!(value["diff"]["identical"], true);
    }

    #[test]
    fn eval_explain_and_benchmark_json_succeed() {
        let temporary = TempDirectory::new();
        let package = temporary.0.join("phase4.d2ip");
        let mut out = Vec::new();
        let mut err = Vec::new();

        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("eval"),
                    example_pack().into_os_string(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        let evaluation = parse_json(&out, "eval");
        assert_eq!(
            evaluation["phase4"]["selections"]["diagnose_fault:case-retriever"]["selected"],
            "case-retriever-compact"
        );

        out.clear();
        err.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("compile"),
                    example_pack().into_os_string(),
                    OsString::from("--out"),
                    package.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );

        out.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("explain"),
                    package.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        let explanation = parse_json(&out, "explain");
        assert_eq!(
            explanation["selection"]["diagnose_fault:case-retriever"]["selected"],
            "case-retriever-compact"
        );

        out.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("benchmark"),
                    package.into_os_string(),
                    OsString::from("--iterations"),
                    OsString::from("1"),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS,
            "benchmark stderr: {}",
            String::from_utf8_lossy(&err)
        );
        let benchmark = parse_json(&out, "benchmark");
        assert_eq!(benchmark["success"], true);
        assert_eq!(benchmark["report"]["case_count"], 50);
        assert_eq!(benchmark["report"]["repeatability_rate"], 1.0);
    }

    #[test]
    fn adapter_commands_emit_compatible_conformance_reports() {
        let temporary = TempDirectory::new();
        let package = temporary.0.join("phase5.d2ip");
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("compile"),
                    example_pack().into_os_string(),
                    OsString::from("--out"),
                    package.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );

        out.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("adapter-check"),
                    package.as_os_str().to_owned(),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        let compatibility = parse_json(&out, "adapter-check");
        assert_eq!(compatibility["report"]["compatible"], true);

        out.clear();
        assert_eq!(
            run_with_io(
                [
                    OsString::from("d2ic"),
                    OsString::from("adapter-conformance"),
                    package.into_os_string(),
                    OsString::from("--iterations"),
                    OsString::from("1"),
                    OsString::from("--json"),
                ],
                &mut out,
                &mut err,
            ),
            EXIT_SUCCESS
        );
        let conformance = parse_json(&out, "adapter-conformance");
        assert_eq!(conformance["report"]["success"], true);
        assert_eq!(
            conformance["report"]["vectors"].as_array().map(Vec::len),
            Some(52)
        );
        assert_eq!(conformance["report"]["output_schema_match"], true);
        assert_eq!(conformance["report"]["error_mapping_match"], true);

        out.clear();
        assert_eq!(
            run_with_io(["d2ic", "adapter-abi", "--json"], &mut out, &mut err,),
            EXIT_SUCCESS
        );
        let abi = parse_json(&out, "adapter-abi");
        assert_eq!(
            abi["mapping"]["adapter_contract_version"],
            d2i_runtime_adapter::ADAPTER_CONTRACT_VERSION
        );
        assert!(abi["mapping"]["unresolved_external_contracts"]
            .as_array()
            .is_some_and(|items| !items.is_empty()));
    }
}
