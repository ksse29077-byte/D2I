use d2i_kernel::{
    run_kernel_benchmark, CandidateConfig, KernelBenchmarkOptions, KernelBenchmarkReport,
};
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("d2i-kernel-bench: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut options = KernelBenchmarkOptions::default();
    let mut output = None;
    let mut candidate_path = None;
    let mut candidate_hash = None;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--items" => {
                options.item_count = parse_next(&mut arguments, "--items")?;
            }
            "--warmup" => {
                options.warmup_iterations = parse_next(&mut arguments, "--warmup")?;
            }
            "--iterations" => {
                options.measured_iterations = parse_next(&mut arguments, "--iterations")?;
            }
            "--out" => output = Some(PathBuf::from(next(&mut arguments, "--out")?)),
            "--candidate" => {
                candidate_path = Some(PathBuf::from(next(&mut arguments, "--candidate")?));
            }
            "--hash" => candidate_hash = Some(next(&mut arguments, "--hash")?),
            "--help" | "-h" => {
                println!(
                    "d2i-kernel-bench [--items N] [--warmup N] [--iterations N] \
                     [--candidate LIB --hash SHA256] [--out FILE]"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument '{argument}'")),
        }
    }
    let candidate = match (candidate_path, candidate_hash) {
        (Some(library_path), Some(expected_sha256)) => Some(CandidateConfig {
            library_path,
            expected_sha256,
        }),
        (None, None) => None,
        _ => return Err("--candidate and --hash must be supplied together".to_owned()),
    };
    let report = run_kernel_benchmark(options, candidate.as_ref())?;
    let bytes = report_json(&report)?;
    if let Some(path) = output {
        std::fs::write(&path, &bytes)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    } else {
        print!("{}", String::from_utf8_lossy(&bytes));
    }
    Ok(())
}

fn next(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value"))
}

fn parse_next<T>(arguments: &mut impl Iterator<Item = String>, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = next(arguments, name)?;
    value
        .parse()
        .map_err(|error| format!("invalid {name} value '{value}': {error}"))
}

fn report_json(report: &KernelBenchmarkReport) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}
