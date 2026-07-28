use d2i_embodied::{
    certify_runtime_binding, check_integration_readiness, initialize_activation_ledger,
    load_integration_manifest, load_runtime_binding_evidence, verify_activation_ledger,
};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const HELP: &str = "\
d2i-embodied - offline embodied integration contract tools

Usage:
  d2i-embodied readiness MANIFEST_JSON
  d2i-embodied certify MANIFEST_JSON BINDING_EVIDENCE_JSON
  d2i-embodied ledger-init MANIFEST_JSON LEDGER_DIR LEDGER_ID ACTIVATOR_ID MAX_ENTRIES
  d2i-embodied ledger-check LEDGER_DIR

Exit codes:
  0  manifest is ready
  3  invalid input or execution failure
  6  integration is valid but is not ready or certified
";

fn main() {
    std::process::exit(match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("d2i-embodied: {error}");
            3
        }
    });
}

fn run() -> Result<i32, String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => {
            print!("{HELP}");
            Ok(0)
        }
        [command] if matches!(command.as_str(), "--help" | "-h" | "help") => {
            print!("{HELP}");
            Ok(0)
        }
        [command, path] if command == "readiness" => {
            let manifest =
                load_integration_manifest(Path::new(path)).map_err(|error| error.to_string())?;
            let report =
                check_integration_readiness(&manifest).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
            );
            Ok(if report.ready { 0 } else { 6 })
        }
        [command, manifest_path, evidence_path] if command == "certify" => {
            let manifest = load_integration_manifest(Path::new(manifest_path))
                .map_err(|error| error.to_string())?;
            let evidence = load_runtime_binding_evidence(Path::new(evidence_path))
                .map_err(|error| error.to_string())?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|error| format!("system clock is before Unix epoch: {error}"))?
                .as_secs();
            let certification = certify_runtime_binding(&manifest, &evidence, now)
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&certification.report)
                    .map_err(|error| error.to_string())?
            );
            Ok(if certification.report.certified { 0 } else { 6 })
        }
        [command, manifest_path, ledger_path, ledger_id, activator_id, maximum_entries]
            if command == "ledger-init" =>
        {
            let manifest = load_integration_manifest(Path::new(manifest_path))
                .map_err(|error| error.to_string())?;
            let maximum_entries = maximum_entries
                .parse::<u64>()
                .map_err(|error| format!("invalid MAX_ENTRIES: {error}"))?;
            let verification = initialize_activation_ledger(
                Path::new(ledger_path),
                ledger_id,
                &manifest,
                BTreeSet::from([activator_id.clone()]),
                maximum_entries,
            )
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verification).map_err(|error| error.to_string())?
            );
            Ok(0)
        }
        [command, ledger_path] if command == "ledger-check" => {
            let verification = verify_activation_ledger(Path::new(ledger_path))
                .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verification).map_err(|error| error.to_string())?
            );
            Ok(0)
        }
        _ => Err(format!("invalid arguments\n{HELP}")),
    }
}
