use d2i_learning::{
    append_episode, append_promotion, build_candidate_package, evaluate_candidate_package,
    export_store, initialize_store, load_candidate_package, load_dataset_registry,
    verify_dataset_artifacts, verify_promotion_ledger, verify_store, Actor, Approval, CanaryPlan,
    CandidateBuildOptions, Episode, ExperienceStorePolicy, OfflineEvaluationReport,
    PromotionPolicy, RollbackPlan,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

const HELP: &str = "\
d2i-learning - controlled offline experience compiler

Usage:
  d2i-learning store-init POLICY_JSON STORE_DIR
  d2i-learning store-append STORE_DIR EPISODE_JSON ACTOR_ID ROLES
  d2i-learning store-verify STORE_DIR
  d2i-learning store-export STORE_DIR OUTPUT_JSONL ACTOR_ID ROLES
  d2i-learning candidate-build STORE_DIR BASE_PACKAGE OUTPUT_DIR ACTOR_ID ROLES CANDIDATE_ID BUILDER_ID CREATED_AT
  d2i-learning candidate-verify CANDIDATE_DIR
  d2i-learning candidate-evaluate CANDIDATE_DIR BASE_PACKAGE OUTPUT_JSON EVALUATOR_ID EVALUATED_AT ITERATIONS
  d2i-learning promote CANDIDATE_DIR EVALUATION_JSON LEDGER_DIR APPROVAL_JSON CANARY_JSON ROLLBACK_JSON SECRET_KEY_HEX
  d2i-learning ledger-verify LEDGER_DIR
  d2i-learning dataset-check REGISTRY_JSON
  d2i-learning dataset-verify REGISTRY_JSON ARTIFACT_ROOT

ROLES is a comma-separated role list. Secret key files contain exactly 64 hex
characters and are never printed.
";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("d2i-learning: {error}");
            3
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(command) = arguments.first().map(String::as_str) else {
        print!("{HELP}");
        return Ok(());
    };
    match command {
        "--help" | "-h" | "help" => {
            print!("{HELP}");
            Ok(())
        }
        "store-init" => {
            exact(&arguments, 3)?;
            let policy: ExperienceStorePolicy = read_json(Path::new(&arguments[1]))?;
            initialize_store(Path::new(&arguments[2]), &policy)
                .map_err(|error| error.to_string())?;
            print_json(&verify_store(Path::new(&arguments[2])).map_err(|error| error.to_string())?)
        }
        "store-append" => {
            exact(&arguments, 5)?;
            let episode: Episode = read_json(Path::new(&arguments[2]))?;
            let verification = append_episode(
                Path::new(&arguments[1]),
                &actor(&arguments[3], &arguments[4]),
                episode,
            )
            .map_err(|error| error.to_string())?;
            print_json(&verification)
        }
        "store-verify" => {
            exact(&arguments, 2)?;
            print_json(&verify_store(Path::new(&arguments[1])).map_err(|error| error.to_string())?)
        }
        "store-export" => {
            exact(&arguments, 5)?;
            let hash = export_store(
                Path::new(&arguments[1]),
                Path::new(&arguments[2]),
                &actor(&arguments[3], &arguments[4]),
            )
            .map_err(|error| error.to_string())?;
            print_json(&serde_json::json!({"export_hash": hash}))
        }
        "candidate-build" => {
            exact(&arguments, 9)?;
            let options = CandidateBuildOptions {
                candidate_id: arguments[6].clone(),
                builder_id: arguments[7].clone(),
                created_at_unix_seconds: parse(&arguments[8], "CREATED_AT")?,
            };
            let package = build_candidate_package(
                Path::new(&arguments[1]),
                Path::new(&arguments[2]),
                Path::new(&arguments[3]),
                &actor(&arguments[4], &arguments[5]),
                &options,
            )
            .map_err(|error| error.to_string())?;
            print_json(&serde_json::json!({
                "candidate_id": package.manifest.candidate_id,
                "candidate_content_hash": package.candidate_content_hash,
                "dataset_report": package.dataset_report,
            }))
        }
        "candidate-verify" => {
            exact(&arguments, 2)?;
            let package = load_candidate_package(Path::new(&arguments[1]))
                .map_err(|error| error.to_string())?;
            print_json(&serde_json::json!({
                "candidate_id": package.manifest.candidate_id,
                "candidate_content_hash": package.candidate_content_hash,
                "dataset_report": package.dataset_report,
            }))
        }
        "candidate-evaluate" => {
            exact(&arguments, 7)?;
            let report = evaluate_candidate_package(
                Path::new(&arguments[1]),
                Path::new(&arguments[2]),
                &arguments[4],
                parse(&arguments[5], "EVALUATED_AT")?,
                parse(&arguments[6], "ITERATIONS")?,
                PromotionPolicy::default(),
            )
            .map_err(|error| error.to_string())?;
            write_json_new(Path::new(&arguments[3]), &report)?;
            print_json(&report)
        }
        "promote" => {
            exact(&arguments, 8)?;
            let evaluation: OfflineEvaluationReport = read_json(Path::new(&arguments[2]))?;
            let approval: Approval = read_json(Path::new(&arguments[4]))?;
            let canary: CanaryPlan = read_json(Path::new(&arguments[5]))?;
            let rollback: RollbackPlan = read_json(Path::new(&arguments[6]))?;
            let key = read_secret_key(Path::new(&arguments[7]))?;
            let record = append_promotion(
                Path::new(&arguments[3]),
                Path::new(&arguments[1]),
                &evaluation,
                approval,
                canary,
                rollback,
                key,
            )
            .map_err(|error| error.to_string())?;
            print_json(&record)
        }
        "ledger-verify" => {
            exact(&arguments, 2)?;
            let records = verify_promotion_ledger(Path::new(&arguments[1]))
                .map_err(|error| error.to_string())?;
            print_json(&serde_json::json!({
                "record_count": records.len(),
                "chain_head": records.last().map(|record| record.record_hash.as_str()),
            }))
        }
        "dataset-check" => {
            exact(&arguments, 2)?;
            let registry = load_dataset_registry(Path::new(&arguments[1]))
                .map_err(|error| error.to_string())?;
            let report = d2i_learning::check_dataset_registry(&registry)
                .map_err(|error| error.to_string())?;
            print_json(&report)
        }
        "dataset-verify" => {
            exact(&arguments, 3)?;
            let registry = load_dataset_registry(Path::new(&arguments[1]))
                .map_err(|error| error.to_string())?;
            let verification = verify_dataset_artifacts(&registry, Path::new(&arguments[2]))
                .map_err(|error| error.to_string())?;
            print_json(&verification)
        }
        _ => Err(format!("unknown command '{command}'\n{HELP}")),
    }
}

fn exact(arguments: &[String], expected: usize) -> Result<(), String> {
    if arguments.len() == expected {
        Ok(())
    } else {
        Err(format!("wrong argument count\n{HELP}"))
    }
}

fn actor(actor_id: &str, roles: &str) -> Actor {
    Actor {
        actor_id: actor_id.to_owned(),
        roles: roles
            .split(',')
            .filter(|role| !role.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>(),
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = read_bounded(path, 2 * 1024 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    std::fs::read(path).map_err(|error| error.to_string())
}

fn write_json_new(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())
}

fn print_json(value: &impl Serialize) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{text}");
    Ok(())
}

fn parse<T: std::str::FromStr>(value: &str, name: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .map_err(|error| format!("invalid {name} '{value}': {error}"))
}

fn read_secret_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = read_bounded(path, 128)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| error.to_string())?
        .trim();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("secret key file must contain exactly 64 hex characters".to_owned());
    }
    let mut key = [0_u8; 32];
    for (index, slot) in key.iter_mut().enumerate() {
        let offset = index * 2;
        *slot =
            u8::from_str_radix(&text[offset..offset + 2], 16).map_err(|error| error.to_string())?;
    }
    Ok(key)
}
