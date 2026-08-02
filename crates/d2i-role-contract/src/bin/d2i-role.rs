use d2i_role_contract::{
    compile_role_source, parse_json_strict, RoleCompileFormatV1, RoleContractBundleV1,
    RoleContractError, RoleContractV1,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("d2i-role failed closed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), RoleContractError> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| RoleContractError::Invalid(usage().to_owned()))?;
    let options = parse_options(args)?;
    match command.as_str() {
        "validate" => {
            let source = required_path(&options, "--source")?;
            let bundle = compile_source_path(&source)?;
            println!(
                "{}",
                json!({
                    "status": "valid",
                    "role_contract_id": bundle.contract.role_contract_id,
                    "role_version": bundle.contract.role_version,
                    "contract_sha256": bundle.contract.contract_sha256,
                    "bundle_sha256": bundle.bundle_sha256
                })
            );
        }
        "compile" => {
            let source = required_path(&options, "--source")?;
            let output = required_path(&options, "--output")?;
            let bundle = compile_source_path(&source)?;
            write_bundle(&output, &bundle)?;
            println!(
                "{}",
                json!({
                    "status": "compiled",
                    "output": output,
                    "contract_sha256": bundle.contract.contract_sha256,
                    "bundle_sha256": bundle.bundle_sha256
                })
            );
        }
        "inspect" => {
            let contract_path = required_path(&options, "--contract")?;
            let bytes = read_bounded(&contract_path)?;
            let contract: RoleContractV1 = parse_json_strict(&bytes)?;
            contract.validate()?;
            println!(
                "{}",
                json!({
                    "schema_version": contract.schema_version,
                    "role_contract_id": contract.role_contract_id,
                    "role_version": contract.role_version,
                    "organization_id": contract.organization_scope.organization_id,
                    "work_class_ids": contract.accepted_work_classes.iter().map(|value| &value.work_class_id).collect::<Vec<_>>(),
                    "application_pack_ids": contract.application_bindings.iter().map(|value| &value.application_pack_id).collect::<Vec<_>>(),
                    "capability_ids": contract.capability_policy.allowed_capability_ids,
                    "contract_sha256": contract.contract_sha256
                })
            );
        }
        "verify" => {
            let bundle_root = required_path(&options, "--bundle")?;
            let bytes = read_bounded(&bundle_root.join("role.bundle.json"))?;
            let bundle: RoleContractBundleV1 = parse_json_strict(&bytes)?;
            bundle.validate()?;
            verify_bundle_files(&bundle_root, &bundle)?;
            println!(
                "{}",
                json!({
                    "status": "verified",
                    "contract_sha256": bundle.contract.contract_sha256,
                    "bundle_sha256": bundle.bundle_sha256
                })
            );
        }
        _ => return Err(RoleContractError::Invalid(usage().to_owned())),
    }
    Ok(())
}

fn parse_options(
    args: impl Iterator<Item = String>,
) -> Result<BTreeMap<String, String>, RoleContractError> {
    let values = args.collect::<Vec<_>>();
    if values.len() % 2 != 0 {
        return Err(RoleContractError::Invalid(usage().to_owned()));
    }
    let mut options = BTreeMap::new();
    for pair in values.chunks_exact(2) {
        if !pair[0].starts_with("--") || options.insert(pair[0].clone(), pair[1].clone()).is_some()
        {
            return Err(RoleContractError::Invalid(
                "duplicate or malformed CLI option".to_owned(),
            ));
        }
    }
    Ok(options)
}

fn required_path(
    options: &BTreeMap<String, String>,
    name: &str,
) -> Result<PathBuf, RoleContractError> {
    options
        .get(name)
        .map(PathBuf::from)
        .ok_or_else(|| RoleContractError::Invalid(format!("required option is absent: {name}")))
}

fn compile_source_path(path: &Path) -> Result<RoleContractBundleV1, RoleContractError> {
    let bytes = read_bounded(path)?;
    let format = match path.extension().and_then(|value| value.to_str()) {
        Some("json") => RoleCompileFormatV1::Json,
        Some("yaml" | "yml") => RoleCompileFormatV1::Yaml,
        _ => {
            return Err(RoleContractError::Invalid(
                "Role source extension must be json, yaml, or yml".to_owned(),
            ))
        }
    };
    compile_role_source(&bytes, format)
}

fn write_bundle(root: &Path, bundle: &RoleContractBundleV1) -> Result<(), RoleContractError> {
    if root.exists() {
        return Err(RoleContractError::Io(
            "Role bundle output already exists".to_owned(),
        ));
    }
    fs::create_dir_all(root).map_err(io_error)?;
    for (name, value) in [
        ("role.contract.json", to_pretty(&bundle.contract)?),
        ("role.manifest.json", to_pretty(&bundle.manifest)?),
        ("role.source-lock.json", to_pretty(&bundle.source_lock)?),
        ("role.conformance.json", to_pretty(&bundle.conformance)?),
        ("role.bundle.json", to_pretty(bundle)?),
    ] {
        let path = root.join(name);
        fs::write(&path, value).map_err(io_error)?;
    }
    Ok(())
}

fn verify_bundle_files(
    root: &Path,
    bundle: &RoleContractBundleV1,
) -> Result<(), RoleContractError> {
    let expected = [
        ("role.contract.json", serde_json::to_value(&bundle.contract)),
        ("role.manifest.json", serde_json::to_value(&bundle.manifest)),
        (
            "role.source-lock.json",
            serde_json::to_value(&bundle.source_lock),
        ),
        (
            "role.conformance.json",
            serde_json::to_value(&bundle.conformance),
        ),
    ];
    for (name, expected) in expected {
        let expected = expected.map_err(|error| RoleContractError::Json(error.to_string()))?;
        let actual: serde_json::Value = parse_json_strict(&read_bounded(&root.join(name))?)?;
        if actual != expected {
            return Err(RoleContractError::Integrity(format!(
                "Role bundle file differs: {name}"
            )));
        }
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, RoleContractError> {
    let metadata = fs::metadata(path).map_err(io_error)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
        return Err(RoleContractError::Io(
            "Role file is absent, empty, or oversized".to_owned(),
        ));
    }
    fs::read(path).map_err(io_error)
}

fn to_pretty(value: &impl Serialize) -> Result<Vec<u8>, RoleContractError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| RoleContractError::Json(error.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn io_error(error: std::io::Error) -> RoleContractError {
    RoleContractError::Io(error.to_string())
}

fn usage() -> &'static str {
    "usage: d2i-role <validate|compile|inspect|verify> --source <path> [--output <dir>] | --contract <path> | --bundle <dir>"
}
