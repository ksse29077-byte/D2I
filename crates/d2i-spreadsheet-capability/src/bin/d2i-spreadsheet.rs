use d2i_spreadsheet_capability::{
    parse_spreadsheet_json_strict, SpreadsheetCapabilityPackV1, SpreadsheetContextSliceV1,
    SpreadsheetOperationBindingV1, SpreadsheetOperationReceiptV1,
    SpreadsheetPostOperationVerificationV1, SpreadsheetQueryResultV1, SpreadsheetQueryV1,
    SpreadsheetSemanticDiffV1, SpreadsheetSemanticSnapshotV1, SpreadsheetWorkCertificationV1,
    SpreadsheetWorkCompletionReportV1, SpreadsheetWorkReplayReportV1,
};
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let artifact = next_utf8(&mut arguments).ok_or_else(usage)?;
    if next_utf8(&mut arguments).as_deref() != Some("verify") {
        return Err(usage());
    }
    if next_utf8(&mut arguments).as_deref() != Some("--input") {
        return Err(usage());
    }
    let input = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let remaining = arguments.collect::<Vec<_>>();
    if artifact != "certification" && !remaining.is_empty() {
        return Err(usage());
    }

    match artifact.as_str() {
        "snapshot" => verify::<SpreadsheetSemanticSnapshotV1, _>(&input, |value| value.validate()),
        "capability" => verify::<SpreadsheetCapabilityPackV1, _>(&input, |value| value.validate()),
        "query" => verify::<SpreadsheetQueryV1, _>(&input, |value| value.validate()),
        "query-result" => verify::<SpreadsheetQueryResultV1, _>(&input, |value| value.validate()),
        "context-slice" => verify::<SpreadsheetContextSliceV1, _>(&input, |value| value.validate()),
        "binding" => verify::<SpreadsheetOperationBindingV1, _>(&input, |value| value.validate()),
        "receipt" => verify::<SpreadsheetOperationReceiptV1, _>(&input, |value| value.validate()),
        "diff" => verify::<SpreadsheetSemanticDiffV1, _>(&input, |value| value.validate()),
        "verification" => {
            verify::<SpreadsheetPostOperationVerificationV1, _>(&input, |value| value.validate())
        }
        "replay" => verify::<SpreadsheetWorkReplayReportV1, _>(&input, |value| value.validate()),
        "completion" => {
            verify::<SpreadsheetWorkCompletionReportV1, _>(&input, |value| value.validate())
        }
        "certification" => verify_certification(&input, &remaining),
        _ => Err(usage()),
    }
}

fn next_utf8(arguments: &mut impl Iterator<Item = std::ffi::OsString>) -> Option<String> {
    arguments.next()?.into_string().ok()
}

fn verify_certification(input: &Path, arguments: &[std::ffi::OsString]) -> Result<(), String> {
    if arguments.len() != 2 || arguments[0] != "--public-key" {
        return Err(usage());
    }
    let public_key_text =
        std::fs::read_to_string(PathBuf::from(&arguments[1])).map_err(|error| error.to_string())?;
    let public_key = VerifyingKey::from_bytes(&decode_public_key(public_key_text.trim())?)
        .map_err(|error| format!("invalid Ed25519 public key: {error}"))?;
    verify::<SpreadsheetWorkCertificationV1, _>(input, |value| {
        value.validate_signature(&public_key)
    })
}

fn decode_public_key(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Ed25519 public key must be exactly 32 hex-encoded bytes".to_owned());
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let start = index * 2;
        *slot = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|error| format!("invalid public-key hex: {error}"))?;
    }
    Ok(output)
}

fn verify<T, F>(path: &Path, validate: F) -> Result<(), String>
where
    T: DeserializeOwned,
    F: FnOnce(&T) -> Result<(), d2i_spreadsheet_capability::SpreadsheetCapabilityError>,
{
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value: T = parse_spreadsheet_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    println!("verified: {}", path.display());
    Ok(())
}

fn usage() -> String {
    "usage: d2i-spreadsheet <snapshot|capability|query|query-result|context-slice|binding|receipt|diff|verification|replay|completion> verify --input <path> | d2i-spreadsheet certification verify --input <path> --public-key <hex-file>".to_owned()
}
