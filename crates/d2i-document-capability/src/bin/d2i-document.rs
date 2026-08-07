use d2i_document_capability::{
    parse_document_json_strict, DocumentBackendDescriptorV1, DocumentCapabilityPackV1,
    DocumentOperationBindingV1, DocumentOperationIntentV1, DocumentOperationReceiptV1,
    DocumentPostOperationVerificationV1, DocumentSemanticDiffV1,
    DocumentSemanticEquivalenceReportV1, DocumentSemanticSnapshotV1,
    DocumentStructuralQualityAssessmentV1, DocumentWorkCertificationV1,
    DocumentWorkCompletionReportV1, DocumentWorkReplayReportV1,
};
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let artifact = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    let verb = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    if verb != "verify" {
        return Err(usage());
    }
    let input_flag = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)?;
    if input_flag != "--input" {
        return Err(usage());
    }
    let input = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    let remaining = arguments.collect::<Vec<_>>();
    if artifact != "certification" {
        reject_remaining(&remaining)?;
    }
    match artifact.as_str() {
        "snapshot" => {
            verify::<DocumentSemanticSnapshotV1, _>(&input, |value| value.validate_integrity())
        }
        "capability" => {
            verify::<DocumentCapabilityPackV1, _>(&input, |value| value.validate_integrity())
        }
        "backend" => {
            verify::<DocumentBackendDescriptorV1, _>(&input, |value| value.validate_integrity())
        }
        "intent" => {
            verify::<DocumentOperationIntentV1, _>(&input, |value| value.validate_integrity())
        }
        "binding" => {
            verify::<DocumentOperationBindingV1, _>(&input, |value| value.validate_integrity())
        }
        "receipt" => {
            verify::<DocumentOperationReceiptV1, _>(&input, |value| value.validate_integrity())
        }
        "diff" => verify::<DocumentSemanticDiffV1, _>(&input, |value| value.validate_integrity()),
        "verification" => verify::<DocumentPostOperationVerificationV1, _>(&input, |value| {
            value.validate_integrity()
        }),
        "quality" => verify::<DocumentStructuralQualityAssessmentV1, _>(&input, |value| {
            value.validate_integrity()
        }),
        "equivalence" => verify::<DocumentSemanticEquivalenceReportV1, _>(&input, |value| {
            value.validate_integrity()
        }),
        "replay" => {
            verify::<DocumentWorkReplayReportV1, _>(&input, |value| value.validate_integrity())
        }
        "completion" => {
            verify::<DocumentWorkCompletionReportV1, _>(&input, |value| value.validate_integrity())
        }
        "certification" => verify_certification(&input, &remaining),
        _ => Err(usage()),
    }
}

fn reject_remaining(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    if arguments.is_empty() {
        Ok(())
    } else {
        Err(usage())
    }
}

fn verify_certification(input: &Path, arguments: &[std::ffi::OsString]) -> Result<(), String> {
    if arguments.len() != 2 || arguments[0] != "--public-key" {
        return Err(usage());
    }
    let public_key_path = PathBuf::from(&arguments[1]);
    let public_key_text =
        std::fs::read_to_string(&public_key_path).map_err(|error| error.to_string())?;
    let public_key_bytes = decode_public_key(public_key_text.trim())?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|error| format!("invalid Ed25519 public key: {error}"))?;
    verify::<DocumentWorkCertificationV1, _>(input, |value| value.validate_signature(&public_key))
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
    F: FnOnce(&T) -> Result<(), d2i_document_capability::DocumentCapabilityError>,
{
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value: T = parse_document_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    println!("verified: {}", path.display());
    Ok(())
}

fn usage() -> String {
    "usage: d2i-document <snapshot|capability|backend|intent|binding|receipt|diff|verification|quality|equivalence|replay|completion> verify --input <path> | d2i-document certification verify --input <path> --public-key <hex-file>".to_owned()
}
