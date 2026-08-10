use d2i_pdf_interchange::{
    parse_pdf_json_strict, PdfWorkCertificationV1, PdfWorkCompletionReportV1, PdfWorkReplayReportV1,
};
use ed25519_dalek::VerifyingKey;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [kind, action, flag, path]
            if kind == "completion" && action == "verify" && flag == "--input" =>
        {
            verify_completion(path)
        }
        [kind, action, flag, path]
            if kind == "replay" && action == "verify" && flag == "--input" =>
        {
            verify_replay(path)
        }
        [kind, action, input_flag, path, key_flag, key_path]
            if kind == "certification"
                && action == "verify"
                && input_flag == "--input"
                && key_flag == "--public-key" =>
        {
            verify_certification(path, key_path)
        }
        _ => Err("usage: d2i-pdf-interchange completion|replay verify --input <file> | certification verify --input <file> --public-key <hex-file>".to_owned()),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn verify_completion(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let report: PdfWorkCompletionReportV1 =
        parse_pdf_json_strict(&bytes).map_err(|error| error.to_string())?;
    report.validate_gate().map_err(|error| error.to_string())
}

fn verify_replay(path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let report: PdfWorkReplayReportV1 =
        parse_pdf_json_strict(&bytes).map_err(|error| error.to_string())?;
    report.validate_gate().map_err(|error| error.to_string())
}

fn verify_certification(path: &str, key_path: &str) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let certification: PdfWorkCertificationV1 =
        parse_pdf_json_strict(&bytes).map_err(|error| error.to_string())?;
    let text = std::fs::read_to_string(key_path).map_err(|error| error.to_string())?;
    let text = text.trim();
    if text.len() != 64 {
        return Err("certification public key must be 32-byte hexadecimal".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let part = std::str::from_utf8(chunk).map_err(|error| error.to_string())?;
        bytes[index] = u8::from_str_radix(part, 16).map_err(|error| error.to_string())?;
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    certification
        .verify(&key, u64::try_from(now).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}
