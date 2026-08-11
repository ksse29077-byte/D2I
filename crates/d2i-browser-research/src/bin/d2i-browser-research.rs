use d2i_browser_research::{
    default_research_network_profile_v1, parse_json_strict, ResearchWorkCertificationV1,
    ResearchWorkCompletionReportV1, ResearchWorkReplayReportV1,
};
use ed25519_dalek::VerifyingKey;
use std::env;
use std::fs;

fn main() {
    if let Err(error) = run() {
        eprintln!("d2i-browser-research: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [command] if command == "default-network-profile" => {
            let profile = default_research_network_profile_v1().map_err(|error| error.to_string())?;
            let value = serde_json::to_string_pretty(&profile).map_err(|error| error.to_string())?;
            println!("{value}");
            Ok(())
        }
        [command, path] if command == "validate-replay" => {
            let bytes = fs::read(path).map_err(|error| error.to_string())?;
            let report: ResearchWorkReplayReportV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            report.validate_gate().map_err(|error| error.to_string())
        }
        [command, path] if command == "validate-completion" => {
            let bytes = fs::read(path).map_err(|error| error.to_string())?;
            let report: ResearchWorkCompletionReportV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            report.validate_gate().map_err(|error| error.to_string())
        }
        [command, path, public_key_path] if command == "validate-certification" => {
            let bytes = fs::read(path).map_err(|error| error.to_string())?;
            let certification: ResearchWorkCertificationV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            let public_key = decode_public_key(
                fs::read_to_string(public_key_path)
                    .map_err(|error| error.to_string())?
                    .trim(),
            )?;
            let verification_time = certification
                .issued_at_unix_ms
                .saturating_add(1)
                .min(certification.expires_at_unix_ms.saturating_sub(1));
            certification
                .verify(&public_key, verification_time)
                .map_err(|error| error.to_string())
        }
        _ => Err(
            "usage: d2i-browser-research <default-network-profile|validate-replay PATH|validate-completion PATH|validate-certification PATH PUBLIC_KEY>"
                .to_owned(),
        ),
    }
}

fn decode_public_key(value: &str) -> Result<VerifyingKey, String> {
    if value.len() != 64 {
        return Err("certification public key must be 32-byte hexadecimal".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "certification public key is not hexadecimal".to_owned())?;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())
}
