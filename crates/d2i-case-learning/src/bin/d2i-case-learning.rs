use d2i_case_learning::{validate_candidate, LearningCandidateExportBundleV1, LearningCandidateV1};
use d2i_episodic_memory::parse_json_strict;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 4
        && arguments[0] == "export"
        && arguments[1] == "verify"
        && arguments[2] == "--bundle"
    {
        let path = PathBuf::from(&arguments[3]).join("learning-candidate-export-bundle-v1.json");
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        let bundle: LearningCandidateExportBundleV1 =
            parse_json_strict(&bytes).map_err(|error| error.to_string())?;
        let verified = bundle.clone().seal().map_err(|error| error.to_string())?;
        if verified != bundle {
            return Err("export bundle hash mismatch".to_owned());
        }
        println!("{}", bundle.bundle_sha256);
        return Ok(());
    }
    if arguments.len() != 4 || arguments[1] != "verify" || arguments[2] != "--input" {
        return Err(
            "usage: d2i-case-learning candidate verify --input <json> | export verify --bundle <directory>"
                .to_owned(),
        );
    }
    let bytes = std::fs::read(PathBuf::from(&arguments[3])).map_err(|error| error.to_string())?;
    match arguments[0].as_str() {
        "candidate" => {
            let candidate: LearningCandidateV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            validate_candidate(&candidate).map_err(|error| error.to_string())?;
            println!("{}", candidate.candidate_sha256);
        }
        "export" => {
            let bundle: LearningCandidateExportBundleV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            let verified = bundle.clone().seal().map_err(|error| error.to_string())?;
            if verified != bundle {
                return Err("export bundle hash mismatch".to_owned());
            }
            println!("{}", bundle.bundle_sha256);
        }
        _ => return Err("unsupported artifact".to_owned()),
    }
    Ok(())
}
