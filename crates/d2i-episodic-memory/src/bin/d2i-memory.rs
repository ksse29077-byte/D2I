use d2i_episodic_memory::{
    hash_without, parse_json_strict, ApprovedEpisodeSummaryV1, CaseEpisodeV1, EpisodeMemoryQueryV1,
    EpisodeTombstoneV1, EpisodicMemoryReplayReportV1, MemoryAugmentedCaseContextV1,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() == 3 && arguments[0] == "replay" && arguments[1] == "--bundle" {
        let path = PathBuf::from(&arguments[2]).join("episodic-memory-replay-report-v1.json");
        let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
        let report: EpisodicMemoryReplayReportV1 =
            parse_json_strict(&bytes).map_err(|error| error.to_string())?;
        let actual = hash_without(&report, &["normalized_report_sha256"])
            .map_err(|error| error.to_string())?;
        if actual != report.normalized_report_sha256 || report.critical_error_count != 0 {
            return Err("replay report hash or critical-error gate failed".to_owned());
        }
        println!("{}", report.normalized_report_sha256);
        return Ok(());
    }
    if arguments.len() != 4 || arguments[1] != "verify" || arguments[2] != "--input" {
        return Err(
            "usage: d2i-memory <episode|summary|query|attachment|tombstone> verify --input <json> | replay --bundle <directory>"
                .to_owned(),
        );
    }
    let bytes = std::fs::read(PathBuf::from(&arguments[3])).map_err(|error| error.to_string())?;
    let hash = match arguments[0].as_str() {
        "episode" => {
            let value: CaseEpisodeV1 =
                parse_json_strict(&bytes).map_err(|error| error.to_string())?;
            value.validate().map_err(|error| error.to_string())?;
            value.canonical_episode_sha256
        }
        "summary" => verify_hash_only::<ApprovedEpisodeSummaryV1>(
            &bytes,
            &["summary_sha256", "signature_hex"],
            "summary_sha256",
        )?,
        "query" => {
            verify_hash_only::<EpisodeMemoryQueryV1>(&bytes, &["query_sha256"], "query_sha256")?
        }
        "attachment" => verify_hash_only::<MemoryAugmentedCaseContextV1>(
            &bytes,
            &["augmented_context_sha256"],
            "augmented_context_sha256",
        )?,
        "tombstone" => verify_hash_only::<EpisodeTombstoneV1>(
            &bytes,
            &["tombstone_sha256"],
            "tombstone_sha256",
        )?,
        _ => return Err("unsupported artifact".to_owned()),
    };
    println!("{hash}");
    Ok(())
}

fn verify_hash_only<T>(bytes: &[u8], omitted: &[&str], field: &str) -> Result<String, String>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = parse_json_strict(bytes).map_err(|error| error.to_string())?;
    let actual = hash_without(&value, omitted).map_err(|error| error.to_string())?;
    let json = serde_json::to_value(&value).map_err(|error| error.to_string())?;
    let expected = json
        .get(field)
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("{field} is missing"))?;
    if actual != expected {
        return Err(format!("{field} mismatch"));
    }
    Ok(actual)
}
