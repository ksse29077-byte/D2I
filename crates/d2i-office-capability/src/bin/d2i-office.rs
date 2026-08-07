use d2i_office_capability::{
    parse_json_strict, CapabilitySourceRecordV1, McpToolCatalogSnapshotV1,
    OfficeArtifactReferenceV1, OfficeCapabilityCandidateV1, OfficeWorkspaceCompletionReportV1,
    OfficeWorkspaceReplayReportV1, WorkspaceObservationSnapshotV1, WorkspaceOperationBindingV1,
    WorkspaceOperationIntentV1, WorkspaceOperationReceiptV1,
};
use serde::Serialize;
use std::env;
use std::fs;
use std::process::ExitCode;

#[derive(Serialize)]
struct VerificationOutput {
    schema_version: u32,
    artifact: String,
    valid: bool,
    artifact_sha256: Option<String>,
    error: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&output)
                    .unwrap_or_else(|error| format!("{{\"error\":\"{error}\"}}"))
            );
            if output.valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<VerificationOutput, String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 || arguments[1] != "--input" {
        return Err("usage: d2i-office <source|catalog|candidate|artifact|observation|intent|binding|receipt|replay|completion> --input <path>".to_owned());
    }
    let artifact = arguments[0].clone();
    let bytes = fs::read(&arguments[2]).map_err(|error| error.to_string())?;
    let result = match artifact.as_str() {
        "source" => verify::<CapabilitySourceRecordV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.record_sha256.clone())
        }),
        "catalog" => verify::<McpToolCatalogSnapshotV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.catalog_sha256.clone())
        }),
        "candidate" => verify::<OfficeCapabilityCandidateV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.candidate_sha256.clone())
        }),
        "artifact" => verify::<OfficeArtifactReferenceV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.artifact_sha256.clone())
        }),
        "observation" => verify::<WorkspaceObservationSnapshotV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.observation_sha256.clone())
        }),
        "intent" => verify::<WorkspaceOperationIntentV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.intent_sha256.clone())
        }),
        "binding" => verify::<WorkspaceOperationBindingV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.binding_sha256.clone())
        }),
        "receipt" => verify::<WorkspaceOperationReceiptV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.receipt_sha256.clone())
        }),
        "replay" => verify::<OfficeWorkspaceReplayReportV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.report_sha256.clone())
        }),
        "completion" => verify::<OfficeWorkspaceCompletionReportV1>(&bytes, |value| {
            value
                .validate_integrity()
                .map(|_| value.finished_sha256.clone())
        }),
        _ => return Err("unsupported OFFICE-100 artifact".to_owned()),
    };
    Ok(match result {
        Ok(hash) => VerificationOutput {
            schema_version: 1,
            artifact,
            valid: true,
            artifact_sha256: Some(hash),
            error: None,
        },
        Err(error) => VerificationOutput {
            schema_version: 1,
            artifact,
            valid: false,
            artifact_sha256: None,
            error: Some(error),
        },
    })
}

fn verify<T>(
    bytes: &[u8],
    validate: impl FnOnce(&T) -> Result<String, d2i_office_capability::OfficeCapabilityError>,
) -> Result<String, String>
where
    T: serde::de::DeserializeOwned,
{
    let value = parse_json_strict::<T>(bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())
}
