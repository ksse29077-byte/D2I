use d2i_enterprise_api_plane::*;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.as_slice() {
        [kind, operation, flag, path] if operation == "verify" && flag == "--input" => {
            verify_artifact(kind, Path::new(path))
        }
        _ => Err("usage: d2i-enterprise <plane|connector|approval|operation|endpoint|credential|observation-request|observation|intent|binding|receipt|verification|network-policy|idempotency|health|replay|completion|certification> verify --input <json>".to_owned()),
    }
}

fn verify_artifact(kind: &str, path: &Path) -> Result<(), String> {
    match kind {
        "plane" => parse_and_validate::<ExecutionPlaneDescriptorV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "connector" => parse_and_validate::<EnterpriseConnectorPackV1>(
            path,
            EnterpriseConnectorPackV1::validate_integrity,
        ),
        "approval" => parse_and_validate::<EnterpriseConnectorApprovalV1>(
            path,
            EnterpriseConnectorApprovalV1::validate_integrity,
        ),
        "operation" => parse_and_validate::<EnterpriseOperationDescriptorV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "endpoint" => parse_and_validate::<EnterpriseEndpointBindingV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "credential" => parse_and_validate::<EnterpriseCredentialReferenceV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "observation-request" => parse_and_validate::<EnterpriseObservationRequestV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "observation" => parse_and_validate::<EnterpriseObservationSnapshotV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "intent" => parse_and_validate::<EnterpriseOperationIntentV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "binding" => parse_and_validate::<EnterpriseOperationBindingV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "receipt" => parse_and_validate::<EnterpriseOperationReceiptV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "verification" => parse_and_validate::<EnterprisePostActionVerificationV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "network-policy" => parse_and_validate::<EnterpriseNetworkPolicyV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "idempotency" => parse_and_validate::<EnterpriseIdempotencyRecordV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "health" => parse_and_validate::<EnterpriseConnectorHealthV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "replay" => parse_and_validate::<EnterpriseReplayReportV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "completion" => parse_and_validate::<EnterpriseApiCompletionReportV1>(
            path,
            EnterpriseArtifact::validate_integrity,
        ),
        "certification" => parse_and_validate::<EnterpriseApiCertificationV1>(
            path,
            EnterpriseApiCertificationV1::validate_integrity,
        ),
        _ => Err("unsupported enterprise API artifact kind".to_owned()),
    }
}

fn parse_and_validate<T>(
    path: &Path,
    validate: impl FnOnce(&T) -> Result<(), EnterpriseApiError>,
) -> Result<(), String>
where
    T: DeserializeOwned + serde::Serialize,
{
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("input is not a regular non-symlink file".to_owned());
    }
    if metadata.len() > MAX_JSON_BYTES as u64 {
        return Err("input exceeds byte limit".to_owned());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let value: T = parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate(&value).map_err(|error| error.to_string())?;
    println!(
        "{}",
        canonical_sha256(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}
