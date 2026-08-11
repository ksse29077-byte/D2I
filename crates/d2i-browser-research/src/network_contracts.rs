use crate::validation::{validate_hash, validate_id};
use crate::{
    ControlledDownloadIntentV1, ControlledDownloadRequestV1, ResearchError, ResearchFetchRequestV1,
    ResearchNetworkProfileV1,
};

pub fn validate_research_fetch_request_v1(
    request: &ResearchFetchRequestV1,
    profile: &ResearchNetworkProfileV1,
    now_unix_ms: u64,
    worker_executable_sha256: &str,
) -> Result<(), ResearchError> {
    request.validate_seal()?;
    profile.validate_seal()?;
    for value in [
        &request.request_id,
        &request.organization_id,
        &request.case_id,
        &request.role_id,
        &request.source_candidate_id,
    ] {
        validate_id(value, "fetch request identity")?;
    }
    for value in [
        &request.work_grant_sha256,
        &request.research_brief_sha256,
        &request.url_admission_decision_sha256,
        &request.network_profile_sha256,
        &request.worker_executable_sha256,
    ] {
        validate_hash(value, "fetch request hash")?;
    }
    if request.schema_version != 1
        || request.network_profile_sha256 != profile.network_profile_sha256
        || request.worker_executable_sha256 != worker_executable_sha256
        || request.deadline_unix_ms <= now_unix_ms
        || request.deadline_unix_ms.saturating_sub(now_unix_ms) > 300_000
    {
        return Err(ResearchError::AccessDenied(
            "research fetch request binding or deadline differs".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_controlled_download_request_v1(
    request: &ControlledDownloadRequestV1,
    intent: &ControlledDownloadIntentV1,
    profile: &ResearchNetworkProfileV1,
    now_unix_ms: u64,
    worker_executable_sha256: &str,
) -> Result<(), ResearchError> {
    request.validate_seal()?;
    intent.validate_seal()?;
    profile.validate_seal()?;
    for value in [
        &request.request_id,
        &request.organization_id,
        &request.case_id,
        &request.quarantine_artifact_id,
    ] {
        validate_id(value, "download request identity")?;
    }
    for value in [
        &request.intent_sha256,
        &request.url_admission_decision_sha256,
        &request.network_profile_sha256,
        &request.worker_executable_sha256,
    ] {
        validate_hash(value, "download request hash")?;
    }
    if request.schema_version != 1
        || request.organization_id != intent.organization_id
        || request.case_id != intent.case_id
        || request.intent_sha256 != intent.intent_sha256
        || request.network_profile_sha256 != profile.network_profile_sha256
        || request.worker_executable_sha256 != worker_executable_sha256
        || request.deadline_unix_ms <= now_unix_ms
        || request.deadline_unix_ms.saturating_sub(now_unix_ms) > 300_000
    {
        return Err(ResearchError::AccessDenied(
            "controlled download request binding or deadline differs".to_owned(),
        ));
    }
    Ok(())
}
