use crate::validation::{validate_hash, validate_id};
use crate::{
    BrowserResearchSessionV1, BrowserSnapshotManifestV1, ResearchError, ResearchPageSnapshotV1,
    ZERO_HASH,
};

pub fn validate_browser_research_session_v1(
    session: &BrowserResearchSessionV1,
) -> Result<(), ResearchError> {
    session.validate_seal()?;
    for value in [
        &session.session_id,
        &session.organization_id,
        &session.case_id,
        &session.role_id,
        &session.snapshot_server_origin_id,
    ] {
        validate_id(value, "browser research session identity")?;
    }
    for value in [
        &session.edge_executable_sha256,
        &session.edge_driver_executable_sha256,
        &session.wfp_loopback_evidence_sha256,
        &session.research_brief_sha256,
    ] {
        validate_hash(value, "browser research session hash")?;
    }
    if session.schema_version != 1
        || session.maximum_pages == 0
        || session.maximum_pages > 24
        || session.maximum_links == 0
        || session.maximum_links > 24 * 512
        || !session.downloads_denied
        || !session.forms_disabled
    {
        return Err(ResearchError::AccessDenied(
            "browser research session exceeds loopback read-only authority".to_owned(),
        ));
    }
    Ok(())
}

pub fn build_browser_snapshot_manifest_v1(
    manifest_id: &str,
    session: &BrowserResearchSessionV1,
    snapshots: &[ResearchPageSnapshotV1],
    safe_projection_sha256: Vec<String>,
    external_navigation_count: u32,
    browser_download_count: u32,
    browser_form_submit_count: u32,
) -> Result<BrowserSnapshotManifestV1, ResearchError> {
    validate_browser_research_session_v1(session)?;
    validate_id(manifest_id, "browser snapshot manifest ID")?;
    if snapshots.is_empty()
        || snapshots.len() > session.maximum_pages as usize
        || safe_projection_sha256.len() != snapshots.len()
        || external_navigation_count != 0
        || browser_download_count != 0
        || browser_form_submit_count != 0
    {
        return Err(ResearchError::AccessDenied(
            "browser snapshot manifest contains a side effect or count mismatch".to_owned(),
        ));
    }
    for hash in &safe_projection_sha256 {
        validate_hash(hash, "safe snapshot projection hash")?;
    }
    let mut hashes = Vec::with_capacity(snapshots.len());
    for snapshot in snapshots {
        snapshot.validate_seal()?;
        if snapshot.organization_id != session.organization_id
            || snapshot.case_id != session.case_id
        {
            return Err(ResearchError::Integrity(
                "browser snapshot organization or Case differs".to_owned(),
            ));
        }
        hashes.push(snapshot.snapshot_sha256.clone());
    }
    BrowserSnapshotManifestV1 {
        schema_version: 1,
        manifest_id: manifest_id.to_owned(),
        organization_id: session.organization_id.clone(),
        case_id: session.case_id.clone(),
        browser_session_sha256: session.session_sha256.clone(),
        snapshot_sha256: hashes,
        safe_projection_sha256,
        observed_page_count: u32::try_from(snapshots.len())
            .map_err(|_| ResearchError::Resource("snapshot page count overflow".to_owned()))?,
        external_navigation_count,
        browser_download_count,
        browser_form_submit_count,
        manifest_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}
