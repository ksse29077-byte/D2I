use crate::{
    import_external_artifact_atomic, inspect_docx_document, inspect_hwpx_document,
    inspect_pptx_presentation, inspect_xlsx_workbook, OfficeWorkspaceStore,
};
use d2i_browser_research::{
    authorize_download_promotion_v1, sha256_bytes, validate_download_bytes_v1,
    AttachmentTrustDecisionV1, AttachmentTrustReportV1, ControlledDownloadReceiptV1,
    DownloadClassV1, DownloadPromotionReceiptV1, DownloadQuarantineRecordV1,
    DownloadValidationReportV1, ResearchError, MAX_INDIVIDUAL_DOWNLOAD_BYTES, ZERO_HASH,
};
use d2i_office_capability::{OfficeArtifactReferenceV1, ZERO_HASH as OFFICE_ZERO_HASH};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResearchDownloadPromotionOutcomeV1 {
    pub artifact: OfficeArtifactReferenceV1,
    pub receipt: DownloadPromotionReceiptV1,
    pub destination_relative_path: String,
}

pub fn create_download_quarantine_record_v1(
    file: &Path,
    record_id: &str,
    organization_id: &str,
    case_id: &str,
    workspace_id: &str,
    receipt: &ControlledDownloadReceiptV1,
    created_at_unix_ms: u64,
) -> Result<DownloadQuarantineRecordV1, String> {
    receipt.validate_seal().map_err(research_error)?;
    let bytes = read_download_file(file)?;
    let file_hash = sha256_bytes(&bytes);
    if file_hash != receipt.pre_trust_sha256
        || bytes.len() as u64 != receipt.bytes_received
        || receipt.quarantine_artifact_id.is_empty()
    {
        return Err("quarantine file differs from its controlled download receipt".to_owned());
    }
    DownloadQuarantineRecordV1 {
        schema_version: 1,
        record_id: record_id.to_owned(),
        organization_id: organization_id.to_owned(),
        case_id: case_id.to_owned(),
        workspace_id: workspace_id.to_owned(),
        quarantine_artifact_id: receipt.quarantine_artifact_id.clone(),
        download_receipt_sha256: receipt.receipt_sha256.clone(),
        pre_trust_sha256: file_hash,
        file_bytes: bytes.len() as u64,
        created_at_unix_ms,
        record_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(research_error)
}

#[allow(clippy::too_many_arguments)]
pub fn run_attachment_trust_report_v1(
    file: &Path,
    raw_source_url: &str,
    report_id: &str,
    source_snapshot_sha256: &str,
    source_link_id: &str,
    quarantine: &DownloadQuarantineRecordV1,
) -> Result<AttachmentTrustReportV1, String> {
    quarantine.validate_seal().map_err(research_error)?;
    let before = read_download_file(file)?;
    if sha256_bytes(&before) != quarantine.pre_trust_sha256
        || before.len() as u64 != quarantine.file_bytes
    {
        return Err("quarantine file changed before Attachment Services".to_owned());
    }
    let observation = d2i_windows_host::check_attachment_trust(file, raw_source_url)
        .map_err(|error| error.to_string())?;
    let (final_hash, final_bytes) = if observation.file_exists_after_save {
        let after = read_download_file(file)?;
        (sha256_bytes(&after), after.len() as u64)
    } else {
        (sha256_bytes(&[]), 0)
    };
    if final_bytes != observation.file_bytes_after_save {
        return Err("Attachment Services file observation is unstable".to_owned());
    }
    let decision = match observation.decision {
        d2i_windows_host::WindowsAttachmentTrustDecision::Enable => {
            AttachmentTrustDecisionV1::Enable
        }
        d2i_windows_host::WindowsAttachmentTrustDecision::Prompt => {
            AttachmentTrustDecisionV1::Prompt
        }
        d2i_windows_host::WindowsAttachmentTrustDecision::Disable => {
            AttachmentTrustDecisionV1::Disable
        }
        d2i_windows_host::WindowsAttachmentTrustDecision::Unavailable => {
            AttachmentTrustDecisionV1::Unavailable
        }
    };
    AttachmentTrustReportV1 {
        schema_version: 1,
        report_id: report_id.to_owned(),
        organization_id: quarantine.organization_id.clone(),
        case_id: quarantine.case_id.clone(),
        quarantine_record_sha256: quarantine.record_sha256.clone(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        source_link_id: source_link_id.to_owned(),
        decision,
        check_policy_hresult: observation.check_policy_hresult,
        save_hresult: observation.save_hresult,
        file_exists_after_save: observation.file_exists_after_save,
        file_bytes_after_save: observation.file_bytes_after_save,
        final_download_sha256: final_hash.clone(),
        file_mutated_by_trust_provider: final_hash != quarantine.pre_trust_sha256,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(research_error)
}

#[allow(clippy::too_many_arguments)]
pub fn validate_quarantined_download_v1(
    file: &Path,
    parser_scratch_root: &Path,
    report_id: &str,
    expected_class: DownloadClassV1,
    declared_content_type: &str,
    sanitized_filename: &str,
    trust: &AttachmentTrustReportV1,
    observed_at_unix_ms: u64,
) -> Result<DownloadValidationReportV1, String> {
    trust.validate_seal().map_err(research_error)?;
    if trust.decision != AttachmentTrustDecisionV1::Enable || !trust.file_exists_after_save {
        return Err(format!(
            "format validation requires an Attachment Services enable decision: decision={:?}, check_policy_hresult={}, save_hresult={}, file_exists_after_save={}",
            trust.decision,
            trust.check_policy_hresult,
            trust.save_hresult,
            trust.file_exists_after_save
        ));
    }
    let bytes = read_download_file(file)?;
    if sha256_bytes(&bytes) != trust.final_download_sha256
        || bytes.len() as u64 != trust.file_bytes_after_save
    {
        return Err("download changed after Attachment Services".to_owned());
    }
    let parser_verified = verify_with_existing_parser(
        file,
        parser_scratch_root,
        expected_class,
        report_id,
        observed_at_unix_ms,
    );
    validate_download_bytes_v1(
        report_id,
        &trust.organization_id,
        &trust.case_id,
        &trust.final_download_sha256,
        expected_class,
        declared_content_type,
        sanitized_filename,
        &bytes,
        parser_verified,
    )
    .map_err(research_error)
}

#[allow(clippy::too_many_arguments)]
pub fn promote_quarantined_download_v1(
    workspace_root: &Path,
    destination_directory_relative_path: &str,
    quarantine_file: &Path,
    workspace_artifact_id: &str,
    workspace_generation: u64,
    promotion_policy_sha256: &str,
    quarantine: &DownloadQuarantineRecordV1,
    trust: &AttachmentTrustReportV1,
    validation: &DownloadValidationReportV1,
    store: &mut OfficeWorkspaceStore,
    receipt_id: &str,
    promoted_at_unix_ms: u64,
) -> Result<ResearchDownloadPromotionOutcomeV1, String> {
    quarantine.validate_seal().map_err(research_error)?;
    trust.validate_seal().map_err(research_error)?;
    validation.validate_seal().map_err(research_error)?;
    if quarantine.organization_id != trust.organization_id
        || quarantine.case_id != trust.case_id
        || quarantine.record_sha256 != trust.quarantine_record_sha256
        || quarantine.workspace_id.is_empty()
    {
        return Err("download promotion chain binding differs".to_owned());
    }
    let filename = d2i_browser_research::semantic_download_filename_v1(
        workspace_artifact_id,
        validation.detected_class,
    )
    .map_err(research_error)?;
    let directory = destination_directory_relative_path.trim_end_matches(['/', '\\']);
    if directory.is_empty() {
        return Err("download promotion destination directory is empty".to_owned());
    }
    let destination_relative_path = format!("{directory}/{filename}");

    // Build the sealed authorization before the filesystem side effect. It remains
    // process-local until the exact imported artifact is re-observed and persisted.
    let receipt = authorize_download_promotion_v1(
        receipt_id,
        &quarantine.workspace_id,
        workspace_artifact_id,
        workspace_generation,
        promotion_policy_sha256,
        trust,
        validation,
        &quarantine.record_sha256,
        &trust.source_snapshot_sha256,
        &trust.source_link_id,
        promoted_at_unix_ms,
    )
    .map_err(research_error)?;
    let mut artifact = import_external_artifact_atomic(
        workspace_root,
        &quarantine.workspace_id,
        workspace_artifact_id,
        quarantine_file,
        &destination_relative_path,
        &trust.final_download_sha256,
        workspace_generation,
        MAX_INDIVIDUAL_DOWNLOAD_BYTES,
    )?;
    artifact.data_class_ids = vec!["external-untrusted-artifact".to_owned()];
    artifact.evidence_ids = vec![
        trust.report_sha256.clone(),
        validation.report_sha256.clone(),
        quarantine.record_sha256.clone(),
    ];
    artifact.artifact_sha256 = OFFICE_ZERO_HASH.to_owned();
    artifact = artifact.seal().map_err(|error| error.to_string())?;
    store.append(
        "external-artifact",
        workspace_artifact_id,
        &artifact,
        promoted_at_unix_ms,
    )?;
    store.append(
        "download-promotion",
        receipt_id,
        &receipt,
        promoted_at_unix_ms,
    )?;
    fs::remove_file(quarantine_file).map_err(|error| {
        format!("promoted quarantine artifact cleanup requires recovery: {error}")
    })?;
    Ok(ResearchDownloadPromotionOutcomeV1 {
        artifact,
        receipt,
        destination_relative_path,
    })
}

fn verify_with_existing_parser(
    file: &Path,
    scratch_root: &Path,
    class: DownloadClassV1,
    parser_identity: &str,
    observed_at_unix_ms: u64,
) -> bool {
    match class {
        DownloadClassV1::Docx => inspect_docx_document(
            file,
            "document.external-download",
            "artifact.external-download",
            1,
            "backend.docx.bounded-parser",
            observed_at_unix_ms,
            &crate::default_document_resource_limits(),
        )
        .is_ok(),
        DownloadClassV1::Hwpx => inspect_hwpx_document(
            file,
            "document.external-download",
            "artifact.external-download",
            1,
            "backend.hwpx.bounded-parser",
            observed_at_unix_ms,
            &crate::default_document_resource_limits(),
        )
        .is_ok(),
        DownloadClassV1::Xlsx => inspect_xlsx_workbook(
            file,
            "workbook.external-download",
            "artifact.external-download",
            1,
            "backend.xlsx.bounded-parser",
            observed_at_unix_ms,
            &d2i_spreadsheet_capability::default_spreadsheet_resource_limits(),
        )
        .is_ok(),
        DownloadClassV1::Pptx => inspect_pptx_presentation(
            file,
            "presentation.external-download",
            "artifact.external-download",
            1,
            "backend.pptx.bounded-parser",
            observed_at_unix_ms,
            &d2i_presentation_capability::default_presentation_resource_limits(),
        )
        .is_ok(),
        DownloadClassV1::Pdf => verify_external_pdf(file, scratch_root, parser_identity),
        DownloadClassV1::Txt
        | DownloadClassV1::Csv
        | DownloadClassV1::Png
        | DownloadClassV1::Jpeg => true,
        DownloadClassV1::Unknown => false,
    }
}

fn verify_external_pdf(file: &Path, scratch_root: &Path, parser_identity: &str) -> bool {
    let metadata = match fs::metadata(file) {
        Ok(value) if value.len() <= d2i_pdf_interchange::MAX_EXTERNAL_PDF_BYTES => value,
        _ => return false,
    };
    if metadata.len() == 0 || !scratch_root.is_dir() {
        return false;
    }
    let safe_identity = parser_identity
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .take(32)
        .map(char::from)
        .collect::<String>();
    let output = scratch_root.join(format!("pdf-validation-{safe_identity}"));
    if output.exists() || fs::create_dir(&output).is_err() {
        return false;
    }
    let result = d2i_windows_host::render_pdf_with_windows_data_pdf(
        file,
        &output,
        d2i_pdf_interchange::MAX_EXTERNAL_PDF_PAGES,
        100_000_000,
        1_800,
    )
    .is_ok();
    let cleanup = fs::remove_dir_all(&output).is_ok();
    result && cleanup
}

fn read_download_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !path.is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_INDIVIDUAL_DOWNLOAD_BYTES
    {
        return Err("download path is not a bounded absolute regular file".to_owned());
    }
    if d2i_windows_host::is_reparse_point(path).map_err(|error| error.to_string())? {
        return Err("download path cannot be a reparse point".to_owned());
    }
    fs::read(path).map_err(|error| error.to_string())
}

fn research_error(error: ResearchError) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parser_rejects_unknown_binary() -> Result<(), Box<dyn std::error::Error>> {
        let root = temporary_root("unknown-binary");
        fs::create_dir_all(&root)?;
        let file = root.join("artifact.bin");
        fs::write(&file, [0_u8, 1, 2, 3])?;
        assert!(!verify_with_existing_parser(
            &file,
            &root,
            DownloadClassV1::Unknown,
            "parser.unknown",
            1_000,
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn temporary_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("d2i-office600-{label}-{}", std::process::id()))
    }
}
