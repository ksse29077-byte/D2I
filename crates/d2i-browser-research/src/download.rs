use crate::validation::{sha256_bytes, validate_hash, validate_id};
use crate::{
    AttachmentTrustDecisionV1, AttachmentTrustReportV1, ControlledDownloadIntentV1,
    DownloadClassV1, DownloadPromotionReceiptV1, DownloadPromotionStatusV1,
    DownloadValidationReportV1, DownloadValidationStatusV1, ResearchError, ResearchSourcePolicyV1,
    ZERO_HASH,
};
use std::io::{Cursor, Read};
use zip::ZipArchive;

pub const MAX_DOWNLOADS_PER_CASE: u32 = 8;
pub const MAX_INDIVIDUAL_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_TOTAL_DOWNLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 4096;
const MAX_PACKAGE_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_IMAGE_PIXELS: u64 = 100_000_000;

pub fn validate_controlled_download_intent_v1(
    intent: &ControlledDownloadIntentV1,
    source_policy: &ResearchSourcePolicyV1,
    brief_download_allowed: bool,
) -> Result<(), ResearchError> {
    intent.validate_seal()?;
    validate_id(&intent.intent_id, "download intent ID")?;
    validate_id(&intent.organization_id, "download intent organization")?;
    validate_id(&intent.case_id, "download intent Case")?;
    validate_id(&intent.source_link_id, "download source link")?;
    validate_hash(&intent.source_snapshot_sha256, "download source snapshot")?;
    if intent.schema_version != 1
        || !brief_download_allowed
        || intent.maximum_bytes == 0
        || intent.maximum_bytes > MAX_INDIVIDUAL_DOWNLOAD_BYTES
        || intent.expected_class == DownloadClassV1::Unknown
        || !source_policy
            .allowed_download_classes
            .contains(&intent.expected_class)
    {
        return Err(ResearchError::AccessDenied(
            "controlled download intent is not eligible".to_owned(),
        ));
    }
    Ok(())
}

pub fn sanitize_download_filename_v1(value: &str) -> Result<String, ResearchError> {
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 255
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\', ':'])
        || value.contains("..")
        || value.ends_with(['.', ' '])
        || [
            ".exe", ".com", ".scr", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse",
            ".wsf", ".hta", ".lnk", ".url", ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z",
            ".tar", ".gz", ".iso", ".vhd", ".vhdx",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
    {
        return Err(ResearchError::AccessDenied(
            "download filename contains traversal, ADS, control, or unsafe suffix".to_owned(),
        ));
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "clock$"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    ) {
        return Err(ResearchError::AccessDenied(
            "download filename is a Windows device name".to_owned(),
        ));
    }
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() || matches!(character, '.' | '-' | '_' | ' ') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        return Err(ResearchError::Invalid(
            "download filename becomes empty after sanitization".to_owned(),
        ));
    }
    Ok(sanitized)
}

pub fn semantic_download_filename_v1(
    artifact_id: &str,
    class: DownloadClassV1,
) -> Result<String, ResearchError> {
    validate_id(artifact_id, "download artifact ID")?;
    let extension = extension_for_class(class)
        .ok_or_else(|| ResearchError::Unsupported("unknown download class".to_owned()))?;
    let filesystem_stem = artifact_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(format!("{filesystem_stem}.{extension}"))
}

#[allow(clippy::too_many_arguments)]
pub fn validate_download_bytes_v1(
    report_id: &str,
    organization_id: &str,
    case_id: &str,
    final_download_sha256: &str,
    expected_class: DownloadClassV1,
    declared_content_type: &str,
    sanitized_filename: &str,
    bytes: &[u8],
    external_parser_verified: bool,
) -> Result<DownloadValidationReportV1, ResearchError> {
    validate_id(report_id, "download validation report ID")?;
    validate_id(organization_id, "download validation organization")?;
    validate_id(case_id, "download validation Case")?;
    validate_hash(final_download_sha256, "final download hash")?;
    if sha256_bytes(bytes) != final_download_sha256 {
        return Err(ResearchError::Integrity(
            "download bytes differ from post-trust hash".to_owned(),
        ));
    }
    if bytes.is_empty() || bytes.len() as u64 > MAX_INDIVIDUAL_DOWNLOAD_BYTES {
        return Err(ResearchError::Resource(
            "download is empty or exceeds individual limit".to_owned(),
        ));
    }
    let sanitized = sanitize_download_filename_v1(sanitized_filename)?;
    if sanitized != sanitized_filename {
        return Err(ResearchError::Invalid(
            "download validation requires the canonical sanitized filename".to_owned(),
        ));
    }
    let inspection = inspect_download(bytes, sanitized_filename)?;
    let extension_matches = extension_for_class(inspection.class)
        .map(|extension| {
            sanitized_filename
                .to_ascii_lowercase()
                .ends_with(&format!(".{extension}"))
        })
        .unwrap_or(false);
    let mime_matches = content_type_matches(inspection.class, declared_content_type);
    let magic_matches = inspection.class != DownloadClassV1::Unknown;
    let parser_verified = inspection.parser_verified || external_parser_verified;
    let mut reasons = inspection.reason_codes;
    if inspection.class != expected_class {
        reasons.push("detected_class_differs".to_owned());
    }
    if !extension_matches {
        reasons.push("extension_differs".to_owned());
    }
    if !mime_matches {
        reasons.push("content_type_differs".to_owned());
    }
    if !magic_matches {
        reasons.push("magic_unrecognized".to_owned());
    }
    if !inspection.macro_free {
        reasons.push("macro_enabled_package".to_owned());
    }
    if !inspection.package_safe {
        reasons.push("package_security_failed".to_owned());
    }
    if !parser_verified {
        reasons.push("format_parser_not_verified".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    let status = if reasons.is_empty() {
        DownloadValidationStatusV1::Passed
    } else {
        DownloadValidationStatusV1::Rejected
    };
    DownloadValidationReportV1 {
        schema_version: 1,
        report_id: report_id.to_owned(),
        organization_id: organization_id.to_owned(),
        case_id: case_id.to_owned(),
        final_download_sha256: final_download_sha256.to_owned(),
        expected_class,
        detected_class: inspection.class,
        declared_content_type: declared_content_type.to_owned(),
        sanitized_filename: sanitized_filename.to_owned(),
        extension_matches,
        mime_matches,
        magic_matches,
        macro_free: inspection.macro_free,
        package_safe: inspection.package_safe,
        parser_verified,
        status,
        reason_codes: reasons,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

#[allow(clippy::too_many_arguments)]
pub fn authorize_download_promotion_v1(
    receipt_id: &str,
    workspace_id: &str,
    workspace_artifact_id: &str,
    workspace_generation: u64,
    promotion_policy_sha256: &str,
    trust: &AttachmentTrustReportV1,
    validation: &DownloadValidationReportV1,
    quarantine_record_sha256: &str,
    source_snapshot_sha256: &str,
    source_link_id: &str,
    promoted_at_unix_ms: u64,
) -> Result<DownloadPromotionReceiptV1, ResearchError> {
    trust.validate_seal()?;
    validation.validate_seal()?;
    if trust.organization_id != validation.organization_id
        || trust.case_id != validation.case_id
        || trust.final_download_sha256 != validation.final_download_sha256
        || trust.quarantine_record_sha256 != quarantine_record_sha256
        || trust.source_snapshot_sha256 != source_snapshot_sha256
        || trust.source_link_id != source_link_id
        || trust.decision != AttachmentTrustDecisionV1::Enable
        || !trust.file_exists_after_save
        || validation.status != DownloadValidationStatusV1::Passed
        || workspace_generation == 0
    {
        return Err(ResearchError::AccessDenied(
            "download promotion requires enable trust and passed format validation".to_owned(),
        ));
    }
    validate_id(workspace_id, "promotion workspace ID")?;
    validate_id(workspace_artifact_id, "promotion artifact ID")?;
    validate_hash(promotion_policy_sha256, "promotion policy hash")?;
    validate_hash(quarantine_record_sha256, "quarantine record hash")?;
    validate_hash(source_snapshot_sha256, "promotion source snapshot")?;
    DownloadPromotionReceiptV1 {
        schema_version: 1,
        receipt_id: receipt_id.to_owned(),
        organization_id: trust.organization_id.clone(),
        case_id: trust.case_id.clone(),
        workspace_id: workspace_id.to_owned(),
        quarantine_record_sha256: quarantine_record_sha256.to_owned(),
        attachment_trust_report_sha256: trust.report_sha256.clone(),
        validation_report_sha256: validation.report_sha256.clone(),
        final_download_sha256: trust.final_download_sha256.clone(),
        source_snapshot_sha256: source_snapshot_sha256.to_owned(),
        source_link_id: source_link_id.to_owned(),
        workspace_artifact_id: workspace_artifact_id.to_owned(),
        workspace_generation,
        promotion_policy_sha256: promotion_policy_sha256.to_owned(),
        status: DownloadPromotionStatusV1::Promoted,
        promoted_at_unix_ms,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

struct DownloadInspection {
    class: DownloadClassV1,
    macro_free: bool,
    package_safe: bool,
    parser_verified: bool,
    reason_codes: Vec<String>,
}

fn inspect_download(bytes: &[u8], filename: &str) -> Result<DownloadInspection, ResearchError> {
    if bytes.starts_with(b"MZ") {
        return Ok(rejected_inspection("executable_magic_forbidden"));
    }
    if bytes.starts_with(b"%PDF-") {
        return Ok(DownloadInspection {
            class: DownloadClassV1::Pdf,
            macro_free: true,
            package_safe: true,
            parser_verified: false,
            reason_codes: Vec::new(),
        });
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        let valid = validate_png_dimensions(bytes)?;
        return Ok(DownloadInspection {
            class: DownloadClassV1::Png,
            macro_free: true,
            package_safe: valid,
            parser_verified: valid,
            reason_codes: if valid {
                Vec::new()
            } else {
                vec!["image_pixel_budget".to_owned()]
            },
        });
    }
    if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        let valid = validate_jpeg_dimensions(bytes)?;
        return Ok(DownloadInspection {
            class: DownloadClassV1::Jpeg,
            macro_free: true,
            package_safe: valid,
            parser_verified: valid,
            reason_codes: if valid {
                Vec::new()
            } else {
                vec!["image_pixel_budget".to_owned()]
            },
        });
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return inspect_office_package(bytes);
    }
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return Ok(rejected_inspection("unknown_binary_format"));
    }
    let line_count = bytes
        .iter()
        .filter(|byte| **byte == b'\n')
        .count()
        .saturating_add(1);
    if line_count > 1_000_000 {
        return Ok(rejected_inspection("text_line_budget_exceeded"));
    }
    let class = if filename.to_ascii_lowercase().ends_with(".csv") {
        DownloadClassV1::Csv
    } else {
        DownloadClassV1::Txt
    };
    Ok(DownloadInspection {
        class,
        macro_free: true,
        package_safe: true,
        parser_verified: true,
        reason_codes: Vec::new(),
    })
}

fn inspect_office_package(bytes: &[u8]) -> Result<DownloadInspection, ResearchError> {
    let mut archive = ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| ResearchError::Invalid("ZIP package cannot be parsed".to_owned()))?;
    if archive.is_empty() || archive.len() > MAX_PACKAGE_ENTRIES {
        return Ok(rejected_inspection("package_entry_budget"));
    }
    let mut names = Vec::with_capacity(archive.len());
    let mut total_uncompressed = 0_u64;
    let mut macro_free = true;
    let mut package_safe = true;
    let mut mimetype = String::new();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| ResearchError::Invalid("ZIP entry cannot be read".to_owned()))?;
        let name = entry.name().replace('\\', "/");
        if name.starts_with('/')
            || name.split('/').any(|part| part == "..")
            || name.contains(':')
            || entry.enclosed_name().is_none()
        {
            package_safe = false;
        }
        let lower = name.to_ascii_lowercase();
        if lower.ends_with("vbaproject.bin")
            || lower.contains("macroenabled")
            || lower.ends_with(".exe")
            || lower.ends_with(".dll")
        {
            macro_free = false;
        }
        if lower.contains("externallinks/")
            || lower.ends_with("connections.xml")
            || lower.contains("oleobjects/")
        {
            package_safe = false;
        }
        total_uncompressed = total_uncompressed.saturating_add(entry.size());
        if total_uncompressed > MAX_PACKAGE_UNCOMPRESSED_BYTES
            || (entry.compressed_size() > 0 && entry.size() / entry.compressed_size().max(1) > 200)
        {
            package_safe = false;
        }
        if lower.ends_with(".rels") {
            if entry.size() > 8 * 1024 * 1024 {
                package_safe = false;
            } else {
                let mut relationships = String::new();
                let read_failed = entry.read_to_string(&mut relationships).is_err();
                let relationships = relationships.to_ascii_lowercase();
                if read_failed
                    || relationships.contains("targetmode=\"external\"")
                    || relationships.contains("targetmode='external'")
                {
                    package_safe = false;
                }
            }
        } else if lower == "mimetype" && entry.size() <= 256 {
            entry
                .read_to_string(&mut mimetype)
                .map_err(|_| ResearchError::Invalid("package mimetype is invalid".to_owned()))?;
        }
        names.push(lower);
    }
    let class = if names.iter().any(|name| name == "word/document.xml") {
        DownloadClassV1::Docx
    } else if names.iter().any(|name| name == "xl/workbook.xml") {
        DownloadClassV1::Xlsx
    } else if names.iter().any(|name| name == "ppt/presentation.xml") {
        DownloadClassV1::Pptx
    } else if names.iter().any(|name| name == "contents/content.hpf")
        || mimetype.trim() == "application/hwp+zip"
    {
        DownloadClassV1::Hwpx
    } else {
        DownloadClassV1::Unknown
    };
    let mut reasons = Vec::new();
    if class == DownloadClassV1::Unknown {
        reasons.push("generic_archive_forbidden".to_owned());
    }
    Ok(DownloadInspection {
        class,
        macro_free,
        package_safe,
        parser_verified: class != DownloadClassV1::Unknown && macro_free && package_safe,
        reason_codes: reasons,
    })
}

fn validate_png_dimensions(bytes: &[u8]) -> Result<bool, ResearchError> {
    if bytes.len() < 24 || &bytes[12..16] != b"IHDR" {
        return Ok(false);
    }
    let width = u32::from_be_bytes(
        bytes[16..20]
            .try_into()
            .map_err(|_| ResearchError::Invalid("PNG width cannot be decoded".to_owned()))?,
    ) as u64;
    let height = u32::from_be_bytes(
        bytes[20..24]
            .try_into()
            .map_err(|_| ResearchError::Invalid("PNG height cannot be decoded".to_owned()))?,
    ) as u64;
    Ok(width > 0 && height > 0 && width.saturating_mul(height) <= MAX_IMAGE_PIXELS)
}

fn validate_jpeg_dimensions(bytes: &[u8]) -> Result<bool, ResearchError> {
    let mut index = 2_usize;
    while index + 9 < bytes.len() {
        if bytes[index] != 0xff {
            index += 1;
            continue;
        }
        let marker = bytes[index + 1];
        index += 2;
        if matches!(marker, 0xd8 | 0xd9) {
            continue;
        }
        if index + 2 > bytes.len() {
            return Ok(false);
        }
        let length = u16::from_be_bytes([bytes[index], bytes[index + 1]]) as usize;
        if length < 2 || index + length > bytes.len() {
            return Ok(false);
        }
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            if length < 7 {
                return Ok(false);
            }
            let height = u16::from_be_bytes([bytes[index + 3], bytes[index + 4]]) as u64;
            let width = u16::from_be_bytes([bytes[index + 5], bytes[index + 6]]) as u64;
            return Ok(width > 0 && height > 0 && width.saturating_mul(height) <= MAX_IMAGE_PIXELS);
        }
        index += length;
    }
    Ok(false)
}

fn rejected_inspection(reason: &str) -> DownloadInspection {
    DownloadInspection {
        class: DownloadClassV1::Unknown,
        macro_free: false,
        package_safe: false,
        parser_verified: false,
        reason_codes: vec![reason.to_owned()],
    }
}

fn extension_for_class(class: DownloadClassV1) -> Option<&'static str> {
    match class {
        DownloadClassV1::Pdf => Some("pdf"),
        DownloadClassV1::Docx => Some("docx"),
        DownloadClassV1::Hwpx => Some("hwpx"),
        DownloadClassV1::Xlsx => Some("xlsx"),
        DownloadClassV1::Pptx => Some("pptx"),
        DownloadClassV1::Txt => Some("txt"),
        DownloadClassV1::Csv => Some("csv"),
        DownloadClassV1::Png => Some("png"),
        DownloadClassV1::Jpeg => Some("jpg"),
        DownloadClassV1::Unknown => None,
    }
}

fn content_type_matches(class: DownloadClassV1, value: &str) -> bool {
    let value = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match class {
        DownloadClassV1::Pdf => value == "application/pdf",
        DownloadClassV1::Docx => {
            value == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        DownloadClassV1::Hwpx => {
            matches!(value.as_str(), "application/hwp+zip" | "application/zip")
        }
        DownloadClassV1::Xlsx => {
            value == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        DownloadClassV1::Pptx => {
            value == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        }
        DownloadClassV1::Txt => matches!(value.as_str(), "text/plain" | "application/octet-stream"),
        DownloadClassV1::Csv => matches!(
            value.as_str(),
            "text/csv" | "application/csv" | "text/plain"
        ),
        DownloadClassV1::Png => value == "image/png",
        DownloadClassV1::Jpeg => value == "image/jpeg",
        DownloadClassV1::Unknown => false,
    }
}
