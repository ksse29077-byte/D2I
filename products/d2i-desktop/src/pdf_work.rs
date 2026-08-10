use d2i_pdf_interchange::{
    pdf_canonical_sha256, PdfDocumentSnapshotV1, PdfOriginClassV1, PdfPageSnapshotV1,
    PdfRenderRequestV1, PdfRenderResultV1, PdfVerificationStatusV1, PdfVisualFingerprintV1,
    ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativePdfExportWorkerEvidenceV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub process_id: u32,
    pub source_page_or_visible_unit_count: u32,
    pub hidden_unit_count: u32,
    pub private_desktop: bool,
    pub application_visible_on_private_desktop: bool,
    pub network_denied: bool,
    pub pdfa_requested: bool,
    pub exporter_pdfa_flag: bool,
    pub output_pdf_sha256: String,
    pub output_pdf_bytes: u64,
    pub output_fresh_and_stable: bool,
    pub forced_process_termination: bool,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfRenderWorkerEvidenceV1 {
    pub schema_version: u32,
    pub external_untrusted: bool,
    pub render_request: PdfRenderRequestV1,
    pub visual_fingerprints: Vec<PdfVisualFingerprintV1>,
    pub document_snapshot: PdfDocumentSnapshotV1,
    pub render_result: PdfRenderResultV1,
    pub pdf_load_microseconds: u64,
    pub render_microseconds: u64,
    pub evidence_sha256: String,
}

pub fn word_pdf_export_worker_main() -> i32 {
    worker_exit(run_word_pdf_export_worker())
}

pub fn excel_pdf_export_worker_main() -> i32 {
    worker_exit(run_excel_pdf_export_worker())
}

pub fn powerpoint_pdf_export_worker_main() -> i32 {
    worker_exit(run_powerpoint_pdf_export_worker())
}

pub fn pdf_render_worker_main() -> i32 {
    let failure_report = std::env::args_os().nth(5).map(PathBuf::from);
    match run_pdf_render_worker() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            if let Some(path) = failure_report {
                let bounded = error.chars().take(2_048).collect::<String>();
                let _ = fs::write(path, bounded.as_bytes());
            }
            1
        }
    }
}

fn worker_exit(result: Result<(), String>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_word_pdf_export_worker() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err(
            "usage: word-pdf-worker <source.docx> <output.pdf> <pdfa:true|false> <report.json>"
                .to_owned(),
        );
    }
    let source = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let pdfa = parse_bool(&arguments[2])?;
    let report = PathBuf::from(&arguments[3]);
    let receipt = d2i_windows_host::export_word_document_pdf(&source, &output, pdfa)
        .map_err(|error| error.to_string())?;
    write_export_evidence(
        &report,
        NativePdfExportWorkerEvidenceV1 {
            schema_version: 1,
            backend_id: "word_fixed_pdf".to_owned(),
            process_id: receipt.word_process_id,
            source_page_or_visible_unit_count: receipt.page_count,
            hidden_unit_count: 0,
            private_desktop: receipt.private_desktop,
            application_visible_on_private_desktop: receipt.visible,
            network_denied: true,
            pdfa_requested: pdfa,
            exporter_pdfa_flag: pdfa,
            output_pdf_sha256: file_sha256(&output)?,
            output_pdf_bytes: file_bytes(&output)?,
            output_fresh_and_stable: receipt.output_fresh_and_stable,
            forced_process_termination: false,
            evidence_sha256: ZERO_HASH.to_owned(),
        },
    )
}

fn run_excel_pdf_export_worker() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("usage: excel-pdf-worker <source.xlsx> <output.pdf> <excel.exe> <pdfa:true|false> <report.json>".to_owned());
    }
    let source = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let excel = PathBuf::from(&arguments[2]);
    let pdfa = parse_bool(&arguments[3])?;
    let report = PathBuf::from(&arguments[4]);
    let receipt = d2i_windows_host::export_excel_workbook_pdf(&source, &output, &excel, pdfa)
        .map_err(|error| error.to_string())?;
    write_export_evidence(
        &report,
        NativePdfExportWorkerEvidenceV1 {
            schema_version: 1,
            backend_id: "excel_fixed_pdf".to_owned(),
            process_id: receipt.excel_process_id,
            source_page_or_visible_unit_count: receipt.visible_sheet_count,
            hidden_unit_count: receipt.hidden_sheet_count,
            private_desktop: receipt.private_desktop,
            application_visible_on_private_desktop: receipt.visible,
            network_denied: true,
            pdfa_requested: pdfa,
            exporter_pdfa_flag: false,
            output_pdf_sha256: file_sha256(&output)?,
            output_pdf_bytes: file_bytes(&output)?,
            output_fresh_and_stable: receipt.output_fresh_and_stable,
            forced_process_termination: receipt.forced_process_termination,
            evidence_sha256: ZERO_HASH.to_owned(),
        },
    )
}

fn run_powerpoint_pdf_export_worker() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 4 {
        return Err("usage: powerpoint-pdf-worker <source.pptx> <output.pdf> <pdfa:true|false> <report.json>".to_owned());
    }
    let source = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let pdfa = parse_bool(&arguments[2])?;
    let report = PathBuf::from(&arguments[3]);
    let receipt = d2i_windows_host::export_powerpoint_presentation_pdf(&source, &output, pdfa)
        .map_err(|error| error.to_string())?;
    write_export_evidence(
        &report,
        NativePdfExportWorkerEvidenceV1 {
            schema_version: 1,
            backend_id: "powerpoint_fixed_pdf".to_owned(),
            process_id: receipt.powerpoint_process_id,
            source_page_or_visible_unit_count: receipt.visible_slide_count,
            hidden_unit_count: receipt.hidden_slide_count,
            private_desktop: receipt.private_desktop,
            application_visible_on_private_desktop: receipt.application_visible_on_private_desktop,
            network_denied: true,
            pdfa_requested: pdfa,
            exporter_pdfa_flag: pdfa,
            output_pdf_sha256: file_sha256(&output)?,
            output_pdf_bytes: file_bytes(&output)?,
            output_fresh_and_stable: receipt.output_fresh_and_stable,
            forced_process_termination: false,
            evidence_sha256: ZERO_HASH.to_owned(),
        },
    )
}

fn run_pdf_render_worker() -> Result<(), String> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 5 {
        return Err("usage: pdf-render-worker <input.pdf> <png-directory> <expected-pdf-sha256> <external:true|false> <report.json>".to_owned());
    }
    let pdf = PathBuf::from(&arguments[0]);
    let output = PathBuf::from(&arguments[1]);
    let expected = arguments[2].to_string_lossy().to_string();
    let external = parse_bool(&arguments[3])?;
    let report = PathBuf::from(&arguments[4]);
    if file_sha256(&pdf)? != expected {
        return Err("PDF renderer source hash differs".to_owned());
    }
    let maximum_pages = if external { 100 } else { 500 };
    let now = unix_milliseconds()?;
    let request = PdfRenderRequestV1 {
        schema_version: 1,
        request_id: if external {
            "render-request.external-pdf.1"
        } else {
            "render-request.generated-pdf.1"
        }
        .to_owned(),
        expected_pdf_sha256: expected.clone(),
        external_untrusted: external,
        maximum_pages,
        maximum_pdf_bytes: if external {
            128 * 1024 * 1024
        } else {
            512 * 1024 * 1024
        },
        maximum_total_pixels: if external { 100_000_000 } else { 500_000_000 },
        maximum_page_width_millipoints: 2_000_000,
        maximum_page_height_millipoints: 2_000_000,
        maximum_output_png_bytes: 128 * 1024 * 1024,
        maximum_worker_memory_bytes: 768 * 1024 * 1024,
        maximum_page_render_milliseconds: 30_000,
        maximum_total_render_milliseconds: 120_000,
        destination_width_pixels: 1_800,
        issued_at_unix_ms: now,
        deadline_unix_ms: now.saturating_add(120_000),
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    request
        .validate_limits(file_bytes(&pdf)?, now)
        .map_err(|error| error.to_string())?;
    let receipt = d2i_windows_host::render_pdf_with_windows_data_pdf(
        &pdf,
        &output,
        maximum_pages,
        request.maximum_total_pixels,
        request.destination_width_pixels,
    )
    .map_err(|error| error.to_string())?;
    let pdf_load_microseconds = receipt.pdf_load_microseconds;
    let render_microseconds = receipt.render_microseconds;
    let mut pages = Vec::with_capacity(receipt.pages.len());
    let mut visual_fingerprints = Vec::with_capacity(receipt.pages.len());
    for page in receipt.pages {
        let fingerprint = PdfVisualFingerprintV1 {
            schema_version: 1,
            fingerprint_id: format!("fingerprint.pdf.page.{}", page.page_index),
            rendered_png_sha256: page.rendered_png_sha256.clone(),
            non_white_pixel_millionths: page.non_white_pixel_millionths,
            luminance_buckets: page.luminance_buckets,
            color_buckets: page.color_buckets,
            edge_buckets: page.edge_buckets,
            occupancy_buckets: page.occupancy_buckets,
            perceptual_hash_sha256: pdf_canonical_sha256(&(
                page.rendered_png_sha256.clone(),
                page.non_white_pixel_millionths,
            ))
            .map_err(|error| error.to_string())?,
            fingerprint_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| error.to_string())?;
        pages.push(
            PdfPageSnapshotV1 {
                page_index: page.page_index,
                width_millipoints: page.width_millipoints,
                height_millipoints: page.height_millipoints,
                rotation_degrees: page.rotation_degrees,
                rendered_width_pixels: page.rendered_width_pixels,
                rendered_height_pixels: page.rendered_height_pixels,
                rendered_png_sha256: page.rendered_png_sha256,
                visual_fingerprint_sha256: fingerprint.fingerprint_sha256.clone(),
                non_white_pixel_millionths: page.non_white_pixel_millionths,
                blankness_millionths: 1_000_000_u32.saturating_sub(page.non_white_pixel_millionths),
                page_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?,
        );
        visual_fingerprints.push(fingerprint);
    }
    let snapshot = PdfDocumentSnapshotV1 {
        schema_version: 1,
        snapshot_id: if external {
            "snapshot.external-pdf.render-only"
        } else {
            "snapshot.generated-pdf.verified"
        }
        .to_owned(),
        pdf_artifact_id: if external {
            "artifact.external-pdf.render-only"
        } else {
            "artifact.generated-pdf.verified"
        }
        .to_owned(),
        pdf_generation: 1,
        origin_class: if external {
            PdfOriginClassV1::ExternalUntrusted
        } else {
            PdfOriginClassV1::D2iGenerated
        },
        pdf_sha256: expected.clone(),
        pdf_file_bytes: file_bytes(&pdf)?,
        page_count: receipt.page_count,
        password_protected: receipt.password_protected,
        pages,
        export_pair_ref: None,
        renderer_build_id: "windows.data.pdf.v1".to_owned(),
        renderer_executable_sha256: current_executable_sha256()?,
        observed_at_unix_ms: now,
        freshness_expires_at_unix_ms: now.saturating_add(120_000),
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let result = PdfRenderResultV1 {
        schema_version: 1,
        result_id: "result.windows-pdf-render.1".to_owned(),
        request_sha256: request.request_sha256.clone(),
        pdf_sha256: expected,
        document_snapshot_sha256: snapshot.snapshot_sha256.clone(),
        rendered_page_count: snapshot.page_count,
        rendered_total_pixels: receipt.total_rendered_pixels,
        status: if external {
            PdfVerificationStatusV1::RenderOnly
        } else {
            PdfVerificationStatusV1::Passed
        },
        failure_code: if external {
            d2i_pdf_interchange::PdfFailureCodeV1::ExternalPdfRenderOnly
        } else {
            d2i_pdf_interchange::PdfFailureCodeV1::None
        },
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let mut evidence = PdfRenderWorkerEvidenceV1 {
        schema_version: 1,
        external_untrusted: external,
        render_request: request,
        visual_fingerprints,
        document_snapshot: snapshot,
        render_result: result,
        pdf_load_microseconds,
        render_microseconds,
        evidence_sha256: ZERO_HASH.to_owned(),
    };
    evidence.evidence_sha256 = evidence_hash(&evidence)?;
    write_new_json(&report, &evidence)
}

fn unix_milliseconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|error| error.to_string())
}

fn write_export_evidence(
    path: &Path,
    mut value: NativePdfExportWorkerEvidenceV1,
) -> Result<(), String> {
    value.evidence_sha256 = evidence_hash(&value)?;
    write_new_json(path, &value)
}

fn evidence_hash<T: Serialize>(value: &T) -> Result<String, String> {
    let mut value = serde_json::to_value(value).map_err(|error| error.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "worker evidence is not an object".to_owned())?;
    if object
        .insert(
            "evidence_sha256".to_owned(),
            serde_json::Value::String(ZERO_HASH.to_owned()),
        )
        .is_none()
    {
        return Err("worker evidence hash field is absent".to_owned());
    }
    pdf_canonical_sha256(&value).map_err(|error| error.to_string())
}

fn write_new_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if path.exists() || !path.parent().is_some_and(Path::is_dir) {
        return Err("worker report path is not a new file in an existing directory".to_owned());
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| error.to_string())
}

fn parse_bool(value: &std::ffi::OsStr) -> Result<bool, String> {
    match value.to_string_lossy().as_ref() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err("boolean worker argument must be true or false".to_owned()),
    }
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn file_bytes(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|value| value.len())
        .map_err(|error| error.to_string())
}

fn current_executable_sha256() -> Result<String, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    file_sha256(&executable)
}
