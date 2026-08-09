use d2i_desktop::{create_pptx_template, inspect_pptx_presentation};
use d2i_office_capability::{canonical_json_bytes, sha256_bytes};
use d2i_presentation_capability::{default_presentation_resource_limits, ZERO_HASH};
use d2i_windows_host::{
    execute_powerpoint_presentation_operation, installed_excel_process_ids,
    installed_powerpoint_process_ids, PowerPointAutomationOperationV1,
};
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct PowerPointLiveReportV1 {
    schema_version: u32,
    powerpoint_executable_sha256: String,
    source_sha256: String,
    destination_sha256: String,
    source_slides: u32,
    destination_slides: u32,
    powerpoint_process_id: u32,
    chart_excel_process_id: u32,
    chart_excel_process_count: u32,
    forced_excel_process_termination: bool,
    powerpoint_visible: bool,
    application_visible_on_private_desktop: bool,
    private_desktop: bool,
    display_alerts: i32,
    automation_security: i32,
    rendered_slides: u32,
    text_overflows: u32,
    residual_owned_powerpoint_processes: u32,
    residual_owned_excel_processes: u32,
    complete: bool,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-400 PowerPoint live E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if !(2..=3).contains(&arguments.len()) {
        return Err(
            "usage: d2i-office400-powerpoint-live-e2e <POWERPNT.EXE> <new-output-root> [approved-template]".to_owned(),
        );
    }
    let powerpoint = PathBuf::from(&arguments[0])
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let root = PathBuf::from(&arguments[1]);
    if !powerpoint.is_file() || root.exists() {
        return Err("PowerPoint executable or output root binding differs".to_owned());
    }
    std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let render = root.join("render");
    std::fs::create_dir(&render).map_err(|error| error.to_string())?;
    let source_extension = arguments
        .get(2)
        .and_then(|value| Path::new(value).extension())
        .and_then(|value| value.to_str())
        .filter(|value| value.eq_ignore_ascii_case("potx"))
        .unwrap_or("pptx");
    let source = root.join(format!("source.{source_extension}"));
    let staged = root.join("staged.pptx");
    let destination = root.join("destination.pptx");
    let report_path = root.join("powerpoint-live-report.json");
    let limits = default_presentation_resource_limits();
    if let Some(template) = arguments.get(2) {
        let template = PathBuf::from(template)
            .canonicalize()
            .map_err(|error| error.to_string())?;
        std::fs::copy(template, &source).map_err(|error| error.to_string())?;
    } else {
        create_pptx_template(&source, "presentation.office400.live", 1, &limits)?;
    }
    let source_snapshot = inspect_pptx_presentation(
        &source,
        "presentation.office400.live",
        "artifact.office400.live",
        1,
        "backend.pptx.file",
        1_000,
        &limits,
    )?;
    let before = installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let before_excel = installed_excel_process_ids().map_err(|error| error.to_string())?;
    let add_receipt = execute_powerpoint_presentation_operation(
        &source,
        &staged,
        &PowerPointAutomationOperationV1::AddSlide {
            title: "2026 July training results".to_owned(),
            body: "Verified PowerPoint live-backend smoke operation".to_owned(),
        },
        None,
    )
    .map_err(|error| error.to_string())?;
    let receipt = execute_powerpoint_presentation_operation(
        &staged,
        &destination,
        &PowerPointAutomationOperationV1::InsertChart {
            slide_index: 2,
            shape_name: "d2i.chart.training-results".to_owned(),
            chart_type: 51,
            categories: vec![
                "Completed".to_owned(),
                "Planned".to_owned(),
                "Pending".to_owned(),
            ],
            values: vec![55, 120, 18],
        },
        Some(&render),
    )
    .map_err(|error| error.to_string())?;
    let after = installed_powerpoint_process_ids().map_err(|error| error.to_string())?;
    let residual = after
        .iter()
        .filter(|process_id| !before.contains(process_id))
        .count();
    let after_excel = installed_excel_process_ids().map_err(|error| error.to_string())?;
    let residual_excel = after_excel
        .iter()
        .filter(|process_id| !before_excel.contains(process_id))
        .count();
    let destination_snapshot = inspect_pptx_presentation(
        &destination,
        "presentation.office400.live",
        "artifact.office400.live",
        2,
        "backend.powerpoint.com",
        2_000,
        &limits,
    )?;
    let exact_image = add_receipt
        .powerpoint_image_path
        .canonicalize()
        .map_err(|error| error.to_string())?
        == powerpoint
        && receipt
            .powerpoint_image_path
            .canonicalize()
            .map_err(|error| error.to_string())?
            == powerpoint;
    let complete = exact_image
        && destination_snapshot.slide_count == source_snapshot.slide_count.saturating_add(1)
        && add_receipt.chart_excel_process_id.is_none()
        && add_receipt.chart_excel_process_ids.is_empty()
        && receipt.chart_excel_process_id.is_some()
        && !receipt.chart_excel_process_ids.is_empty()
        && !add_receipt.visible
        && !receipt.visible
        && add_receipt.application_visible_on_private_desktop
        && receipt.application_visible_on_private_desktop
        && add_receipt.private_desktop
        && receipt.private_desktop
        && add_receipt.display_alerts == 1
        && receipt.display_alerts == 1
        && add_receipt.automation_security == 3
        && receipt.automation_security == 3
        && add_receipt.operation_count == 1
        && receipt.operation_count == 1
        && receipt.rendered_slide_count == destination_snapshot.slide_count
        && receipt.text_overflow_count == 0
        && residual == 0
        && residual_excel == 0;
    if !complete {
        return Err("PowerPoint live receipt or cleanup gate differs".to_owned());
    }
    let mut report = PowerPointLiveReportV1 {
        schema_version: 1,
        powerpoint_executable_sha256: file_hash(&powerpoint)?,
        source_sha256: source_snapshot.source_content_sha256,
        destination_sha256: destination_snapshot.source_content_sha256,
        source_slides: source_snapshot.slide_count,
        destination_slides: destination_snapshot.slide_count,
        powerpoint_process_id: receipt.powerpoint_process_id,
        chart_excel_process_id: receipt
            .chart_excel_process_id
            .ok_or_else(|| "PowerPoint chart did not bind a dedicated Excel process".to_owned())?,
        chart_excel_process_count: u32::try_from(receipt.chart_excel_process_ids.len())
            .map_err(|error| error.to_string())?,
        forced_excel_process_termination: receipt.forced_excel_process_termination,
        powerpoint_visible: receipt.visible,
        application_visible_on_private_desktop: receipt.application_visible_on_private_desktop,
        private_desktop: receipt.private_desktop,
        display_alerts: receipt.display_alerts,
        automation_security: receipt.automation_security,
        rendered_slides: receipt.rendered_slide_count,
        text_overflows: receipt.text_overflow_count,
        residual_owned_powerpoint_processes: u32::try_from(residual)
            .map_err(|error| error.to_string())?,
        residual_owned_excel_processes: u32::try_from(residual_excel)
            .map_err(|error| error.to_string())?,
        complete,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = report_hash(&report)?;
    std::fs::write(
        report_path,
        canonical_json_bytes(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn file_hash(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn report_hash(value: &PowerPointLiveReportV1) -> Result<String, String> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| error.to_string())?
        .as_object()
        .cloned()
        .ok_or_else(|| "PowerPoint live report must be an object".to_owned())?;
    object.remove("report_sha256");
    canonical_json_bytes(&object)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}
