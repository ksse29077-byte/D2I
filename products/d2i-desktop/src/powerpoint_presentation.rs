use crate::pptx_presentation::{inspect_pptx_presentation, verify_pptx_chart_facts};
use d2i_presentation_capability::{
    parse_presentation_json_strict, PresentationChartKindV1, PresentationFactBindingV1,
    PresentationMutationV1, PresentationResourceLimitsV1, PresentationSemanticSnapshotV1,
};
use d2i_spreadsheet_capability::SpreadsheetScalarV1;
use d2i_windows_host::{
    execute_powerpoint_presentation_operation, PowerPointAutomationOperationV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerPointPresentationWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub workspace_root: String,
    pub expected_source_sha256: String,
    pub powerpoint_executable_path: String,
    pub expected_powerpoint_sha256: String,
    pub presentation_id: String,
    pub artifact_id: String,
    pub generation: u64,
    pub backend_id: String,
    pub observed_at_unix_ms: u64,
    pub mutation: PresentationMutationV1,
    pub facts: PresentationFactBindingV1,
    pub render_directory: Option<String>,
    pub limits: PresentationResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerPointPresentationMutationReceiptV1 {
    pub schema_version: u32,
    pub source_content_sha256: String,
    pub destination_content_sha256: String,
    pub destination_semantic_sha256: String,
    pub powerpoint_process_id: u32,
    pub chart_excel_process_id: Option<u32>,
    pub chart_excel_process_ids: Vec<u32>,
    pub powerpoint_visible: bool,
    pub application_visible_on_private_desktop: bool,
    pub private_desktop: bool,
    pub display_alerts: i32,
    pub automation_security: i32,
    pub operation_count: u32,
    pub rendered_slide_count: u32,
    pub text_overflow_count: u32,
    pub forced_process_termination: bool,
    pub temporary_files_remaining: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerPointPresentationWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub snapshot: PresentationSemanticSnapshotV1,
    pub mutation_receipt: PowerPointPresentationMutationReceiptV1,
}

pub fn powerpoint_presentation_worker_main() -> i32 {
    match run_worker() {
        Ok(response) => match d2i_office_capability::canonical_json_bytes(&response) {
            Ok(bytes) if std::io::stdout().write_all(&bytes).is_ok() => 0,
            Ok(_) | Err(_) => 1,
        },
        Err(error) => {
            eprintln!("{}", bounded_error(&error));
            1
        }
    }
}

fn run_worker() -> Result<PowerPointPresentationWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let request: PowerPointPresentationWorkerRequestV1 =
        parse_presentation_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate_request(&request)?;
    let source = Path::new(&request.source_path);
    let destination = Path::new(&request.destination_path);
    let powerpoint = Path::new(&request.powerpoint_executable_path);
    if d2i_office_capability::sha256_bytes(&fs::read(source).map_err(|error| error.to_string())?)
        != request.expected_source_sha256
        || d2i_office_capability::sha256_bytes(
            &fs::read(powerpoint).map_err(|error| error.to_string())?,
        ) != request.expected_powerpoint_sha256
    {
        return Err("PowerPoint worker source or executable hash differs".to_owned());
    }
    request
        .facts
        .validate()
        .map_err(|error| error.to_string())?;
    let operation = lower_operation(&request)?;
    let receipt = execute_powerpoint_presentation_operation(
        source,
        destination,
        &operation,
        request.render_directory.as_deref().map(Path::new),
    )
    .map_err(|error| error.to_string())?;
    let observed_powerpoint = receipt
        .powerpoint_image_path
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let approved_powerpoint = powerpoint
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let observed_powerpoint_sha256 = d2i_office_capability::sha256_bytes(
        &fs::read(&observed_powerpoint).map_err(|error| error.to_string())?,
    );
    if !observed_powerpoint
        .to_string_lossy()
        .eq_ignore_ascii_case(&approved_powerpoint.to_string_lossy())
        || observed_powerpoint_sha256 != request.expected_powerpoint_sha256
    {
        return Err("PowerPoint COM process image differs from the approved executable".to_owned());
    }
    if let PresentationMutationV1::InsertChart { chart, .. } = &request.mutation {
        let values = chart
            .fact_ids
            .iter()
            .map(|id| fact_i32(&request.facts, id))
            .collect::<Result<Vec<_>, _>>()?;
        verify_pptx_chart_facts(
            destination,
            &chart.category_labels,
            &values,
            &request.limits,
        )?;
    }
    let snapshot = inspect_pptx_presentation(
        destination,
        &request.presentation_id,
        &request.artifact_id,
        request.generation,
        &request.backend_id,
        request.observed_at_unix_ms,
        &request.limits,
    )?;
    if snapshot.source_content_sha256 == request.expected_source_sha256 {
        return Err("PowerPoint COM did not produce a new generation".to_owned());
    }
    Ok(PowerPointPresentationWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        mutation_receipt: PowerPointPresentationMutationReceiptV1 {
            schema_version: 1,
            source_content_sha256: request.expected_source_sha256,
            destination_content_sha256: snapshot.source_content_sha256.clone(),
            destination_semantic_sha256: snapshot.semantic_state_sha256.clone(),
            powerpoint_process_id: receipt.powerpoint_process_id,
            chart_excel_process_id: receipt.chart_excel_process_id,
            chart_excel_process_ids: receipt.chart_excel_process_ids,
            powerpoint_visible: receipt.visible,
            application_visible_on_private_desktop: receipt.application_visible_on_private_desktop,
            private_desktop: receipt.private_desktop,
            display_alerts: receipt.display_alerts,
            automation_security: receipt.automation_security,
            operation_count: receipt.operation_count,
            rendered_slide_count: receipt.rendered_slide_count,
            text_overflow_count: receipt.text_overflow_count,
            forced_process_termination: receipt.forced_excel_process_termination,
            temporary_files_remaining: 0,
        },
        snapshot,
    })
}

fn lower_operation(
    request: &PowerPointPresentationWorkerRequestV1,
) -> Result<PowerPointAutomationOperationV1, String> {
    match &request.mutation {
        PresentationMutationV1::AddSlide { .. } => Ok(PowerPointAutomationOperationV1::AddSlide {
            title: "Pending title".to_owned(),
            body: "Pending content".to_owned(),
        }),
        PresentationMutationV1::SetTitle { slide_id, title } => {
            Ok(PowerPointAutomationOperationV1::SetText {
                slide_index: slide_index(slide_id)?,
                shape_name: "d2i.title".to_owned(),
                text: title.clone(),
            })
        }
        PresentationMutationV1::SetText {
            slide_id,
            shape_id,
            text,
        } => Ok(PowerPointAutomationOperationV1::SetText {
            slide_index: slide_index(slide_id)?,
            shape_name: shape_id.clone(),
            text: text.clone(),
        }),
        PresentationMutationV1::InsertImage {
            slide_id,
            shape_id,
            image,
        } => {
            let path = Path::new(&request.workspace_root)
                .join(&image.workspace_relative_path)
                .canonicalize()
                .map_err(|error| error.to_string())?;
            let root = Path::new(&request.workspace_root)
                .canonicalize()
                .map_err(|error| error.to_string())?;
            if !path.starts_with(root)
                || d2i_office_capability::sha256_bytes(
                    &fs::read(&path).map_err(|error| error.to_string())?,
                ) != image.image_sha256
            {
                return Err("PowerPoint image binding differs".to_owned());
            }
            Ok(PowerPointAutomationOperationV1::InsertImage {
                slide_index: slide_index(slide_id)?,
                shape_name: shape_id.clone(),
                image_path: path,
            })
        }
        PresentationMutationV1::InsertTable {
            slide_id,
            shape_id,
            table,
        } => {
            let values = table
                .fact_ids
                .iter()
                .map(|id| fact_i32_or_text(&request.facts, id))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(PowerPointAutomationOperationV1::InsertTable {
                slide_index: slide_index(slide_id)?,
                shape_name: shape_id.clone(),
                cells: vec![table.column_labels.clone(), values],
            })
        }
        PresentationMutationV1::InsertChart {
            slide_id,
            shape_id,
            chart,
        } => {
            let values = chart
                .fact_ids
                .iter()
                .map(|id| fact_i32(&request.facts, id))
                .collect::<Result<Vec<_>, _>>()?;
            let chart_type = match chart.chart_kind {
                PresentationChartKindV1::ClusteredColumn => 51,
                PresentationChartKindV1::Bar => 57,
                PresentationChartKindV1::Line => 4,
            };
            Ok(PowerPointAutomationOperationV1::InsertChart {
                slide_index: slide_index(slide_id)?,
                shape_name: shape_id.clone(),
                chart_type,
                categories: chart.category_labels.clone(),
                values,
            })
        }
        _ => Err("PowerPoint COM operation is unsupported in v1".to_owned()),
    }
}

fn slide_index(value: &str) -> Result<i32, String> {
    value
        .strip_prefix("slide.")
        .ok_or_else(|| "PowerPoint semantic slide ID differs".to_owned())?
        .parse::<i32>()
        .map_err(|error| error.to_string())
        .and_then(|value| {
            if (1..=500).contains(&value) {
                Ok(value)
            } else {
                Err("PowerPoint slide index exceeds bounds".to_owned())
            }
        })
}

fn fact_i32(binding: &PresentationFactBindingV1, id: &str) -> Result<i32, String> {
    let fact = binding
        .facts
        .iter()
        .find(|fact| fact.fact_id == id)
        .ok_or_else(|| "PowerPoint chart fact is absent".to_owned())?;
    match fact.typed_value {
        SpreadsheetScalarV1::Integer { value } => {
            i32::try_from(value).map_err(|_| "PowerPoint chart fact exceeds i32".to_owned())
        }
        _ => Err("PowerPoint chart requires integer typed facts".to_owned()),
    }
}

fn fact_i32_or_text(binding: &PresentationFactBindingV1, id: &str) -> Result<String, String> {
    fact_i32(binding, id).map(|value| value.to_string())
}

fn validate_request(value: &PowerPointPresentationWorkerRequestV1) -> Result<(), String> {
    if value.schema_version != 1
        || value.request_id.is_empty()
        || value.request_id.len() > 512
        || value.generation < 2
        || !Path::new(&value.source_path).is_file()
        || Path::new(&value.destination_path).exists()
        || value.source_path == value.destination_path
        || !Path::new(&value.powerpoint_executable_path).is_file()
        || !Path::new(&value.workspace_root).is_dir()
        || value
            .render_directory
            .as_ref()
            .is_some_and(|path| !Path::new(path).is_dir())
    {
        return Err("PowerPoint worker request is invalid".to_owned());
    }
    Ok(())
}

pub fn spawn_powerpoint_presentation_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    request: &PowerPointPresentationWorkerRequestV1,
    timeout: Duration,
) -> Result<PowerPointPresentationWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
        || d2i_office_capability::sha256_bytes(
            &fs::read(worker_executable).map_err(|error| error.to_string())?,
        ) != expected_worker_sha256
    {
        return Err("PowerPoint worker executable binding differs".to_owned());
    }
    validate_request(request)?;
    let request_bytes =
        d2i_office_capability::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let mut command = Command::new(worker_executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "PowerPoint worker stdin is unavailable".to_owned())?
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "PowerPoint worker stdout is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "PowerPoint worker stderr is unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout, 4 * 1024 * 1024));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr, 8 * 1024));
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            return Err("PowerPoint worker exceeded its bounded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = stdout_reader
        .join()
        .map_err(|_| "PowerPoint stdout reader panicked".to_owned())??;
    let error = stderr_reader
        .join()
        .map_err(|_| "PowerPoint stderr reader panicked".to_owned())??;
    if !status.success() {
        return Err(format!(
            "PowerPoint worker failed without a verified response: {}",
            String::from_utf8_lossy(&error).trim()
        ));
    }
    let response: PowerPointPresentationWorkerResponseV1 =
        parse_presentation_json_strict(&output).map_err(|error| error.to_string())?;
    response
        .snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    let chart_operation = matches!(request.mutation, PresentationMutationV1::InsertChart { .. });
    let chart_processes = &response.mutation_receipt.chart_excel_process_ids;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.snapshot.artifact_generation != request.generation
        || response.mutation_receipt.powerpoint_visible
        || !response
            .mutation_receipt
            .application_visible_on_private_desktop
        || !response.mutation_receipt.private_desktop
        || response.mutation_receipt.display_alerts != 1
        || response.mutation_receipt.automation_security != 3
        || response.mutation_receipt.operation_count != 1
        || response.mutation_receipt.text_overflow_count != 0
        || chart_processes.len() > 4
        || chart_operation == chart_processes.is_empty()
        || response.mutation_receipt.chart_excel_process_id != chart_processes.first().copied()
        || (response.mutation_receipt.forced_process_termination && !chart_operation)
        || response.mutation_receipt.temporary_files_remaining != 0
    {
        return Err("PowerPoint worker response differs from its bound request".to_owned());
    }
    Ok(response)
}

fn read_bounded<T: Read>(pipe: T, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    pipe.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("PowerPoint worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn bounded_error(value: &str) -> String {
    if value.len() <= 512
        && !value.contains("\\\\")
        && !value.contains(":\\")
        && !value.contains("file://")
    {
        value.to_owned()
    } else {
        "powerpoint_worker_bounded_failure".to_owned()
    }
}
