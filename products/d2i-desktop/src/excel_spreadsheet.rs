use crate::{inspect_xlsx_workbook, validate_spreadsheet_mutation, ResolvedSpreadsheetOperationV1};
use d2i_office_capability::sha256_bytes;
use d2i_spreadsheet_capability::{
    parse_spreadsheet_json_strict, IndexedSpreadsheetWorkbookV1, SpreadsheetFormulaV1,
    SpreadsheetMutationV1, SpreadsheetResourceLimitsV1, SpreadsheetScalarV1,
    SpreadsheetSemanticSnapshotV1,
};
use d2i_windows_host::{
    execute_excel_spreadsheet_operation, ExcelAutomationFormulaV1, ExcelAutomationOperationV1,
    ExcelAutomationReceiptV1, ExcelAutomationScalarV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcelSpreadsheetMutationReceiptV1 {
    pub schema_version: u32,
    pub source_content_sha256: String,
    pub destination_content_sha256: String,
    pub destination_semantic_sha256: String,
    pub excel_process_id: u32,
    pub excel_visible: bool,
    pub display_alerts: bool,
    pub automation_security: i32,
    pub enable_events: bool,
    pub ask_to_update_links: bool,
    pub full_recalculation: bool,
    pub forced_process_termination: bool,
    pub operation_count: u32,
    pub temporary_files_remaining: u32,
}

pub struct ExcelSpreadsheetMutationV1<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub expected_source_sha256: &'a str,
    pub excel_executable: &'a Path,
    pub workbook_id: &'a str,
    pub artifact_id: &'a str,
    pub generation: u64,
    pub backend_id: &'a str,
    pub observed_at_unix_ms: u64,
    pub operation: &'a ResolvedSpreadsheetOperationV1,
    pub limits: &'a SpreadsheetResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcelSpreadsheetWorkerRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub source_path: String,
    pub destination_path: String,
    pub expected_source_sha256: String,
    pub excel_executable_path: String,
    pub expected_excel_sha256: String,
    pub workbook_id: String,
    pub artifact_id: String,
    pub generation: u64,
    pub backend_id: String,
    pub observed_at_unix_ms: u64,
    pub operation: ResolvedSpreadsheetOperationV1,
    pub limits: SpreadsheetResourceLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcelSpreadsheetWorkerResponseV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub snapshot: SpreadsheetSemanticSnapshotV1,
    pub mutation_receipt: ExcelSpreadsheetMutationReceiptV1,
}

pub fn mutate_xlsx_with_excel(
    request: ExcelSpreadsheetMutationV1<'_>,
) -> Result<
    (
        SpreadsheetSemanticSnapshotV1,
        ExcelSpreadsheetMutationReceiptV1,
    ),
    String,
> {
    validate_spreadsheet_mutation(request.operation, request.limits)?;
    if !request.source.is_file()
        || request.destination.exists()
        || !request.excel_executable.is_file()
        || request.generation < 2
    {
        return Err(
            "Excel mutation requires bound files, an existing source, and a new generation"
                .to_owned(),
        );
    }
    let source_bytes = fs::read(request.source).map_err(|error| error.to_string())?;
    let source_sha256 = sha256_bytes(&source_bytes);
    if source_sha256 != request.expected_source_sha256 {
        return Err("Excel mutation source hash differs".to_owned());
    }
    let source_index = inspect_xlsx_workbook(
        request.source,
        request.workbook_id,
        request.artifact_id,
        request.generation.saturating_sub(1),
        request.backend_id,
        request.observed_at_unix_ms,
        request.limits,
    )?;
    let operation = lower_excel_operation(&source_index, request.operation)?;
    let destination_parent = request
        .destination
        .parent()
        .ok_or_else(|| "Excel destination parent is missing".to_owned())?;
    if !destination_parent.is_dir()
        || d2i_windows_host::is_reparse_point(destination_parent)
            .map_err(|error| error.to_string())?
    {
        return Err("Excel destination parent is unsafe".to_owned());
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let staging =
        destination_parent.join(format!(".d2i-excel-{}-{nonce}.xlsx", std::process::id()));
    fs::write(&staging, &source_bytes).map_err(|error| error.to_string())?;
    let excel_receipt =
        match execute_excel_spreadsheet_operation(&staging, request.excel_executable, &operation) {
            Ok(receipt) => receipt,
            Err(error) => return cleanup_error(&staging, &error.to_string()),
        };
    let fresh = match inspect_xlsx_workbook(
        &staging,
        request.workbook_id,
        request.artifact_id,
        request.generation,
        request.backend_id,
        request.observed_at_unix_ms,
        request.limits,
    ) {
        Ok(index) => index,
        Err(error) => return cleanup_error(&staging, &error),
    };
    if let Err(error) = verify_operation_effect(&source_index, &fresh, request.operation) {
        return cleanup_error(&staging, &error);
    }
    if let Err(error) = d2i_windows_host::atomic_move(&staging, request.destination, false) {
        let _ = cleanup_staging(&staging);
        return Err(error.to_string());
    }
    let destination_bytes = fs::read(request.destination).map_err(|error| error.to_string())?;
    let receipt = build_receipt(
        source_sha256,
        sha256_bytes(&destination_bytes),
        fresh.snapshot.semantic_state_sha256.clone(),
        excel_receipt,
    );
    Ok((fresh.snapshot, receipt))
}

fn lower_excel_operation(
    workbook: &IndexedSpreadsheetWorkbookV1,
    operation: &ResolvedSpreadsheetOperationV1,
) -> Result<ExcelAutomationOperationV1, String> {
    match &operation.mutation {
        SpreadsheetMutationV1::SetCellValue {
            target_cell_id,
            value,
        } => {
            let cell = resolve_cell(workbook, target_cell_id, true)?;
            Ok(ExcelAutomationOperationV1::SetCellValue {
                sheet_index: i32::try_from(cell.sheet_ordinal)
                    .map_err(|error| format!("Excel sheet ordinal: {error}"))?,
                cell: a1_reference(cell.column_ordinal, cell.data_row_ordinal + 1)?,
                value: lower_scalar(value)?,
            })
        }
        SpreadsheetMutationV1::SetCellFormula {
            target_cell_id,
            formula,
        } => {
            let target = resolve_cell(workbook, target_cell_id, true)?;
            let lowered = lower_formula(workbook, target.sheet_ordinal, formula)?;
            Ok(ExcelAutomationOperationV1::SetCellFormula {
                sheet_index: i32::try_from(target.sheet_ordinal)
                    .map_err(|error| format!("Excel sheet ordinal: {error}"))?,
                cell: a1_reference(target.column_ordinal, target.data_row_ordinal + 1)?,
                formula: lowered,
            })
        }
        SpreadsheetMutationV1::AppendTableRow { table_id, values } => {
            let table = workbook
                .tables
                .iter()
                .find(|table| &table.metadata.table_id == table_id)
                .ok_or_else(|| "Excel append table is absent".to_owned())?;
            let sheet_ordinal = parse_sheet_ordinal(&table.metadata.sheet_id)?;
            let next_excel_row = table.rows.last().map_or(2, |row| row.ordinal + 2);
            let columns = table
                .metadata
                .columns
                .iter()
                .map(|column| (column.column_id.as_str(), column.ordinal))
                .collect::<std::collections::BTreeMap<_, _>>();
            let mut lowered = Vec::new();
            for value in values {
                let column = columns
                    .get(value.column_id.as_str())
                    .copied()
                    .ok_or_else(|| "Excel append column is absent".to_owned())?;
                lowered.push((
                    i32::try_from(column)
                        .map_err(|error| format!("Excel append column: {error}"))?,
                    lower_scalar(&value.value)?,
                ));
            }
            lowered.sort_by_key(|(column, _)| *column);
            Ok(ExcelAutomationOperationV1::AppendRow {
                sheet_index: i32::try_from(sheet_ordinal)
                    .map_err(|error| format!("Excel sheet ordinal: {error}"))?,
                excel_row: i32::try_from(next_excel_row)
                    .map_err(|error| format!("Excel append row: {error}"))?,
                values: lowered,
            })
        }
        SpreadsheetMutationV1::ApplyCellStyle { .. }
        | SpreadsheetMutationV1::CreateTable { .. } => {
            Err("Excel live backend operation is unsupported in v1".to_owned())
        }
    }
}

fn lower_formula(
    workbook: &IndexedSpreadsheetWorkbookV1,
    target_sheet: u32,
    formula: &SpreadsheetFormulaV1,
) -> Result<ExcelAutomationFormulaV1, String> {
    let cell = |identifier: &str| -> Result<String, String> {
        let resolved = resolve_cell(workbook, identifier, true)?;
        if resolved.sheet_ordinal != target_sheet {
            return Err("Excel v1 formula cannot cross worksheet boundaries".to_owned());
        }
        a1_reference(resolved.column_ordinal, resolved.data_row_ordinal + 1)
    };
    match formula {
        SpreadsheetFormulaV1::SumRange { source_range_id } => {
            let range = resolve_range(workbook, source_range_id)?;
            if range.sheet_ordinal != target_sheet {
                return Err("Excel v1 formula range crosses worksheets".to_owned());
            }
            Ok(ExcelAutomationFormulaV1::Sum {
                range: format!(
                    "{}:{}",
                    a1_reference(range.column_ordinal, range.first_data_row + 1)?,
                    a1_reference(range.column_ordinal, range.last_data_row + 1)?
                ),
            })
        }
        SpreadsheetFormulaV1::Difference {
            left_cell_id,
            right_cell_id,
        } => Ok(ExcelAutomationFormulaV1::Difference {
            left: cell(left_cell_id)?,
            right: cell(right_cell_id)?,
        }),
        SpreadsheetFormulaV1::Product {
            left_cell_id,
            right_cell_id,
        } => Ok(ExcelAutomationFormulaV1::Product {
            left: cell(left_cell_id)?,
            right: cell(right_cell_id)?,
        }),
        SpreadsheetFormulaV1::Ratio {
            numerator_cell_id,
            denominator_cell_id,
        } => Ok(ExcelAutomationFormulaV1::Ratio {
            numerator: cell(numerator_cell_id)?,
            denominator: cell(denominator_cell_id)?,
        }),
    }
}

fn lower_scalar(value: &SpreadsheetScalarV1) -> Result<ExcelAutomationScalarV1, String> {
    match value {
        SpreadsheetScalarV1::Text { value } => Ok(ExcelAutomationScalarV1::Text(value.clone())),
        SpreadsheetScalarV1::Integer { value } => i32::try_from(*value)
            .map(ExcelAutomationScalarV1::Integer)
            .map_err(|_| "Excel v1 integer exceeds exact I4 range".to_owned()),
        SpreadsheetScalarV1::Decimal {
            scaled_value,
            scale,
        } => Ok(ExcelAutomationScalarV1::Decimal {
            scaled_value: *scaled_value,
            scale: *scale,
        }),
        SpreadsheetScalarV1::Boolean { value } => Ok(ExcelAutomationScalarV1::Boolean(*value)),
        SpreadsheetScalarV1::Blank
        | SpreadsheetScalarV1::Date { .. }
        | SpreadsheetScalarV1::Error { .. } => {
            Err("Excel v1 live mutation scalar is unsupported".to_owned())
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CellCoordinate {
    sheet_ordinal: u32,
    data_row_ordinal: u32,
    column_ordinal: u32,
}

fn parse_cell_id(value: &str) -> Result<CellCoordinate, String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "cell" || parts[1] != "sheet" {
        return Err("Excel cell ID does not use the v1 semantic format".to_owned());
    }
    Ok(CellCoordinate {
        sheet_ordinal: parts[2]
            .parse::<u32>()
            .map_err(|error| format!("Excel cell sheet: {error}"))?,
        data_row_ordinal: parts[3]
            .strip_prefix('r')
            .ok_or_else(|| "Excel cell row marker is absent".to_owned())?
            .parse::<u32>()
            .map_err(|error| format!("Excel cell row: {error}"))?,
        column_ordinal: parts[4]
            .strip_prefix('c')
            .ok_or_else(|| "Excel cell column marker is absent".to_owned())?
            .parse::<u32>()
            .map_err(|error| format!("Excel cell column: {error}"))?,
    })
}

fn resolve_cell(
    workbook: &IndexedSpreadsheetWorkbookV1,
    identifier: &str,
    require_populated: bool,
) -> Result<CellCoordinate, String> {
    let cell = parse_cell_id(identifier)?;
    let table = workbook
        .tables
        .iter()
        .find(|table| {
            parse_sheet_ordinal(&table.metadata.sheet_id).ok() == Some(cell.sheet_ordinal)
        })
        .ok_or_else(|| "Excel semantic cell sheet is absent".to_owned())?;
    let row = table
        .rows
        .iter()
        .find(|row| row.ordinal == cell.data_row_ordinal)
        .ok_or_else(|| "Excel semantic cell row is absent".to_owned())?;
    let column = table
        .metadata
        .columns
        .iter()
        .find(|column| column.ordinal == cell.column_ordinal)
        .ok_or_else(|| "Excel semantic cell column is absent".to_owned())?;
    if require_populated
        && !row
            .values
            .iter()
            .any(|value| value.column_id == column.column_id)
    {
        return Err("Excel semantic cell is not populated in the bound snapshot".to_owned());
    }
    Ok(cell)
}

#[derive(Debug, Clone, Copy)]
struct RangeCoordinate {
    sheet_ordinal: u32,
    first_data_row: u32,
    last_data_row: u32,
    column_ordinal: u32,
}

fn resolve_range(
    workbook: &IndexedSpreadsheetWorkbookV1,
    identifier: &str,
) -> Result<RangeCoordinate, String> {
    let parts = identifier.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "range" || parts[1] != "sheet" {
        return Err("Excel range ID does not use the v1 semantic format".to_owned());
    }
    let (first, last) = parts[3]
        .split_once('-')
        .ok_or_else(|| "Excel range row interval is absent".to_owned())?;
    let range = RangeCoordinate {
        sheet_ordinal: parts[2]
            .parse::<u32>()
            .map_err(|error| format!("Excel range sheet: {error}"))?,
        first_data_row: first
            .strip_prefix('r')
            .ok_or_else(|| "Excel range first row marker is absent".to_owned())?
            .parse::<u32>()
            .map_err(|error| format!("Excel range first row: {error}"))?,
        last_data_row: last
            .strip_prefix('r')
            .ok_or_else(|| "Excel range last row marker is absent".to_owned())?
            .parse::<u32>()
            .map_err(|error| format!("Excel range last row: {error}"))?,
        column_ordinal: parts[4]
            .strip_prefix('c')
            .ok_or_else(|| "Excel range column marker is absent".to_owned())?
            .parse::<u32>()
            .map_err(|error| format!("Excel range column: {error}"))?,
    };
    if range.first_data_row == 0 || range.last_data_row < range.first_data_row {
        return Err("Excel range row interval is invalid".to_owned());
    }
    resolve_cell(
        workbook,
        &format!(
            "cell.sheet.{:04}.r{:06}.c{:06}",
            range.sheet_ordinal, range.first_data_row, range.column_ordinal
        ),
        true,
    )?;
    resolve_cell(
        workbook,
        &format!(
            "cell.sheet.{:04}.r{:06}.c{:06}",
            range.sheet_ordinal, range.last_data_row, range.column_ordinal
        ),
        true,
    )?;
    Ok(range)
}

fn parse_sheet_ordinal(sheet_id: &str) -> Result<u32, String> {
    sheet_id
        .strip_prefix("sheet.")
        .ok_or_else(|| "Excel sheet ID format differs".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("Excel sheet ordinal: {error}"))
}

fn a1_reference(column: u32, row: u32) -> Result<String, String> {
    if column == 0 || column > 16_384 || row == 0 || row > 1_048_576 {
        return Err("Excel coordinate exceeds format bounds".to_owned());
    }
    let mut value = column;
    let mut letters = Vec::new();
    while value > 0 {
        value -= 1;
        letters.push(
            char::from_u32(u32::from(b'A') + value % 26)
                .ok_or_else(|| "Excel column conversion failed".to_owned())?,
        );
        value /= 26;
    }
    letters.reverse();
    Ok(format!("{}{row}", letters.into_iter().collect::<String>()))
}

fn verify_operation_effect(
    before: &IndexedSpreadsheetWorkbookV1,
    after: &IndexedSpreadsheetWorkbookV1,
    operation: &ResolvedSpreadsheetOperationV1,
) -> Result<(), String> {
    if before.snapshot.source_content_sha256 == after.snapshot.source_content_sha256
        || before.snapshot.snapshot_sha256 == after.snapshot.snapshot_sha256
    {
        return Err("Excel operation did not produce a fresh workbook generation".to_owned());
    }
    match &operation.mutation {
        SpreadsheetMutationV1::AppendTableRow { table_id, .. } => {
            let before_rows = before
                .tables
                .iter()
                .find(|table| &table.metadata.table_id == table_id)
                .map(|table| table.rows.len())
                .ok_or_else(|| "Excel before table is absent".to_owned())?;
            let after_rows = after
                .tables
                .iter()
                .find(|table| &table.metadata.table_id == table_id)
                .map(|table| table.rows.len())
                .ok_or_else(|| "Excel after table is absent".to_owned())?;
            if after_rows != before_rows.saturating_add(1) {
                return Err("Excel append postcondition differs".to_owned());
            }
        }
        SpreadsheetMutationV1::SetCellFormula { .. } => {
            if after.snapshot.total_formula_cells <= before.snapshot.total_formula_cells {
                return Err("Excel formula postcondition differs".to_owned());
            }
        }
        SpreadsheetMutationV1::SetCellValue { .. } => {
            if after.snapshot.workbook_data_sha256 == before.snapshot.workbook_data_sha256 {
                return Err("Excel value postcondition differs".to_owned());
            }
        }
        SpreadsheetMutationV1::ApplyCellStyle { .. }
        | SpreadsheetMutationV1::CreateTable { .. } => {
            return Err("Excel unsupported operation reached verification".to_owned())
        }
    }
    Ok(())
}

fn build_receipt(
    source_content_sha256: String,
    destination_content_sha256: String,
    destination_semantic_sha256: String,
    excel: ExcelAutomationReceiptV1,
) -> ExcelSpreadsheetMutationReceiptV1 {
    ExcelSpreadsheetMutationReceiptV1 {
        schema_version: 1,
        source_content_sha256,
        destination_content_sha256,
        destination_semantic_sha256,
        excel_process_id: excel.excel_process_id,
        excel_visible: excel.visible,
        display_alerts: excel.display_alerts,
        automation_security: excel.automation_security,
        enable_events: excel.enable_events,
        ask_to_update_links: excel.ask_to_update_links,
        full_recalculation: excel.full_recalculation,
        forced_process_termination: excel.forced_process_termination,
        operation_count: excel.operation_count,
        temporary_files_remaining: 0,
    }
}

fn cleanup_error<T>(staging: &Path, message: &str) -> Result<T, String> {
    cleanup_staging(staging)?;
    Err(message.to_owned())
}

fn cleanup_staging(staging: &Path) -> Result<(), String> {
    if staging.exists() {
        fs::remove_file(staging).map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn excel_spreadsheet_worker_main() -> i32 {
    match run_excel_spreadsheet_worker() {
        Ok(response) => {
            let bytes = match d2i_office_capability::canonical_json_bytes(&response) {
                Ok(bytes) => bytes,
                Err(_) => return 1,
            };
            if std::io::stdout().write_all(&bytes).is_err() {
                return 1;
            }
            0
        }
        Err(error) => {
            eprintln!("{}", bounded_worker_error(&error));
            1
        }
    }
}

fn run_excel_spreadsheet_worker() -> Result<ExcelSpreadsheetWorkerResponseV1, String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let request: ExcelSpreadsheetWorkerRequestV1 =
        parse_spreadsheet_json_strict(&bytes).map_err(|error| error.to_string())?;
    validate_worker_request(&request)?;
    let excel = Path::new(&request.excel_executable_path);
    if sha256_bytes(&fs::read(excel).map_err(|error| error.to_string())?)
        != request.expected_excel_sha256
    {
        return Err("Excel worker executable hash differs".to_owned());
    }
    let (snapshot, mutation_receipt) = mutate_xlsx_with_excel(ExcelSpreadsheetMutationV1 {
        source: Path::new(&request.source_path),
        destination: Path::new(&request.destination_path),
        expected_source_sha256: &request.expected_source_sha256,
        excel_executable: excel,
        workbook_id: &request.workbook_id,
        artifact_id: &request.artifact_id,
        generation: request.generation,
        backend_id: &request.backend_id,
        observed_at_unix_ms: request.observed_at_unix_ms,
        operation: &request.operation,
        limits: &request.limits,
    })?;
    Ok(ExcelSpreadsheetWorkerResponseV1 {
        schema_version: 1,
        request_id: request.request_id,
        snapshot,
        mutation_receipt,
    })
}

pub fn spawn_excel_spreadsheet_worker(
    worker_executable: &Path,
    expected_worker_sha256: &str,
    excel_executable: &Path,
    expected_excel_sha256: &str,
    request: &ExcelSpreadsheetWorkerRequestV1,
    timeout: Duration,
) -> Result<ExcelSpreadsheetWorkerResponseV1, String> {
    if !worker_executable.is_file()
        || d2i_windows_host::is_reparse_point(worker_executable)
            .map_err(|error| error.to_string())?
        || sha256_bytes(&fs::read(worker_executable).map_err(|error| error.to_string())?)
            != expected_worker_sha256
        || !excel_executable.is_file()
        || sha256_bytes(&fs::read(excel_executable).map_err(|error| error.to_string())?)
            != expected_excel_sha256
        || request.excel_executable_path != excel_executable.to_string_lossy()
        || request.expected_excel_sha256 != expected_excel_sha256
    {
        return Err("Excel worker or application binding differs".to_owned());
    }
    validate_worker_request(request)?;
    let before_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let request_bytes =
        d2i_office_capability::canonical_json_bytes(request).map_err(|error| error.to_string())?;
    let mut command = Command::new(worker_executable);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let worker_process_id = child.id();
    child
        .stdin
        .as_mut()
        .ok_or_else(|| "Excel worker stdin is unavailable".to_owned())?
        .write_all(&request_bytes)
        .map_err(|error| error.to_string())?;
    drop(child.stdin.take());
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Excel worker stdout is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Excel worker stderr is unavailable".to_owned())?;
    let stdout_reader = std::thread::spawn(move || read_bounded_pipe(stdout, 4 * 1024 * 1024));
    let stderr_reader = std::thread::spawn(move || read_bounded_pipe(stderr, 4_096));
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill().map_err(|error| error.to_string())?;
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            cleanup_timed_out_worker(request, worker_process_id, &before_excel, excel_executable)?;
            return Err("Excel worker exceeded its bounded deadline".to_owned());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = join_pipe_reader(stdout_reader)?;
    let error_output = join_pipe_reader(stderr_reader)?;
    if !status.success() {
        cleanup_timed_out_worker(request, worker_process_id, &before_excel, excel_executable)?;
        return Err(format!(
            "Excel worker failed without a verified response: {}",
            String::from_utf8_lossy(&error_output).trim()
        ));
    }
    let response: ExcelSpreadsheetWorkerResponseV1 =
        parse_spreadsheet_json_strict(&output).map_err(|error| error.to_string())?;
    response
        .snapshot
        .validate()
        .map_err(|error| error.to_string())?;
    if response.schema_version != 1
        || response.request_id != request.request_id
        || response.snapshot.workbook_id != request.workbook_id
        || response.snapshot.artifact_id != request.artifact_id
        || response.snapshot.artifact_generation != request.generation
        || response.snapshot.backend_id != request.backend_id
        || response.mutation_receipt.excel_visible
        || response.mutation_receipt.display_alerts
        || response.mutation_receipt.automation_security != 3
        || response.mutation_receipt.enable_events
        || response.mutation_receipt.ask_to_update_links
        || !response.mutation_receipt.full_recalculation
        || response.mutation_receipt.operation_count != 1
        || response.mutation_receipt.temporary_files_remaining != 0
    {
        return Err("Excel worker response differs from the bound request".to_owned());
    }
    Ok(response)
}

fn validate_worker_request(request: &ExcelSpreadsheetWorkerRequestV1) -> Result<(), String> {
    if request.schema_version != 1
        || request.request_id.is_empty()
        || request.request_id.len() > 512
        || request.generation < 2
        || !Path::new(&request.source_path).is_file()
        || Path::new(&request.destination_path).exists()
        || !Path::new(&request.excel_executable_path).is_file()
        || request.source_path == request.destination_path
    {
        return Err("Excel worker request is invalid".to_owned());
    }
    Ok(())
}

fn cleanup_timed_out_worker(
    request: &ExcelSpreadsheetWorkerRequestV1,
    worker_process_id: u32,
    before_excel: &[u32],
    excel_executable: &Path,
) -> Result<(), String> {
    for process_id in
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?
    {
        if before_excel.contains(&process_id) {
            continue;
        }
        match d2i_windows_host::process_image_path(process_id) {
            Ok(actual)
                if actual
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&excel_executable.to_string_lossy()) =>
            {
                d2i_windows_host::terminate_process_if_exact_image(process_id, excel_executable)
                    .map_err(|error| error.to_string())?;
            }
            Ok(actual)
                if actual
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case("EXCEL.EXE")) =>
            {
                return Err("new Excel PID uses an unexpected executable path".to_owned())
            }
            Ok(_) | Err(_) => {}
        }
    }
    let destination = Path::new(&request.destination_path);
    if destination.is_file() {
        fs::remove_file(destination).map_err(|error| error.to_string())?;
    }
    if let Some(parent) = destination.parent() {
        let prefix = format!(".d2i-excel-{worker_process_id}-");
        for entry in fs::read_dir(parent)
            .map_err(|error| error.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?
        {
            let metadata = entry.metadata().map_err(|error| error.to_string())?;
            if entry.file_name().to_string_lossy().starts_with(&prefix)
                && metadata.is_file()
                && !metadata.file_type().is_symlink()
            {
                fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
            }
        }
    }
    Ok(())
}

fn read_bounded_pipe<T: Read>(pipe: T, maximum: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    pipe.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err("Excel worker pipe exceeded its bound".to_owned());
    }
    Ok(bytes)
}

fn join_pipe_reader(
    reader: std::thread::JoinHandle<Result<Vec<u8>, String>>,
) -> Result<Vec<u8>, String> {
    reader
        .join()
        .map_err(|_| "Excel worker pipe reader panicked".to_owned())?
}

fn bounded_worker_error(error: &str) -> String {
    if error.len() <= 512
        && !error.contains("\\\\")
        && !error.contains(":\\")
        && !error.contains("file://")
    {
        error.to_owned()
    } else {
        "excel_worker_bounded_failure".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_identifiers_lower_without_raw_formula_text() {
        assert_eq!(
            a1_reference(27, 2).unwrap_or_else(|error| panic!("A1 lowering must succeed: {error}")),
            "AA2"
        );
        assert!(parse_cell_id("A1").is_err());
        let range = "range.sheet.0001.r000001-r000010.c000003";
        assert_eq!(range.split('.').count(), 5);
    }
}
