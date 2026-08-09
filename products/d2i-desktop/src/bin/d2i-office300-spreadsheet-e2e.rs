#[cfg(windows)]
use d2i_desktop::{
    create_xlsx_workbook, inspect_xlsx_workbook, mutate_xlsx_with_excel, mutate_xlsx_workbook,
    ExcelSpreadsheetMutationV1, ResolvedSpreadsheetOperationV1,
};
#[cfg(windows)]
use d2i_office_capability::{canonical_json_bytes, sha256_bytes};
#[cfg(windows)]
use d2i_spreadsheet_capability::{
    default_spreadsheet_resource_limits, execute_spreadsheet_query, slice_spreadsheet_context,
    SpreadsheetColumnValueV1, SpreadsheetContextBudgetV1, SpreadsheetFormulaV1,
    SpreadsheetMutationV1, SpreadsheetPredicateOperatorV1, SpreadsheetPredicateV1,
    SpreadsheetQueryPlanV1, SpreadsheetQueryV1, SpreadsheetScalarV1, ZERO_HASH,
};
#[cfg(windows)]
use serde::Serialize;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
#[cfg(windows)]
struct Arguments {
    output_root: PathBuf,
    excel: PathBuf,
}

#[derive(Debug, Serialize)]
#[cfg(windows)]
struct SpreadsheetE2eReportV1 {
    schema_version: u32,
    source_sha256: String,
    file_generation_sha256: String,
    excel_generation_sha256: String,
    excel_executable_sha256: String,
    excel_process_id: u32,
    formula_cells: u32,
    query_result_sha256: String,
    context_slice_sha256: String,
    context_facts: u32,
    context_bytes: u32,
    wfp_provider_key: String,
    wfp_sublayer_key: String,
    wfp_filter_keys: [String; 4],
    wfp_exact_before: bool,
    wfp_exact_after: bool,
    wfp_removed: bool,
    appcontainer_profile_removed: bool,
    residual_excel_processes: u32,
    original_unchanged: bool,
    complete: bool,
    report_sha256: String,
}

#[cfg(windows)]
fn main() {
    match parse_arguments().and_then(run) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(windows)]
fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args_os().skip(1).collect::<Vec<_>>();
    if values.len() != 4 || values[0] != "--output-root" || values[2] != "--excel" {
        return Err(
            "usage: d2i-office300-spreadsheet-e2e --output-root <path> --excel <path>".to_owned(),
        );
    }
    Ok(Arguments {
        output_root: PathBuf::from(&values[1]),
        excel: PathBuf::from(&values[3]),
    })
}

#[cfg(windows)]
fn run(arguments: Arguments) -> Result<(), String> {
    if !arguments.excel.is_file() {
        return Err("pinned Excel executable is unavailable".to_owned());
    }
    fs::create_dir_all(&arguments.output_root).map_err(|error| error.to_string())?;
    let source = arguments.output_root.join("generation-0001.xlsx");
    let file_generation = arguments.output_root.join("generation-0002.xlsx");
    let excel_generation = arguments.output_root.join("generation-0003.xlsx");
    let report_path = arguments.output_root.join("spreadsheet-e2e-report.json");
    for path in [&source, &file_generation, &excel_generation, &report_path] {
        if path.exists() {
            fs::remove_file(path).map_err(|error| error.to_string())?;
        }
    }
    let limits = default_spreadsheet_resource_limits();
    create_xlsx_workbook(
        &source,
        "Records",
        &[
            "Record".to_owned(),
            "Planned".to_owned(),
            "Actual".to_owned(),
            "Variance".to_owned(),
        ],
        &limits,
    )?;
    let source_sha256 = file_sha256(&source)?;
    let source_index = inspect_xlsx_workbook(
        &source,
        "workbook.office300.e2e",
        "artifact.office300.e2e",
        1,
        "backend.xlsx.file",
        now_unix_ms()?,
        &limits,
    )?;
    let table = &source_index.tables[0].metadata;
    let values = table
        .columns
        .iter()
        .zip([
            SpreadsheetScalarV1::Text {
                value: "record-001".to_owned(),
            },
            SpreadsheetScalarV1::Integer { value: 125 },
            SpreadsheetScalarV1::Integer { value: 100 },
            SpreadsheetScalarV1::Integer { value: 0 },
        ])
        .map(|(column, value)| SpreadsheetColumnValueV1 {
            column_id: column.column_id.clone(),
            value,
        })
        .collect::<Vec<_>>();
    let file_index = mutate_xlsx_workbook(
        &source,
        &file_generation,
        &ResolvedSpreadsheetOperationV1 {
            mutation: SpreadsheetMutationV1::AppendTableRow {
                table_id: table.table_id.clone(),
                values,
            },
        },
        "workbook.office300.e2e",
        "artifact.office300.e2e",
        2,
        "backend.xlsx.file",
        now_unix_ms()?,
        &limits,
    )?;
    let before_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let identity = d2i_windows_host::host_identity().map_err(|error| error.to_string())?;
    let profile_name = format!("d2i.office300.wfp.{}", std::process::id());
    let profile = d2i_windows_host::provision_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string())?;
    let policy = match d2i_windows_host::install_wfp_loopback_policy(
        &arguments.excel,
        &profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(policy) => policy,
        Err(error) => {
            let _ = d2i_windows_host::delete_appcontainer_profile(&profile_name);
            return Err(error.to_string());
        }
    };
    let verified_before = match d2i_windows_host::verify_wfp_loopback_policy(
        &arguments.excel,
        &profile.profile_sid,
        &identity.user_sid,
    ) {
        Ok(verified) => verified,
        Err(error) => {
            return match cleanup_wfp(&profile_name, &profile.profile_sid) {
                Ok(()) => Err(error.to_string()),
                Err(cleanup_error) => Err(format!(
                    "{error}; WFP/profile cleanup also failed: {cleanup_error}"
                )),
            };
        }
    };
    if verified_before != policy {
        let _ = cleanup_wfp(&profile_name, &profile.profile_sid);
        return Err("Excel WFP policy differs immediately after installation".to_owned());
    }
    let excel_result = mutate_xlsx_with_excel(ExcelSpreadsheetMutationV1 {
        source: &file_generation,
        destination: &excel_generation,
        expected_source_sha256: &file_index.snapshot.source_content_sha256,
        excel_executable: &arguments.excel,
        workbook_id: "workbook.office300.e2e",
        artifact_id: "artifact.office300.e2e",
        generation: 3,
        backend_id: "backend.excel.com",
        observed_at_unix_ms: now_unix_ms()?,
        operation: &ResolvedSpreadsheetOperationV1 {
            mutation: SpreadsheetMutationV1::SetCellFormula {
                target_cell_id: "cell.sheet.0001.r000001.c000004".to_owned(),
                formula: SpreadsheetFormulaV1::Difference {
                    left_cell_id: "cell.sheet.0001.r000001.c000002".to_owned(),
                    right_cell_id: "cell.sheet.0001.r000001.c000003".to_owned(),
                },
            },
        },
        limits: &limits,
    });
    let verified_after = d2i_windows_host::verify_wfp_loopback_policy(
        &arguments.excel,
        &profile.profile_sid,
        &identity.user_sid,
    )
    .map_err(|error| error.to_string());
    let policy_removal = d2i_windows_host::remove_wfp_loopback_policy(&profile.profile_sid)
        .map_err(|error| error.to_string());
    let profile_removal = d2i_windows_host::delete_appcontainer_profile(&profile_name)
        .map_err(|error| error.to_string());
    let ((excel_snapshot, excel_receipt), verified_after) = match (
        excel_result,
        verified_after,
        policy_removal,
        profile_removal,
    ) {
        (Ok(excel), Ok(verified), Ok(()), Ok(())) if verified == policy => (excel, verified),
        state => return Err(format!("Excel E2E or cleanup failed: {state:?}")),
    };
    let fresh = inspect_xlsx_workbook(
        &excel_generation,
        "workbook.office300.e2e",
        "artifact.office300.e2e",
        3,
        "backend.excel.com",
        now_unix_ms()?,
        &limits,
    )?;
    if fresh.snapshot.snapshot_sha256 != excel_snapshot.snapshot_sha256
        || fresh.snapshot.total_formula_cells != 1
    {
        return Err("fresh Excel reopen differs from worker snapshot".to_owned());
    }
    let query = SpreadsheetQueryV1 {
        schema_version: 1,
        query_id: "query.office300.e2e".to_owned(),
        case_id: "case.office300.e2e".to_owned(),
        workbook_snapshot_sha256: fresh.snapshot.snapshot_sha256.clone(),
        table_id: fresh.tables[0].metadata.table_id.clone(),
        plan: SpreadsheetQueryPlanV1::Filter {
            predicates: vec![SpreadsheetPredicateV1 {
                column_id: fresh.tables[0].metadata.columns[0].column_id.clone(),
                operator: SpreadsheetPredicateOperatorV1::Equal,
                operand: SpreadsheetScalarV1::Text {
                    value: "record-001".to_owned(),
                },
            }],
            projection_column_ids: fresh.tables[0]
                .metadata
                .columns
                .iter()
                .map(|column| column.column_id.clone())
                .collect(),
            maximum_rows: 1,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 8,
            maximum_bytes: 8_192,
            maximum_estimated_tokens: 2_048,
        },
        issued_at_unix_ms: now_unix_ms()?,
        expires_at_unix_ms: now_unix_ms()?.saturating_add(60_000),
        evidence_ids: vec!["evidence.office300.excel-e2e".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let result = execute_spreadsheet_query(&fresh, &query, now_unix_ms()?, &limits)
        .map_err(|error| error.to_string())?;
    let slice = slice_spreadsheet_context(
        "slice.office300.e2e",
        "case.office300.e2e",
        &result,
        &query.context_budget,
        &limits,
        vec!["evidence.office300.context-slice".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    let after_excel =
        d2i_windows_host::installed_excel_process_ids().map_err(|error| error.to_string())?;
    let residual = after_excel
        .iter()
        .filter(|process_id| !before_excel.contains(process_id))
        .count();
    let original_unchanged = file_sha256(&source)? == source_sha256;
    let mut report = SpreadsheetE2eReportV1 {
        schema_version: 1,
        source_sha256,
        file_generation_sha256: file_index.snapshot.source_content_sha256,
        excel_generation_sha256: fresh.snapshot.source_content_sha256,
        excel_executable_sha256: file_sha256(&arguments.excel)?,
        excel_process_id: excel_receipt.excel_process_id,
        formula_cells: fresh.snapshot.total_formula_cells,
        query_result_sha256: result.result_sha256,
        context_slice_sha256: slice.slice_sha256,
        context_facts: slice.selected_fact_count,
        context_bytes: slice.serialized_bytes,
        wfp_provider_key: verified_after.provider_key,
        wfp_sublayer_key: verified_after.sublayer_key,
        wfp_filter_keys: verified_after.filter_keys,
        wfp_exact_before: true,
        wfp_exact_after: true,
        wfp_removed: true,
        appcontainer_profile_removed: true,
        residual_excel_processes: u32::try_from(residual)
            .map_err(|error| format!("residual Excel count: {error}"))?,
        original_unchanged,
        complete: residual == 0 && original_unchanged,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = report_hash(&report)?;
    if !report.complete {
        return Err("Excel E2E terminal invariants differ".to_owned());
    }
    fs::write(
        report_path,
        canonical_json_bytes(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    println!("{}", report.report_sha256);
    Ok(())
}

#[cfg(windows)]
fn cleanup_wfp(profile_name: &str, profile_sid: &str) -> Result<(), String> {
    d2i_windows_host::remove_wfp_loopback_policy(profile_sid).map_err(|error| error.to_string())?;
    d2i_windows_host::delete_appcontainer_profile(profile_name).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn file_sha256(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(windows)]
fn now_unix_ms() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())
        .and_then(|duration| u64::try_from(duration.as_millis()).map_err(|error| error.to_string()))
}

#[cfg(windows)]
fn report_hash(report: &SpreadsheetE2eReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::json!(ZERO_HASH);
    canonical_json_bytes(&value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Excel live E2E requires Windows desktop Office deployment");
    std::process::exit(2);
}
