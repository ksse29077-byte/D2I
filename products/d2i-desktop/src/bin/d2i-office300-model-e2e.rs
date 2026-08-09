use d2i_desktop::{PinnedWork500ModelSuiteV1, Work500ModelPathsV1};
use d2i_intelligence_provider::SituationInterpretationRequestV1;
use d2i_office_capability::{canonical_json_bytes, sha256_bytes};
use d2i_situation_model::{FreshnessBoundV1, ZERO_HASH as SITUATION_ZERO_HASH};
use d2i_spreadsheet_capability::{
    default_spreadsheet_resource_limits, execute_spreadsheet_query,
    project_context_slice_to_situation, slice_spreadsheet_context, IndexedSpreadsheetRowV1,
    IndexedSpreadsheetTableV1, IndexedSpreadsheetWorkbookV1, SpreadsheetColumnTypeV1,
    SpreadsheetColumnV1, SpreadsheetColumnValueV1, SpreadsheetContextBudgetV1, SpreadsheetFormatV1,
    SpreadsheetPredicateOperatorV1, SpreadsheetPredicateV1, SpreadsheetQueryPlanV1,
    SpreadsheetQueryV1, SpreadsheetScalarV1, SpreadsheetSemanticSnapshotV1, SpreadsheetSheetV1,
    SpreadsheetTableV1, ZERO_HASH,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const ROWS: u32 = 20_000;
const COLUMNS: u32 = 8;

#[derive(Serialize)]
struct SpreadsheetModelE2eReportV1 {
    schema_version: u32,
    model_artifact_sha256: String,
    runtime_artifact_sha256: String,
    workbook_rows: u32,
    source_cells: u64,
    query_scanned_cells: u64,
    query_fact_count: u32,
    context_fact_count: u32,
    omitted_fact_count: u32,
    context_bytes: u32,
    estimated_tokens: u32,
    situation_request_bytes: u32,
    provider_invocations: u32,
    actual_qwen_cases: u32,
    elapsed_microseconds: u64,
    peak_worker_memory_bytes: u64,
    context_slice_sha256: String,
    situation_projection_sha256: String,
    invocation_sha256: String,
    result_sha256: String,
    raw_workbook_dump_count: u32,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("OFFICE-300 model E2E failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err("usage: d2i-office300-model-e2e <runtime> <model> <output-json>".to_owned());
    }
    let runtime = PathBuf::from(&arguments[0]);
    let model = PathBuf::from(&arguments[1]);
    let output = PathBuf::from(&arguments[2]);
    if output.exists() {
        return Err("spreadsheet model report must be a new file".to_owned());
    }
    let now_seconds = unix_seconds()?;
    let now_milliseconds = now_seconds.saturating_mul(1_000);
    let workbook = large_workbook(now_milliseconds)?;
    let query = SpreadsheetQueryV1 {
        schema_version: 1,
        query_id: "query.office300.model-context".to_owned(),
        case_id: "case.office300.model-context".to_owned(),
        workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        table_id: "table.office300.records".to_owned(),
        plan: SpreadsheetQueryPlanV1::Filter {
            predicates: vec![SpreadsheetPredicateV1 {
                column_id: "column.department".to_owned(),
                operator: SpreadsheetPredicateOperatorV1::Equal,
                operand: SpreadsheetScalarV1::Text {
                    value: "department.0".to_owned(),
                },
            }],
            projection_column_ids: vec![
                "column.record".to_owned(),
                "column.department".to_owned(),
                "column.amount".to_owned(),
                "column.approved".to_owned(),
            ],
            maximum_rows: 32,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 8,
            maximum_bytes: 8 * 1024,
            maximum_estimated_tokens: 2_048,
        },
        issued_at_unix_ms: now_milliseconds,
        expires_at_unix_ms: now_milliseconds.saturating_add(60_000),
        evidence_ids: vec!["evidence.office300.query".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let result = execute_spreadsheet_query(
        &workbook,
        &query,
        now_milliseconds,
        &default_spreadsheet_resource_limits(),
    )
    .map_err(|error| error.to_string())?;
    let slice = slice_spreadsheet_context(
        "slice.office300.model-context",
        "case.office300.model-context",
        &result,
        &query.context_budget,
        &default_spreadsheet_resource_limits(),
        vec!["evidence.office300.slice".to_owned()],
    )
    .map_err(|error| error.to_string())?;
    let projection = project_context_slice_to_situation(
        &slice,
        FreshnessBoundV1 {
            observed_at_unix_seconds: now_seconds,
            valid_until_unix_seconds: now_seconds.saturating_add(60),
            maximum_age_seconds: 60,
        },
    )
    .map_err(|error| error.to_string())?;
    let request = SituationInterpretationRequestV1 {
        schema_version: 1,
        request_id: "request.office300.situation".to_owned(),
        case_id: "case.office300.model-context".to_owned(),
        context_sha256: projection.projection_sha256.clone(),
        generation: 1,
        trusted_base_facts: projection.facts,
        unresolved_requirement_ids: vec!["requirement.spreadsheet.next-step".to_owned()],
        allowed_semantic_target_ids: vec!["cell.sheet.0001.r000001.c000004".to_owned()],
        allowed_capability_ids: vec!["spreadsheet.set_cell_formula".to_owned()],
        forbidden_capability_ids: vec!["process.launch".to_owned()],
        source_observation_hashes: vec![slice.slice_sha256.clone()],
        previous_situation_sha256: None,
        provider_invocation_sha256: SITUATION_ZERO_HASH.to_owned(),
        evidence_ids: vec!["evidence.office300.typed-facts".to_owned()],
        request_sha256: SITUATION_ZERO_HASH.to_owned(),
    };
    let situation_request_bytes = u32::try_from(
        canonical_json_bytes(&request)
            .map_err(|error| error.to_string())?
            .len(),
    )
    .map_err(|error| error.to_string())?;
    if situation_request_bytes > 32 * 1024
        || slice.source_cell_count != u64::from(ROWS) * u64::from(COLUMNS)
        || slice.selected_fact_count > 8
        || slice.serialized_bytes > 8 * 1024
    {
        return Err("spreadsheet model context exceeded its bounded slice".to_owned());
    }
    let workspace = workspace_root()?;
    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: runtime.clone(),
        model_artifact: model.clone(),
        work_root: workspace.join("target/office300-model-process"),
    })
    .map_err(|error| error.to_string())?;
    let call = suite
        .interpret_situation(
            request,
            "invocation.office300.situation",
            "replay.office300.situation",
        )
        .map_err(|error| error.to_string())?;
    call.result.validate().map_err(|error| error.to_string())?;
    let mut report = SpreadsheetModelE2eReportV1 {
        schema_version: 1,
        model_artifact_sha256: file_sha256(&model)?,
        runtime_artifact_sha256: file_sha256(&runtime)?,
        workbook_rows: ROWS,
        source_cells: slice.source_cell_count,
        query_scanned_cells: result.scanned_cells,
        query_fact_count: u32::try_from(result.facts.len()).map_err(|error| error.to_string())?,
        context_fact_count: slice.selected_fact_count,
        omitted_fact_count: slice.omitted_fact_count,
        context_bytes: slice.serialized_bytes,
        estimated_tokens: slice.estimated_tokens,
        situation_request_bytes,
        provider_invocations: 1,
        actual_qwen_cases: 1,
        elapsed_microseconds: call.metrics.elapsed_milliseconds.saturating_mul(1_000),
        peak_worker_memory_bytes: call.metrics.peak_job_memory_bytes,
        context_slice_sha256: slice.slice_sha256,
        situation_projection_sha256: projection.projection_sha256,
        invocation_sha256: call.invocation.invocation_sha256,
        result_sha256: call.result.result_sha256,
        raw_workbook_dump_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 = report_hash(&report)?;
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(
        output,
        canonical_json_bytes(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn large_workbook(now_unix_ms: u64) -> Result<IndexedSpreadsheetWorkbookV1, String> {
    let columns = vec![
        column("column.record", 1, SpreadsheetColumnTypeV1::Text)?,
        column("column.department", 2, SpreadsheetColumnTypeV1::Text)?,
        column("column.amount", 3, SpreadsheetColumnTypeV1::Integer)?,
        column("column.approved", 4, SpreadsheetColumnTypeV1::Boolean)?,
        column("column.quarter", 5, SpreadsheetColumnTypeV1::Text)?,
        column("column.count", 6, SpreadsheetColumnTypeV1::Integer)?,
        column("column.ratio", 7, SpreadsheetColumnTypeV1::Decimal)?,
        column("column.date", 8, SpreadsheetColumnTypeV1::Date)?,
    ];
    let populated = u64::from(ROWS) * u64::from(COLUMNS);
    let table = SpreadsheetTableV1 {
        table_id: "table.office300.records".to_owned(),
        sheet_id: "sheet.office300.records".to_owned(),
        source_range_sha256: hash("range.office300.records")?,
        row_count: ROWS,
        columns,
        table_state_sha256: hash("table.office300.state")?,
    };
    let snapshot = SpreadsheetSemanticSnapshotV1 {
        schema_version: 1,
        workbook_id: "workbook.office300.model".to_owned(),
        artifact_id: "artifact.office300.model".to_owned(),
        artifact_generation: 1,
        format_id: SpreadsheetFormatV1::Xlsx,
        backend_id: "backend.xlsx.file".to_owned(),
        sheets: vec![SpreadsheetSheetV1 {
            sheet_id: "sheet.office300.records".to_owned(),
            ordinal: 1,
            sheet_name_sha256: hash("Records")?,
            used_row_count: ROWS.saturating_add(1),
            used_column_count: COLUMNS,
            populated_cell_count: populated,
            formula_count: 0,
            table_ids: vec![table.table_id.clone()],
            sheet_state_sha256: hash("sheet.office300.state")?,
        }],
        tables: vec![table.clone()],
        total_populated_cells: populated,
        total_formula_cells: 0,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: hash("source.office300.large")?,
        workbook_data_sha256: hash("data.office300.large")?,
        semantic_state_sha256: hash("semantic.office300.large")?,
        observed_at_unix_ms: now_unix_ms,
        freshness_expires_at_unix_ms: now_unix_ms.saturating_add(60_000),
        evidence_ids: vec!["evidence.office300.large-index".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let rows = (0..ROWS)
        .map(|index| IndexedSpreadsheetRowV1 {
            row_id: format!("row.{:06}", index + 1),
            ordinal: index + 1,
            values: vec![
                value(
                    "column.record",
                    SpreadsheetScalarV1::Text {
                        value: format!("record.{index}"),
                    },
                ),
                value(
                    "column.department",
                    SpreadsheetScalarV1::Text {
                        value: format!("department.{}", index % 4),
                    },
                ),
                value(
                    "column.amount",
                    SpreadsheetScalarV1::Integer {
                        value: i64::from(index),
                    },
                ),
                value(
                    "column.approved",
                    SpreadsheetScalarV1::Boolean {
                        value: index % 2 == 0,
                    },
                ),
                value(
                    "column.quarter",
                    SpreadsheetScalarV1::Text {
                        value: format!("quarter.{}", index % 4 + 1),
                    },
                ),
                value("column.count", SpreadsheetScalarV1::Integer { value: 1 }),
                value(
                    "column.ratio",
                    SpreadsheetScalarV1::Decimal {
                        scaled_value: i64::from(index % 100),
                        scale: 2,
                    },
                ),
                value(
                    "column.date",
                    SpreadsheetScalarV1::Date {
                        days_since_unix_epoch: 20_000 + (index % 365) as i32,
                    },
                ),
            ],
        })
        .collect();
    Ok(IndexedSpreadsheetWorkbookV1 {
        snapshot,
        tables: vec![IndexedSpreadsheetTableV1 {
            metadata: table,
            rows,
        }],
    })
}

fn column(
    id: &str,
    ordinal: u32,
    inferred_type: SpreadsheetColumnTypeV1,
) -> Result<SpreadsheetColumnV1, String> {
    Ok(SpreadsheetColumnV1 {
        column_id: id.to_owned(),
        ordinal,
        inferred_type,
        header_sha256: hash(id)?,
        unit_id: (id == "column.amount").then(|| "unit.krw".to_owned()),
        nullable: false,
    })
}

fn value(column_id: &str, value: SpreadsheetScalarV1) -> SpreadsheetColumnValueV1 {
    SpreadsheetColumnValueV1 {
        column_id: column_id.to_owned(),
        value,
    }
}

fn hash(label: &str) -> Result<String, String> {
    d2i_spreadsheet_capability::spreadsheet_canonical_sha256(&label)
        .map_err(|error| error.to_string())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .map_err(|error| error.to_string())
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    std::fs::read(path)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| error.to_string())
}

fn report_hash(report: &SpreadsheetModelE2eReportV1) -> Result<String, String> {
    let mut value = serde_json::to_value(report).map_err(|error| error.to_string())?;
    value["report_sha256"] = serde_json::Value::String(ZERO_HASH.to_owned());
    d2i_office_capability::canonical_sha256(&value).map_err(|error| error.to_string())
}
