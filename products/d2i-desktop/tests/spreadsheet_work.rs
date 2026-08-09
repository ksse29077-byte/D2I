use d2i_desktop::{
    create_xlsx_workbook, inspect_xlsx_workbook, mutate_xlsx_workbook,
    spawn_spreadsheet_file_worker, ResolvedSpreadsheetOperationV1, SpreadsheetFileWorkerRequestV1,
};
use d2i_office_capability::sha256_bytes;
use d2i_spreadsheet_capability::{
    default_spreadsheet_resource_limits, parse_spreadsheet_json_strict, SpreadsheetColumnValueV1,
    SpreadsheetFormulaV1, SpreadsheetMutationV1, SpreadsheetQueryV1, SpreadsheetScalarV1,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "d2i-office300-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("test root must be created: {error}"));
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn pinned_file_worker_mutates_new_generation_and_preserves_original() {
    let root = TestRoot::new("file-worker");
    let source = root.0.join("generation-0001.xlsx");
    let destination = root.0.join("generation-0002.xlsx");
    let limits = default_spreadsheet_resource_limits();
    create_xlsx_workbook(
        &source,
        "Records",
        &["Record".to_owned(), "Amount".to_owned()],
        &limits,
    )
    .unwrap_or_else(|error| panic!("fixture workbook must be created: {error}"));
    let original = file_hash(&source);
    let index = inspect_xlsx_workbook(
        &source,
        "workbook.office300.test",
        "artifact.office300.test",
        1,
        "backend.xlsx.file",
        1_000,
        &limits,
    )
    .unwrap_or_else(|error| panic!("fixture workbook must inspect: {error}"));
    let columns = &index.tables[0].metadata.columns;
    let operation = ResolvedSpreadsheetOperationV1 {
        mutation: SpreadsheetMutationV1::AppendTableRow {
            table_id: index.tables[0].metadata.table_id.clone(),
            values: vec![
                SpreadsheetColumnValueV1 {
                    column_id: columns[0].column_id.clone(),
                    value: SpreadsheetScalarV1::Text {
                        value: "record-001".to_owned(),
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: columns[1].column_id.clone(),
                    value: SpreadsheetScalarV1::Integer { value: 42 },
                },
            ],
        },
    };
    let worker = Path::new(env!("CARGO_BIN_EXE_d2i-office300-spreadsheet-worker"));
    let response = spawn_spreadsheet_file_worker(
        worker,
        &file_hash(worker),
        &SpreadsheetFileWorkerRequestV1 {
            schema_version: 1,
            request_id: "request.office300.file-worker-test".to_owned(),
            source_path: source.to_string_lossy().to_string(),
            destination_path: destination.to_string_lossy().to_string(),
            expected_source_sha256: original.clone(),
            workbook_id: "workbook.office300.test".to_owned(),
            artifact_id: "artifact.office300.test".to_owned(),
            generation: 2,
            backend_id: "backend.xlsx.file".to_owned(),
            observed_at_unix_ms: 2_000,
            operation,
            limits,
        },
        Duration::from_secs(30),
    )
    .unwrap_or_else(|error| panic!("pinned file worker must succeed: {error}"));
    assert_eq!(file_hash(&source), original);
    assert_eq!(response.snapshot.artifact_generation, 2);
    assert_eq!(response.snapshot.tables[0].row_count, 1);
    assert_eq!(response.snapshot.total_populated_cells, 4);
    assert!(destination.is_file());
}

#[test]
fn file_backend_rejects_formula_without_calculation_engine() {
    let root = TestRoot::new("formula-rejection");
    let source = root.0.join("generation-0001.xlsx");
    let destination = root.0.join("generation-0002.xlsx");
    let limits = default_spreadsheet_resource_limits();
    create_xlsx_workbook(
        &source,
        "Records",
        &["Left".to_owned(), "Right".to_owned(), "Result".to_owned()],
        &limits,
    )
    .unwrap_or_else(|error| panic!("fixture workbook must be created: {error}"));
    let error = match mutate_xlsx_workbook(
        &source,
        &destination,
        &ResolvedSpreadsheetOperationV1 {
            mutation: SpreadsheetMutationV1::SetCellFormula {
                target_cell_id: "cell.sheet.0001.r000001.c000003".to_owned(),
                formula: SpreadsheetFormulaV1::Difference {
                    left_cell_id: "cell.sheet.0001.r000001.c000001".to_owned(),
                    right_cell_id: "cell.sheet.0001.r000001.c000002".to_owned(),
                },
            },
        },
        "workbook.office300.test",
        "artifact.office300.test",
        2,
        "backend.xlsx.file",
        2_000,
        &limits,
    ) {
        Ok(_) => panic!("file backend must not claim formula calculation"),
        Err(error) => error,
    };
    assert!(error.contains("does not calculate formulas"));
    assert!(!destination.exists());
}

#[test]
fn strict_spreadsheet_json_rejects_unknown_fields() {
    let error = match parse_spreadsheet_json_strict::<SpreadsheetQueryV1>(
        br#"{"schema_version":1,"unknown":true}"#,
    ) {
        Ok(_) => panic!("unknown spreadsheet fields must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unknown field"));
}

fn file_hash(path: &Path) -> String {
    sha256_bytes(
        &fs::read(path).unwrap_or_else(|error| panic!("test file must be readable: {error}")),
    )
}
