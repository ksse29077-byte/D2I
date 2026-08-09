use d2i_desktop::{
    create_pptx_template, inspect_pptx_presentation, mutate_pptx_presentation,
    spawn_presentation_file_worker, PptxPresentationMutationV1, PresentationFileWorkerRequestV1,
};
use d2i_office_capability::sha256_bytes;
use d2i_presentation_capability::{
    default_presentation_resource_limits, parse_presentation_json_strict, PresentationChartKindV1,
    PresentationChartSpecV1, PresentationFactBindingV1, PresentationLayoutSlotV1,
    PresentationMutationV1, PresentationQueryV1, ZERO_HASH,
};
use d2i_spreadsheet_capability::{
    SpreadsheetFactKindV1, SpreadsheetScalarV1, SpreadsheetTypedFactV1,
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
            "d2i-office400-{label}-{}-{nonce}",
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

fn fact(id: &str, value: i64) -> SpreadsheetTypedFactV1 {
    SpreadsheetTypedFactV1 {
        fact_id: id.to_owned(),
        fact_kind: SpreadsheetFactKindV1::Aggregate,
        subject_id: "training.2026-07".to_owned(),
        predicate_id: "participant.count".to_owned(),
        typed_value: SpreadsheetScalarV1::Integer { value },
        unit_id: Some("unit.people".to_owned()),
        source_table_id: "table.training".to_owned(),
        source_column_ids: vec!["column.count".to_owned()],
        source_row_count: 3,
        source_range_sha256: sha256_bytes(b"training-range"),
        confidence_millionths: 1_000_000,
        priority: 1,
        evidence_ids: vec!["evidence.office300.query".to_owned()],
        fact_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("fact: {error}"))
}

fn facts() -> PresentationFactBindingV1 {
    let facts = vec![
        fact("fact.training.manager", 55),
        fact("fact.training.online", 120),
        fact("fact.training.external", 18),
    ];
    let ids = facts
        .iter()
        .map(|value| value.fact_id.clone())
        .collect::<Vec<_>>();
    PresentationFactBindingV1 {
        schema_version: 1,
        binding_id: "binding.office400.training".to_owned(),
        spreadsheet_context_slice_sha256: sha256_bytes(b"spreadsheet-slice"),
        spreadsheet_query_result_sha256: sha256_bytes(b"spreadsheet-result"),
        source_workbook_snapshot_sha256: sha256_bytes(b"spreadsheet-snapshot"),
        facts,
        summary_fact_ids: ids.clone(),
        table_fact_ids: ids.clone(),
        chart_fact_ids: ids,
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("fact binding: {error}"))
}

#[cfg(windows)]
#[test]
fn pinned_file_worker_creates_a_new_generation_and_preserves_original() {
    let root = TestRoot::new("file-worker");
    let source = root.0.join("generation-0001.pptx");
    let destination = root.0.join("generation-0002.pptx");
    let limits = default_presentation_resource_limits();
    let source_snapshot = create_pptx_template(&source, "presentation.office400", 120, &limits)
        .unwrap_or_else(|error| panic!("presentation fixture: {error}"));
    let original = file_hash(&source);
    let worker = Path::new(env!("CARGO_BIN_EXE_d2i-office400-presentation-worker"));
    let response = spawn_presentation_file_worker(
        worker,
        &file_hash(worker),
        &PresentationFileWorkerRequestV1 {
            schema_version: 1,
            request_id: "request.office400.file-worker".to_owned(),
            source_path: source.to_string_lossy().into_owned(),
            destination_path: destination.to_string_lossy().into_owned(),
            workspace_root: root.0.to_string_lossy().into_owned(),
            expected_source_sha256: source_snapshot.source_content_sha256,
            presentation_id: "presentation.office400".to_owned(),
            artifact_id: "artifact.office400".to_owned(),
            generation: 2,
            backend_id: "backend.pptx.file".to_owned(),
            observed_at_unix_ms: 2_000,
            mutation: PresentationMutationV1::AddSlide {
                planned_slide_id: "slide.generated.summary".to_owned(),
                purpose_id: "purpose.executive-summary".to_owned(),
                layout_id: "layout.title-body".to_owned(),
            },
            facts: facts(),
            limits,
        },
        Duration::from_secs(30),
    )
    .unwrap_or_else(|error| panic!("pinned presentation worker: {error}"));
    assert_eq!(file_hash(&source), original);
    assert_eq!(response.snapshot.artifact_generation, 2);
    assert_eq!(response.snapshot.slide_count, 121);
    assert!(destination.is_file());
}

#[test]
fn pptx_backend_rejects_chart_authoring_without_a_chart_package_lowering() {
    let root = TestRoot::new("chart-rejection");
    let source = root.0.join("source.pptx");
    let destination = root.0.join("destination.pptx");
    let limits = default_presentation_resource_limits();
    let snapshot = create_pptx_template(&source, "presentation.office400", 5, &limits)
        .unwrap_or_else(|error| panic!("presentation fixture: {error}"));
    let result = mutate_pptx_presentation(PptxPresentationMutationV1 {
        source: &source,
        destination: &destination,
        workspace_root: &root.0,
        expected_source_sha256: &snapshot.source_content_sha256,
        presentation_id: "presentation.office400",
        artifact_id: "artifact.office400",
        generation: 2,
        backend_id: "backend.pptx.file",
        observed_at_unix_ms: 2_000,
        mutation: &PresentationMutationV1::InsertChart {
            slide_id: "slide.0004".to_owned(),
            shape_id: "shape.training-chart".to_owned(),
            chart: PresentationChartSpecV1 {
                chart_id: "chart.training".to_owned(),
                chart_kind: PresentationChartKindV1::ClusteredColumn,
                slot: PresentationLayoutSlotV1::ChartMain,
                category_labels: vec![
                    "manager".to_owned(),
                    "online".to_owned(),
                    "external".to_owned(),
                ],
                series_label: "participants".to_owned(),
                fact_ids: vec![
                    "fact.training.manager".to_owned(),
                    "fact.training.online".to_owned(),
                    "fact.training.external".to_owned(),
                ],
            },
        },
        facts: &facts(),
        limits: &limits,
    });
    let error = match result {
        Ok(_) => panic!("PPTX file chart authoring unexpectedly succeeded"),
        Err(error) => error,
    };
    assert!(error.contains("does not author charts"));
    assert!(!destination.exists());
}

#[test]
fn package_limits_and_active_external_material_fail_closed() {
    let root = TestRoot::new("package-negative");
    let source = root.0.join("source.pptx");
    let limits = default_presentation_resource_limits();
    create_pptx_template(&source, "presentation.office400", 5, &limits)
        .unwrap_or_else(|error| panic!("presentation fixture: {error}"));
    let mut tiny = limits;
    tiny.maximum_presentation_bytes = 1_024;
    assert!(inspect_pptx_presentation(
        &source,
        "presentation.office400",
        "artifact.office400",
        1,
        "backend.pptx.file",
        1_000,
        &tiny,
    )
    .is_err());
}

#[test]
fn strict_presentation_json_rejects_unknown_fields() {
    let result = parse_presentation_json_strict::<PresentationQueryV1>(
        br#"{"schema_version":1,"unknown":true}"#,
    );
    let error = match result {
        Ok(_) => panic!("unknown presentation field unexpectedly parsed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("unknown field"));
}

fn file_hash(path: &Path) -> String {
    sha256_bytes(
        &fs::read(path).unwrap_or_else(|error| panic!("test file must be readable: {error}")),
    )
}
