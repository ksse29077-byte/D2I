use super::*;
use d2i_situation_model::{ContentTrustClassV1, FreshnessBoundV1};

const NOW: u64 = 1_500;

fn hash(label: &str) -> String {
    spreadsheet_canonical_sha256(&label)
        .unwrap_or_else(|error| panic!("test hash must be valid: {error}"))
}

fn column(
    column_id: &str,
    ordinal: u32,
    inferred_type: SpreadsheetColumnTypeV1,
) -> SpreadsheetColumnV1 {
    SpreadsheetColumnV1 {
        column_id: column_id.to_owned(),
        ordinal,
        inferred_type,
        header_sha256: hash(column_id),
        unit_id: (column_id == "amount").then(|| "unit.usd".to_owned()),
        nullable: false,
    }
}

fn test_workbook(row_count: u32) -> IndexedSpreadsheetWorkbookV1 {
    let columns = vec![
        column("record_id", 1, SpreadsheetColumnTypeV1::Text),
        column("department", 2, SpreadsheetColumnTypeV1::Text),
        column("amount", 3, SpreadsheetColumnTypeV1::Integer),
        column("approved", 4, SpreadsheetColumnTypeV1::Boolean),
        column("quarter", 5, SpreadsheetColumnTypeV1::Text),
        column("item_count", 6, SpreadsheetColumnTypeV1::Integer),
        column("ratio", 7, SpreadsheetColumnTypeV1::Decimal),
        column("recorded_date", 8, SpreadsheetColumnTypeV1::Date),
    ];
    let table = SpreadsheetTableV1 {
        table_id: "table.records".to_owned(),
        sheet_id: "sheet.records".to_owned(),
        source_range_sha256: hash("records-range"),
        row_count,
        columns,
        table_state_sha256: hash("records-state"),
    };
    let populated = u64::from(row_count) * 8;
    let snapshot = SpreadsheetSemanticSnapshotV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        workbook_id: "workbook.office".to_owned(),
        artifact_id: "artifact.office.records".to_owned(),
        artifact_generation: 1,
        format_id: SpreadsheetFormatV1::Xlsx,
        backend_id: "backend.xlsx.file".to_owned(),
        sheets: vec![SpreadsheetSheetV1 {
            sheet_id: "sheet.records".to_owned(),
            ordinal: 1,
            sheet_name_sha256: hash("Records"),
            used_row_count: row_count + 1,
            used_column_count: 8,
            populated_cell_count: populated,
            formula_count: 0,
            table_ids: vec!["table.records".to_owned()],
            sheet_state_sha256: hash("sheet-state"),
        }],
        tables: vec![table.clone()],
        total_populated_cells: populated,
        total_formula_cells: 0,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: hash("source"),
        workbook_data_sha256: hash("data"),
        semantic_state_sha256: hash("semantics"),
        observed_at_unix_ms: 1_000,
        freshness_expires_at_unix_ms: 2_000,
        evidence_ids: vec!["evidence.fixture".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("test snapshot must seal: {error}"));

    let rows = (0..row_count)
        .map(|index| IndexedSpreadsheetRowV1 {
            row_id: format!("row.{:06}", index + 1),
            ordinal: index + 1,
            values: vec![
                SpreadsheetColumnValueV1 {
                    column_id: "record_id".to_owned(),
                    value: SpreadsheetScalarV1::Text {
                        value: format!("record.{index}"),
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "department".to_owned(),
                    value: SpreadsheetScalarV1::Text {
                        value: format!("dept.{}", index % 4),
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "amount".to_owned(),
                    value: SpreadsheetScalarV1::Integer {
                        value: i64::from(index),
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "approved".to_owned(),
                    value: SpreadsheetScalarV1::Boolean {
                        value: index % 2 == 0,
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "quarter".to_owned(),
                    value: SpreadsheetScalarV1::Text {
                        value: format!("q{}", index % 4 + 1),
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "item_count".to_owned(),
                    value: SpreadsheetScalarV1::Integer { value: 1 },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "ratio".to_owned(),
                    value: SpreadsheetScalarV1::Decimal {
                        scaled_value: i64::from(index % 100),
                        scale: 2,
                    },
                },
                SpreadsheetColumnValueV1 {
                    column_id: "recorded_date".to_owned(),
                    value: SpreadsheetScalarV1::Date {
                        days_since_unix_epoch: 20_000 + (index % 365) as i32,
                    },
                },
            ],
        })
        .collect();
    IndexedSpreadsheetWorkbookV1 {
        snapshot,
        tables: vec![IndexedSpreadsheetTableV1 {
            metadata: table,
            rows,
        }],
    }
}

fn filter_query(workbook: &IndexedSpreadsheetWorkbookV1) -> SpreadsheetQueryV1 {
    SpreadsheetQueryV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        query_id: "query.office.department".to_owned(),
        case_id: "case.office.300".to_owned(),
        workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        table_id: "table.records".to_owned(),
        plan: SpreadsheetQueryPlanV1::Filter {
            predicates: vec![SpreadsheetPredicateV1 {
                column_id: "department".to_owned(),
                operator: SpreadsheetPredicateOperatorV1::Equal,
                operand: SpreadsheetScalarV1::Text {
                    value: "dept.0".to_owned(),
                },
            }],
            projection_column_ids: vec![
                "record_id".to_owned(),
                "department".to_owned(),
                "amount".to_owned(),
                "approved".to_owned(),
                "quarter".to_owned(),
                "item_count".to_owned(),
                "ratio".to_owned(),
                "recorded_date".to_owned(),
            ],
            maximum_rows: 32,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 64,
            maximum_bytes: 32 * 1024,
            maximum_estimated_tokens: 8_192,
        },
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        evidence_ids: vec!["evidence.query".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("test query must seal: {error}"))
}

#[test]
fn default_limits_are_valid() {
    validate_limits(&default_spreadsheet_resource_limits())
        .unwrap_or_else(|error| panic!("default limits must validate: {error}"));
}

#[test]
fn large_workbook_is_sliced_before_model_context() {
    let workbook = test_workbook(20_000);
    let query = filter_query(&workbook);
    let result = execute_spreadsheet_query(
        &workbook,
        &query,
        NOW,
        &default_spreadsheet_resource_limits(),
    )
    .unwrap_or_else(|error| panic!("large query must execute: {error}"));
    assert_eq!(result.scanned_rows, 20_000);
    assert_eq!(result.scanned_cells, 160_000);
    assert_eq!(result.matched_rows, 5_000);
    assert_eq!(result.facts.len(), 256);

    let slice = slice_spreadsheet_context(
        "slice.office.department",
        "case.office.300",
        &result,
        &query.context_budget,
        &default_spreadsheet_resource_limits(),
        vec!["evidence.slice".to_owned()],
    )
    .unwrap_or_else(|error| panic!("context slicing must succeed: {error}"));
    assert!(!slice.selected_facts.is_empty());
    assert!(slice.selected_facts.len() <= 64);
    assert_eq!(
        usize::try_from(slice.omitted_fact_count)
            .unwrap_or_else(|error| panic!("omitted count must fit usize: {error}"))
            + slice.selected_facts.len(),
        256
    );
    assert!(slice.serialized_bytes <= 32 * 1024);
    assert!(slice.estimated_tokens <= 8_192);
    assert_eq!(slice.source_cell_count, 160_000);
    assert!(!slice.complete_for_query);
}

#[test]
fn identical_query_has_identical_result_and_slice_hashes() {
    let workbook = test_workbook(128);
    let query = filter_query(&workbook);
    let limits = default_spreadsheet_resource_limits();
    let first = execute_spreadsheet_query(&workbook, &query, NOW, &limits)
        .unwrap_or_else(|error| panic!("first query must execute: {error}"));
    let second = execute_spreadsheet_query(&workbook, &query, NOW, &limits)
        .unwrap_or_else(|error| panic!("second query must execute: {error}"));
    assert_eq!(first.result_sha256, second.result_sha256);

    let first_slice = slice_spreadsheet_context(
        "slice.office.repeat",
        "case.office.300",
        &first,
        &query.context_budget,
        &limits,
        vec!["evidence.slice".to_owned()],
    )
    .unwrap_or_else(|error| panic!("first slice must seal: {error}"));
    let second_slice = slice_spreadsheet_context(
        "slice.office.repeat",
        "case.office.300",
        &second,
        &query.context_budget,
        &limits,
        vec!["evidence.slice".to_owned()],
    )
    .unwrap_or_else(|error| panic!("second slice must seal: {error}"));
    assert_eq!(first_slice.slice_sha256, second_slice.slice_sha256);
}

#[test]
fn aggregate_returns_typed_group_facts() {
    let workbook = test_workbook(20_000);
    let query = SpreadsheetQueryV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        query_id: "query.office.aggregate".to_owned(),
        case_id: "case.office.300".to_owned(),
        workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        table_id: "table.records".to_owned(),
        plan: SpreadsheetQueryPlanV1::Aggregate {
            predicates: Vec::new(),
            group_by_column_ids: vec!["department".to_owned()],
            measures: vec![
                SpreadsheetMeasureV1 {
                    measure_id: "record_count".to_owned(),
                    aggregate: SpreadsheetAggregateV1::Count,
                    column_id: None,
                    unit_id: None,
                },
                SpreadsheetMeasureV1 {
                    measure_id: "amount_sum".to_owned(),
                    aggregate: SpreadsheetAggregateV1::Sum,
                    column_id: Some("amount".to_owned()),
                    unit_id: Some("unit.usd".to_owned()),
                },
            ],
            maximum_groups: 4,
        },
        context_budget: SpreadsheetContextBudgetV1 {
            maximum_facts: 16,
            maximum_bytes: 16 * 1024,
            maximum_estimated_tokens: 4_096,
        },
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        evidence_ids: vec!["evidence.aggregate".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("aggregate query must seal: {error}"));
    let result = execute_spreadsheet_query(
        &workbook,
        &query,
        NOW,
        &default_spreadsheet_resource_limits(),
    )
    .unwrap_or_else(|error| panic!("aggregate query must execute: {error}"));
    assert_eq!(result.facts.len(), 8);
    assert_eq!(result.matched_rows, 20_000);
    assert_eq!(
        result
            .facts
            .iter()
            .filter(|fact| fact.predicate_id == "record_count")
            .map(|fact| &fact.typed_value)
            .collect::<Vec<_>>(),
        vec![
            &SpreadsheetScalarV1::Integer { value: 5_000 },
            &SpreadsheetScalarV1::Integer { value: 5_000 },
            &SpreadsheetScalarV1::Integer { value: 5_000 },
            &SpreadsheetScalarV1::Integer { value: 5_000 },
        ]
    );
}

#[test]
fn stale_unknown_and_type_mismatched_queries_fail_closed() {
    let workbook = test_workbook(8);
    let limits = default_spreadsheet_resource_limits();
    let query = filter_query(&workbook);
    assert!(matches!(
        execute_spreadsheet_query(&workbook, &query, 2_001, &limits),
        Err(SpreadsheetCapabilityError::Stale(_))
    ));

    let mut unknown = query.clone();
    if let SpreadsheetQueryPlanV1::Filter {
        projection_column_ids,
        ..
    } = &mut unknown.plan
    {
        projection_column_ids[0] = "unknown_column".to_owned();
    }
    unknown.query_sha256 = ZERO_HASH.to_owned();
    let unknown = unknown
        .seal()
        .unwrap_or_else(|error| panic!("unknown-column query contract must seal: {error}"));
    assert!(matches!(
        execute_spreadsheet_query(&workbook, &unknown, NOW, &limits),
        Err(SpreadsheetCapabilityError::Invalid(_))
    ));

    let mut mismatched = query;
    if let SpreadsheetQueryPlanV1::Filter { predicates, .. } = &mut mismatched.plan {
        predicates[0].operand = SpreadsheetScalarV1::Integer { value: 4 };
    }
    mismatched.query_sha256 = ZERO_HASH.to_owned();
    let mismatched = mismatched
        .seal()
        .unwrap_or_else(|error| panic!("typed query contract must seal: {error}"));
    assert!(matches!(
        execute_spreadsheet_query(&workbook, &mismatched, NOW, &limits),
        Err(SpreadsheetCapabilityError::Invalid(_))
    ));
}

#[test]
fn credential_like_cell_never_enters_context() {
    let mut workbook = test_workbook(1);
    workbook.tables[0].rows[0].values[0].value = SpreadsheetScalarV1::Text {
        value: "password: do-not-disclose".to_owned(),
    };
    let mut query = filter_query(&workbook);
    query.plan = SpreadsheetQueryPlanV1::Filter {
        predicates: vec![SpreadsheetPredicateV1 {
            column_id: "approved".to_owned(),
            operator: SpreadsheetPredicateOperatorV1::Equal,
            operand: SpreadsheetScalarV1::Boolean { value: true },
        }],
        projection_column_ids: vec!["record_id".to_owned()],
        maximum_rows: 1,
    };
    query.query_sha256 = ZERO_HASH.to_owned();
    let query = query
        .seal()
        .unwrap_or_else(|error| panic!("sensitive fixture query must seal: {error}"));
    let limits = default_spreadsheet_resource_limits();
    let result =
        execute_spreadsheet_query(&workbook, &query, NOW, &limits).unwrap_or_else(|error| {
            panic!("sensitive value may remain in private query result: {error}")
        });
    assert!(matches!(
        slice_spreadsheet_context(
            "slice.sensitive",
            "case.office.300",
            &result,
            &query.context_budget,
            &limits,
            vec!["evidence.slice".to_owned()],
        ),
        Err(SpreadsheetCapabilityError::Sensitive(_))
    ));
}

#[test]
fn context_projection_preserves_verified_typed_lineage() {
    let workbook = test_workbook(8);
    let query = filter_query(&workbook);
    let limits = default_spreadsheet_resource_limits();
    let result = execute_spreadsheet_query(&workbook, &query, NOW, &limits)
        .unwrap_or_else(|error| panic!("query must execute: {error}"));
    let slice = slice_spreadsheet_context(
        "slice.projection",
        "case.office.300",
        &result,
        &query.context_budget,
        &limits,
        vec!["evidence.slice".to_owned()],
    )
    .unwrap_or_else(|error| panic!("slice must seal: {error}"));
    let projection = project_context_slice_to_situation(
        &slice,
        FreshnessBoundV1 {
            observed_at_unix_seconds: 1,
            valid_until_unix_seconds: 61,
            maximum_age_seconds: 60,
        },
    )
    .unwrap_or_else(|error| panic!("projection must validate: {error}"));
    assert_eq!(projection.facts.len(), slice.selected_facts.len());
    assert!(projection.facts.iter().all(|fact| {
        fact.source_trust_class == ContentTrustClassV1::VerifiedObservation
            && fact.typed_object["context_slice_sha256"] == slice.slice_sha256
    }));
}

#[test]
fn activation_is_single_use_and_unknown_json_fields_are_rejected() {
    let mut ledger = SpreadsheetActivationLedgerV1::default();
    let activation_hash = hash("activation");
    ledger
        .consume("activation.office.300", &activation_hash)
        .unwrap_or_else(|error| panic!("first activation must be admitted: {error}"));
    assert!(matches!(
        ledger.consume("activation.office.300", &activation_hash),
        Err(SpreadsheetCapabilityError::Replay(_))
    ));

    let workbook = test_workbook(1);
    let query = filter_query(&workbook);
    let mut value =
        serde_json::to_value(query).unwrap_or_else(|error| panic!("query must serialize: {error}"));
    value["unexpected"] = serde_json::json!(true);
    let bytes = serde_json::to_vec(&value)
        .unwrap_or_else(|error| panic!("fixture JSON must serialize: {error}"));
    assert!(parse_spreadsheet_json_strict::<SpreadsheetQueryV1>(&bytes).is_err());
}

#[test]
fn indexed_row_order_and_declared_types_are_enforced() {
    let limits = default_spreadsheet_resource_limits();
    let mut unordered = test_workbook(2);
    unordered.tables[0].rows.swap(0, 1);
    let query = filter_query(&unordered);
    assert!(matches!(
        execute_spreadsheet_query(&unordered, &query, NOW, &limits),
        Err(SpreadsheetCapabilityError::Invalid(_))
    ));

    let mut mistyped = test_workbook(1);
    mistyped.tables[0].rows[0].values[2].value = SpreadsheetScalarV1::Text {
        value: "not-a-number".to_owned(),
    };
    let query = filter_query(&mistyped);
    assert!(matches!(
        execute_spreadsheet_query(&mistyped, &query, NOW, &limits),
        Err(SpreadsheetCapabilityError::Invalid(_))
    ));
}
