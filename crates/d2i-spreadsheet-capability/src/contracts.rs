use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetFormatV1 {
    Xlsx,
    Csv,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetBackendKindV1 {
    XlsxFile,
    CsvFile,
    ExcelCom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetOperationV1 {
    Inspect,
    Query,
    CreateFromTemplate,
    SetCellValue,
    SetCellFormula,
    AppendTableRow,
    ApplyCellStyle,
    CreateTable,
    SaveVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetColumnTypeV1 {
    Blank,
    Text,
    Integer,
    Decimal,
    Boolean,
    Date,
    Error,
    Mixed,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "value_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpreadsheetScalarV1 {
    Blank,
    Text { value: String },
    Integer { value: i64 },
    Decimal { scaled_value: i64, scale: u32 },
    Boolean { value: bool },
    Date { days_since_unix_epoch: i32 },
    Error { code: String },
}

impl SpreadsheetScalarV1 {
    pub fn column_type(&self) -> SpreadsheetColumnTypeV1 {
        match self {
            Self::Blank => SpreadsheetColumnTypeV1::Blank,
            Self::Text { .. } => SpreadsheetColumnTypeV1::Text,
            Self::Integer { .. } => SpreadsheetColumnTypeV1::Integer,
            Self::Decimal { .. } => SpreadsheetColumnTypeV1::Decimal,
            Self::Boolean { .. } => SpreadsheetColumnTypeV1::Boolean,
            Self::Date { .. } => SpreadsheetColumnTypeV1::Date,
            Self::Error { .. } => SpreadsheetColumnTypeV1::Error,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetPredicateOperatorV1 {
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetAggregateV1 {
    Count,
    Sum,
    Minimum,
    Maximum,
    Average,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "query_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpreadsheetQueryPlanV1 {
    Lookup {
        key_column_id: String,
        key_value: SpreadsheetScalarV1,
        projection_column_ids: Vec<String>,
    },
    Filter {
        predicates: Vec<SpreadsheetPredicateV1>,
        projection_column_ids: Vec<String>,
        maximum_rows: u32,
    },
    Aggregate {
        predicates: Vec<SpreadsheetPredicateV1>,
        group_by_column_ids: Vec<String>,
        measures: Vec<SpreadsheetMeasureV1>,
        maximum_groups: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "formula_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpreadsheetFormulaV1 {
    SumRange {
        source_range_id: String,
    },
    Difference {
        left_cell_id: String,
        right_cell_id: String,
    },
    Product {
        left_cell_id: String,
        right_cell_id: String,
    },
    Ratio {
        numerator_cell_id: String,
        denominator_cell_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetFactKindV1 {
    Aggregate,
    Lookup,
    Projection,
    Quality,
    Lineage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetRiskClassV1 {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetOperationResultV1 {
    Verified,
    Rejected,
    Stale,
    Unsupported,
    Unsafe,
    RecoveryRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpreadsheetVerificationStatusV1 {
    Verified,
    Failed,
    Inconclusive,
    Unsupported,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetResourceLimitsV1 {
    pub maximum_workbook_bytes: u64,
    pub maximum_package_entries: u32,
    pub maximum_uncompressed_bytes: u64,
    pub maximum_compression_ratio: u32,
    pub maximum_xml_bytes: u64,
    pub maximum_xml_depth: u32,
    pub maximum_xml_nodes: u32,
    pub maximum_xml_attributes: u32,
    pub maximum_sheets: u32,
    pub maximum_tables: u32,
    pub maximum_rows_per_table: u32,
    pub maximum_columns_per_table: u32,
    pub maximum_populated_cells: u64,
    pub maximum_shared_strings: u32,
    pub maximum_cell_text_characters: u32,
    pub maximum_query_scan_cells: u64,
    pub maximum_query_facts: u32,
    pub maximum_context_facts: u32,
    pub maximum_context_bytes: u32,
    pub maximum_operations_per_case: u32,
    pub maximum_model_invocations: u32,
    pub maximum_save_generations: u32,
    pub maximum_worker_milliseconds: u64,
    pub maximum_application_session_milliseconds: u64,
    pub maximum_worker_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetColumnV1 {
    pub column_id: String,
    pub ordinal: u32,
    pub inferred_type: SpreadsheetColumnTypeV1,
    pub header_sha256: String,
    pub unit_id: Option<String>,
    pub nullable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetTableV1 {
    pub table_id: String,
    pub sheet_id: String,
    pub source_range_sha256: String,
    pub row_count: u32,
    pub columns: Vec<SpreadsheetColumnV1>,
    pub table_state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetSheetV1 {
    pub sheet_id: String,
    pub ordinal: u32,
    pub sheet_name_sha256: String,
    pub used_row_count: u32,
    pub used_column_count: u32,
    pub populated_cell_count: u64,
    pub formula_count: u32,
    pub table_ids: Vec<String>,
    pub sheet_state_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetSemanticSnapshotV1 {
    pub schema_version: u32,
    pub workbook_id: String,
    pub artifact_id: String,
    pub artifact_generation: u64,
    pub format_id: SpreadsheetFormatV1,
    pub backend_id: String,
    pub sheets: Vec<SpreadsheetSheetV1>,
    pub tables: Vec<SpreadsheetTableV1>,
    pub total_populated_cells: u64,
    pub total_formula_cells: u32,
    pub unsupported_feature_ids: Vec<String>,
    pub source_content_sha256: String,
    pub workbook_data_sha256: String,
    pub semantic_state_sha256: String,
    pub observed_at_unix_ms: u64,
    pub freshness_expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub snapshot_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetPredicateV1 {
    pub column_id: String,
    pub operator: SpreadsheetPredicateOperatorV1,
    pub operand: SpreadsheetScalarV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetMeasureV1 {
    pub measure_id: String,
    pub aggregate: SpreadsheetAggregateV1,
    pub column_id: Option<String>,
    pub unit_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetContextBudgetV1 {
    pub maximum_facts: u32,
    pub maximum_bytes: u32,
    pub maximum_estimated_tokens: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetQueryV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub case_id: String,
    pub workbook_snapshot_sha256: String,
    pub table_id: String,
    pub plan: SpreadsheetQueryPlanV1,
    pub context_budget: SpreadsheetContextBudgetV1,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetTypedFactV1 {
    pub fact_id: String,
    pub fact_kind: SpreadsheetFactKindV1,
    pub subject_id: String,
    pub predicate_id: String,
    pub typed_value: SpreadsheetScalarV1,
    pub unit_id: Option<String>,
    pub source_table_id: String,
    pub source_column_ids: Vec<String>,
    pub source_row_count: u32,
    pub source_range_sha256: String,
    pub confidence_millionths: u32,
    pub priority: u32,
    pub evidence_ids: Vec<String>,
    pub fact_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetQueryResultV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub query_sha256: String,
    pub workbook_snapshot_sha256: String,
    pub scanned_rows: u32,
    pub scanned_cells: u64,
    pub matched_rows: u32,
    pub facts: Vec<SpreadsheetTypedFactV1>,
    pub complete: bool,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetContextSliceV1 {
    pub schema_version: u32,
    pub slice_id: String,
    pub case_id: String,
    pub workbook_snapshot_sha256: String,
    pub query_sha256: String,
    pub query_result_sha256: String,
    pub selected_facts: Vec<SpreadsheetTypedFactV1>,
    pub omitted_fact_count: u32,
    pub source_cell_count: u64,
    pub selected_fact_count: u32,
    pub serialized_bytes: u32,
    pub estimated_tokens: u32,
    pub complete_for_query: bool,
    pub evidence_ids: Vec<String>,
    pub slice_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mutation_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SpreadsheetMutationV1 {
    SetCellValue {
        target_cell_id: String,
        value: SpreadsheetScalarV1,
    },
    SetCellFormula {
        target_cell_id: String,
        formula: SpreadsheetFormulaV1,
    },
    AppendTableRow {
        table_id: String,
        values: Vec<SpreadsheetColumnValueV1>,
    },
    ApplyCellStyle {
        target_cell_id: String,
        style_id: String,
    },
    CreateTable {
        sheet_id: String,
        table_id: String,
        column_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetColumnValueV1 {
    pub column_id: String,
    pub value: SpreadsheetScalarV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetCapabilityPackV1 {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub application_family_ids: Vec<String>,
    pub supported_format_ids: Vec<SpreadsheetFormatV1>,
    pub semantic_operations: Vec<SpreadsheetOperationV1>,
    pub query_kinds: Vec<String>,
    pub resource_limits: SpreadsheetResourceLimitsV1,
    pub pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetBackendDescriptorV1 {
    pub schema_version: u32,
    pub backend_id: String,
    pub backend_kind: SpreadsheetBackendKindV1,
    pub supported_format_ids: Vec<SpreadsheetFormatV1>,
    pub supported_operations: Vec<SpreadsheetOperationV1>,
    pub requires_application: bool,
    pub application_sha256: Option<String>,
    pub worker_sha256: String,
    pub network_denied: bool,
    pub macro_disabled: bool,
    pub descriptor_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetBackendApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub backend_descriptor_sha256: String,
    pub capability_pack_sha256: String,
    pub workspace_profile_sha256: String,
    pub approved_operation_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub approval_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetOperationIntentV1 {
    pub schema_version: u32,
    pub intent_id: String,
    pub case_id: String,
    pub workbook_id: String,
    pub artifact_id: String,
    pub source_generation: u64,
    pub source_content_sha256: String,
    pub source_snapshot_sha256: String,
    pub operation: SpreadsheetOperationV1,
    pub mutation: Option<SpreadsheetMutationV1>,
    pub query_sha256: Option<String>,
    pub context_slice_sha256: Option<String>,
    pub expected_postcondition_ids: Vec<String>,
    pub risk_class: SpreadsheetRiskClassV1,
    pub intent_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetOperationBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub role_instance_sha256: String,
    pub case_instance_sha256: String,
    pub lease_sha256: String,
    pub case_work_grant_sha256: String,
    pub workspace_profile_sha256: String,
    pub root_binding_sha256: String,
    pub artifact_version_sha256: String,
    pub intent_sha256: String,
    pub capability_pack_sha256: String,
    pub backend_descriptor_sha256: String,
    pub backend_approval_sha256: String,
    pub policy_admission_sha256: String,
    pub activation_id: String,
    pub activation_sha256: String,
    pub worker_sha256: String,
    pub application_sha256: Option<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub binding_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetOperationReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub binding_sha256: String,
    pub operation: SpreadsheetOperationV1,
    pub result: SpreadsheetOperationResultV1,
    pub source_content_sha256: String,
    pub destination_content_sha256: Option<String>,
    pub fresh_snapshot_sha256: Option<String>,
    pub query_result_sha256: Option<String>,
    pub context_slice_sha256: Option<String>,
    pub activation_consumed: bool,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub audit_event_ids: Vec<String>,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetSemanticDiffV1 {
    pub schema_version: u32,
    pub before_snapshot_sha256: String,
    pub after_snapshot_sha256: String,
    pub changed_sheet_ids: Vec<String>,
    pub changed_table_ids: Vec<String>,
    pub changed_cell_ids: Vec<String>,
    pub formula_change_count: u32,
    pub unexpected_change_ids: Vec<String>,
    pub diff_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetPostOperationVerificationV1 {
    pub schema_version: u32,
    pub verification_id: String,
    pub binding_sha256: String,
    pub receipt_sha256: String,
    pub diff_sha256: String,
    pub fresh_snapshot_sha256: String,
    pub expected_postcondition_ids: Vec<String>,
    pub satisfied_postcondition_ids: Vec<String>,
    pub protected_invariant_ids: Vec<String>,
    pub status: SpreadsheetVerificationStatusV1,
    pub verified_at_unix_ms: u64,
    pub verification_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetWorkReplayReportV1 {
    pub schema_version: u32,
    pub scenario_count: u32,
    pub runs_per_scenario: u32,
    pub query_hash_mismatch_count: u32,
    pub context_slice_hash_mismatch_count: u32,
    pub operation_hash_mismatch_count: u32,
    pub blind_replay_count: u32,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetPerformanceMetricsV1 {
    pub parse_microseconds: u64,
    pub index_microseconds: u64,
    pub query_microseconds: u64,
    pub context_slice_microseconds: u64,
    pub mutation_microseconds: u64,
    pub recalculate_microseconds: u64,
    pub save_microseconds: u64,
    pub verify_microseconds: u64,
    pub model_microseconds: u64,
    pub peak_worker_memory_bytes: u64,
    pub workbook_cells: u64,
    pub model_context_facts: u32,
    pub model_context_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetSafetyMetricsV1 {
    pub raw_workbook_dump: u32,
    pub raw_formula_from_model: u32,
    pub arbitrary_com: u32,
    pub arbitrary_query: u32,
    pub external_link_fetch: u32,
    pub macro_execution: u32,
    pub wrong_workbook: u32,
    pub wrong_sheet: u32,
    pub wrong_cell: u32,
    pub stale_write: u32,
    pub duplicate_mutation: u32,
    pub original_overwrite: u32,
    pub unexpected_drift: u32,
    pub network_access: u32,
    pub credential_leak: u32,
    pub false_completion: u32,
    pub critical_error: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetResidualMetricsV1 {
    pub activations: u32,
    pub excel_processes: u32,
    pub file_workers: u32,
    pub temporary_packages: u32,
    pub workspace_locks: u32,
    pub workbook_locks: u32,
    pub wfp_objects: u32,
    pub profiles: u32,
    pub credentials: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub capability_pack_sha256: String,
    pub workbook_cases: u32,
    pub routine_cases: u32,
    pub exception_cases: u32,
    pub successful_operations: u32,
    pub verified_operations: u32,
    pub verified_closures: u32,
    pub xlsx_file_mutations: u32,
    pub excel_com_mutations: u32,
    pub fresh_reopens: u32,
    pub workbook_cells: u64,
    pub query_count: u32,
    pub context_slice_count: u32,
    pub actual_qwen_cases: u32,
    pub provider_invocations: u32,
    pub replan_count: u32,
    pub clarification_count: u32,
    pub crash_windows_verified: u32,
    pub replay_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub excel_executable_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub performance: SpreadsheetPerformanceMetricsV1,
    pub safety: SpreadsheetSafetyMetricsV1,
    pub residual: SpreadsheetResidualMetricsV1,
    pub complete: bool,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpreadsheetWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub capability_pack_sha256: String,
    pub backend_approval_sha256s: Vec<String>,
    pub workspace_profile_sha256: String,
    pub completion_report_sha256: String,
    pub replay_report_sha256: String,
    pub evidence_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSpreadsheetRowV1 {
    pub row_id: String,
    pub ordinal: u32,
    pub values: Vec<SpreadsheetColumnValueV1>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSpreadsheetTableV1 {
    pub metadata: SpreadsheetTableV1,
    pub rows: Vec<IndexedSpreadsheetRowV1>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IndexedSpreadsheetWorkbookV1 {
    pub snapshot: SpreadsheetSemanticSnapshotV1,
    pub tables: Vec<IndexedSpreadsheetTableV1>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SpreadsheetSituationProjectionV1 {
    pub context_slice_sha256: String,
    pub facts: Vec<d2i_situation_model::SituationFactV1>,
    pub projection_sha256: String,
    pub typed_payload: Value,
}
