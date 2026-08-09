//! Bounded spreadsheet semantics, typed query facts, and context slicing for OFFICE-300.

mod contracts;

pub use contracts::*;

use d2i_office_capability::{canonical_json_bytes, parse_json_strict, sha256_bytes};
use d2i_situation_model::{
    ConfidenceV1, ContentTrustClassV1, FreshnessBoundV1, SituationFactKindV1, SituationFactV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};

pub const SPREADSHEET_SCHEMA_VERSION: u32 = 1;
pub const ZERO_HASH: &str = d2i_office_capability::ZERO_HASH;
pub const MAX_SPREADSHEET_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SPREADSHEET_STRING_BYTES: usize = 512;
pub const MAX_QUERY_FACTS: usize = 256;
pub const MAX_CONTEXT_FACTS: usize = 64;
pub const MAX_CONTEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpreadsheetCapabilityError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    ResourceLimit(String),
    Sensitive(String),
    Signature(String),
}

impl Display for SpreadsheetCapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Integrity(message) => ("integrity", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Stale(message) => ("stale", message),
            Self::Replay(message) => ("replay", message),
            Self::ResourceLimit(message) => ("resource_limit", message),
            Self::Sensitive(message) => ("sensitive", message),
            Self::Signature(message) => ("signature", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for SpreadsheetCapabilityError {}

fn invalid(message: impl Into<String>) -> SpreadsheetCapabilityError {
    SpreadsheetCapabilityError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> SpreadsheetCapabilityError {
    SpreadsheetCapabilityError::Integrity(message.into())
}

fn resource(message: impl Into<String>) -> SpreadsheetCapabilityError {
    SpreadsheetCapabilityError::ResourceLimit(message.into())
}

pub fn parse_spreadsheet_json_strict<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, SpreadsheetCapabilityError> {
    if bytes.len() > MAX_SPREADSHEET_JSON_BYTES {
        return Err(resource("spreadsheet contract JSON exceeds 4 MiB"));
    }
    parse_json_strict(bytes).map_err(|error| invalid(error.to_string()))
}

pub fn spreadsheet_canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, SpreadsheetCapabilityError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| invalid(error.to_string()))
}

fn hash_without<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<String, SpreadsheetCapabilityError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| invalid(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("spreadsheet artifact must serialize as an object"))?;
    for field in excluded {
        object.remove(*field);
    }
    spreadsheet_canonical_sha256(&object)
}

fn validate_hash(value: &str, label: &str) -> Result<(), SpreadsheetCapabilityError> {
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{label} must be a lowercase SHA-256")));
    }
    Ok(())
}

fn validate_id(value: &str, label: &str) -> Result<(), SpreadsheetCapabilityError> {
    if value.is_empty()
        || value.len() > MAX_SPREADSHEET_STRING_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return Err(invalid(format!("{label} must be a bounded identifier")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), SpreadsheetCapabilityError> {
    if value.is_empty() || value.chars().count() > 512 || value.contains('\0') {
        return Err(invalid(format!(
            "{label} is empty or exceeds 512 characters"
        )));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
    maximum: usize,
) -> Result<(), SpreadsheetCapabilityError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return Err(resource(format!("{label} cardinality is invalid")));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_id(value, label)?;
        if !unique.insert(value) {
            return Err(invalid(format!("{label} contains a duplicate")));
        }
    }
    Ok(())
}

fn validate_hashes(
    values: &[String],
    label: &str,
    allow_empty: bool,
    maximum: usize,
) -> Result<(), SpreadsheetCapabilityError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return Err(resource(format!("{label} cardinality is invalid")));
    }
    let mut unique = BTreeSet::new();
    for value in values {
        validate_hash(value, label)?;
        if !unique.insert(value) {
            return Err(invalid(format!("{label} contains a duplicate")));
        }
    }
    Ok(())
}

fn validate_scalar(value: &SpreadsheetScalarV1) -> Result<(), SpreadsheetCapabilityError> {
    match value {
        SpreadsheetScalarV1::Blank
        | SpreadsheetScalarV1::Integer { .. }
        | SpreadsheetScalarV1::Boolean { .. } => Ok(()),
        SpreadsheetScalarV1::Text { value } => validate_text(value, "spreadsheet text value"),
        SpreadsheetScalarV1::Decimal { scale, .. } if *scale <= 6 => Ok(()),
        SpreadsheetScalarV1::Decimal { .. } => {
            Err(invalid("spreadsheet decimal scale exceeds six places"))
        }
        SpreadsheetScalarV1::Date {
            days_since_unix_epoch,
        } if (-200_000..=200_000).contains(days_since_unix_epoch) => Ok(()),
        SpreadsheetScalarV1::Date { .. } => Err(invalid("spreadsheet date is outside v1 bounds")),
        SpreadsheetScalarV1::Error { code } => validate_id(code, "spreadsheet error code"),
    }
}

fn scalar_contains_sensitive_text(value: &SpreadsheetScalarV1) -> bool {
    let SpreadsheetScalarV1::Text { value } = value else {
        return false;
    };
    let normalized = value.to_ascii_lowercase();
    [
        "password:",
        "passwd:",
        "api_key",
        "api-key",
        "secret:",
        "client_secret",
        "bearer ",
        "private_key",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn validate_limits(limits: &SpreadsheetResourceLimitsV1) -> Result<(), SpreadsheetCapabilityError> {
    let valid = limits.maximum_workbook_bytes >= 1_024
        && limits.maximum_workbook_bytes <= 512 * 1024 * 1024
        && limits.maximum_package_entries > 0
        && limits.maximum_package_entries <= 4_096
        && limits.maximum_uncompressed_bytes >= limits.maximum_workbook_bytes
        && limits.maximum_uncompressed_bytes <= 2_u64 * 1024 * 1024 * 1024
        && (1..=1_000).contains(&limits.maximum_compression_ratio)
        && limits.maximum_xml_bytes > 0
        && limits.maximum_xml_bytes <= limits.maximum_uncompressed_bytes
        && (1..=256).contains(&limits.maximum_xml_depth)
        && limits.maximum_xml_nodes > 0
        && limits.maximum_xml_attributes > 0
        && (1..=256).contains(&limits.maximum_sheets)
        && (1..=1_024).contains(&limits.maximum_tables)
        && (1..=1_000_000).contains(&limits.maximum_rows_per_table)
        && (1..=16_384).contains(&limits.maximum_columns_per_table)
        && limits.maximum_populated_cells > 0
        && limits.maximum_shared_strings > 0
        && (1..=32_768).contains(&limits.maximum_cell_text_characters)
        && limits.maximum_query_scan_cells > 0
        && limits.maximum_query_scan_cells <= limits.maximum_populated_cells
        && (1..=MAX_QUERY_FACTS as u32).contains(&limits.maximum_query_facts)
        && (1..=MAX_CONTEXT_FACTS as u32).contains(&limits.maximum_context_facts)
        && (1_024..=MAX_CONTEXT_BYTES as u32).contains(&limits.maximum_context_bytes)
        && limits.maximum_operations_per_case > 0
        && limits.maximum_model_invocations > 0
        && limits.maximum_save_generations > 0
        && limits.maximum_worker_milliseconds > 0
        && limits.maximum_application_session_milliseconds >= limits.maximum_worker_milliseconds
        && limits.maximum_worker_memory_bytes >= 16 * 1024 * 1024;
    if !valid {
        return Err(invalid("spreadsheet resource limits are outside v1 bounds"));
    }
    Ok(())
}

pub fn default_spreadsheet_resource_limits() -> SpreadsheetResourceLimitsV1 {
    SpreadsheetResourceLimitsV1 {
        maximum_workbook_bytes: 256 * 1024 * 1024,
        maximum_package_entries: 2_048,
        maximum_uncompressed_bytes: 1024 * 1024 * 1024,
        maximum_compression_ratio: 200,
        maximum_xml_bytes: 512 * 1024 * 1024,
        maximum_xml_depth: 128,
        maximum_xml_nodes: 4_000_000,
        maximum_xml_attributes: 12_000_000,
        maximum_sheets: 64,
        maximum_tables: 256,
        maximum_rows_per_table: 250_000,
        maximum_columns_per_table: 1_024,
        maximum_populated_cells: 2_000_000,
        maximum_shared_strings: 1_000_000,
        maximum_cell_text_characters: 8_192,
        maximum_query_scan_cells: 1_000_000,
        maximum_query_facts: MAX_QUERY_FACTS as u32,
        maximum_context_facts: MAX_CONTEXT_FACTS as u32,
        maximum_context_bytes: MAX_CONTEXT_BYTES as u32,
        maximum_operations_per_case: 32,
        maximum_model_invocations: 16,
        maximum_save_generations: 64,
        maximum_worker_milliseconds: 120_000,
        maximum_application_session_milliseconds: 180_000,
        maximum_worker_memory_bytes: 2_u64 * 1024 * 1024 * 1024,
    }
}

impl SpreadsheetSemanticSnapshotV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.sheets.sort_by_key(|sheet| sheet.ordinal);
        self.tables
            .sort_by(|left, right| left.table_id.cmp(&right.table_id));
        self.unsupported_feature_ids.sort();
        self.evidence_ids.sort();
        self.snapshot_sha256 = hash_without(&self, &["snapshot_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION || self.artifact_generation == 0 {
            return Err(invalid(
                "spreadsheet snapshot version or generation is invalid",
            ));
        }
        for (value, label) in [
            (&self.workbook_id, "workbook ID"),
            (&self.artifact_id, "artifact ID"),
            (&self.backend_id, "backend ID"),
        ] {
            validate_id(value, label)?;
        }
        for (value, label) in [
            (&self.source_content_sha256, "source content hash"),
            (&self.workbook_data_sha256, "workbook data hash"),
            (&self.semantic_state_sha256, "semantic state hash"),
            (&self.snapshot_sha256, "snapshot hash"),
        ] {
            validate_hash(value, label)?;
        }
        if self.sheets.is_empty() || self.sheets.len() > 256 || self.tables.len() > 1_024 {
            return Err(resource("spreadsheet snapshot collections exceed bounds"));
        }
        let mut sheet_ids = BTreeSet::new();
        let mut last_ordinal = None;
        let mut populated = 0_u64;
        let mut formulas = 0_u32;
        for sheet in &self.sheets {
            validate_id(&sheet.sheet_id, "sheet ID")?;
            validate_hash(&sheet.sheet_name_sha256, "sheet name hash")?;
            validate_hash(&sheet.sheet_state_sha256, "sheet state hash")?;
            validate_ids(&sheet.table_ids, "sheet table IDs", true, 1_024)?;
            if !sheet_ids.insert(&sheet.sheet_id)
                || last_ordinal.is_some_and(|last| last >= sheet.ordinal)
            {
                return Err(invalid("sheet IDs or ordinals are not unique and ordered"));
            }
            last_ordinal = Some(sheet.ordinal);
            populated = populated.saturating_add(sheet.populated_cell_count);
            formulas = formulas.saturating_add(sheet.formula_count);
        }
        let mut table_ids = BTreeSet::new();
        for table in &self.tables {
            validate_table(table)?;
            if !sheet_ids.contains(&table.sheet_id) || !table_ids.insert(&table.table_id) {
                return Err(invalid(
                    "spreadsheet table has a missing sheet or duplicate ID",
                ));
            }
        }
        if populated != self.total_populated_cells || formulas != self.total_formula_cells {
            return Err(integrity(
                "spreadsheet snapshot totals differ from sheet metadata",
            ));
        }
        validate_ids(
            &self.unsupported_feature_ids,
            "unsupported spreadsheet feature IDs",
            true,
            256,
        )?;
        validate_ids(&self.evidence_ids, "snapshot evidence IDs", false, 256)?;
        if self.observed_at_unix_ms == 0
            || self.freshness_expires_at_unix_ms <= self.observed_at_unix_ms
            || self.freshness_expires_at_unix_ms - self.observed_at_unix_ms > 86_400_000
        {
            return Err(invalid("spreadsheet snapshot freshness is invalid"));
        }
        if hash_without(self, &["snapshot_sha256"])? != self.snapshot_sha256 {
            return Err(integrity("spreadsheet snapshot self-hash differs"));
        }
        Ok(())
    }
}

fn validate_table(table: &SpreadsheetTableV1) -> Result<(), SpreadsheetCapabilityError> {
    validate_id(&table.table_id, "table ID")?;
    validate_id(&table.sheet_id, "table sheet ID")?;
    validate_hash(&table.source_range_sha256, "table source range hash")?;
    validate_hash(&table.table_state_sha256, "table state hash")?;
    if table.columns.is_empty() || table.columns.len() > 16_384 {
        return Err(resource("spreadsheet table column count is invalid"));
    }
    let mut ids = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    for column in &table.columns {
        validate_id(&column.column_id, "column ID")?;
        validate_hash(&column.header_sha256, "column header hash")?;
        if let Some(unit) = &column.unit_id {
            validate_id(unit, "column unit ID")?;
        }
        if !ids.insert(&column.column_id) || !ordinals.insert(column.ordinal) {
            return Err(invalid("table column ID or ordinal is duplicated"));
        }
    }
    Ok(())
}

impl SpreadsheetQueryV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.evidence_ids.sort();
        self.query_sha256 = hash_without(&self, &["query_sha256"])?;
        self.validate_contract()?;
        Ok(self)
    }

    pub fn validate_at(
        &self,
        now_unix_ms: u64,
        limits: &SpreadsheetResourceLimitsV1,
    ) -> Result<(), SpreadsheetCapabilityError> {
        self.validate_contract()?;
        validate_limits(limits)?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms > self.expires_at_unix_ms {
            return Err(SpreadsheetCapabilityError::Stale(
                "spreadsheet query is outside its validity window".to_owned(),
            ));
        }
        if self.context_budget.maximum_facts > limits.maximum_context_facts
            || self.context_budget.maximum_bytes > limits.maximum_context_bytes
        {
            return Err(resource(
                "spreadsheet query context budget exceeds runtime policy",
            ));
        }
        Ok(())
    }

    /// Validates the immutable query contract without applying a wall-clock freshness check.
    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        self.validate_contract()
    }

    fn validate_contract(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 300_000
        {
            return Err(invalid("spreadsheet query version or TTL is invalid"));
        }
        validate_id(&self.query_id, "query ID")?;
        validate_id(&self.case_id, "query Case ID")?;
        validate_hash(&self.workbook_snapshot_sha256, "query snapshot hash")?;
        validate_id(&self.table_id, "query table ID")?;
        validate_hash(&self.query_sha256, "query hash")?;
        validate_ids(&self.evidence_ids, "query evidence IDs", false, 128)?;
        validate_context_budget(&self.context_budget)?;
        validate_query_plan(&self.plan)?;
        if hash_without(self, &["query_sha256"])? != self.query_sha256 {
            return Err(integrity("spreadsheet query self-hash differs"));
        }
        Ok(())
    }
}

fn validate_context_budget(
    budget: &SpreadsheetContextBudgetV1,
) -> Result<(), SpreadsheetCapabilityError> {
    if budget.maximum_facts == 0
        || budget.maximum_facts > MAX_CONTEXT_FACTS as u32
        || budget.maximum_bytes < 1_024
        || budget.maximum_bytes > MAX_CONTEXT_BYTES as u32
        || budget.maximum_estimated_tokens == 0
        || budget.maximum_estimated_tokens > 8_192
        || budget.maximum_estimated_tokens > budget.maximum_bytes
    {
        return Err(resource("spreadsheet context budget is outside v1 bounds"));
    }
    Ok(())
}

fn validate_query_plan(plan: &SpreadsheetQueryPlanV1) -> Result<(), SpreadsheetCapabilityError> {
    match plan {
        SpreadsheetQueryPlanV1::Lookup {
            key_column_id,
            key_value,
            projection_column_ids,
        } => {
            validate_id(key_column_id, "lookup key column")?;
            validate_scalar(key_value)?;
            validate_ids(
                projection_column_ids,
                "lookup projection columns",
                false,
                32,
            )
        }
        SpreadsheetQueryPlanV1::Filter {
            predicates,
            projection_column_ids,
            maximum_rows,
        } => {
            validate_predicates(predicates)?;
            validate_ids(
                projection_column_ids,
                "filter projection columns",
                false,
                32,
            )?;
            if !(1..=32).contains(maximum_rows) {
                return Err(resource("filter result row bound must be within 1..=32"));
            }
            Ok(())
        }
        SpreadsheetQueryPlanV1::Aggregate {
            predicates,
            group_by_column_ids,
            measures,
            maximum_groups,
        } => {
            validate_predicates_allow_empty(predicates)?;
            validate_ids(group_by_column_ids, "aggregate group columns", true, 2)?;
            if measures.is_empty() || measures.len() > 16 || !(1..=32).contains(maximum_groups) {
                return Err(resource("aggregate measure or group bound is invalid"));
            }
            let mut measure_ids = BTreeSet::new();
            for measure in measures {
                validate_id(&measure.measure_id, "measure ID")?;
                if !measure_ids.insert(&measure.measure_id) {
                    return Err(invalid("aggregate measure IDs contain duplicates"));
                }
                match measure.aggregate {
                    SpreadsheetAggregateV1::Count if measure.column_id.is_some() => {
                        return Err(invalid("count measure cannot select a value column"));
                    }
                    SpreadsheetAggregateV1::Count => {}
                    _ => validate_id(
                        measure
                            .column_id
                            .as_deref()
                            .ok_or_else(|| invalid("numeric aggregate requires a source column"))?,
                        "aggregate source column",
                    )?,
                }
                if let Some(unit) = &measure.unit_id {
                    validate_id(unit, "measure unit ID")?;
                }
            }
            Ok(())
        }
    }
}

fn validate_predicates(
    values: &[SpreadsheetPredicateV1],
) -> Result<(), SpreadsheetCapabilityError> {
    if values.is_empty() {
        return Err(invalid("filter query requires at least one predicate"));
    }
    validate_predicates_allow_empty(values)
}

fn validate_predicates_allow_empty(
    values: &[SpreadsheetPredicateV1],
) -> Result<(), SpreadsheetCapabilityError> {
    if values.len() > 16 {
        return Err(resource("spreadsheet predicate count exceeds 16"));
    }
    for predicate in values {
        validate_id(&predicate.column_id, "predicate column ID")?;
        validate_scalar(&predicate.operand)?;
    }
    Ok(())
}

impl SpreadsheetTypedFactV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.source_column_ids.sort();
        self.evidence_ids.sort();
        self.fact_sha256 = hash_without(&self, &["fact_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        for (value, label) in [
            (&self.fact_id, "spreadsheet fact ID"),
            (&self.subject_id, "spreadsheet fact subject"),
            (&self.predicate_id, "spreadsheet fact predicate"),
            (&self.source_table_id, "spreadsheet fact source table"),
        ] {
            validate_id(value, label)?;
        }
        validate_scalar(&self.typed_value)?;
        if let Some(unit) = &self.unit_id {
            validate_id(unit, "spreadsheet fact unit")?;
        }
        validate_ids(&self.source_column_ids, "fact source columns", true, 32)?;
        validate_hash(&self.source_range_sha256, "fact source range hash")?;
        validate_ids(&self.evidence_ids, "fact evidence IDs", false, 128)?;
        if self.confidence_millionths > 1_000_000 || self.priority > 1_000_000 {
            return Err(invalid(
                "spreadsheet fact confidence or priority exceeds one million",
            ));
        }
        validate_hash(&self.fact_sha256, "spreadsheet fact hash")?;
        if hash_without(self, &["fact_sha256"])? != self.fact_sha256 {
            return Err(integrity("spreadsheet fact self-hash differs"));
        }
        Ok(())
    }
}

impl SpreadsheetQueryResultV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.facts
            .sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
        self.result_sha256 = hash_without(&self, &["result_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION || self.facts.len() > MAX_QUERY_FACTS {
            return Err(resource("spreadsheet query result exceeds v1 bounds"));
        }
        validate_id(&self.query_id, "query result ID")?;
        validate_hash(&self.query_sha256, "query result query hash")?;
        validate_hash(&self.workbook_snapshot_sha256, "query result snapshot hash")?;
        validate_hash(&self.result_sha256, "query result hash")?;
        let mut ids = BTreeSet::new();
        for fact in &self.facts {
            fact.validate()?;
            if !ids.insert(&fact.fact_id) {
                return Err(invalid("query result fact IDs contain duplicates"));
            }
        }
        if hash_without(self, &["result_sha256"])? != self.result_sha256 {
            return Err(integrity("spreadsheet query result self-hash differs"));
        }
        Ok(())
    }
}

impl SpreadsheetContextSliceV1 {
    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION
            || self.selected_facts.is_empty()
            || self.selected_facts.len() > MAX_CONTEXT_FACTS
            || self.selected_fact_count as usize != self.selected_facts.len()
            || self.serialized_bytes as usize > MAX_CONTEXT_BYTES
            || self.estimated_tokens > 8_192
        {
            return Err(resource("spreadsheet context slice exceeds v1 bounds"));
        }
        validate_id(&self.slice_id, "context slice ID")?;
        validate_id(&self.case_id, "context slice Case ID")?;
        for hash in [
            &self.workbook_snapshot_sha256,
            &self.query_sha256,
            &self.query_result_sha256,
            &self.slice_sha256,
        ] {
            validate_hash(hash, "context slice hash")?;
        }
        validate_ids(&self.evidence_ids, "context slice evidence IDs", false, 128)?;
        for fact in &self.selected_facts {
            fact.validate()?;
            if scalar_contains_sensitive_text(&fact.typed_value) {
                return Err(SpreadsheetCapabilityError::Sensitive(
                    "credential-like spreadsheet value cannot enter model context".to_owned(),
                ));
            }
        }
        if hash_without(self, &["slice_sha256"])? != self.slice_sha256 {
            return Err(integrity("spreadsheet context slice self-hash differs"));
        }
        Ok(())
    }
}

pub fn execute_spreadsheet_query(
    workbook: &IndexedSpreadsheetWorkbookV1,
    query: &SpreadsheetQueryV1,
    now_unix_ms: u64,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<SpreadsheetQueryResultV1, SpreadsheetCapabilityError> {
    workbook.snapshot.validate()?;
    query.validate_at(now_unix_ms, limits)?;
    if query.workbook_snapshot_sha256 != workbook.snapshot.snapshot_sha256 {
        return Err(SpreadsheetCapabilityError::Stale(
            "query is bound to a different workbook snapshot".to_owned(),
        ));
    }
    let table = workbook
        .tables
        .iter()
        .find(|table| table.metadata.table_id == query.table_id)
        .ok_or_else(|| invalid("query table is absent from the indexed workbook"))?;
    validate_indexed_table(table, limits)?;
    let columns = table
        .metadata
        .columns
        .iter()
        .map(|column| (column.column_id.as_str(), column))
        .collect::<BTreeMap<_, _>>();
    validate_query_columns(&query.plan, &columns)?;

    let mut scanned_rows = 0_u32;
    let mut scanned_cells = 0_u64;
    let mut matched = Vec::new();
    for row in &table.rows {
        scanned_rows = scanned_rows.saturating_add(1);
        scanned_cells = scanned_cells.saturating_add(row.values.len() as u64);
        if scanned_cells > limits.maximum_query_scan_cells {
            return Err(resource("spreadsheet query exceeded its scan-cell budget"));
        }
        if row_matches(row, query_predicates(&query.plan))? {
            matched.push(row);
        }
    }

    let facts = match &query.plan {
        SpreadsheetQueryPlanV1::Lookup {
            key_column_id,
            key_value,
            projection_column_ids,
        } => {
            let exact = matched
                .into_iter()
                .filter(|row| row_value(row, key_column_id) == Some(key_value))
                .collect::<Vec<_>>();
            if exact.len() > 1 {
                return Err(invalid("lookup key is ambiguous in the selected table"));
            }
            project_rows(
                &query.query_id,
                &table.metadata,
                &exact,
                projection_column_ids,
                SpreadsheetFactKindV1::Lookup,
                &query.evidence_ids,
            )?
        }
        SpreadsheetQueryPlanV1::Filter {
            projection_column_ids,
            maximum_rows,
            ..
        } => {
            let limit = usize::try_from(*maximum_rows)
                .map_err(|_| resource("filter row limit conversion failed"))?;
            project_rows(
                &query.query_id,
                &table.metadata,
                &matched.into_iter().take(limit).collect::<Vec<_>>(),
                projection_column_ids,
                SpreadsheetFactKindV1::Projection,
                &query.evidence_ids,
            )?
        }
        SpreadsheetQueryPlanV1::Aggregate {
            group_by_column_ids,
            measures,
            maximum_groups,
            ..
        } => aggregate_rows(
            &query.query_id,
            &table.metadata,
            &matched,
            group_by_column_ids,
            measures,
            *maximum_groups,
            &query.evidence_ids,
        )?,
    };
    if facts.len() > limits.maximum_query_facts as usize {
        return Err(resource("spreadsheet query generated too many typed facts"));
    }
    SpreadsheetQueryResultV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        query_id: query.query_id.clone(),
        query_sha256: query.query_sha256.clone(),
        workbook_snapshot_sha256: workbook.snapshot.snapshot_sha256.clone(),
        scanned_rows,
        scanned_cells,
        matched_rows: u32::try_from(matched_row_count(&query.plan, &table.rows)?)
            .map_err(|_| resource("matched row count overflow"))?,
        facts,
        complete: true,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn validate_indexed_table(
    table: &IndexedSpreadsheetTableV1,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<(), SpreadsheetCapabilityError> {
    validate_table(&table.metadata)?;
    if table.rows.len() > limits.maximum_rows_per_table as usize
        || table.rows.len() != table.metadata.row_count as usize
    {
        return Err(resource(
            "indexed spreadsheet row count differs or exceeds bounds",
        ));
    }
    let columns = table
        .metadata
        .columns
        .iter()
        .map(|column| (column.column_id.as_str(), column))
        .collect::<BTreeMap<_, _>>();
    let mut row_ids = BTreeSet::new();
    let mut row_ordinals = BTreeSet::new();
    let mut previous_ordinal = None;
    for row in &table.rows {
        validate_id(&row.row_id, "indexed row ID")?;
        if !row_ids.insert(&row.row_id)
            || !row_ordinals.insert(row.ordinal)
            || previous_ordinal.is_some_and(|ordinal| ordinal >= row.ordinal)
            || row.values.len() > columns.len()
        {
            return Err(invalid(
                "indexed row ID/ordinal is duplicated, unordered, or row is too wide",
            ));
        }
        previous_ordinal = Some(row.ordinal);
        let mut value_columns = BTreeSet::new();
        for value in &row.values {
            validate_id(&value.column_id, "indexed value column ID")?;
            validate_scalar(&value.value)?;
            let Some(column) = columns.get(value.column_id.as_str()) else {
                return Err(invalid(
                    "indexed row references an unknown or duplicate column",
                ));
            };
            if !value_columns.insert(&value.column_id) {
                return Err(invalid(
                    "indexed row references an unknown or duplicate column",
                ));
            }
            if !scalar_matches_column(&value.value, column.inferred_type) {
                return Err(invalid(
                    "indexed cell value differs from its declared column type",
                ));
            }
        }
    }
    Ok(())
}

fn scalar_matches_column(
    value: &SpreadsheetScalarV1,
    column_type: SpreadsheetColumnTypeV1,
) -> bool {
    matches!(value, SpreadsheetScalarV1::Blank)
        || column_type == SpreadsheetColumnTypeV1::Mixed
        || value.column_type() == column_type
}

fn validate_query_columns(
    plan: &SpreadsheetQueryPlanV1,
    columns: &BTreeMap<&str, &SpreadsheetColumnV1>,
) -> Result<(), SpreadsheetCapabilityError> {
    let mut requested = Vec::new();
    let mut typed_operands = Vec::new();
    match plan {
        SpreadsheetQueryPlanV1::Lookup {
            key_column_id,
            key_value,
            projection_column_ids,
        } => {
            requested.push(key_column_id);
            typed_operands.push((key_column_id, key_value));
            requested.extend(projection_column_ids);
        }
        SpreadsheetQueryPlanV1::Filter {
            predicates,
            projection_column_ids,
            ..
        } => {
            requested.extend(predicates.iter().map(|predicate| &predicate.column_id));
            typed_operands.extend(
                predicates
                    .iter()
                    .map(|predicate| (&predicate.column_id, &predicate.operand)),
            );
            requested.extend(projection_column_ids);
        }
        SpreadsheetQueryPlanV1::Aggregate {
            predicates,
            group_by_column_ids,
            measures,
            ..
        } => {
            requested.extend(predicates.iter().map(|predicate| &predicate.column_id));
            typed_operands.extend(
                predicates
                    .iter()
                    .map(|predicate| (&predicate.column_id, &predicate.operand)),
            );
            requested.extend(group_by_column_ids);
            requested.extend(
                measures
                    .iter()
                    .filter_map(|measure| measure.column_id.as_ref()),
            );
        }
    }
    if requested
        .into_iter()
        .any(|column_id| !columns.contains_key(column_id.as_str()))
    {
        return Err(invalid("spreadsheet query references an unknown column"));
    }
    for (column_id, operand) in typed_operands {
        let column = columns
            .get(column_id.as_str())
            .ok_or_else(|| invalid("spreadsheet query references an unknown typed column"))?;
        if !scalar_matches_column(operand, column.inferred_type) {
            return Err(invalid(
                "spreadsheet query operand differs from its declared column type",
            ));
        }
    }
    Ok(())
}

fn query_predicates(plan: &SpreadsheetQueryPlanV1) -> &[SpreadsheetPredicateV1] {
    match plan {
        SpreadsheetQueryPlanV1::Lookup { .. } => &[],
        SpreadsheetQueryPlanV1::Filter { predicates, .. }
        | SpreadsheetQueryPlanV1::Aggregate { predicates, .. } => predicates,
    }
}

fn row_matches(
    row: &IndexedSpreadsheetRowV1,
    predicates: &[SpreadsheetPredicateV1],
) -> Result<bool, SpreadsheetCapabilityError> {
    predicates.iter().try_fold(true, |matches, predicate| {
        if !matches {
            return Ok(false);
        }
        let value = row_value(row, &predicate.column_id).unwrap_or(&SpreadsheetScalarV1::Blank);
        compare_predicate(value, predicate.operator, &predicate.operand)
    })
}

fn row_value<'a>(
    row: &'a IndexedSpreadsheetRowV1,
    column_id: &str,
) -> Option<&'a SpreadsheetScalarV1> {
    row.values
        .iter()
        .find(|value| value.column_id == column_id)
        .map(|value| &value.value)
}

fn compare_predicate(
    left: &SpreadsheetScalarV1,
    operator: SpreadsheetPredicateOperatorV1,
    right: &SpreadsheetScalarV1,
) -> Result<bool, SpreadsheetCapabilityError> {
    let ordering = compare_scalars(left, right)?;
    Ok(match operator {
        SpreadsheetPredicateOperatorV1::Equal => ordering == Ordering::Equal,
        SpreadsheetPredicateOperatorV1::NotEqual => ordering != Ordering::Equal,
        SpreadsheetPredicateOperatorV1::LessThan => ordering == Ordering::Less,
        SpreadsheetPredicateOperatorV1::LessThanOrEqual => ordering != Ordering::Greater,
        SpreadsheetPredicateOperatorV1::GreaterThan => ordering == Ordering::Greater,
        SpreadsheetPredicateOperatorV1::GreaterThanOrEqual => ordering != Ordering::Less,
    })
}

fn compare_scalars(
    left: &SpreadsheetScalarV1,
    right: &SpreadsheetScalarV1,
) -> Result<Ordering, SpreadsheetCapabilityError> {
    match (left, right) {
        (SpreadsheetScalarV1::Blank, SpreadsheetScalarV1::Blank) => Ok(Ordering::Equal),
        (SpreadsheetScalarV1::Blank, _) | (_, SpreadsheetScalarV1::Blank) => {
            Err(invalid("blank spreadsheet values are not order-comparable"))
        }
        _ => match (numeric_scale6(left), numeric_scale6(right)) {
            (Some(left), Some(right)) => Ok(left.cmp(&right)),
            (None, None) if left.column_type() == right.column_type() => Ok(left.cmp(right)),
            _ => Err(invalid(
                "spreadsheet predicate compares incompatible scalar types",
            )),
        },
    }
}

fn numeric_scale6(value: &SpreadsheetScalarV1) -> Option<i128> {
    match value {
        SpreadsheetScalarV1::Integer { value } => Some(i128::from(*value) * 1_000_000),
        SpreadsheetScalarV1::Decimal {
            scaled_value,
            scale,
        } if *scale <= 6 => Some(i128::from(*scaled_value) * 10_i128.pow(6 - *scale)),
        _ => None,
    }
}

fn project_rows(
    query_id: &str,
    table: &SpreadsheetTableV1,
    rows: &[&IndexedSpreadsheetRowV1],
    columns: &[String],
    kind: SpreadsheetFactKindV1,
    evidence_ids: &[String],
) -> Result<Vec<SpreadsheetTypedFactV1>, SpreadsheetCapabilityError> {
    let mut facts = Vec::new();
    for row in rows {
        for column_id in columns {
            let value = row_value(row, column_id)
                .cloned()
                .unwrap_or(SpreadsheetScalarV1::Blank);
            let unit_id = table
                .columns
                .iter()
                .find(|column| &column.column_id == column_id)
                .and_then(|column| column.unit_id.clone());
            let range_hash = spreadsheet_canonical_sha256(&(
                &table.source_range_sha256,
                &row.row_id,
                column_id,
            ))?;
            let fact_id = format!("fact.{query_id}.{:04}.{:04}", row.ordinal, facts.len() + 1);
            facts.push(
                SpreadsheetTypedFactV1 {
                    fact_id,
                    fact_kind: kind,
                    subject_id: row.row_id.clone(),
                    predicate_id: column_id.clone(),
                    typed_value: value,
                    unit_id,
                    source_table_id: table.table_id.clone(),
                    source_column_ids: vec![column_id.clone()],
                    source_row_count: 1,
                    source_range_sha256: range_hash,
                    confidence_millionths: 1_000_000,
                    priority: if kind == SpreadsheetFactKindV1::Lookup {
                        900_000
                    } else {
                        700_000
                    },
                    evidence_ids: evidence_ids.to_vec(),
                    fact_sha256: ZERO_HASH.to_owned(),
                }
                .seal()?,
            );
        }
    }
    Ok(facts)
}

fn aggregate_rows(
    query_id: &str,
    table: &SpreadsheetTableV1,
    rows: &[&IndexedSpreadsheetRowV1],
    group_columns: &[String],
    measures: &[SpreadsheetMeasureV1],
    maximum_groups: u32,
    evidence_ids: &[String],
) -> Result<Vec<SpreadsheetTypedFactV1>, SpreadsheetCapabilityError> {
    let mut groups = BTreeMap::<Vec<SpreadsheetScalarV1>, Vec<&IndexedSpreadsheetRowV1>>::new();
    for row in rows {
        let key = group_columns
            .iter()
            .map(|column| {
                row_value(row, column)
                    .cloned()
                    .unwrap_or(SpreadsheetScalarV1::Blank)
            })
            .collect::<Vec<_>>();
        groups.entry(key).or_default().push(*row);
    }
    if groups.len() > maximum_groups as usize {
        return Err(resource(
            "aggregate result exceeds the approved group bound",
        ));
    }
    let mut facts = Vec::new();
    for (group_index, (group_key, group_rows)) in groups.into_iter().enumerate() {
        let group_hash = spreadsheet_canonical_sha256(&group_key)?;
        let subject_id = format!("group.{}", &group_hash[7..23]);
        for measure in measures {
            let value = aggregate_measure(&group_rows, measure)?;
            let columns = group_columns
                .iter()
                .cloned()
                .chain(measure.column_id.iter().cloned())
                .collect::<Vec<_>>();
            let range_hash = spreadsheet_canonical_sha256(&(
                &table.source_range_sha256,
                &group_hash,
                &measure.measure_id,
                group_rows.len(),
            ))?;
            facts.push(
                SpreadsheetTypedFactV1 {
                    fact_id: format!(
                        "fact.{query_id}.aggregate.{:04}.{}",
                        group_index + 1,
                        measure.measure_id
                    ),
                    fact_kind: SpreadsheetFactKindV1::Aggregate,
                    subject_id: subject_id.clone(),
                    predicate_id: measure.measure_id.clone(),
                    typed_value: value,
                    unit_id: measure.unit_id.clone(),
                    source_table_id: table.table_id.clone(),
                    source_column_ids: columns,
                    source_row_count: u32::try_from(group_rows.len())
                        .map_err(|_| resource("aggregate source row count overflow"))?,
                    source_range_sha256: range_hash,
                    confidence_millionths: 1_000_000,
                    priority: 1_000_000,
                    evidence_ids: evidence_ids.to_vec(),
                    fact_sha256: ZERO_HASH.to_owned(),
                }
                .seal()?,
            );
        }
    }
    Ok(facts)
}

fn aggregate_measure(
    rows: &[&IndexedSpreadsheetRowV1],
    measure: &SpreadsheetMeasureV1,
) -> Result<SpreadsheetScalarV1, SpreadsheetCapabilityError> {
    if measure.aggregate == SpreadsheetAggregateV1::Count {
        return Ok(SpreadsheetScalarV1::Integer {
            value: i64::try_from(rows.len()).map_err(|_| resource("count aggregate overflow"))?,
        });
    }
    let column = measure
        .column_id
        .as_deref()
        .ok_or_else(|| invalid("aggregate source column is missing"))?;
    let values = rows
        .iter()
        .filter_map(|row| row_value(row, column))
        .filter(|value| !matches!(value, SpreadsheetScalarV1::Blank))
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(SpreadsheetScalarV1::Blank);
    }
    match measure.aggregate {
        SpreadsheetAggregateV1::Count => Err(invalid(
            "count aggregate reached the non-count aggregation path",
        )),
        SpreadsheetAggregateV1::Sum | SpreadsheetAggregateV1::Average => {
            let sum = values.iter().try_fold(0_i128, |sum, value| {
                numeric_scale6(value)
                    .and_then(|value| sum.checked_add(value))
                    .ok_or_else(|| {
                        invalid("numeric aggregate contains non-numeric or overflowed data")
                    })
            })?;
            let scaled = if measure.aggregate == SpreadsheetAggregateV1::Average {
                sum / i128::try_from(values.len())
                    .map_err(|_| resource("average divisor overflow"))?
            } else {
                sum
            };
            Ok(SpreadsheetScalarV1::Decimal {
                scaled_value: i64::try_from(scaled)
                    .map_err(|_| resource("numeric aggregate exceeds fixed-point range"))?,
                scale: 6,
            })
        }
        SpreadsheetAggregateV1::Minimum | SpreadsheetAggregateV1::Maximum => {
            let mut selected = (*values[0]).clone();
            for value in values.into_iter().skip(1) {
                let ordering = compare_scalars(value, &selected)?;
                let replace = (measure.aggregate == SpreadsheetAggregateV1::Minimum
                    && ordering == Ordering::Less)
                    || (measure.aggregate == SpreadsheetAggregateV1::Maximum
                        && ordering == Ordering::Greater);
                if replace {
                    selected = value.clone();
                }
            }
            Ok(selected)
        }
    }
}

fn matched_row_count(
    plan: &SpreadsheetQueryPlanV1,
    rows: &[IndexedSpreadsheetRowV1],
) -> Result<usize, SpreadsheetCapabilityError> {
    match plan {
        SpreadsheetQueryPlanV1::Lookup {
            key_column_id,
            key_value,
            ..
        } => Ok(rows
            .iter()
            .filter(|row| row_value(row, key_column_id) == Some(key_value))
            .count()),
        _ => rows.iter().try_fold(0_usize, |count, row| {
            Ok(count + usize::from(row_matches(row, query_predicates(plan))?))
        }),
    }
}

pub fn slice_spreadsheet_context(
    slice_id: &str,
    case_id: &str,
    result: &SpreadsheetQueryResultV1,
    budget: &SpreadsheetContextBudgetV1,
    limits: &SpreadsheetResourceLimitsV1,
    evidence_ids: Vec<String>,
) -> Result<SpreadsheetContextSliceV1, SpreadsheetCapabilityError> {
    validate_id(slice_id, "context slice ID")?;
    validate_id(case_id, "context slice Case ID")?;
    result.validate()?;
    validate_context_budget(budget)?;
    validate_limits(limits)?;
    if budget.maximum_facts > limits.maximum_context_facts
        || budget.maximum_bytes > limits.maximum_context_bytes
    {
        return Err(resource("context slice budget exceeds runtime limits"));
    }
    let mut facts = result.facts.clone();
    facts.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then_with(|| left.fact_kind.cmp(&right.fact_kind))
            .then_with(|| left.fact_id.cmp(&right.fact_id))
    });
    let mut selected = Vec::new();
    let mut omitted = 0_u32;
    for fact in facts {
        if scalar_contains_sensitive_text(&fact.typed_value) {
            return Err(SpreadsheetCapabilityError::Sensitive(
                "credential-like spreadsheet value cannot enter model context".to_owned(),
            ));
        }
        if selected.len() >= budget.maximum_facts as usize {
            omitted = omitted.saturating_add(1);
            continue;
        }
        let mut candidate = selected.clone();
        candidate.push(fact.clone());
        let bytes = canonical_json_bytes(&candidate)
            .map_err(|error| invalid(error.to_string()))?
            .len();
        let estimated_tokens = bytes.div_ceil(4);
        if bytes > budget.maximum_bytes as usize
            || estimated_tokens > budget.maximum_estimated_tokens as usize
        {
            omitted = omitted.saturating_add(1);
        } else {
            selected.push(fact);
        }
    }
    if selected.is_empty() {
        return Err(resource(
            "context budget cannot retain one typed spreadsheet fact",
        ));
    }
    let mut slice = SpreadsheetContextSliceV1 {
        schema_version: SPREADSHEET_SCHEMA_VERSION,
        slice_id: slice_id.to_owned(),
        case_id: case_id.to_owned(),
        workbook_snapshot_sha256: result.workbook_snapshot_sha256.clone(),
        query_sha256: result.query_sha256.clone(),
        query_result_sha256: result.result_sha256.clone(),
        selected_fact_count: u32::try_from(selected.len())
            .map_err(|_| resource("selected fact count overflow"))?,
        selected_facts: selected,
        omitted_fact_count: omitted,
        source_cell_count: result.scanned_cells,
        serialized_bytes: 0,
        estimated_tokens: 0,
        complete_for_query: result.complete && omitted == 0,
        evidence_ids,
        slice_sha256: ZERO_HASH.to_owned(),
    };
    slice.evidence_ids.sort();
    update_context_slice_size(&mut slice)?;
    while slice.serialized_bytes > budget.maximum_bytes
        || slice.estimated_tokens > budget.maximum_estimated_tokens
    {
        if slice.selected_facts.pop().is_none() {
            return Err(resource(
                "context budget cannot retain one typed spreadsheet fact",
            ));
        }
        slice.selected_fact_count = slice.selected_fact_count.saturating_sub(1);
        slice.omitted_fact_count = slice.omitted_fact_count.saturating_add(1);
        slice.complete_for_query = false;
        update_context_slice_size(&mut slice)?;
    }
    slice.slice_sha256 = hash_without(&slice, &["slice_sha256"])?;
    slice.validate()?;
    Ok(slice)
}

fn update_context_slice_size(
    slice: &mut SpreadsheetContextSliceV1,
) -> Result<(), SpreadsheetCapabilityError> {
    for _ in 0..4 {
        let bytes = canonical_json_bytes(slice)
            .map_err(|error| invalid(error.to_string()))?
            .len();
        let bytes = u32::try_from(bytes).map_err(|_| resource("context slice byte overflow"))?;
        let tokens = bytes.div_ceil(4);
        if slice.serialized_bytes == bytes && slice.estimated_tokens == tokens {
            return Ok(());
        }
        slice.serialized_bytes = bytes;
        slice.estimated_tokens = tokens;
    }
    Err(integrity(
        "context slice size metadata did not converge deterministically",
    ))
}

pub fn project_context_slice_to_situation(
    slice: &SpreadsheetContextSliceV1,
    freshness: FreshnessBoundV1,
) -> Result<SpreadsheetSituationProjectionV1, SpreadsheetCapabilityError> {
    slice.validate()?;
    freshness
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    let mut facts = Vec::new();
    for spreadsheet_fact in &slice.selected_facts {
        let typed_object = json!({
            "spreadsheet_value": spreadsheet_fact.typed_value,
            "unit_id": spreadsheet_fact.unit_id,
            "source_table_id": spreadsheet_fact.source_table_id,
            "source_column_ids": spreadsheet_fact.source_column_ids,
            "source_row_count": spreadsheet_fact.source_row_count,
            "source_range_sha256": spreadsheet_fact.source_range_sha256,
            "context_slice_sha256": slice.slice_sha256,
        });
        let fact = SituationFactV1 {
            fact_id: spreadsheet_fact.fact_id.clone(),
            fact_kind: SituationFactKindV1::Observed,
            subject: spreadsheet_fact.subject_id.clone(),
            predicate: spreadsheet_fact.predicate_id.clone(),
            typed_object,
            confidence: ConfidenceV1::Millionths(spreadsheet_fact.confidence_millionths),
            evidence_refs: spreadsheet_fact.evidence_ids.clone(),
            source_trust_class: ContentTrustClassV1::VerifiedObservation,
            provider_id: None,
            freshness: freshness.clone(),
            contradiction_group_id: None,
            fact_sha256: d2i_situation_model::ZERO_HASH.to_owned(),
        }
        .seal()
        .map_err(|error| invalid(error.to_string()))?;
        facts.push(fact);
    }
    facts.sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    let typed_payload = serde_json::to_value(&facts).map_err(|error| invalid(error.to_string()))?;
    let projection_sha256 =
        spreadsheet_canonical_sha256(&(&slice.slice_sha256, &facts, &typed_payload))?;
    Ok(SpreadsheetSituationProjectionV1 {
        context_slice_sha256: slice.slice_sha256.clone(),
        facts,
        projection_sha256,
        typed_payload,
    })
}

impl SpreadsheetCapabilityPackV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.application_family_ids.sort();
        self.supported_format_ids.sort();
        self.semantic_operations.sort();
        self.query_kinds.sort();
        self.pack_sha256 = hash_without(&self, &["pack_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION {
            return Err(invalid(
                "spreadsheet capability pack version is unsupported",
            ));
        }
        validate_id(&self.pack_id, "spreadsheet pack ID")?;
        validate_id(&self.pack_version, "spreadsheet pack version")?;
        validate_ids(
            &self.application_family_ids,
            "application family IDs",
            false,
            16,
        )?;
        if self.supported_format_ids.is_empty()
            || self.semantic_operations.is_empty()
            || self.query_kinds.is_empty()
        {
            return Err(invalid("spreadsheet capability pack is incomplete"));
        }
        validate_ids(&self.query_kinds, "query kind IDs", false, 8)?;
        validate_limits(&self.resource_limits)?;
        validate_hash(&self.pack_sha256, "capability pack hash")?;
        if hash_without(self, &["pack_sha256"])? != self.pack_sha256 {
            return Err(integrity("spreadsheet capability pack self-hash differs"));
        }
        Ok(())
    }
}

impl SpreadsheetBackendDescriptorV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.supported_format_ids.sort();
        self.supported_operations.sort();
        self.descriptor_sha256 = hash_without(&self, &["descriptor_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION
            || self.supported_format_ids.is_empty()
            || self.supported_operations.is_empty()
        {
            return Err(invalid("spreadsheet backend descriptor is incomplete"));
        }
        validate_id(&self.backend_id, "spreadsheet backend ID")?;
        validate_hash(&self.worker_sha256, "spreadsheet worker hash")?;
        if self.requires_application != self.application_sha256.is_some() {
            return Err(invalid(
                "spreadsheet backend application binding is inconsistent",
            ));
        }
        if let Some(hash) = &self.application_sha256 {
            validate_hash(hash, "spreadsheet application hash")?;
        }
        if !self.network_denied || !self.macro_disabled {
            return Err(SpreadsheetCapabilityError::Unauthorized(
                "spreadsheet backend must deny network and disable macros".to_owned(),
            ));
        }
        validate_hash(&self.descriptor_sha256, "backend descriptor hash")?;
        if hash_without(self, &["descriptor_sha256"])? != self.descriptor_sha256 {
            return Err(integrity(
                "spreadsheet backend descriptor self-hash differs",
            ));
        }
        Ok(())
    }
}

impl SpreadsheetBackendApprovalV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, SpreadsheetCapabilityError> {
        self.approved_operation_ids.sort();
        self.signature_hex.clear();
        self.approval_sha256 = ZERO_HASH.to_owned();
        let payload = canonical_json_bytes(&self).map_err(|error| invalid(error.to_string()))?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.approval_sha256 = hash_without(&self, &["approval_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), SpreadsheetCapabilityError> {
        self.validate()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms > self.expires_at_unix_ms {
            return Err(SpreadsheetCapabilityError::Stale(
                "spreadsheet backend approval is outside its validity window".to_owned(),
            ));
        }
        let mut payload = self.clone();
        payload.signature_hex.clear();
        payload.approval_sha256 = ZERO_HASH.to_owned();
        verify_signature(key, &payload, &self.signature_hex)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(invalid(
                "spreadsheet backend approval time or version is invalid",
            ));
        }
        for (value, label) in [
            (&self.approval_id, "backend approval ID"),
            (&self.organization_id, "backend approval organization"),
            (&self.signer_id, "backend approval signer"),
            (&self.signing_key_id, "backend approval signing key"),
        ] {
            validate_id(value, label)?;
        }
        for hash in [
            &self.backend_descriptor_sha256,
            &self.capability_pack_sha256,
            &self.workspace_profile_sha256,
            &self.approval_sha256,
        ] {
            validate_hash(hash, "backend approval hash")?;
        }
        validate_ids(
            &self.approved_operation_ids,
            "approved spreadsheet operations",
            false,
            32,
        )?;
        validate_signature_hex(&self.signature_hex)?;
        if hash_without(self, &["approval_sha256"])? != self.approval_sha256 {
            return Err(integrity("spreadsheet backend approval self-hash differs"));
        }
        Ok(())
    }
}

impl SpreadsheetOperationIntentV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.expected_postcondition_ids.sort();
        self.intent_sha256 = hash_without(&self, &["intent_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION || self.source_generation == 0 {
            return Err(invalid(
                "spreadsheet operation intent version or generation is invalid",
            ));
        }
        for (value, label) in [
            (&self.intent_id, "spreadsheet intent ID"),
            (&self.case_id, "spreadsheet intent Case ID"),
            (&self.workbook_id, "spreadsheet intent workbook ID"),
            (&self.artifact_id, "spreadsheet intent artifact ID"),
        ] {
            validate_id(value, label)?;
        }
        for hash in [
            &self.source_content_sha256,
            &self.source_snapshot_sha256,
            &self.intent_sha256,
        ] {
            validate_hash(hash, "spreadsheet intent hash")?;
        }
        if let Some(hash) = &self.query_sha256 {
            validate_hash(hash, "spreadsheet intent query hash")?;
        }
        if let Some(hash) = &self.context_slice_sha256 {
            validate_hash(hash, "spreadsheet intent context slice hash")?;
        }
        validate_ids(
            &self.expected_postcondition_ids,
            "spreadsheet expected postconditions",
            false,
            32,
        )?;
        validate_operation_mutation(self.operation, self.mutation.as_ref())?;
        if hash_without(self, &["intent_sha256"])? != self.intent_sha256 {
            return Err(integrity("spreadsheet operation intent self-hash differs"));
        }
        Ok(())
    }
}

fn validate_operation_mutation(
    operation: SpreadsheetOperationV1,
    mutation: Option<&SpreadsheetMutationV1>,
) -> Result<(), SpreadsheetCapabilityError> {
    match (operation, mutation) {
        (
            SpreadsheetOperationV1::SetCellValue,
            Some(SpreadsheetMutationV1::SetCellValue {
                target_cell_id,
                value,
            }),
        ) => {
            validate_id(target_cell_id, "target cell ID")?;
            validate_scalar(value)
        }
        (
            SpreadsheetOperationV1::SetCellFormula,
            Some(SpreadsheetMutationV1::SetCellFormula {
                target_cell_id,
                formula,
            }),
        ) => {
            validate_id(target_cell_id, "target formula cell ID")?;
            validate_formula(formula)
        }
        (
            SpreadsheetOperationV1::AppendTableRow,
            Some(SpreadsheetMutationV1::AppendTableRow { table_id, values }),
        ) => {
            validate_id(table_id, "append table ID")?;
            if values.is_empty() || values.len() > 1_024 {
                return Err(resource("append row value count is invalid"));
            }
            let mut columns = BTreeSet::new();
            for value in values {
                validate_id(&value.column_id, "append row column ID")?;
                validate_scalar(&value.value)?;
                if !columns.insert(&value.column_id) {
                    return Err(invalid("append row repeats a column"));
                }
            }
            Ok(())
        }
        (
            SpreadsheetOperationV1::ApplyCellStyle,
            Some(SpreadsheetMutationV1::ApplyCellStyle {
                target_cell_id,
                style_id,
            }),
        ) => {
            validate_id(target_cell_id, "style target cell ID")?;
            validate_id(style_id, "spreadsheet style ID")
        }
        (
            SpreadsheetOperationV1::CreateTable,
            Some(SpreadsheetMutationV1::CreateTable {
                sheet_id,
                table_id,
                column_ids,
            }),
        ) => {
            validate_id(sheet_id, "new table sheet ID")?;
            validate_id(table_id, "new table ID")?;
            validate_ids(column_ids, "new table column IDs", false, 1_024)
        }
        (
            SpreadsheetOperationV1::Inspect
            | SpreadsheetOperationV1::Query
            | SpreadsheetOperationV1::CreateFromTemplate
            | SpreadsheetOperationV1::SaveVersion,
            None,
        ) => Ok(()),
        _ => Err(invalid("spreadsheet operation and mutation payload differ")),
    }
}

fn validate_formula(formula: &SpreadsheetFormulaV1) -> Result<(), SpreadsheetCapabilityError> {
    match formula {
        SpreadsheetFormulaV1::SumRange { source_range_id } => {
            validate_id(source_range_id, "formula source range ID")
        }
        SpreadsheetFormulaV1::Difference {
            left_cell_id,
            right_cell_id,
        }
        | SpreadsheetFormulaV1::Product {
            left_cell_id,
            right_cell_id,
        } => {
            validate_id(left_cell_id, "formula left cell ID")?;
            validate_id(right_cell_id, "formula right cell ID")
        }
        SpreadsheetFormulaV1::Ratio {
            numerator_cell_id,
            denominator_cell_id,
        } => {
            validate_id(numerator_cell_id, "formula numerator cell ID")?;
            validate_id(denominator_cell_id, "formula denominator cell ID")
        }
    }
}

macro_rules! impl_self_hashed_artifact {
    ($type:ty, $field:ident, $artifact:ident, $validate:block) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
                self.$field = hash_without(&self, &[stringify!($field)])?;
                self.validate()?;
                Ok(self)
            }

            pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
                if self.schema_version != SPREADSHEET_SCHEMA_VERSION {
                    return Err(invalid("spreadsheet artifact schema version is unsupported"));
                }
                validate_hash(&self.$field, stringify!($field))?;
                let $artifact = self;
                $validate
                if hash_without(self, &[stringify!($field)])? != self.$field {
                    return Err(integrity(concat!(stringify!($type), " self-hash differs")));
                }
                Ok(())
            }
        }
    };
}

impl_self_hashed_artifact!(SpreadsheetOperationBindingV1, binding_sha256, artifact, {
    validate_id(&artifact.binding_id, "spreadsheet binding ID")?;
    validate_id(&artifact.activation_id, "spreadsheet activation ID")?;
    for hash in [
        &artifact.role_instance_sha256,
        &artifact.case_instance_sha256,
        &artifact.lease_sha256,
        &artifact.case_work_grant_sha256,
        &artifact.workspace_profile_sha256,
        &artifact.root_binding_sha256,
        &artifact.artifact_version_sha256,
        &artifact.intent_sha256,
        &artifact.capability_pack_sha256,
        &artifact.backend_descriptor_sha256,
        &artifact.backend_approval_sha256,
        &artifact.policy_admission_sha256,
        &artifact.activation_sha256,
        &artifact.worker_sha256,
    ] {
        validate_hash(hash, "spreadsheet binding hash")?;
    }
    if let Some(hash) = &artifact.application_sha256 {
        validate_hash(hash, "spreadsheet binding application hash")?;
    }
    if artifact.issued_at_unix_ms == 0 || artifact.expires_at_unix_ms <= artifact.issued_at_unix_ms
    {
        return Err(invalid("spreadsheet binding TTL is invalid"));
    }
});

impl_self_hashed_artifact!(SpreadsheetOperationReceiptV1, receipt_sha256, artifact, {
    validate_id(&artifact.receipt_id, "spreadsheet receipt ID")?;
    validate_hash(&artifact.binding_sha256, "spreadsheet receipt binding hash")?;
    validate_hash(
        &artifact.source_content_sha256,
        "spreadsheet receipt source hash",
    )?;
    for optional in [
        &artifact.destination_content_sha256,
        &artifact.fresh_snapshot_sha256,
        &artifact.query_result_sha256,
        &artifact.context_slice_sha256,
    ] {
        optional
            .as_ref()
            .map(|hash| validate_hash(hash, "spreadsheet receipt optional hash"))
            .transpose()?;
    }
    validate_ids(
        &artifact.audit_event_ids,
        "spreadsheet receipt audit IDs",
        false,
        64,
    )?;
    if artifact.started_at_unix_ms == 0
        || artifact.completed_at_unix_ms < artifact.started_at_unix_ms
    {
        return Err(invalid("spreadsheet receipt timestamps are invalid"));
    }
});

impl SpreadsheetSemanticDiffV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.changed_sheet_ids.sort();
        self.changed_table_ids.sort();
        self.changed_cell_ids.sort();
        self.unexpected_change_ids.sort();
        self.diff_sha256 = hash_without(&self, &["diff_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION {
            return Err(invalid("spreadsheet diff schema version is unsupported"));
        }
        validate_hash(&self.before_snapshot_sha256, "diff before hash")?;
        validate_hash(&self.after_snapshot_sha256, "diff after hash")?;
        for ids in [
            &self.changed_sheet_ids,
            &self.changed_table_ids,
            &self.changed_cell_ids,
            &self.unexpected_change_ids,
        ] {
            validate_ids(ids, "spreadsheet diff IDs", true, 256)?;
        }
        validate_hash(&self.diff_sha256, "spreadsheet diff hash")?;
        if hash_without(self, &["diff_sha256"])? != self.diff_sha256 {
            return Err(integrity("spreadsheet diff self-hash differs"));
        }
        Ok(())
    }
}

impl_self_hashed_artifact!(
    SpreadsheetPostOperationVerificationV1,
    verification_sha256,
    artifact,
    {
        validate_id(&artifact.verification_id, "spreadsheet verification ID")?;
        for hash in [
            &artifact.binding_sha256,
            &artifact.receipt_sha256,
            &artifact.diff_sha256,
            &artifact.fresh_snapshot_sha256,
        ] {
            validate_hash(hash, "spreadsheet verification hash")?;
        }
        validate_ids(
            &artifact.expected_postcondition_ids,
            "expected postconditions",
            false,
            32,
        )?;
        validate_ids(
            &artifact.satisfied_postcondition_ids,
            "satisfied postconditions",
            true,
            32,
        )?;
        validate_ids(
            &artifact.protected_invariant_ids,
            "protected spreadsheet invariants",
            false,
            32,
        )?;
        if artifact.verified_at_unix_ms == 0 {
            return Err(invalid("spreadsheet verification time is invalid"));
        }
    }
);

impl_self_hashed_artifact!(SpreadsheetWorkReplayReportV1, report_sha256, artifact, {
    if artifact.scenario_count == 0 || artifact.runs_per_scenario == 0 {
        return Err(invalid("spreadsheet replay dimensions are invalid"));
    }
});

impl SpreadsheetWorkCompletionReportV1 {
    pub fn seal(mut self) -> Result<Self, SpreadsheetCapabilityError> {
        self.finished_sha256 = hash_without(&self, &["finished_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION {
            return Err(invalid("spreadsheet Completion version is unsupported"));
        }
        validate_id(&self.report_id, "spreadsheet Completion report ID")?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.capability_pack_sha256,
            &self.replay_report_sha256,
            &self.protected_audit_terminal_sha256,
            &self.excel_executable_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
            &self.finished_sha256,
        ] {
            validate_hash(hash, "spreadsheet Completion hash")?;
        }
        if self.complete {
            let safety =
                serde_json::to_value(&self.safety).map_err(|error| invalid(error.to_string()))?;
            let residual =
                serde_json::to_value(&self.residual).map_err(|error| invalid(error.to_string()))?;
            if safety
                .as_object()
                .is_none_or(|values| values.values().any(|value| value.as_u64() != Some(0)))
                || residual
                    .as_object()
                    .is_none_or(|values| values.values().any(|value| value.as_u64() != Some(0)))
                || self.successful_operations != self.verified_operations
                || self.xlsx_file_mutations == 0
                || self.excel_com_mutations == 0
                || self.query_count == 0
                || self.context_slice_count == 0
                || self.actual_qwen_cases == 0
            {
                return Err(integrity(
                    "spreadsheet Completion has a non-zero terminal gate",
                ));
            }
        }
        if hash_without(self, &["finished_sha256"])? != self.finished_sha256 {
            return Err(integrity("spreadsheet Completion self-hash differs"));
        }
        Ok(())
    }
}

impl SpreadsheetWorkCertificationV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, SpreadsheetCapabilityError> {
        self.backend_approval_sha256s.sort();
        self.evidence_ids.sort();
        self.signature_hex.clear();
        self.certification_sha256 = ZERO_HASH.to_owned();
        let payload = canonical_json_bytes(&self).map_err(|error| invalid(error.to_string()))?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.certification_sha256 = hash_without(&self, &["certification_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), SpreadsheetCapabilityError> {
        self.validate_signature(key)?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms > self.expires_at_unix_ms {
            return Err(SpreadsheetCapabilityError::Stale(
                "spreadsheet certification is outside its validity window".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validates the certification hash and signature without applying wall-clock freshness.
    pub fn validate_signature(&self, key: &VerifyingKey) -> Result<(), SpreadsheetCapabilityError> {
        self.validate()?;
        let mut payload = self.clone();
        payload.signature_hex.clear();
        payload.certification_sha256 = ZERO_HASH.to_owned();
        verify_signature(key, &payload, &self.signature_hex)
    }

    pub fn validate(&self) -> Result<(), SpreadsheetCapabilityError> {
        if self.schema_version != SPREADSHEET_SCHEMA_VERSION
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(invalid(
                "spreadsheet certification time or version is invalid",
            ));
        }
        for (value, label) in [
            (&self.certification_id, "spreadsheet certification ID"),
            (&self.signer_id, "spreadsheet certification signer"),
            (&self.signing_key_id, "spreadsheet certification key"),
        ] {
            validate_id(value, label)?;
        }
        for hash in [
            &self.capability_pack_sha256,
            &self.workspace_profile_sha256,
            &self.completion_report_sha256,
            &self.replay_report_sha256,
            &self.certification_sha256,
        ] {
            validate_hash(hash, "spreadsheet certification hash")?;
        }
        validate_hashes(
            &self.backend_approval_sha256s,
            "spreadsheet backend approval hashes",
            false,
            8,
        )?;
        validate_ids(
            &self.evidence_ids,
            "spreadsheet certification evidence",
            false,
            64,
        )?;
        validate_signature_hex(&self.signature_hex)?;
        if hash_without(self, &["certification_sha256"])? != self.certification_sha256 {
            return Err(integrity("spreadsheet certification self-hash differs"));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SpreadsheetActivationLedgerV1 {
    consumed: BTreeSet<(String, String)>,
}

impl SpreadsheetActivationLedgerV1 {
    pub fn consume(
        &mut self,
        activation_id: &str,
        activation_sha256: &str,
    ) -> Result<(), SpreadsheetCapabilityError> {
        validate_id(activation_id, "spreadsheet activation ID")?;
        validate_hash(activation_sha256, "spreadsheet activation hash")?;
        if !self
            .consumed
            .insert((activation_id.to_owned(), activation_sha256.to_owned()))
        {
            return Err(SpreadsheetCapabilityError::Replay(
                "spreadsheet activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }
}

fn validate_signature_hex(value: &str) -> Result<(), SpreadsheetCapabilityError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("spreadsheet signature must be 64-byte hex"));
    }
    Ok(())
}

fn verify_signature<T: Serialize>(
    key: &VerifyingKey,
    payload: &T,
    signature_hex: &str,
) -> Result<(), SpreadsheetCapabilityError> {
    let signature = hex_decode_64(signature_hex)?;
    let signature = Signature::from_bytes(&signature);
    let payload = canonical_json_bytes(payload).map_err(|error| invalid(error.to_string()))?;
    key.verify(&payload, &signature).map_err(|_| {
        SpreadsheetCapabilityError::Signature("signature verification failed".to_owned())
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_decode_64(value: &str) -> Result<[u8; 64], SpreadsheetCapabilityError> {
    validate_signature_hex(value)?;
    let mut output = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, SpreadsheetCapabilityError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(invalid("spreadsheet signature contains non-hex data")),
    }
}

#[cfg(test)]
mod tests;
