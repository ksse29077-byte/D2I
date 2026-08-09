use crate::spreadsheet_package::BoundedSpreadsheetPackage;
use crate::{validate_spreadsheet_mutation, ResolvedSpreadsheetOperationV1};
use d2i_office_capability::sha256_bytes;
use d2i_spreadsheet_capability::{
    spreadsheet_canonical_sha256, IndexedSpreadsheetRowV1, IndexedSpreadsheetTableV1,
    IndexedSpreadsheetWorkbookV1, SpreadsheetColumnTypeV1, SpreadsheetColumnV1,
    SpreadsheetColumnValueV1, SpreadsheetFormatV1, SpreadsheetMutationV1,
    SpreadsheetResourceLimitsV1, SpreadsheetScalarV1, SpreadsheetSemanticSnapshotV1,
    SpreadsheetSheetV1, SpreadsheetTableV1, ZERO_HASH,
};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer, XmlVersion};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;

#[derive(Debug, Clone)]
struct WorksheetBinding {
    sheet_id: String,
    ordinal: u32,
    name_sha256: String,
    part_name: String,
}

#[derive(Debug, Clone)]
struct ParsedWorksheet {
    values: BTreeMap<(u32, u32), SpreadsheetScalarV1>,
    formulas: BTreeMap<(u32, u32), String>,
    maximum_row: u32,
    maximum_column: u32,
}

pub fn create_xlsx_workbook(
    destination: &Path,
    sheet_name: &str,
    headers: &[String],
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<u64, String> {
    validate_sheet_name(sheet_name)?;
    if headers.is_empty()
        || headers.len()
            > usize::try_from(limits.maximum_columns_per_table)
                .map_err(|error| format!("XLSX header bound: {error}"))?
    {
        return Err("XLSX headers exceed the approved table width".to_owned());
    }
    let mut unique = BTreeSet::new();
    for header in headers {
        if header.is_empty() || header.chars().count() > 128 || header.contains('\0') {
            return Err("XLSX header is empty or exceeds 128 characters".to_owned());
        }
        if !unique.insert(header) {
            return Err("XLSX headers must be unique".to_owned());
        }
    }
    let package = BoundedSpreadsheetPackage::from_entries(
        minimal_xlsx_entries(sheet_name, headers)?,
        limits,
    )?;
    package.write_atomic(destination, limits)
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_xlsx_workbook(
    path: &Path,
    workbook_id: &str,
    artifact_id: &str,
    artifact_generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<IndexedSpreadsheetWorkbookV1, String> {
    let package = BoundedSpreadsheetPackage::open(path, limits)?;
    inspect_package(
        &package,
        path,
        workbook_id,
        artifact_id,
        artifact_generation,
        backend_id,
        observed_at_unix_ms,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn mutate_xlsx_workbook(
    source: &Path,
    destination: &Path,
    operation: &ResolvedSpreadsheetOperationV1,
    workbook_id: &str,
    artifact_id: &str,
    artifact_generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<IndexedSpreadsheetWorkbookV1, String> {
    validate_spreadsheet_mutation(operation, limits)?;
    if destination.exists() {
        return Err("XLSX destination must be a new generation".to_owned());
    }
    let source_index = inspect_xlsx_workbook(
        source,
        workbook_id,
        artifact_id,
        artifact_generation.saturating_sub(1).max(1),
        backend_id,
        observed_at_unix_ms,
        limits,
    )?;
    let mut package = BoundedSpreadsheetPackage::open(source, limits)?;
    let bindings = parse_workbook_bindings(&package)?;
    match &operation.mutation {
        SpreadsheetMutationV1::SetCellValue {
            target_cell_id,
            value,
        } => {
            let semantic = parse_cell_id(target_cell_id)?;
            validate_existing_cell_target(&source_index, &semantic)?;
            let binding = bindings
                .iter()
                .find(|binding| binding.ordinal == semantic.sheet_ordinal)
                .ok_or_else(|| "XLSX target sheet is absent".to_owned())?;
            let target = a1_reference(semantic.column_ordinal, semantic.data_row_ordinal + 1)?;
            let transformed =
                replace_existing_cell(package.entry(&binding.part_name)?, &target, value)?;
            package.replace_entry(&binding.part_name, transformed)?;
        }
        SpreadsheetMutationV1::AppendTableRow { table_id, values } => {
            let table = source_index
                .tables
                .iter()
                .find(|table| &table.metadata.table_id == table_id)
                .ok_or_else(|| "XLSX append table is absent".to_owned())?;
            let sheet_ordinal = parse_sheet_ordinal(&table.metadata.sheet_id)?;
            let binding = bindings
                .iter()
                .find(|binding| binding.ordinal == sheet_ordinal)
                .ok_or_else(|| "XLSX append sheet is absent".to_owned())?;
            let next_excel_row = table
                .rows
                .last()
                .map_or(2, |row| row.ordinal.saturating_add(2));
            if next_excel_row.saturating_sub(1) > limits.maximum_rows_per_table {
                return Err("XLSX append exceeds the row bound".to_owned());
            }
            let columns = table
                .metadata
                .columns
                .iter()
                .map(|column| (column.column_id.as_str(), column.ordinal))
                .collect::<BTreeMap<_, _>>();
            let mut resolved = Vec::new();
            for value in values {
                let ordinal = columns
                    .get(value.column_id.as_str())
                    .copied()
                    .ok_or_else(|| "XLSX append references an unknown column".to_owned())?;
                resolved.push((ordinal, value.value.clone()));
            }
            resolved.sort_by_key(|(ordinal, _)| *ordinal);
            let transformed = append_row(
                package.entry(&binding.part_name)?,
                next_excel_row,
                &resolved,
            )?;
            package.replace_entry(&binding.part_name, transformed)?;
        }
        SpreadsheetMutationV1::SetCellFormula { .. } => {
            return Err(
                "XLSX file backend does not calculate formulas; use the pinned Excel backend"
                    .to_owned(),
            )
        }
        SpreadsheetMutationV1::ApplyCellStyle { .. }
        | SpreadsheetMutationV1::CreateTable { .. } => {
            return Err("XLSX file backend operation is unsupported in v1".to_owned())
        }
    }
    package.write_atomic(destination, limits)?;
    inspect_xlsx_workbook(
        destination,
        workbook_id,
        artifact_id,
        artifact_generation,
        backend_id,
        observed_at_unix_ms,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_package(
    package: &BoundedSpreadsheetPackage,
    path: &Path,
    workbook_id: &str,
    artifact_id: &str,
    artifact_generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<IndexedSpreadsheetWorkbookV1, String> {
    if artifact_generation == 0 || observed_at_unix_ms == 0 {
        return Err("XLSX generation and observation time must be non-zero".to_owned());
    }
    let bindings = parse_workbook_bindings(package)?;
    if bindings.is_empty()
        || bindings.len()
            > usize::try_from(limits.maximum_sheets)
                .map_err(|error| format!("XLSX sheet bound: {error}"))?
    {
        return Err("XLSX sheet count exceeds the approved bound".to_owned());
    }
    let shared_strings = if package
        .entry_names()
        .any(|name| name == "xl/sharedStrings.xml")
    {
        parse_shared_strings(package.entry("xl/sharedStrings.xml")?, limits)?
    } else {
        Vec::new()
    };

    let mut sheets = Vec::new();
    let mut tables = Vec::new();
    let mut indexed_tables = Vec::new();
    let mut total_populated_cells = 0_u64;
    let mut total_formula_cells = 0_u32;
    let mut workbook_data_material = Vec::new();
    for binding in &bindings {
        let parsed = parse_worksheet(package.entry(&binding.part_name)?, &shared_strings, limits)?;
        let table_id = format!("table.{}.used_range", binding.sheet_id);
        let columns = build_columns(binding, &parsed)?;
        let rows = build_rows(binding, &columns, &parsed)?;
        let source_range_sha256 = spreadsheet_canonical_sha256(&(
            &binding.part_name,
            parsed.maximum_row,
            parsed.maximum_column,
        ))
        .map_err(|error| error.to_string())?;
        let table_state_sha256 = spreadsheet_canonical_sha256(&(
            &source_range_sha256,
            &columns,
            rows.iter()
                .map(|row| (&row.row_id, row.ordinal, &row.values))
                .collect::<Vec<_>>(),
        ))
        .map_err(|error| error.to_string())?;
        let row_count =
            u32::try_from(rows.len()).map_err(|error| format!("XLSX table row count: {error}"))?;
        let table = SpreadsheetTableV1 {
            table_id: table_id.clone(),
            sheet_id: binding.sheet_id.clone(),
            source_range_sha256,
            row_count,
            columns,
            table_state_sha256,
        };
        let populated = u64::try_from(parsed.values.len())
            .map_err(|error| format!("XLSX populated cell count: {error}"))?;
        let formulas = u32::try_from(parsed.formulas.len())
            .map_err(|error| format!("XLSX formula count: {error}"))?;
        total_populated_cells = total_populated_cells
            .checked_add(populated)
            .ok_or_else(|| "XLSX populated cell count overflow".to_owned())?;
        total_formula_cells = total_formula_cells
            .checked_add(formulas)
            .ok_or_else(|| "XLSX formula count overflow".to_owned())?;
        let sheet_state_sha256 = spreadsheet_canonical_sha256(&(
            &binding.sheet_id,
            &table.table_state_sha256,
            populated,
            formulas,
        ))
        .map_err(|error| error.to_string())?;
        sheets.push(SpreadsheetSheetV1 {
            sheet_id: binding.sheet_id.clone(),
            ordinal: binding.ordinal,
            sheet_name_sha256: binding.name_sha256.clone(),
            used_row_count: parsed.maximum_row,
            used_column_count: parsed.maximum_column,
            populated_cell_count: populated,
            formula_count: formulas,
            table_ids: vec![table_id],
            sheet_state_sha256,
        });
        workbook_data_material.push((table.table_state_sha256.clone(), rows.len()));
        tables.push(table.clone());
        indexed_tables.push(IndexedSpreadsheetTableV1 {
            metadata: table,
            rows,
        });
    }

    let source_bytes =
        std::fs::read(path).map_err(|error| format!("XLSX source hash read: {error}"))?;
    let workbook_data_sha256 =
        spreadsheet_canonical_sha256(&workbook_data_material).map_err(|error| error.to_string())?;
    let semantic_state_sha256 =
        spreadsheet_canonical_sha256(&(&sheets, &tables)).map_err(|error| error.to_string())?;
    let snapshot = SpreadsheetSemanticSnapshotV1 {
        schema_version: 1,
        workbook_id: workbook_id.to_owned(),
        artifact_id: artifact_id.to_owned(),
        artifact_generation,
        format_id: SpreadsheetFormatV1::Xlsx,
        backend_id: backend_id.to_owned(),
        sheets,
        tables,
        total_populated_cells,
        total_formula_cells,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: sha256_bytes(&source_bytes),
        workbook_data_sha256,
        semantic_state_sha256,
        observed_at_unix_ms,
        freshness_expires_at_unix_ms: observed_at_unix_ms.saturating_add(60_000),
        evidence_ids: vec!["evidence.xlsx.bounded-fresh-reopen".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    Ok(IndexedSpreadsheetWorkbookV1 {
        snapshot,
        tables: indexed_tables,
    })
}

fn parse_workbook_bindings(
    package: &BoundedSpreadsheetPackage,
) -> Result<Vec<WorksheetBinding>, String> {
    let relationships = parse_relationship_map(package.entry("xl/_rels/workbook.xml.rels")?)?;
    let mut reader = Reader::from_reader(package.entry("xl/workbook.xml")?);
    reader.config_mut().trim_text(true);
    let mut bindings = Vec::new();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("XLSX workbook XML: {error}"))?
        {
            Event::Start(start) | Event::Empty(start)
                if start.local_name().as_ref().eq_ignore_ascii_case(b"sheet") =>
            {
                let name = attribute_value(&start, b"name")?
                    .ok_or_else(|| "XLSX sheet name is missing".to_owned())?;
                validate_sheet_name(&name)?;
                let relationship_id = attribute_value(&start, b"id")?
                    .ok_or_else(|| "XLSX sheet relationship is missing".to_owned())?;
                let target = relationships
                    .get(&relationship_id)
                    .ok_or_else(|| "XLSX sheet relationship target is missing".to_owned())?;
                let part_name = resolve_workbook_target(target)?;
                if !part_name.starts_with("xl/worksheets/") || !part_name.ends_with(".xml") {
                    return Err("XLSX sheet relationship is not a worksheet".to_owned());
                }
                let ordinal = u32::try_from(bindings.len() + 1)
                    .map_err(|error| format!("XLSX sheet ordinal: {error}"))?;
                bindings.push(WorksheetBinding {
                    sheet_id: format!("sheet.{ordinal:04}"),
                    ordinal,
                    name_sha256: sha256_bytes(name.as_bytes()),
                    part_name,
                });
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let mut targets = BTreeSet::new();
    if bindings
        .iter()
        .any(|binding| !targets.insert(&binding.part_name))
    {
        return Err("XLSX workbook repeats a worksheet target".to_owned());
    }
    for binding in &bindings {
        package.entry(&binding.part_name)?;
    }
    Ok(bindings)
}

fn parse_relationship_map(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut relationships = BTreeMap::new();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("XLSX workbook relationships: {error}"))?
        {
            Event::Start(start) | Event::Empty(start)
                if start
                    .local_name()
                    .as_ref()
                    .eq_ignore_ascii_case(b"relationship") =>
            {
                let id = attribute_value(&start, b"id")?
                    .ok_or_else(|| "XLSX relationship ID is missing".to_owned())?;
                let target = attribute_value(&start, b"target")?
                    .ok_or_else(|| "XLSX relationship target is missing".to_owned())?;
                if relationships.insert(id, target).is_some() {
                    return Err("XLSX relationship ID is duplicated".to_owned());
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(relationships)
}

fn resolve_workbook_target(target: &str) -> Result<String, String> {
    let mut components = vec!["xl".to_owned()];
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components
                    .pop()
                    .ok_or_else(|| "XLSX workbook relationship escapes the package".to_owned())?;
            }
            value if value.contains('\\') || value.contains(':') || value.contains('%') => {
                return Err("XLSX workbook target is unsafe".to_owned())
            }
            value => components.push(value.to_owned()),
        }
    }
    if components.first().map(String::as_str) != Some("xl") {
        return Err("XLSX workbook relationship escapes xl/".to_owned());
    }
    Ok(components.join("/"))
}

fn parse_shared_strings(
    bytes: &[u8],
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<Vec<String>, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut values = Vec::new();
    let mut in_item = false;
    let mut in_text = false;
    let mut current = String::new();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("XLSX shared strings: {error}"))?
        {
            Event::Start(start) if start.local_name().as_ref() == b"si" => {
                in_item = true;
                current.clear();
            }
            Event::Start(start) if in_item && start.local_name().as_ref() == b"t" => {
                in_text = true;
            }
            Event::Text(text) if in_item && in_text => {
                let decoded = text
                    .decode()
                    .map_err(|error| format!("XLSX shared string decode: {error}"))?;
                current.push_str(&decoded);
                if current.chars().count()
                    > usize::try_from(limits.maximum_cell_text_characters).unwrap_or(usize::MAX)
                {
                    return Err("XLSX shared string exceeds its bound".to_owned());
                }
            }
            Event::End(end) if end.local_name().as_ref() == b"t" => in_text = false,
            Event::End(end) if end.local_name().as_ref() == b"si" => {
                if values.len()
                    >= usize::try_from(limits.maximum_shared_strings)
                        .map_err(|error| format!("XLSX shared-string bound: {error}"))?
                {
                    return Err("XLSX shared string count exceeds its bound".to_owned());
                }
                values.push(current.clone());
                in_item = false;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(values)
}

fn parse_worksheet(
    bytes: &[u8],
    shared_strings: &[String],
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<ParsedWorksheet, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut values = BTreeMap::new();
    let mut formulas = BTreeMap::new();
    let mut current_reference = None;
    let mut current_type = None;
    let mut current_value = String::new();
    let mut current_formula = String::new();
    let mut inline_text = String::new();
    let mut in_value = false;
    let mut in_formula = false;
    let mut in_inline_text = false;
    let mut maximum_row = 0_u32;
    let mut maximum_column = 0_u32;
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("XLSX worksheet XML: {error}"))?
        {
            Event::Start(start) if start.local_name().as_ref() == b"c" => {
                if current_reference.is_some() {
                    return Err("XLSX worksheet nests cell elements".to_owned());
                }
                current_reference = Some(
                    attribute_value(&start, b"r")?
                        .ok_or_else(|| "XLSX cell reference is missing".to_owned())?,
                );
                current_type = attribute_value(&start, b"t")?;
                current_value.clear();
                current_formula.clear();
                inline_text.clear();
            }
            Event::Empty(start) if start.local_name().as_ref() == b"c" => {
                let reference = attribute_value(&start, b"r")?
                    .ok_or_else(|| "XLSX cell reference is missing".to_owned())?;
                let (row, column) = parse_a1_reference(&reference)?;
                maximum_row = maximum_row.max(row);
                maximum_column = maximum_column.max(column);
            }
            Event::Start(start)
                if current_reference.is_some() && start.local_name().as_ref() == b"v" =>
            {
                in_value = true;
            }
            Event::Start(start)
                if current_reference.is_some() && start.local_name().as_ref() == b"f" =>
            {
                in_formula = true;
            }
            Event::Start(start)
                if current_reference.is_some() && start.local_name().as_ref() == b"t" =>
            {
                in_inline_text = true;
            }
            Event::Text(text) if current_reference.is_some() => {
                let decoded = text
                    .decode()
                    .map_err(|error| format!("XLSX cell text decode: {error}"))?;
                if in_value {
                    current_value.push_str(&decoded);
                } else if in_formula {
                    current_formula.push_str(&decoded);
                } else if in_inline_text {
                    inline_text.push_str(&decoded);
                }
                if current_value.len() + current_formula.len() + inline_text.len()
                    > usize::try_from(limits.maximum_cell_text_characters)
                        .unwrap_or(usize::MAX)
                        .saturating_mul(4)
                {
                    return Err("XLSX cell payload exceeds its bound".to_owned());
                }
            }
            Event::End(end) if end.local_name().as_ref() == b"v" => in_value = false,
            Event::End(end) if end.local_name().as_ref() == b"f" => in_formula = false,
            Event::End(end) if end.local_name().as_ref() == b"t" => in_inline_text = false,
            Event::End(end) if end.local_name().as_ref() == b"c" => {
                let reference = current_reference
                    .take()
                    .ok_or_else(|| "XLSX cell close is unbalanced".to_owned())?;
                let (row, column) = parse_a1_reference(&reference)?;
                if row > limits.maximum_rows_per_table.saturating_add(1)
                    || column > limits.maximum_columns_per_table
                {
                    return Err("XLSX cell reference exceeds table bounds".to_owned());
                }
                maximum_row = maximum_row.max(row);
                maximum_column = maximum_column.max(column);
                if !current_formula.is_empty() {
                    validate_passive_formula(&current_formula)?;
                    if formulas
                        .insert((row, column), current_formula.clone())
                        .is_some()
                    {
                        return Err("XLSX cell reference is duplicated".to_owned());
                    }
                }
                let value = parse_cell_scalar(
                    current_type.as_deref(),
                    &current_value,
                    &inline_text,
                    shared_strings,
                )?;
                if !matches!(value, SpreadsheetScalarV1::Blank)
                    && values.insert((row, column), value).is_some()
                {
                    return Err("XLSX cell reference is duplicated".to_owned());
                }
                current_type = None;
            }
            Event::Eof => break,
            _ => {}
        }
        if values.len() as u64 > limits.maximum_populated_cells {
            return Err("XLSX populated cells exceed the approved bound".to_owned());
        }
    }
    if current_reference.is_some() {
        return Err("XLSX cell element is unclosed".to_owned());
    }
    Ok(ParsedWorksheet {
        values,
        formulas,
        maximum_row,
        maximum_column,
    })
}

fn parse_cell_scalar(
    cell_type: Option<&str>,
    value: &str,
    inline_text: &str,
    shared_strings: &[String],
) -> Result<SpreadsheetScalarV1, String> {
    match cell_type.unwrap_or("n") {
        "s" => {
            let index = value
                .parse::<usize>()
                .map_err(|error| format!("XLSX shared-string index: {error}"))?;
            bounded_text_scalar(
                shared_strings
                    .get(index)
                    .ok_or_else(|| "XLSX shared-string index is outside the table".to_owned())?,
            )
        }
        "inlineStr" => bounded_text_scalar(inline_text),
        "str" | "d" => bounded_text_scalar(value),
        "b" => match value {
            "0" => Ok(SpreadsheetScalarV1::Boolean { value: false }),
            "1" => Ok(SpreadsheetScalarV1::Boolean { value: true }),
            _ => Err("XLSX Boolean cell value is invalid".to_owned()),
        },
        "e" => Ok(SpreadsheetScalarV1::Error {
            code: normalize_error_code(value)?,
        }),
        "n" if value.is_empty() => Ok(SpreadsheetScalarV1::Blank),
        "n" => parse_numeric_scalar(value),
        other => Err(format!("XLSX cell type is unsupported: {other}")),
    }
}

fn bounded_text_scalar(value: &str) -> Result<SpreadsheetScalarV1, String> {
    if value.is_empty() {
        return Ok(SpreadsheetScalarV1::Blank);
    }
    if value.chars().count() > 512 || value.contains('\0') {
        return Err("XLSX queryable text exceeds the 512-character typed-fact bound".to_owned());
    }
    Ok(SpreadsheetScalarV1::Text {
        value: value.to_owned(),
    })
}

fn parse_numeric_scalar(value: &str) -> Result<SpreadsheetScalarV1, String> {
    if value.contains(['e', 'E']) {
        return Err("XLSX scientific notation is unsupported in deterministic v1".to_owned());
    }
    if let Ok(integer) = value.parse::<i64>() {
        return Ok(SpreadsheetScalarV1::Integer { value: integer });
    }
    let negative = value.starts_with('-');
    let unsigned = value.strip_prefix(['-', '+']).unwrap_or(value);
    let (whole, fractional) = unsigned
        .split_once('.')
        .ok_or_else(|| "XLSX numeric cell is not a bounded decimal".to_owned())?;
    if fractional.is_empty()
        || fractional.len() > 6
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("XLSX decimal exceeds six deterministic places".to_owned());
    }
    let combined = format!("{whole}{fractional}")
        .parse::<i64>()
        .map_err(|error| format!("XLSX decimal range: {error}"))?;
    Ok(SpreadsheetScalarV1::Decimal {
        scaled_value: if negative { -combined } else { combined },
        scale: u32::try_from(fractional.len())
            .map_err(|error| format!("XLSX decimal scale: {error}"))?,
    })
}

fn normalize_error_code(value: &str) -> Result<String, String> {
    let normalized = value
        .trim_matches('#')
        .trim_end_matches(['!', '?'])
        .replace(['/', ' '], "_")
        .to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err("XLSX error code is invalid".to_owned());
    }
    Ok(format!("error.{normalized}"))
}

fn validate_passive_formula(formula: &str) -> Result<(), String> {
    if formula.is_empty() || formula.len() > 2_048 || formula.contains('\0') {
        return Err("XLSX formula is empty or exceeds its bound".to_owned());
    }
    let uppercase = formula.to_ascii_uppercase();
    for forbidden in [
        "[",
        "HTTP:",
        "HTTPS:",
        "FILE:",
        "\\\\",
        "WEBSERVICE(",
        "FILTERXML(",
        "RTD(",
        "DDE(",
        "HYPERLINK(",
        "CALL(",
        "REGISTER(",
        "EXEC(",
    ] {
        if uppercase.contains(forbidden) {
            return Err(format!(
                "XLSX active/external formula is forbidden: {forbidden}"
            ));
        }
    }
    Ok(())
}

fn build_columns(
    binding: &WorksheetBinding,
    parsed: &ParsedWorksheet,
) -> Result<Vec<SpreadsheetColumnV1>, String> {
    let maximum_column = parsed.maximum_column.max(1);
    let mut columns = Vec::new();
    for ordinal in 1..=maximum_column {
        let header = parsed
            .values
            .get(&(1, ordinal))
            .map(scalar_header_text)
            .transpose()?
            .unwrap_or_else(|| format!("column-{ordinal}"));
        let inferred_type = parsed
            .values
            .iter()
            .filter(|((row, column), _)| *row > 1 && *column == ordinal)
            .fold(SpreadsheetColumnTypeV1::Blank, |current, (_, value)| {
                merge_column_type(current, value.column_type())
            });
        columns.push(SpreadsheetColumnV1 {
            column_id: format!("column.{}.{ordinal:04}", binding.sheet_id),
            ordinal,
            inferred_type,
            header_sha256: sha256_bytes(header.as_bytes()),
            unit_id: None,
            nullable: parsed
                .values
                .keys()
                .filter(|(row, _)| *row > 1)
                .any(|(row, _)| !parsed.values.contains_key(&(*row, ordinal))),
        });
    }
    Ok(columns)
}

fn build_rows(
    binding: &WorksheetBinding,
    columns: &[SpreadsheetColumnV1],
    parsed: &ParsedWorksheet,
) -> Result<Vec<IndexedSpreadsheetRowV1>, String> {
    let row_numbers = parsed
        .values
        .keys()
        .filter_map(|(row, _)| (*row > 1).then_some(*row))
        .collect::<BTreeSet<_>>();
    let mut rows = Vec::new();
    for excel_row in row_numbers {
        let data_ordinal = excel_row - 1;
        let values = columns
            .iter()
            .filter_map(|column| {
                parsed
                    .values
                    .get(&(excel_row, column.ordinal))
                    .cloned()
                    .map(|value| SpreadsheetColumnValueV1 {
                        column_id: column.column_id.clone(),
                        value,
                    })
            })
            .collect::<Vec<_>>();
        rows.push(IndexedSpreadsheetRowV1 {
            row_id: format!("row.{}.{data_ordinal:06}", binding.sheet_id),
            ordinal: data_ordinal,
            values,
        });
    }
    Ok(rows)
}

fn scalar_header_text(value: &SpreadsheetScalarV1) -> Result<String, String> {
    match value {
        SpreadsheetScalarV1::Text { value } => Ok(value.clone()),
        SpreadsheetScalarV1::Integer { value } => Ok(value.to_string()),
        SpreadsheetScalarV1::Decimal {
            scaled_value,
            scale,
        } => format_decimal(*scaled_value, *scale),
        SpreadsheetScalarV1::Boolean { value } => Ok(value.to_string()),
        SpreadsheetScalarV1::Date {
            days_since_unix_epoch,
        } => Ok(format!("date-{days_since_unix_epoch}")),
        SpreadsheetScalarV1::Error { code } => Ok(code.clone()),
        SpreadsheetScalarV1::Blank => Err("XLSX blank header cannot produce text".to_owned()),
    }
}

fn merge_column_type(
    current: SpreadsheetColumnTypeV1,
    next: SpreadsheetColumnTypeV1,
) -> SpreadsheetColumnTypeV1 {
    if current == SpreadsheetColumnTypeV1::Blank {
        next
    } else if next == SpreadsheetColumnTypeV1::Blank || current == next {
        current
    } else {
        SpreadsheetColumnTypeV1::Mixed
    }
}

#[derive(Debug, Clone, Copy)]
struct SemanticCellId {
    sheet_ordinal: u32,
    data_row_ordinal: u32,
    column_ordinal: u32,
}

fn parse_cell_id(value: &str) -> Result<SemanticCellId, String> {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "cell" || parts[1] != "sheet" {
        return Err("spreadsheet cell ID does not use the v1 semantic format".to_owned());
    }
    let row = parts[3]
        .strip_prefix('r')
        .ok_or_else(|| "spreadsheet cell row marker is missing".to_owned())?;
    let column = parts[4]
        .strip_prefix('c')
        .ok_or_else(|| "spreadsheet cell column marker is missing".to_owned())?;
    Ok(SemanticCellId {
        sheet_ordinal: parts[2]
            .parse::<u32>()
            .map_err(|error| format!("spreadsheet cell sheet ordinal: {error}"))?,
        data_row_ordinal: row
            .parse::<u32>()
            .map_err(|error| format!("spreadsheet cell row ordinal: {error}"))?,
        column_ordinal: column
            .parse::<u32>()
            .map_err(|error| format!("spreadsheet cell column ordinal: {error}"))?,
    })
}

fn validate_existing_cell_target(
    workbook: &IndexedSpreadsheetWorkbookV1,
    semantic: &SemanticCellId,
) -> Result<(), String> {
    let table = workbook
        .tables
        .iter()
        .find(|table| {
            parse_sheet_ordinal(&table.metadata.sheet_id).ok() == Some(semantic.sheet_ordinal)
        })
        .ok_or_else(|| "spreadsheet cell sheet is absent".to_owned())?;
    let row = table
        .rows
        .iter()
        .find(|row| row.ordinal == semantic.data_row_ordinal)
        .ok_or_else(|| "spreadsheet cell row is absent".to_owned())?;
    let column = table
        .metadata
        .columns
        .iter()
        .find(|column| column.ordinal == semantic.column_ordinal)
        .ok_or_else(|| "spreadsheet cell column is absent".to_owned())?;
    if !row
        .values
        .iter()
        .any(|value| value.column_id == column.column_id)
    {
        return Err("XLSX file backend only mutates an existing populated cell".to_owned());
    }
    Ok(())
}

fn parse_sheet_ordinal(sheet_id: &str) -> Result<u32, String> {
    sheet_id
        .strip_prefix("sheet.")
        .ok_or_else(|| "spreadsheet sheet ID format differs".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("spreadsheet sheet ordinal: {error}"))
}

fn replace_existing_cell(
    bytes: &[u8],
    target_reference: &str,
    value: &SpreadsheetScalarV1,
) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut skip_depth = 0_u32;
    let mut changed = false;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("XLSX mutation XML: {error}"))?;
        if skip_depth > 0 {
            match &event {
                Event::Start(_) => skip_depth = skip_depth.saturating_add(1),
                Event::End(_) => skip_depth = skip_depth.saturating_sub(1),
                Event::Eof => return Err("XLSX target cell is unclosed".to_owned()),
                _ => {}
            }
            continue;
        }
        match event {
            Event::Start(start) if start.local_name().as_ref() == b"c" => {
                if attribute_value(&start, b"r")?.as_deref() == Some(target_reference) {
                    let style = attribute_value(&start, b"s")?;
                    write_cell(&mut writer, target_reference, value, style.as_deref())?;
                    skip_depth = 1;
                    changed = true;
                } else {
                    writer
                        .write_event(Event::Start(start))
                        .map_err(|error| format!("XLSX mutation write: {error}"))?;
                }
            }
            Event::Empty(start) if start.local_name().as_ref() == b"c" => {
                if attribute_value(&start, b"r")?.as_deref() == Some(target_reference) {
                    let style = attribute_value(&start, b"s")?;
                    write_cell(&mut writer, target_reference, value, style.as_deref())?;
                    changed = true;
                } else {
                    writer
                        .write_event(Event::Empty(start))
                        .map_err(|error| format!("XLSX mutation write: {error}"))?;
                }
            }
            Event::Eof => break,
            other => writer
                .write_event(other)
                .map_err(|error| format!("XLSX mutation write: {error}"))?,
        }
    }
    if !changed {
        return Err("XLSX target cell was not found during mutation".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn append_row(
    bytes: &[u8],
    excel_row: u32,
    values: &[(u32, SpreadsheetScalarV1)],
) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut inserted = false;
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("XLSX append XML: {error}"))?
        {
            Event::End(end) if end.local_name().as_ref() == b"sheetData" => {
                let mut row = BytesStart::new("row");
                let row_text = excel_row.to_string();
                row.push_attribute(("r", row_text.as_str()));
                writer
                    .write_event(Event::Start(row))
                    .map_err(|error| format!("XLSX append row: {error}"))?;
                for (column, value) in values {
                    let reference = a1_reference(*column, excel_row)?;
                    write_cell(&mut writer, &reference, value, None)?;
                }
                writer
                    .write_event(Event::End(BytesEnd::new("row")))
                    .map_err(|error| format!("XLSX append row close: {error}"))?;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| format!("XLSX append sheetData close: {error}"))?;
                inserted = true;
            }
            Event::Eof => break,
            event => writer
                .write_event(event)
                .map_err(|error| format!("XLSX append write: {error}"))?,
        }
    }
    if !inserted {
        return Err("XLSX worksheet has no sheetData element".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn write_cell(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    reference: &str,
    value: &SpreadsheetScalarV1,
    style: Option<&str>,
) -> Result<(), String> {
    let mut cell = BytesStart::new("c");
    cell.push_attribute(("r", reference));
    if let Some(style) = style {
        cell.push_attribute(("s", style));
    }
    match value {
        SpreadsheetScalarV1::Text { value } => {
            cell.push_attribute(("t", "inlineStr"));
            writer
                .write_event(Event::Start(cell))
                .map_err(|error| format!("XLSX text cell: {error}"))?;
            writer
                .write_event(Event::Start(BytesStart::new("is")))
                .map_err(|error| format!("XLSX inline string: {error}"))?;
            writer
                .write_event(Event::Start(BytesStart::new("t")))
                .map_err(|error| format!("XLSX text start: {error}"))?;
            writer
                .write_event(Event::Text(BytesText::new(value)))
                .map_err(|error| format!("XLSX text value: {error}"))?;
            writer
                .write_event(Event::End(BytesEnd::new("t")))
                .map_err(|error| format!("XLSX text end: {error}"))?;
            writer
                .write_event(Event::End(BytesEnd::new("is")))
                .map_err(|error| format!("XLSX inline string end: {error}"))?;
            writer
                .write_event(Event::End(BytesEnd::new("c")))
                .map_err(|error| format!("XLSX text cell close: {error}"))?;
            return Ok(());
        }
        SpreadsheetScalarV1::Boolean { .. } => cell.push_attribute(("t", "b")),
        SpreadsheetScalarV1::Error { .. } => cell.push_attribute(("t", "e")),
        SpreadsheetScalarV1::Date { .. } => cell.push_attribute(("t", "n")),
        SpreadsheetScalarV1::Blank
        | SpreadsheetScalarV1::Integer { .. }
        | SpreadsheetScalarV1::Decimal { .. } => {}
    }
    writer
        .write_event(Event::Start(cell))
        .map_err(|error| format!("XLSX cell start: {error}"))?;
    writer
        .write_event(Event::Start(BytesStart::new("v")))
        .map_err(|error| format!("XLSX value start: {error}"))?;
    let scalar = match value {
        SpreadsheetScalarV1::Blank => String::new(),
        SpreadsheetScalarV1::Integer { value } => value.to_string(),
        SpreadsheetScalarV1::Decimal {
            scaled_value,
            scale,
        } => format_decimal(*scaled_value, *scale)?,
        SpreadsheetScalarV1::Boolean { value } => if *value { "1" } else { "0" }.to_owned(),
        SpreadsheetScalarV1::Date {
            days_since_unix_epoch,
        } => i64::from(*days_since_unix_epoch)
            .saturating_add(25_569)
            .to_string(),
        SpreadsheetScalarV1::Error { code } => format!("#{}!", code.to_ascii_uppercase()),
        SpreadsheetScalarV1::Text { .. } => {
            return Err("XLSX text cell reached numeric serialization".to_owned())
        }
    };
    writer
        .write_event(Event::Text(BytesText::new(&scalar)))
        .map_err(|error| format!("XLSX cell value: {error}"))?;
    writer
        .write_event(Event::End(BytesEnd::new("v")))
        .map_err(|error| format!("XLSX value end: {error}"))?;
    writer
        .write_event(Event::End(BytesEnd::new("c")))
        .map_err(|error| format!("XLSX cell end: {error}"))
}

fn format_decimal(scaled_value: i64, scale: u32) -> Result<String, String> {
    if scale > 6 {
        return Err("XLSX decimal scale exceeds six places".to_owned());
    }
    if scale == 0 {
        return Ok(scaled_value.to_string());
    }
    let negative = scaled_value < 0;
    let digits = scaled_value.unsigned_abs().to_string();
    let scale = usize::try_from(scale).map_err(|error| format!("decimal scale: {error}"))?;
    let padded = if digits.len() <= scale {
        format!("{}{}", "0".repeat(scale + 1 - digits.len()), digits)
    } else {
        digits
    };
    let split = padded.len() - scale;
    Ok(format!(
        "{}{}.{}",
        if negative { "-" } else { "" },
        &padded[..split],
        &padded[split..]
    ))
}

fn parse_a1_reference(reference: &str) -> Result<(u32, u32), String> {
    if reference.is_empty() || reference.len() > 16 || reference.contains(['$', ':']) {
        return Err("XLSX A1 cell reference is invalid".to_owned());
    }
    let split = reference
        .find(|character: char| character.is_ascii_digit())
        .ok_or_else(|| "XLSX A1 cell reference lacks a row".to_owned())?;
    let (letters, digits) = reference.split_at(split);
    if letters.is_empty()
        || digits.is_empty()
        || !letters.bytes().all(|byte| byte.is_ascii_alphabetic())
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("XLSX A1 cell reference is malformed".to_owned());
    }
    let mut column = 0_u32;
    for byte in letters.bytes() {
        column = column
            .checked_mul(26)
            .and_then(|value| value.checked_add(u32::from(byte.to_ascii_uppercase() - b'A' + 1)))
            .ok_or_else(|| "XLSX column reference overflows".to_owned())?;
    }
    let row = digits
        .parse::<u32>()
        .map_err(|error| format!("XLSX row reference: {error}"))?;
    if row == 0 || column == 0 || column > 16_384 || row > 1_048_576 {
        return Err("XLSX A1 cell reference exceeds format bounds".to_owned());
    }
    Ok((row, column))
}

fn a1_reference(column: u32, row: u32) -> Result<String, String> {
    if column == 0 || column > 16_384 || row == 0 || row > 1_048_576 {
        return Err("XLSX cell coordinate exceeds format bounds".to_owned());
    }
    let mut value = column;
    let mut letters = Vec::new();
    while value > 0 {
        value -= 1;
        letters.push(
            char::from_u32(u32::from(b'A') + value % 26)
                .ok_or_else(|| "XLSX column conversion failed".to_owned())?,
        );
        value /= 26;
    }
    letters.reverse();
    Ok(format!("{}{row}", letters.into_iter().collect::<String>()))
}

fn attribute_value(start: &BytesStart<'_>, local: &[u8]) -> Result<Option<String>, String> {
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| format!("XLSX XML attribute: {error}"))?;
        if attribute
            .key
            .local_name()
            .as_ref()
            .eq_ignore_ascii_case(local)
        {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, start.decoder())
                .map(|value| Some(value.into_owned()))
                .map_err(|error| format!("XLSX XML attribute value: {error}"));
        }
    }
    Ok(None)
}

fn validate_sheet_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > 31
        || value.contains(['\\', '/', '?', '*', '[', ']', ':', '\0'])
        || value.starts_with('\'')
        || value.ends_with('\'')
    {
        return Err("XLSX sheet name is invalid".to_owned());
    }
    Ok(())
}

fn minimal_xlsx_entries(
    sheet_name: &str,
    headers: &[String],
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut worksheet = Writer::new(Cursor::new(Vec::new()));
    let mut root = BytesStart::new("worksheet");
    root.push_attribute((
        "xmlns",
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    ));
    worksheet
        .write_event(Event::Start(root))
        .map_err(|error| format!("XLSX worksheet root: {error}"))?;
    worksheet
        .write_event(Event::Start(BytesStart::new("sheetData")))
        .map_err(|error| format!("XLSX sheetData: {error}"))?;
    let mut row = BytesStart::new("row");
    row.push_attribute(("r", "1"));
    worksheet
        .write_event(Event::Start(row))
        .map_err(|error| format!("XLSX header row: {error}"))?;
    for (index, header) in headers.iter().enumerate() {
        let ordinal =
            u32::try_from(index + 1).map_err(|error| format!("XLSX header ordinal: {error}"))?;
        write_cell(
            &mut worksheet,
            &a1_reference(ordinal, 1)?,
            &SpreadsheetScalarV1::Text {
                value: header.clone(),
            },
            None,
        )?;
    }
    worksheet
        .write_event(Event::End(BytesEnd::new("row")))
        .map_err(|error| format!("XLSX header row close: {error}"))?;
    worksheet
        .write_event(Event::End(BytesEnd::new("sheetData")))
        .map_err(|error| format!("XLSX sheetData close: {error}"))?;
    worksheet
        .write_event(Event::End(BytesEnd::new("worksheet")))
        .map_err(|error| format!("XLSX worksheet close: {error}"))?;

    let escaped_name = xml_escape_attribute(sheet_name);
    let mut entries = BTreeMap::new();
    entries.insert(
        "[Content_Types].xml".to_owned(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#.to_vec(),
    );
    entries.insert(
        "_rels/.rels".to_owned(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#.to_vec(),
    );
    entries.insert(
        "xl/workbook.xml".to_owned(),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"{escaped_name}\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>"
        )
        .into_bytes(),
    );
    entries.insert(
        "xl/_rels/workbook.xml.rels".to_owned(),
        br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#.to_vec(),
    );
    entries.insert(
        "xl/worksheets/sheet1.xml".to_owned(),
        worksheet.into_inner().into_inner(),
    );
    Ok(entries)
}

fn xml_escape_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_spreadsheet_capability::default_spreadsheet_resource_limits;

    fn temporary_file(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("d2i-office300-{}-{name}", std::process::id()))
    }

    #[test]
    fn a1_conversion_is_bounded_and_round_trips() {
        for (column, row, expected) in [
            (1, 1, "A1"),
            (26, 7, "Z7"),
            (27, 8, "AA8"),
            (16_384, 1_048_576, "XFD1048576"),
        ] {
            let reference = a1_reference(column, row)
                .unwrap_or_else(|error| panic!("A1 render must succeed: {error}"));
            assert_eq!(reference, expected);
            assert_eq!(
                parse_a1_reference(&reference)
                    .unwrap_or_else(|error| panic!("A1 parse must succeed: {error}")),
                (row, column)
            );
        }
        assert!(parse_a1_reference("$A$1").is_err());
        assert!(a1_reference(16_385, 1).is_err());
    }

    #[test]
    fn file_backend_creates_appends_mutates_and_freshly_reopens() {
        let source = temporary_file("source.xlsx");
        let first = temporary_file("first.xlsx");
        let second = temporary_file("second.xlsx");
        for path in [&source, &first, &second] {
            let _ = std::fs::remove_file(path);
        }
        let limits = default_spreadsheet_resource_limits();
        create_xlsx_workbook(
            &source,
            "Records",
            &["Record".to_owned(), "Amount".to_owned()],
            &limits,
        )
        .unwrap_or_else(|error| panic!("XLSX create must succeed: {error}"));
        let created = inspect_xlsx_workbook(
            &source,
            "workbook.fixture",
            "artifact.fixture",
            1,
            "backend.xlsx.file",
            1_000,
            &limits,
        )
        .unwrap_or_else(|error| panic!("XLSX inspect must succeed: {error}"));
        assert_eq!(created.tables[0].rows.len(), 0);
        let table_id = created.tables[0].metadata.table_id.clone();
        let columns = &created.tables[0].metadata.columns;
        let appended = mutate_xlsx_workbook(
            &source,
            &first,
            &ResolvedSpreadsheetOperationV1 {
                mutation: SpreadsheetMutationV1::AppendTableRow {
                    table_id,
                    values: vec![
                        SpreadsheetColumnValueV1 {
                            column_id: columns[0].column_id.clone(),
                            value: SpreadsheetScalarV1::Text {
                                value: "record-1".to_owned(),
                            },
                        },
                        SpreadsheetColumnValueV1 {
                            column_id: columns[1].column_id.clone(),
                            value: SpreadsheetScalarV1::Integer { value: 10 },
                        },
                    ],
                },
            },
            "workbook.fixture",
            "artifact.fixture",
            2,
            "backend.xlsx.file",
            2_000,
            &limits,
        )
        .unwrap_or_else(|error| panic!("XLSX append must succeed: {error}"));
        assert_eq!(appended.tables[0].rows.len(), 1);
        let mutated = mutate_xlsx_workbook(
            &first,
            &second,
            &ResolvedSpreadsheetOperationV1 {
                mutation: SpreadsheetMutationV1::SetCellValue {
                    target_cell_id: "cell.sheet.0001.r000001.c000002".to_owned(),
                    value: SpreadsheetScalarV1::Integer { value: 25 },
                },
            },
            "workbook.fixture",
            "artifact.fixture",
            3,
            "backend.xlsx.file",
            3_000,
            &limits,
        )
        .unwrap_or_else(|error| panic!("XLSX cell mutation must succeed: {error}"));
        assert_eq!(
            mutated.tables[0].rows[0].values[1].value,
            SpreadsheetScalarV1::Integer { value: 25 }
        );
        assert_ne!(
            appended.snapshot.source_content_sha256,
            mutated.snapshot.source_content_sha256
        );
        for path in [&source, &first, &second] {
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn active_and_external_formulas_are_rejected() {
        for formula in [
            "WEBSERVICE(\"https://example.test\")",
            "'[external.xlsx]Sheet1'!A1",
            "HYPERLINK(\"file:///secret\")",
            "RTD(\"server\")",
        ] {
            assert!(validate_passive_formula(formula).is_err(), "{formula}");
        }
        assert!(validate_passive_formula("SUM(A1:A10)").is_ok());
    }
}
