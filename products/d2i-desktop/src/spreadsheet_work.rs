use d2i_spreadsheet_capability::{
    SpreadsheetColumnValueV1, SpreadsheetFormulaV1, SpreadsheetMutationV1,
    SpreadsheetResourceLimitsV1, SpreadsheetScalarV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSpreadsheetOperationV1 {
    pub mutation: SpreadsheetMutationV1,
}

pub fn validate_spreadsheet_mutation(
    operation: &ResolvedSpreadsheetOperationV1,
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<(), String> {
    match &operation.mutation {
        SpreadsheetMutationV1::SetCellValue {
            target_cell_id,
            value,
        } => {
            validate_identifier(target_cell_id, "spreadsheet target cell")?;
            validate_scalar(value)
        }
        SpreadsheetMutationV1::SetCellFormula {
            target_cell_id,
            formula,
        } => {
            validate_identifier(target_cell_id, "spreadsheet formula target")?;
            validate_formula(formula)
        }
        SpreadsheetMutationV1::AppendTableRow { table_id, values } => {
            validate_identifier(table_id, "spreadsheet append table")?;
            validate_row_values(values, limits)
        }
        SpreadsheetMutationV1::ApplyCellStyle {
            target_cell_id,
            style_id,
        } => {
            validate_identifier(target_cell_id, "spreadsheet style target")?;
            validate_identifier(style_id, "spreadsheet style")
        }
        SpreadsheetMutationV1::CreateTable {
            sheet_id,
            table_id,
            column_ids,
        } => {
            validate_identifier(sheet_id, "spreadsheet table sheet")?;
            validate_identifier(table_id, "spreadsheet table")?;
            if column_ids.is_empty()
                || column_ids.len()
                    > usize::try_from(limits.maximum_columns_per_table)
                        .map_err(|error| format!("spreadsheet column bound: {error}"))?
            {
                return Err("spreadsheet table columns exceed the approved bound".to_owned());
            }
            let mut unique = BTreeSet::new();
            for column_id in column_ids {
                validate_identifier(column_id, "spreadsheet table column")?;
                if !unique.insert(column_id) {
                    return Err("spreadsheet table column is duplicated".to_owned());
                }
            }
            Ok(())
        }
    }
}

fn validate_row_values(
    values: &[SpreadsheetColumnValueV1],
    limits: &SpreadsheetResourceLimitsV1,
) -> Result<(), String> {
    if values.is_empty()
        || values.len()
            > usize::try_from(limits.maximum_columns_per_table)
                .map_err(|error| format!("spreadsheet row column bound: {error}"))?
    {
        return Err("spreadsheet append row exceeds the approved width".to_owned());
    }
    let mut columns = BTreeSet::new();
    for value in values {
        validate_identifier(&value.column_id, "spreadsheet append column")?;
        validate_scalar(&value.value)?;
        if !columns.insert(&value.column_id) {
            return Err("spreadsheet append row repeats a column".to_owned());
        }
    }
    Ok(())
}

fn validate_formula(formula: &SpreadsheetFormulaV1) -> Result<(), String> {
    match formula {
        SpreadsheetFormulaV1::SumRange { source_range_id } => {
            validate_identifier(source_range_id, "spreadsheet formula range")
        }
        SpreadsheetFormulaV1::Difference {
            left_cell_id,
            right_cell_id,
        }
        | SpreadsheetFormulaV1::Product {
            left_cell_id,
            right_cell_id,
        } => {
            validate_identifier(left_cell_id, "spreadsheet formula left cell")?;
            validate_identifier(right_cell_id, "spreadsheet formula right cell")
        }
        SpreadsheetFormulaV1::Ratio {
            numerator_cell_id,
            denominator_cell_id,
        } => {
            validate_identifier(numerator_cell_id, "spreadsheet formula numerator")?;
            validate_identifier(denominator_cell_id, "spreadsheet formula denominator")
        }
    }
}

fn validate_scalar(value: &SpreadsheetScalarV1) -> Result<(), String> {
    match value {
        SpreadsheetScalarV1::Text { value } if value.is_empty() || value.chars().count() > 512 => {
            Err("spreadsheet text value is empty or exceeds 512 characters".to_owned())
        }
        SpreadsheetScalarV1::Text { value } if value.contains('\0') => {
            Err("spreadsheet text value contains NUL".to_owned())
        }
        SpreadsheetScalarV1::Decimal { scale, .. } if *scale > 6 => {
            Err("spreadsheet decimal scale exceeds six places".to_owned())
        }
        SpreadsheetScalarV1::Error { code } => validate_identifier(code, "spreadsheet error code"),
        _ => Ok(()),
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return Err(format!("{label} is not a bounded identifier"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_spreadsheet_capability::default_spreadsheet_resource_limits;

    #[test]
    fn raw_formula_text_has_no_resolved_operation_shape() {
        let operation = ResolvedSpreadsheetOperationV1 {
            mutation: SpreadsheetMutationV1::SetCellFormula {
                target_cell_id: "cell.sheet.0001.r000001.c000003".to_owned(),
                formula: SpreadsheetFormulaV1::Difference {
                    left_cell_id: "cell.sheet.0001.r000001.c000001".to_owned(),
                    right_cell_id: "cell.sheet.0001.r000001.c000002".to_owned(),
                },
            },
        };
        validate_spreadsheet_mutation(&operation, &default_spreadsheet_resource_limits())
            .unwrap_or_else(|error| panic!("typed formula must validate: {error}"));
        let json = serde_json::to_string(&operation)
            .unwrap_or_else(|error| panic!("operation must serialize: {error}"));
        assert!(!json.contains("WEBSERVICE"));
        assert!(!json.contains("formula_text"));
    }
}
