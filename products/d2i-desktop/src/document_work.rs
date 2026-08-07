use d2i_document_capability::{
    DocumentPageLayoutSpecV1, DocumentResourceLimitsV1, DocumentStyleRoleV1,
};
use serde::{Deserialize, Serialize};

/// Trusted, resolved operation passed to a format-specific worker. No paths,
/// XPath, XML, COM member names, commands, or scripts are accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolvedDocumentOperationV1 {
    AppendParagraph {
        text: String,
        style_role: DocumentStyleRoleV1,
    },
    InsertHeading {
        text: String,
        level: u8,
    },
    ReplaceText {
        target_node_id: String,
        expected_old_text_sha256: String,
        replacement_text: String,
        maximum_replacements: u32,
    },
    ApplyParagraphStyle {
        target_node_id: String,
        style_role: DocumentStyleRoleV1,
    },
    InsertTable {
        table_id: String,
        cells: Vec<Vec<String>>,
        header_rows: u32,
    },
    SetTableCell {
        table_id: String,
        row: u32,
        column: u32,
        text: String,
    },
    InsertImage {
        image_id: String,
        media_type: String,
        content_sha256: String,
        bytes: Vec<u8>,
    },
    SetPageLayout {
        layout: DocumentPageLayoutSpecV1,
    },
}

pub fn default_document_resource_limits() -> DocumentResourceLimitsV1 {
    DocumentResourceLimitsV1 {
        maximum_document_bytes: 16 * 1024 * 1024,
        maximum_package_entries: 256,
        maximum_uncompressed_bytes: 64 * 1024 * 1024,
        maximum_compression_ratio: 100,
        maximum_xml_bytes: 8 * 1024 * 1024,
        maximum_xml_depth: 64,
        maximum_xml_nodes: 100_000,
        maximum_xml_attributes: 250_000,
        maximum_sections: 32,
        maximum_nodes: 4_096,
        maximum_tables: 64,
        maximum_table_rows: 256,
        maximum_table_columns: 64,
        maximum_table_cells: 16_384,
        maximum_images: 64,
        maximum_image_bytes: 8 * 1024 * 1024,
        maximum_total_embedded_bytes: 32 * 1024 * 1024,
        maximum_text_characters_per_node: 8_192,
        maximum_total_observed_characters: 128_000,
        maximum_generated_characters_per_case: 128_000,
        maximum_operations_per_case: 64,
        maximum_model_invocations: 64,
        maximum_save_generations: 64,
        maximum_worker_milliseconds: 30_000,
        maximum_application_session_milliseconds: 120_000,
        maximum_worker_memory_bytes: 1024 * 1024 * 1024,
    }
}

pub(crate) fn validate_resolved_operation(
    operation: &ResolvedDocumentOperationV1,
    limits: &DocumentResourceLimitsV1,
) -> Result<(), String> {
    let validate_text = |text: &str| {
        if text.is_empty()
            || text.chars().count()
                > usize::try_from(limits.maximum_text_characters_per_node).unwrap_or(usize::MAX)
            || text.contains('\0')
        {
            Err("resolved document text exceeds its bound".to_owned())
        } else {
            Ok(())
        }
    };
    match operation {
        ResolvedDocumentOperationV1::AppendParagraph { text, .. } => validate_text(text),
        ResolvedDocumentOperationV1::InsertHeading { text, level } => {
            validate_text(text)?;
            if !(1..=2).contains(level) {
                return Err("document heading level must be 1 or 2".to_owned());
            }
            Ok(())
        }
        ResolvedDocumentOperationV1::ReplaceText {
            target_node_id,
            expected_old_text_sha256,
            replacement_text,
            maximum_replacements,
        } => {
            validate_semantic_id(target_node_id)?;
            d2i_office_capability::validate_hash(expected_old_text_sha256, "old text hash")
                .map_err(|error| error.to_string())?;
            validate_text(replacement_text)?;
            if *maximum_replacements != 1 {
                return Err("replace_text permits exactly one replacement".to_owned());
            }
            Ok(())
        }
        ResolvedDocumentOperationV1::ApplyParagraphStyle { target_node_id, .. } => {
            validate_semantic_id(target_node_id)
        }
        ResolvedDocumentOperationV1::InsertTable {
            table_id,
            cells,
            header_rows,
        } => {
            validate_semantic_id(table_id)?;
            if cells.is_empty()
                || cells.len() > usize::try_from(limits.maximum_table_rows).unwrap_or(usize::MAX)
            {
                return Err("document table row count is invalid".to_owned());
            }
            let columns = cells.first().map(Vec::len).unwrap_or_default();
            if columns == 0
                || columns > usize::try_from(limits.maximum_table_columns).unwrap_or(usize::MAX)
                || usize::try_from(*header_rows).unwrap_or(usize::MAX) > cells.len()
                || cells.iter().any(|row| row.len() != columns)
            {
                return Err("document table columns are inconsistent".to_owned());
            }
            for text in cells.iter().flatten() {
                validate_text(text)?;
            }
            Ok(())
        }
        ResolvedDocumentOperationV1::SetTableCell {
            table_id,
            row,
            column,
            text,
        } => {
            validate_semantic_id(table_id)?;
            if *row >= limits.maximum_table_rows || *column >= limits.maximum_table_columns {
                return Err("document table cell is outside resource bounds".to_owned());
            }
            validate_text(text)
        }
        ResolvedDocumentOperationV1::InsertImage {
            image_id,
            media_type,
            content_sha256,
            bytes,
        } => {
            validate_semantic_id(image_id)?;
            d2i_office_capability::validate_hash(content_sha256, "image hash")
                .map_err(|error| error.to_string())?;
            if !matches!(media_type.as_str(), "image/png" | "image/jpeg")
                || bytes.is_empty()
                || u64::try_from(bytes.len()).map_or(true, |size| size > limits.maximum_image_bytes)
                || d2i_office_capability::sha256_bytes(bytes) != *content_sha256
            {
                return Err("document image is not a bound PNG/JPEG artifact".to_owned());
            }
            Ok(())
        }
        ResolvedDocumentOperationV1::SetPageLayout { layout } => layout
            .clone()
            .seal()
            .and_then(|sealed| sealed.validate_integrity())
            .map_err(|error| error.to_string()),
    }
}

fn validate_semantic_id(value: &str) -> Result<(), String> {
    d2i_office_capability::validate_id(value, "semantic document ID")
        .map_err(|error| error.to_string())
}
