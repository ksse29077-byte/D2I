use crate::document_package::BoundedDocumentPackage;
use crate::document_work::{validate_resolved_operation, ResolvedDocumentOperationV1};
use d2i_document_capability::{
    document_canonical_sha256, DocumentFormatV1, DocumentNodeKindV1, DocumentResourceLimitsV1,
    DocumentSemanticNodeV1, DocumentSemanticSnapshotV1, DocumentStyleRoleV1, PageOrientationV1,
    ZERO_HASH,
};
use d2i_office_capability::sha256_bytes;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

pub fn create_docx_document(
    destination: &Path,
    limits: &DocumentResourceLimitsV1,
) -> Result<u64, String> {
    if destination.exists() {
        return Err("DOCX destination must be a new generation".to_owned());
    }
    let package = BoundedDocumentPackage::from_entries(
        DocumentFormatV1::Docx,
        minimal_docx_entries(),
        limits,
    )?;
    package.write_atomic(destination, limits)
}

pub fn mutate_docx_document(
    source: &Path,
    destination: &Path,
    operation: &ResolvedDocumentOperationV1,
    limits: &DocumentResourceLimitsV1,
) -> Result<u64, String> {
    validate_resolved_operation(operation, limits)?;
    if destination.exists() {
        return Err("DOCX destination must be a new generation".to_owned());
    }
    let mut package = BoundedDocumentPackage::open(source, DocumentFormatV1::Docx, limits)?;
    let document = package.entry("word/document.xml")?.to_vec();
    let updated = match operation {
        ResolvedDocumentOperationV1::AppendParagraph { text, style_role } => transform_docx(
            &document,
            DocxTransform::AppendParagraph {
                text,
                style_role: *style_role,
            },
        )?,
        ResolvedDocumentOperationV1::InsertHeading { text, level } => transform_docx(
            &document,
            DocxTransform::AppendHeading {
                text,
                level: *level,
            },
        )?,
        ResolvedDocumentOperationV1::ReplaceText {
            target_node_id,
            expected_old_text_sha256,
            replacement_text,
            ..
        } => transform_docx(
            &document,
            DocxTransform::ReplaceText {
                target_node_id,
                expected_old_text_sha256,
                replacement_text,
            },
        )?,
        ResolvedDocumentOperationV1::ApplyParagraphStyle {
            target_node_id,
            style_role,
        } => transform_docx(
            &document,
            DocxTransform::ApplyStyle {
                target_node_id,
                style_role: *style_role,
            },
        )?,
        ResolvedDocumentOperationV1::InsertTable {
            table_id,
            cells,
            header_rows,
        } => transform_docx(
            &document,
            DocxTransform::AppendTable {
                table_id,
                cells,
                header_rows: *header_rows,
            },
        )?,
        ResolvedDocumentOperationV1::SetTableCell {
            table_id,
            row,
            column,
            text,
        } => transform_docx(
            &document,
            DocxTransform::SetTableCell {
                table_id,
                row: *row,
                column: *column,
                text,
            },
        )?,
        ResolvedDocumentOperationV1::InsertImage {
            image_id,
            media_type,
            bytes,
            ..
        } => {
            let extension = if media_type == "image/png" {
                "png"
            } else {
                "jpg"
            };
            let entry = format!("word/media/{image_id}.{extension}");
            package.insert_entry(&entry, bytes.clone())?;
            let relationships = package.entry("word/_rels/document.xml.rels")?.to_vec();
            package.replace_entry(
                "word/_rels/document.xml.rels",
                append_docx_image_relationship(&relationships, image_id, &entry)?,
            )?;
            transform_docx(&document, DocxTransform::AppendImageMarker { image_id })?
        }
        ResolvedDocumentOperationV1::SetPageLayout { layout } => {
            transform_docx(&document, DocxTransform::SetPageLayout { layout })?
        }
    };
    package.replace_entry("word/document.xml", updated)?;
    package.write_atomic(destination, limits)
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_docx_document(
    path: &Path,
    document_id: &str,
    artifact_id: &str,
    artifact_generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &DocumentResourceLimitsV1,
) -> Result<DocumentSemanticSnapshotV1, String> {
    let package = BoundedDocumentPackage::open(path, DocumentFormatV1::Docx, limits)?;
    let projection = parse_docx_projection(package.entry("word/document.xml")?, limits)?;
    let content_hash = sha256_bytes(
        &std::fs::read(path).map_err(|error| format!("DOCX content hash read: {error}"))?,
    );
    let image_refs = package
        .entry_names()
        .filter(|name| name.starts_with("word/media/") && is_supported_image_name(name))
        .enumerate()
        .map(|(index, _)| format!("image-{:04}", index + 1))
        .collect::<Vec<_>>();
    let mut ordered_nodes = projection.nodes;
    for (index, image_ref) in image_refs.iter().enumerate() {
        let ordinal = u32::try_from(ordered_nodes.len())
            .map_err(|error| format!("DOCX image ordinal: {error}"))?;
        let text = format!("embedded-image-{index}");
        ordered_nodes.push(DocumentSemanticNodeV1 {
            node_id: format!("doc-node-{ordinal:04}"),
            node_kind: DocumentNodeKindV1::Image,
            section_id: "section-0001".to_owned(),
            ordinal,
            style_id: None,
            text_excerpt: Some(text.clone()),
            text_sha256: Some(sha256_bytes(text.as_bytes())),
            table_id: None,
            image_id: Some(image_ref.clone()),
            truncated: false,
        });
    }
    let style_catalog_sha256 = if package.has_entry("word/styles.xml") {
        sha256_bytes(package.entry("word/styles.xml")?)
    } else {
        sha256_bytes(b"docx-no-style-part")
    };
    let semantic_state_sha256 = document_canonical_sha256(&(
        &ordered_nodes,
        &projection.table_ids,
        &image_refs,
        &projection.page_layout_summary,
    ))
    .map_err(|error| error.to_string())?;
    DocumentSemanticSnapshotV1 {
        schema_version: 1,
        document_id: document_id.to_owned(),
        artifact_id: artifact_id.to_owned(),
        artifact_generation,
        format_id: DocumentFormatV1::Docx,
        backend_id: backend_id.to_owned(),
        document_property_ids: vec!["property.wordprocessingml-package".to_owned()],
        section_ids: vec!["section-0001".to_owned()],
        ordered_nodes,
        style_catalog_sha256,
        image_refs,
        table_refs: projection.table_ids,
        page_layout_summary: projection.page_layout_summary,
        content_summary: projection.content_summary,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: content_hash,
        semantic_state_sha256,
        observed_at_unix_ms,
        freshness_expires_at_unix_ms: observed_at_unix_ms.saturating_add(60_000),
        evidence_ids: vec!["evidence.docx.bounded-reopen".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

struct DocxProjection {
    nodes: Vec<DocumentSemanticNodeV1>,
    table_ids: Vec<String>,
    page_layout_summary: String,
    content_summary: String,
}

fn parse_docx_projection(
    bytes: &[u8],
    limits: &DocumentResourceLimitsV1,
) -> Result<DocxProjection, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut paragraph_depth = 0_u32;
    let mut table_depth = 0_u32;
    let mut current_text = String::new();
    let mut current_style = None;
    let mut current_table_text = String::new();
    let mut nodes = Vec::new();
    let mut table_ids = Vec::new();
    let mut page_layout_summary = "a4:portrait:template-margins".to_owned();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("DOCX semantic parse: {error}"))?
        {
            Event::Start(start) => match local_name(start.name().as_ref()) {
                b"p" => {
                    paragraph_depth = paragraph_depth.saturating_add(1);
                    if paragraph_depth == 1 && table_depth == 0 {
                        current_text.clear();
                        current_style = None;
                    }
                }
                b"pStyle" if paragraph_depth == 1 && table_depth == 0 => {
                    current_style = attribute_value(&start, b"val")?;
                }
                b"tbl" => {
                    table_depth = table_depth.saturating_add(1);
                    if table_depth == 1 {
                        current_table_text.clear();
                    }
                }
                _ => {}
            },
            Event::Empty(start) => match local_name(start.name().as_ref()) {
                b"pStyle" if paragraph_depth == 1 && table_depth == 0 => {
                    current_style = attribute_value(&start, b"val")?;
                }
                b"pgSz" => {
                    let orientation = attribute_value(&start, b"orient")?
                        .unwrap_or_else(|| "portrait".to_owned());
                    page_layout_summary = format!("a4:{orientation}:template-margins");
                }
                _ => {}
            },
            Event::Text(text) => {
                let decoded = text
                    .decode()
                    .map_err(|error| format!("DOCX text decode: {error}"))?;
                if current_text.chars().count() + decoded.chars().count()
                    <= usize::try_from(limits.maximum_text_characters_per_node)
                        .unwrap_or(usize::MAX)
                {
                    current_text.push_str(&decoded);
                }
                if table_depth > 0 {
                    if !current_table_text.is_empty() {
                        current_table_text.push('|');
                    }
                    current_table_text.push_str(&decoded);
                }
            }
            Event::End(end) => match local_name(end.name().as_ref()) {
                b"p" => {
                    if paragraph_depth == 1 && table_depth == 0 && !current_text.is_empty() {
                        let ordinal = u32::try_from(nodes.len())
                            .map_err(|error| format!("DOCX node ordinal: {error}"))?;
                        let heading = current_style
                            .as_deref()
                            .is_some_and(|value| value.starts_with("Heading") || value == "Title");
                        nodes.push(DocumentSemanticNodeV1 {
                            node_id: format!("doc-node-{ordinal:04}"),
                            node_kind: if heading {
                                DocumentNodeKindV1::Heading
                            } else {
                                DocumentNodeKindV1::Paragraph
                            },
                            section_id: "section-0001".to_owned(),
                            ordinal,
                            style_id: current_style.clone(),
                            text_excerpt: Some(current_text.clone()),
                            text_sha256: Some(sha256_bytes(current_text.as_bytes())),
                            table_id: None,
                            image_id: None,
                            truncated: false,
                        });
                    }
                    paragraph_depth = paragraph_depth.saturating_sub(1);
                }
                b"tbl" => {
                    if table_depth == 1 {
                        let ordinal = u32::try_from(nodes.len())
                            .map_err(|error| format!("DOCX table ordinal: {error}"))?;
                        let table_id = format!("table-{:04}", table_ids.len() + 1);
                        nodes.push(DocumentSemanticNodeV1 {
                            node_id: format!("doc-node-{ordinal:04}"),
                            node_kind: DocumentNodeKindV1::Table,
                            section_id: "section-0001".to_owned(),
                            ordinal,
                            style_id: Some("TableGrid".to_owned()),
                            text_excerpt: Some(current_table_text.clone()),
                            text_sha256: Some(sha256_bytes(current_table_text.as_bytes())),
                            table_id: Some(table_id.clone()),
                            image_id: None,
                            truncated: false,
                        });
                        table_ids.push(table_id);
                    }
                    table_depth = table_depth.saturating_sub(1);
                }
                _ => {}
            },
            Event::DocType(_) | Event::GeneralRef(_) | Event::PI(_) => {
                return Err("active DOCX XML construct is forbidden".to_owned())
            }
            Event::Eof => break,
            Event::Decl(_) | Event::Comment(_) | Event::CData(_) => {}
        }
    }
    let mut content_summary = nodes
        .iter()
        .filter_map(|node| node.text_excerpt.as_deref())
        .collect::<Vec<_>>()
        .join("\n");
    let maximum = usize::try_from(limits.maximum_total_observed_characters).unwrap_or(usize::MAX);
    if content_summary.chars().count() > maximum {
        content_summary = content_summary.chars().take(maximum).collect();
    }
    if content_summary.is_empty() {
        content_summary = "empty-document".to_owned();
    }
    Ok(DocxProjection {
        nodes,
        table_ids,
        page_layout_summary,
        content_summary,
    })
}

enum DocxTransform<'a> {
    AppendParagraph {
        text: &'a str,
        style_role: DocumentStyleRoleV1,
    },
    AppendHeading {
        text: &'a str,
        level: u8,
    },
    ReplaceText {
        target_node_id: &'a str,
        expected_old_text_sha256: &'a str,
        replacement_text: &'a str,
    },
    ApplyStyle {
        target_node_id: &'a str,
        style_role: DocumentStyleRoleV1,
    },
    AppendTable {
        table_id: &'a str,
        cells: &'a [Vec<String>],
        header_rows: u32,
    },
    SetTableCell {
        table_id: &'a str,
        row: u32,
        column: u32,
        text: &'a str,
    },
    AppendImageMarker {
        image_id: &'a str,
    },
    SetPageLayout {
        layout: &'a d2i_document_capability::DocumentPageLayoutSpecV1,
    },
}

fn transform_docx(bytes: &[u8], transform: DocxTransform<'_>) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut paragraph_index = 0_usize;
    let mut paragraph_depth = 0_u32;
    let mut table_depth = 0_u32;
    let mut target_paragraph = false;
    let mut target_text_seen = false;
    let mut target_old_text = String::new();
    let mut table_index = 0_usize;
    let mut current_table = None;
    let mut current_row = 0_u32;
    let mut current_column = 0_u32;
    let mut in_target_cell = false;
    let mut changed = false;
    loop {
        let event = reader.read_event().map_err(|error| error.to_string())?;
        match event {
            Event::Start(start) if local_name(start.name().as_ref()) == b"p" => {
                paragraph_depth = paragraph_depth.saturating_add(1);
                if table_depth == 0 && paragraph_depth == 1 {
                    let node_id = format!("doc-node-{paragraph_index:04}");
                    target_paragraph = match &transform {
                        DocxTransform::ReplaceText { target_node_id, .. }
                        | DocxTransform::ApplyStyle { target_node_id, .. } => {
                            node_id == **target_node_id
                        }
                        _ => false,
                    };
                    paragraph_index = paragraph_index.saturating_add(1);
                    target_text_seen = false;
                    target_old_text.clear();
                }
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
                if target_paragraph {
                    if let DocxTransform::ApplyStyle { style_role, .. } = &transform {
                        write_docx_paragraph_properties(&mut writer, *style_role)?;
                        changed = true;
                    }
                }
            }
            Event::Start(start) if local_name(start.name().as_ref()) == b"tbl" => {
                table_depth = table_depth.saturating_add(1);
                table_index = table_index.saturating_add(1);
                current_table = Some(format!("table-{table_index:04}"));
                current_row = 0;
                current_column = 0;
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Start(start) if local_name(start.name().as_ref()) == b"tr" => {
                current_column = 0;
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Start(start) if local_name(start.name().as_ref()) == b"tc" => {
                in_target_cell = match &transform {
                    DocxTransform::SetTableCell {
                        table_id,
                        row,
                        column,
                        ..
                    } => {
                        current_table.as_deref() == Some(*table_id)
                            && current_row == *row
                            && current_column == *column
                    }
                    _ => false,
                };
                target_text_seen = false;
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Empty(start) if local_name(start.name().as_ref()) == b"pgSz" => {
                if let DocxTransform::SetPageLayout { layout } = &transform {
                    write_docx_page_size(&mut writer, layout.orientation)?;
                    changed = true;
                    continue;
                }
                writer
                    .write_event(Event::Empty(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Empty(start) if local_name(start.name().as_ref()) == b"pgMar" => {
                if let DocxTransform::SetPageLayout { layout } = &transform {
                    write_docx_margins(&mut writer, layout)?;
                    changed = true;
                    continue;
                }
                writer
                    .write_event(Event::Empty(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Text(text) if target_paragraph || in_target_cell => {
                let decoded = text.decode().map_err(|error| error.to_string())?;
                if target_paragraph {
                    target_old_text.push_str(&decoded);
                }
                if !target_text_seen {
                    let replacement = match &transform {
                        DocxTransform::ReplaceText {
                            replacement_text, ..
                        } if target_paragraph => Some(*replacement_text),
                        DocxTransform::SetTableCell { text, .. } if in_target_cell => Some(*text),
                        _ => None,
                    };
                    if let Some(replacement) = replacement {
                        writer
                            .write_event(Event::Text(BytesText::new(replacement)))
                            .map_err(|error| error.to_string())?;
                        target_text_seen = true;
                        changed = true;
                        continue;
                    }
                }
                writer
                    .write_event(Event::Text(text))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"p" => {
                if target_paragraph {
                    if let DocxTransform::ReplaceText {
                        expected_old_text_sha256,
                        ..
                    } = &transform
                    {
                        if sha256_bytes(target_old_text.as_bytes()) != **expected_old_text_sha256 {
                            return Err("DOCX target text became stale".to_owned());
                        }
                    }
                }
                if table_depth == 0 && paragraph_depth == 1 {
                    target_paragraph = false;
                }
                paragraph_depth = paragraph_depth.saturating_sub(1);
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"tc" => {
                current_column = current_column.saturating_add(1);
                in_target_cell = false;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"tr" => {
                current_row = current_row.saturating_add(1);
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"tbl" => {
                table_depth = table_depth.saturating_sub(1);
                current_table = None;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::Start(start) if local_name(start.name().as_ref()) == b"sectPr" => {
                append_docx_transform_before_section(&mut writer, &transform, &mut changed)?;
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Eof => break,
            other => writer
                .write_event(other)
                .map_err(|error| error.to_string())?,
        }
    }
    if !changed {
        return Err("DOCX semantic target was not found".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn append_docx_transform_before_section(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    transform: &DocxTransform<'_>,
    changed: &mut bool,
) -> Result<(), String> {
    match transform {
        DocxTransform::AppendParagraph { text, style_role } => {
            write_docx_paragraph(writer, text, *style_role)?;
            *changed = true;
        }
        DocxTransform::AppendHeading { text, level } => {
            write_docx_paragraph(
                writer,
                text,
                if *level == 1 {
                    DocumentStyleRoleV1::Heading1
                } else {
                    DocumentStyleRoleV1::Heading2
                },
            )?;
            *changed = true;
        }
        DocxTransform::AppendTable {
            table_id,
            cells,
            header_rows,
        } => {
            write_docx_table(writer, table_id, cells, *header_rows)?;
            *changed = true;
        }
        DocxTransform::AppendImageMarker { image_id } => {
            write_docx_paragraph(
                writer,
                &format!("[embedded image: {image_id}]"),
                DocumentStyleRoleV1::Caption,
            )?;
            *changed = true;
        }
        _ => {}
    }
    Ok(())
}

fn write_docx_paragraph(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    text: &str,
    role: DocumentStyleRoleV1,
) -> Result<(), String> {
    writer
        .write_event(Event::Start(BytesStart::new("w:p")))
        .map_err(|error| error.to_string())?;
    write_docx_paragraph_properties(writer, role)?;
    writer
        .write_event(Event::Start(BytesStart::new("w:r")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::Start(BytesStart::new("w:t")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("w:t")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("w:r")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("w:p")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_docx_paragraph_properties(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    role: DocumentStyleRoleV1,
) -> Result<(), String> {
    writer
        .write_event(Event::Start(BytesStart::new("w:pPr")))
        .map_err(|error| error.to_string())?;
    let mut style = BytesStart::new("w:pStyle");
    style.push_attribute(("w:val", docx_style_id(role)));
    writer
        .write_event(Event::Empty(style))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("w:pPr")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_docx_table(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    _table_id: &str,
    cells: &[Vec<String>],
    header_rows: u32,
) -> Result<(), String> {
    writer
        .write_event(Event::Start(BytesStart::new("w:tbl")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::Start(BytesStart::new("w:tblPr")))
        .map_err(|error| error.to_string())?;
    let mut style = BytesStart::new("w:tblStyle");
    style.push_attribute(("w:val", "TableGrid"));
    writer
        .write_event(Event::Empty(style))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("w:tblPr")))
        .map_err(|error| error.to_string())?;
    for (row_index, row) in cells.iter().enumerate() {
        writer
            .write_event(Event::Start(BytesStart::new("w:tr")))
            .map_err(|error| error.to_string())?;
        if u32::try_from(row_index).unwrap_or(u32::MAX) < header_rows {
            writer
                .write_event(Event::Start(BytesStart::new("w:trPr")))
                .map_err(|error| error.to_string())?;
            writer
                .write_event(Event::Empty(BytesStart::new("w:tblHeader")))
                .map_err(|error| error.to_string())?;
            writer
                .write_event(Event::End(BytesEnd::new("w:trPr")))
                .map_err(|error| error.to_string())?;
        }
        for text in row {
            writer
                .write_event(Event::Start(BytesStart::new("w:tc")))
                .map_err(|error| error.to_string())?;
            write_docx_paragraph(
                writer,
                text,
                if u32::try_from(row_index).unwrap_or(u32::MAX) < header_rows {
                    DocumentStyleRoleV1::TableHeader
                } else {
                    DocumentStyleRoleV1::TableBody
                },
            )?;
            writer
                .write_event(Event::End(BytesEnd::new("w:tc")))
                .map_err(|error| error.to_string())?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("w:tr")))
            .map_err(|error| error.to_string())?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("w:tbl")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_docx_page_size(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    orientation: PageOrientationV1,
) -> Result<(), String> {
    let mut size = BytesStart::new("w:pgSz");
    if orientation == PageOrientationV1::Portrait {
        size.push_attribute(("w:w", "11906"));
        size.push_attribute(("w:h", "16838"));
    } else {
        size.push_attribute(("w:w", "16838"));
        size.push_attribute(("w:h", "11906"));
        size.push_attribute(("w:orient", "landscape"));
    }
    writer
        .write_event(Event::Empty(size))
        .map_err(|error| error.to_string())
}

fn write_docx_margins(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    layout: &d2i_document_capability::DocumentPageLayoutSpecV1,
) -> Result<(), String> {
    let twips = |millimeters: u32| millimeters.saturating_mul(1440) / 25;
    let top = twips(layout.top_margin_millimeters).to_string();
    let bottom = twips(layout.bottom_margin_millimeters).to_string();
    let left = twips(layout.left_margin_millimeters).to_string();
    let right = twips(layout.right_margin_millimeters).to_string();
    let mut margins = BytesStart::new("w:pgMar");
    margins.push_attribute(("w:top", top.as_str()));
    margins.push_attribute(("w:right", right.as_str()));
    margins.push_attribute(("w:bottom", bottom.as_str()));
    margins.push_attribute(("w:left", left.as_str()));
    margins.push_attribute(("w:header", "720"));
    margins.push_attribute(("w:footer", "720"));
    margins.push_attribute(("w:gutter", "0"));
    writer
        .write_event(Event::Empty(margins))
        .map_err(|error| error.to_string())
}

fn append_docx_image_relationship(
    bytes: &[u8],
    image_id: &str,
    entry: &str,
) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut inserted = false;
    loop {
        let event = reader.read_event().map_err(|error| error.to_string())?;
        match event {
            Event::End(end) if local_name(end.name().as_ref()) == b"Relationships" => {
                let mut relationship = BytesStart::new("Relationship");
                relationship.push_attribute(("Id", image_id));
                relationship.push_attribute((
                    "Type",
                    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                ));
                let target = entry.strip_prefix("word/").unwrap_or(entry);
                relationship.push_attribute(("Target", target));
                writer
                    .write_event(Event::Empty(relationship))
                    .map_err(|error| error.to_string())?;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
                inserted = true;
            }
            Event::Eof => break,
            other => writer
                .write_event(other)
                .map_err(|error| error.to_string())?,
        }
    }
    if !inserted {
        return Err("DOCX relationship root is missing".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn minimal_docx_entries() -> BTreeMap<String, Vec<u8>> {
    [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("_rels/.rels", ROOT_RELATIONSHIPS),
        ("docProps/core.xml", CORE_PROPERTIES),
        ("word/document.xml", DOCUMENT_XML),
        ("word/styles.xml", STYLES_XML),
        ("word/_rels/document.xml.rels", DOCUMENT_RELATIONSHIPS),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.to_owned(), bytes.to_vec()))
    .collect()
}

fn docx_style_id(role: DocumentStyleRoleV1) -> &'static str {
    match role {
        DocumentStyleRoleV1::Title => "Title",
        DocumentStyleRoleV1::Heading1 => "Heading1",
        DocumentStyleRoleV1::Heading2 => "Heading2",
        DocumentStyleRoleV1::Caption => "Caption",
        DocumentStyleRoleV1::TableHeader | DocumentStyleRoleV1::Emphasis => "Strong",
        DocumentStyleRoleV1::Body | DocumentStyleRoleV1::TableBody => "Normal",
    }
}

fn local_name(name: &[u8]) -> &[u8] {
    name.rsplit(|byte| *byte == b':').next().unwrap_or(name)
}

fn attribute_value(start: &BytesStart<'_>, name: &[u8]) -> Result<Option<String>, String> {
    for attribute in start.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| error.to_string())?;
        if local_name(attribute.key.as_ref()) == name {
            return String::from_utf8(attribute.value.into_owned())
                .map(Some)
                .map_err(|error| error.to_string());
        }
    }
    Ok(None)
}

fn is_supported_image_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".png") || lower.ends_with(".jpg") || lower.ends_with(".jpeg")
}

const CONTENT_TYPES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Default Extension="jpg" ContentType="image/jpeg"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>"#;
const ROOT_RELATIONSHIPS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>"#;
const DOCUMENT_RELATIONSHIPS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>"#;
const CORE_PROPERTIES: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>D2I verified document</dc:title><dc:creator>D2I</dc:creator><cp:lastModifiedBy>D2I</cp:lastModifiedBy></cp:coreProperties>"#;
const DOCUMENT_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:pPr><w:pStyle w:val="Normal"/></w:pPr><w:r><w:t>D2I working document</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr></w:body></w:document>"#;
const STYLES_XML: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="28"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="24"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="Caption"/><w:basedOn w:val="Normal"/></w:style><w:style w:type="character" w:styleId="Strong"><w:name w:val="Strong"/><w:rPr><w:b/></w:rPr></w:style><w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="auto"/><w:left w:val="single" w:sz="4" w:color="auto"/><w:bottom w:val="single" w:sz="4" w:color="auto"/><w:right w:val="single" w:sz="4" w:color="auto"/><w:insideH w:val="single" w:sz="4" w:color="auto"/><w:insideV w:val="single" w:sz="4" w:color="auto"/></w:tblBorders></w:tblPr></w:style></w:styles>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_work::default_document_resource_limits;

    #[test]
    fn minimal_docx_is_structurally_bounded() {
        BoundedDocumentPackage::from_entries(
            DocumentFormatV1::Docx,
            minimal_docx_entries(),
            &default_document_resource_limits(),
        )
        .unwrap_or_else(|error| panic!("minimal DOCX: {error}"));
    }

    #[test]
    fn active_relationship_is_rejected_by_package_layer() {
        let mut entries = minimal_docx_entries();
        entries.insert(
            "word/_rels/document.xml.rels".to_owned(),
            br#"<Relationships><Relationship TargetMode="External" Target="https://example.test"/></Relationships>"#.to_vec(),
        );
        assert!(BoundedDocumentPackage::from_entries(
            DocumentFormatV1::Docx,
            entries,
            &default_document_resource_limits(),
        )
        .is_err());
    }
}
