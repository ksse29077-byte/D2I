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
use std::io::Cursor;
use std::path::Path;

pub fn create_hwpx_from_template(
    template: &Path,
    destination: &Path,
    limits: &DocumentResourceLimitsV1,
) -> Result<u64, String> {
    if destination.exists() {
        return Err("HWPX destination must be a new generation".to_owned());
    }
    let package = BoundedDocumentPackage::open(template, DocumentFormatV1::Hwpx, limits)?;
    package.write_atomic(destination, limits)
}

pub fn mutate_hwpx_document(
    source: &Path,
    destination: &Path,
    operation: &ResolvedDocumentOperationV1,
    limits: &DocumentResourceLimitsV1,
) -> Result<u64, String> {
    validate_resolved_operation(operation, limits)?;
    if destination.exists() {
        return Err("HWPX destination must be a new generation".to_owned());
    }
    let mut package = BoundedDocumentPackage::open(source, DocumentFormatV1::Hwpx, limits)?;
    let section = package.entry("Contents/section0.xml")?.to_vec();
    let updated = match operation {
        ResolvedDocumentOperationV1::AppendParagraph { text, style_role } => transform_hwpx(
            &section,
            HwpxTransform::AppendParagraph {
                text,
                style_role: *style_role,
            },
        )?,
        ResolvedDocumentOperationV1::InsertHeading { text, level } => transform_hwpx(
            &section,
            HwpxTransform::AppendHeading {
                text,
                level: *level,
            },
        )?,
        ResolvedDocumentOperationV1::ReplaceText {
            target_node_id,
            expected_old_text_sha256,
            replacement_text,
            maximum_replacements: _,
        } => transform_hwpx(
            &section,
            HwpxTransform::ReplaceText {
                target_node_id,
                expected_old_text_sha256,
                replacement_text,
            },
        )?,
        ResolvedDocumentOperationV1::ApplyParagraphStyle {
            target_node_id,
            style_role,
        } => transform_hwpx(
            &section,
            HwpxTransform::ApplyStyle {
                target_node_id,
                style_role: *style_role,
            },
        )?,
        ResolvedDocumentOperationV1::InsertTable {
            table_id,
            cells,
            header_rows,
        } => transform_hwpx(
            &section,
            HwpxTransform::AppendTable {
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
        } => transform_hwpx(
            &section,
            HwpxTransform::SetTableCell {
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
            let entry = format!("BinData/{image_id}.{extension}");
            package.insert_entry(&entry, bytes.clone())?;
            let content = package.entry("Contents/content.hpf")?.to_vec();
            package.replace_entry(
                "Contents/content.hpf",
                append_hwpx_manifest_item(&content, image_id, &entry, media_type)?,
            )?;
            transform_hwpx(&section, HwpxTransform::AppendImageMarker { image_id })?
        }
        ResolvedDocumentOperationV1::SetPageLayout { layout } => {
            transform_hwpx(&section, HwpxTransform::SetPageLayout { layout })?
        }
    };
    package.replace_entry("Contents/section0.xml", updated)?;
    package.write_atomic(destination, limits)
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_hwpx_document(
    path: &Path,
    document_id: &str,
    artifact_id: &str,
    artifact_generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &DocumentResourceLimitsV1,
) -> Result<DocumentSemanticSnapshotV1, String> {
    let package = BoundedDocumentPackage::open(path, DocumentFormatV1::Hwpx, limits)?;
    let section = package.entry("Contents/section0.xml")?;
    let content_hash = sha256_bytes(
        &std::fs::read(path).map_err(|error| format!("HWPX content hash read: {error}"))?,
    );
    let projection = parse_hwpx_projection(section, limits)?;
    let image_refs = package
        .entry_names()
        .filter(|name| name.starts_with("BinData/") && is_supported_image_name(name))
        .enumerate()
        .map(|(index, _)| format!("image-{:04}", projection.image_ids.len() + index + 1))
        .collect::<Vec<_>>();
    let mut ordered_nodes = projection.nodes;
    for (index, image_ref) in image_refs.iter().enumerate() {
        ordered_nodes.push(DocumentSemanticNodeV1 {
            node_id: image_ref.clone(),
            node_kind: DocumentNodeKindV1::Image,
            section_id: "section-0001".to_owned(),
            ordinal: u32::try_from(ordered_nodes.len())
                .map_err(|error| format!("HWPX image ordinal: {error}"))?,
            style_id: None,
            text_excerpt: Some(format!("embedded-image-{index}")),
            text_sha256: Some(sha256_bytes(format!("embedded-image-{index}").as_bytes())),
            table_id: None,
            image_id: Some(image_ref.clone()),
            truncated: false,
        });
    }
    let style_catalog_sha256 = sha256_bytes(package.entry("Contents/header.xml")?);
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
        format_id: DocumentFormatV1::Hwpx,
        backend_id: backend_id.to_owned(),
        document_property_ids: vec!["property.hwpml-package".to_owned()],
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
        evidence_ids: vec!["evidence.hwpx.bounded-reopen".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

struct HwpxProjection {
    nodes: Vec<DocumentSemanticNodeV1>,
    table_ids: Vec<String>,
    image_ids: Vec<String>,
    page_layout_summary: String,
    content_summary: String,
}

fn parse_hwpx_projection(
    bytes: &[u8],
    limits: &DocumentResourceLimitsV1,
) -> Result<HwpxProjection, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut paragraph_depth = 0_u32;
    let mut table_depth = 0_u32;
    let mut current_text = String::new();
    let mut current_style = None;
    let mut current_table_text = String::new();
    let mut nodes = Vec::new();
    let mut table_ids = Vec::new();
    let mut image_ids = Vec::new();
    let mut page_layout_summary = "a4:portrait:unknown-margins".to_owned();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("HWPX semantic parse: {error}"))?
        {
            Event::Start(start) => match local_name(start.name().as_ref()) {
                b"p" => {
                    paragraph_depth = paragraph_depth.saturating_add(1);
                    if paragraph_depth == 1 && table_depth == 0 {
                        current_text.clear();
                        current_style = attribute_value(&start, b"styleIDRef")?;
                    }
                }
                b"tbl" => {
                    table_depth = table_depth.saturating_add(1);
                    if table_depth == 1 {
                        current_table_text.clear();
                    }
                }
                b"pic" => {
                    image_ids.push(format!("image-{:04}", image_ids.len() + 1));
                }
                b"pagePr" => {
                    let landscape = attribute_value(&start, b"landscape")?
                        .unwrap_or_else(|| "WIDELY".to_owned());
                    page_layout_summary = if landscape == "WIDELY" {
                        "a4:portrait:template-margins".to_owned()
                    } else {
                        "a4:landscape:template-margins".to_owned()
                    };
                }
                _ => {}
            },
            Event::Empty(start) => {
                if local_name(start.name().as_ref()) == b"pic" {
                    image_ids.push(format!("image-{:04}", image_ids.len() + 1));
                }
            }
            Event::Text(text) => {
                let decoded = text
                    .decode()
                    .map_err(|error| format!("HWPX text decode: {error}"))?;
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
                            .map_err(|error| format!("HWPX node ordinal: {error}"))?;
                        let style_id = current_style.clone();
                        let heading = style_id
                            .as_deref()
                            .and_then(|value| value.parse::<u32>().ok())
                            .is_some_and(|value| (2..=8).contains(&value) || value == 14);
                        nodes.push(DocumentSemanticNodeV1 {
                            node_id: format!("doc-node-{ordinal:04}"),
                            node_kind: if heading {
                                DocumentNodeKindV1::Heading
                            } else {
                                DocumentNodeKindV1::Paragraph
                            },
                            section_id: "section-0001".to_owned(),
                            ordinal,
                            style_id,
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
                            .map_err(|error| format!("HWPX table ordinal: {error}"))?;
                        let table_id = format!("table-{:04}", table_ids.len() + 1);
                        nodes.push(DocumentSemanticNodeV1 {
                            node_id: format!("doc-node-{ordinal:04}"),
                            node_kind: DocumentNodeKindV1::Table,
                            section_id: "section-0001".to_owned(),
                            ordinal,
                            style_id: Some("table_body".to_owned()),
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
                return Err("active HWPX XML construct is forbidden".to_owned())
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
    Ok(HwpxProjection {
        nodes,
        table_ids,
        image_ids,
        page_layout_summary,
        content_summary,
    })
}

enum HwpxTransform<'a> {
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

fn transform_hwpx(bytes: &[u8], transform: HwpxTransform<'_>) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().check_end_names = true;
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut paragraph_index = 0_usize;
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
        let event = reader
            .read_event()
            .map_err(|error| format!("HWPX transform parse: {error}"))?;
        match event {
            Event::Start(start) if local_name(start.name().as_ref()) == b"p" => {
                let node_id = format!("doc-node-{paragraph_index:04}");
                target_paragraph = match &transform {
                    HwpxTransform::ReplaceText { target_node_id, .. }
                    | HwpxTransform::ApplyStyle { target_node_id, .. } => {
                        node_id == **target_node_id
                    }
                    _ => false,
                };
                target_text_seen = false;
                target_old_text.clear();
                paragraph_index = paragraph_index.saturating_add(1);
                if target_paragraph {
                    if let HwpxTransform::ApplyStyle { style_role, .. } = &transform {
                        let mut replacement = BytesStart::new("hp:p");
                        for attribute in start.attributes().with_checks(true) {
                            let attribute = attribute.map_err(|error| error.to_string())?;
                            if local_name(attribute.key.as_ref()) != b"styleIDRef"
                                && local_name(attribute.key.as_ref()) != b"paraPrIDRef"
                            {
                                replacement.push_attribute(attribute);
                            }
                        }
                        let (style, para) = hwpx_style_ids(*style_role);
                        replacement.push_attribute(("styleIDRef", style));
                        replacement.push_attribute(("paraPrIDRef", para));
                        writer
                            .write_event(Event::Start(replacement))
                            .map_err(|error| error.to_string())?;
                        changed = true;
                        continue;
                    }
                }
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Start(start) if local_name(start.name().as_ref()) == b"tbl" => {
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
                    HwpxTransform::SetTableCell {
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
            Event::Start(start) if local_name(start.name().as_ref()) == b"pagePr" => {
                if let HwpxTransform::SetPageLayout { layout } = &transform {
                    let mut replacement = BytesStart::new("hp:pagePr");
                    let landscape = match layout.orientation {
                        PageOrientationV1::Portrait => "WIDELY",
                        PageOrientationV1::Landscape => "NARROWLY",
                    };
                    let (width, height) = if layout.orientation == PageOrientationV1::Portrait {
                        ("59528", "84188")
                    } else {
                        ("84188", "59528")
                    };
                    replacement.push_attribute(("landscape", landscape));
                    replacement.push_attribute(("width", width));
                    replacement.push_attribute(("height", height));
                    replacement.push_attribute(("gutterType", "LEFT_ONLY"));
                    writer
                        .write_event(Event::Start(replacement))
                        .map_err(|error| error.to_string())?;
                    changed = true;
                    continue;
                }
                writer
                    .write_event(Event::Start(start))
                    .map_err(|error| error.to_string())?;
            }
            Event::Empty(start) if local_name(start.name().as_ref()) == b"margin" => {
                if let HwpxTransform::SetPageLayout { layout } = &transform {
                    let mut replacement = BytesStart::new("hp:margin");
                    let hwp = |millimeters: u32| millimeters.saturating_mul(283).to_string();
                    let left = hwp(layout.left_margin_millimeters);
                    let right = hwp(layout.right_margin_millimeters);
                    let top = hwp(layout.top_margin_millimeters);
                    let bottom = hwp(layout.bottom_margin_millimeters);
                    replacement.push_attribute(("header", "4252"));
                    replacement.push_attribute(("footer", "4252"));
                    replacement.push_attribute(("gutter", "0"));
                    replacement.push_attribute(("left", left.as_str()));
                    replacement.push_attribute(("right", right.as_str()));
                    replacement.push_attribute(("top", top.as_str()));
                    replacement.push_attribute(("bottom", bottom.as_str()));
                    writer
                        .write_event(Event::Empty(replacement))
                        .map_err(|error| error.to_string())?;
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
                        HwpxTransform::ReplaceText {
                            replacement_text, ..
                        } if target_paragraph => Some(*replacement_text),
                        HwpxTransform::SetTableCell { text, .. } if in_target_cell => Some(*text),
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
                current_table = None;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"p" => {
                if target_paragraph {
                    if let HwpxTransform::ReplaceText {
                        expected_old_text_sha256,
                        ..
                    } = &transform
                    {
                        if sha256_bytes(target_old_text.as_bytes()) != **expected_old_text_sha256 {
                            return Err("HWPX target text became stale".to_owned());
                        }
                    }
                }
                target_paragraph = false;
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::End(end) if local_name(end.name().as_ref()) == b"sec" => {
                match &transform {
                    HwpxTransform::AppendParagraph { text, style_role } => {
                        write_hwpx_paragraph(&mut writer, text, *style_role)?;
                        changed = true;
                    }
                    HwpxTransform::AppendHeading { text, level } => {
                        write_hwpx_paragraph(
                            &mut writer,
                            text,
                            if *level == 1 {
                                DocumentStyleRoleV1::Heading1
                            } else {
                                DocumentStyleRoleV1::Heading2
                            },
                        )?;
                        changed = true;
                    }
                    HwpxTransform::AppendTable {
                        table_id,
                        cells,
                        header_rows,
                    } => {
                        write_hwpx_table(&mut writer, table_id, cells, *header_rows)?;
                        changed = true;
                    }
                    HwpxTransform::AppendImageMarker { image_id } => {
                        write_hwpx_paragraph(
                            &mut writer,
                            &format!("[embedded image: {image_id}]"),
                            DocumentStyleRoleV1::Caption,
                        )?;
                        changed = true;
                    }
                    _ => {}
                }
                writer
                    .write_event(Event::End(end))
                    .map_err(|error| error.to_string())?;
            }
            Event::Eof => break,
            other => writer
                .write_event(other)
                .map_err(|error| error.to_string())?,
        }
    }
    if !changed {
        return Err("HWPX semantic target was not found".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn write_hwpx_paragraph(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    text: &str,
    role: DocumentStyleRoleV1,
) -> Result<(), String> {
    let (style, para) = hwpx_style_ids(role);
    let mut paragraph = BytesStart::new("hp:p");
    let id = format!("{}", deterministic_numeric_id(text));
    paragraph.push_attribute(("id", id.as_str()));
    paragraph.push_attribute(("paraPrIDRef", para));
    paragraph.push_attribute(("styleIDRef", style));
    paragraph.push_attribute(("pageBreak", "0"));
    paragraph.push_attribute(("columnBreak", "0"));
    paragraph.push_attribute(("merged", "0"));
    writer
        .write_event(Event::Start(paragraph))
        .map_err(|error| error.to_string())?;
    let mut run = BytesStart::new("hp:run");
    run.push_attribute(("charPrIDRef", "0"));
    writer
        .write_event(Event::Start(run))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::Start(BytesStart::new("hp:t")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::Text(BytesText::new(text)))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("hp:t")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("hp:run")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("hp:p")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_hwpx_table(
    writer: &mut Writer<Cursor<Vec<u8>>>,
    table_id: &str,
    cells: &[Vec<String>],
    header_rows: u32,
) -> Result<(), String> {
    let rows = cells.len();
    let columns = cells.first().map(Vec::len).unwrap_or_default();
    let mut paragraph = BytesStart::new("hp:p");
    paragraph.push_attribute((
        "id",
        deterministic_numeric_id(table_id).to_string().as_str(),
    ));
    paragraph.push_attribute(("paraPrIDRef", "3"));
    paragraph.push_attribute(("styleIDRef", "0"));
    paragraph.push_attribute(("pageBreak", "0"));
    paragraph.push_attribute(("columnBreak", "0"));
    paragraph.push_attribute(("merged", "0"));
    writer
        .write_event(Event::Start(paragraph))
        .map_err(|error| error.to_string())?;
    let mut run = BytesStart::new("hp:run");
    run.push_attribute(("charPrIDRef", "0"));
    writer
        .write_event(Event::Start(run))
        .map_err(|error| error.to_string())?;
    let mut table = BytesStart::new("hp:tbl");
    let numeric_id = deterministic_numeric_id(table_id).to_string();
    let row_count = rows.to_string();
    let column_count = columns.to_string();
    table.push_attribute(("id", numeric_id.as_str()));
    table.push_attribute(("zOrder", "0"));
    table.push_attribute(("numberingType", "TABLE"));
    table.push_attribute(("textWrap", "TOP_AND_BOTTOM"));
    table.push_attribute(("textFlow", "BOTH_SIDES"));
    table.push_attribute(("lock", "0"));
    table.push_attribute(("dropcapstyle", "None"));
    table.push_attribute(("pageBreak", "CELL"));
    table.push_attribute(("repeatHeader", if header_rows > 0 { "1" } else { "0" }));
    table.push_attribute(("rowCnt", row_count.as_str()));
    table.push_attribute(("colCnt", column_count.as_str()));
    table.push_attribute(("cellSpacing", "0"));
    table.push_attribute(("borderFillIDRef", "3"));
    table.push_attribute(("noAdjust", "0"));
    writer
        .write_event(Event::Start(table))
        .map_err(|error| error.to_string())?;
    let total_width = 42_000_u32;
    let column_width = total_width / u32::try_from(columns).unwrap_or(1).max(1);
    for (row_index, row) in cells.iter().enumerate() {
        writer
            .write_event(Event::Start(BytesStart::new("hp:tr")))
            .map_err(|error| error.to_string())?;
        for (column_index, text) in row.iter().enumerate() {
            let mut cell = BytesStart::new("hp:tc");
            cell.push_attribute(("name", ""));
            cell.push_attribute((
                "header",
                if u32::try_from(row_index).unwrap_or(u32::MAX) < header_rows {
                    "1"
                } else {
                    "0"
                },
            ));
            cell.push_attribute(("hasMargin", "0"));
            cell.push_attribute(("protect", "0"));
            cell.push_attribute(("editable", "0"));
            cell.push_attribute(("dirty", "0"));
            cell.push_attribute(("borderFillIDRef", "3"));
            writer
                .write_event(Event::Start(cell))
                .map_err(|error| error.to_string())?;
            let mut sublist = BytesStart::new("hp:subList");
            sublist.push_attribute(("id", ""));
            sublist.push_attribute(("textDirection", "HORIZONTAL"));
            sublist.push_attribute(("lineWrap", "BREAK"));
            sublist.push_attribute(("vertAlign", "CENTER"));
            sublist.push_attribute(("linkListIDRef", "0"));
            sublist.push_attribute(("linkListNextIDRef", "0"));
            sublist.push_attribute(("textWidth", "0"));
            sublist.push_attribute(("textHeight", "0"));
            sublist.push_attribute(("hasTextRef", "0"));
            sublist.push_attribute(("hasNumRef", "0"));
            writer
                .write_event(Event::Start(sublist))
                .map_err(|error| error.to_string())?;
            write_hwpx_paragraph(
                writer,
                text,
                if u32::try_from(row_index).unwrap_or(u32::MAX) < header_rows {
                    DocumentStyleRoleV1::TableHeader
                } else {
                    DocumentStyleRoleV1::TableBody
                },
            )?;
            writer
                .write_event(Event::End(BytesEnd::new("hp:subList")))
                .map_err(|error| error.to_string())?;
            let mut address = BytesStart::new("hp:cellAddr");
            let column = column_index.to_string();
            let row_number = row_index.to_string();
            address.push_attribute(("colAddr", column.as_str()));
            address.push_attribute(("rowAddr", row_number.as_str()));
            writer
                .write_event(Event::Empty(address))
                .map_err(|error| error.to_string())?;
            let mut span = BytesStart::new("hp:cellSpan");
            span.push_attribute(("colSpan", "1"));
            span.push_attribute(("rowSpan", "1"));
            writer
                .write_event(Event::Empty(span))
                .map_err(|error| error.to_string())?;
            let mut size = BytesStart::new("hp:cellSz");
            let width = column_width.to_string();
            size.push_attribute(("width", width.as_str()));
            size.push_attribute(("height", "2886"));
            writer
                .write_event(Event::Empty(size))
                .map_err(|error| error.to_string())?;
            let mut margin = BytesStart::new("hp:cellMargin");
            margin.push_attribute(("left", "510"));
            margin.push_attribute(("right", "510"));
            margin.push_attribute(("top", "141"));
            margin.push_attribute(("bottom", "141"));
            writer
                .write_event(Event::Empty(margin))
                .map_err(|error| error.to_string())?;
            writer
                .write_event(Event::End(BytesEnd::new("hp:tc")))
                .map_err(|error| error.to_string())?;
        }
        writer
            .write_event(Event::End(BytesEnd::new("hp:tr")))
            .map_err(|error| error.to_string())?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("hp:tbl")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("hp:run")))
        .map_err(|error| error.to_string())?;
    writer
        .write_event(Event::End(BytesEnd::new("hp:p")))
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn append_hwpx_manifest_item(
    bytes: &[u8],
    image_id: &str,
    entry: &str,
    media_type: &str,
) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut inserted = false;
    loop {
        let event = reader.read_event().map_err(|error| error.to_string())?;
        match event {
            Event::End(end) if local_name(end.name().as_ref()) == b"manifest" => {
                let mut item = BytesStart::new("opf:item");
                item.push_attribute(("id", image_id));
                item.push_attribute(("href", entry));
                item.push_attribute(("media-type", media_type));
                writer
                    .write_event(Event::Empty(item))
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
        return Err("HWPX content manifest is missing".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn hwpx_style_ids(role: DocumentStyleRoleV1) -> (&'static str, &'static str) {
    match role {
        DocumentStyleRoleV1::Title | DocumentStyleRoleV1::Heading1 => ("2", "10"),
        DocumentStyleRoleV1::Heading2 => ("3", "9"),
        DocumentStyleRoleV1::Caption => ("1", "11"),
        DocumentStyleRoleV1::Body
        | DocumentStyleRoleV1::TableHeader
        | DocumentStyleRoleV1::TableBody
        | DocumentStyleRoleV1::Emphasis => ("0", "3"),
    }
}

fn deterministic_numeric_id(value: &str) -> u32 {
    let hash = sha256_bytes(value.as_bytes());
    u32::from_str_radix(&hash[7..15], 16).unwrap_or(1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document_work::default_document_resource_limits;

    #[test]
    fn deterministic_id_is_stable() {
        assert_eq!(
            deterministic_numeric_id("table.fixture"),
            deterministic_numeric_id("table.fixture")
        );
    }

    #[test]
    fn projection_rejects_active_xml() {
        assert!(parse_hwpx_projection(
            b"<!DOCTYPE x><hs:sec xmlns:hs='x'/>",
            &default_document_resource_limits()
        )
        .is_err());
    }
}
