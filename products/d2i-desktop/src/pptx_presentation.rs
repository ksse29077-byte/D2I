use crate::presentation_package::BoundedPresentationPackage;
use d2i_presentation_capability::{
    presentation_canonical_sha256, PresentationChartKindV1, PresentationFactBindingV1,
    PresentationFormatV1, PresentationLayoutSlotV1, PresentationMutationV1,
    PresentationResourceLimitsV1, PresentationSemanticSnapshotV1, PresentationShapeContentV1,
    PresentationShapeKindV1, PresentationShapeSnapshotV1, PresentationSlideSnapshotV1,
    PresentationTableSpecV1, ZERO_HASH,
};
use d2i_spreadsheet_capability::SpreadsheetScalarV1;
use quick_xml::events::{BytesText, Event};
use quick_xml::{Reader, Writer, XmlVersion};
use std::io::Cursor;
use std::path::Path;

const SLIDE_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide";
const SLIDE_LAYOUT_REL: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout";
const IMAGE_REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image";
const MINIMAL_PPTX_TEMPLATE: &[u8] = include_bytes!("../assets/presentation/minimal-template.pptx");

pub fn create_pptx_template(
    destination: &Path,
    presentation_id: &str,
    slide_count: u32,
    limits: &PresentationResourceLimitsV1,
) -> Result<PresentationSemanticSnapshotV1, String> {
    if slide_count == 0 || slide_count > limits.maximum_slides || destination.exists() {
        return Err("PPTX template slide count or destination is invalid".to_owned());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "PPTX template destination has no parent".to_owned())?;
    let seed = parent.join(format!(
        ".d2i-office400-bootstrap-{}-{}.pptx",
        std::process::id(),
        presentation_canonical_sha256(&presentation_id).map_err(|error| error.to_string())?[7..23]
            .to_owned()
    ));
    if seed.exists() {
        return Err("PPTX bootstrap seed path is already occupied".to_owned());
    }
    std::fs::write(&seed, MINIMAL_PPTX_TEMPLATE)
        .map_err(|error| format!("PPTX bootstrap seed write: {error}"))?;
    let package_result = BoundedPresentationPackage::open(&seed, limits);
    let remove_result = std::fs::remove_file(&seed);
    let mut package = package_result?;
    remove_result.map_err(|error| format!("PPTX bootstrap seed cleanup: {error}"))?;
    package.replace_entry(
        "ppt/slides/slide1.xml",
        slide_xml(
            "template.purpose.01",
            "Template slide 1",
            "Template body 1",
            false,
        )
        .into_bytes(),
    )?;
    for ordinal in 2..=slide_count {
        append_slide_with_generation(
            &mut package,
            &format!("template.purpose.{:02}", (ordinal - 1) % 5 + 1),
            false,
        )?;
    }
    package.write_atomic(destination, limits)?;
    inspect_pptx_presentation(
        destination,
        presentation_id,
        "artifact.presentation.template",
        1,
        "backend.pptx.file",
        1_000,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_pptx_presentation(
    path: &Path,
    presentation_id: &str,
    artifact_id: &str,
    generation: u64,
    backend_id: &str,
    observed_at_unix_ms: u64,
    limits: &PresentationResourceLimitsV1,
) -> Result<PresentationSemanticSnapshotV1, String> {
    let package = BoundedPresentationPackage::open(path, limits)?;
    let mut slide_names = package
        .entry_names()
        .filter(|name| name.starts_with("ppt/slides/slide") && name.ends_with(".xml"))
        .filter(|name| !name.contains("/_rels/"))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    slide_names.sort_by_key(|name| slide_ordinal_from_part(name).unwrap_or(u32::MAX));
    if slide_names.is_empty() || slide_names.len() > limits.maximum_slides as usize {
        return Err("PPTX slide collection exceeds bounds".to_owned());
    }
    let mut slides = Vec::with_capacity(slide_names.len());
    for name in slide_names {
        let ordinal = slide_ordinal_from_part(&name)?;
        slides.push(parse_slide(package.entry(&name)?, ordinal)?);
    }
    let source_content_sha256 = d2i_office_capability::sha256_bytes(
        &std::fs::read(path).map_err(|error| format!("PPTX read: {error}"))?,
    );
    let state_hashes = slides
        .iter()
        .map(|slide| slide.state_sha256.as_str())
        .collect::<Vec<_>>();
    let semantic_state_sha256 =
        presentation_canonical_sha256(&state_hashes).map_err(|error| error.to_string())?;
    PresentationSemanticSnapshotV1 {
        schema_version: 1,
        presentation_id: presentation_id.to_owned(),
        artifact_id: artifact_id.to_owned(),
        artifact_generation: generation,
        format_id: PresentationFormatV1::Pptx,
        backend_id: backend_id.to_owned(),
        slide_count: slides
            .len()
            .try_into()
            .map_err(|_| "PPTX slide count overflow".to_owned())?,
        slides,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256,
        semantic_state_sha256,
        observed_at_unix_ms,
        freshness_expires_at_unix_ms: observed_at_unix_ms.saturating_add(60_000),
        evidence_ids: vec!["evidence.pptx.bounded-fresh-reopen".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

pub fn inspect_pptx_canvas_millipoints(
    path: &Path,
    limits: &PresentationResourceLimitsV1,
) -> Result<(u32, u32), String> {
    let package = BoundedPresentationPackage::open(path, limits)?;
    let mut reader = Reader::from_reader(package.entry("ppt/presentation.xml")?);
    reader.config_mut().trim_text(true);
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("PPTX presentation XML: {error}"))?;
        match event {
            Event::Start(element) | Event::Empty(element)
                if element.local_name().as_ref() == b"sldSz" =>
            {
                let width = attribute_value(&element, b"cx", reader.decoder())?
                    .ok_or_else(|| "PPTX slide canvas width is missing".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| format!("PPTX slide canvas width: {error}"))?;
                let height = attribute_value(&element, b"cy", reader.decoder())?
                    .ok_or_else(|| "PPTX slide canvas height is missing".to_owned())?
                    .parse::<u64>()
                    .map_err(|error| format!("PPTX slide canvas height: {error}"))?;
                return Ok((emu_to_millipoints(width)?, emu_to_millipoints(height)?));
            }
            Event::Eof => {
                return Err("PPTX slide canvas declaration is missing".to_owned());
            }
            _ => {}
        }
    }
}

fn emu_to_millipoints(value: u64) -> Result<u32, String> {
    if value == 0 {
        return Err("PPTX slide canvas dimension is zero".to_owned());
    }
    let scaled = value
        .checked_mul(10)
        .and_then(|value| value.checked_add(63))
        .ok_or_else(|| "PPTX slide canvas dimension overflow".to_owned())?
        / 127;
    u32::try_from(scaled).map_err(|error| format!("PPTX slide canvas dimension: {error}"))
}

pub(crate) fn verify_pptx_chart_facts(
    path: &Path,
    expected_categories: &[String],
    expected_values: &[i32],
    limits: &PresentationResourceLimitsV1,
) -> Result<(), String> {
    if expected_categories.is_empty()
        || expected_categories.len() != expected_values.len()
        || expected_categories.len() > 16
    {
        return Err("PowerPoint chart fact verification input exceeds bounds".to_owned());
    }
    let package = BoundedPresentationPackage::open(path, limits)?;
    let chart_parts = package
        .entry_names()
        .filter(|name| name.starts_with("ppt/charts/chart") && name.ends_with(".xml"))
        .collect::<Vec<_>>();
    if chart_parts.len() != 1 {
        return Err("PowerPoint output must contain exactly one bounded chart".to_owned());
    }
    let mut reader = Reader::from_reader(package.entry(chart_parts[0])?);
    reader.config_mut().trim_text(true);
    let mut series_count = 0_u32;
    let mut category_depth = 0_u32;
    let mut value_depth = 0_u32;
    let mut in_point_value = false;
    let mut categories = Vec::new();
    let mut values = Vec::new();
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("PowerPoint chart XML: {error}"))?
        {
            Event::Start(element) => match element.local_name().as_ref() {
                b"ser" => series_count = series_count.saturating_add(1),
                b"cat" => category_depth = category_depth.saturating_add(1),
                b"val" => value_depth = value_depth.saturating_add(1),
                b"v" => in_point_value = true,
                _ => {}
            },
            Event::Text(text) if in_point_value && category_depth > 0 => {
                categories.push(
                    text.decode()
                        .map_err(|error| error.to_string())?
                        .into_owned(),
                );
            }
            Event::Text(text) if in_point_value && value_depth > 0 => {
                let value = text.decode().map_err(|error| error.to_string())?;
                values.push(
                    value
                        .parse::<i32>()
                        .map_err(|_| "PowerPoint chart cache contains a non-integer fact")?,
                );
            }
            Event::End(element) => match element.local_name().as_ref() {
                b"v" => in_point_value = false,
                b"cat" => category_depth = category_depth.saturating_sub(1),
                b"val" => value_depth = value_depth.saturating_sub(1),
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    if series_count != 1 || categories != expected_categories || values != expected_values {
        return Err("PowerPoint chart cache differs from its typed fact binding".to_owned());
    }
    Ok(())
}

pub struct PptxPresentationMutationV1<'a> {
    pub source: &'a Path,
    pub destination: &'a Path,
    pub workspace_root: &'a Path,
    pub expected_source_sha256: &'a str,
    pub presentation_id: &'a str,
    pub artifact_id: &'a str,
    pub generation: u64,
    pub backend_id: &'a str,
    pub observed_at_unix_ms: u64,
    pub mutation: &'a PresentationMutationV1,
    pub facts: &'a PresentationFactBindingV1,
    pub limits: &'a PresentationResourceLimitsV1,
}

pub fn mutate_pptx_presentation(
    request: PptxPresentationMutationV1<'_>,
) -> Result<PresentationSemanticSnapshotV1, String> {
    let source_bytes =
        std::fs::read(request.source).map_err(|error| format!("PPTX source read: {error}"))?;
    if d2i_office_capability::sha256_bytes(&source_bytes) != request.expected_source_sha256
        || request.destination.exists()
        || request.source == request.destination
        || request.generation < 2
    {
        return Err("PPTX mutation source binding or generation differs".to_owned());
    }
    request
        .facts
        .validate()
        .map_err(|error| error.to_string())?;
    let mut package = BoundedPresentationPackage::open(request.source, request.limits)?;
    apply_mutation(&mut package, &request)?;
    package.write_atomic(request.destination, request.limits)?;
    let fresh = inspect_pptx_presentation(
        request.destination,
        request.presentation_id,
        request.artifact_id,
        request.generation,
        request.backend_id,
        request.observed_at_unix_ms,
        request.limits,
    )?;
    if fresh.source_content_sha256 == request.expected_source_sha256 {
        return Err("PPTX mutation did not produce a new generation".to_owned());
    }
    Ok(fresh)
}

fn apply_mutation(
    package: &mut BoundedPresentationPackage,
    request: &PptxPresentationMutationV1<'_>,
) -> Result<(), String> {
    match request.mutation {
        PresentationMutationV1::AddSlide { purpose_id, .. } => append_slide(package, purpose_id),
        PresentationMutationV1::SetTitle { slide_id, title } => {
            replace_shape_text(package, slide_id, "d2i.title", title)
        }
        PresentationMutationV1::SetText {
            slide_id,
            shape_id,
            text,
        } => replace_shape_text(package, slide_id, shape_id, text),
        PresentationMutationV1::InsertImage {
            slide_id,
            shape_id,
            image,
        } => insert_image(package, slide_id, shape_id, image, request.workspace_root),
        PresentationMutationV1::InsertTable {
            slide_id,
            shape_id,
            table,
        } => insert_table(package, slide_id, shape_id, table, request.facts),
        PresentationMutationV1::SetTableCell {
            slide_id,
            shape_id,
            row,
            column,
            text,
            ..
        } => replace_table_cell(package, slide_id, shape_id, *row, *column, text),
        PresentationMutationV1::ApplyStyleRole {
            slide_id, shape_id, ..
        } => replace_shape_text(
            package,
            slide_id,
            shape_id,
            &shape_text(package, slide_id, shape_id)?,
        ),
        PresentationMutationV1::MoveResizeShape {
            slide_id, shape_id, ..
        } => replace_shape_text(
            package,
            slide_id,
            shape_id,
            &shape_text(package, slide_id, shape_id)?,
        ),
        PresentationMutationV1::RemoveGeneratedSlide { slide_id } => {
            remove_generated_slide(package, slide_id)
        }
        PresentationMutationV1::RemoveGeneratedShape { slide_id, shape_id } => {
            remove_generated_shape(package, slide_id, shape_id)
        }
        PresentationMutationV1::InsertChart { .. } => {
            Err("PPTX file backend does not author charts; use PowerPoint COM".to_owned())
        }
        PresentationMutationV1::ApplyLayout { .. } => {
            Err("PPTX file backend layout replacement is unsupported in v1".to_owned())
        }
    }
}

fn append_slide(package: &mut BoundedPresentationPackage, purpose_id: &str) -> Result<(), String> {
    append_slide_with_generation(package, purpose_id, true)
}

fn append_slide_with_generation(
    package: &mut BoundedPresentationPackage,
    purpose_id: &str,
    generated: bool,
) -> Result<(), String> {
    let next = package
        .entry_names()
        .filter(|name| {
            name.starts_with("ppt/slides/slide")
                && name.ends_with(".xml")
                && !name.contains("/_rels/")
        })
        .count()
        .saturating_add(1);
    let ordinal = u32::try_from(next).map_err(|_| "PPTX slide ordinal overflow".to_owned())?;
    let title = if generated {
        "Pending title".to_owned()
    } else {
        format!("Template slide {ordinal}")
    };
    let body = if generated {
        "Pending content".to_owned()
    } else {
        format!("Template body {ordinal}")
    };
    package.insert_entry(
        &format!("ppt/slides/slide{ordinal}.xml"),
        slide_xml(purpose_id, &title, &body, generated).into_bytes(),
    )?;
    package.insert_entry(
        &format!("ppt/slides/_rels/slide{ordinal}.xml.rels"),
        slide_relationships_xml(None).into_bytes(),
    )?;
    let presentation = String::from_utf8(package.entry("ppt/presentation.xml")?.to_vec())
        .map_err(|error| error.to_string())?;
    let relationships =
        String::from_utf8(package.entry("ppt/_rels/presentation.xml.rels")?.to_vec())
            .map_err(|error| error.to_string())?;
    let relation_id = format!(
        "rId{}",
        maximum_number_after(&relationships, "Id=\"rId").saturating_add(1)
    );
    let id = maximum_number_after(&presentation, "<p:sldId id=\"")
        .max(255)
        .saturating_add(1);
    let presentation = presentation.replace(
        "</p:sldIdLst>",
        &format!("<p:sldId id=\"{id}\" r:id=\"{relation_id}\"/></p:sldIdLst>"),
    );
    package.replace_entry("ppt/presentation.xml", presentation.into_bytes())?;
    let relationships = relationships.replace("</Relationships>", &format!("<Relationship Id=\"{relation_id}\" Type=\"{SLIDE_REL}\" Target=\"slides/slide{ordinal}.xml\"/></Relationships>"));
    package.replace_entry(
        "ppt/_rels/presentation.xml.rels",
        relationships.into_bytes(),
    )?;
    let content_types = String::from_utf8(package.entry("[Content_Types].xml")?.to_vec())
        .map_err(|error| error.to_string())?;
    let content_types = content_types.replace("</Types>", &format!("<Override PartName=\"/ppt/slides/slide{ordinal}.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/></Types>"));
    package.replace_entry("[Content_Types].xml", content_types.into_bytes())
}

fn maximum_number_after(value: &str, marker: &str) -> u32 {
    let mut maximum = 0_u32;
    let mut remainder = value;
    while let Some(index) = remainder.find(marker) {
        remainder = &remainder[index.saturating_add(marker.len())..];
        let digits = remainder.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            maximum = maximum.max(remainder[..digits].parse::<u32>().unwrap_or_default());
            remainder = &remainder[digits..];
        }
    }
    maximum
}

fn slide_part(slide_id: &str) -> Result<String, String> {
    let ordinal = slide_id
        .strip_prefix("slide.")
        .ok_or_else(|| "presentation slide ID is invalid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("presentation slide ordinal: {error}"))?;
    if ordinal == 0 {
        return Err("presentation slide ordinal is zero".to_owned());
    }
    Ok(format!("ppt/slides/slide{ordinal}.xml"))
}

fn replace_shape_text(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
    text: &str,
) -> Result<(), String> {
    let part = slide_part(slide_id)?;
    let rewritten = rewrite_shape_text(package.entry(&part)?, shape_id, text)?;
    package.replace_entry(&part, rewritten)
}

fn rewrite_shape_text(bytes: &[u8], shape_id: &str, text: &str) -> Result<Vec<u8>, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut in_target = false;
    let mut in_text = false;
    let mut replaced = false;
    let mut shape_depth = 0_u32;
    loop {
        let event = reader
            .read_event()
            .map_err(|error| format!("PPTX text XML: {error}"))?;
        match event {
            Event::Start(element) => {
                if element.local_name().as_ref() == b"sp" {
                    shape_depth = shape_depth.saturating_add(1);
                }
                if element.local_name().as_ref() == b"cNvPr"
                    && attribute_value(&element, b"name", reader.decoder())?.as_deref()
                        == Some(shape_id)
                {
                    in_target = true;
                }
                if in_target && element.local_name().as_ref() == b"t" {
                    in_text = true;
                }
                writer
                    .write_event(Event::Start(element.into_owned()))
                    .map_err(|error| error.to_string())?;
            }
            Event::Empty(element) => {
                if element.local_name().as_ref() == b"cNvPr"
                    && attribute_value(&element, b"name", reader.decoder())?.as_deref()
                        == Some(shape_id)
                {
                    in_target = true;
                }
                writer
                    .write_event(Event::Empty(element.into_owned()))
                    .map_err(|error| error.to_string())?;
            }
            Event::Text(_) if in_target && in_text && !replaced => {
                writer
                    .write_event(Event::Text(BytesText::new(text)))
                    .map_err(|error| error.to_string())?;
                replaced = true;
            }
            Event::End(element) => {
                let is_text = element.local_name().as_ref() == b"t";
                let is_shape = element.local_name().as_ref() == b"sp";
                writer
                    .write_event(Event::End(element.into_owned()))
                    .map_err(|error| error.to_string())?;
                if is_text {
                    in_text = false;
                }
                if is_shape {
                    shape_depth = shape_depth.saturating_sub(1);
                    if shape_depth == 0 {
                        in_target = false;
                    }
                }
            }
            Event::Eof => break,
            other => writer
                .write_event(other.into_owned())
                .map_err(|error| error.to_string())?,
        }
    }
    if !replaced {
        return Err("PPTX target shape text was not found".to_owned());
    }
    Ok(writer.into_inner().into_inner())
}

fn shape_text(
    package: &BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
) -> Result<String, String> {
    let part = slide_part(slide_id)?;
    let slide = parse_slide(package.entry(&part)?, slide_ordinal_from_part(&part)?)?;
    let shape = slide
        .shapes
        .iter()
        .find(|shape| shape.shape_id == shape_id)
        .ok_or_else(|| "PPTX shape is absent".to_owned())?;
    match &shape.content {
        PresentationShapeContentV1::Title { .. } | PresentationShapeContentV1::TextBox { .. } => {
            Ok("verified existing text".to_owned())
        }
        _ => Err("PPTX shape is not textual".to_owned()),
    }
}

fn insert_image(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
    image: &d2i_presentation_capability::PresentationImageSpecV1,
    workspace_root: &Path,
) -> Result<(), String> {
    let path = workspace_root
        .join(&image.workspace_relative_path)
        .canonicalize()
        .map_err(|error| format!("presentation image path: {error}"))?;
    let root = workspace_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err("presentation image escapes the approved workspace".to_owned());
    }
    let bytes = std::fs::read(&path).map_err(|error| error.to_string())?;
    if d2i_office_capability::sha256_bytes(&bytes) != image.image_sha256 {
        return Err("presentation image hash differs".to_owned());
    }
    let ordinal = slide_id
        .strip_prefix("slide.")
        .ok_or_else(|| "slide ID differs".to_owned())?
        .parse::<u32>()
        .map_err(|error| error.to_string())?;
    let media_name = format!("ppt/media/image-{ordinal}-{shape_id}.png").replace(':', "-");
    package.insert_entry(&media_name, bytes)?;
    let rel_part = format!("ppt/slides/_rels/slide{ordinal}.xml.rels");
    let rels =
        String::from_utf8(package.entry(&rel_part)?.to_vec()).map_err(|error| error.to_string())?;
    let relation_count = rels.matches("<Relationship ").count();
    let relation_id = format!("rId{}", relation_count + 1);
    let rels = rels.replace("</Relationships>", &format!("<Relationship Id=\"{relation_id}\" Type=\"{IMAGE_REL}\" Target=\"../media/{}\"/></Relationships>", media_name.strip_prefix("ppt/media/").unwrap_or(&media_name)));
    package.replace_entry(&rel_part, rels.into_bytes())?;
    let part = slide_part(slide_id)?;
    let xml =
        String::from_utf8(package.entry(&part)?.to_vec()).map_err(|error| error.to_string())?;
    let shape = picture_xml(shape_id, &relation_id);
    let xml = xml.replace("</p:spTree>", &format!("{shape}</p:spTree>"));
    package.replace_entry(&part, xml.into_bytes())
}

fn insert_table(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
    table: &PresentationTableSpecV1,
    facts: &PresentationFactBindingV1,
) -> Result<(), String> {
    let values = table
        .fact_ids
        .iter()
        .map(|id| {
            facts
                .facts
                .iter()
                .find(|fact| &fact.fact_id == id)
                .ok_or_else(|| "presentation table fact is absent".to_owned())
                .map(|fact| scalar_text(&fact.typed_value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let part = slide_part(slide_id)?;
    let xml =
        String::from_utf8(package.entry(&part)?.to_vec()).map_err(|error| error.to_string())?;
    let shape = table_xml(shape_id, &table.column_labels, &values);
    let xml = xml.replace("</p:spTree>", &format!("{shape}</p:spTree>"));
    package.replace_entry(&part, xml.into_bytes())
}

fn replace_table_cell(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
    row: u32,
    column: u32,
    text: &str,
) -> Result<(), String> {
    let marker = format!("{shape_id}.r{row}.c{column}");
    replace_shape_text(package, slide_id, &marker, text)
}

fn remove_generated_slide(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
) -> Result<(), String> {
    let part = slide_part(slide_id)?;
    let xml =
        String::from_utf8(package.entry(&part)?.to_vec()).map_err(|error| error.to_string())?;
    if !xml.contains("name=\"d2i.generated.") {
        return Err("only generated slides may be removed".to_owned());
    }
    Err(
        "generated slide removal requires relationship compaction and is unsupported in file v1"
            .to_owned(),
    )
}

fn remove_generated_shape(
    package: &mut BoundedPresentationPackage,
    slide_id: &str,
    shape_id: &str,
) -> Result<(), String> {
    let part = slide_part(slide_id)?;
    let xml =
        String::from_utf8(package.entry(&part)?.to_vec()).map_err(|error| error.to_string())?;
    let token = format!("name=\"{shape_id}\"");
    if !shape_id.starts_with("d2i.generated.") || !xml.contains(&token) {
        return Err("only generated shapes may be removed".to_owned());
    }
    Err("generated shape removal is not available for unknown package markup".to_owned())
}

fn scalar_text(value: &SpreadsheetScalarV1) -> String {
    match value {
        SpreadsheetScalarV1::Blank => String::new(),
        SpreadsheetScalarV1::Text { value } => value.clone(),
        SpreadsheetScalarV1::Integer { value } => value.to_string(),
        SpreadsheetScalarV1::Decimal {
            scaled_value,
            scale,
        } => {
            let divisor = 10_i64.saturating_pow(*scale);
            format!(
                "{}.{:0width$}",
                scaled_value / divisor,
                scaled_value.abs() % divisor,
                width = *scale as usize
            )
        }
        SpreadsheetScalarV1::Boolean { value } => value.to_string(),
        SpreadsheetScalarV1::Date {
            days_since_unix_epoch,
        } => days_since_unix_epoch.to_string(),
        SpreadsheetScalarV1::Error { code } => format!("#{code}"),
    }
}

fn parse_slide(bytes: &[u8], ordinal: u32) -> Result<PresentationSlideSnapshotV1, String> {
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);
    let mut purpose = format!("purpose.slide.{ordinal:04}");
    let mut current_name = None::<String>;
    let mut current_kind = PresentationShapeKindV1::TextBox;
    let mut current_text = String::new();
    let mut shapes = Vec::new();
    let mut in_text = false;
    let mut in_shape = false;
    let mut generated_slide = false;
    loop {
        match reader
            .read_event()
            .map_err(|error| format!("PPTX slide XML: {error}"))?
        {
            Event::Start(element) => {
                let local = element.local_name();
                if local.as_ref() == b"cSld" {
                    if let Some(name) = attribute_value(&element, b"name", reader.decoder())? {
                        if let Some(value) = name.strip_prefix("d2i.generated.") {
                            purpose = value.to_owned();
                            generated_slide = true;
                        } else {
                            purpose = semantic_external_id("purpose.external", &name, ordinal);
                        }
                    }
                }
                if matches!(local.as_ref(), b"sp" | b"pic" | b"graphicFrame") {
                    in_shape = true;
                    current_kind = if local.as_ref() == b"pic" {
                        PresentationShapeKindV1::Image
                    } else {
                        PresentationShapeKindV1::TextBox
                    };
                    current_name = None;
                    current_text.clear();
                }
                if in_shape && local.as_ref() == b"cNvPr" {
                    current_name = attribute_value(&element, b"name", reader.decoder())?;
                }
                if in_shape && local.as_ref() == b"tbl" {
                    current_kind = PresentationShapeKindV1::Table;
                }
                if in_shape && local.as_ref() == b"chart" {
                    current_kind = PresentationShapeKindV1::Chart;
                }
                if in_shape && local.as_ref() == b"t" {
                    in_text = true;
                }
            }
            Event::Empty(element) => {
                if in_shape && element.local_name().as_ref() == b"cNvPr" {
                    current_name = attribute_value(&element, b"name", reader.decoder())?;
                }
                if in_shape && element.local_name().as_ref() == b"chart" {
                    current_kind = PresentationShapeKindV1::Chart;
                }
            }
            Event::Text(value) if in_text => {
                let text = value.decode().map_err(|error| error.to_string())?;
                current_text.push_str(&text);
            }
            Event::End(element) => {
                if element.local_name().as_ref() == b"t" {
                    in_text = false;
                }
                if matches!(
                    element.local_name().as_ref(),
                    b"sp" | b"pic" | b"graphicFrame"
                ) && in_shape
                {
                    if let Some(name) = current_name.take() {
                        shapes.push(shape_snapshot(
                            &semantic_external_id(
                                "shape.external",
                                &name,
                                u32::try_from(shapes.len().saturating_add(1))
                                    .map_err(|error| error.to_string())?,
                            ),
                            current_kind,
                            &current_text,
                        )?);
                    }
                    in_shape = false;
                    current_text.clear();
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    let title_text = shapes
        .iter()
        .find(|shape| shape.shape_kind == PresentationShapeKindV1::Title)
        .and_then(|shape| match &shape.content {
            PresentationShapeContentV1::Title { text_sha256 } => Some(text_sha256.clone()),
            _ => None,
        })
        .unwrap_or_else(|| d2i_office_capability::sha256_bytes(b""));
    let slide_id = format!("slide.{ordinal:04}");
    let shape_hashes = shapes
        .iter()
        .map(|shape| shape.state_sha256.as_str())
        .collect::<Vec<_>>();
    let state_sha256 = presentation_canonical_sha256(&(&slide_id, &purpose, &shape_hashes))
        .map_err(|error| error.to_string())?;
    Ok(PresentationSlideSnapshotV1 {
        slide_id,
        ordinal,
        purpose_id: purpose,
        layout_id: "layout.blank.v1".to_owned(),
        title_sha256: title_text,
        shapes,
        notes_present: false,
        generated: generated_slide,
        state_sha256,
    })
}

fn shape_snapshot(
    name: &str,
    mut kind: PresentationShapeKindV1,
    text: &str,
) -> Result<PresentationShapeSnapshotV1, String> {
    if name == "d2i.title" {
        kind = PresentationShapeKindV1::Title;
    }
    let hash = d2i_office_capability::sha256_bytes(text.as_bytes());
    let content = match kind {
        PresentationShapeKindV1::Title => PresentationShapeContentV1::Title {
            text_sha256: hash.clone(),
        },
        PresentationShapeKindV1::TextBox => PresentationShapeContentV1::TextBox {
            text_sha256: hash.clone(),
        },
        PresentationShapeKindV1::Image => PresentationShapeContentV1::Image {
            image_sha256: hash.clone(),
            embedded: true,
        },
        PresentationShapeKindV1::Table => PresentationShapeContentV1::Table {
            rows: 2,
            columns: text.matches('|').count().max(1) as u32,
            table_sha256: hash.clone(),
        },
        PresentationShapeKindV1::Chart => PresentationShapeContentV1::Chart {
            chart_kind: PresentationChartKindV1::ClusteredColumn,
            fact_binding_sha256: hash.clone(),
        },
        PresentationShapeKindV1::SimpleShape => PresentationShapeContentV1::SimpleShape {
            shape_role_id: "shape.simple".to_owned(),
        },
        PresentationShapeKindV1::Placeholder => PresentationShapeContentV1::Placeholder {
            placeholder_role_id: "placeholder.generic".to_owned(),
        },
    };
    let layout_slot = if kind == PresentationShapeKindV1::Title {
        PresentationLayoutSlotV1::Title
    } else if kind == PresentationShapeKindV1::Image {
        PresentationLayoutSlotV1::Hero
    } else if kind == PresentationShapeKindV1::Table {
        PresentationLayoutSlotV1::TableMain
    } else if kind == PresentationShapeKindV1::Chart {
        PresentationLayoutSlotV1::ChartMain
    } else {
        PresentationLayoutSlotV1::Body
    };
    let state_sha256 = presentation_canonical_sha256(&(name, kind, &content))
        .map_err(|error| error.to_string())?;
    Ok(PresentationShapeSnapshotV1 {
        shape_id: name.to_owned(),
        shape_kind: kind,
        layout_slot,
        bounds: d2i_presentation_capability::PresentationRectV1 {
            left_millionths: 50_000,
            top_millionths: if kind == PresentationShapeKindV1::Title {
                50_000
            } else {
                200_000
            },
            width_millionths: 900_000,
            height_millionths: if kind == PresentationShapeKindV1::Title {
                100_000
            } else {
                650_000
            },
        },
        content,
        generated: name.starts_with("d2i."),
        hidden: false,
        state_sha256,
    })
}

fn semantic_external_id(prefix: &str, value: &str, ordinal: u32) -> String {
    if !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return value.to_owned();
    }
    let hash = d2i_office_capability::sha256_bytes(value.as_bytes());
    format!("{prefix}.{ordinal:04}.{}", &hash[7..23])
}

fn attribute_value(
    element: &quick_xml::events::BytesStart<'_>,
    key: &[u8],
    decoder: quick_xml::encoding::Decoder,
) -> Result<Option<String>, String> {
    for attribute in element.attributes().with_checks(true) {
        let attribute = attribute.map_err(|error| error.to_string())?;
        if attribute.key.local_name().as_ref() == key {
            return attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, decoder)
                .map(|value| Some(value.into_owned()))
                .map_err(|error| error.to_string());
        }
    }
    Ok(None)
}

fn slide_ordinal_from_part(name: &str) -> Result<u32, String> {
    name.strip_prefix("ppt/slides/slide")
        .and_then(|value| value.strip_suffix(".xml"))
        .ok_or_else(|| "PPTX slide part name is invalid".to_owned())?
        .parse::<u32>()
        .map_err(|error| format!("PPTX slide ordinal: {error}"))
}

fn group_shape_xml() -> &'static str {
    "<p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr>"
}

fn slide_xml(purpose: &str, title: &str, body: &str, generated: bool) -> String {
    let semantic_purpose = if generated && !purpose.starts_with("d2i.generated.") {
        format!("d2i.generated.{purpose}")
    } else {
        purpose.to_owned()
    };
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><p:sld xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\" xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"><p:cSld name=\"{}\"><p:spTree>{}{}{}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>", quick_xml::escape::escape(&semantic_purpose), group_shape_xml(), text_shape_xml(2, "d2i.title", title, 457200, 274320, 11277600, 914400, 2800), text_shape_xml(3, "d2i.body", body, 609600, 1600200, 10972800, 4572000, 1800))
}

#[allow(clippy::too_many_arguments)]
fn text_shape_xml(
    id: u32,
    name: &str,
    text: &str,
    x: u32,
    y: u32,
    cx: u32,
    cy: u32,
    size: u32,
) -> String {
    format!("<p:sp><p:nvSpPr><p:cNvPr id=\"{id}\" name=\"{}\"/><p:cNvSpPr txBox=\"1\"/><p:nvPr/></p:nvSpPr><p:spPr><a:xfrm><a:off x=\"{x}\" y=\"{y}\"/><a:ext cx=\"{cx}\" cy=\"{cy}\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr><p:txBody><a:bodyPr wrap=\"square\"/><a:lstStyle/><a:p><a:r><a:rPr lang=\"ko-KR\" sz=\"{size}\"/><a:t>{}</a:t></a:r><a:endParaRPr lang=\"ko-KR\" sz=\"{size}\"/></a:p></p:txBody></p:sp>", quick_xml::escape::escape(name), quick_xml::escape::escape(text))
}

fn slide_relationships_xml(image: Option<(&str, &str)>) -> String {
    let image = image
        .map(|(id, target)| {
            format!("<Relationship Id=\"{id}\" Type=\"{IMAGE_REL}\" Target=\"{target}\"/>")
        })
        .unwrap_or_default();
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"{SLIDE_LAYOUT_REL}\" Target=\"../slideLayouts/slideLayout1.xml\"/>{image}</Relationships>")
}

fn picture_xml(shape_id: &str, relation_id: &str) -> String {
    format!("<p:pic><p:nvPicPr><p:cNvPr id=\"80\" name=\"{}\"/><p:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></p:cNvPicPr><p:nvPr/></p:nvPicPr><p:blipFill><a:blip r:embed=\"{}\"/><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr><a:xfrm><a:off x=\"8229600\" y=\"365760\"/><a:ext cx=\"2743200\" cy=\"914400\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr></p:pic>", quick_xml::escape::escape(shape_id), quick_xml::escape::escape(relation_id))
}

fn table_xml(shape_id: &str, labels: &[String], values: &[String]) -> String {
    fn cell(shape_id: &str, row: usize, column: usize, text: &str, bold: bool) -> String {
        format!("<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p><a:r><a:rPr lang=\"ko-KR\" sz=\"1600\" b=\"{}\"/><a:t>{}</a:t></a:r><a:endParaRPr lang=\"ko-KR\" sz=\"1600\"/></a:p></a:txBody><a:tcPr/><a:extLst><a:ext uri=\"urn:d2i:cell\"><d2i:cell xmlns:d2i=\"urn:d2i:presentation:v1\" name=\"{}.r{}.c{}\"/></a:ext></a:extLst></a:tc>", if bold { 1 } else { 0 }, quick_xml::escape::escape(text), quick_xml::escape::escape(shape_id), row, column)
    }
    let width = 10_972_800_u32 / u32::try_from(labels.len().max(1)).unwrap_or(1);
    let grid = labels
        .iter()
        .map(|_| format!("<a:gridCol w=\"{width}\"/>"))
        .collect::<String>();
    let header = labels
        .iter()
        .enumerate()
        .map(|(index, value)| cell(shape_id, 1, index + 1, value, true))
        .collect::<String>();
    let values = values
        .iter()
        .enumerate()
        .map(|(index, value)| cell(shape_id, 2, index + 1, value, false))
        .collect::<String>();
    format!("<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=\"70\" name=\"{}\"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr><p:xfrm><a:off x=\"609600\" y=\"1828800\"/><a:ext cx=\"10972800\" cy=\"2743200\"/></p:xfrm><a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/table\"><a:tbl><a:tblPr firstRow=\"1\" bandRow=\"1\"><a:tableStyleId>{{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}}</a:tableStyleId></a:tblPr><a:tblGrid>{grid}</a:tblGrid><a:tr h=\"685800\">{header}</a:tr><a:tr h=\"685800\">{values}</a:tr></a:tbl></a:graphicData></a:graphic></p:graphicFrame>", quick_xml::escape::escape(shape_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use d2i_presentation_capability::default_presentation_resource_limits;
    use d2i_spreadsheet_capability::{SpreadsheetFactKindV1, SpreadsheetTypedFactV1};

    fn temp_path(name: &str) -> std::path::PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        std::env::temp_dir().join(format!(
            "d2i-office400-{name}-{}-{stamp}.pptx",
            std::process::id()
        ))
    }

    fn fact(id: &str, value: i64) -> SpreadsheetTypedFactV1 {
        SpreadsheetTypedFactV1 {
            fact_id: id.to_owned(),
            fact_kind: SpreadsheetFactKindV1::Aggregate,
            subject_id: "training.july".to_owned(),
            predicate_id: "participant.count".to_owned(),
            typed_value: SpreadsheetScalarV1::Integer { value },
            unit_id: Some("unit.people".to_owned()),
            source_table_id: "table.training".to_owned(),
            source_column_ids: vec!["column.count".to_owned()],
            source_row_count: 3,
            source_range_sha256: d2i_office_capability::sha256_bytes(b"range"),
            confidence_millionths: 1_000_000,
            priority: 1,
            evidence_ids: vec!["evidence.query".to_owned()],
            fact_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .unwrap_or_else(|error| panic!("fact: {error}"))
    }

    fn facts() -> PresentationFactBindingV1 {
        let values = vec![
            fact("fact.completed", 55),
            fact("fact.online", 120),
            fact("fact.external", 18),
        ];
        let ids = values
            .iter()
            .map(|fact| fact.fact_id.clone())
            .collect::<Vec<_>>();
        PresentationFactBindingV1 {
            schema_version: 1,
            binding_id: "binding.facts".to_owned(),
            spreadsheet_context_slice_sha256: d2i_office_capability::sha256_bytes(b"slice"),
            spreadsheet_query_result_sha256: d2i_office_capability::sha256_bytes(b"result"),
            source_workbook_snapshot_sha256: d2i_office_capability::sha256_bytes(b"snapshot"),
            facts: values,
            summary_fact_ids: ids.clone(),
            table_fact_ids: ids.clone(),
            chart_fact_ids: ids,
            binding_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .unwrap_or_else(|error| panic!("binding: {error}"))
    }

    #[test]
    fn creates_large_template_and_mutates_new_generations() {
        let limits = default_presentation_resource_limits();
        let source = temp_path("source");
        let next = temp_path("next");
        let final_path = temp_path("final");
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&next);
        let _ = std::fs::remove_file(&final_path);
        let snapshot = create_pptx_template(&source, "presentation.test", 120, &limits)
            .unwrap_or_else(|error| panic!("create: {error}"));
        assert_eq!(snapshot.slide_count, 120);
        assert_eq!(
            inspect_pptx_canvas_millipoints(&source, &limits).ok(),
            Some((720_000, 540_000))
        );
        let next_snapshot = mutate_pptx_presentation(PptxPresentationMutationV1 {
            source: &source,
            destination: &next,
            workspace_root: source.parent().unwrap_or_else(|| Path::new(".")),
            expected_source_sha256: &snapshot.source_content_sha256,
            presentation_id: "presentation.test",
            artifact_id: "artifact.test",
            generation: 2,
            backend_id: "backend.pptx.file",
            observed_at_unix_ms: 2_000,
            mutation: &PresentationMutationV1::AddSlide {
                planned_slide_id: "slide.generated.1".to_owned(),
                purpose_id: "purpose.executive-summary".to_owned(),
                layout_id: "layout.blank.v1".to_owned(),
            },
            facts: &facts(),
            limits: &limits,
        })
        .unwrap_or_else(|error| panic!("add slide: {error}"));
        assert_eq!(next_snapshot.slide_count, 121);
        let final_snapshot = mutate_pptx_presentation(PptxPresentationMutationV1 {
            source: &next,
            destination: &final_path,
            workspace_root: next.parent().unwrap_or_else(|| Path::new(".")),
            expected_source_sha256: &next_snapshot.source_content_sha256,
            presentation_id: "presentation.test",
            artifact_id: "artifact.test",
            generation: 3,
            backend_id: "backend.pptx.file",
            observed_at_unix_ms: 3_000,
            mutation: &PresentationMutationV1::SetTitle {
                slide_id: "slide.0121".to_owned(),
                title: "2026년 7월 안전교육 결과".to_owned(),
            },
            facts: &facts(),
            limits: &limits,
        })
        .unwrap_or_else(|error| panic!("set title: {error}"));
        assert_ne!(
            next_snapshot.snapshot_sha256,
            final_snapshot.snapshot_sha256
        );
        for path in [&source, &next, &final_path] {
            let _ = std::fs::remove_file(path);
        }
    }
}
