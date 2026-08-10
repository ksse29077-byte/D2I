use d2i_design_intelligence::{
    CommonDesignRoleV1, DesignArtifactFeatureV1, DesignArtifactFormatV1, DesignDensityClassV1,
    DesignFeatureVectorV1, NormalizedDesignRectV1, ZERO_HASH,
};
use d2i_document_capability::{DocumentFormatV1, DocumentNodeKindV1, DocumentSemanticSnapshotV1};
use d2i_presentation_capability::{
    PresentationLayoutSlotV1, PresentationSemanticSnapshotV1, PresentationShapeContentV1,
};
use std::collections::BTreeSet;

fn density_class(count: usize) -> DesignDensityClassV1 {
    match count {
        0..=3 => DesignDensityClassV1::Low,
        4..=8 => DesignDensityClassV1::Medium,
        _ => DesignDensityClassV1::High,
    }
}

fn ratio(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(numerator.saturating_mul(1_000_000) / denominator).unwrap_or(1_000_000)
}

fn role(slot: PresentationLayoutSlotV1) -> CommonDesignRoleV1 {
    match slot {
        PresentationLayoutSlotV1::Title => CommonDesignRoleV1::ArtifactTitle,
        PresentationLayoutSlotV1::Footer => CommonDesignRoleV1::Footnote,
        PresentationLayoutSlotV1::TableMain => CommonDesignRoleV1::TableBody,
        PresentationLayoutSlotV1::ChartMain => CommonDesignRoleV1::ChartLabel,
        PresentationLayoutSlotV1::Hero => CommonDesignRoleV1::KpiValue,
        PresentationLayoutSlotV1::Body
        | PresentationLayoutSlotV1::BodyLeft
        | PresentationLayoutSlotV1::BodyRight => CommonDesignRoleV1::Body,
    }
}

/// Converts the existing bounded PresentationML semantic snapshot into normalized design facts.
pub fn extract_presentation_design_features(
    snapshot: &PresentationSemanticSnapshotV1,
    organization_id: &str,
    artifact_class: &str,
    template_family_id: &str,
    quality_weight_millionths: u32,
) -> Result<Vec<DesignArtifactFeatureV1>, String> {
    snapshot.validate().map_err(|error| error.to_string())?;
    if quality_weight_millionths > 1_000_000 || snapshot.slides.is_empty() {
        return Err("presentation design extraction input is outside bounds".to_owned());
    }
    snapshot
        .slides
        .iter()
        .map(|slide| {
            let total = slide.shapes.len();
            let image_count = slide
                .shapes
                .iter()
                .filter(|shape| matches!(shape.content, PresentationShapeContentV1::Image { .. }))
                .count();
            let table_count = slide
                .shapes
                .iter()
                .filter(|shape| matches!(shape.content, PresentationShapeContentV1::Table { .. }))
                .count();
            let chart_count = slide
                .shapes
                .iter()
                .filter(|shape| matches!(shape.content, PresentationShapeContentV1::Chart { .. }))
                .count();
            let text_count = total.saturating_sub(image_count + table_count + chart_count);
            let vector = DesignFeatureVectorV1 {
                layout_ratios: slide
                    .shapes
                    .iter()
                    .flat_map(|shape| {
                        [
                            shape.bounds.left_millionths,
                            shape.bounds.top_millionths,
                            shape.bounds.width_millionths,
                            shape.bounds.height_millionths,
                        ]
                    })
                    .collect(),
                font_role_ratios: vec![1_000_000, 650_000, 420_000],
                color_role_distribution: vec![650_000, 200_000, 150_000],
                spacing_distribution: vec![60_000, 30_000, 18_000],
                white_space_millionths: 400_000_u32.saturating_sub(
                    u32::try_from(total)
                        .unwrap_or(u32::MAX)
                        .saturating_mul(20_000),
                ),
                shape_density_millionths: ratio(total, 20),
                text_density_millionths: ratio(text_count, total.max(1)),
                image_ratio_millionths: ratio(image_count, total.max(1)),
                table_density_millionths: ratio(table_count, total.max(1)),
                chart_density_millionths: ratio(chart_count, total.max(1)),
                alignment_features: slide
                    .shapes
                    .iter()
                    .map(|shape| shape.bounds.left_millionths)
                    .collect(),
                vector_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())?;
            DesignArtifactFeatureV1 {
                schema_version: 1,
                feature_id: format!("feature.{}.{}", snapshot.artifact_id, slide.ordinal),
                organization_id: organization_id.to_owned(),
                artifact_id: snapshot.artifact_id.clone(),
                artifact_sha256: snapshot.source_content_sha256.clone(),
                artifact_class: artifact_class.to_owned(),
                format: DesignArtifactFormatV1::Pptx,
                template_family_id: template_family_id.to_owned(),
                unit_role_id: slide.purpose_id.clone(),
                layout_id: slide.layout_id.clone(),
                normalized_slots: slide
                    .shapes
                    .iter()
                    .map(|shape| NormalizedDesignRectV1 {
                        left_millionths: shape.bounds.left_millionths,
                        top_millionths: shape.bounds.top_millionths,
                        width_millionths: shape.bounds.width_millionths,
                        height_millionths: shape.bounds.height_millionths,
                    })
                    .collect(),
                typography_role_ids: slide
                    .shapes
                    .iter()
                    .map(|shape| role(shape.layout_slot))
                    .collect(),
                color_role_ids: vec![
                    "brand_primary".to_owned(),
                    "background".to_owned(),
                    "text_primary".to_owned(),
                ],
                spacing_ids: vec!["design.spacing.outer_margin".to_owned()],
                table_feature_ids: (table_count > 0)
                    .then(|| "table.semantic".to_owned())
                    .into_iter()
                    .collect(),
                chart_feature_ids: (chart_count > 0)
                    .then(|| "chart.semantic".to_owned())
                    .into_iter()
                    .collect(),
                image_feature_ids: (image_count > 0)
                    .then(|| "image.semantic".to_owned())
                    .into_iter()
                    .collect(),
                density_class: density_class(total),
                source_exemplar_ref: format!("exemplar.{}.{}", snapshot.artifact_id, slide.ordinal),
                quality_weight_millionths,
                vector,
                feature_sha256: ZERO_HASH.to_owned(),
            }
            .seal()
            .map_err(|error| error.to_string())
        })
        .collect()
}

/// Converts the existing HWPX/DOCX semantic projection without exposing source text or raw XML.
pub fn extract_document_design_feature(
    snapshot: &DocumentSemanticSnapshotV1,
    organization_id: &str,
    artifact_class: &str,
    template_family_id: &str,
    quality_weight_millionths: u32,
) -> Result<DesignArtifactFeatureV1, String> {
    snapshot
        .validate_integrity()
        .map_err(|error| error.to_string())?;
    let format = match snapshot.format_id {
        DocumentFormatV1::Hwpx => DesignArtifactFormatV1::Hwpx,
        DocumentFormatV1::Docx => DesignArtifactFormatV1::Docx,
        DocumentFormatV1::Hwp | DocumentFormatV1::Doc => {
            return Err(
                "legacy binary document format is not a Design Intelligence v1 corpus format"
                    .to_owned(),
            )
        }
    };
    let node_count = snapshot.ordered_nodes.len();
    let text_count = snapshot
        .ordered_nodes
        .iter()
        .filter(|node| {
            matches!(
                node.node_kind,
                DocumentNodeKindV1::Paragraph | DocumentNodeKindV1::Heading
            )
        })
        .count();
    let vector = DesignFeatureVectorV1 {
        layout_ratios: vec![1_000_000, 70_000, 70_000],
        font_role_ratios: vec![1_000_000, 700_000, 500_000],
        color_role_distribution: vec![800_000, 200_000],
        spacing_distribution: vec![50_000, 20_000, 12_000],
        white_space_millionths: 360_000,
        shape_density_millionths: ratio(node_count, 64),
        text_density_millionths: ratio(text_count, node_count.max(1)),
        image_ratio_millionths: ratio(snapshot.image_refs.len(), node_count.max(1)),
        table_density_millionths: ratio(snapshot.table_refs.len(), node_count.max(1)),
        chart_density_millionths: 0,
        alignment_features: vec![0, 500_000, 1_000_000],
        vector_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    DesignArtifactFeatureV1 {
        schema_version: 1,
        feature_id: format!("feature.{}.document", snapshot.artifact_id),
        organization_id: organization_id.to_owned(),
        artifact_id: snapshot.artifact_id.clone(),
        artifact_sha256: snapshot.source_content_sha256.clone(),
        artifact_class: artifact_class.to_owned(),
        format,
        template_family_id: template_family_id.to_owned(),
        unit_role_id: "document.body".to_owned(),
        layout_id: snapshot.page_layout_summary.replace(':', "."),
        normalized_slots: vec![NormalizedDesignRectV1 {
            left_millionths: 70_000,
            top_millionths: 70_000,
            width_millionths: 860_000,
            height_millionths: 860_000,
        }],
        typography_role_ids: vec![CommonDesignRoleV1::Heading1, CommonDesignRoleV1::Body],
        color_role_ids: vec!["brand_primary".to_owned(), "text_primary".to_owned()],
        spacing_ids: vec!["design.spacing.paragraph_spacing".to_owned()],
        table_feature_ids: snapshot.table_refs.clone(),
        chart_feature_ids: Vec::new(),
        image_feature_ids: snapshot.image_refs.clone(),
        density_class: density_class(node_count),
        source_exemplar_ref: format!("exemplar.{}.document", snapshot.artifact_id),
        quality_weight_millionths,
        vector,
        feature_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

/// Rejects a mixed-tenant feature collection before grammar compilation.
pub fn verify_design_feature_isolation(
    features: &[DesignArtifactFeatureV1],
    organization_id: &str,
) -> Result<(), String> {
    let organizations = features
        .iter()
        .map(|feature| feature.organization_id.as_str())
        .collect::<BTreeSet<_>>();
    if organizations.len() != 1 || !organizations.contains(organization_id) {
        return Err("design feature collection crosses organization boundary".to_owned());
    }
    for feature in features {
        feature.validate().map_err(|error| error.to_string())?;
    }
    Ok(())
}
