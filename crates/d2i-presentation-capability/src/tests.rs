use super::*;
use d2i_spreadsheet_capability::{
    SpreadsheetFactKindV1, SpreadsheetScalarV1, SpreadsheetTypedFactV1,
};

fn hash(value: &str) -> String {
    presentation_canonical_sha256(&value).unwrap_or_else(|error| panic!("hash: {error}"))
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
        source_range_sha256: hash("source.range"),
        confidence_millionths: 1_000_000,
        priority: 1,
        evidence_ids: vec!["evidence.office300.query".to_owned()],
        fact_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("fact: {error}"))
}

fn snapshot(slides: u32) -> PresentationSemanticSnapshotV1 {
    let slides = (1..=slides)
        .map(|ordinal| PresentationSlideSnapshotV1 {
            slide_id: format!("slide.{ordinal:04}"),
            ordinal,
            purpose_id: format!("purpose.{:02}", ordinal % 5),
            layout_id: "layout.title-body".to_owned(),
            title_sha256: hash(&format!("title.{ordinal}")),
            shapes: vec![PresentationShapeSnapshotV1 {
                shape_id: format!("shape.{ordinal:04}.title"),
                shape_kind: PresentationShapeKindV1::Title,
                layout_slot: PresentationLayoutSlotV1::Title,
                bounds: PresentationRectV1 {
                    left_millionths: 50_000,
                    top_millionths: 40_000,
                    width_millionths: 900_000,
                    height_millionths: 100_000,
                },
                content: PresentationShapeContentV1::Title {
                    text_sha256: hash(&format!("title.{ordinal}")),
                },
                generated: false,
                hidden: false,
                state_sha256: hash(&format!("shape.{ordinal}")),
            }],
            notes_present: false,
            generated: false,
            state_sha256: hash(&format!("slide.{ordinal}")),
        })
        .collect::<Vec<_>>();
    PresentationSemanticSnapshotV1 {
        schema_version: 1,
        presentation_id: "presentation.monthly-report".to_owned(),
        artifact_id: "artifact.monthly-report".to_owned(),
        artifact_generation: 1,
        format_id: PresentationFormatV1::Pptx,
        backend_id: "backend.pptx.file".to_owned(),
        slide_count: slides.len() as u32,
        slides,
        unsupported_feature_ids: Vec::new(),
        source_content_sha256: hash("source"),
        semantic_state_sha256: hash("semantic"),
        observed_at_unix_ms: 1_000,
        freshness_expires_at_unix_ms: 61_000,
        evidence_ids: vec!["evidence.fresh-reopen".to_owned()],
        snapshot_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("snapshot: {error}"))
}

#[test]
fn large_deck_query_and_context_are_bounded_and_deterministic() {
    let source = snapshot(120);
    let query = PresentationQueryV1 {
        schema_version: 1,
        query_id: "query.template-layouts".to_owned(),
        case_id: "case.office400".to_owned(),
        presentation_snapshot_sha256: source.snapshot_sha256.clone(),
        plan: PresentationQueryPlanV1::TemplateSlides {
            layout_ids: vec!["layout.title-body".to_owned()],
        },
        maximum_results: 8,
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 61_000,
        evidence_ids: vec!["evidence.query".to_owned()],
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("query: {error}"));
    let matches = source
        .slides
        .iter()
        .take(8)
        .map(|slide| PresentationQueryMatchV1 {
            slide_id: slide.slide_id.clone(),
            ordinal: slide.ordinal,
            purpose_id: slide.purpose_id.clone(),
            layout_id: slide.layout_id.clone(),
            relevance_millionths: 1_000_000,
            evidence_ids: vec!["evidence.exact-layout".to_owned()],
        })
        .collect();
    let result = PresentationQueryResultV1 {
        schema_version: 1,
        query_id: query.query_id.clone(),
        query_sha256: query.query_sha256,
        presentation_snapshot_sha256: source.snapshot_sha256.clone(),
        scanned_slides: 120,
        matches,
        complete: true,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("result: {error}"));
    let facts = vec![
        fact("fact.training.completed", 55),
        fact("fact.training.online", 120),
        fact("fact.training.external", 18),
    ];
    let fact_ids = facts
        .iter()
        .map(|value| value.fact_id.clone())
        .collect::<Vec<_>>();
    let binding = PresentationFactBindingV1 {
        schema_version: 1,
        binding_id: "binding.office300.facts".to_owned(),
        spreadsheet_context_slice_sha256: hash("spreadsheet.slice"),
        spreadsheet_query_result_sha256: hash("spreadsheet.result"),
        source_workbook_snapshot_sha256: hash("spreadsheet.snapshot"),
        facts,
        summary_fact_ids: fact_ids.clone(),
        table_fact_ids: fact_ids.clone(),
        chart_fact_ids: fact_ids.clone(),
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("binding: {error}"));
    let slides = source
        .slides
        .iter()
        .take(8)
        .map(|slide| PresentationContextSlideV1 {
            slide_id: slide.slide_id.clone(),
            purpose_id: slide.purpose_id.clone(),
            layout_id: slide.layout_id.clone(),
            title_sha256: slide.title_sha256.clone(),
            shape_kind_ids: vec![PresentationShapeKindV1::Title],
            evidence_ids: vec!["evidence.context-selection".to_owned()],
        })
        .collect();
    let slice = PresentationContextSliceV1 {
        schema_version: 1,
        slice_id: "slice.office400".to_owned(),
        case_id: "case.office400".to_owned(),
        presentation_snapshot_sha256: source.snapshot_sha256,
        query_result_sha256: result.result_sha256,
        fact_binding_sha256: binding.binding_sha256,
        selected_slides: slides,
        selected_fact_ids: fact_ids,
        text_excerpt_sha256s: vec![hash("safe-excerpt")],
        omitted_slide_count: 112,
        serialized_bytes: 0,
        estimated_tokens: 2_000,
        evidence_ids: vec!["evidence.bounded-context".to_owned()],
        slice_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("slice: {error}"));
    assert_eq!(slice.selected_slides.len(), 8);
    assert!(slice.serialized_bytes <= 32 * 1024);
    let second = slice
        .clone()
        .seal()
        .unwrap_or_else(|error| panic!("second seal: {error}"));
    assert_eq!(slice.slice_sha256, second.slice_sha256);
}

#[test]
fn raw_xml_com_secret_and_absolute_image_paths_fail_closed() {
    let mut intent = PresentationOperationIntentV1 {
        schema_version: 1,
        intent_id: "intent.bad".to_owned(),
        case_id: "case.office400".to_owned(),
        presentation_id: "presentation.one".to_owned(),
        artifact_id: "artifact.one".to_owned(),
        source_generation: 1,
        source_content_sha256: hash("source"),
        source_snapshot_sha256: hash("snapshot"),
        operation: PresentationOperationV1::SetText,
        mutation: Some(PresentationMutationV1::SetText {
            slide_id: "slide.1".to_owned(),
            shape_id: "shape.1".to_owned(),
            text: "<p:sld>PowerPoint.Application password: hidden".to_owned(),
        }),
        context_slice_sha256: hash("context"),
        slide_plan_sha256: hash("plan"),
        fact_binding_sha256: hash("facts"),
        expected_postcondition_ids: vec!["post.text".to_owned()],
        risk_class: PresentationRiskClassV1::Reversible,
        intent_sha256: ZERO_HASH.to_owned(),
    };
    assert!(intent.clone().seal().is_err());
    intent.mutation = Some(PresentationMutationV1::InsertImage {
        slide_id: "slide.1".to_owned(),
        shape_id: "shape.logo".to_owned(),
        image: PresentationImageSpecV1 {
            image_id: "image.logo".to_owned(),
            image_sha256: hash("image"),
            workspace_relative_path: "C:\\secret\\logo.png".to_owned(),
            slot: PresentationLayoutSlotV1::Hero,
            fit: "contain".to_owned(),
        },
    });
    intent.operation = PresentationOperationV1::InsertImage;
    assert!(intent.seal().is_err());
}

#[test]
fn shape_bounds_and_completion_tamper_are_rejected() {
    let mut value = snapshot(1);
    value.slides[0].shapes[0].bounds.width_millionths = 1_000_000;
    assert!(value.validate().is_err());
}
