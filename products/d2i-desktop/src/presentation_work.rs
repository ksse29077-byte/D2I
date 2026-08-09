use d2i_presentation_capability::{
    PresentationMutationV1, PresentationOperationV1, PresentationSlidePlanV1,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPresentationOperationV1 {
    pub mutation: PresentationMutationV1,
}

pub fn presentation_operation(mutation: &PresentationMutationV1) -> PresentationOperationV1 {
    match mutation {
        PresentationMutationV1::AddSlide { .. } => PresentationOperationV1::AddSlide,
        PresentationMutationV1::SetTitle { .. } => PresentationOperationV1::SetTitle,
        PresentationMutationV1::SetText { .. } => PresentationOperationV1::SetText,
        PresentationMutationV1::InsertImage { .. } => PresentationOperationV1::InsertImage,
        PresentationMutationV1::InsertTable { .. } => PresentationOperationV1::InsertTable,
        PresentationMutationV1::SetTableCell { .. } => PresentationOperationV1::SetTableCell,
        PresentationMutationV1::InsertChart { .. } => PresentationOperationV1::InsertChart,
        PresentationMutationV1::ApplyLayout { .. } => PresentationOperationV1::ApplyLayout,
        PresentationMutationV1::ApplyStyleRole { .. } => PresentationOperationV1::ApplyStyleRole,
        PresentationMutationV1::MoveResizeShape { .. } => PresentationOperationV1::MoveResizeShape,
        PresentationMutationV1::RemoveGeneratedSlide { .. } => {
            PresentationOperationV1::RemoveGeneratedSlide
        }
        PresentationMutationV1::RemoveGeneratedShape { .. } => {
            PresentationOperationV1::RemoveGeneratedShape
        }
    }
}

pub fn presentation_capability_id(operation: PresentationOperationV1) -> &'static str {
    match operation {
        PresentationOperationV1::Inspect => "presentation.inspect",
        PresentationOperationV1::Query => "presentation.query",
        PresentationOperationV1::CreateFromTemplate => "presentation.create_from_template",
        PresentationOperationV1::AddSlide => "presentation.add_slide",
        PresentationOperationV1::SetTitle => "presentation.set_title",
        PresentationOperationV1::SetText => "presentation.set_text",
        PresentationOperationV1::InsertImage => "presentation.insert_image",
        PresentationOperationV1::InsertTable => "presentation.insert_table",
        PresentationOperationV1::SetTableCell => "presentation.set_table_cell",
        PresentationOperationV1::InsertChart => "presentation.insert_chart",
        PresentationOperationV1::ApplyLayout => "presentation.apply_layout",
        PresentationOperationV1::ApplyStyleRole => "presentation.apply_style_role",
        PresentationOperationV1::MoveResizeShape => "presentation.move_resize_shape",
        PresentationOperationV1::SaveVersion => "presentation.save_version",
        PresentationOperationV1::RemoveGeneratedSlide => "presentation.remove_generated_slide",
        PresentationOperationV1::RemoveGeneratedShape => "presentation.remove_generated_shape",
    }
}

pub fn validate_resolved_presentation_operation(
    operation: &ResolvedPresentationOperationV1,
    plan: &PresentationSlidePlanV1,
) -> Result<(), String> {
    plan.validate().map_err(|error| error.to_string())?;
    let value = serde_json::to_value(&operation.mutation).map_err(|error| error.to_string())?;
    let text = serde_json::to_string(&value)
        .map_err(|error| error.to_string())?
        .to_ascii_lowercase();
    if text.contains("<p:sld")
        || text.contains("powerpoint.application")
        || text.contains("createobject")
        || text.contains("vbaproject")
        || text.contains("http://")
        || text.contains("https://")
        || text.contains("file://")
        || text.contains("\\\\")
    {
        return Err(
            "presentation operation contains raw execution or external material".to_owned(),
        );
    }
    Ok(())
}
