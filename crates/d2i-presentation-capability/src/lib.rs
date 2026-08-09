//! Bounded presentation semantics and trusted OFFICE-400 execution contracts.

mod contracts;
pub use contracts::*;

use d2i_office_capability::{canonical_json_bytes, parse_json_strict, sha256_bytes};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};

pub const PRESENTATION_SCHEMA_VERSION: u32 = 1;
pub const ZERO_HASH: &str = d2i_office_capability::ZERO_HASH;
pub const MAX_PRESENTATION_JSON_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PRESENTATION_SLIDES: usize = 500;
pub const MAX_QUERY_SLIDES: usize = 32;
pub const MAX_CONTEXT_SLIDES: usize = 8;
pub const MAX_CONTEXT_FACTS: usize = 16;
pub const MAX_CONTEXT_EXCERPTS: usize = 16;
pub const MAX_CONTEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationCapabilityError {
    Invalid(String),
    Integrity(String),
    Unauthorized(String),
    Stale(String),
    Replay(String),
    ResourceLimit(String),
    Sensitive(String),
    Signature(String),
}

impl Display for PresentationCapabilityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        let (code, message) = match self {
            Self::Invalid(value) => ("invalid", value),
            Self::Integrity(value) => ("integrity", value),
            Self::Unauthorized(value) => ("unauthorized", value),
            Self::Stale(value) => ("stale", value),
            Self::Replay(value) => ("replay", value),
            Self::ResourceLimit(value) => ("resource_limit", value),
            Self::Sensitive(value) => ("sensitive", value),
            Self::Signature(value) => ("signature", value),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for PresentationCapabilityError {}

fn invalid(message: impl Into<String>) -> PresentationCapabilityError {
    PresentationCapabilityError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> PresentationCapabilityError {
    PresentationCapabilityError::Integrity(message.into())
}

fn resource(message: impl Into<String>) -> PresentationCapabilityError {
    PresentationCapabilityError::ResourceLimit(message.into())
}

pub fn parse_presentation_json_strict<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, PresentationCapabilityError> {
    if bytes.len() > MAX_PRESENTATION_JSON_BYTES {
        return Err(resource("presentation contract JSON exceeds 4 MiB"));
    }
    parse_json_strict(bytes).map_err(|error| invalid(error.to_string()))
}

pub fn presentation_canonical_sha256<T: Serialize>(
    value: &T,
) -> Result<String, PresentationCapabilityError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_bytes(&bytes))
        .map_err(|error| invalid(error.to_string()))
}

fn hash_without<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<String, PresentationCapabilityError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| invalid(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("presentation artifact must serialize as an object"))?;
    for field in excluded {
        object.remove(*field);
    }
    presentation_canonical_sha256(&object)
}

fn validate_hash(value: &str, label: &str) -> Result<(), PresentationCapabilityError> {
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

fn validate_id(value: &str, label: &str) -> Result<(), PresentationCapabilityError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/{}-".contains(&byte))
    {
        return Err(invalid(format!("{label} must be a bounded identifier")));
    }
    Ok(())
}

fn validate_text(value: &str, label: &str) -> Result<(), PresentationCapabilityError> {
    if value.is_empty() || value.chars().count() > 2_048 || value.contains('\0') {
        return Err(resource(format!(
            "{label} is empty or exceeds 2048 characters"
        )));
    }
    let lowered = value.to_ascii_lowercase();
    if value.trim_start().starts_with('<')
        || lowered.contains("powerpoint.application")
        || lowered.contains("createobject(")
        || lowered.contains("invoke-expression")
        || lowered.contains("<p:sld")
        || lowered.contains("vba project")
        || lowered.contains("password:")
        || lowered.contains("api_key")
        || lowered.contains("bearer ")
    {
        return Err(PresentationCapabilityError::Sensitive(format!(
            "{label} contains raw execution, markup, or sensitive material"
        )));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    label: &str,
    allow_empty: bool,
    maximum: usize,
) -> Result<(), PresentationCapabilityError> {
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
) -> Result<(), PresentationCapabilityError> {
    if (!allow_empty && values.is_empty()) || values.len() > maximum {
        return Err(resource(format!("{label} cardinality is invalid")));
    }
    for value in values {
        validate_hash(value, label)?;
    }
    Ok(())
}

fn validate_json_bounds<T: Serialize>(value: &T) -> Result<(), PresentationCapabilityError> {
    let value = serde_json::to_value(value).map_err(|error| invalid(error.to_string()))?;
    fn walk(value: &Value, depth: usize) -> Result<(), PresentationCapabilityError> {
        if depth > 64 {
            return Err(resource("presentation JSON nesting exceeds 64"));
        }
        match value {
            Value::String(value) if value.chars().count() > 4_096 || value.contains('\0') => {
                Err(resource("presentation string exceeds its global bound"))
            }
            Value::Array(values) if values.len() > 1_024 => {
                Err(resource("presentation collection exceeds its global bound"))
            }
            Value::Array(values) => values.iter().try_for_each(|value| walk(value, depth + 1)),
            Value::Object(values) if values.len() > 128 => {
                Err(resource("presentation object exceeds its field bound"))
            }
            Value::Object(values) => values.values().try_for_each(|value| walk(value, depth + 1)),
            _ => Ok(()),
        }
    }
    walk(&value, 0)
}

fn validate_hashed<T: Serialize>(
    value: &T,
    field: &str,
    actual: &str,
) -> Result<(), PresentationCapabilityError> {
    validate_hash(actual, field)?;
    validate_json_bounds(value)?;
    if hash_without(value, &[field])? != actual {
        return Err(integrity(format!("{field} self-hash differs")));
    }
    Ok(())
}

pub fn default_presentation_resource_limits() -> PresentationResourceLimitsV1 {
    PresentationResourceLimitsV1 {
        maximum_presentation_bytes: 256 * 1024 * 1024,
        maximum_package_entries: 4_096,
        maximum_uncompressed_bytes: 1024 * 1024 * 1024,
        maximum_compression_ratio: 200,
        maximum_xml_bytes: 512 * 1024 * 1024,
        maximum_xml_depth: 128,
        maximum_xml_nodes: 4_000_000,
        maximum_slides: MAX_PRESENTATION_SLIDES as u32,
        maximum_shapes_per_slide: 256,
        maximum_text_characters: 32_768,
        maximum_table_rows: 256,
        maximum_table_columns: 64,
        maximum_query_slides: MAX_QUERY_SLIDES as u32,
        maximum_context_slides: MAX_CONTEXT_SLIDES as u32,
        maximum_context_facts: MAX_CONTEXT_FACTS as u32,
        maximum_context_excerpts: MAX_CONTEXT_EXCERPTS as u32,
        maximum_context_bytes: MAX_CONTEXT_BYTES as u32,
        maximum_model_invocations: 16,
        maximum_save_generations: 128,
        maximum_worker_milliseconds: 120_000,
        maximum_application_session_milliseconds: 180_000,
        maximum_worker_memory_bytes: 2_u64 * 1024 * 1024 * 1024,
    }
}

fn validate_limits(
    value: &PresentationResourceLimitsV1,
) -> Result<(), PresentationCapabilityError> {
    if value.maximum_presentation_bytes < 1_024
        || value.maximum_package_entries == 0
        || value.maximum_package_entries > 16_384
        || value.maximum_uncompressed_bytes < value.maximum_presentation_bytes
        || value.maximum_compression_ratio == 0
        || value.maximum_compression_ratio > 1_000
        || value.maximum_xml_bytes == 0
        || value.maximum_xml_bytes > value.maximum_uncompressed_bytes
        || value.maximum_xml_depth == 0
        || value.maximum_xml_depth > 256
        || value.maximum_xml_nodes == 0
        || value.maximum_slides == 0
        || value.maximum_slides > MAX_PRESENTATION_SLIDES as u32
        || value.maximum_shapes_per_slide == 0
        || value.maximum_shapes_per_slide > 1_024
        || value.maximum_query_slides == 0
        || value.maximum_query_slides > MAX_QUERY_SLIDES as u32
        || value.maximum_context_slides == 0
        || value.maximum_context_slides > MAX_CONTEXT_SLIDES as u32
        || value.maximum_context_facts == 0
        || value.maximum_context_facts > MAX_CONTEXT_FACTS as u32
        || value.maximum_context_excerpts == 0
        || value.maximum_context_excerpts > MAX_CONTEXT_EXCERPTS as u32
        || value.maximum_context_bytes < 1_024
        || value.maximum_context_bytes > MAX_CONTEXT_BYTES as u32
        || value.maximum_worker_milliseconds == 0
        || value.maximum_application_session_milliseconds < value.maximum_worker_milliseconds
        || value.maximum_worker_memory_bytes < 16 * 1024 * 1024
    {
        return Err(resource(
            "presentation resource limits are outside v1 bounds",
        ));
    }
    Ok(())
}

impl PresentationSemanticSnapshotV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.slides.sort_by_key(|slide| slide.ordinal);
        self.unsupported_feature_ids.sort();
        self.evidence_ids.sort();
        self.snapshot_sha256 = hash_without(&self, &["snapshot_sha256"])?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.artifact_generation == 0
            || self.slides.is_empty()
            || self.slides.len() > MAX_PRESENTATION_SLIDES
            || self.slide_count as usize != self.slides.len()
            || self.observed_at_unix_ms == 0
            || self.freshness_expires_at_unix_ms <= self.observed_at_unix_ms
        {
            return Err(invalid(
                "presentation snapshot version, size, generation, or freshness is invalid",
            ));
        }
        for (value, label) in [
            (&self.presentation_id, "presentation ID"),
            (&self.artifact_id, "artifact ID"),
            (&self.backend_id, "backend ID"),
        ] {
            validate_id(value, label)?;
        }
        validate_hash(&self.source_content_sha256, "source content hash")?;
        validate_hash(&self.semantic_state_sha256, "semantic state hash")?;
        validate_ids(
            &self.unsupported_feature_ids,
            "unsupported feature IDs",
            true,
            256,
        )?;
        validate_ids(&self.evidence_ids, "snapshot evidence IDs", false, 256)?;
        let mut slide_ids = BTreeSet::new();
        let mut ordinals = BTreeSet::new();
        for slide in &self.slides {
            validate_id(&slide.slide_id, "slide ID")?;
            validate_id(&slide.purpose_id, "purpose ID")?;
            validate_id(&slide.layout_id, "layout ID")?;
            validate_hash(&slide.title_sha256, "slide title hash")?;
            validate_hash(&slide.state_sha256, "slide state hash")?;
            if !slide_ids.insert(&slide.slide_id)
                || !ordinals.insert(slide.ordinal)
                || slide.shapes.len() > 1_024
            {
                return Err(invalid("slide ID or ordinal is duplicated"));
            }
            let mut shape_ids = BTreeSet::new();
            for shape in &slide.shapes {
                validate_id(&shape.shape_id, "shape ID")?;
                validate_hash(&shape.state_sha256, "shape state hash")?;
                if !shape_ids.insert(&shape.shape_id)
                    || shape.bounds.width_millionths == 0
                    || shape.bounds.height_millionths == 0
                    || shape
                        .bounds
                        .left_millionths
                        .saturating_add(shape.bounds.width_millionths)
                        > 1_000_000
                    || shape
                        .bounds
                        .top_millionths
                        .saturating_add(shape.bounds.height_millionths)
                        > 1_000_000
                {
                    return Err(invalid("shape identity or finite slide bounds are invalid"));
                }
            }
        }
        validate_hashed(self, "snapshot_sha256", &self.snapshot_sha256)
    }
}

impl PresentationQueryV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.evidence_ids.sort();
        self.query_sha256 = hash_without(&self, &["query_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.maximum_results == 0
            || self.maximum_results > MAX_QUERY_SLIDES as u32
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 300_000
        {
            return Err(invalid(
                "presentation query version, bound, or TTL is invalid",
            ));
        }
        validate_id(&self.query_id, "query ID")?;
        validate_id(&self.case_id, "query Case ID")?;
        validate_hash(&self.presentation_snapshot_sha256, "query snapshot hash")?;
        validate_ids(&self.evidence_ids, "query evidence IDs", false, 128)?;
        match &self.plan {
            PresentationQueryPlanV1::FindSlidesByPurpose { purpose_ids } => {
                validate_ids(purpose_ids, "purpose IDs", false, 16)?
            }
            PresentationQueryPlanV1::FindSlidesByTitle { title_terms } => {
                if title_terms.is_empty() || title_terms.len() > 16 {
                    return Err(resource("title term count is invalid"));
                }
                for value in title_terms {
                    validate_text(value, "title term")?;
                }
            }
            PresentationQueryPlanV1::FindSlidesByContentFact { fact_ids } => {
                validate_ids(fact_ids, "fact IDs", false, 16)?
            }
            PresentationQueryPlanV1::LayoutCandidates { purpose_id } => {
                validate_id(purpose_id, "layout purpose ID")?
            }
            PresentationQueryPlanV1::TemplateSlides { layout_ids } => {
                validate_ids(layout_ids, "template layout IDs", false, 16)?
            }
            PresentationQueryPlanV1::RelatedSlides { slide_ids } => {
                validate_ids(slide_ids, "related slide IDs", false, 16)?
            }
        }
        validate_hashed(self, "query_sha256", &self.query_sha256)
    }
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), PresentationCapabilityError> {
        self.validate()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms > self.expires_at_unix_ms {
            return Err(PresentationCapabilityError::Stale(
                "presentation query is outside its validity window".to_owned(),
            ));
        }
        Ok(())
    }
}

impl PresentationQueryResultV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.result_sha256 = hash_without(&self, &["result_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.scanned_slides > MAX_PRESENTATION_SLIDES as u32
            || self.matches.len() > MAX_QUERY_SLIDES
        {
            return Err(resource("presentation query result exceeds bounds"));
        }
        validate_id(&self.query_id, "query result ID")?;
        validate_hash(&self.query_sha256, "query hash")?;
        validate_hash(&self.presentation_snapshot_sha256, "snapshot hash")?;
        let mut ids = BTreeSet::new();
        for value in &self.matches {
            validate_id(&value.slide_id, "query slide ID")?;
            validate_id(&value.purpose_id, "query purpose ID")?;
            validate_id(&value.layout_id, "query layout ID")?;
            if value.relevance_millionths > 1_000_000 || !ids.insert(&value.slide_id) {
                return Err(invalid("query match relevance or identity is invalid"));
            }
            validate_ids(&value.evidence_ids, "query match evidence", false, 32)?;
        }
        validate_hashed(self, "result_sha256", &self.result_sha256)
    }
}

impl PresentationFactBindingV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.summary_fact_ids.sort();
        self.table_fact_ids.sort();
        self.chart_fact_ids.sort();
        self.binding_sha256 = hash_without(&self, &["binding_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1 || self.facts.is_empty() || self.facts.len() > MAX_CONTEXT_FACTS
        {
            return Err(resource(
                "presentation fact binding must contain 1..=16 facts",
            ));
        }
        validate_id(&self.binding_id, "fact binding ID")?;
        for value in [
            &self.spreadsheet_context_slice_sha256,
            &self.spreadsheet_query_result_sha256,
            &self.source_workbook_snapshot_sha256,
        ] {
            validate_hash(value, "spreadsheet lineage hash")?;
        }
        let mut facts = BTreeSet::new();
        for fact in &self.facts {
            fact.validate()
                .map_err(|error| invalid(error.to_string()))?;
            if !facts.insert(fact.fact_id.as_str()) {
                return Err(invalid("fact binding contains duplicate facts"));
            }
        }
        for (values, label) in [
            (&self.summary_fact_ids, "summary facts"),
            (&self.table_fact_ids, "table facts"),
            (&self.chart_fact_ids, "chart facts"),
        ] {
            validate_ids(values, label, false, MAX_CONTEXT_FACTS)?;
            if values.iter().any(|id| !facts.contains(id.as_str())) {
                return Err(integrity(format!("{label} are not bound typed facts")));
            }
        }
        validate_hashed(self, "binding_sha256", &self.binding_sha256)
    }
}

impl PresentationContextSliceV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.selected_fact_ids.sort();
        self.text_excerpt_sha256s.sort();
        self.evidence_ids.sort();
        self.serialized_bytes = 0;
        self.slice_sha256 = ZERO_HASH.to_owned();
        for _ in 0..4 {
            self.serialized_bytes = canonical_json_bytes(&self)
                .map_err(|error| invalid(error.to_string()))?
                .len()
                .try_into()
                .map_err(|_| resource("context size overflow"))?;
            self.slice_sha256 = hash_without(&self, &["slice_sha256"])?;
        }
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.selected_slides.is_empty()
            || self.selected_slides.len() > MAX_CONTEXT_SLIDES
            || self.selected_fact_ids.is_empty()
            || self.selected_fact_ids.len() > MAX_CONTEXT_FACTS
            || self.text_excerpt_sha256s.len() > MAX_CONTEXT_EXCERPTS
            || self.serialized_bytes == 0
            || self.serialized_bytes > MAX_CONTEXT_BYTES as u32
            || self.estimated_tokens == 0
            || self.estimated_tokens > 8_192
        {
            return Err(resource("presentation context slice exceeds v1 bounds"));
        }
        validate_id(&self.slice_id, "context slice ID")?;
        validate_id(&self.case_id, "context Case ID")?;
        for value in [
            &self.presentation_snapshot_sha256,
            &self.query_result_sha256,
            &self.fact_binding_sha256,
        ] {
            validate_hash(value, "context lineage hash")?;
        }
        validate_ids(
            &self.selected_fact_ids,
            "context facts",
            false,
            MAX_CONTEXT_FACTS,
        )?;
        validate_hashes(
            &self.text_excerpt_sha256s,
            "context excerpts",
            true,
            MAX_CONTEXT_EXCERPTS,
        )?;
        validate_ids(&self.evidence_ids, "context evidence", false, 128)?;
        for slide in &self.selected_slides {
            validate_id(&slide.slide_id, "context slide ID")?;
            validate_id(&slide.purpose_id, "context purpose ID")?;
            validate_id(&slide.layout_id, "context layout ID")?;
            validate_hash(&slide.title_sha256, "context title hash")?;
            validate_ids(&slide.evidence_ids, "context slide evidence", false, 32)?;
        }
        let actual: u32 = canonical_json_bytes(self)
            .map_err(|error| invalid(error.to_string()))?
            .len()
            .try_into()
            .map_err(|_| resource("context size overflow"))?;
        if actual != self.serialized_bytes {
            return Err(integrity("context serialized byte count differs"));
        }
        validate_hashed(self, "slice_sha256", &self.slice_sha256)
    }
}

impl PresentationBriefV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.required_topic_ids.sort();
        self.required_fact_ids.sort();
        self.brief_sha256 = hash_without(&self, &["brief_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1 || self.maximum_slides == 0 || self.maximum_slides > 32 {
            return Err(resource("presentation brief slide budget is invalid"));
        }
        validate_id(&self.brief_id, "brief ID")?;
        validate_id(&self.case_id, "brief Case ID")?;
        validate_text(&self.objective, "brief objective")?;
        validate_id(&self.audience_id, "audience ID")?;
        validate_ids(&self.required_topic_ids, "brief topics", false, 32)?;
        validate_ids(
            &self.required_fact_ids,
            "brief facts",
            false,
            MAX_CONTEXT_FACTS,
        )?;
        validate_hash(&self.context_slice_sha256, "brief context hash")?;
        validate_hashed(self, "brief_sha256", &self.brief_sha256)
    }
}

fn validate_layout(value: &PresentationLayoutSpecV1) -> Result<(), PresentationCapabilityError> {
    validate_id(&value.layout_id, "layout ID")?;
    if value.required_slots.is_empty()
        || value.required_slots.len() > 8
        || !(8..=72).contains(&value.minimum_font_points)
    {
        return Err(resource("layout slots or font bound are invalid"));
    }
    Ok(())
}

fn validate_image(value: &PresentationImageSpecV1) -> Result<(), PresentationCapabilityError> {
    validate_id(&value.image_id, "image ID")?;
    validate_hash(&value.image_sha256, "image hash")?;
    if value.workspace_relative_path.is_empty()
        || value.workspace_relative_path.len() > 512
        || value.workspace_relative_path.starts_with('/')
        || value.workspace_relative_path.contains(':')
        || value.workspace_relative_path.contains("..")
        || value.workspace_relative_path.starts_with("\\\\")
        || !matches!(value.fit.as_str(), "contain" | "cover")
    {
        return Err(invalid("image path or fit is unsafe"));
    }
    Ok(())
}

fn validate_table(value: &PresentationTableSpecV1) -> Result<(), PresentationCapabilityError> {
    validate_id(&value.table_id, "table ID")?;
    if value.column_labels.is_empty()
        || value.column_labels.len() > 64
        || value.row_labels.is_empty()
        || value.row_labels.len() > 256
        || value.fact_ids.is_empty()
        || value.fact_ids.len() > MAX_CONTEXT_FACTS
    {
        return Err(resource("table dimensions or fact count are invalid"));
    }
    for value in value.column_labels.iter().chain(value.row_labels.iter()) {
        validate_text(value, "table label")?;
    }
    validate_ids(&value.fact_ids, "table facts", false, MAX_CONTEXT_FACTS)
}

fn validate_chart(value: &PresentationChartSpecV1) -> Result<(), PresentationCapabilityError> {
    validate_id(&value.chart_id, "chart ID")?;
    validate_text(&value.series_label, "chart series label")?;
    if value.category_labels.is_empty()
        || value.category_labels.len() > 16
        || value.fact_ids.len() != value.category_labels.len()
    {
        return Err(resource(
            "chart categories and facts must be bounded and aligned",
        ));
    }
    for label in &value.category_labels {
        validate_text(label, "chart category")?;
    }
    validate_ids(&value.fact_ids, "chart facts", false, MAX_CONTEXT_FACTS)
}

impl PresentationSlidePlanV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.covered_topic_ids.sort();
        self.covered_fact_ids.sort();
        self.plan_sha256 = hash_without(&self, &["plan_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1 || self.slides.is_empty() || self.slides.len() > 32 {
            return Err(resource("slide plan must contain 1..=32 slides"));
        }
        validate_id(&self.plan_id, "plan ID")?;
        for value in [
            &self.brief_sha256,
            &self.context_slice_sha256,
            &self.fact_binding_sha256,
            &self.model_invocation_sha256,
        ] {
            validate_hash(value, "slide plan binding hash")?;
        }
        validate_ids(&self.covered_topic_ids, "covered topics", false, 32)?;
        validate_ids(
            &self.covered_fact_ids,
            "covered facts",
            false,
            MAX_CONTEXT_FACTS,
        )?;
        let mut ids = BTreeSet::new();
        let mut purposes = BTreeSet::new();
        for slide in &self.slides {
            validate_id(&slide.planned_slide_id, "planned slide ID")?;
            validate_id(&slide.purpose_id, "planned purpose ID")?;
            validate_text(&slide.title, "slide title")?;
            validate_layout(&slide.layout)?;
            if !ids.insert(&slide.planned_slide_id) || !purposes.insert(&slide.purpose_id) {
                return Err(invalid("slide plan contains a duplicate slide or purpose"));
            }
            if slide.contents.len() > 16 {
                return Err(resource("slide content count exceeds 16"));
            }
            for content in &slide.contents {
                validate_text(&content.text, "slide content")?;
                validate_ids(
                    &content.authoritative_fact_ids,
                    "content facts",
                    true,
                    MAX_CONTEXT_FACTS,
                )?;
            }
            if let Some(image) = &slide.image {
                validate_image(image)?;
            }
            if let Some(table) = &slide.table {
                validate_table(table)?;
            }
            if let Some(chart) = &slide.chart {
                validate_chart(chart)?;
            }
            validate_ids(
                &slide.required_fact_ids,
                "slide required facts",
                true,
                MAX_CONTEXT_FACTS,
            )?;
        }
        validate_hashed(self, "plan_sha256", &self.plan_sha256)
    }

    pub fn validate_against(
        &self,
        brief: &PresentationBriefV1,
        facts: &PresentationFactBindingV1,
    ) -> Result<(), PresentationCapabilityError> {
        self.validate()?;
        brief.validate()?;
        facts.validate()?;
        if self.brief_sha256 != brief.brief_sha256
            || self.context_slice_sha256 != brief.context_slice_sha256
            || self.fact_binding_sha256 != facts.binding_sha256
            || self.slides.len() > brief.maximum_slides as usize
        {
            return Err(integrity("slide plan differs from brief or fact binding"));
        }
        for required in &brief.required_topic_ids {
            if !self.covered_topic_ids.contains(required) {
                return Err(invalid("slide plan omits a required topic"));
            }
        }
        for required in &brief.required_fact_ids {
            if !self.covered_fact_ids.contains(required) {
                return Err(invalid("slide plan omits a required fact"));
            }
        }
        Ok(())
    }
}

fn validate_mutation(value: &PresentationMutationV1) -> Result<(), PresentationCapabilityError> {
    match value {
        PresentationMutationV1::AddSlide {
            planned_slide_id,
            purpose_id,
            layout_id,
        } => {
            validate_id(planned_slide_id, "new slide ID")?;
            validate_id(purpose_id, "new slide purpose")?;
            validate_id(layout_id, "new slide layout")
        }
        PresentationMutationV1::SetTitle { slide_id, title } => {
            validate_id(slide_id, "title slide ID")?;
            validate_text(title, "slide title")
        }
        PresentationMutationV1::SetText {
            slide_id,
            shape_id,
            text,
        } => {
            validate_id(slide_id, "text slide ID")?;
            validate_id(shape_id, "text shape ID")?;
            validate_text(text, "shape text")
        }
        PresentationMutationV1::InsertImage {
            slide_id,
            shape_id,
            image,
        } => {
            validate_id(slide_id, "image slide ID")?;
            validate_id(shape_id, "image shape ID")?;
            validate_image(image)
        }
        PresentationMutationV1::InsertTable {
            slide_id,
            shape_id,
            table,
        } => {
            validate_id(slide_id, "table slide ID")?;
            validate_id(shape_id, "table shape ID")?;
            validate_table(table)
        }
        PresentationMutationV1::SetTableCell {
            slide_id,
            shape_id,
            row,
            column,
            text,
            fact_id,
        } => {
            validate_id(slide_id, "cell slide ID")?;
            validate_id(shape_id, "cell shape ID")?;
            if *row == 0 || *row > 256 || *column == 0 || *column > 64 {
                return Err(resource("table cell coordinate exceeds v1 bounds"));
            }
            validate_text(text, "table cell text")?;
            if let Some(id) = fact_id {
                validate_id(id, "table cell fact ID")?;
            }
            Ok(())
        }
        PresentationMutationV1::InsertChart {
            slide_id,
            shape_id,
            chart,
        } => {
            validate_id(slide_id, "chart slide ID")?;
            validate_id(shape_id, "chart shape ID")?;
            validate_chart(chart)
        }
        PresentationMutationV1::ApplyLayout { slide_id, layout } => {
            validate_id(slide_id, "layout slide ID")?;
            validate_layout(layout)
        }
        PresentationMutationV1::ApplyStyleRole {
            slide_id, shape_id, ..
        }
        | PresentationMutationV1::MoveResizeShape {
            slide_id, shape_id, ..
        }
        | PresentationMutationV1::RemoveGeneratedShape { slide_id, shape_id } => {
            validate_id(slide_id, "mutation slide ID")?;
            validate_id(shape_id, "mutation shape ID")
        }
        PresentationMutationV1::RemoveGeneratedSlide { slide_id } => {
            validate_id(slide_id, "removed slide ID")
        }
    }
}

impl PresentationOperationIntentV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.expected_postcondition_ids.sort();
        self.intent_sha256 = hash_without(&self, &["intent_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1 || self.source_generation == 0 {
            return Err(invalid(
                "presentation intent version or generation is invalid",
            ));
        }
        for (value, label) in [
            (&self.intent_id, "intent ID"),
            (&self.case_id, "intent Case ID"),
            (&self.presentation_id, "presentation ID"),
            (&self.artifact_id, "artifact ID"),
        ] {
            validate_id(value, label)?;
        }
        for value in [
            &self.source_content_sha256,
            &self.source_snapshot_sha256,
            &self.context_slice_sha256,
            &self.slide_plan_sha256,
            &self.fact_binding_sha256,
        ] {
            validate_hash(value, "intent binding hash")?;
        }
        let mutation_required = !matches!(
            self.operation,
            PresentationOperationV1::Inspect
                | PresentationOperationV1::Query
                | PresentationOperationV1::SaveVersion
        );
        if mutation_required != self.mutation.is_some() {
            return Err(invalid(
                "presentation operation and mutation payload differ",
            ));
        }
        if let Some(value) = &self.mutation {
            validate_mutation(value)?;
        }
        validate_ids(
            &self.expected_postcondition_ids,
            "intent postconditions",
            false,
            32,
        )?;
        validate_hashed(self, "intent_sha256", &self.intent_sha256)
    }
}

macro_rules! impl_simple_hashed {
    ($type:ty, $field:ident, $validate:expr) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
                self.$field = hash_without(&self, &[stringify!($field)])?;
                self.validate()?;
                Ok(self)
            }
            pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
                ($validate)(self)?;
                validate_hashed(self, stringify!($field), &self.$field)
            }
        }
    };
}

impl_simple_hashed!(
    PresentationCapabilityPackV1,
    pack_sha256,
    |value: &PresentationCapabilityPackV1| {
        if value.schema_version != 1
            || value.application_family_ids.is_empty()
            || value.application_family_ids.len() > 16
            || value.semantic_operations.is_empty()
            || value.semantic_operations.len() > 32
        {
            return Err(resource(
                "presentation capability pack collections are invalid",
            ));
        }
        validate_id(&value.pack_id, "pack ID")?;
        validate_id(&value.pack_version, "pack version")?;
        validate_ids(
            &value.application_family_ids,
            "application family IDs",
            false,
            16,
        )?;
        validate_limits(&value.resource_limits)
    }
);

impl_simple_hashed!(
    PresentationBackendDescriptorV1,
    descriptor_sha256,
    |value: &PresentationBackendDescriptorV1| {
        if value.schema_version != 1
            || value.supported_operations.is_empty()
            || value.supported_operations.len() > 32
            || !value.network_denied
            || !value.macro_disabled
            || value.requires_application
                != matches!(value.backend_kind, PresentationBackendKindV1::PowerpointCom)
            || value.requires_application != value.application_sha256.is_some()
        {
            return Err(invalid("presentation backend security contract differs"));
        }
        validate_id(&value.backend_id, "backend ID")?;
        validate_hash(&value.worker_sha256, "worker hash")?;
        if let Some(hash) = &value.application_sha256 {
            validate_hash(hash, "application hash")?;
        }
        Ok(())
    }
);

fn validate_binding(
    value: &PresentationOperationBindingV1,
) -> Result<(), PresentationCapabilityError> {
    if value.schema_version != 1
        || value.expected_source_generation == 0
        || value.issued_at_unix_ms == 0
        || value.expires_at_unix_ms <= value.issued_at_unix_ms
        || value.expires_at_unix_ms - value.issued_at_unix_ms > 300_000
    {
        return Err(invalid(
            "presentation binding version, generation, or TTL is invalid",
        ));
    }
    validate_id(&value.binding_id, "binding ID")?;
    validate_id(&value.activation_id, "activation ID")?;
    for hash in [
        &value.role_instance_sha256,
        &value.case_instance_sha256,
        &value.lease_sha256,
        &value.case_work_grant_sha256,
        &value.workspace_profile_sha256,
        &value.root_binding_sha256,
        &value.artifact_version_sha256,
        &value.intent_sha256,
        &value.context_slice_sha256,
        &value.slide_plan_sha256,
        &value.fact_binding_sha256,
        &value.capability_pack_sha256,
        &value.backend_descriptor_sha256,
        &value.backend_approval_sha256,
        &value.policy_admission_sha256,
        &value.activation_sha256,
        &value.worker_sha256,
    ] {
        validate_hash(hash, "binding hash")?;
    }
    if let Some(hash) = &value.application_sha256 {
        validate_hash(hash, "binding application hash")?;
    }
    Ok(())
}
impl_simple_hashed!(
    PresentationOperationBindingV1,
    binding_sha256,
    validate_binding
);

impl_simple_hashed!(
    PresentationOperationReceiptV1,
    receipt_sha256,
    |value: &PresentationOperationReceiptV1| {
        if value.schema_version != 1
            || value.started_at_unix_ms == 0
            || value.completed_at_unix_ms < value.started_at_unix_ms
        {
            return Err(invalid("presentation receipt timing is invalid"));
        }
        validate_id(&value.receipt_id, "receipt ID")?;
        validate_hash(&value.binding_sha256, "receipt binding hash")?;
        validate_hash(&value.source_content_sha256, "receipt source hash")?;
        if let Some(hash) = &value.destination_content_sha256 {
            validate_hash(hash, "receipt destination hash")?;
        }
        if let Some(hash) = &value.fresh_snapshot_sha256 {
            validate_hash(hash, "receipt snapshot hash")?;
        }
        validate_ids(&value.audit_event_ids, "receipt audit IDs", false, 64)?;
        if matches!(value.result, PresentationOperationResultV1::Verified)
            && (!value.activation_consumed
                || value.destination_content_sha256.is_none()
                || value.fresh_snapshot_sha256.is_none())
        {
            return Err(integrity(
                "verified receipt lacks consumed activation or fresh evidence",
            ));
        }
        Ok(())
    }
);

impl_simple_hashed!(
    PresentationSemanticDiffV1,
    diff_sha256,
    |value: &PresentationSemanticDiffV1| {
        if value.schema_version != 1 {
            return Err(invalid("presentation diff version differs"));
        }
        validate_hash(&value.before_snapshot_sha256, "diff before hash")?;
        validate_hash(&value.after_snapshot_sha256, "diff after hash")?;
        for (ids, label) in [
            (&value.added_slide_ids, "added slides"),
            (&value.changed_slide_ids, "changed slides"),
            (&value.changed_shape_ids, "changed shapes"),
            (&value.removed_generated_ids, "removed generated IDs"),
            (&value.unexpected_change_ids, "unexpected changes"),
        ] {
            validate_ids(ids, label, true, 512)?;
        }
        Ok(())
    }
);

fn quality_is_zero(value: &PresentationStructuralQualityV1) -> bool {
    value == &PresentationStructuralQualityV1::default()
}

impl_simple_hashed!(
    PresentationPostOperationVerificationV1,
    verification_sha256,
    |value: &PresentationPostOperationVerificationV1| {
        if value.schema_version != 1 || value.verified_at_unix_ms == 0 {
            return Err(invalid(
                "presentation verification version or timing differs",
            ));
        }
        validate_id(&value.verification_id, "verification ID")?;
        for hash in [
            &value.binding_sha256,
            &value.receipt_sha256,
            &value.diff_sha256,
            &value.fresh_snapshot_sha256,
        ] {
            validate_hash(hash, "verification hash")?;
        }
        validate_ids(
            &value.expected_postcondition_ids,
            "expected postconditions",
            false,
            32,
        )?;
        validate_ids(
            &value.satisfied_postcondition_ids,
            "satisfied postconditions",
            true,
            32,
        )?;
        validate_ids(
            &value.protected_invariant_ids,
            "protected invariants",
            false,
            32,
        )?;
        if matches!(value.status, PresentationVerificationStatusV1::Verified)
            && (value.expected_postcondition_ids != value.satisfied_postcondition_ids
                || !quality_is_zero(&value.quality))
        {
            return Err(integrity(
                "verified presentation has unsatisfied postconditions or structural defects",
            ));
        }
        Ok(())
    }
);

impl_simple_hashed!(
    PresentationProvenanceV1,
    provenance_sha256,
    |value: &PresentationProvenanceV1| {
        if value.schema_version != 1 {
            return Err(invalid("presentation provenance version differs"));
        }
        validate_id(&value.artifact_id, "provenance artifact ID")?;
        for hash in [
            &value.source_template_sha256,
            &value.source_workbook_snapshot_sha256,
            &value.fact_binding_sha256,
            &value.context_slice_sha256,
            &value.slide_plan_sha256,
        ] {
            validate_hash(hash, "provenance hash")?;
        }
        validate_hashes(
            &value.operation_receipt_sha256s,
            "operation receipts",
            false,
            128,
        )
    }
);

impl_simple_hashed!(
    PresentationReplayReportV1,
    report_sha256,
    |value: &PresentationReplayReportV1| {
        if value.schema_version != 1
            || value.scenario_count != 128
            || value.runs_per_scenario != 100
            || value.query_hash_mismatch_count != 0
            || value.context_hash_mismatch_count != 0
            || value.plan_hash_mismatch_count != 0
            || value.operation_hash_mismatch_count != 0
            || value.blind_replay_count != 0
        {
            return Err(integrity(
                "presentation replay report does not prove deterministic 128 x 100 replay",
            ));
        }
        Ok(())
    }
);

impl PresentationBackendApprovalV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, PresentationCapabilityError> {
        self.signature_hex.clear();
        self.approval_sha256 = ZERO_HASH.to_owned();
        self.signature_hex = hex_signature(&key.sign(&signature_payload(
            &self,
            &["signature_hex", "approval_sha256"],
        )?));
        self.approval_sha256 = hash_without(&self, &["approval_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn verify(&self, key: &VerifyingKey, now: u64) -> Result<(), PresentationCapabilityError> {
        self.validate()?;
        if now < self.issued_at_unix_ms || now > self.expires_at_unix_ms {
            return Err(PresentationCapabilityError::Stale(
                "presentation backend approval is expired".to_owned(),
            ));
        }
        verify_signature(
            key,
            &signature_payload(self, &["signature_hex", "approval_sha256"])?,
            &self.signature_hex,
        )
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid("backend approval version or TTL is invalid"));
        }
        for value in [
            &self.approval_id,
            &self.organization_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(value, "backend approval ID")?;
        }
        for hash in [
            &self.backend_descriptor_sha256,
            &self.capability_pack_sha256,
            &self.workspace_profile_sha256,
        ] {
            validate_hash(hash, "backend approval hash")?;
        }
        if let Some(hash) = &self.application_executable_sha256 {
            validate_hash(hash, "approved application hash")?;
        }
        validate_ids(
            &self.approved_operation_ids,
            "approved operations",
            false,
            32,
        )?;
        validate_signature_hex(&self.signature_hex)?;
        validate_hashed(self, "approval_sha256", &self.approval_sha256)
    }
}

impl PresentationWorkCompletionReportV1 {
    pub fn seal(mut self) -> Result<Self, PresentationCapabilityError> {
        self.finished_sha256 = hash_without(&self, &["finished_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1 || self.report_id.is_empty() {
            return Err(invalid("OFFICE-400 Completion identity differs"));
        }
        validate_id(&self.report_id, "Completion report ID")?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.capability_pack_sha256,
            &self.replay_report_sha256,
            &self.protected_audit_terminal_sha256,
            &self.powerpoint_executable_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
            &self.fact_binding_sha256,
        ] {
            validate_hash(hash, "Completion hash")?;
        }
        let gates = self.presentation_cases >= 20
            && self.routine_cases >= 12
            && self.exception_cases >= 8
            && self.successful_operations > 0
            && self.verified_operations == self.successful_operations
            && self.verified_closures > 0
            && self.pptx_file_mutations >= 8
            && self.powerpoint_com_mutations >= 4
            && self.powerpoint_chart_mutations >= 1
            && self.fresh_reopens > self.successful_operations
            && self.rendered_slides >= 5
            && self.source_slides >= 120
            && self.context_slides <= MAX_CONTEXT_SLIDES as u32
            && self.source_workbook_cells >= 100_000
            && self.context_facts <= MAX_CONTEXT_FACTS as u32
            && self.actual_qwen_cases >= 4
            && self.provider_invocations >= 4
            && self.replan_count >= 1
            && self.crash_windows_verified >= 12
            && self.safety == PresentationSafetyMetricsV1::default()
            && quality_is_zero(&self.structural_quality)
            && self.residual == PresentationResidualMetricsV1::default()
            && self.presentation_semantic_capability_evidence
            && self.context_slice_evidence
            && self.fact_binding_evidence
            && self.pptx_file_work_evidence
            && self.powerpoint_live_work_evidence
            && self.chart_evidence
            && self.render_evidence
            && self.office300_lineage_evidence
            && self.track_o_office400_evidence
            && self.complete;
        if !gates {
            return Err(integrity("OFFICE-400 Completion gates are incomplete"));
        }
        validate_hashed(self, "finished_sha256", &self.finished_sha256)
    }
}

impl PresentationWorkCertificationV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, PresentationCapabilityError> {
        self.signature_hex.clear();
        self.certification_sha256 = ZERO_HASH.to_owned();
        self.signature_hex = hex_signature(&key.sign(&signature_payload(
            &self,
            &["signature_hex", "certification_sha256"],
        )?));
        self.certification_sha256 = hash_without(&self, &["certification_sha256"])?;
        self.validate()?;
        Ok(self)
    }
    pub fn verify(&self, key: &VerifyingKey, now: u64) -> Result<(), PresentationCapabilityError> {
        self.validate()?;
        if now < self.issued_at_unix_ms || now > self.expires_at_unix_ms {
            return Err(PresentationCapabilityError::Stale(
                "OFFICE-400 certification is expired".to_owned(),
            ));
        }
        verify_signature(
            key,
            &signature_payload(self, &["signature_hex", "certification_sha256"])?,
            &self.signature_hex,
        )
    }
    pub fn validate(&self) -> Result<(), PresentationCapabilityError> {
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid(
                "OFFICE-400 certification version or TTL is invalid",
            ));
        }
        for value in [
            &self.certification_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(value, "certification ID")?;
        }
        for hash in [
            &self.capability_pack_sha256,
            &self.workspace_profile_sha256,
            &self.completion_report_sha256,
            &self.replay_report_sha256,
            &self.office300_finished_sha256,
        ] {
            validate_hash(hash, "certification hash")?;
        }
        validate_hashes(
            &self.backend_approval_sha256s,
            "certified backends",
            false,
            8,
        )?;
        validate_ids(&self.evidence_ids, "certification evidence", false, 64)?;
        validate_signature_hex(&self.signature_hex)?;
        validate_hashed(self, "certification_sha256", &self.certification_sha256)
    }
}

#[derive(Debug, Default)]
pub struct PresentationActivationLedgerV1 {
    consumed: BTreeSet<(String, String)>,
}

impl PresentationActivationLedgerV1 {
    pub fn consume(
        &mut self,
        activation_id: &str,
        activation_sha256: &str,
    ) -> Result<(), PresentationCapabilityError> {
        validate_id(activation_id, "presentation activation ID")?;
        validate_hash(activation_sha256, "presentation activation hash")?;
        if !self
            .consumed
            .insert((activation_id.to_owned(), activation_sha256.to_owned()))
        {
            return Err(PresentationCapabilityError::Replay(
                "presentation activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }
}

fn signature_payload<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<Vec<u8>, PresentationCapabilityError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| invalid(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("signed presentation value must be an object"))?;
    for field in excluded {
        object.remove(*field);
    }
    canonical_json_bytes(&object).map_err(|error| invalid(error.to_string()))
}

fn hex_signature(value: &Signature) -> String {
    value
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_signature_hex(value: &str) -> Result<(), PresentationCapabilityError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "presentation signature must be 64-byte hexadecimal",
        ));
    }
    Ok(())
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    value: &str,
) -> Result<(), PresentationCapabilityError> {
    validate_signature_hex(value)?;
    let mut bytes = [0_u8; 64];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| invalid("signature is not UTF-8"))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|_| invalid("signature hexadecimal is invalid"))?;
    }
    key.verify(payload, &Signature::from_bytes(&bytes))
        .map_err(|error| PresentationCapabilityError::Signature(error.to_string()))
}

pub fn presentation_cli_main() -> i32 {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let result = match arguments.as_slice() {
        [kind, action, flag, path] if action == "verify" && flag == "--input" && kind == "completion" => std::fs::read(path).map_err(|error| error.to_string()).and_then(|bytes| parse_presentation_json_strict::<PresentationWorkCompletionReportV1>(&bytes).map_err(|error| error.to_string())).and_then(|value| value.validate().map_err(|error| error.to_string())),
        [kind, action, input_flag, path, key_flag, public_key] if kind == "certification" && action == "verify" && input_flag == "--input" && key_flag == "--public-key" => verify_certification_file(path, public_key),
        _ => Err("usage: d2i-presentation completion verify --input <file> | certification verify --input <file> --public-key <hex-file>".to_owned()),
    };
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn verify_certification_file(path: &str, public_key_path: &str) -> Result<(), String> {
    let value: PresentationWorkCertificationV1 =
        parse_presentation_json_strict(&std::fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let text = std::fs::read_to_string(public_key_path).map_err(|error| error.to_string())?;
    let text = text.trim();
    if text.len() != 64 {
        return Err("certification public key length differs".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|error| error.to_string())?,
            16,
        )
        .map_err(|error| error.to_string())?;
    }
    let key = VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())?;
    value.validate().map_err(|error| error.to_string())?;
    verify_signature(
        &key,
        &signature_payload(&value, &["signature_hex", "certification_sha256"])
            .map_err(|error| error.to_string())?,
        &value.signature_hex,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests;
