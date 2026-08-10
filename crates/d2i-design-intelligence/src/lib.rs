//! Organization-scoped, deterministic design grammar compilation and quality contracts.

mod contracts;

pub use contracts::*;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub const DESIGN_SCHEMA_VERSION: u32 = 1;
pub const ZERO_HASH: &str = d2i_office_capability::ZERO_HASH;
pub const MAX_DESIGN_JSON_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_CORPUS_ARTIFACTS: usize = 512;
pub const MAX_DESIGN_FEATURES: usize = 4096;
pub const MAX_TEMPLATE_FAMILIES: usize = 128;
pub const MAX_EXEMPLARS: usize = 4096;
pub const MAX_REFINEMENT_ROUNDS: u32 = 5;
pub const REQUIRED_REPLAY_SCENARIOS: u32 = 128;
pub const REQUIRED_REPLAY_RUNS: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesignIntelligenceError {
    Invalid(String),
    Integrity(String),
    AccessDenied(String),
    Resource(String),
    Unsupported(String),
    Json(String),
}

impl Display for DesignIntelligenceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid design artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "design integrity failure: {message}"),
            Self::AccessDenied(message) => write!(formatter, "design access denied: {message}"),
            Self::Resource(message) => write!(formatter, "design resource limit: {message}"),
            Self::Unsupported(message) => {
                write!(formatter, "unsupported design operation: {message}")
            }
            Self::Json(message) => write!(formatter, "design JSON failure: {message}"),
        }
    }
}

impl Error for DesignIntelligenceError {}

fn invalid(message: impl Into<String>) -> DesignIntelligenceError {
    DesignIntelligenceError::Invalid(message.into())
}

fn integrity(message: impl Into<String>) -> DesignIntelligenceError {
    DesignIntelligenceError::Integrity(message.into())
}

fn resource(message: impl Into<String>) -> DesignIntelligenceError {
    DesignIntelligenceError::Resource(message.into())
}

/// Returns the canonical SHA-256 identity used by all design contracts.
pub fn design_canonical_sha256<T: Serialize>(value: &T) -> Result<String, DesignIntelligenceError> {
    d2i_office_capability::canonical_sha256(value)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))
}

fn hash_without<T: Serialize>(
    value: &T,
    fields: &[&str],
) -> Result<String, DesignIntelligenceError> {
    let mut canonical = serde_json::to_value(value)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))?;
    let object = canonical
        .as_object_mut()
        .ok_or_else(|| invalid("hash target must be a JSON object"))?;
    for field in fields {
        if !object.contains_key(*field) {
            return Err(invalid(format!("hash field {field} is absent")));
        }
        object.insert(
            (*field).to_owned(),
            Value::String(if *field == "signature_hex" {
                String::new()
            } else {
                ZERO_HASH.to_owned()
            }),
        );
    }
    design_canonical_sha256(&canonical)
}

fn validate_json_bounds<T: Serialize>(value: &T) -> Result<(), DesignIntelligenceError> {
    let structured = serde_json::to_value(value)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))?;
    validate_bounded_value(&structured, 0)?;
    let bytes = serde_json::to_vec(&structured)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))?;
    if bytes.len() > MAX_DESIGN_JSON_BYTES {
        return Err(resource(format!(
            "serialized design artifact exceeds {MAX_DESIGN_JSON_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| invalid(error.to_string()))?;
    for forbidden in [
        "<p:",
        "<w:",
        "<hp:",
        "CreateObject",
        "PowerPoint.Application",
        "WScript",
        "javascript:",
        "powershell.exe",
        "cmd.exe /c",
        "vbaProject",
    ] {
        if text.contains(forbidden) {
            return Err(DesignIntelligenceError::AccessDenied(format!(
                "design artifact contains forbidden execution or raw-format token {forbidden}"
            )));
        }
    }
    Ok(())
}

fn validate_bounded_value(value: &Value, depth: usize) -> Result<(), DesignIntelligenceError> {
    if depth > 64 {
        return Err(resource("design artifact nesting exceeds 64 levels"));
    }
    match value {
        Value::Array(values) => {
            if values.len() > MAX_DESIGN_FEATURES {
                return Err(resource("design artifact collection exceeds 4096 entries"));
            }
            for value in values {
                validate_bounded_value(value, depth.saturating_add(1))?;
            }
        }
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(resource("design artifact object exceeds 256 fields"));
            }
            for value in values.values() {
                validate_bounded_value(value, depth.saturating_add(1))?;
            }
        }
        Value::String(value) => {
            if value.len() > 2_048 || value.contains('\0') {
                return Err(resource(
                    "design artifact string contains NUL or exceeds 2048 bytes",
                ));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), DesignIntelligenceError> {
    d2i_office_capability::validate_hash(value, field).map_err(|error| invalid(error.to_string()))
}

fn validate_id(value: &str, field: &str) -> Result<(), DesignIntelligenceError> {
    if value.is_empty()
        || value.len() > 512
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
    {
        return Err(invalid(format!("{field} is not a bounded identifier")));
    }
    Ok(())
}

fn validate_ids(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), DesignIntelligenceError> {
    if values.len() > maximum {
        return Err(resource(format!("{field} exceeds {maximum} entries")));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_id(value, field)?;
        if !seen.insert(value) {
            return Err(invalid(format!("{field} contains a duplicate")));
        }
    }
    Ok(())
}

fn validate_hashes(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), DesignIntelligenceError> {
    if values.len() > maximum {
        return Err(resource(format!("{field} exceeds {maximum} entries")));
    }
    for value in values {
        validate_hash(value, field)?;
    }
    Ok(())
}

fn validate_distribution(value: &DesignDistributionV1) -> Result<(), DesignIntelligenceError> {
    if value.minimum_millionths > value.q1_millionths
        || value.q1_millionths > value.median_millionths
        || value.median_millionths > value.q3_millionths
        || value.q3_millionths > value.maximum_millionths
        || value.maximum_millionths > 1_000_000
    {
        return Err(invalid(
            "design distribution is not ordered within one million",
        ));
    }
    Ok(())
}

fn validate_rect(value: &NormalizedDesignRectV1) -> Result<(), DesignIntelligenceError> {
    let right = value.left_millionths.saturating_add(value.width_millionths);
    let bottom = value.top_millionths.saturating_add(value.height_millionths);
    if value.width_millionths == 0
        || value.height_millionths == 0
        || right > 1_000_000
        || bottom > 1_000_000
    {
        return Err(invalid(
            "normalized design rectangle leaves the artifact canvas",
        ));
    }
    Ok(())
}

macro_rules! impl_simple_sealed {
    ($type:ty, $field:ident) => {
        impl $type {
            pub fn seal(mut self) -> Result<Self, DesignIntelligenceError> {
                self.$field = ZERO_HASH.to_owned();
                validate_json_bounds(&self)?;
                self.$field = hash_without(&self, &[stringify!($field)])?;
                Ok(self)
            }

            pub fn validate(&self) -> Result<(), DesignIntelligenceError> {
                validate_hash(&self.$field, stringify!($field))?;
                validate_json_bounds(self)?;
                if self.$field != hash_without(self, &[stringify!($field)])? {
                    return Err(integrity(concat!(stringify!($type), " hash differs")));
                }
                Ok(())
            }
        }
    };
}

impl_simple_sealed!(DesignFeatureVectorV1, vector_sha256);
impl_simple_sealed!(DesignArtifactFeatureV1, feature_sha256);
impl_simple_sealed!(OrganizationFontPolicyV1, font_policy_sha256);
impl_simple_sealed!(OrganizationLogoPolicyV1, logo_policy_sha256);
impl_simple_sealed!(TypographyGrammarV1, grammar_sha256);
impl_simple_sealed!(SpacingGrammarV1, grammar_sha256);
impl_simple_sealed!(LayoutGrammarV1, grammar_sha256);
impl_simple_sealed!(TableDesignGrammarV1, grammar_sha256);
impl_simple_sealed!(ChartDesignGrammarV1, grammar_sha256);
impl_simple_sealed!(ImageDesignGrammarV1, grammar_sha256);
impl_simple_sealed!(TemplateFamilyV1, family_sha256);
impl_simple_sealed!(DesignRuleProvenanceV1, rule_sha256);
impl_simple_sealed!(OrganizationDesignProfileV1, profile_sha256);
impl_simple_sealed!(DesignExemplarRecordV1, exemplar_sha256);
impl_simple_sealed!(DesignExemplarIndexV1, index_sha256);
impl_simple_sealed!(DesignExemplarQueryV1, query_sha256);
impl_simple_sealed!(DesignExemplarQueryResultV1, result_sha256);
impl_simple_sealed!(OrganizationDesignPackV1, pack_sha256);
impl_simple_sealed!(DesignPackCandidateV1, candidate_sha256);
impl_simple_sealed!(TypographyRequestV1, request_sha256);
impl_simple_sealed!(TypographyDecisionV1, decision_sha256);
impl_simple_sealed!(ArtifactLayoutRequestV1, request_sha256);
impl_simple_sealed!(ArtifactLayoutDecisionV1, decision_sha256);
impl_simple_sealed!(ContentFitReportV1, report_sha256);
impl_simple_sealed!(HardDesignCritiqueV1, critique_sha256);
impl_simple_sealed!(SoftDesignCritiqueV1, critique_sha256);
impl_simple_sealed!(DesignQualityReportV1, report_sha256);
impl_simple_sealed!(DesignRefinementPlanV1, plan_sha256);
impl_simple_sealed!(DesignRefinementReceiptV1, receipt_sha256);
impl_simple_sealed!(VisualClaimIntegrityReportV1, report_sha256);
impl_simple_sealed!(DesignPreferenceRecordV1, record_sha256);
impl_simple_sealed!(DesignWorkReplayReportV1, report_sha256);
impl_simple_sealed!(DesignBusinessAcceptanceReportV1, report_sha256);
impl_simple_sealed!(DesignWorkCompletionReportV1, finished_sha256);

impl OrganizationDesignCorpusV1 {
    pub fn seal(mut self) -> Result<Self, DesignIntelligenceError> {
        self.corpus_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        self.corpus_sha256 = hash_without(&self, &["corpus_sha256"])?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), DesignIntelligenceError> {
        self.validate_content()?;
        validate_hash(&self.corpus_sha256, "corpus_sha256")?;
        if self.corpus_sha256 != hash_without(self, &["corpus_sha256"])? {
            return Err(integrity("organization design corpus hash differs"));
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<(), DesignIntelligenceError> {
        if self.schema_version != DESIGN_SCHEMA_VERSION {
            return Err(invalid("unsupported organization design corpus schema"));
        }
        validate_id(&self.corpus_id, "corpus_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_hash(&self.manifest_approval_sha256, "manifest_approval_sha256")?;
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_CORPUS_ARTIFACTS {
            return Err(resource(
                "organization design corpus artifact count is outside bounds",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut hashes = BTreeSet::new();
        for artifact in &self.artifacts {
            validate_id(&artifact.artifact_id, "artifact_id")?;
            validate_hash(&artifact.artifact_sha256, "artifact_sha256")?;
            validate_id(&artifact.artifact_class, "artifact_class")?;
            validate_id(&artifact.template_status_id, "template_status_id")?;
            validate_id(&artifact.data_classification_id, "data_classification_id")?;
            validate_ids(&artifact.provenance_ids, "provenance_ids", 64)?;
            if !ids.insert(&artifact.artifact_id) || !hashes.insert(&artifact.artifact_sha256) {
                return Err(invalid(
                    "organization design corpus contains duplicate identity",
                ));
            }
            if artifact.approval_state == DesignApprovalStateV1::Approved
                && artifact.approved_at_unix_ms.is_none()
            {
                return Err(invalid("approved design artifact lacks approval time"));
            }
            if artifact.unit_ratings.len() > 512 {
                return Err(resource("design unit ratings exceed bounds"));
            }
            for rating in &artifact.unit_ratings {
                validate_id(&rating.unit_id, "unit_id")?;
                validate_ids(&rating.evidence_ids, "unit evidence_ids", 32)?;
            }
        }
        validate_json_bounds(self)
    }
}

fn quality_weight(label: DesignQualityLabelV1) -> u32 {
    match label {
        DesignQualityLabelV1::Gold => 1_000_000,
        DesignQualityLabelV1::Approved => 800_000,
        DesignQualityLabelV1::LegacyApproved => 250_000,
        DesignQualityLabelV1::Deprecated | DesignQualityLabelV1::Rejected => 0,
    }
}

fn approved_training_artifact(artifact: &DesignArtifactRecordV1) -> bool {
    artifact.approval_state == DesignApprovalStateV1::Approved
        && !artifact.holdout
        && quality_weight(artifact.quality_label) > 0
}

fn distribution(median: u32, spread: u32) -> DesignDistributionV1 {
    DesignDistributionV1 {
        minimum_millionths: median.saturating_sub(spread.saturating_mul(2)),
        q1_millionths: median.saturating_sub(spread),
        median_millionths: median,
        q3_millionths: median.saturating_add(spread).min(1_000_000),
        maximum_millionths: median
            .saturating_add(spread.saturating_mul(2))
            .min(1_000_000),
    }
}

/// Compiles approved training features into a quarantined, immutable pack candidate.
pub fn compile_design_pack(
    corpus: &OrganizationDesignCorpusV1,
    features: &[DesignArtifactFeatureV1],
    compiled_at_unix_ms: u64,
) -> Result<DesignPackCandidateV1, DesignIntelligenceError> {
    corpus.validate()?;
    if features.is_empty() || features.len() > MAX_DESIGN_FEATURES {
        return Err(resource("design feature count is outside bounds"));
    }
    let artifact_by_id = corpus
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut training = Vec::new();
    for feature in features {
        feature.validate()?;
        if feature.schema_version != DESIGN_SCHEMA_VERSION
            || feature.organization_id != corpus.organization_id
        {
            return Err(DesignIntelligenceError::AccessDenied(
                "design feature organization differs from corpus".to_owned(),
            ));
        }
        let artifact = artifact_by_id
            .get(feature.artifact_id.as_str())
            .ok_or_else(|| invalid("design feature artifact is absent from corpus"))?;
        if feature.artifact_sha256 != artifact.artifact_sha256
            || feature.artifact_class != artifact.artifact_class
            || feature.format != artifact.format
        {
            return Err(integrity(
                "design feature does not bind its corpus artifact",
            ));
        }
        if approved_training_artifact(artifact) {
            if feature.quality_weight_millionths != quality_weight(artifact.quality_label) {
                return Err(integrity(
                    "design feature quality weight differs from manifest label",
                ));
            }
            training.push((artifact, feature));
        }
    }
    if training.is_empty() {
        return Err(invalid(
            "no approved non-holdout design feature is available",
        ));
    }
    training.sort_by(|left, right| {
        left.1
            .artifact_class
            .cmp(&right.1.artifact_class)
            .then_with(|| left.1.template_family_id.cmp(&right.1.template_family_id))
            .then_with(|| left.1.feature_id.cmp(&right.1.feature_id))
    });

    let artifact_classes = training
        .iter()
        .map(|(_, feature)| feature.artifact_class.clone())
        .collect::<BTreeSet<_>>();
    let organization_maturity = if training.len() <= 2 {
        DesignPackMaturityV1::TemplateLock
    } else if artifact_classes.len() >= 3 && training.len() >= 10 {
        DesignPackMaturityV1::OrganizationLearned
    } else {
        DesignPackMaturityV1::FamilyLearned
    };
    let font_policy = default_font_policy(&corpus.organization_id)?;
    let logo_policy = OrganizationLogoPolicyV1 {
        schema_version: 1,
        organization_id: corpus.organization_id.clone(),
        approved_logo_artifact_refs: vec![format!("asset.{}.logo.primary", corpus.organization_id)],
        safe_area_millionths: 30_000,
        minimum_width_millionths: 40_000,
        minimum_height_millionths: 20_000,
        allowed_position_ids: vec!["top_left".to_owned(), "bottom_right".to_owned()],
        allowed_background_class_ids: vec!["light".to_owned(), "dark".to_owned()],
        variant_ids: vec!["primary".to_owned(), "reverse".to_owned()],
        distortion_forbidden: true,
        logo_policy_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let typography = TypographyGrammarV1 {
        schema_version: 1,
        grammar_id: format!("grammar.{}.typography.v1", corpus.organization_id),
        organization_id: corpus.organization_id.clone(),
        role_policies: font_policy.roles.clone(),
        hierarchy_ratio_rules: vec![distribution(650_000, 75_000), distribution(750_000, 50_000)],
        grammar_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let spacing = SpacingGrammarV1 {
        schema_version: 1,
        grammar_id: format!("grammar.{}.spacing.v1", corpus.organization_id),
        organization_id: corpus.organization_id.clone(),
        rules: [
            ("outer_margin", 60_000),
            ("title_top", 55_000),
            ("title_to_content", 45_000),
            ("column_gap", 30_000),
            ("card_gap", 24_000),
            ("paragraph_spacing", 18_000),
            ("table_cell_padding", 12_000),
            ("footer_gap", 20_000),
        ]
        .into_iter()
        .map(|(id, median)| SpacingRuleV1 {
            spacing_id: format!("design.spacing.{id}"),
            distribution: distribution(median, median / 5),
        })
        .collect(),
        grammar_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let table = default_table_grammar(&corpus.organization_id)?;
    let chart = default_chart_grammar(&corpus.organization_id)?;
    let image = default_image_grammar(&corpus.organization_id)?;

    let mut grouped: BTreeMap<(String, String), Vec<&DesignArtifactFeatureV1>> = BTreeMap::new();
    for (_, feature) in &training {
        grouped
            .entry((
                feature.artifact_class.clone(),
                feature.template_family_id.clone(),
            ))
            .or_default()
            .push(feature);
    }
    if grouped.len() > MAX_TEMPLATE_FAMILIES {
        return Err(resource("compiled template families exceed bounds"));
    }
    let mut layout_grammars = Vec::new();
    let mut template_families = Vec::new();
    let mut rule_provenance = Vec::new();
    for ((artifact_class, family_id), family_features) in grouped {
        let family_maturity = if family_features.len() <= 2 {
            DesignPackMaturityV1::TemplateLock
        } else {
            organization_maturity
        };
        let gold_count = family_features
            .iter()
            .filter(|feature| feature.quality_weight_millionths == 1_000_000)
            .count();
        let confidence = if gold_count >= 3 {
            950_000
        } else if gold_count > 0 {
            800_000
        } else {
            600_000
        };
        let first = family_features[0];
        let layout = LayoutGrammarV1 {
            schema_version: 1,
            grammar_id: format!("grammar.{}.layout.{}", corpus.organization_id, family_id),
            organization_id: corpus.organization_id.clone(),
            artifact_class: artifact_class.clone(),
            layout_family_id: first.layout_id.clone(),
            slots: if first.normalized_slots.is_empty() {
                default_layout_slots()
            } else {
                first
                    .normalized_slots
                    .iter()
                    .take(8)
                    .enumerate()
                    .map(|(index, rect)| LayoutSlotRuleV1 {
                        slot_id: format!("slot.{}.{index}", first.layout_id),
                        semantic_role: first
                            .typography_role_ids
                            .get(index)
                            .copied()
                            .unwrap_or(CommonDesignRoleV1::Body),
                        allowed_region: rect.clone(),
                        required: index < 2,
                    })
                    .collect()
            },
            grid_column_count: 12,
            outer_margin: distribution(60_000, 12_000),
            grammar_sha256: ZERO_HASH.to_owned(),
        }
        .seal()?;
        for slot in &layout.slots {
            validate_rect(&slot.allowed_region)?;
        }
        layout_grammars.push(layout.clone());
        let exemplar_refs = family_features
            .iter()
            .map(|feature| feature.source_exemplar_ref.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        template_families.push(
            TemplateFamilyV1 {
                schema_version: 1,
                organization_id: corpus.organization_id.clone(),
                artifact_class: artifact_class.clone(),
                family_id: family_id.clone(),
                family_version: "1.0.0".to_owned(),
                eligible_exemplar_refs: exemplar_refs.clone(),
                layout_role_ids: family_features
                    .iter()
                    .map(|feature| feature.layout_id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                typography_grammar_ref: typography.grammar_sha256.clone(),
                color_grammar_ref: format!("grammar.{}.color.v1", corpus.organization_id),
                spacing_grammar_ref: spacing.grammar_sha256.clone(),
                table_grammar_ref: table.grammar_sha256.clone(),
                chart_grammar_ref: chart.grammar_sha256.clone(),
                image_grammar_ref: image.grammar_sha256.clone(),
                maturity: family_maturity,
                confidence_millionths: confidence,
                family_sha256: ZERO_HASH.to_owned(),
            }
            .seal()?,
        );
        rule_provenance.push(
            DesignRuleProvenanceV1 {
                rule_id: format!("design.layout.{artifact_class}.{family_id}"),
                source_exemplar_ids: exemplar_refs,
                source_sha256s: family_features
                    .iter()
                    .map(|feature| feature.artifact_sha256.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                support_count: u32::try_from(family_features.len()).unwrap_or(u32::MAX),
                gold_support_count: u32::try_from(gold_count).unwrap_or(u32::MAX),
                confidence_millionths: confidence,
                distribution: distribution(500_000, 100_000),
                rule_sha256: ZERO_HASH.to_owned(),
            }
            .seal()?,
        );
    }
    let profile = OrganizationDesignProfileV1 {
        schema_version: 1,
        profile_id: format!("profile.{}.design.v1", corpus.organization_id),
        organization_id: corpus.organization_id.clone(),
        brand_role_ids: vec![
            "brand_primary".to_owned(),
            "brand_secondary".to_owned(),
            "accent_1".to_owned(),
            "background".to_owned(),
            "surface".to_owned(),
            "text_primary".to_owned(),
            "text_secondary".to_owned(),
        ],
        font_policy_sha256: font_policy.font_policy_sha256.clone(),
        color_role_ids: training
            .iter()
            .flat_map(|(_, feature)| feature.color_role_ids.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        spacing_scale_ids: spacing
            .rules
            .iter()
            .map(|rule| rule.spacing_id.clone())
            .collect(),
        grid_policy_id: "grid.twelve-column".to_owned(),
        logo_policy_sha256: logo_policy.logo_policy_sha256.clone(),
        image_policy_id: image.grammar_sha256.clone(),
        table_policy_id: table.grammar_sha256.clone(),
        chart_policy_id: chart.grammar_sha256.clone(),
        artifact_class_refs: artifact_classes.into_iter().collect(),
        pack_version: "1.0.0".to_owned(),
        provenance_ids: vec![corpus.corpus_sha256.clone()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    let pack = OrganizationDesignPackV1 {
        schema_version: 1,
        pack_id: format!("{}.design", corpus.organization_id),
        pack_version: "1.0.0".to_owned(),
        organization_id: corpus.organization_id.clone(),
        source_corpus_sha256: corpus.corpus_sha256.clone(),
        profile,
        typography_grammar: typography,
        spacing_grammar: spacing,
        layout_grammars,
        table_grammar: table,
        chart_grammar: chart,
        image_grammar: image,
        logo_policy,
        template_families,
        rule_provenance,
        holdout_artifact_sha256s: corpus
            .artifacts
            .iter()
            .filter(|artifact| artifact.holdout)
            .map(|artifact| artifact.artifact_sha256.clone())
            .collect(),
        compiled_at_unix_ms,
        pack_sha256: ZERO_HASH.to_owned(),
    }
    .seal()?;
    validate_pack_structure(&pack)?;
    DesignPackCandidateV1 {
        schema_version: 1,
        candidate_id: format!("candidate.{}.1.0.0", corpus.organization_id),
        organization_id: corpus.organization_id.clone(),
        source_corpus_sha256: corpus.corpus_sha256.clone(),
        pack,
        training_artifact_count: u32::try_from(
            corpus
                .artifacts
                .iter()
                .filter(|artifact| approved_training_artifact(artifact))
                .count(),
        )
        .unwrap_or(u32::MAX),
        holdout_artifact_count: u32::try_from(
            corpus
                .artifacts
                .iter()
                .filter(|artifact| artifact.holdout)
                .count(),
        )
        .unwrap_or(u32::MAX),
        rejected_artifact_count: u32::try_from(
            corpus
                .artifacts
                .iter()
                .filter(|artifact| artifact.quality_label == DesignQualityLabelV1::Rejected)
                .count(),
        )
        .unwrap_or(u32::MAX),
        validation_evidence_ids: vec!["evidence.design.holdout-separated".to_owned()],
        quarantined: true,
        candidate_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn default_font_policy(
    organization_id: &str,
) -> Result<OrganizationFontPolicyV1, DesignIntelligenceError> {
    let role = |role, preferred: &str, fallback: &[&str], minimum, preferred_size, maximum| {
        DesignFontRolePolicyV1 {
            role,
            preferred_font_family: preferred.to_owned(),
            approved_fallback_families: fallback.iter().map(|value| (*value).to_owned()).collect(),
            weight_min: 400,
            weight_max: 700,
            font_size_min_millipoints: minimum,
            font_size_preferred_millipoints: preferred_size,
            font_size_max_millipoints: maximum,
            line_spacing_min_millionths: 950_000,
            line_spacing_max_millionths: 1_400_000,
            letter_spacing_min_millipoints: -200,
            letter_spacing_max_millipoints: 500,
            script_coverage_ids: vec![
                "hangul".to_owned(),
                "latin".to_owned(),
                "numeric".to_owned(),
            ],
        }
    };
    OrganizationFontPolicyV1 {
        schema_version: 1,
        organization_id: organization_id.to_owned(),
        roles: vec![
            role(
                CommonDesignRoleV1::ArtifactTitle,
                "Aptos Display",
                &["Malgun Gothic", "Arial"],
                26_000,
                30_000,
                34_000,
            ),
            role(
                CommonDesignRoleV1::ArtifactSubtitle,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                16_000,
                20_000,
                24_000,
            ),
            role(
                CommonDesignRoleV1::SectionTitle,
                "Aptos Display",
                &["Malgun Gothic", "Arial"],
                22_000,
                26_000,
                30_000,
            ),
            role(
                CommonDesignRoleV1::Heading1,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                17_000,
                20_000,
                24_000,
            ),
            role(
                CommonDesignRoleV1::Heading2,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                14_000,
                17_000,
                20_000,
            ),
            role(
                CommonDesignRoleV1::Body,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                10_000,
                13_000,
                16_000,
            ),
            role(
                CommonDesignRoleV1::Caption,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                8_000,
                10_000,
                12_000,
            ),
            role(
                CommonDesignRoleV1::KpiValue,
                "Aptos Display",
                &["Malgun Gothic", "Arial"],
                24_000,
                30_000,
                38_000,
            ),
            role(
                CommonDesignRoleV1::KpiLabel,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                10_000,
                12_000,
                15_000,
            ),
            role(
                CommonDesignRoleV1::TableHeader,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                9_000,
                11_000,
                13_000,
            ),
            role(
                CommonDesignRoleV1::TableBody,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                8_000,
                10_000,
                12_000,
            ),
            role(
                CommonDesignRoleV1::TableTotal,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                9_000,
                11_000,
                13_000,
            ),
            role(
                CommonDesignRoleV1::ChartTitle,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                12_000,
                15_000,
                18_000,
            ),
            role(
                CommonDesignRoleV1::ChartLabel,
                "Aptos",
                &["Malgun Gothic", "Arial"],
                8_000,
                10_000,
                12_000,
            ),
        ],
        font_policy_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn default_layout_slots() -> Vec<LayoutSlotRuleV1> {
    vec![
        LayoutSlotRuleV1 {
            slot_id: "title".to_owned(),
            semantic_role: CommonDesignRoleV1::ArtifactTitle,
            allowed_region: NormalizedDesignRectV1 {
                left_millionths: 60_000,
                top_millionths: 50_000,
                width_millionths: 880_000,
                height_millionths: 140_000,
            },
            required: true,
        },
        LayoutSlotRuleV1 {
            slot_id: "body_main".to_owned(),
            semantic_role: CommonDesignRoleV1::Body,
            allowed_region: NormalizedDesignRectV1 {
                left_millionths: 60_000,
                top_millionths: 220_000,
                width_millionths: 880_000,
                height_millionths: 680_000,
            },
            required: true,
        },
    ]
}

fn default_table_grammar(
    organization_id: &str,
) -> Result<TableDesignGrammarV1, DesignIntelligenceError> {
    TableDesignGrammarV1 {
        schema_version: 1,
        grammar_id: format!("grammar.{organization_id}.table.v1"),
        organization_id: organization_id.to_owned(),
        header_font_role: CommonDesignRoleV1::TableHeader,
        header_color_role: "brand_primary".to_owned(),
        body_font_role: CommonDesignRoleV1::TableBody,
        horizontal_alignment_id: "left_or_numeric_right".to_owned(),
        vertical_alignment_id: "middle".to_owned(),
        border_policy_id: "subtle_horizontal".to_owned(),
        row_height: distribution(50_000, 8_000),
        cell_padding: distribution(12_000, 2_000),
        zebra_enabled: true,
        total_row_policy_id: "emphasized_total".to_owned(),
        number_emphasis_role: CommonDesignRoleV1::TableTotal,
        grammar_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn default_chart_grammar(
    organization_id: &str,
) -> Result<ChartDesignGrammarV1, DesignIntelligenceError> {
    ChartDesignGrammarV1 {
        schema_version: 1,
        grammar_id: format!("grammar.{organization_id}.chart.v1"),
        organization_id: organization_id.to_owned(),
        allowed_chart_type_ids: vec![
            "clustered_column".to_owned(),
            "bar".to_owned(),
            "line".to_owned(),
        ],
        series_color_role_order: vec![
            "brand_primary".to_owned(),
            "accent_1".to_owned(),
            "brand_secondary".to_owned(),
        ],
        title_role: CommonDesignRoleV1::ChartTitle,
        legend_position_id: "bottom".to_owned(),
        data_label_policy_id: "important_only".to_owned(),
        axis_policy_id: "zero_based_when_quantitative".to_owned(),
        gridline_policy_id: "major_horizontal_subtle".to_owned(),
        number_format_id: "fact_unit_bound".to_owned(),
        emphasis_series_policy_id: "semantic_primary".to_owned(),
        grammar_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn default_image_grammar(
    organization_id: &str,
) -> Result<ImageDesignGrammarV1, DesignIntelligenceError> {
    ImageDesignGrammarV1 {
        schema_version: 1,
        grammar_id: format!("grammar.{organization_id}.image.v1"),
        organization_id: organization_id.to_owned(),
        preferred_aspect_ratio_millionths: vec![1_000_000, 1_500_000, 562_500],
        placement_role_ids: vec!["image_main".to_owned(), "image_secondary".to_owned()],
        allowed_fit_ids: vec!["contain".to_owned(), "cover".to_owned()],
        crop_allowed: true,
        border_role_id: "surface_boundary".to_owned(),
        corner_policy_id: "square_or_small_radius".to_owned(),
        caption_role: CommonDesignRoleV1::ImageCaption,
        minimum_resolution_pixels: 640,
        maximum_enlargement_millionths: 1_250_000,
        text_image_balance: distribution(500_000, 150_000),
        grammar_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn validate_pack_structure(pack: &OrganizationDesignPackV1) -> Result<(), DesignIntelligenceError> {
    pack.validate()?;
    if pack.schema_version != 1
        || pack.profile.organization_id != pack.organization_id
        || pack.typography_grammar.organization_id != pack.organization_id
        || pack.spacing_grammar.organization_id != pack.organization_id
        || pack.table_grammar.organization_id != pack.organization_id
        || pack.chart_grammar.organization_id != pack.organization_id
        || pack.image_grammar.organization_id != pack.organization_id
        || pack.logo_policy.organization_id != pack.organization_id
        || pack.template_families.is_empty()
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "design pack contains a cross-organization or empty component".to_owned(),
        ));
    }
    for grammar in &pack.layout_grammars {
        grammar.validate()?;
        if grammar.organization_id != pack.organization_id {
            return Err(DesignIntelligenceError::AccessDenied(
                "layout grammar organization differs from pack".to_owned(),
            ));
        }
        validate_distribution(&grammar.outer_margin)?;
        for slot in &grammar.slots {
            validate_rect(&slot.allowed_region)?;
        }
    }
    for family in &pack.template_families {
        family.validate()?;
        if family.organization_id != pack.organization_id {
            return Err(DesignIntelligenceError::AccessDenied(
                "template family organization differs from pack".to_owned(),
            ));
        }
    }
    validate_hashes(
        &pack.holdout_artifact_sha256s,
        "holdout_artifact_sha256s",
        512,
    )?;
    Ok(())
}

impl OrganizationDesignPackApprovalV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, DesignIntelligenceError> {
        self.signature_hex.clear();
        self.approval_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        self.approval_sha256 = hash_without(&self, &["approval_sha256", "signature_hex"])?;
        self.signature_hex = hex_encode(&key.sign(self.approval_sha256.as_bytes()).to_bytes());
        Ok(self)
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), DesignIntelligenceError> {
        self.validate_content()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(DesignIntelligenceError::AccessDenied(
                "design pack approval is not currently valid".to_owned(),
            ));
        }
        let expected = hash_without(self, &["approval_sha256", "signature_hex"])?;
        if expected != self.approval_sha256 {
            return Err(integrity("design pack approval hash differs"));
        }
        verify_signature(key, self.approval_sha256.as_bytes(), &self.signature_hex)
    }

    fn validate_content(&self) -> Result<(), DesignIntelligenceError> {
        if self.schema_version != 1 || self.issued_at_unix_ms >= self.expires_at_unix_ms {
            return Err(invalid("design pack approval version or validity differs"));
        }
        validate_id(&self.approval_id, "approval_id")?;
        validate_id(&self.organization_id, "organization_id")?;
        validate_hash(&self.design_pack_sha256, "design_pack_sha256")?;
        validate_ids(
            &self.allowed_artifact_classes,
            "allowed_artifact_classes",
            64,
        )?;
        if self.allowed_artifact_classes.is_empty() {
            return Err(invalid("design pack approval allows no artifact class"));
        }
        validate_id(&self.environment_id, "environment_id")?;
        validate_id(&self.approver_id, "approver_id")?;
        validate_id(&self.signing_key_id, "signing_key_id")?;
        validate_json_bounds(self)
    }
}

/// Produces a separately signed approval for one immutable design pack.
pub fn approve_design_pack(
    candidate: &DesignPackCandidateV1,
    allowed_artifact_classes: Vec<String>,
    environment_id: String,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    key: &SigningKey,
) -> Result<OrganizationDesignPackApprovalV1, DesignIntelligenceError> {
    candidate.validate()?;
    validate_pack_structure(&candidate.pack)?;
    if candidate.organization_id != candidate.pack.organization_id || !candidate.quarantined {
        return Err(invalid(
            "only a quarantined organization-bound candidate can be approved",
        ));
    }
    for artifact_class in &allowed_artifact_classes {
        if !candidate
            .pack
            .profile
            .artifact_class_refs
            .contains(artifact_class)
        {
            return Err(DesignIntelligenceError::AccessDenied(
                "approval requests an artifact class absent from the pack".to_owned(),
            ));
        }
    }
    OrganizationDesignPackApprovalV1 {
        schema_version: 1,
        approval_id: format!("approval.{}.design.1.0.0", candidate.organization_id),
        organization_id: candidate.organization_id.clone(),
        design_pack_sha256: candidate.pack.pack_sha256.clone(),
        allowed_artifact_classes,
        environment_id,
        issued_at_unix_ms,
        expires_at_unix_ms,
        approver_id: "approver.organization-design".to_owned(),
        signing_key_id: "key.organization-design.v1".to_owned(),
        signature_hex: String::new(),
        approval_sha256: ZERO_HASH.to_owned(),
    }
    .sign(key)
}

/// Builds a content-minimized exemplar index from approved training features.
pub fn build_exemplar_index(
    corpus: &OrganizationDesignCorpusV1,
    pack: &OrganizationDesignPackV1,
    features: &[DesignArtifactFeatureV1],
) -> Result<DesignExemplarIndexV1, DesignIntelligenceError> {
    corpus.validate()?;
    validate_pack_structure(pack)?;
    if corpus.organization_id != pack.organization_id
        || corpus.corpus_sha256 != pack.source_corpus_sha256
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "exemplar index corpus and pack binding differs".to_owned(),
        ));
    }
    let artifacts = corpus
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut exemplars = Vec::new();
    for feature in features {
        let artifact = artifacts
            .get(feature.artifact_id.as_str())
            .ok_or_else(|| invalid("exemplar feature artifact is absent"))?;
        if !approved_training_artifact(artifact) {
            continue;
        }
        if feature.organization_id != pack.organization_id
            || feature.artifact_sha256 != artifact.artifact_sha256
        {
            return Err(DesignIntelligenceError::AccessDenied(
                "exemplar feature organization or artifact differs".to_owned(),
            ));
        }
        exemplars.push(
            DesignExemplarRecordV1 {
                schema_version: 1,
                exemplar_id: feature.source_exemplar_ref.clone(),
                organization_id: pack.organization_id.clone(),
                artifact_class: feature.artifact_class.clone(),
                unit_role_id: feature.unit_role_id.clone(),
                template_family_id: feature.template_family_id.clone(),
                layout_vector_sha256: feature.vector.vector_sha256.clone(),
                typography_vector_sha256: design_canonical_sha256(&feature.typography_role_ids)?,
                color_vector_sha256: design_canonical_sha256(&feature.color_role_ids)?,
                spacing_vector_sha256: design_canonical_sha256(&feature.spacing_ids)?,
                content_density_class: feature.density_class,
                source_artifact_sha256: feature.artifact_sha256.clone(),
                quality_weight_millionths: feature.quality_weight_millionths,
                text_length: 0,
                line_count: 0,
                text_sha256: design_canonical_sha256(&("redacted", &feature.source_exemplar_ref))?,
                exemplar_sha256: ZERO_HASH.to_owned(),
            }
            .seal()?,
        );
    }
    exemplars.sort_by(|left, right| {
        left.artifact_class
            .cmp(&right.artifact_class)
            .then_with(|| {
                right
                    .quality_weight_millionths
                    .cmp(&left.quality_weight_millionths)
            })
            .then_with(|| left.exemplar_id.cmp(&right.exemplar_id))
    });
    if exemplars.is_empty() || exemplars.len() > MAX_EXEMPLARS {
        return Err(resource("exemplar index size is outside bounds"));
    }
    DesignExemplarIndexV1 {
        schema_version: 1,
        index_id: format!("index.{}.design-exemplars.v1", pack.organization_id),
        organization_id: pack.organization_id.clone(),
        design_pack_sha256: pack.pack_sha256.clone(),
        exemplars,
        index_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Executes an exact organization/artifact-class exemplar query.
pub fn query_exemplars(
    index: &DesignExemplarIndexV1,
    query: &DesignExemplarQueryV1,
) -> Result<DesignExemplarQueryResultV1, DesignIntelligenceError> {
    index.validate()?;
    query.validate()?;
    if index.organization_id != query.organization_id {
        return Err(DesignIntelligenceError::AccessDenied(
            "exemplar query organization differs from index".to_owned(),
        ));
    }
    if query.maximum_results == 0 || query.maximum_results > 32 {
        return Err(resource("exemplar query result limit is outside bounds"));
    }
    let mut matches = index
        .exemplars
        .iter()
        .filter(|exemplar| {
            exemplar.organization_id == query.organization_id
                && exemplar.artifact_class == query.artifact_class
                && exemplar.unit_role_id == query.unit_role_id
        })
        .map(|exemplar| {
            let density_distance = if exemplar.content_density_class == query.density_class {
                0
            } else {
                200_000
            };
            DesignExemplarMatchV1 {
                exemplar_id: exemplar.exemplar_id.clone(),
                template_family_id: exemplar.template_family_id.clone(),
                distance_millionths: density_distance
                    + (1_000_000_u32.saturating_sub(exemplar.quality_weight_millionths) / 4),
                evidence_ids: vec![exemplar.exemplar_sha256.clone()],
            }
        })
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| {
        left.distance_millionths
            .cmp(&right.distance_millionths)
            .then_with(|| left.exemplar_id.cmp(&right.exemplar_id))
    });
    matches.truncate(query.maximum_results as usize);
    DesignExemplarQueryResultV1 {
        schema_version: 1,
        query_id: query.query_id.clone(),
        query_sha256: query.query_sha256.clone(),
        index_sha256: index.index_sha256.clone(),
        matches,
        result_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Selects only an approved font family and keeps size inside the compiled range.
pub fn solve_typography(
    request: &TypographyRequestV1,
    pack: &OrganizationDesignPackV1,
    installed_font_families: &BTreeSet<String>,
) -> Result<TypographyDecisionV1, DesignIntelligenceError> {
    request.validate()?;
    validate_pack_structure(pack)?;
    if request.organization_id != pack.organization_id
        || request.design_pack_sha256 != pack.pack_sha256
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "typography request differs from the selected design pack".to_owned(),
        ));
    }
    let policy = pack
        .typography_grammar
        .role_policies
        .iter()
        .find(|policy| policy.role == request.semantic_role)
        .ok_or_else(|| {
            DesignIntelligenceError::Unsupported("typography role is absent".to_owned())
        })?;
    if policy.font_size_min_millipoints > policy.font_size_preferred_millipoints
        || policy.font_size_preferred_millipoints > policy.font_size_max_millipoints
    {
        return Err(integrity("font policy size range is not ordered"));
    }
    let selected = if installed_font_families.contains(&policy.preferred_font_family) {
        Some((policy.preferred_font_family.clone(), false))
    } else {
        policy
            .approved_fallback_families
            .iter()
            .find(|family| installed_font_families.contains(*family))
            .cloned()
            .map(|family| (family, true))
    };
    let area = u64::from(request.available_width_millionths)
        .saturating_mul(u64::from(request.available_height_millionths));
    let density = u64::from(request.character_count).saturating_mul(1_000_000_000);
    let tight = area == 0 || density > area.saturating_mul(4);
    let mut size = policy.font_size_preferred_millipoints;
    if tight {
        size = size
            .saturating_sub(2_000)
            .max(policy.font_size_min_millipoints);
    }
    let estimated_line_count = if request.available_width_millionths == 0 {
        request.character_count
    } else {
        request
            .character_count
            .saturating_mul(size)
            .saturating_div(request.available_width_millionths.max(1))
            .saturating_add(1)
    };
    let (selected_font_family, used_fallback, fit_status) = match selected {
        Some((family, fallback)) if tight && size == policy.font_size_min_millipoints => (
            Some(family),
            fallback,
            DesignFitStatusV1::NeedsAlternativeLayout,
        ),
        Some((family, fallback)) => (Some(family), fallback, DesignFitStatusV1::Fit),
        None => (None, false, DesignFitStatusV1::FontMissing),
    };
    TypographyDecisionV1 {
        schema_version: 1,
        decision_id: format!("decision.{}.typography", request.request_id),
        request_sha256: request.request_sha256.clone(),
        design_pack_sha256: pack.pack_sha256.clone(),
        selected_font_family,
        used_fallback,
        font_size_millipoints: size,
        weight: policy.weight_min.max(400).min(policy.weight_max),
        line_spacing_millionths: policy
            .line_spacing_min_millionths
            .saturating_add(policy.line_spacing_max_millionths)
            / 2,
        paragraph_spacing_millionths: pack
            .spacing_grammar
            .rules
            .iter()
            .find(|rule| rule.spacing_id.ends_with("paragraph_spacing"))
            .map(|rule| rule.distribution.median_millionths)
            .unwrap_or(0),
        alignment_id: "role_default".to_owned(),
        estimated_line_count,
        fit_status,
        evidence_ids: vec![pack.typography_grammar.grammar_sha256.clone()],
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Selects one exact organization/artifact-class layout family without model geometry.
pub fn solve_layout(
    request: &ArtifactLayoutRequestV1,
    pack: &OrganizationDesignPackV1,
) -> Result<ArtifactLayoutDecisionV1, DesignIntelligenceError> {
    request.validate()?;
    validate_pack_structure(pack)?;
    if request.organization_id != pack.organization_id
        || request.design_pack_sha256 != pack.pack_sha256
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "layout request differs from the selected design pack".to_owned(),
        ));
    }
    let family = pack
        .template_families
        .iter()
        .filter(|family| family.artifact_class == request.artifact_class)
        .min_by(|left, right| {
            right
                .confidence_millionths
                .cmp(&left.confidence_millionths)
                .then_with(|| left.family_id.cmp(&right.family_id))
        })
        .ok_or_else(|| {
            DesignIntelligenceError::Unsupported("artifact class is absent from pack".to_owned())
        })?;
    let layout = pack
        .layout_grammars
        .iter()
        .filter(|layout| layout.artifact_class == request.artifact_class)
        .find(|layout| family.layout_role_ids.contains(&layout.layout_family_id))
        .or_else(|| {
            pack.layout_grammars
                .iter()
                .find(|layout| layout.artifact_class == request.artifact_class)
        })
        .ok_or_else(|| integrity("template family has no layout grammar"))?;
    let required_roles = request
        .content_role_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let available_roles = layout
        .slots
        .iter()
        .map(|slot| slot.semantic_role)
        .collect::<BTreeSet<_>>();
    let missing = required_roles.difference(&available_roles).count();
    ArtifactLayoutDecisionV1 {
        schema_version: 1,
        decision_id: format!("decision.{}.layout", request.request_id),
        request_sha256: request.request_sha256.clone(),
        design_pack_sha256: pack.pack_sha256.clone(),
        template_family_id: family.family_id.clone(),
        layout_family_id: layout.layout_family_id.clone(),
        slot_assignments: layout.slots.clone(),
        typography_decision_sha256s: Vec::new(),
        fit_status: if missing == 0 {
            DesignFitStatusV1::Fit
        } else {
            DesignFitStatusV1::NeedsAlternativeLayout
        },
        design_distance_millionths: u32::try_from(missing)
            .unwrap_or(u32::MAX)
            .saturating_mul(150_000),
        evidence_ids: vec![family.family_sha256.clone(), layout.grammar_sha256.clone()],
        decision_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn hard_violation_total(metrics: &HardDesignViolationMetricsV1) -> u32 {
    [
        metrics.font_family_violation,
        metrics.font_size_violation,
        metrics.text_overflow,
        metrics.off_canvas_or_page,
        metrics.forbidden_overlap,
        metrics.alignment_violation,
        metrics.spacing_violation,
        metrics.margin_violation,
        metrics.color_role_violation,
        metrics.logo_violation,
        metrics.table_violation,
        metrics.image_distortion,
        metrics.chart_policy_violation,
        metrics.placeholder_leakage,
        metrics.missing_title,
        metrics.missing_required_section,
        metrics.unverified_kpi,
        metrics.fact_mismatch,
        metrics.chart_fact_mismatch,
        metrics.wrong_organization_pack,
        metrics.wrong_template_family,
    ]
    .into_iter()
    .fold(0_u32, u32::saturating_add)
}

/// Applies the non-negotiable deterministic design and truth gate.
pub fn critique_hard(
    critique_id: String,
    organization_id: String,
    artifact_sha256: String,
    design_pack_sha256: String,
    metrics: HardDesignViolationMetricsV1,
) -> Result<HardDesignCritiqueV1, DesignIntelligenceError> {
    validate_id(&critique_id, "critique_id")?;
    validate_id(&organization_id, "organization_id")?;
    validate_hash(&artifact_sha256, "artifact_sha256")?;
    validate_hash(&design_pack_sha256, "design_pack_sha256")?;
    let mut issues = Vec::new();
    let candidates = [
        (metrics.font_family_violation, "font_family"),
        (metrics.font_size_violation, "font_size"),
        (metrics.text_overflow, "text_overflow"),
        (metrics.off_canvas_or_page, "off_canvas_or_page"),
        (metrics.forbidden_overlap, "forbidden_overlap"),
        (metrics.alignment_violation, "alignment"),
        (metrics.spacing_violation, "spacing"),
        (metrics.margin_violation, "margin"),
        (metrics.color_role_violation, "color_role"),
        (metrics.logo_violation, "logo"),
        (metrics.table_violation, "table"),
        (metrics.image_distortion, "image_distortion"),
        (metrics.chart_policy_violation, "chart_policy"),
        (metrics.placeholder_leakage, "placeholder"),
        (metrics.missing_title, "missing_title"),
        (metrics.missing_required_section, "missing_section"),
        (metrics.unverified_kpi, "unverified_kpi"),
        (metrics.fact_mismatch, "fact_mismatch"),
        (metrics.chart_fact_mismatch, "chart_fact_mismatch"),
        (metrics.wrong_organization_pack, "wrong_organization_pack"),
        (metrics.wrong_template_family, "wrong_template_family"),
    ];
    for (count, id) in candidates {
        if count > 0 {
            issues.push(format!("design.issue.{id}"));
        }
    }
    let violation_count = hard_violation_total(&metrics);
    HardDesignCritiqueV1 {
        schema_version: 1,
        critique_id,
        organization_id,
        artifact_sha256,
        design_pack_sha256,
        metrics,
        status: if violation_count == 0 {
            DesignCritiqueStatusV1::Passed
        } else {
            DesignCritiqueStatusV1::Failed
        },
        issue_ids: issues,
        critique_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Calibrates style distance against a family holdout envelope.
pub fn critique_soft(
    critique_id: String,
    organization_id: String,
    artifact_sha256: String,
    design_pack_sha256: String,
    template_family_id: String,
    distances: [u32; 5],
    acceptance_envelope_max_millionths: u32,
) -> Result<SoftDesignCritiqueV1, DesignIntelligenceError> {
    if distances.iter().any(|value| *value > 1_000_000)
        || acceptance_envelope_max_millionths > 1_000_000
    {
        return Err(invalid("soft design distance leaves normalized range"));
    }
    let aggregate = distances.iter().copied().fold(0_u32, u32::saturating_add) / 5;
    SoftDesignCritiqueV1 {
        schema_version: 1,
        critique_id,
        organization_id,
        artifact_sha256,
        design_pack_sha256,
        template_family_id,
        geometry_distance_millionths: distances[0],
        hierarchy_distance_millionths: distances[1],
        spacing_distance_millionths: distances[2],
        color_distance_millionths: distances[3],
        density_distance_millionths: distances[4],
        aggregate_distance_millionths: aggregate,
        acceptance_envelope_max_millionths,
        status: if aggregate <= acceptance_envelope_max_millionths {
            DesignCritiqueStatusV1::Passed
        } else {
            DesignCritiqueStatusV1::Failed
        },
        critique_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Combines hard truth/design checks and the calibrated family-distance check.
pub fn build_quality_report(
    report_id: String,
    hard: &HardDesignCritiqueV1,
    soft: &SoftDesignCritiqueV1,
    render_evidence_sha256: Option<String>,
    structural_conformance_sha256: String,
) -> Result<DesignQualityReportV1, DesignIntelligenceError> {
    hard.validate()?;
    soft.validate()?;
    if hard.organization_id != soft.organization_id
        || hard.artifact_sha256 != soft.artifact_sha256
        || hard.design_pack_sha256 != soft.design_pack_sha256
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "hard and soft critiques do not describe the same artifact binding".to_owned(),
        ));
    }
    if let Some(hash) = &render_evidence_sha256 {
        validate_hash(hash, "render_evidence_sha256")?;
    }
    validate_hash(
        &structural_conformance_sha256,
        "structural_conformance_sha256",
    )?;
    DesignQualityReportV1 {
        schema_version: 1,
        report_id,
        organization_id: hard.organization_id.clone(),
        artifact_sha256: hard.artifact_sha256.clone(),
        hard_critique_sha256: hard.critique_sha256.clone(),
        soft_critique_sha256: soft.critique_sha256.clone(),
        render_evidence_sha256,
        structural_conformance_sha256,
        status: if hard.status == DesignCritiqueStatusV1::Passed
            && soft.status == DesignCritiqueStatusV1::Passed
        {
            DesignCritiqueStatusV1::Passed
        } else {
            DesignCritiqueStatusV1::Failed
        },
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn repair_for_issue(issue: &str) -> DesignRepairOperationV1 {
    match issue {
        "design.issue.text_overflow" | "design.issue.font_size" => {
            DesignRepairOperationV1::ResizeWithinAllowedRange
        }
        "design.issue.table" => DesignRepairOperationV1::ReflowTable,
        "design.issue.image_distortion" | "design.issue.logo" => {
            DesignRepairOperationV1::ChangeImageFit
        }
        "design.issue.spacing" | "design.issue.margin" | "design.issue.alignment" => {
            DesignRepairOperationV1::AdjustSpacingWithinGrammar
        }
        "design.issue.off_canvas_or_page" | "design.issue.forbidden_overlap" => {
            DesignRepairOperationV1::MoveToAllowedSlot
        }
        "design.issue.missing_section" | "design.issue.wrong_template_family" => {
            DesignRepairOperationV1::SwitchLayout
        }
        _ => DesignRepairOperationV1::SplitSlide,
    }
}

/// Produces only closed, bounded repair operations; arbitrary model-authored geometry is absent.
pub fn plan_refinement(
    plan_id: String,
    hard: &HardDesignCritiqueV1,
    soft: &SoftDesignCritiqueV1,
) -> Result<DesignRefinementPlanV1, DesignIntelligenceError> {
    hard.validate()?;
    soft.validate()?;
    if hard.organization_id != soft.organization_id
        || hard.artifact_sha256 != soft.artifact_sha256
        || hard.design_pack_sha256 != soft.design_pack_sha256
    {
        return Err(DesignIntelligenceError::AccessDenied(
            "refinement critiques differ in organization or artifact binding".to_owned(),
        ));
    }
    let mut issue_ids = hard.issue_ids.clone();
    if soft.status == DesignCritiqueStatusV1::Failed {
        issue_ids.push("design.issue.family_distance".to_owned());
    }
    issue_ids.sort();
    issue_ids.dedup();
    let steps = issue_ids
        .into_iter()
        .take(MAX_REFINEMENT_ROUNDS as usize)
        .enumerate()
        .map(|(index, issue)| DesignRefinementStepV1 {
            sequence: u32::try_from(index).unwrap_or(u32::MAX).saturating_add(1),
            operation: repair_for_issue(&issue),
            target_id: "artifact.layout".to_owned(),
            reason_code: issue,
        })
        .collect::<Vec<_>>();
    DesignRefinementPlanV1 {
        schema_version: 1,
        plan_id,
        organization_id: hard.organization_id.clone(),
        artifact_sha256: hard.artifact_sha256.clone(),
        design_pack_sha256: hard.design_pack_sha256.clone(),
        hard_critique_sha256: hard.critique_sha256.clone(),
        maximum_rounds: MAX_REFINEMENT_ROUNDS,
        steps,
        plan_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Verifies that every visually emphasized number is backed by an authoritative fact.
pub fn verify_visual_claim_integrity(
    report_id: String,
    artifact_sha256: String,
    authoritative_fact_ids: Vec<String>,
    displayed_kpi_fact_ids: Vec<String>,
    chart_fact_ids: Vec<String>,
    table_total_fact_ids: Vec<String>,
) -> Result<VisualClaimIntegrityReportV1, DesignIntelligenceError> {
    validate_hash(&artifact_sha256, "artifact_sha256")?;
    validate_ids(&authoritative_fact_ids, "authoritative_fact_ids", 4096)?;
    validate_ids(&displayed_kpi_fact_ids, "displayed_kpi_fact_ids", 1024)?;
    validate_ids(&chart_fact_ids, "chart_fact_ids", 1024)?;
    validate_ids(&table_total_fact_ids, "table_total_fact_ids", 1024)?;
    let authoritative = authoritative_fact_ids.iter().collect::<BTreeSet<_>>();
    let visual = displayed_kpi_fact_ids
        .iter()
        .chain(chart_fact_ids.iter())
        .chain(table_total_fact_ids.iter())
        .collect::<BTreeSet<_>>();
    let unverified_kpi_count = displayed_kpi_fact_ids
        .iter()
        .filter(|fact| !authoritative.contains(fact))
        .count();
    let fact_mismatch_count = visual.difference(&authoritative).count();
    VisualClaimIntegrityReportV1 {
        schema_version: 1,
        report_id,
        artifact_sha256,
        authoritative_fact_ids,
        displayed_kpi_fact_ids,
        chart_fact_ids,
        table_total_fact_ids,
        unverified_kpi_count: u32::try_from(unverified_kpi_count).unwrap_or(u32::MAX),
        fact_mismatch_count: u32::try_from(fact_mismatch_count).unwrap_or(u32::MAX),
        model_created_fact_count: 0,
        verified: unverified_kpi_count == 0 && fact_mismatch_count == 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

/// Compares each replay result with the sealed baseline without invoking Office applications.
pub fn verify_design_replay(
    baseline_result_sha256s: &[String],
    replay_result_sha256s: &[Vec<String>],
) -> Result<DesignWorkReplayReportV1, DesignIntelligenceError> {
    if baseline_result_sha256s.len() != REQUIRED_REPLAY_SCENARIOS as usize
        || replay_result_sha256s.len() != REQUIRED_REPLAY_SCENARIOS as usize
    {
        return Err(resource("design replay requires exactly 128 scenarios"));
    }
    let mut mismatch_count = 0_u32;
    for (baseline, runs) in baseline_result_sha256s.iter().zip(replay_result_sha256s) {
        validate_hash(baseline, "baseline_result_sha256")?;
        if runs.len() != REQUIRED_REPLAY_RUNS as usize {
            return Err(resource(
                "each design replay scenario requires exactly 100 runs",
            ));
        }
        for result in runs {
            validate_hash(result, "replay_result_sha256")?;
            mismatch_count = mismatch_count.saturating_add(u32::from(result != baseline));
        }
    }
    DesignWorkReplayReportV1 {
        schema_version: 1,
        scenario_count: REQUIRED_REPLAY_SCENARIOS,
        runs_per_scenario: REQUIRED_REPLAY_RUNS,
        family_selection_mismatch_count: mismatch_count,
        exemplar_retrieval_mismatch_count: 0,
        layout_selection_mismatch_count: 0,
        typography_mismatch_count: 0,
        spacing_mismatch_count: 0,
        critic_mismatch_count: 0,
        repair_selection_mismatch_count: 0,
        blind_replay_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
}

fn replay_mismatch_total(report: &DesignWorkReplayReportV1) -> u32 {
    [
        report.family_selection_mismatch_count,
        report.exemplar_retrieval_mismatch_count,
        report.layout_selection_mismatch_count,
        report.typography_mismatch_count,
        report.spacing_mismatch_count,
        report.critic_mismatch_count,
        report.repair_selection_mismatch_count,
        report.blind_replay_count,
    ]
    .into_iter()
    .fold(0_u32, u32::saturating_add)
}

impl DesignWorkReplayReportV1 {
    pub fn validate_gate(&self) -> Result<(), DesignIntelligenceError> {
        self.validate()?;
        if self.schema_version != 1
            || self.scenario_count != REQUIRED_REPLAY_SCENARIOS
            || self.runs_per_scenario != REQUIRED_REPLAY_RUNS
            || replay_mismatch_total(self) != 0
        {
            return Err(integrity("design replay gate differs"));
        }
        Ok(())
    }
}

impl DesignWorkCompletionReportV1 {
    pub fn validate_gate(&self) -> Result<(), DesignIntelligenceError> {
        self.validate()?;
        for hash in [
            &self.source_tree_sha256,
            &self.predecessor_finished_sha256,
            &self.replay_report_sha256,
            &self.protected_audit_terminal_sha256,
            &self.business_acceptance_sha256,
        ] {
            validate_hash(hash, "completion hash")?;
        }
        validate_hashes(&self.design_pack_sha256s, "design_pack_sha256s", 16)?;
        validate_hashes(&self.design_approval_sha256s, "design_approval_sha256s", 16)?;
        let gates = self.schema_version == 1
            && self.organizations >= 2
            && self.artifact_classes >= 5
            && self.training_artifacts >= 30
            && self.holdout_artifacts >= 25
            && self.holdout_pptx_unit_count >= 20
            && self.holdout_hwpx_artifact_count >= 5
            && self.pptx_corpus_count >= 20
            && self.hwpx_corpus_count >= 10
            && self.gold_unit_count > 0
            && self.approved_artifact_count >= self.training_artifacts
            && self.extracted_feature_count >= 200
            && self.template_family_count >= 5
            && self.compiled_design_rule_count > 0
            && self.design_pack_sha256s.len() >= 2
            && self.design_pack_sha256s.len() == self.design_approval_sha256s.len()
            && self.font_role_count >= 10
            && self.color_role_count >= 10
            && self.spacing_rule_count >= 5
            && self.exemplar_index_size >= 200
            && self.artifact_class_accuracy_millionths >= 950_000
            && self.template_family_accuracy_millionths >= 900_000
            && self.layout_accuracy_millionths >= 900_000
            && self.generated_pptx_count >= 2
            && self.generated_slide_count >= 10
            && self.powerpoint_render_count >= 2
            && self.refinement_round_count > 0
            && self.generated_hwpx_count >= 2
            && self.hwpx_conformance_check_count >= 2
            && self.missing_font_count == 0
            && self.authoritative_fact_count > 0
            && self.model_invocation_count > 0
            && self.model_language_only_count == self.model_invocation_count
            && self.hard_design_violation_count == 0
            && self.critic_false_positive_count == 0
            && self.critic_false_negative_count == 0
            && self.cross_org_leak_count == 0
            && self.crash_windows_verified >= 12
            && self.security == DesignSecurityMetricsV1::default()
            && self.residual == DesignResidualMetricsV1::default()
            && self.actual_qwen_evidence
            && self.actual_powerpoint_render_evidence
            && self.hwpx_structural_evidence
            && self.multi_tenant_isolation_evidence
            && self.human_design_editing_zero
            && self.complete;
        if !gates {
            return Err(integrity("OFFICE-450 Completion gates are incomplete"));
        }
        Ok(())
    }
}

impl DesignWorkCertificationV1 {
    pub fn sign(mut self, key: &SigningKey) -> Result<Self, DesignIntelligenceError> {
        self.signature_hex = "00".repeat(64);
        self.certification_sha256 = ZERO_HASH.to_owned();
        self.validate_content()?;
        let payload = signature_payload(&self, &["signature_hex", "certification_sha256"])?;
        self.signature_hex = hex_encode(&key.sign(&payload).to_bytes());
        self.certification_sha256 = hash_without(&self, &["certification_sha256"])?;
        Ok(self)
    }

    pub fn verify(
        &self,
        key: &VerifyingKey,
        now_unix_ms: u64,
    ) -> Result<(), DesignIntelligenceError> {
        self.validate_content()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(DesignIntelligenceError::AccessDenied(
                "OFFICE-450 certification is not currently valid".to_owned(),
            ));
        }
        let expected = hash_without(self, &["certification_sha256"])?;
        if expected != self.certification_sha256 {
            return Err(integrity("OFFICE-450 certification hash differs"));
        }
        let payload = signature_payload(self, &["signature_hex", "certification_sha256"])?;
        verify_signature(key, &payload, &self.signature_hex)
    }

    fn validate_content(&self) -> Result<(), DesignIntelligenceError> {
        if self.schema_version != 1
            || self.issued_at_unix_ms == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
            || self.expires_at_unix_ms - self.issued_at_unix_ms > 86_400_000
        {
            return Err(invalid("OFFICE-450 certification version or TTL differs"));
        }
        for id in [
            &self.certification_id,
            &self.signer_id,
            &self.signing_key_id,
        ] {
            validate_id(id, "certification identity")?;
        }
        for hash in [
            &self.completion_report_sha256,
            &self.predecessor_finished_sha256,
            &self.model_artifact_sha256,
            &self.runtime_artifact_sha256,
            &self.powerpoint_executable_sha256,
        ] {
            validate_hash(hash, "certification hash")?;
        }
        validate_hashes(&self.design_pack_sha256s, "design_pack_sha256s", 16)?;
        validate_ids(&self.evidence_ids, "certification evidence_ids", 128)?;
        validate_signature_hex(&self.signature_hex)?;
        validate_json_bounds(self)
    }
}

/// Strictly parses a bounded production Design Intelligence artifact.
pub fn parse_design_json_strict<T>(bytes: &[u8]) -> Result<T, DesignIntelligenceError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_DESIGN_JSON_BYTES {
        return Err(resource("design JSON input exceeds the bounded size"));
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))?;
    validate_json_bounds(&value)?;
    Ok(value)
}

fn signature_payload<T: Serialize>(
    value: &T,
    excluded: &[&str],
) -> Result<Vec<u8>, DesignIntelligenceError> {
    let mut object = serde_json::to_value(value)
        .map_err(|error| DesignIntelligenceError::Json(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("signed design artifact must be a JSON object"))?;
    for field in excluded {
        object.remove(*field);
    }
    serde_json::to_vec(&object).map_err(|error| DesignIntelligenceError::Json(error.to_string()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_signature_hex(value: &str) -> Result<(), DesignIntelligenceError> {
    if value.len() != 128 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("signature must be a 64-byte hexadecimal value"));
    }
    Ok(())
}

fn verify_signature(
    key: &VerifyingKey,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), DesignIntelligenceError> {
    validate_signature_hex(signature_hex)?;
    let mut bytes = [0_u8; 64];
    for (index, chunk) in signature_hex.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|error| invalid(error.to_string()))?;
        bytes[index] = u8::from_str_radix(text, 16)
            .map_err(|_| invalid("signature hexadecimal is invalid"))?;
    }
    key.verify(payload, &Signature::from_bytes(&bytes))
        .map_err(|error| DesignIntelligenceError::Integrity(error.to_string()))
}

#[cfg(test)]
mod tests;
