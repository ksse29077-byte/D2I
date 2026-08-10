use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignArtifactFormatV1 {
    Pptx,
    Hwpx,
    Docx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignQualityLabelV1 {
    Gold,
    Approved,
    LegacyApproved,
    Deprecated,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignApprovalStateV1 {
    Approved,
    Unapproved,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignPackMaturityV1 {
    TemplateLock,
    FamilyLearned,
    OrganizationLearned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommonDesignRoleV1 {
    ArtifactTitle,
    ArtifactSubtitle,
    SectionTitle,
    Heading1,
    Heading2,
    Body,
    Caption,
    Footnote,
    KpiValue,
    KpiLabel,
    TableHeader,
    TableBody,
    TableTotal,
    ChartTitle,
    ChartLabel,
    ImageCaption,
    Warning,
    Emphasis,
    Muted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignDensityClassV1 {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignFitStatusV1 {
    Fit,
    NeedsAlternativeLayout,
    NeedsSplit,
    NeedsLanguageCompression,
    FontMissing,
    HumanException,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignCritiqueStatusV1 {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignRepairOperationV1 {
    SwitchLayout,
    SplitSlide,
    ResizeWithinAllowedRange,
    AdjustSpacingWithinGrammar,
    ReflowTable,
    ChangeImageFit,
    ShortenLanguage,
    MoveToAllowedSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignUnitRatingV1 {
    pub unit_id: String,
    pub quality_label: DesignQualityLabelV1,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignArtifactRecordV1 {
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub format: DesignArtifactFormatV1,
    pub artifact_class: String,
    pub template_family_hint: Option<String>,
    pub quality_label: DesignQualityLabelV1,
    pub approval_state: DesignApprovalStateV1,
    pub approved_at_unix_ms: Option<u64>,
    pub unit_ratings: Vec<DesignUnitRatingV1>,
    pub template_status_id: String,
    pub data_classification_id: String,
    pub provenance_ids: Vec<String>,
    pub holdout: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDesignCorpusV1 {
    pub schema_version: u32,
    pub corpus_id: String,
    pub organization_id: String,
    pub artifacts: Vec<DesignArtifactRecordV1>,
    pub manifest_approval_sha256: String,
    pub corpus_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignDistributionV1 {
    pub minimum_millionths: u32,
    pub q1_millionths: u32,
    pub median_millionths: u32,
    pub q3_millionths: u32,
    pub maximum_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedDesignRectV1 {
    pub left_millionths: u32,
    pub top_millionths: u32,
    pub width_millionths: u32,
    pub height_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignFeatureVectorV1 {
    pub layout_ratios: Vec<u32>,
    pub font_role_ratios: Vec<u32>,
    pub color_role_distribution: Vec<u32>,
    pub spacing_distribution: Vec<u32>,
    pub white_space_millionths: u32,
    pub shape_density_millionths: u32,
    pub text_density_millionths: u32,
    pub image_ratio_millionths: u32,
    pub table_density_millionths: u32,
    pub chart_density_millionths: u32,
    pub alignment_features: Vec<u32>,
    pub vector_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignArtifactFeatureV1 {
    pub schema_version: u32,
    pub feature_id: String,
    pub organization_id: String,
    pub artifact_id: String,
    pub artifact_sha256: String,
    pub artifact_class: String,
    pub format: DesignArtifactFormatV1,
    pub template_family_id: String,
    pub unit_role_id: String,
    pub layout_id: String,
    pub normalized_slots: Vec<NormalizedDesignRectV1>,
    pub typography_role_ids: Vec<CommonDesignRoleV1>,
    pub color_role_ids: Vec<String>,
    pub spacing_ids: Vec<String>,
    pub table_feature_ids: Vec<String>,
    pub chart_feature_ids: Vec<String>,
    pub image_feature_ids: Vec<String>,
    pub density_class: DesignDensityClassV1,
    pub source_exemplar_ref: String,
    pub quality_weight_millionths: u32,
    pub vector: DesignFeatureVectorV1,
    pub feature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignFontRolePolicyV1 {
    pub role: CommonDesignRoleV1,
    pub preferred_font_family: String,
    pub approved_fallback_families: Vec<String>,
    pub weight_min: u16,
    pub weight_max: u16,
    pub font_size_min_millipoints: u32,
    pub font_size_preferred_millipoints: u32,
    pub font_size_max_millipoints: u32,
    pub line_spacing_min_millionths: u32,
    pub line_spacing_max_millionths: u32,
    pub letter_spacing_min_millipoints: i32,
    pub letter_spacing_max_millipoints: i32,
    pub script_coverage_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationFontPolicyV1 {
    pub schema_version: u32,
    pub organization_id: String,
    pub roles: Vec<DesignFontRolePolicyV1>,
    pub font_policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationLogoPolicyV1 {
    pub schema_version: u32,
    pub organization_id: String,
    pub approved_logo_artifact_refs: Vec<String>,
    pub safe_area_millionths: u32,
    pub minimum_width_millionths: u32,
    pub minimum_height_millionths: u32,
    pub allowed_position_ids: Vec<String>,
    pub allowed_background_class_ids: Vec<String>,
    pub variant_ids: Vec<String>,
    pub distortion_forbidden: bool,
    pub logo_policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypographyGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub role_policies: Vec<DesignFontRolePolicyV1>,
    pub hierarchy_ratio_rules: Vec<DesignDistributionV1>,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacingRuleV1 {
    pub spacing_id: String,
    pub distribution: DesignDistributionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpacingGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub rules: Vec<SpacingRuleV1>,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutSlotRuleV1 {
    pub slot_id: String,
    pub semantic_role: CommonDesignRoleV1,
    pub allowed_region: NormalizedDesignRectV1,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub artifact_class: String,
    pub layout_family_id: String,
    pub slots: Vec<LayoutSlotRuleV1>,
    pub grid_column_count: u16,
    pub outer_margin: DesignDistributionV1,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableDesignGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub header_font_role: CommonDesignRoleV1,
    pub header_color_role: String,
    pub body_font_role: CommonDesignRoleV1,
    pub horizontal_alignment_id: String,
    pub vertical_alignment_id: String,
    pub border_policy_id: String,
    pub row_height: DesignDistributionV1,
    pub cell_padding: DesignDistributionV1,
    pub zebra_enabled: bool,
    pub total_row_policy_id: String,
    pub number_emphasis_role: CommonDesignRoleV1,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChartDesignGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub allowed_chart_type_ids: Vec<String>,
    pub series_color_role_order: Vec<String>,
    pub title_role: CommonDesignRoleV1,
    pub legend_position_id: String,
    pub data_label_policy_id: String,
    pub axis_policy_id: String,
    pub gridline_policy_id: String,
    pub number_format_id: String,
    pub emphasis_series_policy_id: String,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDesignGrammarV1 {
    pub schema_version: u32,
    pub grammar_id: String,
    pub organization_id: String,
    pub preferred_aspect_ratio_millionths: Vec<u32>,
    pub placement_role_ids: Vec<String>,
    pub allowed_fit_ids: Vec<String>,
    pub crop_allowed: bool,
    pub border_role_id: String,
    pub corner_policy_id: String,
    pub caption_role: CommonDesignRoleV1,
    pub minimum_resolution_pixels: u32,
    pub maximum_enlargement_millionths: u32,
    pub text_image_balance: DesignDistributionV1,
    pub grammar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateFamilyV1 {
    pub schema_version: u32,
    pub organization_id: String,
    pub artifact_class: String,
    pub family_id: String,
    pub family_version: String,
    pub eligible_exemplar_refs: Vec<String>,
    pub layout_role_ids: Vec<String>,
    pub typography_grammar_ref: String,
    pub color_grammar_ref: String,
    pub spacing_grammar_ref: String,
    pub table_grammar_ref: String,
    pub chart_grammar_ref: String,
    pub image_grammar_ref: String,
    pub maturity: DesignPackMaturityV1,
    pub confidence_millionths: u32,
    pub family_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignRuleProvenanceV1 {
    pub rule_id: String,
    pub source_exemplar_ids: Vec<String>,
    pub source_sha256s: Vec<String>,
    pub support_count: u32,
    pub gold_support_count: u32,
    pub confidence_millionths: u32,
    pub distribution: DesignDistributionV1,
    pub rule_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDesignProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub organization_id: String,
    pub brand_role_ids: Vec<String>,
    pub font_policy_sha256: String,
    pub color_role_ids: Vec<String>,
    pub spacing_scale_ids: Vec<String>,
    pub grid_policy_id: String,
    pub logo_policy_sha256: String,
    pub image_policy_id: String,
    pub table_policy_id: String,
    pub chart_policy_id: String,
    pub artifact_class_refs: Vec<String>,
    pub pack_version: String,
    pub provenance_ids: Vec<String>,
    pub profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignExemplarRecordV1 {
    pub schema_version: u32,
    pub exemplar_id: String,
    pub organization_id: String,
    pub artifact_class: String,
    pub unit_role_id: String,
    pub template_family_id: String,
    pub layout_vector_sha256: String,
    pub typography_vector_sha256: String,
    pub color_vector_sha256: String,
    pub spacing_vector_sha256: String,
    pub content_density_class: DesignDensityClassV1,
    pub source_artifact_sha256: String,
    pub quality_weight_millionths: u32,
    pub text_length: u32,
    pub line_count: u32,
    pub text_sha256: String,
    pub exemplar_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignExemplarIndexV1 {
    pub schema_version: u32,
    pub index_id: String,
    pub organization_id: String,
    pub design_pack_sha256: String,
    pub exemplars: Vec<DesignExemplarRecordV1>,
    pub index_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignExemplarQueryV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub organization_id: String,
    pub artifact_class: String,
    pub unit_role_id: String,
    pub required_content_role_ids: Vec<CommonDesignRoleV1>,
    pub table_required: bool,
    pub chart_required: bool,
    pub image_required: bool,
    pub density_class: DesignDensityClassV1,
    pub aspect_or_page_class_id: String,
    pub maximum_results: u32,
    pub query_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignExemplarMatchV1 {
    pub exemplar_id: String,
    pub template_family_id: String,
    pub distance_millionths: u32,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignExemplarQueryResultV1 {
    pub schema_version: u32,
    pub query_id: String,
    pub query_sha256: String,
    pub index_sha256: String,
    pub matches: Vec<DesignExemplarMatchV1>,
    pub result_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDesignPackV1 {
    pub schema_version: u32,
    pub pack_id: String,
    pub pack_version: String,
    pub organization_id: String,
    pub source_corpus_sha256: String,
    pub profile: OrganizationDesignProfileV1,
    pub typography_grammar: TypographyGrammarV1,
    pub spacing_grammar: SpacingGrammarV1,
    pub layout_grammars: Vec<LayoutGrammarV1>,
    pub table_grammar: TableDesignGrammarV1,
    pub chart_grammar: ChartDesignGrammarV1,
    pub image_grammar: ImageDesignGrammarV1,
    pub logo_policy: OrganizationLogoPolicyV1,
    pub template_families: Vec<TemplateFamilyV1>,
    pub rule_provenance: Vec<DesignRuleProvenanceV1>,
    pub holdout_artifact_sha256s: Vec<String>,
    pub compiled_at_unix_ms: u64,
    pub pack_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignPackCandidateV1 {
    pub schema_version: u32,
    pub candidate_id: String,
    pub organization_id: String,
    pub source_corpus_sha256: String,
    pub pack: OrganizationDesignPackV1,
    pub training_artifact_count: u32,
    pub holdout_artifact_count: u32,
    pub rejected_artifact_count: u32,
    pub validation_evidence_ids: Vec<String>,
    pub quarantined: bool,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationDesignPackApprovalV1 {
    pub schema_version: u32,
    pub approval_id: String,
    pub organization_id: String,
    pub design_pack_sha256: String,
    pub allowed_artifact_classes: Vec<String>,
    pub environment_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub approver_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub approval_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypographyRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub design_pack_sha256: String,
    pub semantic_role: CommonDesignRoleV1,
    pub text_sha256: String,
    pub character_count: u32,
    pub language_script_id: String,
    pub available_width_millionths: u32,
    pub available_height_millionths: u32,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypographyDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub request_sha256: String,
    pub design_pack_sha256: String,
    pub selected_font_family: Option<String>,
    pub used_fallback: bool,
    pub font_size_millipoints: u32,
    pub weight: u16,
    pub line_spacing_millionths: u32,
    pub paragraph_spacing_millionths: u32,
    pub alignment_id: String,
    pub estimated_line_count: u32,
    pub fit_status: DesignFitStatusV1,
    pub evidence_ids: Vec<String>,
    pub decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLayoutRequestV1 {
    pub schema_version: u32,
    pub request_id: String,
    pub organization_id: String,
    pub design_pack_sha256: String,
    pub artifact_class: String,
    pub content_role_ids: Vec<CommonDesignRoleV1>,
    pub required_fact_ids: Vec<String>,
    pub required_image_ids: Vec<String>,
    pub density_class: DesignDensityClassV1,
    pub aspect_or_page_class_id: String,
    pub request_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLayoutDecisionV1 {
    pub schema_version: u32,
    pub decision_id: String,
    pub request_sha256: String,
    pub design_pack_sha256: String,
    pub template_family_id: String,
    pub layout_family_id: String,
    pub slot_assignments: Vec<LayoutSlotRuleV1>,
    pub typography_decision_sha256s: Vec<String>,
    pub fit_status: DesignFitStatusV1,
    pub design_distance_millionths: u32,
    pub evidence_ids: Vec<String>,
    pub decision_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentFitReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub design_pack_sha256: String,
    pub layout_decision_sha256: String,
    pub overflow_count: u32,
    pub below_minimum_font_count: u32,
    pub split_required_count: u32,
    pub compression_required_count: u32,
    pub fit_status: DesignFitStatusV1,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HardDesignViolationMetricsV1 {
    pub font_family_violation: u32,
    pub font_size_violation: u32,
    pub text_overflow: u32,
    pub off_canvas_or_page: u32,
    pub forbidden_overlap: u32,
    pub alignment_violation: u32,
    pub spacing_violation: u32,
    pub margin_violation: u32,
    pub color_role_violation: u32,
    pub logo_violation: u32,
    pub table_violation: u32,
    pub image_distortion: u32,
    pub chart_policy_violation: u32,
    pub placeholder_leakage: u32,
    pub missing_title: u32,
    pub missing_required_section: u32,
    pub unverified_kpi: u32,
    pub fact_mismatch: u32,
    pub chart_fact_mismatch: u32,
    pub wrong_organization_pack: u32,
    pub wrong_template_family: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardDesignCritiqueV1 {
    pub schema_version: u32,
    pub critique_id: String,
    pub organization_id: String,
    pub artifact_sha256: String,
    pub design_pack_sha256: String,
    pub metrics: HardDesignViolationMetricsV1,
    pub status: DesignCritiqueStatusV1,
    pub issue_ids: Vec<String>,
    pub critique_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoftDesignCritiqueV1 {
    pub schema_version: u32,
    pub critique_id: String,
    pub organization_id: String,
    pub artifact_sha256: String,
    pub design_pack_sha256: String,
    pub template_family_id: String,
    pub geometry_distance_millionths: u32,
    pub hierarchy_distance_millionths: u32,
    pub spacing_distance_millionths: u32,
    pub color_distance_millionths: u32,
    pub density_distance_millionths: u32,
    pub aggregate_distance_millionths: u32,
    pub acceptance_envelope_max_millionths: u32,
    pub status: DesignCritiqueStatusV1,
    pub critique_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignQualityReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub organization_id: String,
    pub artifact_sha256: String,
    pub hard_critique_sha256: String,
    pub soft_critique_sha256: String,
    pub render_evidence_sha256: Option<String>,
    pub structural_conformance_sha256: String,
    pub status: DesignCritiqueStatusV1,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignRefinementStepV1 {
    pub sequence: u32,
    pub operation: DesignRepairOperationV1,
    pub target_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignRefinementPlanV1 {
    pub schema_version: u32,
    pub plan_id: String,
    pub organization_id: String,
    pub artifact_sha256: String,
    pub design_pack_sha256: String,
    pub hard_critique_sha256: String,
    pub maximum_rounds: u32,
    pub steps: Vec<DesignRefinementStepV1>,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignRefinementReceiptV1 {
    pub schema_version: u32,
    pub receipt_id: String,
    pub plan_sha256: String,
    pub source_artifact_sha256: String,
    pub result_artifact_sha256: String,
    pub applied_step_count: u32,
    pub bounded_round_count: u32,
    pub final_quality_report_sha256: String,
    pub verified: bool,
    pub receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VisualClaimIntegrityReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub artifact_sha256: String,
    pub authoritative_fact_ids: Vec<String>,
    pub displayed_kpi_fact_ids: Vec<String>,
    pub chart_fact_ids: Vec<String>,
    pub table_total_fact_ids: Vec<String>,
    pub unverified_kpi_count: u32,
    pub fact_mismatch_count: u32,
    pub model_created_fact_count: u32,
    pub verified: bool,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignPreferenceRecordV1 {
    pub schema_version: u32,
    pub record_id: String,
    pub organization_id: String,
    pub artifact_class: String,
    pub design_pack_sha256: String,
    pub candidate_a_sha256: String,
    pub candidate_b_sha256: String,
    pub preferred_candidate_id: String,
    pub review_context_sha256: String,
    pub reviewer_id: String,
    pub evidence_ids: Vec<String>,
    pub quarantined: bool,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignWorkReplayReportV1 {
    pub schema_version: u32,
    pub scenario_count: u32,
    pub runs_per_scenario: u32,
    pub family_selection_mismatch_count: u32,
    pub exemplar_retrieval_mismatch_count: u32,
    pub layout_selection_mismatch_count: u32,
    pub typography_mismatch_count: u32,
    pub spacing_mismatch_count: u32,
    pub critic_mismatch_count: u32,
    pub repair_selection_mismatch_count: u32,
    pub blind_replay_count: u32,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DesignSecurityMetricsV1 {
    pub cross_org_leak: u32,
    pub raw_corpus_to_model: u32,
    pub raw_xml_to_model: u32,
    pub font_binary_export: u32,
    pub unapproved_external_asset: u32,
    pub network_access: u32,
    pub arbitrary_process: u32,
    pub arbitrary_command: u32,
    pub workspace_escape: u32,
    pub credential_leak: u32,
    pub prompt_injection_rule_promotion: u32,
    pub rejected_artifact_rule_promotion: u32,
    pub online_self_mutation: u32,
    pub false_completion: u32,
    pub critical_error: u32,
    pub model_raw_coordinate_count: u32,
    pub model_raw_color_count: u32,
    pub model_raw_font_count: u32,
    pub model_raw_font_size_count: u32,
    pub model_layout_execution_authority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DesignResidualMetricsV1 {
    pub powerpoint_processes: u32,
    pub excel_processes: u32,
    pub word_processes: u32,
    pub design_workers: u32,
    pub model_workers: u32,
    pub wfp_objects: u32,
    pub profiles: u32,
    pub activations: u32,
    pub temporary_renders: u32,
    pub temporary_design_packs: u32,
    pub file_locks: u32,
    pub workspace_locks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DesignPerformanceMetricsV1 {
    pub corpus_parse_microseconds: u64,
    pub feature_extraction_microseconds: u64,
    pub grammar_compile_microseconds: u64,
    pub exemplar_retrieval_microseconds: u64,
    pub solver_microseconds: u64,
    pub render_microseconds: u64,
    pub critic_microseconds: u64,
    pub refinement_microseconds: u64,
    pub model_microseconds: u64,
    pub peak_worker_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignBusinessAcceptanceReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub generated_artifact_count: u32,
    pub artifacts_requiring_manual_design_editing: u32,
    pub routine_human_design_edits: u32,
    pub hard_pass_count: u32,
    pub soft_envelope_pass_count: u32,
    pub blind_review_artifact_count: u32,
    pub accepted: bool,
    pub report_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignWorkCompletionReportV1 {
    pub schema_version: u32,
    pub report_id: String,
    pub source_tree_sha256: String,
    pub predecessor_finished_sha256: String,
    pub organizations: u32,
    pub artifact_classes: u32,
    pub training_artifacts: u32,
    pub holdout_artifacts: u32,
    pub holdout_pptx_unit_count: u32,
    pub holdout_hwpx_artifact_count: u32,
    pub pptx_corpus_count: u32,
    pub hwpx_corpus_count: u32,
    pub docx_corpus_count: u32,
    pub gold_unit_count: u32,
    pub approved_artifact_count: u32,
    pub extracted_feature_count: u32,
    pub template_family_count: u32,
    pub compiled_design_rule_count: u32,
    pub design_pack_sha256s: Vec<String>,
    pub design_approval_sha256s: Vec<String>,
    pub font_role_count: u32,
    pub color_role_count: u32,
    pub spacing_rule_count: u32,
    pub exemplar_index_size: u32,
    pub artifact_class_accuracy_millionths: u32,
    pub template_family_accuracy_millionths: u32,
    pub layout_accuracy_millionths: u32,
    pub generated_pptx_count: u32,
    pub generated_slide_count: u32,
    pub powerpoint_render_count: u32,
    pub refinement_round_count: u32,
    pub generated_hwpx_count: u32,
    pub hwpx_conformance_check_count: u32,
    pub font_fallback_count: u32,
    pub missing_font_count: u32,
    pub authoritative_fact_count: u32,
    pub model_invocation_count: u32,
    pub model_language_only_count: u32,
    pub hard_design_violation_count: u32,
    pub soft_design_distance_millionths: u32,
    pub critic_false_positive_count: u32,
    pub critic_false_negative_count: u32,
    pub cross_org_leak_count: u32,
    pub crash_windows_verified: u32,
    pub replay_report_sha256: String,
    pub protected_audit_terminal_sha256: String,
    pub business_acceptance_sha256: String,
    pub security: DesignSecurityMetricsV1,
    pub residual: DesignResidualMetricsV1,
    pub performance: DesignPerformanceMetricsV1,
    pub actual_qwen_evidence: bool,
    pub actual_powerpoint_render_evidence: bool,
    pub hwpx_structural_evidence: bool,
    pub multi_tenant_isolation_evidence: bool,
    pub human_design_editing_zero: bool,
    pub complete: bool,
    pub finished_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesignWorkCertificationV1 {
    pub schema_version: u32,
    pub certification_id: String,
    pub completion_report_sha256: String,
    pub predecessor_finished_sha256: String,
    pub model_artifact_sha256: String,
    pub runtime_artifact_sha256: String,
    pub powerpoint_executable_sha256: String,
    pub design_pack_sha256s: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub signer_id: String,
    pub signing_key_id: String,
    pub signature_hex: String,
    pub certification_sha256: String,
}
