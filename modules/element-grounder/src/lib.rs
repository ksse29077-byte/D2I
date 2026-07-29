//! Deterministic, side-effect-free Element Grounder reference module.

use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Stable reference module identifier.
pub const MODULE_ID: &str = "element-grounder";
/// Stable reference module version.
pub const MODULE_VERSION: &str = "1.0.0";
/// Build identifier used by deterministic fixtures.
pub const BUILD_ID: &str = "element-grounder-v1";
/// Capability implemented by the reference module.
pub const CAPABILITY_ID: &str = "cognitive.element-ground";
/// Module-owned input schema identifier.
pub const INPUT_SCHEMA_ID: &str = "element-grounding-input-v1";
/// Module-owned output schema identifier.
pub const OUTPUT_SCHEMA_ID: &str = "element-grounding-result-v1";
/// Maximum candidate count accepted by the v1 contract.
pub const MAX_CANDIDATES: u32 = 64;
/// Minimum integer score for a unique result, expressed in thousandths.
pub const UNIQUE_SCORE_THRESHOLD: u32 = 650;
/// Minimum top-two margin for a unique result, expressed in thousandths.
pub const UNIQUE_MARGIN_THRESHOLD: u32 = 150;

const SCHEMA_VERSION: u32 = 1;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_ELEMENTS: usize = 10_000;
const MAX_HINTS: usize = 64;
const MAX_JSON_DEPTH: usize = 32;
const MAX_JSON_NODES: usize = 100_000;
const NOT_FOUND_SCORE_THRESHOLD: u32 = 350;

/// Cognitive IR v1 trust labels mirrored without extending the Core contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLabel {
    AuthenticatedUserInstruction,
    ApprovedPolicy,
    ApprovedProcedure,
    VerifiedOperationalState,
    ObservedUiState,
    UntrustedWebContent,
    UntrustedDocumentContent,
    Fixture,
}

impl TrustLabel {
    fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticatedUserInstruction => "authenticated_user_instruction",
            Self::ApprovedPolicy => "approved_policy",
            Self::ApprovedProcedure => "approved_procedure",
            Self::VerifiedOperationalState => "verified_operational_state",
            Self::ObservedUiState => "observed_ui_state",
            Self::UntrustedWebContent => "untrusted_web_content",
            Self::UntrustedDocumentContent => "untrusted_document_content",
            Self::Fixture => "fixture",
        }
    }

    fn is_untrusted_content(self) -> bool {
        matches!(
            self,
            Self::ObservedUiState | Self::UntrustedWebContent | Self::UntrustedDocumentContent
        )
    }
}

/// Cognitive IR v1 observation source kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSourceKind {
    Fixture,
    Uia,
    WebDriver,
    FileMetadata,
    Process,
}

/// Cognitive IR v1 provenance mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveProvenance {
    pub source: String,
    pub source_hash: String,
    pub module_id: String,
}

/// Cognitive IR v1 observable element mirror.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservableElement {
    pub element_id: String,
    pub kind: String,
    pub label: String,
    pub value: Value,
    pub trust_labels: BTreeSet<TrustLabel>,
}

/// Cognitive IR v1 redaction metadata mirror.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionMetadata {
    pub field: String,
    pub reason: String,
    pub replacement_hash: String,
}

/// Cognitive IR v1 ObservationSnapshot mirror used at the module boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSnapshot {
    pub schema_version: u32,
    pub observation_id: String,
    pub source_kind: ObservationSourceKind,
    pub target_binding: BTreeMap<String, String>,
    pub state_hash: String,
    pub sequence: u64,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub observable_elements: Vec<ObservableElement>,
    pub redactions: Vec<RedactionMetadata>,
    pub provenance: CognitiveProvenance,
}

impl ObservationSnapshot {
    /// Computes the Cognitive IR v1 stable state hash.
    pub fn compute_state_hash(&self) -> Result<String, ModuleError> {
        canonical_sha256(&serde_json::json!({
            "source_kind": self.source_kind,
            "target_binding": self.target_binding,
            "trust_labels": self.trust_labels,
            "observable_elements": self.observable_elements,
            "redactions": self.redactions,
        }))
    }

    fn validate(&self) -> Result<(), ModuleError> {
        validate_version(self.schema_version, "observation_snapshot")?;
        validate_token(&self.observation_id, "observation_id")?;
        validate_hash(&self.state_hash, "observation state_hash")?;
        validate_provenance(&self.provenance)?;
        if self.trust_labels.is_empty() {
            return invalid("observation trust_labels must not be empty");
        }
        if self.observable_elements.len() > MAX_ELEMENTS {
            return resource("observation contains more than 10000 elements");
        }
        for (key, value) in &self.target_binding {
            validate_token(key, "target binding key")?;
            validate_text(value, "target binding value")?;
        }
        let mut ids = BTreeSet::new();
        for element in &self.observable_elements {
            validate_token(&element.element_id, "element_id")?;
            validate_token(&element.kind, "element kind")?;
            validate_text(&element.label, "element label")?;
            if element.trust_labels.is_empty() {
                return invalid("element trust_labels must not be empty");
            }
            validate_json_bounds(&element.value)?;
            if !ids.insert(element.element_id.as_str()) {
                return invalid("duplicate element_id is not groundable");
            }
        }
        for redaction in &self.redactions {
            validate_token(&redaction.field, "redaction field")?;
            validate_text(&redaction.reason, "redaction reason")?;
            validate_hash(&redaction.replacement_hash, "redaction replacement_hash")?;
        }
        if self.compute_state_hash()? != self.state_hash {
            return Err(ModuleError::new(
                ModuleErrorCode::DeterministicReplayMismatch,
                "ObservationSnapshot state_hash does not match observable state",
            ));
        }
        Ok(())
    }
}

/// Cognitive IR v1 world-fact source kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldFactKind {
    ObservedFact,
    InferredState,
    UserAssertion,
    PolicyFact,
    UntrustedContent,
}

/// Cognitive IR v1 world fact mirror.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldFact {
    pub fact_id: String,
    pub kind: WorldFactKind,
    pub subject: String,
    pub predicate: String,
    pub object: Value,
    pub evidence: Vec<String>,
}

/// Cognitive IR v1 WorldState mirror used only for optional binding checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldState {
    pub schema_version: u32,
    pub world_state_id: String,
    pub goal_id: String,
    pub normalized_facts: Vec<WorldFact>,
    pub known_state: BTreeMap<String, Value>,
    pub uncertain_state: BTreeMap<String, Value>,
    pub conflicts: Vec<String>,
    pub capabilities: BTreeSet<String>,
    pub current_step: String,
    pub current_observation_hash: String,
    pub plan_generation_id: String,
    pub provenance: CognitiveProvenance,
}

impl WorldState {
    fn validate(&self) -> Result<(), ModuleError> {
        validate_version(self.schema_version, "world_state")?;
        validate_token(&self.world_state_id, "world_state_id")?;
        validate_token(&self.goal_id, "world_state goal_id")?;
        validate_token(&self.current_step, "world_state current_step")?;
        validate_hash(
            &self.current_observation_hash,
            "world_state current_observation_hash",
        )?;
        validate_token(&self.plan_generation_id, "world_state plan_generation_id")?;
        validate_provenance(&self.provenance)?;
        for fact in &self.normalized_facts {
            validate_token(&fact.fact_id, "world fact_id")?;
            validate_text(&fact.subject, "world fact subject")?;
            validate_text(&fact.predicate, "world fact predicate")?;
            validate_string_collection(&fact.evidence, "world fact evidence", MAX_HINTS)?;
            validate_json_bounds(&fact.object)?;
        }
        for value in self
            .known_state
            .values()
            .chain(self.uncertain_state.values())
        {
            validate_json_bounds(value)?;
        }
        validate_string_collection(&self.conflicts, "world_state conflicts", 128)?;
        for capability in &self.capabilities {
            validate_token(capability, "world_state capability")?;
        }
        Ok(())
    }
}

/// Replay metadata carried inside the module-owned input for reproducible fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundingReplayContext {
    pub replay_id: String,
    pub seed: u64,
}

/// Module-owned Element Grounder v1 input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGroundingInput {
    pub schema_version: u32,
    pub goal_id: String,
    pub target_text: String,
    pub observation_snapshot: ObservationSnapshot,
    pub world_state: Option<WorldState>,
    pub expected_kinds: Vec<String>,
    pub required_terms: Vec<String>,
    pub excluded_terms: Vec<String>,
    pub context_terms: Vec<String>,
    pub max_candidates: u32,
    pub source_observation_hash: String,
    pub plan_generation_id: String,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub replay_context: GroundingReplayContext,
}

/// Grounding terminal state inside a successful module result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingStatus {
    UniqueMatch,
    Ambiguous,
    NotFound,
    Unsupported,
}

/// One ranked candidate. Scores are deterministic lexical scores, not probabilities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementCandidate {
    pub element_id: String,
    pub kind: String,
    pub label: String,
    pub score: f64,
    pub matched_features: Vec<String>,
    pub evidence: Vec<String>,
    pub trust_labels: BTreeSet<TrustLabel>,
}

/// Module-owned Element Grounder v1 result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElementGroundingResult {
    pub schema_version: u32,
    pub goal_id: String,
    pub source_observation_hash: String,
    pub plan_generation_id: String,
    pub target_text: String,
    pub status: GroundingStatus,
    pub selected_element_id: Option<String>,
    pub candidates: Vec<ElementCandidate>,
    pub ambiguity_reason: Option<String>,
    pub user_confirmation_required: bool,
    pub evidence: Vec<String>,
    pub warnings: Vec<String>,
}

/// Side-effect-free deterministic Element Grounder.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElementGrounder;

impl Module for ElementGrounder {
    type Input = ElementGroundingInput;
    type Output = ElementGroundingResult;

    fn metadata(&self) -> ModuleMetadata {
        ModuleMetadata {
            module_id: MODULE_ID.to_owned(),
            module_version: MODULE_VERSION.to_owned(),
            build_id: BUILD_ID.to_owned(),
        }
    }

    fn capabilities(&self) -> Vec<ModuleCapability> {
        vec![ModuleCapability {
            capability_id: CAPABILITY_ID.to_owned(),
            capability_version: "1.0.0".to_owned(),
            category: ModuleCategory("element_grounder".to_owned()),
            supported_input_kinds: vec![INPUT_SCHEMA_ID.to_owned()],
            supported_output_kinds: vec![OUTPUT_SCHEMA_ID.to_owned()],
            supported_risk_classes: vec!["read_only".to_owned()],
            deterministic: true,
            side_effect: false,
            network_requirement: NetworkRequirement::Denied,
            streaming: false,
            confidence_semantics: ConfidenceSemantics::RelativeRanking,
        }]
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        validate_version(input.schema_version, "element grounding input")?;
        validate_token(&input.goal_id, "goal_id")?;
        validate_text(&input.target_text, "target_text")?;
        validate_hash(&input.source_observation_hash, "source_observation_hash")?;
        validate_token(&input.plan_generation_id, "plan_generation_id")?;
        validate_token(&input.replay_context.replay_id, "replay_context replay_id")?;
        if input.max_candidates == 0 || input.max_candidates > MAX_CANDIDATES {
            return invalid("max_candidates must be within 1..64");
        }
        validate_string_collection(&input.expected_kinds, "expected_kinds", MAX_HINTS)?;
        validate_string_collection(&input.required_terms, "required_terms", MAX_HINTS)?;
        validate_string_collection(&input.excluded_terms, "excluded_terms", MAX_HINTS)?;
        validate_string_collection(&input.context_terms, "context_terms", MAX_HINTS)?;
        validate_search_terms(&input.required_terms, "required_terms")?;
        validate_search_terms(&input.excluded_terms, "excluded_terms")?;
        validate_search_terms(&input.context_terms, "context_terms")?;
        for kind in &input.expected_kinds {
            validate_token(kind, "expected kind")?;
        }
        if input.trust_labels.is_empty() {
            return invalid("input trust_labels must not be empty");
        }
        let input_labels = input
            .trust_labels
            .iter()
            .map(|label| label.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if input_labels != context.invocation_trust_labels {
            return Err(ModuleError::new(
                ModuleErrorCode::UntrustedInputViolation,
                "payload trust_labels do not match trusted invocation context",
            ));
        }

        input.observation_snapshot.validate()?;
        if input.source_observation_hash != input.observation_snapshot.state_hash {
            return stale("source_observation_hash does not match ObservationSnapshot state_hash");
        }
        if context.current_observation_hash.as_deref()
            != Some(input.source_observation_hash.as_str())
        {
            return stale("source_observation_hash does not match caller context");
        }
        if context.current_plan_generation_id.as_deref() != Some(input.plan_generation_id.as_str())
        {
            return stale("plan_generation_id does not match caller context");
        }

        if let Some(world_state) = &input.world_state {
            world_state.validate()?;
            if world_state.goal_id != input.goal_id {
                return stale("WorldState goal_id does not match input goal_id");
            }
            if world_state.current_observation_hash != input.source_observation_hash {
                return stale("WorldState observation hash does not match input binding");
            }
            if world_state.plan_generation_id != input.plan_generation_id {
                return stale("WorldState plan generation does not match input binding");
            }
        }
        Ok(())
    }

    fn invoke(
        &self,
        input: Self::Input,
        _context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let source_hash = canonical_sha256(&input)?;
        let normalized_target = normalize(&input.target_text);
        if normalized_target.is_empty() || tokens(&normalized_target).is_empty() {
            let result = terminal_without_candidates(
                &input,
                GroundingStatus::Unsupported,
                "target_text has no supported searchable content",
                true,
            );
            return module_output(result, source_hash, 1.0, 1, Vec::new());
        }

        let expected_kinds = normalize_terms(&input.expected_kinds);
        let required_terms = normalize_terms(&input.required_terms);
        let excluded_terms = normalize_terms(&input.excluded_terms);
        let context_terms = normalize_terms(&input.context_terms);
        let redacted_elements = redacted_element_ids(&input.observation_snapshot);
        let mut ranked = Vec::new();
        let mut secret_labels_omitted = 0_u32;

        for element in &input.observation_snapshot.observable_elements {
            if secret_like(&element.label) {
                secret_labels_omitted = secret_labels_omitted.saturating_add(1);
                continue;
            }
            if let Some(candidate) = score_element(
                element,
                &normalized_target,
                input.target_text.trim(),
                &expected_kinds,
                &required_terms,
                &excluded_terms,
                &context_terms,
                redacted_elements.contains(&element.element_id),
            ) {
                ranked.push(candidate);
            }
        }
        ranked.sort_by(compare_ranked);

        let top_points = ranked.first().map_or(0, |candidate| candidate.points);
        let second_points = ranked.get(1).map_or(0, |candidate| candidate.points);
        let margin = if ranked.len() > 1 {
            top_points.saturating_sub(second_points)
        } else {
            top_points
        };
        let any_expected_kind = expected_kinds.is_empty()
            || ranked.iter().any(|candidate| candidate.expected_kind_match);
        let (status, reason, confirmation) = classify(
            &ranked,
            top_points,
            margin,
            any_expected_kind,
            input.observation_snapshot.observable_elements.is_empty(),
        );
        let selected_element_id = if status == GroundingStatus::UniqueMatch {
            ranked
                .first()
                .map(|candidate| candidate.element.element_id.clone())
        } else {
            None
        };

        let mut warnings = Vec::new();
        if input
            .observation_snapshot
            .trust_labels
            .iter()
            .any(|label| label.is_untrusted_content())
            || ranked.iter().any(|candidate| {
                candidate
                    .element
                    .trust_labels
                    .iter()
                    .any(|label| label.is_untrusted_content())
            })
        {
            warnings.push(
                "untrusted observation text was ranked only as data and conveyed no authority"
                    .to_owned(),
            );
        }
        if secret_labels_omitted > 0 {
            warnings.push(format!(
                "{secret_labels_omitted} secret-like labels were omitted from candidates"
            ));
        }
        if !redacted_elements.is_empty() {
            warnings
                .push("redacted element values were excluded from value-based matching".to_owned());
        }

        let candidate_limit = usize::try_from(input.max_candidates).map_err(|_| {
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "max_candidates is not representable",
            )
        })?;
        let candidates = ranked
            .iter()
            .take(candidate_limit)
            .map(|candidate| ElementCandidate {
                element_id: candidate.element.element_id.clone(),
                kind: candidate.element.kind.clone(),
                label: candidate.element.label.clone(),
                score: f64::from(candidate.points) / 1_000.0,
                matched_features: candidate.matched_features.clone(),
                evidence: vec![format!(
                    "observation:{}/element:{}",
                    input.observation_snapshot.observation_id, candidate.element.element_id
                )],
                trust_labels: candidate.element.trust_labels.clone(),
            })
            .collect::<Vec<_>>();
        let result = ElementGroundingResult {
            schema_version: SCHEMA_VERSION,
            goal_id: input.goal_id.clone(),
            source_observation_hash: input.source_observation_hash.clone(),
            plan_generation_id: input.plan_generation_id.clone(),
            target_text: input.target_text.clone(),
            status,
            selected_element_id,
            candidates,
            ambiguity_reason: reason,
            user_confirmation_required: confirmation,
            evidence: vec![
                format!("observation:{}", input.observation_snapshot.observation_id),
                "ranking-policy:deterministic-element-grounder-v1".to_owned(),
            ],
            warnings: warnings.clone(),
        };
        validate_result(&result, &input.observation_snapshot)?;
        let confidence = status_confidence(status, top_points, margin);
        let hint_count = input
            .expected_kinds
            .len()
            .saturating_add(input.required_terms.len())
            .saturating_add(input.excluded_terms.len())
            .saturating_add(input.context_terms.len())
            .saturating_add(4);
        let operations = input
            .observation_snapshot
            .observable_elements
            .len()
            .saturating_mul(hint_count)
            .saturating_add(ranked.len())
            .saturating_add(1);
        let logical_operations = u64::try_from(operations).map_err(|_| {
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "logical operation count is not representable",
            )
        })?;
        module_output(
            result,
            source_hash,
            confidence,
            logical_operations,
            warnings,
        )
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec![
                "deterministic scoring policy v1 loaded".to_owned(),
                "model, network, filesystem, and side effects unavailable".to_owned(),
            ],
        }
    }
}

struct RankedCandidate<'a> {
    element: &'a ObservableElement,
    points: u32,
    match_strength: u8,
    expected_kind_match: bool,
    required_terms_match: bool,
    matched_features: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn score_element<'a>(
    element: &'a ObservableElement,
    target: &str,
    raw_target: &str,
    expected_kinds: &[String],
    required_terms: &[String],
    excluded_terms: &[String],
    context_terms: &[String],
    redacted: bool,
) -> Option<RankedCandidate<'a>> {
    let normalized_label = normalize(&element.label);
    let safe_value = if redacted {
        None
    } else {
        element.value.as_str().filter(|value| !secret_like(value))
    };
    let normalized_value = safe_value.map(normalize);
    if excluded_terms.iter().any(|term| {
        contains_term(&normalized_label, term)
            || normalized_value
                .as_deref()
                .is_some_and(|value| contains_term(value, term))
    }) {
        return None;
    }

    let target_tokens = tokens(target);
    let label_tokens = tokens(&normalized_label);
    let mut points = 0_u32;
    let mut strength = 0_u8;
    let mut features = Vec::new();
    if normalized_label == target {
        points = points.saturating_add(700);
        strength = 5;
        features.push("normalized_label_exact".to_owned());
        if element.label.trim() == raw_target {
            points = points.saturating_add(50);
            features.push("raw_label_exact".to_owned());
        }
    } else if normalized_label.contains(target) {
        points = points.saturating_add(550);
        strength = 4;
        features.push("target_phrase_in_label".to_owned());
    } else {
        let overlap = target_tokens
            .iter()
            .filter(|token| label_tokens.contains(*token))
            .count();
        if overlap > 0 {
            let denominator = u32::try_from(target_tokens.len()).ok()?;
            let numerator = u32::try_from(overlap).ok()?;
            points = points.saturating_add(numerator.saturating_mul(450) / denominator);
            strength = 3;
            features.push("target_token_overlap".to_owned());
        }
    }

    let normalized_kind = normalize(&element.kind);
    let expected_kind_match =
        expected_kinds.is_empty() || expected_kinds.contains(&normalized_kind);
    if !expected_kinds.is_empty() && expected_kind_match {
        points = points.saturating_add(200);
        features.push("expected_kind".to_owned());
    }

    let required_terms_match = required_terms.iter().all(|term| {
        contains_term(&normalized_label, term)
            || normalized_value
                .as_deref()
                .is_some_and(|value| contains_term(value, term))
    });
    if !required_terms.is_empty() && required_terms_match {
        points = points.saturating_add(180);
        features.push("required_terms".to_owned());
    }

    let context_matches = context_terms
        .iter()
        .filter(|term| {
            contains_term(&normalized_label, term)
                || normalized_value
                    .as_deref()
                    .is_some_and(|value| contains_term(value, term))
        })
        .count();
    if context_matches > 0 {
        let numerator = u32::try_from(context_matches).ok()?;
        let denominator = u32::try_from(context_terms.len()).ok()?;
        points = points.saturating_add(numerator.saturating_mul(180) / denominator);
        features.push("context_terms".to_owned());
    }

    if normalized_value
        .as_deref()
        .is_some_and(|value| value.contains(target))
    {
        points = points.saturating_add(80);
        features.push("safe_value_clue".to_owned());
    }
    points = points.min(1_000);
    if points == 0 {
        return None;
    }
    Some(RankedCandidate {
        element,
        points,
        match_strength: strength,
        expected_kind_match,
        required_terms_match,
        matched_features: features,
    })
}

fn compare_ranked(left: &RankedCandidate<'_>, right: &RankedCandidate<'_>) -> Ordering {
    right
        .points
        .cmp(&left.points)
        .then_with(|| right.match_strength.cmp(&left.match_strength))
        .then_with(|| right.expected_kind_match.cmp(&left.expected_kind_match))
        .then_with(|| left.element.element_id.cmp(&right.element.element_id))
}

fn classify(
    ranked: &[RankedCandidate<'_>],
    top_points: u32,
    margin: u32,
    any_expected_kind: bool,
    empty_observation: bool,
) -> (GroundingStatus, Option<String>, bool) {
    if empty_observation {
        return (
            GroundingStatus::NotFound,
            Some("ObservationSnapshot contains no observable elements".to_owned()),
            false,
        );
    }
    if ranked.is_empty() {
        return (
            GroundingStatus::NotFound,
            Some("no candidate matched the target or allowed hints".to_owned()),
            false,
        );
    }
    if !any_expected_kind {
        return (
            GroundingStatus::NotFound,
            Some("no candidate has an expected kind".to_owned()),
            false,
        );
    }
    if top_points < NOT_FOUND_SCORE_THRESHOLD {
        return (
            GroundingStatus::NotFound,
            Some("best candidate is below the not-found threshold".to_owned()),
            false,
        );
    }
    let top = &ranked[0];
    if top_points >= UNIQUE_SCORE_THRESHOLD
        && margin >= UNIQUE_MARGIN_THRESHOLD
        && top.expected_kind_match
        && top.required_terms_match
    {
        return (GroundingStatus::UniqueMatch, None, false);
    }
    let reason = if top_points < UNIQUE_SCORE_THRESHOLD {
        "best candidate is below the unique-match threshold"
    } else if margin < UNIQUE_MARGIN_THRESHOLD {
        "top candidates are within the unique-match margin"
    } else if !top.expected_kind_match {
        "best candidate does not satisfy expected_kinds"
    } else {
        "best candidate does not satisfy required_terms"
    };
    (GroundingStatus::Ambiguous, Some(reason.to_owned()), true)
}

fn status_confidence(status: GroundingStatus, top_points: u32, margin: u32) -> f64 {
    let thousandths = match status {
        GroundingStatus::UniqueMatch => top_points.saturating_add(margin).min(2_000) / 2,
        GroundingStatus::Ambiguous => 1_000_u32.saturating_sub(margin.min(1_000)),
        GroundingStatus::NotFound => 1_000_u32.saturating_sub(top_points.min(1_000)),
        GroundingStatus::Unsupported => 1_000,
    };
    f64::from(thousandths) / 1_000.0
}

fn terminal_without_candidates(
    input: &ElementGroundingInput,
    status: GroundingStatus,
    reason: &str,
    user_confirmation_required: bool,
) -> ElementGroundingResult {
    ElementGroundingResult {
        schema_version: SCHEMA_VERSION,
        goal_id: input.goal_id.clone(),
        source_observation_hash: input.source_observation_hash.clone(),
        plan_generation_id: input.plan_generation_id.clone(),
        target_text: input.target_text.clone(),
        status,
        selected_element_id: None,
        candidates: Vec::new(),
        ambiguity_reason: Some(reason.to_owned()),
        user_confirmation_required,
        evidence: vec![
            format!("observation:{}", input.observation_snapshot.observation_id),
            "ranking-policy:deterministic-element-grounder-v1".to_owned(),
        ],
        warnings: Vec::new(),
    }
}

fn module_output(
    result: ElementGroundingResult,
    source_hash: String,
    confidence: f64,
    logical_operations: u64,
    warnings: Vec<String>,
) -> Result<ModuleOutput<ElementGroundingResult>, ModuleError> {
    let mut output = ModuleOutput::new(
        result,
        ModuleProvenance {
            source_id: "cognitive-observation-snapshot".to_owned(),
            source_sha256: source_hash,
            producer: MODULE_ID.to_owned(),
        },
    );
    output.confidence = Some(confidence);
    output.evidence = vec!["deterministic-element-grounder-v1".to_owned()];
    output.warnings = warnings;
    output.logical_operations = logical_operations;
    output.logical_elapsed_ticks = 1;
    Ok(output)
}

fn validate_result(
    result: &ElementGroundingResult,
    observation: &ObservationSnapshot,
) -> Result<(), ModuleError> {
    let element_ids = observation
        .observable_elements
        .iter()
        .map(|element| element.element_id.as_str())
        .collect::<BTreeSet<_>>();
    if result.candidates.len() > usize::try_from(MAX_CANDIDATES).unwrap_or(64) {
        return Err(ModuleError::new(
            ModuleErrorCode::InternalFailure,
            "generated candidate list exceeds module limit",
        ));
    }
    for candidate in &result.candidates {
        if !element_ids.contains(candidate.element_id.as_str())
            || !candidate.score.is_finite()
            || !(0.0..=1.0).contains(&candidate.score)
        {
            return Err(ModuleError::new(
                ModuleErrorCode::InternalFailure,
                "generated candidate violates observation or score contract",
            ));
        }
    }
    match (result.status, result.selected_element_id.as_deref()) {
        (GroundingStatus::UniqueMatch, Some(selected)) if element_ids.contains(selected) => Ok(()),
        (GroundingStatus::UniqueMatch, _) => Err(ModuleError::new(
            ModuleErrorCode::InternalFailure,
            "unique_match requires an observed selected_element_id",
        )),
        (_, None) => Ok(()),
        (_, Some(_)) => Err(ModuleError::new(
            ModuleErrorCode::InternalFailure,
            "non-unique result must not select an element",
        )),
    }
}

fn normalize_terms(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| normalize(value))
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize(value: &str) -> String {
    let mut output = String::new();
    let mut pending_space = false;
    for character in value.trim().chars() {
        if character.is_whitespace() || is_limited_punctuation(character) {
            pending_space = !output.is_empty();
            continue;
        }
        if pending_space {
            output.push(' ');
            pending_space = false;
        }
        output.push(if character.is_ascii() {
            character.to_ascii_lowercase()
        } else {
            character
        });
    }
    output
}

fn is_limited_punctuation(character: char) -> bool {
    matches!(
        character,
        '.' | ','
            | '!'
            | '?'
            | ';'
            | ':'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '"'
            | '\''
            | '-'
            | '_'
            | '/'
            | '\\'
            | '·'
            | '，'
            | '。'
            | '！'
            | '？'
    )
}

fn tokens(value: &str) -> BTreeSet<&str> {
    value
        .split_whitespace()
        .filter(|item| !item.is_empty())
        .collect()
}

fn contains_term(haystack: &str, needle: &str) -> bool {
    !needle.is_empty() && haystack.contains(needle)
}

fn redacted_element_ids(observation: &ObservationSnapshot) -> BTreeSet<String> {
    observation
        .observable_elements
        .iter()
        .filter(|element| {
            observation
                .redactions
                .iter()
                .any(|redaction| redaction.field.contains(&element.element_id))
        })
        .map(|element| element.element_id.clone())
        .collect()
}

fn secret_like(value: &str) -> bool {
    let normalized = normalize(value);
    [
        "password",
        "passwd",
        "secret",
        "api key",
        "apikey",
        "access token",
        "refresh token",
        "authorization",
        "cookie",
        "비밀번호",
        "인증 토큰",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn validate_provenance(provenance: &CognitiveProvenance) -> Result<(), ModuleError> {
    validate_text(&provenance.source, "provenance source")?;
    validate_hash(&provenance.source_hash, "provenance source_hash")?;
    validate_token(&provenance.module_id, "provenance module_id")
}

fn validate_version(version: u32, field: &str) -> Result<(), ModuleError> {
    if version != SCHEMA_VERSION {
        return Err(ModuleError::new(
            ModuleErrorCode::ContractVersionMismatch,
            format!("{field} schema_version must be 1"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return invalid(format!(
            "{field} is empty, contains NUL, or exceeds 4096 bytes"
        ));
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<(), ModuleError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return invalid(format!("{field} contains unsupported characters"));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), ModuleError> {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return invalid(format!("{field} must use sha256:<hex>"));
    };
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid(format!("{field} must contain 64 hex digits"));
    }
    Ok(())
}

fn validate_string_collection(
    values: &[String],
    field: &str,
    maximum: usize,
) -> Result<(), ModuleError> {
    if values.len() > maximum {
        return resource(format!("{field} exceeds its bounded item count"));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn validate_search_terms(values: &[String], field: &str) -> Result<(), ModuleError> {
    if values.iter().any(|value| normalize(value).is_empty()) {
        return invalid(format!(
            "{field} contains a term with no supported searchable content"
        ));
    }
    Ok(())
}

fn validate_json_bounds(value: &Value) -> Result<(), ModuleError> {
    fn visit(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ModuleError> {
        if depth > MAX_JSON_DEPTH {
            return resource("JSON value exceeds depth 32");
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_JSON_NODES {
            return resource("JSON value exceeds node budget");
        }
        match value {
            Value::Array(items) => {
                for item in items {
                    visit(item, depth.saturating_add(1), nodes)?;
                }
            }
            Value::Object(properties) => {
                for item in properties.values() {
                    visit(item, depth.saturating_add(1), nodes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    let mut nodes = 0;
    visit(value, 0, &mut nodes)
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ModuleError> {
    Err(ModuleError::new(ModuleErrorCode::InvalidInput, message))
}

fn resource<T>(message: impl Into<String>) -> Result<T, ModuleError> {
    Err(ModuleError::new(
        ModuleErrorCode::ResourceExhausted,
        message,
    ))
}

fn stale<T>(message: impl Into<String>) -> Result<T, ModuleError> {
    Err(ModuleError::new(
        ModuleErrorCode::DeterministicReplayMismatch,
        message,
    ))
}
