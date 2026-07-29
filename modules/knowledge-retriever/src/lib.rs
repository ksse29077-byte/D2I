//! Deterministic, side-effect-free knowledge retrieval reference module.

use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Stable module identifier.
pub const MODULE_ID: &str = "knowledge-retriever";
/// Stable module version.
pub const MODULE_VERSION: &str = "1.0.0";
/// Stable build identifier.
pub const BUILD_ID: &str = "knowledge-retriever-v1";
/// Implemented capability identifier.
pub const CAPABILITY_ID: &str = "knowledge.retrieve";
/// Input schema identifier.
pub const INPUT_SCHEMA_ID: &str = "knowledge-retriever-input-v1";
/// Output schema identifier.
pub const OUTPUT_SCHEMA_ID: &str = "knowledge-retriever-output-v1";

const MAX_QUERY_BYTES: usize = 2_048;
const MAX_KNOWLEDGE_ITEMS: usize = 64;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_QUERY_TERMS: usize = 64;
const MAX_TAGS_PER_ITEM: usize = 16;
const MAX_TERMINOLOGY_ALIASES: usize = 128;
const MAX_RESULTS: usize = 16;
const MAX_AUTHORITY_RANK: u16 = 1_000;
const DECLARED_MEMORY_BYTES: u64 = 8_388_608;
const SUPPORTED_INTENTS: &[&str] = &[
    "find_definition",
    "find_rule",
    "find_requirement",
    "find_prohibition",
    "find_permission",
    "find_exception",
    "find_procedure",
    "find_role_responsibility",
    "find_threshold",
    "find_case",
    "find_evidence",
    "compare_versions",
    "verify_statement",
];
const UNSUPPORTED_INTENTS: &[&str] = &[
    "semantic_search",
    "vector_search",
    "pdf_parsing",
    "ocr",
    "network_search",
    "file_loading",
    "database_query",
    "answer_generation",
    "domain_judgment",
    "action_execution",
    "persistent_index_mutation",
    "online_learning",
];
const KNOWLEDGE_TYPES: &[&str] = &[
    "definition",
    "rule",
    "requirement",
    "prohibition",
    "permission",
    "exception",
    "procedure",
    "role_responsibility",
    "threshold",
    "case",
    "evidence",
];

/// Query and bounded retrieval options.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeQuery {
    pub query_id: String,
    pub text: String,
    pub intent: String,
    pub requested_knowledge_types: Vec<String>,
    pub filters: QueryFilters,
    pub as_of: Option<String>,
    pub maximum_results: usize,
    pub minimum_evidence_count: usize,
    pub exclude_superseded: bool,
    pub sort: String,
}

/// Domain-independent metadata filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct QueryFilters {
    pub domain_tags: Vec<String>,
    pub task_tags: Vec<String>,
    pub role_tags: Vec<String>,
}

/// Explicit, caller-authored claim used only for labeled conflict detection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredClaim {
    pub claim_key: String,
    pub normalized_value: String,
    pub modality: String,
    pub unit_or_value_type: Option<String>,
    pub scope_key: String,
}

/// Provenance attached to an immutable knowledge item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeProvenance {
    pub source_id: String,
    pub source_sha256: String,
    pub producer: String,
}

/// One immutable item in the caller-supplied knowledge snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeItem {
    pub knowledge_item_id: String,
    pub document_id: String,
    pub revision_id: String,
    pub section_id: String,
    pub locator: String,
    pub text: String,
    pub knowledge_type: String,
    pub authority_rank: u16,
    pub effective_from: Option<String>,
    pub effective_until: Option<String>,
    pub superseded_by: Option<String>,
    pub content_sha256: String,
    pub domain_tags: Vec<String>,
    pub task_tags: Vec<String>,
    pub role_tags: Vec<String>,
    pub access_labels: Vec<String>,
    pub provenance: KnowledgeProvenance,
    pub structured_claim: Option<StructuredClaim>,
}

/// Bounded terminology normalization supplied by the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminologyEntry {
    pub canonical_term: String,
    pub aliases: Vec<String>,
    pub abbreviations: Vec<String>,
}

/// Caller-authorized access labels and optional scope restriction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessContext {
    pub allowed_access_labels: Vec<String>,
    pub allowed_scope_tags: Vec<String>,
}

/// Strict typed module input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRetrieverInput {
    pub query: KnowledgeQuery,
    pub knowledge_snapshot: Vec<KnowledgeItem>,
    pub terminology: Vec<TerminologyEntry>,
    pub access_context: AccessContext,
}

/// Stable domain-level evidence bundle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceBundleStatus {
    EvidenceFound,
    NoEvidence,
    InsufficientEvidence,
    AmbiguousQuery,
    ConflictingEvidence,
    SupersededEvidenceOnly,
}

/// One exact evidence item with relative ranking metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub knowledge_item_id: String,
    pub document_id: String,
    pub revision_id: String,
    pub section_id: String,
    pub locator: String,
    pub excerpt: String,
    pub knowledge_type: String,
    pub authority_rank: u16,
    pub effective_from: Option<String>,
    pub effective_until: Option<String>,
    pub provenance: KnowledgeProvenance,
    pub relevance_score_bps: u16,
    pub ranking_reasons: Vec<String>,
    pub applied_tags: Vec<String>,
    pub structured_claim: Option<StructuredClaim>,
}

/// Explicit conflict between two labeled structured claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRecord {
    pub claim_key: String,
    pub scope_key: String,
    pub left_knowledge_item_id: String,
    pub right_knowledge_item_id: String,
    pub left_value: String,
    pub right_value: String,
}

/// Safe summary of filters applied before scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedFilters {
    pub access_filter_applied: bool,
    pub temporal_filter_applied: bool,
    pub superseded_filter_applied: bool,
    pub metadata_filter_applied: bool,
}

/// Verifiable result payload. The SDK supplies terminal status and canonical hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub schema_version: u32,
    pub query_id: String,
    pub status: EvidenceBundleStatus,
    pub normalized_query: String,
    pub evidence_items: Vec<EvidenceItem>,
    pub conflicts: Vec<ConflictRecord>,
    pub evidence_gaps: Vec<String>,
    pub warnings: Vec<String>,
    pub applied_filters: AppliedFilters,
    pub deterministic_ordering: String,
    pub logical_operations: u64,
}

#[derive(Debug, Clone)]
struct Candidate {
    item: KnowledgeItem,
    score: u16,
    reasons: Vec<String>,
    applied_tags: Vec<String>,
}

/// Pure deterministic knowledge retriever.
#[derive(Debug, Clone, Copy, Default)]
pub struct KnowledgeRetriever;

impl Module for KnowledgeRetriever {
    type Input = KnowledgeRetrieverInput;
    type Output = EvidenceBundle;

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
            category: ModuleCategory("knowledge_retriever".to_owned()),
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
        _context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        validate_input(input)
    }

    fn invoke(
        &self,
        input: Self::Input,
        _context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        if UNSUPPORTED_INTENTS.contains(&input.query.intent.as_str()) {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                format!("query intent '{}' is not supported", input.query.intent),
            ));
        }

        let source_hash = canonical_sha256(&input)?;
        let normalized_query = normalize_text(&input.query.text);
        let aliases = alias_map(&input.terminology);
        let query_terms = expanded_terms(&normalized_query, &aliases);
        let mut logical_operations = 1_u64;
        let mut saw_authorized_superseded = false;
        let mut candidates = Vec::new();

        for item in &input.knowledge_snapshot {
            logical_operations = logical_operations.saturating_add(1);
            if !is_authorized(item, &input.access_context) {
                continue;
            }
            if input.query.exclude_superseded && item.superseded_by.is_some() {
                saw_authorized_superseded = true;
                continue;
            }
            if !is_temporally_applicable(item, input.query.as_of.as_deref()) {
                continue;
            }
            if !matches_metadata(item, &input.query.filters) {
                continue;
            }
            let scored = score_item(item, &normalized_query, &query_terms, &input.query);
            logical_operations = logical_operations.saturating_add(u64::from(scored.score).min(64));
            if scored.score > 0 {
                candidates.push(scored);
            }
        }

        candidates.sort_by(compare_candidates);
        let mut by_content = BTreeMap::<String, Candidate>::new();
        for candidate in candidates {
            by_content
                .entry(candidate.item.content_sha256.clone())
                .or_insert(candidate);
        }
        let mut candidates = by_content.into_values().collect::<Vec<_>>();
        candidates.sort_by(compare_candidates);
        candidates.truncate(input.query.maximum_results);

        let evidence_items = candidates
            .iter()
            .map(candidate_to_evidence)
            .collect::<Vec<_>>();
        let conflicts = detect_conflicts(&evidence_items);
        let status = determine_status(
            &input.query,
            &evidence_items,
            &conflicts,
            saw_authorized_superseded,
        );
        let evidence_gaps = evidence_gaps(&input.query, evidence_items.len(), status);
        let top_score = evidence_items
            .first()
            .map_or(0_u16, |item| item.relevance_score_bps);
        let peak_memory_bytes = estimate_peak_memory(&input);
        logical_operations = logical_operations
            .saturating_add(u64::try_from(evidence_items.len()).unwrap_or(u64::MAX))
            .saturating_add(u64::try_from(conflicts.len()).unwrap_or(u64::MAX));
        let bundle = EvidenceBundle {
            schema_version: 1,
            query_id: input.query.query_id,
            status,
            normalized_query,
            evidence_items,
            conflicts,
            evidence_gaps,
            warnings: Vec::new(),
            applied_filters: AppliedFilters {
                access_filter_applied: true,
                temporal_filter_applied: input.query.as_of.is_some(),
                superseded_filter_applied: input.query.exclude_superseded,
                metadata_filter_applied: has_metadata_filters(&input.query.filters),
            },
            deterministic_ordering:
                "relevance_score_bps desc, authority_rank desc, knowledge_item_id asc".to_owned(),
            logical_operations,
        };
        let mut output = ModuleOutput::new(
            bundle,
            ModuleProvenance {
                source_id: "caller-knowledge-snapshot".to_owned(),
                source_sha256: source_hash,
                producer: MODULE_ID.to_owned(),
            },
        );
        output.confidence = Some(f64::from(top_score) / 10_000.0);
        output.evidence = vec!["deterministic-lexical-ranking-v1".to_owned()];
        output.peak_memory_bytes = peak_memory_bytes;
        output.logical_operations = logical_operations;
        output.logical_elapsed_ticks = logical_operations.max(1);
        Ok(output)
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec![
                "deterministic lexical rules available".to_owned(),
                "network, filesystem, environment, persistence, and side effects unavailable"
                    .to_owned(),
            ],
        }
    }
}

fn validate_input(input: &KnowledgeRetrieverInput) -> Result<(), ModuleError> {
    if input.query.text.trim().is_empty() {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "query text must not be empty",
        ));
    }
    if input.query.text.len() > MAX_QUERY_BYTES {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "query text exceeds 2048 bytes",
        ));
    }
    if !SUPPORTED_INTENTS.contains(&input.query.intent.as_str())
        && !UNSUPPORTED_INTENTS.contains(&input.query.intent.as_str())
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "query intent is unknown",
        ));
    }
    if input.query.maximum_results == 0 || input.query.maximum_results > MAX_RESULTS {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "maximum_results must be within 1..=16",
        ));
    }
    if input.query.minimum_evidence_count > input.query.maximum_results {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "minimum_evidence_count cannot exceed maximum_results",
        ));
    }
    if input.query.sort != "relevance_authority_id" {
        return Err(ModuleError::new(
            ModuleErrorCode::UnsupportedInput,
            "only relevance_authority_id sorting is supported",
        ));
    }
    if input.knowledge_snapshot.len() > MAX_KNOWLEDGE_ITEMS {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "knowledge snapshot exceeds 64 items",
        ));
    }
    let normalized = normalize_text(&input.query.text);
    if tokenize(&normalized).len() > MAX_QUERY_TERMS {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "query exceeds 64 normalized terms",
        ));
    }
    validate_optional_date(input.query.as_of.as_deref(), "query.as_of")?;
    validate_unique_nonempty(&input.access_context.allowed_access_labels, "access labels")?;
    let alias_count = input
        .terminology
        .iter()
        .map(|term| term.aliases.len().saturating_add(term.abbreviations.len()))
        .sum::<usize>();
    if alias_count > MAX_TERMINOLOGY_ALIASES {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "terminology aliases exceed 128",
        ));
    }
    let mut ids = BTreeSet::new();
    for item in &input.knowledge_snapshot {
        if !ids.insert(item.knowledge_item_id.as_str()) {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "duplicate knowledge_item_id",
            ));
        }
        validate_item(item)?;
    }
    Ok(())
}

fn validate_item(item: &KnowledgeItem) -> Result<(), ModuleError> {
    if item.text.len() > MAX_TEXT_BYTES {
        return Err(ModuleError::new(
            ModuleErrorCode::ResourceExhausted,
            "knowledge item text exceeds 4096 bytes",
        ));
    }
    if !KNOWLEDGE_TYPES.contains(&item.knowledge_type.as_str()) {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "knowledge_type is unsupported",
        ));
    }
    if item.authority_rank > MAX_AUTHORITY_RANK {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "authority_rank exceeds 1000",
        ));
    }
    for tags in [&item.domain_tags, &item.task_tags, &item.role_tags] {
        if tags.len() > MAX_TAGS_PER_ITEM {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "knowledge item tag collection exceeds 16",
            ));
        }
        validate_unique_nonempty(tags, "knowledge item tags")?;
    }
    validate_unique_nonempty(&item.access_labels, "knowledge item access labels")?;
    validate_sha256(&item.content_sha256, "content_sha256")?;
    validate_sha256(&item.provenance.source_sha256, "provenance.source_sha256")?;
    validate_optional_date(item.effective_from.as_deref(), "effective_from")?;
    validate_optional_date(item.effective_until.as_deref(), "effective_until")?;
    if let (Some(from), Some(until)) = (&item.effective_from, &item.effective_until) {
        if from > until {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "effective interval is reversed",
            ));
        }
    }
    Ok(())
}

fn validate_unique_nonempty(values: &[String], label: &str) -> Result<(), ModuleError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() || !seen.insert(value) {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("{label} must be non-empty and unique"),
            ));
        }
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<(), ModuleError> {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(())
    } else {
        Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{label} must use sha256:<64 lowercase hex>"),
        ))
    }
}

fn validate_optional_date(value: Option<&str>, label: &str) -> Result<(), ModuleError> {
    if value.is_none_or(valid_date) {
        Ok(())
    } else {
        Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{label} must use YYYY-MM-DD"),
        ))
    }
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    matches!(month, Some(1..=12)) && matches!(day, Some(1..=31))
}

fn normalize_text(value: &str) -> String {
    value
        .split_whitespace()
        .flat_map(|part| part.chars().flat_map(char::to_lowercase).chain([' ']))
        .collect::<String>()
        .trim()
        .to_owned()
}

fn tokenize(value: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    let mut current = String::new();
    for character in value.chars() {
        if character.is_alphanumeric() {
            current.extend(character.to_lowercase());
        } else if !current.is_empty() {
            tokens.insert(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.insert(current);
    }
    tokens
}

fn alias_map(terminology: &[TerminologyEntry]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for entry in terminology {
        let canonical = normalize_text(&entry.canonical_term);
        aliases.insert(canonical.clone(), canonical.clone());
        for alias in entry.aliases.iter().chain(&entry.abbreviations) {
            aliases.insert(normalize_text(alias), canonical.clone());
        }
    }
    aliases
}

fn expanded_terms(query: &str, aliases: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut terms = tokenize(query);
    for (alias, canonical) in aliases {
        if query.contains(alias) || terms.contains(alias) {
            terms.extend(tokenize(canonical));
        }
    }
    terms
}

fn is_authorized(item: &KnowledgeItem, access: &AccessContext) -> bool {
    let allowed_labels = access
        .allowed_access_labels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let labels_allowed = !item.access_labels.is_empty()
        && item
            .access_labels
            .iter()
            .all(|label| allowed_labels.contains(label.as_str()));
    let scopes_allowed = access.allowed_scope_tags.is_empty()
        || item
            .domain_tags
            .iter()
            .chain(&item.task_tags)
            .any(|tag| access.allowed_scope_tags.contains(tag));
    labels_allowed && scopes_allowed
}

fn is_temporally_applicable(item: &KnowledgeItem, as_of: Option<&str>) -> bool {
    let Some(as_of) = as_of else {
        return true;
    };
    item.effective_from
        .as_deref()
        .is_none_or(|from| from <= as_of)
        && item
            .effective_until
            .as_deref()
            .is_none_or(|until| as_of <= until)
}

fn matches_metadata(item: &KnowledgeItem, filters: &QueryFilters) -> bool {
    matches_all(&item.domain_tags, &filters.domain_tags)
        && matches_all(&item.task_tags, &filters.task_tags)
        && matches_all(&item.role_tags, &filters.role_tags)
}

fn matches_all(item_values: &[String], requested: &[String]) -> bool {
    requested.iter().all(|value| item_values.contains(value))
}

fn has_metadata_filters(filters: &QueryFilters) -> bool {
    !filters.domain_tags.is_empty()
        || !filters.task_tags.is_empty()
        || !filters.role_tags.is_empty()
}

fn score_item(
    item: &KnowledgeItem,
    normalized_query: &str,
    query_terms: &BTreeSet<String>,
    query: &KnowledgeQuery,
) -> Candidate {
    let normalized_text = normalize_text(&item.text);
    let item_terms = tokenize(&normalized_text);
    let mut score = 0_u32;
    let mut reasons = Vec::new();
    let exact_phrase = normalized_text.contains(normalized_query);
    if exact_phrase {
        score = score.saturating_add(4_000);
        reasons.push("exact_phrase".to_owned());
    }
    let overlap = query_terms.intersection(&item_terms).count();
    if overlap > 0 && !query_terms.is_empty() {
        let overlap_score = u32::try_from(overlap)
            .unwrap_or(u32::MAX)
            .saturating_mul(3_000)
            / u32::try_from(query_terms.len()).unwrap_or(u32::MAX).max(1);
        score = score.saturating_add(overlap_score);
        reasons.push("query_token_overlap".to_owned());
    }
    if !exact_phrase && overlap == 0 {
        return Candidate {
            item: item.clone(),
            score: 0,
            reasons,
            applied_tags: Vec::new(),
        };
    }
    if query.requested_knowledge_types.is_empty()
        || query
            .requested_knowledge_types
            .contains(&item.knowledge_type)
    {
        score = score.saturating_add(1_000);
        reasons.push("knowledge_type_match".to_owned());
    }
    let applied_tags = matching_tags(item, &query.filters);
    if !applied_tags.is_empty() {
        let tag_score = u32::try_from(applied_tags.len())
            .unwrap_or(u32::MAX)
            .saturating_mul(250)
            .min(1_000);
        score = score.saturating_add(tag_score);
        reasons.push("metadata_tag_match".to_owned());
    }
    if query.as_of.is_some() {
        score = score.saturating_add(500);
        reasons.push("temporal_match".to_owned());
    }
    let authority_score = u32::from(item.authority_rank).min(1_000);
    if authority_score > 0 {
        score = score.saturating_add(authority_score);
        reasons.push("authority_rank".to_owned());
    }
    if item.structured_claim.is_some() && query.intent == "verify_statement" {
        score = score.saturating_add(500);
        reasons.push("structured_claim_match".to_owned());
    }
    if query.intent == "compare_versions" {
        score = score.saturating_add(100);
        reasons.push("version_specificity".to_owned());
    }
    Candidate {
        item: item.clone(),
        score: u16::try_from(score.min(10_000)).unwrap_or(10_000),
        reasons,
        applied_tags,
    }
}

fn matching_tags(item: &KnowledgeItem, filters: &QueryFilters) -> Vec<String> {
    let requested = filters
        .domain_tags
        .iter()
        .chain(&filters.task_tags)
        .chain(&filters.role_tags)
        .collect::<BTreeSet<_>>();
    item.domain_tags
        .iter()
        .chain(&item.task_tags)
        .chain(&item.role_tags)
        .filter(|tag| requested.contains(tag))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn compare_candidates(left: &Candidate, right: &Candidate) -> Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| right.item.authority_rank.cmp(&left.item.authority_rank))
        .then_with(|| {
            left.item
                .knowledge_item_id
                .cmp(&right.item.knowledge_item_id)
        })
}

fn candidate_to_evidence(candidate: &Candidate) -> EvidenceItem {
    let item = &candidate.item;
    EvidenceItem {
        evidence_id: format!("evidence-{}", item.knowledge_item_id),
        knowledge_item_id: item.knowledge_item_id.clone(),
        document_id: item.document_id.clone(),
        revision_id: item.revision_id.clone(),
        section_id: item.section_id.clone(),
        locator: item.locator.clone(),
        excerpt: item.text.clone(),
        knowledge_type: item.knowledge_type.clone(),
        authority_rank: item.authority_rank,
        effective_from: item.effective_from.clone(),
        effective_until: item.effective_until.clone(),
        provenance: item.provenance.clone(),
        relevance_score_bps: candidate.score,
        ranking_reasons: candidate.reasons.clone(),
        applied_tags: candidate.applied_tags.clone(),
        structured_claim: item.structured_claim.clone(),
    }
}

fn detect_conflicts(evidence: &[EvidenceItem]) -> Vec<ConflictRecord> {
    let mut conflicts = Vec::new();
    for (index, left) in evidence.iter().enumerate() {
        let Some(left_claim) = &left.structured_claim else {
            continue;
        };
        for right in evidence.iter().skip(index.saturating_add(1)) {
            let Some(right_claim) = &right.structured_claim else {
                continue;
            };
            if left_claim.claim_key == right_claim.claim_key
                && left_claim.scope_key == right_claim.scope_key
                && left_claim.normalized_value != right_claim.normalized_value
            {
                conflicts.push(ConflictRecord {
                    claim_key: left_claim.claim_key.clone(),
                    scope_key: left_claim.scope_key.clone(),
                    left_knowledge_item_id: left.knowledge_item_id.clone(),
                    right_knowledge_item_id: right.knowledge_item_id.clone(),
                    left_value: left_claim.normalized_value.clone(),
                    right_value: right_claim.normalized_value.clone(),
                });
            }
        }
    }
    conflicts
}

fn determine_status(
    query: &KnowledgeQuery,
    evidence: &[EvidenceItem],
    conflicts: &[ConflictRecord],
    saw_superseded: bool,
) -> EvidenceBundleStatus {
    if tokenize(&normalize_text(&query.text)).is_empty() {
        EvidenceBundleStatus::AmbiguousQuery
    } else if !conflicts.is_empty() {
        EvidenceBundleStatus::ConflictingEvidence
    } else if evidence.is_empty() && saw_superseded {
        EvidenceBundleStatus::SupersededEvidenceOnly
    } else if evidence.is_empty() {
        EvidenceBundleStatus::NoEvidence
    } else if evidence.len() < query.minimum_evidence_count {
        EvidenceBundleStatus::InsufficientEvidence
    } else {
        EvidenceBundleStatus::EvidenceFound
    }
}

fn evidence_gaps(
    query: &KnowledgeQuery,
    count: usize,
    status: EvidenceBundleStatus,
) -> Vec<String> {
    match status {
        EvidenceBundleStatus::NoEvidence => vec!["no_authorized_matching_evidence".to_owned()],
        EvidenceBundleStatus::InsufficientEvidence => vec![format!(
            "required_{}_found_{}",
            query.minimum_evidence_count, count
        )],
        EvidenceBundleStatus::AmbiguousQuery => vec!["query_has_no_searchable_terms".to_owned()],
        EvidenceBundleStatus::SupersededEvidenceOnly => {
            vec!["only_superseded_evidence_matched".to_owned()]
        }
        EvidenceBundleStatus::ConflictingEvidence => {
            vec!["explicit_structured_claims_conflict".to_owned()]
        }
        EvidenceBundleStatus::EvidenceFound => Vec::new(),
    }
}

fn estimate_peak_memory(input: &KnowledgeRetrieverInput) -> u64 {
    let text_bytes = input
        .knowledge_snapshot
        .iter()
        .map(|item| item.text.len())
        .sum::<usize>()
        .saturating_add(input.query.text.len());
    u64::try_from(text_bytes.saturating_mul(4))
        .unwrap_or(DECLARED_MEMORY_BYTES)
        .min(DECLARED_MEMORY_BYTES)
}
