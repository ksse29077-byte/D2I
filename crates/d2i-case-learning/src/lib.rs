//! Quarantined, offline-only learning candidates derived from valid Episodes.

use d2i_episodic_memory::{
    canonical_json_bytes, hash_without, reject_sensitive_value, validate_hash, validate_id,
    CaseEpisodeV1, EpisodeMemoryNamespaceV1, EpisodicMemoryError, TerminalCaseOutcomeV1, ZERO_HASH,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

pub const CASE_LEARNING_SCHEMA_VERSION: u32 = 1;
pub const MAX_LEARNING_CANDIDATES: usize = 4_096;
pub const MAX_SOURCE_EPISODES_PER_CANDIDATE: usize = 64;
pub const MAX_CANDIDATE_BYTES: usize = 128 * 1024;
pub const MAX_PATTERN_CLASSES: usize = 64;

pub const CASE_LEARNING_RECORD_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/case-learning-record-v1.schema.json");
pub const LEARNING_CANDIDATE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/learning-candidate-v1.schema.json");
pub const LEARNING_CANDIDATE_EVALUATION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/learning-candidate-evaluation-v1.schema.json");
pub const LEARNING_CANDIDATE_REVIEW_DECISION_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/learning-candidate-review-decision-v1.schema.json");
pub const LEARNING_CANDIDATE_EXPORT_BUNDLE_V1_SCHEMA: &str =
    include_str!("../../../schemas/workforce/learning-candidate-export-bundle-v1.schema.json");

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseLearningError {
    Invalid(String),
    Unauthorized(String),
    Integrity(String),
    ResourceLimit(String),
    SensitiveContent(String),
}

impl Display for CaseLearningError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        let (code, message) = match self {
            Self::Invalid(message) => ("invalid", message),
            Self::Unauthorized(message) => ("unauthorized", message),
            Self::Integrity(message) => ("integrity", message),
            Self::ResourceLimit(message) => ("resource_limit", message),
            Self::SensitiveContent(message) => ("sensitive_content", message),
        };
        write!(formatter, "{code}: {message}")
    }
}

impl std::error::Error for CaseLearningError {}

impl From<EpisodicMemoryError> for CaseLearningError {
    fn from(value: EpisodicMemoryError) -> Self {
        match value {
            EpisodicMemoryError::Invalid(message) | EpisodicMemoryError::Json(message) => {
                Self::Invalid(message)
            }
            EpisodicMemoryError::Unauthorized(message) => Self::Unauthorized(message),
            EpisodicMemoryError::Integrity(message) | EpisodicMemoryError::Duplicate(message) => {
                Self::Integrity(message)
            }
            EpisodicMemoryError::Stale(message) => Self::Integrity(message),
            EpisodicMemoryError::SensitiveContent(message) => Self::SensitiveContent(message),
            EpisodicMemoryError::ResourceLimit(message) => Self::ResourceLimit(message),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningCandidateKindV1 {
    EvaluationCaseCandidate,
    ProcedurePatternCandidate,
    PlannerExampleCandidate,
    RecoveryPatternCandidate,
    ApplicationSemanticsReviewCandidate,
    PolicyReviewCandidate,
    PromptTemplateReviewCandidate,
    SecurityRegressionCandidate,
    UnsupportedCaseCandidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningCandidateStatusV1 {
    Quarantined,
    Rejected,
    ExportedForOfflineEvaluation,
    EvaluationPassed,
    EvaluationFailed,
    ApprovedForOfflineBuild,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningCandidateV1 {
    pub schema_version: u32,
    pub candidate_id: String,
    pub candidate_kind: LearningCandidateKindV1,
    pub organization_id: String,
    pub namespace_sha256: String,
    pub role_contract_sha256: String,
    pub work_class_id: String,
    pub source_episode_hashes: Vec<String>,
    pub source_approved_summary_hashes: Vec<String>,
    pub minimum_source_count: u32,
    pub observed_pattern_class_ids: Vec<String>,
    pub proposed_semantic_change_class: String,
    pub expected_benefit_class: String,
    pub risk_class: String,
    pub critical_error_relevance: bool,
    pub required_offline_evaluation_ids: Vec<String>,
    pub data_class_ids: Vec<String>,
    pub redaction_proof_ids: Vec<String>,
    pub status: LearningCandidateStatusV1,
    pub quarantine_reason_codes: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub candidate_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseLearningRecordV1 {
    pub schema_version: u32,
    pub record_id: String,
    pub organization_id: String,
    pub namespace_sha256: String,
    pub source_episode_hashes: Vec<String>,
    pub candidate_sha256: Option<String>,
    pub disposition: LearningCandidateStatusV1,
    pub reason_codes: Vec<String>,
    pub recorded_at_unix_ms: u64,
    pub previous_record_sha256: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningCandidateEvaluationV1 {
    pub schema_version: u32,
    pub candidate_sha256: String,
    pub evaluation_suite_id: String,
    pub evaluation_input_sha256: String,
    pub passed: bool,
    pub critical_error_count: u32,
    pub metric_result_hashes: Vec<String>,
    pub evaluated_at_unix_ms: u64,
    pub evaluation_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningCandidateReviewDecisionV1 {
    pub schema_version: u32,
    pub candidate_sha256: String,
    pub evaluation_sha256: String,
    pub decision: LearningCandidateStatusV1,
    pub reviewer_id: String,
    pub signing_key_id: String,
    pub decided_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub decision_sha256: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LearningCandidateExportBundleV1 {
    pub schema_version: u32,
    pub bundle_id: String,
    pub organization_id: String,
    pub namespace_sha256: String,
    pub candidate_hashes: Vec<String>,
    pub candidate_object_hashes: Vec<String>,
    pub evaluation_schema_ids: Vec<String>,
    pub production_package_hashes_before: Vec<String>,
    pub production_package_hashes_after: Vec<String>,
    pub production_mutation_count: u32,
    pub exported_at_unix_ms: u64,
    pub bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRequestV1<'a> {
    pub candidate_kind: LearningCandidateKindV1,
    pub namespace: &'a EpisodeMemoryNamespaceV1,
    pub episodes: &'a [CaseEpisodeV1],
    pub source_approved_summary_hashes: Vec<String>,
    pub observed_pattern_class_ids: Vec<String>,
    pub proposed_semantic_change_class: String,
    pub expected_benefit_class: String,
    pub risk_class: String,
    pub critical_error_relevance: bool,
    pub required_offline_evaluation_ids: Vec<String>,
    pub quarantine_reason_codes: Vec<String>,
    pub evidence_ids: Vec<String>,
}

pub fn create_learning_candidate(
    request: CandidateRequestV1<'_>,
) -> Result<LearningCandidateV1, CaseLearningError> {
    request.namespace.validate()?;
    if !request.namespace.learning_candidate_allowed {
        return Err(CaseLearningError::Unauthorized(
            "Role/namespace disables learning candidates".to_owned(),
        ));
    }
    let minimum = minimum_source_count(request.candidate_kind);
    if request.episodes.len() < minimum
        || request.episodes.len() > MAX_SOURCE_EPISODES_PER_CANDIDATE
    {
        return Err(CaseLearningError::ResourceLimit(format!(
            "candidate requires {minimum}..={MAX_SOURCE_EPISODES_PER_CANDIDATE} source Episodes"
        )));
    }
    let mut source_hashes = Vec::new();
    let mut data_classes = BTreeSet::new();
    let mut work_class = None;
    for episode in request.episodes {
        episode.validate()?;
        if episode.organization_id != request.namespace.organization_id
            || episode.memory_namespace_sha256 != request.namespace.namespace_sha256
            || episode.role_contract_sha256 != request.namespace.role_contract_sha256
        {
            return Err(CaseLearningError::Unauthorized(
                "source Episode crosses organization, namespace, or Role".to_owned(),
            ));
        }
        if !matches!(
            episode.terminal_outcome,
            TerminalCaseOutcomeV1::VerifiedComplete
                | TerminalCaseOutcomeV1::ExplicitRefusal
                | TerminalCaseOutcomeV1::Escalated
        ) {
            return Err(CaseLearningError::Invalid(
                "source Episode is not terminal".to_owned(),
            ));
        }
        if let Some(current) = &work_class {
            if current != &episode.work_class_id {
                return Err(CaseLearningError::Invalid(
                    "source Episodes have different work classes".to_owned(),
                ));
            }
        } else {
            work_class = Some(episode.work_class_id.clone());
        }
        source_hashes.push(episode.canonical_episode_sha256.clone());
        data_classes.extend(episode.data_class_ids.iter().cloned());
    }
    source_hashes.sort();
    source_hashes.dedup();
    if source_hashes.len() < minimum {
        return Err(CaseLearningError::Invalid(
            "source Episodes are not independent".to_owned(),
        ));
    }
    let work_class_id = work_class.ok_or_else(|| {
        CaseLearningError::Invalid("candidate has no source work class".to_owned())
    })?;
    let seed_hash = d2i_episodic_memory::canonical_sha256(&(
        request.candidate_kind,
        &source_hashes,
        &request.observed_pattern_class_ids,
    ))?;
    let mut candidate = LearningCandidateV1 {
        schema_version: 1,
        candidate_id: format!("candidate-{}", &seed_hash[7..31]),
        candidate_kind: request.candidate_kind,
        organization_id: request.namespace.organization_id.clone(),
        namespace_sha256: request.namespace.namespace_sha256.clone(),
        role_contract_sha256: request.namespace.role_contract_sha256.clone(),
        work_class_id,
        source_episode_hashes: source_hashes,
        source_approved_summary_hashes: request.source_approved_summary_hashes,
        minimum_source_count: minimum as u32,
        observed_pattern_class_ids: request.observed_pattern_class_ids,
        proposed_semantic_change_class: request.proposed_semantic_change_class,
        expected_benefit_class: request.expected_benefit_class,
        risk_class: request.risk_class,
        critical_error_relevance: request.critical_error_relevance,
        required_offline_evaluation_ids: request.required_offline_evaluation_ids,
        data_class_ids: data_classes.into_iter().collect(),
        redaction_proof_ids: request
            .episodes
            .iter()
            .flat_map(|episode| episode.redaction_proof_ids.clone())
            .collect(),
        status: LearningCandidateStatusV1::Quarantined,
        quarantine_reason_codes: request.quarantine_reason_codes,
        evidence_ids: request.evidence_ids,
        candidate_sha256: ZERO_HASH.to_owned(),
    };
    normalize_candidate(&mut candidate);
    candidate.candidate_sha256 = hash_without(&candidate, &["candidate_sha256"])?;
    validate_candidate(&candidate)?;
    Ok(candidate)
}

fn minimum_source_count(kind: LearningCandidateKindV1) -> usize {
    match kind {
        LearningCandidateKindV1::ProcedurePatternCandidate
        | LearningCandidateKindV1::PlannerExampleCandidate
        | LearningCandidateKindV1::RecoveryPatternCandidate
        | LearningCandidateKindV1::PromptTemplateReviewCandidate => 2,
        _ => 1,
    }
}

fn normalize_candidate(candidate: &mut LearningCandidateV1) {
    for values in [
        &mut candidate.source_episode_hashes,
        &mut candidate.source_approved_summary_hashes,
        &mut candidate.observed_pattern_class_ids,
        &mut candidate.required_offline_evaluation_ids,
        &mut candidate.data_class_ids,
        &mut candidate.redaction_proof_ids,
        &mut candidate.quarantine_reason_codes,
        &mut candidate.evidence_ids,
    ] {
        values.sort();
        values.dedup();
    }
}

pub fn validate_candidate(candidate: &LearningCandidateV1) -> Result<(), CaseLearningError> {
    if candidate.schema_version != 1 || candidate.status != LearningCandidateStatusV1::Quarantined {
        return Err(CaseLearningError::Unauthorized(
            "new candidate must be quarantined".to_owned(),
        ));
    }
    validate_id(&candidate.candidate_id, "candidate_id")?;
    validate_hash(&candidate.namespace_sha256, "namespace_sha256")?;
    if candidate.source_episode_hashes.len() < minimum_source_count(candidate.candidate_kind)
        || candidate.source_episode_hashes.len() > MAX_SOURCE_EPISODES_PER_CANDIDATE
    {
        return Err(CaseLearningError::ResourceLimit(
            "candidate source count is invalid".to_owned(),
        ));
    }
    for hash in &candidate.source_episode_hashes {
        validate_hash(hash, "source_episode_hash")?;
    }
    reject_sensitive_value(candidate, "learning candidate")?;
    let encoded = canonical_json_bytes(candidate)?;
    let lowered = String::from_utf8_lossy(&encoded).to_ascii_lowercase();
    if [
        "command",
        "activation",
        "grant authority",
        "expand capability",
        "raw value",
        "prompt insertion",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
    {
        return Err(CaseLearningError::Unauthorized(
            "candidate contains executable or authority-expanding material".to_owned(),
        ));
    }
    if encoded.len() > MAX_CANDIDATE_BYTES {
        return Err(CaseLearningError::ResourceLimit(
            "candidate exceeds byte limit".to_owned(),
        ));
    }
    if hash_without(candidate, &["candidate_sha256"])? != candidate.candidate_sha256 {
        return Err(CaseLearningError::Integrity(
            "candidate hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

impl CaseLearningRecordV1 {
    pub fn seal(mut self) -> Result<Self, CaseLearningError> {
        if self.recorded_at_unix_ms == 0 {
            return Err(CaseLearningError::Invalid("record time is zero".to_owned()));
        }
        self.source_episode_hashes.sort();
        self.source_episode_hashes.dedup();
        self.reason_codes.sort();
        self.reason_codes.dedup();
        self.record_sha256 = hash_without(&self, &["record_sha256"])?;
        Ok(self)
    }
}

impl LearningCandidateEvaluationV1 {
    pub fn seal(mut self) -> Result<Self, CaseLearningError> {
        self.metric_result_hashes.sort();
        self.metric_result_hashes.dedup();
        self.evaluation_sha256 = hash_without(&self, &["evaluation_sha256"])?;
        Ok(self)
    }
}

impl LearningCandidateExportBundleV1 {
    pub fn seal(mut self) -> Result<Self, CaseLearningError> {
        for values in [
            &mut self.candidate_hashes,
            &mut self.candidate_object_hashes,
            &mut self.evaluation_schema_ids,
            &mut self.production_package_hashes_before,
            &mut self.production_package_hashes_after,
        ] {
            values.sort();
            values.dedup();
        }
        if self.production_mutation_count != 0
            || self.production_package_hashes_before != self.production_package_hashes_after
        {
            return Err(CaseLearningError::Unauthorized(
                "offline export mutated production artifacts".to_owned(),
            ));
        }
        self.bundle_sha256 = hash_without(&self, &["bundle_sha256"])?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests;
