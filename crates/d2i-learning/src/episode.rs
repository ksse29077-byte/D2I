use crate::{json_bytes, LearningError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const MAX_LIST_ITEMS: usize = 256;
const MAX_TEXT_BYTES: usize = 4096;

/// Trust assigned before an episode may enter candidate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Trusted,
    Reviewed,
    Untrusted,
}

/// Bounded situation identity used for split grouping and shift checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Situation {
    pub category: String,
    pub request: Value,
    #[serde(default)]
    pub context_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub edge_case: bool,
}

/// Route selected by the immutable package that produced the episode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRoute {
    pub skill_id: String,
    pub node_ids: Vec<String>,
    pub module_ids: Vec<String>,
}

/// Bounded action description; arbitrary executable code is not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRecord {
    pub kind: String,
    pub summary: String,
    pub side_effect_requested: bool,
}

/// Stable outcome category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Success,
    Corrected,
    Failed,
    Unknown,
}

/// Observed result after the decision was used or reviewed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeOutcome {
    pub status: OutcomeStatus,
    pub reward_milli: i32,
    pub critical_error: bool,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Human-reviewed correction quarantined from production.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrectionRecord {
    pub corrected_output: Value,
    pub reason: String,
    pub reviewer_id: String,
}

/// Policy decision and approval state observed during execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodePolicy {
    pub result: String,
    pub policy_ids: Vec<String>,
    pub human_approved: bool,
}

/// Source pointer supporting the episode and any correction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodeProvenance {
    pub source: String,
    pub span: String,
    pub content_hash: String,
}

/// Versioned learning episode. Every field is data, never an instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Episode {
    pub schema_version: u32,
    pub episode_id: String,
    pub recorded_at_unix_seconds: u64,
    pub build_id: String,
    pub package_content_hash: String,
    pub situation: Situation,
    pub selected_route: SelectedRoute,
    pub action: ActionRecord,
    pub output: Value,
    pub outcome: EpisodeOutcome,
    pub correction: Option<CorrectionRecord>,
    pub policy: EpisodePolicy,
    pub provenance: Vec<EpisodeProvenance>,
    pub trust: TrustLevel,
}

impl Episode {
    /// Validates bounded fields and cross-field safety invariants.
    pub fn validate(&self) -> Result<(), LearningError> {
        if self.schema_version != 1 {
            return Err(LearningError::Invalid(
                "episode schema_version must be 1".to_owned(),
            ));
        }
        validate_token(&self.episode_id, "episode_id")?;
        validate_token(&self.build_id, "build_id")?;
        validate_hash(&self.package_content_hash, "package_content_hash")?;
        validate_text(&self.situation.category, "situation.category")?;
        validate_text(&self.action.kind, "action.kind")?;
        validate_text(&self.action.summary, "action.summary")?;
        validate_text(&self.policy.result, "policy.result")?;
        if !(-1000..=1000).contains(&self.outcome.reward_milli) {
            return Err(LearningError::Invalid(
                "outcome.reward_milli must be between -1000 and 1000".to_owned(),
            ));
        }
        validate_list(&self.selected_route.node_ids, "selected_route.node_ids")?;
        validate_list(&self.selected_route.module_ids, "selected_route.module_ids")?;
        validate_list(&self.policy.policy_ids, "policy.policy_ids")?;
        if self.provenance.is_empty() || self.provenance.len() > MAX_LIST_ITEMS {
            return Err(LearningError::Invalid(
                "episode provenance count is outside bounds".to_owned(),
            ));
        }
        for provenance in &self.provenance {
            validate_text(&provenance.source, "provenance.source")?;
            validate_text(&provenance.span, "provenance.span")?;
            validate_hash(&provenance.content_hash, "provenance.content_hash")?;
        }
        if matches!(
            self.outcome.status,
            OutcomeStatus::Corrected | OutcomeStatus::Failed
        ) && self.correction.is_none()
        {
            return Err(LearningError::Invalid(
                "corrected or failed outcomes require a reviewed correction".to_owned(),
            ));
        }
        if let Some(correction) = &self.correction {
            validate_text(&correction.reason, "correction.reason")?;
            validate_token(&correction.reviewer_id, "correction.reviewer_id")?;
        }
        if self.action.side_effect_requested
            && (self.policy.result != "allow" || !self.policy.human_approved)
        {
            return Err(LearningError::Invalid(
                "side-effect episodes require allow policy and human approval".to_owned(),
            ));
        }
        let _ = json_bytes(self)?;
        Ok(())
    }
}

pub(crate) fn validate_hash(value: &str, field: &str) -> Result<(), LearningError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(LearningError::Invalid(format!(
            "{field} must use sha256:<hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(LearningError::Invalid(format!(
            "{field} has invalid SHA-256 syntax"
        )));
    }
    Ok(())
}

fn validate_list(values: &[String], field: &str) -> Result<(), LearningError> {
    if values.len() > MAX_LIST_ITEMS {
        return Err(LearningError::Invalid(format!(
            "{field} exceeds {MAX_LIST_ITEMS} items"
        )));
    }
    for value in values {
        validate_token(value, field)?;
    }
    Ok(())
}

pub(crate) fn validate_token(value: &str, field: &str) -> Result<(), LearningError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(LearningError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

pub(crate) fn validate_text(value: &str, field: &str) -> Result<(), LearningError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.contains('\0') {
        return Err(LearningError::Invalid(format!(
            "{field} is empty or exceeds bounds"
        )));
    }
    Ok(())
}
