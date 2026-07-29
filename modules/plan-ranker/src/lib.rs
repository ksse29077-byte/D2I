//! Deterministic, side-effect-free ranking for prevalidated action candidates.

use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Stable module identifier.
pub const MODULE_ID: &str = "plan-ranker";
/// Stable module version.
pub const MODULE_VERSION: &str = "1.0.0";
/// Build identifier used by deterministic fixtures.
pub const BUILD_ID: &str = "plan-ranker-v1";
/// Capability implemented by this module.
pub const CAPABILITY_ID: &str = "cognitive.plan-rank";
/// Module-local input schema identifier.
pub const INPUT_SCHEMA_ID: &str = "cognitive-plan-ranking-input-v1";
/// Module-local output schema identifier.
pub const OUTPUT_SCHEMA_ID: &str = "cognitive-plan-ranking-output-v1";

const MAX_CANDIDATES: usize = 64;
const MAX_EVIDENCE_IDS: usize = 32;
const MAX_MILLIONTHS: u32 = 1_000_000;
const RANKING_POLICY_VERSION: u32 = 1;

/// Result of one upstream hard gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Passed,
    Failed,
    Unknown,
}

/// Stable gate name used in rejection metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateName {
    Policy,
    Activation,
    Binding,
    InputSchema,
    OutputSchema,
    Risk,
    SideEffect,
    Network,
    Credential,
    Capability,
    Quality,
}

/// Prevalidated hard-gate results supplied by trusted boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateResults {
    pub policy: GateStatus,
    pub activation: GateStatus,
    pub binding: GateStatus,
    pub input_schema: GateStatus,
    pub output_schema: GateStatus,
    pub risk: GateStatus,
    pub side_effect: GateStatus,
    pub network: GateStatus,
    pub credential: GateStatus,
    pub capability: GateStatus,
    pub quality: GateStatus,
}

impl GateResults {
    fn ordered(&self) -> [(GateName, GateStatus); 11] {
        [
            (GateName::Policy, self.policy),
            (GateName::Activation, self.activation),
            (GateName::Binding, self.binding),
            (GateName::InputSchema, self.input_schema),
            (GateName::OutputSchema, self.output_schema),
            (GateName::Risk, self.risk),
            (GateName::SideEffect, self.side_effect),
            (GateName::Network, self.network),
            (GateName::Credential, self.credential),
            (GateName::Capability, self.capability),
            (GateName::Quality, self.quality),
        ]
    }

    fn rejection_reasons(&self) -> Vec<GateRejection> {
        self.ordered()
            .into_iter()
            .filter(|(_, status)| *status != GateStatus::Passed)
            .map(|(gate, status)| GateRejection { gate, status })
            .collect()
    }
}

/// Bounded metadata for one upstream candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankingCandidate {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub capability_id: String,
    pub capability_version: String,
    pub input_schema_id: String,
    pub input_schema_version: u32,
    pub output_schema_id: String,
    pub output_schema_version: u32,
    pub normalized_cost_millionths: u32,
    pub success_likelihood_millionths: u32,
    pub gate_results: GateResults,
    pub evidence_ids: Vec<String>,
}

impl RankingCandidate {
    fn validate(&self) -> Result<(), ModuleError> {
        validate_identifier(&self.candidate_id, "candidate_id")?;
        validate_sha256(&self.candidate_hash, "candidate_hash")?;
        validate_identifier(&self.capability_id, "capability_id")?;
        validate_semantic_version(&self.capability_version)?;
        validate_identifier(&self.input_schema_id, "input_schema_id")?;
        validate_identifier(&self.output_schema_id, "output_schema_id")?;
        if self.input_schema_version == 0 || self.output_schema_version == 0 {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "candidate schema versions must be greater than zero",
            ));
        }
        if self.normalized_cost_millionths > MAX_MILLIONTHS
            || self.success_likelihood_millionths > MAX_MILLIONTHS
        {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "candidate cost and success likelihood must be within 0..=1000000",
            ));
        }
        if self.evidence_ids.is_empty() || self.evidence_ids.len() > MAX_EVIDENCE_IDS {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "candidate evidence_ids must contain 1..=32 values",
            ));
        }
        let mut evidence = BTreeSet::new();
        for evidence_id in &self.evidence_ids {
            validate_identifier(evidence_id, "evidence_id")?;
            if !evidence.insert(evidence_id) {
                return Err(ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "candidate evidence_ids must be unique",
                ));
            }
        }
        Ok(())
    }
}

/// Strict module-local Plan Ranker input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerInput {
    pub schema_version: u32,
    pub candidates: Vec<RankingCandidate>,
}

impl PlanRankerInput {
    fn validate(&self) -> Result<(), ModuleError> {
        if self.schema_version != 1 {
            return Err(ModuleError::new(
                ModuleErrorCode::InvalidInput,
                "Plan Ranker input schema_version must be 1",
            ));
        }
        if self.candidates.len() > MAX_CANDIDATES {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "Plan Ranker accepts at most 64 candidates",
            ));
        }
        if self.candidates.is_empty() {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                "no_candidates",
            ));
        }

        let mut candidate_ids = BTreeSet::new();
        let mut candidate_hashes = BTreeSet::new();
        for candidate in &self.candidates {
            candidate.validate()?;
            if !candidate_ids.insert(candidate.candidate_id.as_str()) {
                return Err(ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "candidate_id values must be unique",
                ));
            }
            if !candidate_hashes.insert(candidate.candidate_hash.as_str()) {
                return Err(ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    "candidate_hash values must be unique",
                ));
            }
        }
        Ok(())
    }
}

/// One non-passed hard gate in fixed contract order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateRejection {
    pub gate: GateName,
    pub status: GateStatus,
}

/// Ranked metadata for one eligible candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankedCandidate {
    pub rank: u32,
    pub candidate_id: String,
    pub candidate_hash: String,
    pub normalized_cost_millionths: u32,
    pub success_likelihood_millionths: u32,
}

/// Rejection metadata for one ineligible candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedCandidate {
    pub candidate_id: String,
    pub candidate_hash: String,
    pub reasons: Vec<GateRejection>,
}

/// Whether at least one eligible candidate was ranked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RankingOutcome {
    Ranked,
    NoEligibleCandidate,
}

/// Strict module-local Plan Ranker output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRankerOutput {
    pub schema_version: u32,
    pub ranking_policy_version: u32,
    pub outcome: RankingOutcome,
    pub selected_candidate_id: Option<String>,
    pub selected_candidate_hash: Option<String>,
    pub ranked_candidates: Vec<RankedCandidate>,
    pub rejected_candidates: Vec<RejectedCandidate>,
}

/// Pure deterministic Plan Ranker reference module.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlanRanker;

impl Module for PlanRanker {
    type Input = PlanRankerInput;
    type Output = PlanRankerOutput;

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
            capability_version: MODULE_VERSION.to_owned(),
            category: ModuleCategory("plan_ranker".to_owned()),
            supported_input_kinds: vec![INPUT_SCHEMA_ID.to_owned()],
            supported_output_kinds: vec![OUTPUT_SCHEMA_ID.to_owned()],
            supported_risk_classes: vec!["read_only".to_owned()],
            deterministic: true,
            side_effect: false,
            network_requirement: NetworkRequirement::Denied,
            streaming: false,
            confidence_semantics: ConfidenceSemantics::NotApplicable,
        }]
    }

    fn validate_input(
        &self,
        input: &Self::Input,
        context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        validate_trust_labels(&context.invocation_trust_labels)?;
        input.validate()
    }

    fn invoke(
        &self,
        input: Self::Input,
        context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        self.validate_input(&input, context)?;
        let source_hash = canonical_sha256(&input)?;
        let mut evidence = BTreeMap::new();
        for candidate in &input.candidates {
            evidence.insert(
                (
                    candidate.candidate_hash.clone(),
                    candidate.candidate_id.clone(),
                ),
                format!(
                    "candidate={};evidence={}",
                    candidate.candidate_id,
                    candidate.evidence_ids.join(",")
                ),
            );
        }

        let candidate_count = input.candidates.len();
        let mut eligible = Vec::new();
        let mut rejected = Vec::new();
        for candidate in input.candidates {
            let reasons = candidate.gate_results.rejection_reasons();
            if reasons.is_empty() {
                eligible.push(candidate);
            } else {
                rejected.push(RejectedCandidate {
                    candidate_id: candidate.candidate_id,
                    candidate_hash: candidate.candidate_hash,
                    reasons,
                });
            }
        }

        let eligible_comparisons = insertion_sort_by(&mut eligible, compare_eligible);
        let rejected_comparisons = insertion_sort_by(&mut rejected, compare_rejected);
        let selected_candidate_id = eligible.first().map(|item| item.candidate_id.clone());
        let selected_candidate_hash = eligible.first().map(|item| item.candidate_hash.clone());
        let ranked_candidates = eligible
            .into_iter()
            .enumerate()
            .map(|(index, candidate)| {
                let rank = u32::try_from(index.saturating_add(1)).map_err(|_| {
                    ModuleError::new(
                        ModuleErrorCode::ResourceExhausted,
                        "candidate rank is not representable",
                    )
                })?;
                Ok(RankedCandidate {
                    rank,
                    candidate_id: candidate.candidate_id,
                    candidate_hash: candidate.candidate_hash,
                    normalized_cost_millionths: candidate.normalized_cost_millionths,
                    success_likelihood_millionths: candidate.success_likelihood_millionths,
                })
            })
            .collect::<Result<Vec<_>, ModuleError>>()?;
        let outcome = if ranked_candidates.is_empty() {
            RankingOutcome::NoEligibleCandidate
        } else {
            RankingOutcome::Ranked
        };
        let output_value = PlanRankerOutput {
            schema_version: 1,
            ranking_policy_version: RANKING_POLICY_VERSION,
            outcome,
            selected_candidate_id,
            selected_candidate_hash,
            ranked_candidates,
            rejected_candidates: rejected,
        };

        let candidate_operations = u64::try_from(candidate_count)
            .map_err(|_| {
                ModuleError::new(
                    ModuleErrorCode::ResourceExhausted,
                    "candidate count is not representable",
                )
            })?
            .saturating_mul(13);
        let mut output = ModuleOutput::new(
            output_value,
            ModuleProvenance {
                source_id: "plan-ranking-input".to_owned(),
                source_sha256: source_hash,
                producer: MODULE_ID.to_owned(),
            },
        );
        output.evidence = evidence.into_values().collect();
        output.logical_operations = 1_u64
            .saturating_add(candidate_operations)
            .saturating_add(eligible_comparisons)
            .saturating_add(rejected_comparisons);
        output.logical_elapsed_ticks = 1;
        if context
            .invocation_trust_labels
            .iter()
            .any(|label| is_untrusted_data_label(label))
        {
            output.warnings.push(
                "untrusted content labels were treated as data and did not influence ranking"
                    .to_owned(),
            );
        }
        Ok(output)
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec![
                "ranking policy v1 loaded".to_owned(),
                "network and side effects unavailable".to_owned(),
            ],
        }
    }
}

fn compare_eligible(left: &RankingCandidate, right: &RankingCandidate) -> Ordering {
    left.normalized_cost_millionths
        .cmp(&right.normalized_cost_millionths)
        .then_with(|| {
            right
                .success_likelihood_millionths
                .cmp(&left.success_likelihood_millionths)
        })
        .then_with(|| {
            left.candidate_hash
                .as_bytes()
                .cmp(right.candidate_hash.as_bytes())
        })
        .then_with(|| {
            left.candidate_id
                .as_bytes()
                .cmp(right.candidate_id.as_bytes())
        })
}

fn compare_rejected(left: &RejectedCandidate, right: &RejectedCandidate) -> Ordering {
    left.candidate_hash
        .as_bytes()
        .cmp(right.candidate_hash.as_bytes())
        .then_with(|| {
            left.candidate_id
                .as_bytes()
                .cmp(right.candidate_id.as_bytes())
        })
}

fn insertion_sort_by<T, F>(items: &mut [T], mut compare: F) -> u64
where
    F: FnMut(&T, &T) -> Ordering,
{
    let mut comparisons = 0_u64;
    for index in 1..items.len() {
        let mut cursor = index;
        while cursor > 0 {
            comparisons = comparisons.saturating_add(1);
            if compare(&items[cursor - 1], &items[cursor]) != Ordering::Greater {
                break;
            }
            items.swap(cursor - 1, cursor);
            cursor -= 1;
        }
    }
    comparisons
}

fn validate_trust_labels(labels: &BTreeSet<String>) -> Result<(), ModuleError> {
    const ACCEPTED: [&str; 5] = [
        "fixture",
        "approved_policy",
        "verified_operational_state",
        "untrusted_web_content",
        "untrusted_document_content",
    ];
    if labels
        .iter()
        .any(|label| !ACCEPTED.contains(&label.as_str()))
    {
        return Err(ModuleError::new(
            ModuleErrorCode::UntrustedInputViolation,
            "invocation contains a trust label not accepted by Plan Ranker",
        ));
    }
    let fixture = labels.contains("fixture");
    let production_authority =
        labels.contains("approved_policy") && labels.contains("verified_operational_state");
    if !fixture && !production_authority {
        return Err(ModuleError::new(
            ModuleErrorCode::UntrustedInputViolation,
            "Plan Ranker requires fixture trust or approved policy plus verified operational state",
        ));
    }
    Ok(())
}

fn is_untrusted_data_label(label: &str) -> bool {
    matches!(
        label,
        "untrusted_web_content" | "untrusted_document_content"
    )
}

fn validate_identifier(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must be a stable ASCII identifier of 1..=128 bytes"),
        ));
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<(), ModuleError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must use sha256:<lowercase-hex> form"),
        ));
    };
    if hex.len() != 64
        || !hex
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            format!("{field} must contain 64 lowercase hexadecimal characters"),
        ));
    }
    Ok(())
}

fn validate_semantic_version(value: &str) -> Result<(), ModuleError> {
    let components = value.split('.').collect::<Vec<_>>();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.chars().all(|ch| ch.is_ascii_digit())
        })
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InvalidInput,
            "capability_version must use major.minor.patch numeric form",
        ));
    }
    Ok(())
}
