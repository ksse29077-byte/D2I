//! Deterministic, model-free Goal Compiler reference module.

use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const MODULE_ID: &str = "goal-compiler";
pub const MODULE_VERSION: &str = "1.0.0";
pub const BUILD_ID: &str = "goal-compiler-v1";
pub const CAPABILITY_ID: &str = "cognitive.goal-compile";
pub const INPUT_SCHEMA_ID: &str = "goal-compilation-input-v1";
pub const OUTPUT_SCHEMA_ID: &str = "goal-compilation-result-v1";

const SCHEMA_VERSION: u32 = 1;
const MAX_TEXT_BYTES: usize = 4_096;
const MAX_ITEMS: usize = 64;
const MAX_JSON_DEPTH: usize = 32;

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

    fn is_untrusted(self) -> bool {
        matches!(
            self,
            Self::ObservedUiState | Self::UntrustedWebContent | Self::UntrustedDocumentContent
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveProvenance {
    pub source: String,
    pub source_hash: String,
    pub module_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CognitiveRiskClass {
    ReadOnly,
    Reversible,
    BusinessStateChange,
    HighCriticality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationPolicy {
    Never,
    BeforeRiskyAction,
    BeforeIrreversibleAction,
    Always,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOp {
    Equals,
    NotEquals,
    Contains,
    Exists,
    GreaterOrEqual,
    LessOrEqual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Postcondition {
    pub target_state: String,
    pub op: ComparisonOp,
    pub expected_value: Value,
    pub required: bool,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalSpec {
    pub schema_version: u32,
    pub goal_id: String,
    pub objective: String,
    pub scope: BTreeMap<String, Value>,
    pub required_outcomes: Vec<String>,
    pub constraints: Vec<String>,
    pub success_criteria: Vec<Postcondition>,
    pub risk_class: CognitiveRiskClass,
    pub confirmation_policy: ConfirmationPolicy,
    pub provenance: CognitiveProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalReplayContext {
    pub replay_id: String,
    pub seed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoalCompilationInput {
    pub schema_version: u32,
    pub instruction: String,
    pub locale: String,
    pub source_id: String,
    pub source_hash: String,
    pub scope_hints: BTreeMap<String, Value>,
    pub explicit_constraints: Vec<String>,
    pub success_criteria: Vec<Postcondition>,
    pub confirmation_policy: Option<ConfirmationPolicy>,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub replay_context: GoalReplayContext,
}

impl GoalCompilationInput {
    pub fn compute_source_hash(&self) -> Result<String, ModuleError> {
        canonical_sha256(&serde_json::json!({
            "instruction": self.instruction,
            "locale": self.locale,
            "source_id": self.source_id,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingField {
    Objective,
    Scope,
    RequiredOutcomes,
    SuccessCriteria,
    ApprovalCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClarificationReasonCode {
    MissingRequiredField,
    MultipleObjectives,
    ConflictingConstraints,
    StructuredSuccessCriterionRequired,
    RiskyActionRequiresApproval,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum GoalCompilationResult {
    Compiled {
        goal_spec: GoalSpec,
    },
    ClarificationRequired {
        missing_fields: Vec<MissingField>,
        ambiguities: Vec<String>,
        questions: Vec<String>,
        reason_codes: Vec<ClarificationReasonCode>,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GoalCompiler;

impl Module for GoalCompiler {
    type Input = GoalCompilationInput;
    type Output = GoalCompilationResult;

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
            category: ModuleCategory("goal_compiler".to_owned()),
            supported_input_kinds: vec![INPUT_SCHEMA_ID.to_owned()],
            supported_output_kinds: vec![OUTPUT_SCHEMA_ID.to_owned()],
            supported_risk_classes: vec![
                "read_only".to_owned(),
                "reversible".to_owned(),
                "business_state_change".to_owned(),
                "high_criticality".to_owned(),
            ],
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
        validate_version(input.schema_version)?;
        validate_text(&input.instruction, "instruction")?;
        validate_token(&input.locale, "locale")?;
        validate_token(&input.source_id, "source_id")?;
        validate_hash(&input.source_hash, "source_hash")?;
        validate_token(&input.replay_context.replay_id, "replay_id")?;
        validate_collection(&input.explicit_constraints, "explicit_constraints")?;
        if input.success_criteria.len() > MAX_ITEMS || input.scope_hints.len() > MAX_ITEMS {
            return resource("structured input exceeds collection bounds");
        }
        for value in input.scope_hints.values() {
            validate_json(value, 0)?;
        }
        for criterion in &input.success_criteria {
            validate_postcondition(criterion)?;
        }
        if contains_sensitive_key(&input.scope_hints)
            || input
                .success_criteria
                .iter()
                .any(|criterion| value_contains_sensitive_key(&criterion.expected_value))
        {
            return invalid("raw secret-bearing fields are forbidden");
        }
        if input.compute_source_hash()? != input.source_hash {
            return Err(ModuleError::new(
                ModuleErrorCode::DeterministicReplayMismatch,
                "source_hash does not bind instruction, locale, and source_id",
            ));
        }
        if input.trust_labels.is_empty()
            || !input
                .trust_labels
                .contains(&TrustLabel::AuthenticatedUserInstruction)
            || input.trust_labels.iter().any(|label| label.is_untrusted())
        {
            return Err(ModuleError::new(
                ModuleErrorCode::UntrustedInputViolation,
                "goal compilation requires uncontaminated authenticated user instruction authority",
            ));
        }
        let labels = input
            .trust_labels
            .iter()
            .map(|label| label.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if labels != context.invocation_trust_labels {
            return Err(ModuleError::new(
                ModuleErrorCode::UntrustedInputViolation,
                "payload trust_labels do not match caller context",
            ));
        }
        Ok(())
    }

    fn invoke(
        &self,
        input: Self::Input,
        _context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        if input.locale != "ko-KR" {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                "Goal Compiler v1 supports only ko-KR",
            ));
        }
        let sections = parse_sections(&input.instruction);
        if sections.recognized == 0 {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                "instruction is outside the deterministic labeled grammar",
            ));
        }

        let objective_values = sections.values("목표");
        let scope_values = sections.values("범위");
        let outcome_values = sections.values("결과");
        let inline_constraints = sections.values("제약");
        let free_success = sections.values("성공조건");
        let mut missing = BTreeSet::new();
        let mut ambiguities = Vec::new();
        let mut reasons = BTreeSet::new();

        let objective = if objective_values.len() == 1 {
            Some(objective_values[0].clone())
        } else {
            missing.insert(MissingField::Objective);
            reasons.insert(if objective_values.len() > 1 {
                ambiguities.push(
                    "목표가 둘 이상 선언되어 하나의 GoalSpec으로 분리할 수 없습니다".to_owned(),
                );
                ClarificationReasonCode::MultipleObjectives
            } else {
                ClarificationReasonCode::MissingRequiredField
            });
            None
        };

        let mut scope = input.scope_hints.clone();
        if scope.is_empty() && scope_values.len() == 1 {
            scope.insert(
                "declared_scope".to_owned(),
                Value::String(scope_values[0].clone()),
            );
        }
        if scope.is_empty() {
            missing.insert(MissingField::Scope);
            reasons.insert(ClarificationReasonCode::MissingRequiredField);
        }
        if outcome_values.is_empty() {
            missing.insert(MissingField::RequiredOutcomes);
            reasons.insert(ClarificationReasonCode::MissingRequiredField);
        }
        if input.success_criteria.is_empty() {
            missing.insert(MissingField::SuccessCriteria);
            reasons.insert(if free_success.is_empty() {
                ClarificationReasonCode::MissingRequiredField
            } else {
                ambiguities.push(
                    "자유 텍스트 성공조건은 typed Postcondition으로 안전하게 변환할 수 없습니다"
                        .to_owned(),
                );
                ClarificationReasonCode::StructuredSuccessCriterionRequired
            });
        }

        let constraints = input
            .explicit_constraints
            .iter()
            .cloned()
            .chain(inline_constraints)
            .map(|value| collapse_whitespace(&value))
            .collect::<BTreeSet<_>>();
        if constraints_conflict(&constraints) {
            ambiguities.push("서로 충돌하는 제약이 선언되었습니다".to_owned());
            reasons.insert(ClarificationReasonCode::ConflictingConstraints);
        }

        let risk = if let Some(value) = objective.as_deref() {
            classify_risk(value).ok_or_else(|| {
                ModuleError::new(
                    ModuleErrorCode::UnsupportedInput,
                    "objective uses an operation outside the deterministic risk grammar",
                )
            })?
        } else {
            CognitiveRiskClass::ReadOnly
        };
        let confirmation = match (risk, input.confirmation_policy) {
            (CognitiveRiskClass::ReadOnly, policy) => policy.unwrap_or(ConfirmationPolicy::Never),
            (_, Some(ConfirmationPolicy::BeforeRiskyAction | ConfirmationPolicy::Always)) => input
                .confirmation_policy
                .unwrap_or(ConfirmationPolicy::Always),
            _ => {
                missing.insert(MissingField::ApprovalCondition);
                reasons.insert(ClarificationReasonCode::RiskyActionRequiresApproval);
                ConfirmationPolicy::Always
            }
        };

        if !missing.is_empty() || !ambiguities.is_empty() {
            let questions = clarification_questions(&missing, &ambiguities);
            return output(
                GoalCompilationResult::ClarificationRequired {
                    missing_fields: missing.into_iter().collect(),
                    ambiguities,
                    questions,
                    reason_codes: reasons.into_iter().collect(),
                },
                &input,
            );
        }

        let objective = objective.ok_or_else(|| {
            ModuleError::new(
                ModuleErrorCode::InternalFailure,
                "validated objective disappeared before compilation",
            )
        })?;
        let input_hash = canonical_sha256(&input)?;
        let digest = input_hash.strip_prefix("sha256:").ok_or_else(|| {
            ModuleError::new(
                ModuleErrorCode::InternalFailure,
                "canonical hash has an invalid prefix",
            )
        })?;
        let goal = GoalSpec {
            schema_version: SCHEMA_VERSION,
            goal_id: format!("goal-{}", &digest[..32]),
            objective,
            scope,
            required_outcomes: outcome_values,
            constraints: constraints.into_iter().collect(),
            success_criteria: input.success_criteria.clone(),
            risk_class: risk,
            confirmation_policy: confirmation,
            provenance: CognitiveProvenance {
                source: input.source_id.clone(),
                source_hash: input.source_hash.clone(),
                module_id: MODULE_ID.to_owned(),
            },
        };
        validate_goal(&goal)?;
        output(GoalCompilationResult::Compiled { goal_spec: goal }, &input)
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec![
                "deterministic Korean labeled grammar v1 loaded".to_owned(),
                "model, network, filesystem, and side effects unavailable".to_owned(),
            ],
        }
    }
}

#[derive(Default)]
struct ParsedSections {
    entries: BTreeMap<String, Vec<String>>,
    recognized: usize,
}

impl ParsedSections {
    fn values(&self, key: &str) -> Vec<String> {
        self.entries.get(key).cloned().unwrap_or_default()
    }
}

fn parse_sections(instruction: &str) -> ParsedSections {
    let mut parsed = ParsedSections::default();
    for line in instruction.lines() {
        let line = line.trim();
        let pair = line.split_once(':').or_else(|| line.split_once('：'));
        let Some((raw_key, raw_value)) = pair else {
            continue;
        };
        let key = raw_key.trim();
        if !matches!(key, "목표" | "범위" | "결과" | "제약" | "성공조건") {
            continue;
        }
        let value = collapse_whitespace(raw_value);
        if value.is_empty() {
            continue;
        }
        parsed
            .entries
            .entry(key.to_owned())
            .or_default()
            .push(value);
        parsed.recognized = parsed.recognized.saturating_add(1);
    }
    parsed
}

fn classify_risk(objective: &str) -> Option<CognitiveRiskClass> {
    if contains_any(
        objective,
        &["삭제", "결제", "송금", "계정", "보안", "권한", "비밀번호"],
    ) {
        Some(CognitiveRiskClass::HighCriticality)
    } else if contains_any(objective, &["저장", "제출", "전송", "보내기"]) {
        Some(CognitiveRiskClass::BusinessStateChange)
    } else if contains_any(objective, &["수정", "변경", "업데이트"]) {
        Some(CognitiveRiskClass::Reversible)
    } else if contains_any(objective, &["조회", "읽기", "비교", "목록", "요약", "확인"])
    {
        Some(CognitiveRiskClass::ReadOnly)
    } else {
        None
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn constraints_conflict(constraints: &BTreeSet<String>) -> bool {
    constraints.iter().any(|constraint| {
        constraint
            .strip_suffix(" 금지")
            .is_some_and(|positive| constraints.contains(positive.trim()))
    })
}

fn clarification_questions(
    missing: &BTreeSet<MissingField>,
    ambiguities: &[String],
) -> Vec<String> {
    let mut questions = Vec::new();
    for field in missing {
        questions.push(
            match field {
                MissingField::Objective => "하나의 명확한 목표를 `목표:`로 알려주세요.",
                MissingField::Scope => "작업 범위를 `범위:` 또는 scope_hints로 알려주세요.",
                MissingField::RequiredOutcomes => "필수 결과를 `결과:`로 알려주세요.",
                MissingField::SuccessCriteria => {
                    "검증 가능한 typed success_criteria를 제공해주세요."
                }
                MissingField::ApprovalCondition => "위험 행동 전 확인 정책을 명시해주세요.",
            }
            .to_owned(),
        );
    }
    if !ambiguities.is_empty() {
        questions.push("모호하거나 충돌하는 선언을 하나로 정리해주세요.".to_owned());
    }
    questions
}

fn output(
    value: GoalCompilationResult,
    input: &GoalCompilationInput,
) -> Result<ModuleOutput<GoalCompilationResult>, ModuleError> {
    let mut output = ModuleOutput::new(
        value,
        ModuleProvenance {
            source_id: input.source_id.clone(),
            source_sha256: input.source_hash.clone(),
            producer: MODULE_ID.to_owned(),
        },
    );
    output.evidence = vec!["deterministic-goal-grammar-v1".to_owned()];
    output.logical_operations = u64::try_from(
        input
            .instruction
            .lines()
            .count()
            .saturating_add(input.success_criteria.len())
            .saturating_add(input.explicit_constraints.len())
            .saturating_add(1),
    )
    .map_err(|_| resource_error("logical operation count is not representable"))?;
    output.logical_elapsed_ticks = 1;
    Ok(output)
}

fn validate_goal(goal: &GoalSpec) -> Result<(), ModuleError> {
    validate_version(goal.schema_version)?;
    validate_token(&goal.goal_id, "goal_id")?;
    validate_text(&goal.objective, "objective")?;
    if goal.scope.is_empty()
        || goal.required_outcomes.is_empty()
        || goal.success_criteria.is_empty()
    {
        return Err(ModuleError::new(
            ModuleErrorCode::InternalFailure,
            "compiled GoalSpec is incomplete",
        ));
    }
    validate_collection(&goal.required_outcomes, "required_outcomes")?;
    validate_collection(&goal.constraints, "constraints")?;
    for criterion in &goal.success_criteria {
        validate_postcondition(criterion)?;
    }
    Ok(())
}

fn validate_postcondition(value: &Postcondition) -> Result<(), ModuleError> {
    validate_token(&value.target_state, "postcondition target_state")?;
    if value.timeout_ms == 0 || value.timeout_ms > 60_000 {
        return invalid("postcondition timeout_ms must be within 1..60000");
    }
    validate_json(&value.expected_value, 0)
}

fn validate_json(value: &Value, depth: usize) -> Result<(), ModuleError> {
    if depth > MAX_JSON_DEPTH {
        return resource("JSON value exceeds depth 32");
    }
    match value {
        Value::Array(items) => {
            for item in items {
                validate_json(item, depth.saturating_add(1))?;
            }
        }
        Value::Object(values) => {
            for item in values.values() {
                validate_json(item, depth.saturating_add(1))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn contains_sensitive_key(values: &BTreeMap<String, Value>) -> bool {
    values
        .iter()
        .any(|(key, value)| sensitive_key(key) || value_contains_sensitive_key(value))
}

fn value_contains_sensitive_key(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(value_contains_sensitive_key),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| sensitive_key(key) || value_contains_sensitive_key(value)),
        _ => false,
    }
}

fn sensitive_key(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace(['-', '_'], "");
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "cookie",
        "authorization",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_version(version: u32) -> Result<(), ModuleError> {
    if version != SCHEMA_VERSION {
        return Err(ModuleError::new(
            ModuleErrorCode::ContractVersionMismatch,
            "schema_version must be 1",
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<(), ModuleError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return invalid(format!(
            "{field} is empty, contains control text, or exceeds bounds"
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
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(format!("{field} must use sha256:<hex>"));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid(format!("{field} must contain 64 hex digits"));
    }
    Ok(())
}

fn validate_collection(values: &[String], field: &str) -> Result<(), ModuleError> {
    if values.len() > MAX_ITEMS {
        return resource(format!("{field} exceeds 64 items"));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ModuleError> {
    Err(ModuleError::new(ModuleErrorCode::InvalidInput, message))
}

fn resource<T>(message: impl Into<String>) -> Result<T, ModuleError> {
    Err(resource_error(message))
}

fn resource_error(message: impl Into<String>) -> ModuleError {
    ModuleError::new(ModuleErrorCode::ResourceExhausted, message)
}
