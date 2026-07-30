//! Deterministic `RuleBasedWorkReporter` reference module.

use d2i_cognitive_ir::{
    CognitiveRecoveryKind, CognitiveTiming, GoalProgress, GoalSpec, RecoveryDecision, TrustLabel,
    VerificationResult, WorkReport,
};
use d2i_module_sdk::{
    canonical_sha256, ConfidenceSemantics, InvocationContext, Module, ModuleCapability,
    ModuleCategory, ModuleError, ModuleErrorCode, ModuleMetadata, ModuleOutput, ModuleProvenance,
    NetworkRequirement, SelfCheck,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Stable reference module identifier.
pub const MODULE_ID: &str = "rule-based-work-reporter";
/// Stable reference module version.
pub const MODULE_VERSION: &str = "1.0.0";
/// Build identifier used by deterministic fixtures.
pub const BUILD_ID: &str = "rule-based-work-reporter-v1";
/// Capability implemented by the reference module.
pub const CAPABILITY_ID: &str = "cognitive.work-report";

/// Bounded execution event summary supplied by the cognitive runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEventSummary {
    pub event_id: String,
    pub summary: String,
    pub completed: bool,
    pub logical_tick: u64,
    pub trust_labels: BTreeSet<TrustLabel>,
    pub module_ids: Vec<String>,
}

impl ExecutionEventSummary {
    fn contains_untrusted_content(&self) -> bool {
        self.trust_labels.iter().any(|label| {
            matches!(
                label,
                TrustLabel::UntrustedWebContent | TrustLabel::UntrustedDocumentContent
            )
        })
    }
}

/// Typed input for deterministic report construction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkReporterInput {
    pub goal_spec: GoalSpec,
    pub verification_results: Vec<VerificationResult>,
    pub recovery_decisions: Vec<RecoveryDecision>,
    pub execution_events: Vec<ExecutionEventSummary>,
}

/// Side-effect-free deterministic report module.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleBasedWorkReporter;

impl Module for RuleBasedWorkReporter {
    type Input = WorkReporterInput;
    type Output = WorkReport;

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
            category: ModuleCategory("work_reporter".to_owned()),
            supported_input_kinds: vec!["cognitive-work-report-input-v1".to_owned()],
            supported_output_kinds: vec!["cognitive-work-report-v1".to_owned()],
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
        _context: &InvocationContext,
    ) -> Result<(), ModuleError> {
        input.goal_spec.validate().map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InvalidInput,
                format!("invalid GoalSpec: {error}"),
            )
        })?;
        if input.verification_results.len() > 1_024
            || input.recovery_decisions.len() > 1_024
            || input.execution_events.len() > 1_024
        {
            return Err(ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "work reporter input exceeds bounded collection limits",
            ));
        }
        if input.verification_results.is_empty() && input.recovery_decisions.is_empty() {
            return Err(ModuleError::new(
                ModuleErrorCode::UnsupportedInput,
                "a report requires at least one verification or recovery record",
            ));
        }
        for verification in &input.verification_results {
            verification.validate().map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    format!("invalid VerificationResult: {error}"),
                )
            })?;
        }
        for recovery in &input.recovery_decisions {
            recovery.validate().map_err(|error| {
                ModuleError::new(
                    ModuleErrorCode::InvalidInput,
                    format!("invalid RecoveryDecision: {error}"),
                )
            })?;
        }
        Ok(())
    }

    fn invoke(
        &self,
        input: Self::Input,
        _context: &InvocationContext,
    ) -> Result<ModuleOutput<Self::Output>, ModuleError> {
        let source_hash = canonical_sha256(&input)?;
        let confirmed_facts = input
            .verification_results
            .iter()
            .filter(|result| result.goal_progress == GoalProgress::Complete)
            .map(|result| result.reason.clone())
            .collect::<Vec<_>>();
        let completed_actions = input
            .execution_events
            .iter()
            .filter(|event| event.completed && !event.contains_untrusted_content())
            .map(|event| event.summary.clone())
            .collect::<Vec<_>>();
        let incomplete_items = input
            .verification_results
            .iter()
            .filter(|result| result.goal_progress != GoalProgress::Complete)
            .map(|result| result.reason.clone())
            .chain(
                input
                    .recovery_decisions
                    .iter()
                    .filter(|decision| {
                        matches!(
                            decision.kind,
                            CognitiveRecoveryKind::Stop
                                | CognitiveRecoveryKind::RequestUserInput
                                | CognitiveRecoveryKind::Fallback
                        )
                    })
                    .map(|decision| decision.reason.clone()),
            )
            .collect::<Vec<_>>();
        let uncertainties = input
            .verification_results
            .iter()
            .flat_map(|result| result.warnings.iter().cloned())
            .chain(
                input
                    .recovery_decisions
                    .iter()
                    .flat_map(|decision| decision.evidence.iter().cloned()),
            )
            .collect::<Vec<_>>();
        let user_decision_required = input
            .recovery_decisions
            .iter()
            .any(|decision| decision.kind == CognitiveRecoveryKind::RequestUserInput);
        let mut module_ids = input
            .execution_events
            .iter()
            .flat_map(|event| event.module_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        module_ids.insert(MODULE_ID.to_owned());
        let timings = input
            .execution_events
            .iter()
            .map(|event| CognitiveTiming {
                step: event.event_id.clone(),
                logical_tick: event.logical_tick,
            })
            .collect::<Vec<_>>();
        let mut warnings = input
            .verification_results
            .iter()
            .flat_map(|result| result.warnings.iter().cloned())
            .collect::<Vec<_>>();
        let untrusted_count = input
            .execution_events
            .iter()
            .filter(|event| event.contains_untrusted_content())
            .count();
        if untrusted_count > 0 {
            warnings.push(format!(
                "{untrusted_count} untrusted event summaries were preserved as data and omitted from completed actions"
            ));
        }
        let report = WorkReport {
            schema_version: 1,
            confirmed_facts,
            completed_actions,
            incomplete_items,
            opinions: Vec::new(),
            opinion_basis: Vec::new(),
            uncertainties,
            user_decision_required,
            build_id: BUILD_ID.to_owned(),
            module_ids: module_ids.into_iter().collect(),
            timings,
            warnings,
        };
        report.validate().map_err(|error| {
            ModuleError::new(
                ModuleErrorCode::InternalFailure,
                format!("generated WorkReport failed validation: {error}"),
            )
        })?;
        let mut output = ModuleOutput::new(
            report,
            ModuleProvenance {
                source_id: "cognitive-runtime-events".to_owned(),
                source_sha256: source_hash,
                producer: MODULE_ID.to_owned(),
            },
        );
        output.evidence = vec!["deterministic-rule-set-v1".to_owned()];
        output.logical_operations = u64::try_from(
            input
                .verification_results
                .len()
                .saturating_add(input.recovery_decisions.len())
                .saturating_add(input.execution_events.len())
                .saturating_add(1),
        )
        .map_err(|_| {
            ModuleError::new(
                ModuleErrorCode::ResourceExhausted,
                "logical operation count is not representable",
            )
        })?;
        output.logical_elapsed_ticks = 1;
        Ok(output)
    }

    fn self_check(&self) -> SelfCheck {
        SelfCheck {
            healthy: true,
            details: vec![
                "deterministic rules loaded".to_owned(),
                "network and side effects unavailable".to_owned(),
            ],
        }
    }
}
