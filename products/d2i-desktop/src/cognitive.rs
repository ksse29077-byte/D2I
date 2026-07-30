use crate::{validate_text, validate_token, DesktopError};
pub use d2i_cognitive_ir::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
/// Bounded executor configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CognitiveExecutorConfig {
    pub max_steps: u32,
    pub max_retries: u32,
    pub max_replans: u32,
    pub total_deadline_ticks: u64,
    pub step_deadline_ticks: u64,
}

impl Default for CognitiveExecutorConfig {
    fn default() -> Self {
        Self {
            max_steps: 32,
            max_retries: 3,
            max_replans: 2,
            total_deadline_ticks: 256,
            step_deadline_ticks: 16,
        }
    }
}

impl CognitiveExecutorConfig {
    fn validate(&self) -> Result<(), DesktopError> {
        if self.max_steps == 0
            || self.max_steps > 10_000
            || self.max_retries > 1_000
            || self.max_replans > 1_000
            || self.total_deadline_ticks == 0
            || self.step_deadline_ticks == 0
        {
            return Err(DesktopError::Invalid(
                "cognitive executor bounds are invalid".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Source of fresh observations.
pub trait ObservationProvider {
    fn observe(
        &mut self,
        goal: &GoalSpec,
        sequence: u64,
    ) -> Result<ObservationSnapshot, DesktopError>;
}

/// Reducer from observation to goal-scoped world state.
pub trait WorldStateReducer {
    fn reduce(
        &mut self,
        goal: &GoalSpec,
        observation: &ObservationSnapshot,
        capabilities: &BTreeSet<String>,
        plan_generation_id: &str,
    ) -> Result<WorldState, DesktopError>;
}

/// Registry for declared capabilities.
pub trait CapabilityRegistry {
    fn capabilities(
        &self,
        goal: &GoalSpec,
        world: &WorldState,
    ) -> Result<Vec<CapabilityDescriptor>, DesktopError>;
}

/// Deterministic action candidate source.
pub trait ActionCandidateProvider {
    fn next_candidate(
        &mut self,
        goal: &GoalSpec,
        world: &WorldState,
        plan: &PlanGraph,
        completed_actions: &[String],
    ) -> Result<Option<ActionProposal>, DesktopError>;
}

/// Abstract policy gate.
pub trait ActionPolicyEvaluator {
    fn evaluate(
        &mut self,
        goal: &GoalSpec,
        world: &WorldState,
        proposal: &ActionProposal,
    ) -> Result<AuditOutcome, DesktopError>;
}

/// Abstract activation gate.
pub trait ActivationGate {
    fn evaluate(
        &mut self,
        goal: &GoalSpec,
        world: &WorldState,
        proposal: &ActionProposal,
    ) -> Result<AuditOutcome, DesktopError>;
}

/// Abstract execution boundary. Baseline mocks must not mutate host state.
pub trait ActionExecutor {
    fn execute(&mut self, proposal: &ActionProposal) -> Result<ActionExecution, DesktopError>;
}

/// Postcondition verifier over the fresh observation.
pub trait PostconditionVerifier {
    fn verify(
        &mut self,
        proposal: &ActionProposal,
        execution: &ActionExecution,
        observation: &ObservationSnapshot,
    ) -> Result<VerificationResult, DesktopError>;
}

/// Recovery policy for failed verification.
pub trait RecoveryPolicy {
    fn decide(
        &mut self,
        goal: &GoalSpec,
        proposal: &ActionProposal,
        verification: &VerificationResult,
        retry_budget: u32,
        replan_budget: u32,
    ) -> Result<RecoveryDecision, DesktopError>;
}

/// Audit event sink. Sink failure fails closed.
pub trait CognitiveAuditSink {
    fn record(&mut self, event: CognitiveAuditEvent) -> Result<(), DesktopError>;
}

/// Gate outcome for policy and activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditOutcome {
    pub allowed: bool,
    pub reason: String,
    pub evidence: Vec<String>,
}

/// Minimal deterministic audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CognitiveAuditEvent {
    pub kind: String,
    pub goal_id: String,
    pub proposal_id: Option<String>,
    pub observation_hash: Option<String>,
    pub message: String,
    pub logical_tick: u64,
}

/// Model-free cognitive executor.
pub struct CognitiveExecutor<O, W, C, P, PE, A, X, V, R, S> {
    observation_provider: O,
    world_state_reducer: W,
    capability_registry: C,
    candidate_provider: P,
    policy_evaluator: PE,
    activation_gate: A,
    action_executor: X,
    verifier: V,
    recovery_policy: R,
    audit_sink: S,
    config: CognitiveExecutorConfig,
    build_id: String,
    module_ids: Vec<String>,
}

impl<O, W, C, P, PE, A, X, V, R, S> CognitiveExecutor<O, W, C, P, PE, A, X, V, R, S>
where
    O: ObservationProvider,
    W: WorldStateReducer,
    C: CapabilityRegistry,
    P: ActionCandidateProvider,
    PE: ActionPolicyEvaluator,
    A: ActivationGate,
    X: ActionExecutor,
    V: PostconditionVerifier,
    R: RecoveryPolicy,
    S: CognitiveAuditSink,
{
    /// Creates a deterministic cognitive executor from trait-bounded parts.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        observation_provider: O,
        world_state_reducer: W,
        capability_registry: C,
        candidate_provider: P,
        policy_evaluator: PE,
        activation_gate: A,
        action_executor: X,
        verifier: V,
        recovery_policy: R,
        audit_sink: S,
        config: CognitiveExecutorConfig,
        build_id: String,
        module_ids: Vec<String>,
    ) -> Result<Self, DesktopError> {
        config.validate()?;
        validate_token(&build_id, "cognitive build_id")?;
        validate_text_vec(&module_ids, "cognitive module_ids", 128)?;
        Ok(Self {
            observation_provider,
            world_state_reducer,
            capability_registry,
            candidate_provider,
            policy_evaluator,
            activation_gate,
            action_executor,
            verifier,
            recovery_policy,
            audit_sink,
            config,
            build_id,
            module_ids,
        })
    }

    /// Runs the goal one verified step at a time and returns a work report.
    pub fn run(
        &mut self,
        goal: &GoalSpec,
        initial_plan: &PlanGraph,
    ) -> Result<WorkReport, DesktopError> {
        goal.validate()?;
        let mut plan = initial_plan.clone();
        plan.validate()?;
        let mut logical_tick = 0_u64;
        let mut sequence = 0_u64;
        let mut retry_budget = self.config.max_retries;
        let mut replan_budget = self.config.max_replans;
        let mut completed_actions = Vec::new();
        let mut confirmed_facts = Vec::new();
        let mut warnings = Vec::new();
        let mut timings = Vec::new();
        let mut attempted = BTreeMap::<String, u32>::new();

        let mut observation = self.observe(goal, sequence, &mut logical_tick, &mut timings)?;
        for step in 0..self.config.max_steps {
            self.check_deadline(logical_tick)?;
            let capabilities = BTreeSet::new();
            let world = self.world_state_reducer.reduce(
                goal,
                &observation,
                &capabilities,
                &plan.plan_generation_id,
            )?;
            world.validate()?;
            let descriptors = self.capability_registry.capabilities(goal, &world)?;
            let capability_ids = descriptors
                .iter()
                .map(|descriptor| {
                    descriptor.validate()?;
                    Ok((descriptor.capability_id.clone(), descriptor.clone()))
                })
                .collect::<Result<BTreeMap<_, _>, DesktopError>>()?;
            if capability_ids.is_empty() {
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    vec!["no capability satisfies the goal".to_owned()],
                    Vec::new(),
                    true,
                    timings,
                    warnings,
                    logical_tick,
                );
            }
            let candidate =
                self.candidate_provider
                    .next_candidate(goal, &world, &plan, &completed_actions)?;
            let Some(proposal) = candidate else {
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    Vec::new(),
                    vec!["no remaining action candidates".to_owned()],
                    false,
                    timings,
                    warnings,
                    logical_tick,
                );
            };
            self.validate_proposal(&proposal, goal, &plan, &observation, &capability_ids)?;
            let attempts = attempted.entry(proposal.proposal_id.clone()).or_default();
            if *attempts > self.config.max_retries {
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    vec![format!(
                        "retry budget exhausted for {}",
                        proposal.proposal_id
                    )],
                    Vec::new(),
                    true,
                    timings,
                    warnings,
                    logical_tick,
                );
            }
            *attempts = attempts.saturating_add(1);

            let policy = self.policy_evaluator.evaluate(goal, &world, &proposal)?;
            if !policy.allowed {
                self.audit(
                    goal,
                    Some(&proposal),
                    Some(&observation),
                    "policy_denied",
                    &policy.reason,
                    logical_tick,
                )?;
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    vec![format!(
                        "policy denied {}: {}",
                        proposal.proposal_id, policy.reason
                    )],
                    Vec::new(),
                    true,
                    timings,
                    warnings,
                    logical_tick,
                );
            }
            let activation = self.activation_gate.evaluate(goal, &world, &proposal)?;
            if !activation.allowed {
                self.audit(
                    goal,
                    Some(&proposal),
                    Some(&observation),
                    "activation_denied",
                    &activation.reason,
                    logical_tick,
                )?;
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    vec![format!(
                        "activation denied {}: {}",
                        proposal.proposal_id, activation.reason
                    )],
                    Vec::new(),
                    true,
                    timings,
                    warnings,
                    logical_tick,
                );
            }

            logical_tick = logical_tick.saturating_add(1);
            if logical_tick
                > self
                    .config
                    .step_deadline_ticks
                    .saturating_mul(u64::from(step + 1))
            {
                return self.finish(
                    goal,
                    completed_actions,
                    confirmed_facts,
                    vec!["step deadline exceeded".to_owned()],
                    Vec::new(),
                    true,
                    timings,
                    warnings,
                    logical_tick,
                );
            }
            let execution = self.action_executor.execute(&proposal)?;
            self.audit(
                goal,
                Some(&proposal),
                Some(&observation),
                "executed",
                "one action executed",
                logical_tick,
            )?;
            sequence = sequence.saturating_add(1);
            let fresh_observation =
                self.observe(goal, sequence, &mut logical_tick, &mut timings)?;
            let verification = self
                .verifier
                .verify(&proposal, &execution, &fresh_observation)?;
            verification.validate()?;
            self.audit(
                goal,
                Some(&proposal),
                Some(&fresh_observation),
                "verified",
                &verification.reason,
                logical_tick,
            )?;
            if verification.passed() {
                completed_actions.push(proposal.proposal_id.clone());
                confirmed_facts.push(format!(
                    "{} verified against {}",
                    proposal.proposal_id, verification.observed_state_hash
                ));
                warnings.extend(verification.warnings);
                observation = fresh_observation;
                if verification.goal_progress == GoalProgress::Complete {
                    return self.finish(
                        goal,
                        completed_actions,
                        confirmed_facts,
                        Vec::new(),
                        vec!["goal complete".to_owned()],
                        false,
                        timings,
                        warnings,
                        logical_tick,
                    );
                }
                continue;
            }

            let recovery = self.recovery_policy.decide(
                goal,
                &proposal,
                &verification,
                retry_budget,
                replan_budget,
            )?;
            recovery.validate()?;
            self.audit(
                goal,
                Some(&proposal),
                Some(&fresh_observation),
                "recovery",
                &recovery.reason,
                logical_tick,
            )?;
            match recovery.kind {
                CognitiveRecoveryKind::Retry if retry_budget > 0 => {
                    retry_budget = retry_budget.saturating_sub(1);
                    observation = fresh_observation;
                }
                CognitiveRecoveryKind::Reobserve => {
                    sequence = sequence.saturating_add(1);
                    observation = self.observe(goal, sequence, &mut logical_tick, &mut timings)?;
                }
                CognitiveRecoveryKind::Replan if replan_budget > 0 => {
                    replan_budget = replan_budget.saturating_sub(1);
                    if let Some(generation) = recovery.replacement_plan_generation_id {
                        plan.plan_generation_id = generation;
                    }
                    observation = fresh_observation;
                }
                CognitiveRecoveryKind::Fallback
                | CognitiveRecoveryKind::RequestUserInput
                | CognitiveRecoveryKind::Stop
                | CognitiveRecoveryKind::Retry
                | CognitiveRecoveryKind::Replan => {
                    return self.finish(
                        goal,
                        completed_actions,
                        confirmed_facts,
                        vec![format!(
                            "stopped after failed verification: {}",
                            recovery.reason
                        )],
                        Vec::new(),
                        true,
                        timings,
                        warnings,
                        logical_tick,
                    );
                }
            }
        }

        self.finish(
            goal,
            completed_actions,
            confirmed_facts,
            vec!["maximum step budget exhausted".to_owned()],
            Vec::new(),
            true,
            timings,
            warnings,
            logical_tick,
        )
    }

    fn observe(
        &mut self,
        goal: &GoalSpec,
        sequence: u64,
        logical_tick: &mut u64,
        timings: &mut Vec<CognitiveTiming>,
    ) -> Result<ObservationSnapshot, DesktopError> {
        *logical_tick = logical_tick.saturating_add(1);
        let observation = self.observation_provider.observe(goal, sequence)?;
        observation.validate()?;
        timings.push(CognitiveTiming {
            step: format!("observe-{sequence}"),
            logical_tick: *logical_tick,
        });
        self.audit(
            goal,
            None,
            Some(&observation),
            "observed",
            "fresh observation received",
            *logical_tick,
        )?;
        Ok(observation)
    }

    fn validate_proposal(
        &self,
        proposal: &ActionProposal,
        goal: &GoalSpec,
        plan: &PlanGraph,
        observation: &ObservationSnapshot,
        capabilities: &BTreeMap<String, CapabilityDescriptor>,
    ) -> Result<(), DesktopError> {
        proposal.validate()?;
        if proposal.goal_id != goal.goal_id {
            return Err(DesktopError::Integrity(
                "proposal goal_id does not match goal".to_owned(),
            ));
        }
        if proposal.source_observation_hash != observation.state_hash {
            return Err(DesktopError::Replay(
                "stale action proposal observation hash".to_owned(),
            ));
        }
        if proposal.valid_until_sequence < observation.sequence {
            return Err(DesktopError::Replay(
                "action proposal validity bound has expired".to_owned(),
            ));
        }
        if proposal.plan_generation_id != plan.plan_generation_id {
            return Err(DesktopError::Replay(
                "stale action proposal plan generation".to_owned(),
            ));
        }
        let Some(capability) = capabilities.get(&proposal.capability_id) else {
            return Err(DesktopError::AdapterUnavailable(format!(
                "capability '{}' is unavailable",
                proposal.capability_id
            )));
        };
        if !capability.reversible || proposal.reversibility == Reversibility::Irreversible {
            return Err(DesktopError::AccessDenied(
                "irreversible capability is unsupported".to_owned(),
            ));
        }
        Ok(())
    }

    fn check_deadline(&self, logical_tick: u64) -> Result<(), DesktopError> {
        if logical_tick > self.config.total_deadline_ticks {
            return Err(DesktopError::AccessDenied(
                "cognitive executor total deadline exceeded".to_owned(),
            ));
        }
        Ok(())
    }

    fn audit(
        &mut self,
        goal: &GoalSpec,
        proposal: Option<&ActionProposal>,
        observation: Option<&ObservationSnapshot>,
        kind: &str,
        message: &str,
        logical_tick: u64,
    ) -> Result<(), DesktopError> {
        self.audit_sink.record(CognitiveAuditEvent {
            kind: kind.to_owned(),
            goal_id: goal.goal_id.clone(),
            proposal_id: proposal.map(|value| value.proposal_id.clone()),
            observation_hash: observation.map(|value| value.state_hash.clone()),
            message: message.to_owned(),
            logical_tick,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finish(
        &mut self,
        goal: &GoalSpec,
        completed_actions: Vec<String>,
        confirmed_facts: Vec<String>,
        incomplete_items: Vec<String>,
        opinions: Vec<String>,
        user_decision_required: bool,
        mut timings: Vec<CognitiveTiming>,
        warnings: Vec<String>,
        logical_tick: u64,
    ) -> Result<WorkReport, DesktopError> {
        timings.push(CognitiveTiming {
            step: "finish".to_owned(),
            logical_tick,
        });
        let report = WorkReport {
            schema_version: COGNITIVE_SCHEMA_VERSION,
            confirmed_facts,
            completed_actions,
            incomplete_items,
            opinions,
            opinion_basis: vec![format!("goal {}", goal.goal_id)],
            uncertainties: Vec::new(),
            user_decision_required,
            build_id: self.build_id.clone(),
            module_ids: self.module_ids.clone(),
            timings,
            warnings,
        };
        report.validate()?;
        self.audit(
            goal,
            None,
            None,
            "finished",
            "work report produced",
            logical_tick,
        )?;
        Ok(report)
    }
}

fn validate_text_vec(values: &[String], field: &str, maximum: usize) -> Result<(), DesktopError> {
    if values.len() > maximum {
        return Err(DesktopError::Invalid(format!(
            "{field} exceeds {maximum} entries"
        )));
    }
    for value in values {
        validate_text(value, field)?;
    }
    Ok(())
}
