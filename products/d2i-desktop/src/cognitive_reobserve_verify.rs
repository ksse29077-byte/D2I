use crate::{
    sha256_bytes, validate_hash, validate_text, validate_token, BoundActionExecutionV2,
    ComparisonOp, CompletedReadOnlyObservation, DesktopError, ExecutionStatus, GoalProgress,
    GoalSpec, ObservableElement, ObservationSnapshot, ObservationSourceKind, PolicyReadyActionV1,
    Postcondition, PostconditionResultV2, PostconditionVerifierV2, Provenance,
    TrustedActionExecutionReceiptV1, TrustedExecutionBindingRequestV1, TrustedExecutionStatusV1,
    TrustedPlatformActivationV1, VerifiableObservationFieldV2, VerifiablePostconditionV2,
    VerificationActionProposalV2, VerificationConfidenceV2, VerificationGoalSpecV2,
    VerificationRequestV2, VerificationResultV2, VerificationTargetV2, VerificationVerdictV2,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditLedger,
    WindowsDeploymentAuditStatus, WindowsUiaObservationProvider, WindowsWebObservationProvider,
};
use d2i_cognitive_ir::ActionProposal;
use d2i_trusted_action_execution::AdapterKindV1;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Schema version shared by the additive KRN-300 proof artifacts.
pub const COGNITIVE_REOBSERVE_SCHEMA_VERSION: u32 = 1;
/// Published strict schema for the additive re-observation artifacts.
pub const COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/cognitive/cognitive-reobserve-verifier-v2.schema.json"
));

const MAX_ITEMS: usize = 256;
const MAX_OBSERVATION_DURATION_MS: u64 = 60_000;
const ACTIVATION_BINDING_KEYS: [&str; 2] = ["binding_id", "activation_record_hash"];

/// Strict conversion proof from Cognitive IR v1 into Verification v2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSpecBindingV1 {
    pub schema_version: u32,
    pub binding_id: String,
    pub policy_ready_sha256: String,
    pub proposal_sha256: String,
    pub goal_sha256: String,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub execution_receipt_sha256: String,
    pub bound_execution_sha256: String,
    pub verification_goal_sha256: String,
    pub verification_action_proposal_sha256: String,
    pub goal_criterion_ids: Vec<String>,
    pub action_criterion_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
    pub binding_sha256: String,
}

impl VerificationSpecBindingV1 {
    fn seal(mut self) -> Result<Self, DesktopError> {
        canonicalize_set(&mut self.goal_criterion_ids)?;
        canonicalize_set(&mut self.action_criterion_ids)?;
        canonicalize_set(&mut self.evidence_ids)?;
        self.binding_sha256 = canonical_hash_without(&self, "binding_sha256")?;
        self.validate()?;
        Ok(self)
    }

    /// Validates all bounded identifiers, hashes, and the self-hash.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "verification spec binding")?;
        validate_token(&self.binding_id, "verification spec binding_id")?;
        validate_token(
            &self.source_observation_id,
            "verification spec source observation_id",
        )?;
        for (value, label) in [
            (&self.policy_ready_sha256, "policy_ready_sha256"),
            (&self.proposal_sha256, "proposal_sha256"),
            (&self.goal_sha256, "goal_sha256"),
            (&self.source_observation_hash, "source_observation_hash"),
            (&self.execution_receipt_sha256, "execution_receipt_sha256"),
            (&self.bound_execution_sha256, "bound_execution_sha256"),
            (&self.verification_goal_sha256, "verification_goal_sha256"),
            (
                &self.verification_action_proposal_sha256,
                "verification_action_proposal_sha256",
            ),
            (&self.binding_sha256, "verification_spec_binding_sha256"),
        ] {
            validate_hash(value, label)?;
        }
        validate_sorted_tokens(&self.goal_criterion_ids, "goal criterion IDs", false)?;
        validate_sorted_tokens(&self.action_criterion_ids, "action criterion IDs", false)?;
        validate_sorted_tokens(&self.evidence_ids, "spec evidence IDs", false)?;
        if canonical_hash_without(self, "binding_sha256")? != self.binding_sha256 {
            return Err(DesktopError::Integrity(
                "verification spec binding hash differs from canonical content".to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "verification spec binding")
    }
}

/// Typed v2 specifications plus their strict source binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationSpecAdaptationV1 {
    pub goal: VerificationGoalSpecV2,
    pub proposal: VerificationActionProposalV2,
    pub binding: VerificationSpecBindingV1,
}

/// Strict additive bridge from Cognitive IR v1 to Verification Contract v2.
pub struct VerificationSpecAdapterV1;

impl VerificationSpecAdapterV1 {
    /// Converts exact goal and action contracts using the closed target grammar.
    #[allow(clippy::too_many_arguments)]
    pub fn adapt(
        goal: &GoalSpec,
        policy_ready: &PolicyReadyActionV1,
        selected_proposal: &ActionProposal,
        source: &ObservationSnapshot,
        receipt: &TrustedActionExecutionReceiptV1,
        execution: &BoundActionExecutionV2,
    ) -> Result<VerificationSpecAdaptationV1, DesktopError> {
        goal.validate()?;
        selected_proposal.validate()?;
        source.validate()?;
        receipt.validate().map_err(contract_error)?;
        execution.validate()?;
        let proposal_sha256 = canonical_hash(selected_proposal)?;
        let bound_execution_sha256 = canonical_hash(execution)?;
        if &policy_ready.proposal != selected_proposal
            || policy_ready
                .compute_policy_ready_sha256()
                .map_err(|error| DesktopError::Integrity(error.to_string()))?
                != policy_ready.policy_ready_sha256
            || policy_ready.goal_id != goal.goal_id
            || policy_ready.observation_id != source.observation_id
            || policy_ready.source_observation_hash != source.state_hash
            || policy_ready.source_observation_sequence != source.sequence
            || receipt.policy_ready_sha256 != policy_ready.policy_ready_sha256
            || receipt.proposal_sha256 != proposal_sha256
            || receipt.proposal_id != selected_proposal.proposal_id
            || receipt.goal_id != goal.goal_id
            || receipt.plan_generation_id != selected_proposal.plan_generation_id
            || receipt.source_observation_id != source.observation_id
            || receipt.source_observation_hash != source.state_hash
            || receipt.source_observation_sequence != source.sequence
            || execution.execution_id != receipt.execution_id
            || execution.proposal_id != receipt.proposal_id
            || execution.goal_id != receipt.goal_id
            || execution.plan_generation_id != receipt.plan_generation_id
            || execution.source_observation_id != receipt.source_observation_id
            || execution.source_observation_hash != receipt.source_observation_hash
            || execution.source_observation_sequence != receipt.source_observation_sequence
        {
            return Err(DesktopError::Integrity(
                "verification specification lifecycle binding mismatch".to_owned(),
            ));
        }

        let goal_conditions = convert_postconditions("goal", &goal.success_criteria, source)?;
        let action_conditions =
            convert_postconditions("action", &selected_proposal.expected_postconditions, source)?;
        let verification_goal = VerificationGoalSpecV2 {
            schema_version: 2,
            goal_id: goal.goal_id.clone(),
            objective: goal.objective.clone(),
            scope: goal.scope.clone(),
            required_outcomes: goal.required_outcomes.clone(),
            constraints: goal.constraints.clone(),
            success_criteria: goal_conditions,
            risk_class: goal.risk_class,
            confirmation_policy: goal.confirmation_policy,
            provenance: goal.provenance.clone(),
        };
        verification_goal.validate()?;
        let verification_proposal = VerificationActionProposalV2 {
            schema_version: 2,
            proposal_id: selected_proposal.proposal_id.clone(),
            goal_id: selected_proposal.goal_id.clone(),
            plan_generation_id: selected_proposal.plan_generation_id.clone(),
            source_observation_id: source.observation_id.clone(),
            source_observation_hash: source.state_hash.clone(),
            source_observation_sequence: source.sequence,
            capability_id: selected_proposal.capability_id.clone(),
            semantic_target: selected_proposal.semantic_target.clone(),
            arguments: selected_proposal.arguments.clone(),
            preconditions: convert_postconditions(
                "precondition",
                &selected_proposal.preconditions,
                source,
            )?,
            expected_postconditions: action_conditions,
            risk: selected_proposal.risk,
            reversibility: selected_proposal.reversibility,
            confirmation_requirement: selected_proposal.confirmation_requirement,
            confidence: selected_proposal.confidence,
            evidence: policy_ready.evidence_ids.clone(),
            valid_until_sequence: selected_proposal.valid_until_sequence,
        };
        verification_proposal.validate()?;
        let verification_goal_sha256 = canonical_hash(&verification_goal)?;
        let verification_action_proposal_sha256 = canonical_hash(&verification_proposal)?;
        let binding_id = deterministic_id(
            "verification-spec",
            &[
                &policy_ready.policy_ready_sha256,
                &receipt.receipt_sha256,
                &source.state_hash,
            ],
        )?;
        let binding = VerificationSpecBindingV1 {
            schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
            binding_id,
            policy_ready_sha256: policy_ready.policy_ready_sha256.clone(),
            proposal_sha256,
            goal_sha256: canonical_hash(goal)?,
            source_observation_id: source.observation_id.clone(),
            source_observation_hash: source.state_hash.clone(),
            source_observation_sequence: source.sequence,
            execution_receipt_sha256: receipt.receipt_sha256.clone(),
            bound_execution_sha256,
            verification_goal_sha256,
            verification_action_proposal_sha256,
            goal_criterion_ids: verification_goal
                .success_criteria
                .iter()
                .map(|value| value.criterion_id.clone())
                .collect(),
            action_criterion_ids: verification_proposal
                .expected_postconditions
                .iter()
                .map(|value| value.criterion_id.clone())
                .collect(),
            evidence_ids: vec![
                "cognitive-ir-v1".to_owned(),
                "cognitive-verification-v2".to_owned(),
                "trusted-execution-receipt".to_owned(),
            ],
            binding_sha256: empty_hash(),
        }
        .seal()?;
        Ok(VerificationSpecAdaptationV1 {
            goal: verification_goal,
            proposal: verification_proposal,
            binding,
        })
    }
}

/// Whether an execution state requires a fresh observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReobservationPolicyV1 {
    Required,
    OptionalConfirmation,
    NoExecution,
}

/// Immutable request for one bounded post-execution observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReobservationRequestV1 {
    pub schema_version: u32,
    pub reobservation_id: String,
    pub execution_receipt_sha256: String,
    pub bound_execution_hash: String,
    pub execution_status: ExecutionStatus,
    pub policy: ReobservationPolicyV1,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub integration_id: String,
    pub source_kind: ObservationSourceKind,
    pub source_target_binding_sha256: String,
    pub runtime_binding_sha256: String,
    pub adapter_descriptor_sha256: String,
    pub activation_record_hash: String,
    pub requested_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub request_sha256: String,
}

impl ReobservationRequestV1 {
    /// Constructs an exact request from one KRN-200 binding and receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_binding: &TrustedExecutionBindingRequestV1,
        receipt: &TrustedActionExecutionReceiptV1,
        execution: &BoundActionExecutionV2,
        source: &ObservationSnapshot,
        requested_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        execution_binding.validate().map_err(contract_error)?;
        execution_binding
            .validate_source_observation(source)
            .map_err(contract_error)?;
        receipt.validate().map_err(contract_error)?;
        execution.validate()?;
        let policy = reobservation_policy(receipt.status);
        let mut request = Self {
            schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
            reobservation_id: deterministic_id(
                "reobserve",
                &[&receipt.receipt_sha256, &source.state_hash],
            )?,
            execution_receipt_sha256: receipt.receipt_sha256.clone(),
            bound_execution_hash: canonical_hash(execution)?,
            execution_status: execution.status,
            policy,
            proposal_id: receipt.proposal_id.clone(),
            proposal_sha256: receipt.proposal_sha256.clone(),
            goal_id: receipt.goal_id.clone(),
            plan_generation_id: receipt.plan_generation_id.clone(),
            source_observation_id: source.observation_id.clone(),
            source_observation_hash: source.state_hash.clone(),
            source_observation_sequence: source.sequence,
            integration_id: execution_binding.platform_activation.integration_id.clone(),
            source_kind: source.source_kind,
            source_target_binding_sha256: canonical_hash(&source.target_binding)?,
            runtime_binding_sha256: receipt.runtime_binding_sha256.clone(),
            adapter_descriptor_sha256: receipt.adapter_descriptor_sha256.clone(),
            activation_record_hash: receipt.activation_record_hash.clone(),
            requested_at_unix_ms,
            expires_at_unix_ms,
            evidence_ids: vec![
                "fresh-read-only-observation-required".to_owned(),
                "trusted-execution-receipt".to_owned(),
            ],
            request_sha256: empty_hash(),
        };
        canonicalize_set(&mut request.evidence_ids)?;
        request.request_sha256 = canonical_hash_without(&request, "request_sha256")?;
        request.validate_against(
            execution_binding,
            receipt,
            execution,
            source,
            requested_at_unix_ms,
        )?;
        Ok(request)
    }

    /// Validates exact KRN-200, source observation, runtime, and lifetime bindings.
    pub fn validate_against(
        &self,
        execution_binding: &TrustedExecutionBindingRequestV1,
        receipt: &TrustedActionExecutionReceiptV1,
        execution: &BoundActionExecutionV2,
        source: &ObservationSnapshot,
        now_unix_ms: u64,
    ) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "reobservation request")?;
        execution_binding.validate().map_err(contract_error)?;
        execution_binding
            .validate_source_observation(source)
            .map_err(contract_error)?;
        receipt.validate().map_err(contract_error)?;
        execution.validate()?;
        for value in [
            &self.reobservation_id,
            &self.proposal_id,
            &self.goal_id,
            &self.plan_generation_id,
            &self.source_observation_id,
            &self.integration_id,
        ] {
            validate_token(value, "reobservation identifier")?;
        }
        for value in [
            &self.execution_receipt_sha256,
            &self.bound_execution_hash,
            &self.proposal_sha256,
            &self.source_observation_hash,
            &self.source_target_binding_sha256,
            &self.runtime_binding_sha256,
            &self.adapter_descriptor_sha256,
            &self.activation_record_hash,
            &self.request_sha256,
        ] {
            validate_hash(value, "reobservation hash")?;
        }
        validate_sorted_tokens(&self.evidence_ids, "reobservation evidence", false)?;
        if self.requested_at_unix_ms == 0
            || self.requested_at_unix_ms >= self.expires_at_unix_ms
            || now_unix_ms < self.requested_at_unix_ms
            || now_unix_ms >= self.expires_at_unix_ms
        {
            return Err(DesktopError::Replay(
                "reobservation request is stale or outside its bounded lifetime".to_owned(),
            ));
        }
        if self.execution_receipt_sha256 != receipt.receipt_sha256
            || self.bound_execution_hash != canonical_hash(execution)?
            || self.execution_status != execution.status
            || self.policy != reobservation_policy(receipt.status)
            || self.proposal_id != receipt.proposal_id
            || self.proposal_sha256 != receipt.proposal_sha256
            || self.goal_id != receipt.goal_id
            || self.plan_generation_id != receipt.plan_generation_id
            || self.source_observation_id != source.observation_id
            || self.source_observation_hash != source.state_hash
            || self.source_observation_sequence != source.sequence
            || self.source_kind != source.source_kind
            || self.source_target_binding_sha256 != canonical_hash(&source.target_binding)?
            || self.integration_id != execution_binding.platform_activation.integration_id
            || self.runtime_binding_sha256 != receipt.runtime_binding_sha256
            || self.runtime_binding_sha256
                != execution_binding.platform_activation.runtime_binding_sha256
            || self.adapter_descriptor_sha256 != receipt.adapter_descriptor_sha256
            || self.adapter_descriptor_sha256
                != execution_binding
                    .platform_activation
                    .adapter_descriptor_sha256
            || self.activation_record_hash != receipt.activation_record_hash
            || self.activation_record_hash
                != execution_binding.platform_activation.activation_record_hash
            || self.request_sha256 != canonical_hash_without(self, "request_sha256")?
        {
            return Err(DesktopError::Integrity(
                "reobservation request differs from its trusted execution context".to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "reobservation request")
    }
}

/// Terminal state reported by the dedicated observation worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshObservationWorkerExitStatusV1 {
    Clean,
    Abnormal,
}

/// Audit-safe seal over a fresh normalized observation and runtime evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshObservationProofV1 {
    pub schema_version: u32,
    pub reobservation_request_sha256: String,
    pub execution_receipt_sha256: String,
    pub fresh_observation_id: String,
    pub fresh_observation_hash: String,
    pub fresh_observation_sequence: u64,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub source_kind: ObservationSourceKind,
    pub target_binding_sha256: String,
    pub observation_transport_binding_sha256: String,
    pub observation_activation_record_hash: String,
    pub integration_id: String,
    pub runtime_binding_sha256: String,
    pub process_or_session_binding_sha256: String,
    pub origin_or_window_binding_sha256: String,
    pub observed_at_unix_ms: u64,
    pub observation_duration_ms: u64,
    pub read_only_side_effect_count: u64,
    pub worker_exit_status: FreshObservationWorkerExitStatusV1,
    pub evidence_ids: Vec<String>,
    pub proof_sha256: String,
}

impl FreshObservationProofV1 {
    /// Seals trusted observation metadata after a worker has exited.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &ReobservationRequestV1,
        source: &ObservationSnapshot,
        fresh: &ObservationSnapshot,
        transport_target_binding_sha256: String,
        observation_activation_record_hash: String,
        integration_id: String,
        runtime_binding_sha256: String,
        observed_at_unix_ms: u64,
        observation_duration_ms: u64,
        read_only_side_effect_count: u64,
        worker_exit_status: FreshObservationWorkerExitStatusV1,
    ) -> Result<Self, DesktopError> {
        let (process_or_session, origin_or_window) = identity_binding_hashes(fresh)?;
        let mut proof = Self {
            schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
            reobservation_request_sha256: request.request_sha256.clone(),
            execution_receipt_sha256: request.execution_receipt_sha256.clone(),
            fresh_observation_id: fresh.observation_id.clone(),
            fresh_observation_hash: fresh.state_hash.clone(),
            fresh_observation_sequence: fresh.sequence,
            source_observation_id: source.observation_id.clone(),
            source_observation_hash: source.state_hash.clone(),
            source_observation_sequence: source.sequence,
            source_kind: fresh.source_kind,
            target_binding_sha256: canonical_hash(&fresh.target_binding)?,
            observation_transport_binding_sha256: transport_target_binding_sha256,
            observation_activation_record_hash,
            integration_id,
            runtime_binding_sha256,
            process_or_session_binding_sha256: process_or_session,
            origin_or_window_binding_sha256: origin_or_window,
            observed_at_unix_ms,
            observation_duration_ms,
            read_only_side_effect_count,
            worker_exit_status,
            evidence_ids: vec![
                "dedicated-read-only-worker".to_owned(),
                "fresh-observation".to_owned(),
                "zero-side-effect-counter".to_owned(),
            ],
            proof_sha256: empty_hash(),
        };
        canonicalize_set(&mut proof.evidence_ids)?;
        proof.proof_sha256 = canonical_hash_without(&proof, "proof_sha256")?;
        proof.validate_against(request, source, fresh)?;
        Ok(proof)
    }

    /// Verifies freshness, identity, zero side effects, clean exit, and hashes.
    pub fn validate_against(
        &self,
        request: &ReobservationRequestV1,
        source: &ObservationSnapshot,
        fresh: &ObservationSnapshot,
    ) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "fresh observation proof")?;
        source.validate()?;
        fresh.validate()?;
        for value in [
            &self.reobservation_request_sha256,
            &self.execution_receipt_sha256,
            &self.fresh_observation_hash,
            &self.source_observation_hash,
            &self.target_binding_sha256,
            &self.observation_transport_binding_sha256,
            &self.observation_activation_record_hash,
            &self.runtime_binding_sha256,
            &self.process_or_session_binding_sha256,
            &self.origin_or_window_binding_sha256,
            &self.proof_sha256,
        ] {
            validate_hash(value, "fresh observation proof hash")?;
        }
        for value in [
            &self.fresh_observation_id,
            &self.source_observation_id,
            &self.integration_id,
        ] {
            validate_token(value, "fresh observation proof identifier")?;
        }
        validate_sorted_tokens(&self.evidence_ids, "fresh proof evidence", false)?;
        let (process_or_session, origin_or_window) = identity_binding_hashes(fresh)?;
        if self.reobservation_request_sha256 != request.request_sha256
            || self.execution_receipt_sha256 != request.execution_receipt_sha256
            || self.fresh_observation_id != fresh.observation_id
            || self.fresh_observation_hash != fresh.state_hash
            || self.fresh_observation_sequence != fresh.sequence
            || self.source_observation_id != source.observation_id
            || self.source_observation_hash != source.state_hash
            || self.source_observation_sequence != source.sequence
            || fresh.sequence <= source.sequence
            || fresh.observation_id == source.observation_id
            || self.source_kind != source.source_kind
            || self.source_kind != fresh.source_kind
            || fresh.target_binding != source.target_binding
            || self.target_binding_sha256 != canonical_hash(&source.target_binding)?
            || self.integration_id != request.integration_id
            || self.runtime_binding_sha256 != request.runtime_binding_sha256
            || self.process_or_session_binding_sha256 != process_or_session
            || self.origin_or_window_binding_sha256 != origin_or_window
            || self.observed_at_unix_ms < request.requested_at_unix_ms
            || self.observed_at_unix_ms >= request.expires_at_unix_ms
            || self.observation_duration_ms > MAX_OBSERVATION_DURATION_MS
            || self.read_only_side_effect_count != 0
            || self.worker_exit_status != FreshObservationWorkerExitStatusV1::Clean
            || self.proof_sha256 != canonical_hash_without(self, "proof_sha256")?
        {
            return Err(DesktopError::Integrity(
                "fresh observation proof is stale, substituted, side-effectful, or incomplete"
                    .to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "fresh observation proof")
    }
}

/// Field protected or expected by an additive verification guard.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationGuardFieldV1 {
    Exists,
    Value,
    Kind,
}

/// Exact element/field target used by delta policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationGuardTargetV1 {
    pub element_id: String,
    pub field: VerificationGuardFieldV1,
}

impl VerificationGuardTargetV1 {
    /// Validates the exact element identifier.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.element_id, "verification guard element_id")
    }
}

/// Severity assigned to a protected invariant violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectedInvariantSeverityV1 {
    Fail,
    Unsafe,
}

/// Source-bound value or identity that may not change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedInvariantV1 {
    pub target: VerificationGuardTargetV1,
    pub expected_source_value_hash: String,
    pub severity: ProtectedInvariantSeverityV1,
    pub reason_code: String,
}

/// Explicitly reviewed volatile target ignored by delta classification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoredVolatileTargetV1 {
    pub target: VerificationGuardTargetV1,
    pub approved_reason_code: String,
    pub evidence_id: String,
}

/// Proposal- and source-bound expected-delta and protected-invariant profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationGuardProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub proposal_sha256: String,
    pub source_observation_hash: String,
    pub expected_change_targets: Vec<VerificationGuardTargetV1>,
    pub allowed_change_targets: Vec<VerificationGuardTargetV1>,
    pub protected_invariants: Vec<ProtectedInvariantV1>,
    pub ignored_volatile_targets: Vec<IgnoredVolatileTargetV1>,
    pub maximum_unexpected_changes: usize,
    pub evidence_ids: Vec<String>,
    pub profile_sha256: String,
}

impl VerificationGuardProfileV1 {
    /// Sorts set-like fields, validates source values, and seals the profile.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: String,
        proposal: &ActionProposal,
        source: &ObservationSnapshot,
        mut expected_change_targets: Vec<VerificationGuardTargetV1>,
        mut allowed_change_targets: Vec<VerificationGuardTargetV1>,
        mut protected_invariants: Vec<ProtectedInvariantV1>,
        mut ignored_volatile_targets: Vec<IgnoredVolatileTargetV1>,
        maximum_unexpected_changes: usize,
        mut evidence_ids: Vec<String>,
    ) -> Result<Self, DesktopError> {
        proposal.validate()?;
        source.validate()?;
        expected_change_targets.sort();
        allowed_change_targets.sort();
        protected_invariants.sort();
        ignored_volatile_targets.sort();
        canonicalize_set(&mut evidence_ids)?;
        let mut profile = Self {
            schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
            profile_id,
            proposal_sha256: canonical_hash(proposal)?,
            source_observation_hash: source.state_hash.clone(),
            expected_change_targets,
            allowed_change_targets,
            protected_invariants,
            ignored_volatile_targets,
            maximum_unexpected_changes,
            evidence_ids,
            profile_sha256: empty_hash(),
        };
        profile.profile_sha256 = canonical_hash_without(&profile, "profile_sha256")?;
        profile.validate_against(proposal, source)?;
        Ok(profile)
    }

    /// Validates canonical sets, disjoint classes, and source-bound invariants.
    pub fn validate_against(
        &self,
        proposal: &ActionProposal,
        source: &ObservationSnapshot,
    ) -> Result<(), DesktopError> {
        proposal.validate()?;
        if self.proposal_sha256 != canonical_hash(proposal)? {
            return Err(DesktopError::Integrity(
                "guard profile is bound to another proposal".to_owned(),
            ));
        }
        self.validate_against_placeholder(source)
    }

    fn validate_against_placeholder(
        &self,
        source: &ObservationSnapshot,
    ) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "verification guard profile")?;
        validate_token(&self.profile_id, "verification guard profile_id")?;
        validate_hash(&self.proposal_sha256, "guard proposal_sha256")?;
        validate_hash(
            &self.source_observation_hash,
            "guard source_observation_hash",
        )?;
        validate_hash(&self.profile_sha256, "guard profile_sha256")?;
        source.validate()?;
        if self.source_observation_hash != source.state_hash
            || self.maximum_unexpected_changes > MAX_ITEMS
            || (self.expected_change_targets.is_empty()
                && self.allowed_change_targets.is_empty()
                && self.protected_invariants.is_empty()
                && self.ignored_volatile_targets.is_empty())
        {
            return Err(DesktopError::Invalid(
                "guard profile is unbound, unbounded, or empty".to_owned(),
            ));
        }
        validate_sorted_unique_targets(&self.expected_change_targets, "expected targets")?;
        validate_sorted_unique_targets(&self.allowed_change_targets, "allowed targets")?;
        validate_sorted_tokens(&self.evidence_ids, "guard evidence", true)?;
        if !is_sorted_unique(&self.protected_invariants)
            || !is_sorted_unique(&self.ignored_volatile_targets)
            || self.protected_invariants.len() > MAX_ITEMS
            || self.ignored_volatile_targets.len() > MAX_ITEMS
        {
            return Err(DesktopError::Invalid(
                "guard protected or ignored targets are not canonical".to_owned(),
            ));
        }
        let expected = self
            .expected_change_targets
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let allowed = self
            .allowed_change_targets
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let protected = self
            .protected_invariants
            .iter()
            .map(|value| value.target.clone())
            .collect::<BTreeSet<_>>();
        let ignored = self
            .ignored_volatile_targets
            .iter()
            .map(|value| value.target.clone())
            .collect::<BTreeSet<_>>();
        if expected.len() != self.expected_change_targets.len()
            || allowed.len() != self.allowed_change_targets.len()
            || protected.len() != self.protected_invariants.len()
            || ignored.len() != self.ignored_volatile_targets.len()
            || !expected.is_disjoint(&allowed)
            || !expected.is_disjoint(&protected)
            || !expected.is_disjoint(&ignored)
            || !allowed.is_disjoint(&protected)
            || !allowed.is_disjoint(&ignored)
            || !protected.is_disjoint(&ignored)
        {
            return Err(DesktopError::Invalid(
                "guard target classifications overlap or contain duplicates".to_owned(),
            ));
        }
        for target in expected.iter().chain(allowed.iter()) {
            target.validate()?;
            let _ = observed_target_value(source, target)?;
        }
        for invariant in &self.protected_invariants {
            invariant.target.validate()?;
            validate_token(&invariant.reason_code, "protected invariant reason_code")?;
            validate_hash(
                &invariant.expected_source_value_hash,
                "protected source value hash",
            )?;
            if invariant.expected_source_value_hash
                != canonical_hash(&observed_target_value(source, &invariant.target)?)?
            {
                return Err(DesktopError::Integrity(
                    "protected invariant does not match the source observation".to_owned(),
                ));
            }
        }
        for ignored in &self.ignored_volatile_targets {
            ignored.target.validate()?;
            validate_token(
                &ignored.approved_reason_code,
                "ignored volatile reason_code",
            )?;
            validate_token(&ignored.evidence_id, "ignored volatile evidence_id")?;
        }
        if canonical_hash_without(self, "profile_sha256")? != self.profile_sha256 {
            return Err(DesktopError::Integrity(
                "guard profile hash differs from canonical content".to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "verification guard profile")
    }
}

/// Observable difference kind. Values are represented by hashes and types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDeltaKindV1 {
    ElementAdded,
    ElementRemoved,
    ValueChanged,
    KindChanged,
    TrustLabelsChanged,
    RedactionChanged,
    TargetBindingChanged,
    ExpectedChangeMissing,
    UnexpectedLimitExceeded,
}

/// One audit-safe observation difference with no raw old/new value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationElementDeltaV1 {
    pub delta_id: String,
    pub target: Option<VerificationGuardTargetV1>,
    pub kind: ObservationDeltaKindV1,
    pub before_sha256: Option<String>,
    pub after_sha256: Option<String>,
    pub before_type: Option<String>,
    pub after_type: Option<String>,
    pub reason_code: String,
}

impl ObservationElementDeltaV1 {
    fn validate(&self) -> Result<(), DesktopError> {
        validate_token(&self.delta_id, "observation delta_id")?;
        validate_token(&self.reason_code, "observation delta reason_code")?;
        if let Some(target) = &self.target {
            target.validate()?;
        }
        for hash in [self.before_sha256.as_ref(), self.after_sha256.as_ref()]
            .into_iter()
            .flatten()
        {
            validate_hash(hash, "observation delta value hash")?;
        }
        for kind in [self.before_type.as_ref(), self.after_type.as_ref()]
            .into_iter()
            .flatten()
        {
            validate_token(kind, "observation delta value type")?;
        }
        Ok(())
    }
}

/// Deterministic expected, allowed, protected, unexpected, and ignored delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationDeltaV1 {
    pub schema_version: u32,
    pub source_observation_hash: String,
    pub fresh_observation_hash: String,
    pub guard_profile_sha256: String,
    pub expected_changes: Vec<ObservationElementDeltaV1>,
    pub allowed_changes: Vec<ObservationElementDeltaV1>,
    pub protected_invariant_violations: Vec<ObservationElementDeltaV1>,
    pub unexpected_changes: Vec<ObservationElementDeltaV1>,
    pub ignored_volatile_changes: Vec<ObservationElementDeltaV1>,
    pub security_relevant_changes: Vec<ObservationElementDeltaV1>,
    pub missing_expected_changes: Vec<VerificationGuardTargetV1>,
    pub unexpected_limit_exceeded: bool,
    pub delta_sha256: String,
}

impl ObservationDeltaV1 {
    /// Validates canonical lists and the immutable delta hash.
    pub fn validate(&self) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "observation delta")?;
        for value in [
            &self.source_observation_hash,
            &self.fresh_observation_hash,
            &self.guard_profile_sha256,
            &self.delta_sha256,
        ] {
            validate_hash(value, "observation delta hash")?;
        }
        for values in [
            &self.expected_changes,
            &self.allowed_changes,
            &self.protected_invariant_violations,
            &self.unexpected_changes,
            &self.ignored_volatile_changes,
            &self.security_relevant_changes,
        ] {
            if !is_sorted_unique(values) || values.len() > MAX_ITEMS {
                return Err(DesktopError::Invalid(
                    "observation delta list is not canonical or bounded".to_owned(),
                ));
            }
            for value in values {
                value.validate()?;
            }
        }
        validate_sorted_unique_targets(&self.missing_expected_changes, "missing expected changes")?;
        if self.delta_sha256 != canonical_hash_without(self, "delta_sha256")? {
            return Err(DesktopError::Integrity(
                "observation delta hash differs from canonical content".to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "observation delta")
    }
}

/// Computes a deterministic hash-only observation delta.
pub fn analyze_observation_delta(
    source: &ObservationSnapshot,
    fresh: &ObservationSnapshot,
    profile: &VerificationGuardProfileV1,
) -> Result<ObservationDeltaV1, DesktopError> {
    source.validate()?;
    fresh.validate()?;
    profile.validate_against_placeholder(source)?;
    let source_elements = element_map(source)?;
    let fresh_elements = element_map(fresh)?;
    let mut all_ids = source_elements.keys().cloned().collect::<BTreeSet<_>>();
    all_ids.extend(fresh_elements.keys().cloned());
    let mut changes = Vec::new();
    for element_id in all_ids {
        match (
            source_elements.get(&element_id),
            fresh_elements.get(&element_id),
        ) {
            (None, Some(_after)) => changes.push(delta_change(
                Some(VerificationGuardTargetV1 {
                    element_id,
                    field: VerificationGuardFieldV1::Exists,
                }),
                ObservationDeltaKindV1::ElementAdded,
                None,
                Some(&Value::Bool(true)),
                "element-added",
            )?),
            (Some(_before), None) => changes.push(delta_change(
                Some(VerificationGuardTargetV1 {
                    element_id,
                    field: VerificationGuardFieldV1::Exists,
                }),
                ObservationDeltaKindV1::ElementRemoved,
                Some(&Value::Bool(true)),
                None,
                "element-removed",
            )?),
            (Some(before), Some(after)) => {
                if before.value != after.value {
                    changes.push(delta_change(
                        Some(VerificationGuardTargetV1 {
                            element_id: element_id.clone(),
                            field: VerificationGuardFieldV1::Value,
                        }),
                        ObservationDeltaKindV1::ValueChanged,
                        Some(&before.value),
                        Some(&after.value),
                        "value-changed",
                    )?);
                }
                if before.kind != after.kind {
                    changes.push(delta_change(
                        Some(VerificationGuardTargetV1 {
                            element_id: element_id.clone(),
                            field: VerificationGuardFieldV1::Kind,
                        }),
                        ObservationDeltaKindV1::KindChanged,
                        Some(&Value::String(before.kind.clone())),
                        Some(&Value::String(after.kind.clone())),
                        "kind-changed",
                    )?);
                }
                if before.trust_labels != after.trust_labels {
                    changes.push(delta_change(
                        Some(VerificationGuardTargetV1 {
                            element_id,
                            field: VerificationGuardFieldV1::Value,
                        }),
                        ObservationDeltaKindV1::TrustLabelsChanged,
                        Some(&serde_json::to_value(&before.trust_labels).map_err(json_error)?),
                        Some(&serde_json::to_value(&after.trust_labels).map_err(json_error)?),
                        "trust-labels-changed",
                    )?);
                }
            }
            (None, None) => {}
        }
    }
    if source.redactions != fresh.redactions {
        changes.push(delta_change(
            None,
            ObservationDeltaKindV1::RedactionChanged,
            Some(&serde_json::to_value(&source.redactions).map_err(json_error)?),
            Some(&serde_json::to_value(&fresh.redactions).map_err(json_error)?),
            "redaction-boundary-changed",
        )?);
    }
    if source.trust_labels != fresh.trust_labels {
        changes.push(delta_change(
            None,
            ObservationDeltaKindV1::TrustLabelsChanged,
            Some(&serde_json::to_value(&source.trust_labels).map_err(json_error)?),
            Some(&serde_json::to_value(&fresh.trust_labels).map_err(json_error)?),
            "observation-trust-labels-changed",
        )?);
    }
    if source.target_binding != fresh.target_binding {
        changes.push(delta_change(
            None,
            ObservationDeltaKindV1::TargetBindingChanged,
            Some(&serde_json::to_value(&source.target_binding).map_err(json_error)?),
            Some(&serde_json::to_value(&fresh.target_binding).map_err(json_error)?),
            "target-binding-changed",
        )?);
    }
    changes.sort();

    let expected = profile
        .expected_change_targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let allowed = profile
        .allowed_change_targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let protected = profile
        .protected_invariants
        .iter()
        .map(|value| (value.target.clone(), value))
        .collect::<BTreeMap<_, _>>();
    let ignored = profile
        .ignored_volatile_targets
        .iter()
        .map(|value| value.target.clone())
        .collect::<BTreeSet<_>>();
    let mut expected_changes = Vec::new();
    let mut allowed_changes = Vec::new();
    let mut protected_invariant_violations = Vec::new();
    let mut unexpected_changes = Vec::new();
    let mut ignored_volatile_changes = Vec::new();
    let mut security_relevant_changes = Vec::new();
    let mut observed_expected = BTreeSet::new();
    for change in changes {
        let protected_match = change.target.as_ref().is_some_and(|target| {
            protected.values().any(|invariant| {
                invariant.target == *target
                    || (change.kind == ObservationDeltaKindV1::ElementRemoved
                        && invariant.target.element_id == target.element_id)
            })
        });
        let protected_unsafe = change.target.as_ref().is_some_and(|target| {
            protected.values().any(|invariant| {
                invariant.severity == ProtectedInvariantSeverityV1::Unsafe
                    && (invariant.target == *target
                        || (change.kind == ObservationDeltaKindV1::ElementRemoved
                            && invariant.target.element_id == target.element_id))
            })
        });
        match &change.target {
            Some(_) if protected_match => {
                if protected_unsafe {
                    security_relevant_changes.push(change.clone());
                }
                protected_invariant_violations.push(change);
            }
            Some(target)
                if expected.contains(target) && change_matches_guard_field(&change, target) =>
            {
                observed_expected.insert(target.clone());
                expected_changes.push(change);
            }
            Some(target)
                if allowed.contains(target) && change_matches_guard_field(&change, target) =>
            {
                allowed_changes.push(change);
            }
            Some(target)
                if ignored.contains(target) && change_matches_guard_field(&change, target) =>
            {
                ignored_volatile_changes.push(change);
            }
            _ => {
                if matches!(
                    change.kind,
                    ObservationDeltaKindV1::TargetBindingChanged
                        | ObservationDeltaKindV1::TrustLabelsChanged
                        | ObservationDeltaKindV1::RedactionChanged
                ) {
                    security_relevant_changes.push(change.clone());
                }
                unexpected_changes.push(change);
            }
        }
    }
    let missing_expected_changes = expected
        .difference(&observed_expected)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected_limit_exceeded = unexpected_changes.len() > profile.maximum_unexpected_changes;
    if unexpected_limit_exceeded {
        security_relevant_changes.push(delta_change(
            None,
            ObservationDeltaKindV1::UnexpectedLimitExceeded,
            None,
            None,
            "unexpected-change-limit-exceeded",
        )?);
    }
    for values in [
        &mut expected_changes,
        &mut allowed_changes,
        &mut protected_invariant_violations,
        &mut unexpected_changes,
        &mut ignored_volatile_changes,
        &mut security_relevant_changes,
    ] {
        values.sort();
        values.dedup();
    }
    let mut delta = ObservationDeltaV1 {
        schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
        source_observation_hash: source.state_hash.clone(),
        fresh_observation_hash: fresh.state_hash.clone(),
        guard_profile_sha256: profile.profile_sha256.clone(),
        expected_changes,
        allowed_changes,
        protected_invariant_violations,
        unexpected_changes,
        ignored_volatile_changes,
        security_relevant_changes,
        missing_expected_changes,
        unexpected_limit_exceeded,
        delta_sha256: empty_hash(),
    };
    delta.delta_sha256 = canonical_hash_without(&delta, "delta_sha256")?;
    delta.validate()?;
    Ok(delta)
}

/// Deterministic implementation of the existing side-effect-free v2 trait.
pub struct DeterministicPostconditionVerifierV2 {
    spec_binding: VerificationSpecBindingV1,
    guard_profile: VerificationGuardProfileV1,
    delta: ObservationDeltaV1,
    fresh_proof: FreshObservationProofV1,
    provenance: Provenance,
}

impl DeterministicPostconditionVerifierV2 {
    /// Binds a verifier to one exact spec adaptation, guard, delta, and proof.
    pub fn new(
        spec_binding: VerificationSpecBindingV1,
        guard_profile: VerificationGuardProfileV1,
        delta: ObservationDeltaV1,
        fresh_proof: FreshObservationProofV1,
        provenance: Provenance,
    ) -> Result<Self, DesktopError> {
        spec_binding.validate()?;
        delta.validate()?;
        validate_text(
            &provenance.source,
            "deterministic verifier provenance source",
        )?;
        validate_hash(
            &provenance.source_hash,
            "deterministic verifier provenance source_hash",
        )?;
        validate_token(
            &provenance.module_id,
            "deterministic verifier provenance module_id",
        )?;
        if delta.guard_profile_sha256 != guard_profile.profile_sha256
            || delta.source_observation_hash != guard_profile.source_observation_hash
            || fresh_proof.fresh_observation_hash != delta.fresh_observation_hash
            || fresh_proof.source_observation_hash != delta.source_observation_hash
        {
            return Err(DesktopError::Integrity(
                "verifier guard, delta, or fresh proof binding mismatch".to_owned(),
            ));
        }
        Ok(Self {
            spec_binding,
            guard_profile,
            delta,
            fresh_proof,
            provenance,
        })
    }
}

impl PostconditionVerifierV2 for DeterministicPostconditionVerifierV2 {
    fn verify(
        &mut self,
        request: &VerificationRequestV2,
    ) -> Result<VerificationResultV2, DesktopError> {
        request.validate()?;
        if canonical_hash(&request.goal)? != self.spec_binding.verification_goal_sha256
            || canonical_hash(&request.proposal)?
                != self.spec_binding.verification_action_proposal_sha256
            || canonical_hash(&request.execution)? != self.spec_binding.bound_execution_sha256
            || request.source_observation.state_hash != self.delta.source_observation_hash
            || request.fresh_observation.state_hash != self.delta.fresh_observation_hash
            || request.fresh_observation.state_hash != self.fresh_proof.fresh_observation_hash
            || self.guard_profile.proposal_sha256 != self.spec_binding.proposal_sha256
        {
            return Err(DesktopError::Integrity(
                "verification request differs from deterministic verifier context".to_owned(),
            ));
        }
        let action_postcondition_results = request
            .proposal
            .expected_postconditions
            .iter()
            .map(|criterion| evaluate_postcondition(criterion, &request.fresh_observation))
            .collect::<Result<Vec<_>, DesktopError>>()?;
        let goal_postcondition_results = request
            .goal
            .success_criteria
            .iter()
            .map(|criterion| evaluate_postcondition(criterion, &request.fresh_observation))
            .collect::<Result<Vec<_>, DesktopError>>()?;

        let mut unexpected_changes = Vec::new();
        for change in &self.delta.security_relevant_changes {
            unexpected_changes.push(format!("unsafe:{}", change.delta_id));
        }
        for change in &self.delta.unexpected_changes {
            unexpected_changes.push(format!("unsafe:{}", change.delta_id));
        }
        for change in &self.delta.protected_invariant_violations {
            let severity = self
                .guard_profile
                .protected_invariants
                .iter()
                .find(|value| {
                    value.target
                        == change
                            .target
                            .clone()
                            .unwrap_or_else(|| VerificationGuardTargetV1 {
                                element_id: "observation".to_owned(),
                                field: VerificationGuardFieldV1::Value,
                            })
                })
                .map_or(ProtectedInvariantSeverityV1::Unsafe, |value| value.severity);
            unexpected_changes.push(format!(
                "{}:{}",
                if severity == ProtectedInvariantSeverityV1::Unsafe {
                    "unsafe"
                } else {
                    "fail"
                },
                change.delta_id
            ));
        }
        for target in &self.delta.missing_expected_changes {
            unexpected_changes.push(format!(
                "fail:{}",
                deterministic_id("missing-expected", &[&canonical_hash(target)?],)?
            ));
        }
        unexpected_changes.sort();
        unexpected_changes.dedup();

        let action_verdict = effective_action_verdict(
            request.execution.status,
            &action_postcondition_results,
            &unexpected_changes,
        );
        let goal_progress = effective_goal_progress(action_verdict, &goal_postcondition_results);
        let mut evidence = vec![
            format!("delta:{}", self.delta.delta_sha256),
            format!("fresh-proof:{}", self.fresh_proof.proof_sha256),
            format!("guard:{}", self.guard_profile.profile_sha256),
            format!("spec:{}", self.spec_binding.binding_sha256),
        ];
        evidence.sort();
        let result = VerificationResultV2 {
            schema_version: 2,
            verification_id: request.verification_id.clone(),
            goal_id: request.goal.goal_id.clone(),
            plan_generation_id: request.proposal.plan_generation_id.clone(),
            proposal_id: request.proposal.proposal_id.clone(),
            execution_id: request.execution.execution_id.clone(),
            execution_status: request.execution.status,
            action_verdict,
            action_postcondition_results,
            goal_postcondition_results,
            observed_state_hash: request.fresh_observation.state_hash.clone(),
            goal_progress,
            unexpected_changes,
            warnings: Vec::new(),
            evidence,
            reason: verdict_reason(action_verdict).to_owned(),
            provenance: self.provenance.clone(),
            confidence: VerificationConfidenceV2::NotApplicable,
        };
        result.validate_against(request)?;
        Ok(result)
    }
}

/// Immutable terminal result combining existing v2 output with additive proof hashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedActionResultV1 {
    pub schema_version: u32,
    pub verified_action_id: String,
    pub execution_receipt_sha256: String,
    pub bound_execution_hash: String,
    pub reobservation_request_sha256: String,
    pub fresh_observation_proof_sha256: String,
    pub source_observation_id: String,
    pub source_observation_hash: String,
    pub source_observation_sequence: u64,
    pub fresh_observation_id: String,
    pub fresh_observation_hash: String,
    pub fresh_observation_sequence: u64,
    pub proposal_id: String,
    pub proposal_sha256: String,
    pub goal_id: String,
    pub plan_generation_id: String,
    pub execution_id: String,
    pub execution_status: ExecutionStatus,
    pub verification_request_sha256: String,
    pub verification_result_sha256: String,
    pub action_verdict: VerificationVerdictV2,
    pub goal_progress: GoalProgress,
    pub guard_profile_sha256: String,
    pub observation_delta_sha256: String,
    pub protected_violation_count: usize,
    pub unexpected_change_count: usize,
    pub observed_at_unix_ms: u64,
    pub verified_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
    pub warnings: Vec<String>,
    pub result_sha256: String,
}

impl VerifiedActionResultV1 {
    #[allow(clippy::too_many_arguments)]
    fn build(
        receipt: &TrustedActionExecutionReceiptV1,
        execution: &BoundActionExecutionV2,
        reobservation: &ReobservationRequestV1,
        proof: &FreshObservationProofV1,
        request: &VerificationRequestV2,
        result: &VerificationResultV2,
        spec: &VerificationSpecBindingV1,
        guard: &VerificationGuardProfileV1,
        delta: &ObservationDeltaV1,
        verified_at_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        result.validate_against(request)?;
        let mut terminal = Self {
            schema_version: COGNITIVE_REOBSERVE_SCHEMA_VERSION,
            verified_action_id: deterministic_id(
                "verified-action",
                &[
                    &receipt.receipt_sha256,
                    &result.canonical_hash_against(request)?,
                ],
            )?,
            execution_receipt_sha256: receipt.receipt_sha256.clone(),
            bound_execution_hash: canonical_hash(execution)?,
            reobservation_request_sha256: reobservation.request_sha256.clone(),
            fresh_observation_proof_sha256: proof.proof_sha256.clone(),
            source_observation_id: request.source_observation.observation_id.clone(),
            source_observation_hash: request.source_observation.state_hash.clone(),
            source_observation_sequence: request.source_observation.sequence,
            fresh_observation_id: request.fresh_observation.observation_id.clone(),
            fresh_observation_hash: request.fresh_observation.state_hash.clone(),
            fresh_observation_sequence: request.fresh_observation.sequence,
            proposal_id: request.proposal.proposal_id.clone(),
            proposal_sha256: spec.proposal_sha256.clone(),
            goal_id: request.goal.goal_id.clone(),
            plan_generation_id: request.proposal.plan_generation_id.clone(),
            execution_id: execution.execution_id.clone(),
            execution_status: execution.status,
            verification_request_sha256: request.canonical_hash()?,
            verification_result_sha256: result.canonical_hash_against(request)?,
            action_verdict: result.action_verdict,
            goal_progress: result.goal_progress,
            guard_profile_sha256: guard.profile_sha256.clone(),
            observation_delta_sha256: delta.delta_sha256.clone(),
            protected_violation_count: delta.protected_invariant_violations.len(),
            unexpected_change_count: delta.unexpected_changes.len(),
            observed_at_unix_ms: proof.observed_at_unix_ms,
            verified_at_unix_ms,
            evidence_ids: vec![
                "independent-reobservation".to_owned(),
                "not-case-closure".to_owned(),
                "not-recovery-authority".to_owned(),
                "verification-v2".to_owned(),
            ],
            warnings: result.warnings.clone(),
            result_sha256: empty_hash(),
        };
        canonicalize_set(&mut terminal.evidence_ids)?;
        terminal.warnings.sort();
        terminal.warnings.dedup();
        terminal.result_sha256 = canonical_hash_without(&terminal, "result_sha256")?;
        terminal.validate_against(
            receipt,
            execution,
            reobservation,
            proof,
            request,
            result,
            guard,
            delta,
        )?;
        Ok(terminal)
    }

    /// Validates every proof/result hash and terminal count.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_against(
        &self,
        receipt: &TrustedActionExecutionReceiptV1,
        execution: &BoundActionExecutionV2,
        reobservation: &ReobservationRequestV1,
        proof: &FreshObservationProofV1,
        request: &VerificationRequestV2,
        result: &VerificationResultV2,
        guard: &VerificationGuardProfileV1,
        delta: &ObservationDeltaV1,
    ) -> Result<(), DesktopError> {
        validate_schema(self.schema_version, "verified action result")?;
        validate_token(&self.verified_action_id, "verified action_id")?;
        for value in [
            &self.execution_receipt_sha256,
            &self.bound_execution_hash,
            &self.reobservation_request_sha256,
            &self.fresh_observation_proof_sha256,
            &self.source_observation_hash,
            &self.fresh_observation_hash,
            &self.proposal_sha256,
            &self.verification_request_sha256,
            &self.verification_result_sha256,
            &self.guard_profile_sha256,
            &self.observation_delta_sha256,
            &self.result_sha256,
        ] {
            validate_hash(value, "verified action result hash")?;
        }
        for value in [
            &self.source_observation_id,
            &self.fresh_observation_id,
            &self.proposal_id,
            &self.goal_id,
            &self.plan_generation_id,
            &self.execution_id,
        ] {
            validate_token(value, "verified action result identifier")?;
        }
        validate_sorted_tokens(&self.evidence_ids, "verified result evidence", false)?;
        validate_sorted_tokens(&self.warnings, "verified result warnings", true)?;
        result.validate_against(request)?;
        if self.execution_receipt_sha256 != receipt.receipt_sha256
            || self.bound_execution_hash != canonical_hash(execution)?
            || self.reobservation_request_sha256 != reobservation.request_sha256
            || self.fresh_observation_proof_sha256 != proof.proof_sha256
            || self.source_observation_id != request.source_observation.observation_id
            || self.source_observation_hash != request.source_observation.state_hash
            || self.source_observation_sequence != request.source_observation.sequence
            || self.fresh_observation_id != request.fresh_observation.observation_id
            || self.fresh_observation_hash != request.fresh_observation.state_hash
            || self.fresh_observation_sequence != request.fresh_observation.sequence
            || self.proposal_id != request.proposal.proposal_id
            || self.goal_id != request.goal.goal_id
            || self.plan_generation_id != request.proposal.plan_generation_id
            || self.execution_id != execution.execution_id
            || self.execution_status != execution.status
            || self.verification_request_sha256 != request.canonical_hash()?
            || self.verification_result_sha256 != result.canonical_hash_against(request)?
            || self.action_verdict != result.action_verdict
            || self.goal_progress != result.goal_progress
            || self.guard_profile_sha256 != guard.profile_sha256
            || self.observation_delta_sha256 != delta.delta_sha256
            || self.protected_violation_count != delta.protected_invariant_violations.len()
            || self.unexpected_change_count != delta.unexpected_changes.len()
            || self.observed_at_unix_ms != proof.observed_at_unix_ms
            || self.verified_at_unix_ms < self.observed_at_unix_ms
            || self.result_sha256 != canonical_hash_without(self, "result_sha256")?
        {
            return Err(DesktopError::Integrity(
                "verified action result differs from its bound proof chain".to_owned(),
            ));
        }
        reject_forbidden_artifact(self, "verified action result")
    }
}

/// One certified provider that can issue only a single read-only observation.
pub enum TrustedReadOnlyObservationConfiguration {
    Uia(WindowsUiaObservationProvider),
    WebDriver(WindowsWebObservationProvider),
}

impl TrustedReadOnlyObservationConfiguration {
    fn observe_once(
        self,
        goal: &GoalSpec,
        sequence: u64,
    ) -> Result<CompletedReadOnlyObservation, DesktopError> {
        match self {
            Self::Uia(provider) => provider.observe_once(goal, sequence),
            Self::WebDriver(provider) => provider.observe_once(goal, sequence),
        }
    }
}

/// Rebinds an actually collected source snapshot to the exact KRN-200 platform
/// activation after verifying that only one-shot activation keys differ.
pub fn bind_actual_source_observation(
    actual: &ObservationSnapshot,
    platform: &TrustedPlatformActivationV1,
) -> Result<ObservationSnapshot, DesktopError> {
    actual.validate()?;
    platform.validate().map_err(contract_error)?;
    let expected_kind = match actual.source_kind {
        ObservationSourceKind::Uia => AdapterKindV1::Uia,
        ObservationSourceKind::WebDriver => AdapterKindV1::WebDriver,
        _ => {
            return Err(DesktopError::AccessDenied(
                "only UIA and WebDriver observations can bind to Windows execution".to_owned(),
            ));
        }
    };
    if platform.adapter_kind != expected_kind
        || actual.target_binding.get("integration_id") != Some(&platform.integration_id)
        || actual.target_binding.get("runtime_binding_digest")
            != Some(&platform.runtime_binding_sha256)
    {
        return Err(DesktopError::Integrity(
            "actual source observation differs from the KRN-200 platform identity".to_owned(),
        ));
    }
    let mut bound = actual.clone();
    bound
        .target_binding
        .insert("binding_id".to_owned(), platform.binding_id.clone());
    bound.target_binding.insert(
        "activation_record_hash".to_owned(),
        platform.activation_record_hash.clone(),
    );
    bound.provenance.source_hash = canonical_hash(&bound.target_binding)?;
    bound.state_hash = bound.compute_state_hash()?;
    bound.validate()?;
    Ok(bound)
}

/// Fresh snapshot and proof returned by the dedicated re-observation boundary.
#[derive(Debug, Clone)]
pub struct FreshObservationBundleV1 {
    pub observation: ObservationSnapshot,
    pub proof: FreshObservationProofV1,
    worker_process_id: u32,
}

impl FreshObservationBundleV1 {
    /// Returns the already-terminated observation worker PID for residue checks.
    #[must_use]
    pub const fn worker_process_id(&self) -> u32 {
        self.worker_process_id
    }
}

/// One-shot coordinator for an independently activated read-only worker.
pub struct CognitiveReobserveCoordinator {
    receipt: TrustedActionExecutionReceiptV1,
    source: ObservationSnapshot,
    request: ReobservationRequestV1,
    completed: bool,
    last_worker_process_id: Option<u32>,
}

impl CognitiveReobserveCoordinator {
    /// Validates exact receipt, execution, and source bindings before observation.
    pub fn new(
        execution_binding: &TrustedExecutionBindingRequestV1,
        receipt: TrustedActionExecutionReceiptV1,
        execution: BoundActionExecutionV2,
        source: ObservationSnapshot,
        request: ReobservationRequestV1,
        now_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        request.validate_against(
            execution_binding,
            &receipt,
            &execution,
            &source,
            now_unix_ms,
        )?;
        if request.policy == ReobservationPolicyV1::NoExecution {
            return Err(DesktopError::AccessDenied(
                "denied-before-commit execution has no mutation to reobserve".to_owned(),
            ));
        }
        Ok(Self {
            receipt,
            source,
            request,
            completed: false,
            last_worker_process_id: None,
        })
    }

    /// Starts a separate worker, collects one snapshot, and waits for clean exit.
    pub fn reobserve(
        &mut self,
        observer: TrustedReadOnlyObservationConfiguration,
        goal: &GoalSpec,
        observed_at_unix_ms: u64,
        audit: &mut WindowsDeploymentAuditLedger,
    ) -> Result<FreshObservationBundleV1, DesktopError> {
        if self.completed {
            return Err(DesktopError::Replay(
                "reobservation request was already consumed".to_owned(),
            ));
        }
        self.request.validate_lifetime(observed_at_unix_ms)?;
        append_verification_audit(
            audit,
            WindowsDeploymentAuditEventKind::ReobservationStarted,
            WindowsDeploymentAuditStatus::Succeeded,
            &self.request.reobservation_id,
            BTreeMap::from([
                (
                    "reobservation_request".to_owned(),
                    self.request.request_sha256.clone(),
                ),
                ("receipt".to_owned(), self.receipt.receipt_sha256.clone()),
            ]),
            observed_at_unix_ms,
        )?;
        let sequence = self.source.sequence.checked_add(1).ok_or_else(|| {
            DesktopError::Invalid("fresh observation sequence overflowed".to_owned())
        })?;
        let outcome = observer.observe_once(goal, sequence)?;
        self.last_worker_process_id = Some(outcome.worker_process_id);
        if !outcome.worker_exited_cleanly
            || outcome.read_only_side_effect_count != 0
            || outcome.integration_id != self.request.integration_id
            || outcome.runtime_binding_sha256 != self.request.runtime_binding_sha256
            || outcome.adapter_descriptor_sha256 != self.request.adapter_descriptor_sha256
            || outcome.snapshot.source_kind != self.source.source_kind
        {
            return Err(DesktopError::Integrity(
                "fresh observer identity, side-effect count, or exit status is invalid".to_owned(),
            ));
        }
        validate_logical_target_binding(
            &self.source.target_binding,
            &outcome.snapshot.target_binding,
        )?;
        let mut fresh = outcome.snapshot;
        fresh.target_binding = self.source.target_binding.clone();
        fresh.provenance.source_hash = canonical_hash(&fresh.target_binding)?;
        fresh.state_hash = fresh.compute_state_hash()?;
        fresh.validate()?;
        let proof = FreshObservationProofV1::new(
            &self.request,
            &self.source,
            &fresh,
            outcome.transport_target_binding_sha256,
            outcome.activation_record_hash,
            outcome.integration_id,
            outcome.runtime_binding_sha256,
            observed_at_unix_ms,
            outcome.observation_duration_ms,
            outcome.read_only_side_effect_count,
            FreshObservationWorkerExitStatusV1::Clean,
        )?;
        append_verification_audit(
            audit,
            WindowsDeploymentAuditEventKind::FreshObservationCollected,
            WindowsDeploymentAuditStatus::Succeeded,
            &self.request.reobservation_id,
            BTreeMap::from([
                ("fresh_observation".to_owned(), fresh.state_hash.clone()),
                ("fresh_proof".to_owned(), proof.proof_sha256.clone()),
                (
                    "runtime_binding".to_owned(),
                    proof.runtime_binding_sha256.clone(),
                ),
            ]),
            observed_at_unix_ms,
        )?;
        self.completed = true;
        Ok(FreshObservationBundleV1 {
            observation: fresh,
            proof,
            worker_process_id: outcome.worker_process_id,
        })
    }

    /// Returns the dedicated read-only worker PID after collection.
    #[must_use]
    pub const fn last_worker_process_id(&self) -> Option<u32> {
        self.last_worker_process_id
    }
}

/// Process-local replay ledger. A begun verification remains consumed even if
/// a coordinator is dropped before terminal completion.
#[derive(Debug, Default)]
pub struct VerificationConsumptionLedgerV1 {
    begun_receipts: BTreeSet<String>,
    terminal_receipts: BTreeSet<String>,
}

impl VerificationConsumptionLedgerV1 {
    fn begin(&mut self, receipt_sha256: &str) -> Result<(), DesktopError> {
        validate_hash(receipt_sha256, "verification consumption receipt")?;
        if !self.begun_receipts.insert(receipt_sha256.to_owned()) {
            return Err(DesktopError::Replay(
                "execution receipt verification was already begun".to_owned(),
            ));
        }
        Ok(())
    }

    fn finish(&mut self, receipt_sha256: &str) -> Result<(), DesktopError> {
        if !self.begun_receipts.contains(receipt_sha256)
            || !self.terminal_receipts.insert(receipt_sha256.to_owned())
        {
            return Err(DesktopError::Replay(
                "execution receipt verification is not uniquely consumable".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reports whether terminal verification consumed the receipt.
    #[must_use]
    pub fn is_terminal(&self, receipt_sha256: &str) -> bool {
        self.terminal_receipts.contains(receipt_sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerificationStageV2 {
    Begun,
    Reobserved,
    DeltaAnalyzed,
    RequestBuilt,
    Verified,
    Terminal,
    Poisoned,
}

/// Stateful begin-to-finalize runtime for independent Cognitive Verification v2.
pub struct CognitiveVerificationCoordinatorV2<'a> {
    goal: GoalSpec,
    policy_ready: PolicyReadyActionV1,
    receipt: TrustedActionExecutionReceiptV1,
    execution: BoundActionExecutionV2,
    source: ObservationSnapshot,
    guard: VerificationGuardProfileV1,
    reobserver: CognitiveReobserveCoordinator,
    fresh: Option<FreshObservationBundleV1>,
    delta: Option<ObservationDeltaV1>,
    spec: Option<VerificationSpecAdaptationV1>,
    verification_request: Option<VerificationRequestV2>,
    verification_result: Option<VerificationResultV2>,
    terminal: Option<VerifiedActionResultV1>,
    stage: VerificationStageV2,
    audit: WindowsDeploymentAuditLedger,
    consumption: &'a mut VerificationConsumptionLedgerV1,
}

impl<'a> CognitiveVerificationCoordinatorV2<'a> {
    /// Begins one receipt-bound verification and consumes its replay slot.
    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        execution_binding: TrustedExecutionBindingRequestV1,
        goal: GoalSpec,
        policy_ready: PolicyReadyActionV1,
        receipt: TrustedActionExecutionReceiptV1,
        execution: BoundActionExecutionV2,
        source: ObservationSnapshot,
        reobservation_request: ReobservationRequestV1,
        guard: VerificationGuardProfileV1,
        audit: WindowsDeploymentAuditLedger,
        consumption: &'a mut VerificationConsumptionLedgerV1,
        now_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        goal.validate()?;
        guard.validate_against(&policy_ready.proposal, &source)?;
        reobservation_request.validate_against(
            &execution_binding,
            &receipt,
            &execution,
            &source,
            now_unix_ms,
        )?;
        consumption.begin(&receipt.receipt_sha256)?;
        let reobserver = CognitiveReobserveCoordinator::new(
            &execution_binding,
            receipt.clone(),
            execution.clone(),
            source.clone(),
            reobservation_request.clone(),
            now_unix_ms,
        )?;
        let mut coordinator = Self {
            goal,
            policy_ready,
            receipt,
            execution,
            source,
            guard,
            reobserver,
            fresh: None,
            delta: None,
            spec: None,
            verification_request: None,
            verification_result: None,
            terminal: None,
            stage: VerificationStageV2::Begun,
            audit,
            consumption,
        };
        append_verification_audit(
            &mut coordinator.audit,
            WindowsDeploymentAuditEventKind::ReobservationRequested,
            WindowsDeploymentAuditStatus::Succeeded,
            &reobservation_request.reobservation_id,
            BTreeMap::from([
                (
                    "reobservation_request".to_owned(),
                    reobservation_request.request_sha256,
                ),
                (
                    "receipt".to_owned(),
                    coordinator.receipt.receipt_sha256.clone(),
                ),
            ]),
            now_unix_ms,
        )?;
        Ok(coordinator)
    }

    /// Performs the one fresh read-only observation.
    pub fn reobserve(
        &mut self,
        observer: TrustedReadOnlyObservationConfiguration,
        observed_at_unix_ms: u64,
    ) -> Result<&FreshObservationProofV1, DesktopError> {
        self.require_stage(VerificationStageV2::Begun)?;
        let bundle = self.reobserver.reobserve(
            observer,
            &self.goal,
            observed_at_unix_ms,
            &mut self.audit,
        )?;
        self.fresh = Some(bundle);
        self.stage = VerificationStageV2::Reobserved;
        Ok(&self.fresh.as_ref().ok_or_else(missing_state)?.proof)
    }

    /// Computes expected, protected, unexpected, and ignored changes.
    pub fn analyze_delta(&mut self, now_unix_ms: u64) -> Result<&ObservationDeltaV1, DesktopError> {
        self.require_stage(VerificationStageV2::Reobserved)?;
        let fresh = &self.fresh.as_ref().ok_or_else(missing_state)?.observation;
        let delta = analyze_observation_delta(&self.source, fresh, &self.guard)?;
        append_verification_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::ObservationDeltaComputed,
            WindowsDeploymentAuditStatus::Succeeded,
            &self.receipt.execution_id,
            BTreeMap::from([
                ("delta".to_owned(), delta.delta_sha256.clone()),
                ("guard".to_owned(), self.guard.profile_sha256.clone()),
            ]),
            now_unix_ms,
        )?;
        self.delta = Some(delta);
        self.stage = VerificationStageV2::DeltaAnalyzed;
        self.delta.as_ref().ok_or_else(missing_state)
    }

    /// Builds the existing VerificationRequestV2 without changing its contract.
    pub fn build_verification_request(&mut self) -> Result<&VerificationRequestV2, DesktopError> {
        self.require_stage(VerificationStageV2::DeltaAnalyzed)?;
        let fresh = &self.fresh.as_ref().ok_or_else(missing_state)?.observation;
        let spec = VerificationSpecAdapterV1::adapt(
            &self.goal,
            &self.policy_ready,
            &self.policy_ready.proposal,
            &self.source,
            &self.receipt,
            &self.execution,
        )?;
        let request = VerificationRequestV2 {
            schema_version: 2,
            verification_id: deterministic_id(
                "verification",
                &[
                    &self.receipt.receipt_sha256,
                    &fresh.state_hash,
                    &self.guard.profile_sha256,
                ],
            )?,
            goal: spec.goal.clone(),
            proposal: spec.proposal.clone(),
            execution: self.execution.clone(),
            source_observation: self.source.clone(),
            fresh_observation: fresh.clone(),
        };
        request.validate()?;
        self.spec = Some(spec);
        self.verification_request = Some(request);
        self.stage = VerificationStageV2::RequestBuilt;
        self.verification_request.as_ref().ok_or_else(missing_state)
    }

    /// Runs the deterministic side-effect-free verifier.
    pub fn verify(&mut self, now_unix_ms: u64) -> Result<&VerificationResultV2, DesktopError> {
        self.require_stage(VerificationStageV2::RequestBuilt)?;
        let request = self
            .verification_request
            .as_ref()
            .ok_or_else(missing_state)?;
        append_verification_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::VerificationStarted,
            WindowsDeploymentAuditStatus::Succeeded,
            &request.verification_id,
            BTreeMap::from([("verification_request".to_owned(), request.canonical_hash()?)]),
            now_unix_ms,
        )?;
        let context_hash = canonical_hash(&(
            &self.guard.profile_sha256,
            &self.delta.as_ref().ok_or_else(missing_state)?.delta_sha256,
        ))?;
        let mut verifier = DeterministicPostconditionVerifierV2::new(
            self.spec
                .as_ref()
                .ok_or_else(missing_state)?
                .binding
                .clone(),
            self.guard.clone(),
            self.delta.as_ref().ok_or_else(missing_state)?.clone(),
            self.fresh.as_ref().ok_or_else(missing_state)?.proof.clone(),
            Provenance {
                source: "deterministic protected-invariant verifier v2".to_owned(),
                source_hash: context_hash,
                module_id: "d2i-cognitive-reobserve-verifier-v2".to_owned(),
            },
        )?;
        let result = verifier.verify(request)?;
        result.validate_against(request)?;
        self.verification_result = Some(result);
        self.stage = VerificationStageV2::Verified;
        self.verification_result.as_ref().ok_or_else(missing_state)
    }

    /// Seals the terminal audit-safe artifact and permanently consumes receipt replay.
    pub fn finalize(
        &mut self,
        verified_at_unix_ms: u64,
    ) -> Result<VerifiedActionResultV1, DesktopError> {
        self.require_stage(VerificationStageV2::Verified)?;
        let spec = self.spec.as_ref().ok_or_else(missing_state)?;
        let fresh = self.fresh.as_ref().ok_or_else(missing_state)?;
        let delta = self.delta.as_ref().ok_or_else(missing_state)?;
        let request = self
            .verification_request
            .as_ref()
            .ok_or_else(missing_state)?;
        let result = self
            .verification_result
            .as_ref()
            .ok_or_else(missing_state)?;
        let terminal = VerifiedActionResultV1::build(
            &self.receipt,
            &self.execution,
            &self.reobserver.request,
            &fresh.proof,
            request,
            result,
            &spec.binding,
            &self.guard,
            delta,
            verified_at_unix_ms,
        )?;
        let (kind, status) = terminal_audit_kind(result.action_verdict);
        append_verification_audit(
            &mut self.audit,
            kind,
            status,
            &terminal.verified_action_id,
            BTreeMap::from([
                ("delta".to_owned(), delta.delta_sha256.clone()),
                ("fresh_proof".to_owned(), fresh.proof.proof_sha256.clone()),
                ("guard".to_owned(), self.guard.profile_sha256.clone()),
                ("receipt".to_owned(), self.receipt.receipt_sha256.clone()),
                ("verified_result".to_owned(), terminal.result_sha256.clone()),
                (
                    "verification_request".to_owned(),
                    terminal.verification_request_sha256.clone(),
                ),
                (
                    "verification_result".to_owned(),
                    terminal.verification_result_sha256.clone(),
                ),
            ]),
            verified_at_unix_ms,
        )?;
        self.consumption.finish(&self.receipt.receipt_sha256)?;
        self.terminal = Some(terminal.clone());
        self.stage = VerificationStageV2::Terminal;
        Ok(terminal)
    }

    /// Returns the terminated fresh observation worker PID for residue checks.
    #[must_use]
    pub fn observation_worker_process_id(&self) -> Option<u32> {
        self.fresh
            .as_ref()
            .map(FreshObservationBundleV1::worker_process_id)
    }

    /// Returns the independently collected snapshot after re-observation.
    #[must_use]
    pub fn fresh_observation(&self) -> Option<&ObservationSnapshot> {
        self.fresh.as_ref().map(|bundle| &bundle.observation)
    }

    /// Returns the terminal artifact after successful finalization.
    #[must_use]
    pub fn terminal_result(&self) -> Option<&VerifiedActionResultV1> {
        self.terminal.as_ref()
    }

    fn require_stage(&self, expected: VerificationStageV2) -> Result<(), DesktopError> {
        if self.stage != expected {
            return Err(DesktopError::Replay(
                "cognitive verification phase is missing, repeated, or terminal".to_owned(),
            ));
        }
        Ok(())
    }
}

impl Drop for CognitiveVerificationCoordinatorV2<'_> {
    fn drop(&mut self) {
        if self.stage != VerificationStageV2::Terminal {
            self.stage = VerificationStageV2::Poisoned;
            let _ = append_verification_audit(
                &mut self.audit,
                WindowsDeploymentAuditEventKind::VerificationAborted,
                WindowsDeploymentAuditStatus::Failed,
                &self.receipt.execution_id,
                BTreeMap::from([("receipt".to_owned(), self.receipt.receipt_sha256.clone())]),
                self.receipt.completed_at_unix_ms.max(1),
            );
        }
    }
}

/// Strictly parses a KRN-300 artifact with duplicate-key and resource bounds.
pub fn parse_reobserve_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DesktopError> {
    d2i_trusted_action_execution::parse_json_strict(bytes).map_err(contract_error)
}

fn convert_postconditions(
    prefix: &str,
    conditions: &[Postcondition],
    source: &ObservationSnapshot,
) -> Result<Vec<VerifiablePostconditionV2>, DesktopError> {
    validate_token(prefix, "verification criterion prefix")?;
    if conditions.len() > MAX_ITEMS {
        return Err(DesktopError::Invalid(
            "verification criterion count exceeds its bound".to_owned(),
        ));
    }
    let elements = element_map(source)?;
    let mut fingerprints = BTreeSet::new();
    let mut converted = Vec::with_capacity(conditions.len());
    for (index, condition) in conditions.iter().enumerate() {
        reject_secret_value(&condition.expected_value)?;
        let target = parse_target_state(&condition.target_state)?;
        if !elements.contains_key(&target.element_id) {
            return Err(DesktopError::Precondition(
                "verification criterion target is absent from the source observation".to_owned(),
            ));
        }
        let fingerprint = canonical_hash(condition)?;
        if !fingerprints.insert(fingerprint.clone()) {
            return Err(DesktopError::Invalid(
                "verification criteria contain a duplicate definition".to_owned(),
            ));
        }
        let criterion = VerifiablePostconditionV2 {
            criterion_id: format!("{prefix}-criterion-{index:03}-{}", &fingerprint[7..19]),
            target,
            op: condition.op,
            expected_value: condition.expected_value.clone(),
            required: condition.required,
        };
        criterion.validate()?;
        converted.push(criterion);
    }
    Ok(converted)
}

fn parse_target_state(value: &str) -> Result<VerificationTargetV2, DesktopError> {
    let rest = value.strip_prefix("element:").ok_or_else(|| {
        DesktopError::AdapterUnavailable(
            "postcondition target_state grammar is unsupported by verifier v2".to_owned(),
        )
    })?;
    let (element_id, field) = rest.rsplit_once(':').ok_or_else(|| {
        DesktopError::AdapterUnavailable(
            "postcondition target_state grammar is unsupported by verifier v2".to_owned(),
        )
    })?;
    if element_id.is_empty() || value != format!("element:{element_id}:{field}") {
        return Err(DesktopError::AdapterUnavailable(
            "postcondition target_state grammar is not exact".to_owned(),
        ));
    }
    validate_token(element_id, "postcondition target element_id")?;
    let field = match field {
        "exists" => VerifiableObservationFieldV2::ElementExists,
        "value" => VerifiableObservationFieldV2::ElementValue,
        "kind" => VerifiableObservationFieldV2::ElementKind,
        _ => {
            return Err(DesktopError::AdapterUnavailable(
                "postcondition target field is unsupported by verifier v2".to_owned(),
            ));
        }
    };
    Ok(VerificationTargetV2 {
        element_id: element_id.to_owned(),
        field,
    })
}

fn evaluate_postcondition(
    criterion: &VerifiablePostconditionV2,
    observation: &ObservationSnapshot,
) -> Result<PostconditionResultV2, DesktopError> {
    criterion.validate()?;
    let matches = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == criterion.target.element_id)
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Ok(postcondition_result(
            criterion,
            VerificationVerdictV2::Inconclusive,
            None,
            "duplicate-element-evidence",
        ));
    }
    let observed = match criterion.target.field {
        VerifiableObservationFieldV2::ElementExists => Some(Value::Bool(!matches.is_empty())),
        VerifiableObservationFieldV2::ElementValue => {
            matches.first().map(|element| element.value.clone())
        }
        VerifiableObservationFieldV2::ElementKind => matches
            .first()
            .map(|element| Value::String(element.kind.clone())),
    };
    let verdict = match criterion.op {
        ComparisonOp::Equals => observed
            .as_ref()
            .map_or(Ok(VerificationVerdictV2::Inconclusive), |actual| {
                sealed_value_equals(actual, &criterion.expected_value).map(bool_verdict)
            })?,
        ComparisonOp::NotEquals => observed
            .as_ref()
            .map_or(VerificationVerdictV2::Inconclusive, |actual| {
                bool_verdict(actual != &criterion.expected_value)
            }),
        ComparisonOp::Contains => match (
            observed.as_ref().and_then(Value::as_str),
            criterion.expected_value.as_str(),
        ) {
            (Some(actual), Some(expected)) => bool_verdict(actual.contains(expected)),
            (None, _) if observed.is_none() => VerificationVerdictV2::Inconclusive,
            _ => VerificationVerdictV2::Unsupported,
        },
        ComparisonOp::Exists => criterion.expected_value.as_bool().map_or(
            VerificationVerdictV2::Unsupported,
            |expected| {
                bool_verdict(observed.as_ref().is_some_and(|value| !value.is_null()) == expected)
            },
        ),
        ComparisonOp::GreaterOrEqual | ComparisonOp::LessOrEqual => {
            match (
                observed.as_ref().and_then(json_integer),
                json_integer(&criterion.expected_value),
            ) {
                (Some(actual), Some(expected)) => bool_verdict(match criterion.op {
                    ComparisonOp::GreaterOrEqual => actual >= expected,
                    ComparisonOp::LessOrEqual => actual <= expected,
                    _ => false,
                }),
                (None, _) if observed.is_none() => VerificationVerdictV2::Inconclusive,
                _ => VerificationVerdictV2::Unsupported,
            }
        }
    };
    Ok(postcondition_result(
        criterion,
        verdict,
        observed,
        match verdict {
            VerificationVerdictV2::Passed => "criterion-passed",
            VerificationVerdictV2::Failed => "criterion-failed",
            VerificationVerdictV2::Inconclusive => "criterion-evidence-inconclusive",
            VerificationVerdictV2::Unsupported => "criterion-type-unsupported",
            VerificationVerdictV2::Unsafe => "criterion-unsafe",
        },
    ))
}

fn postcondition_result(
    criterion: &VerifiablePostconditionV2,
    verdict: VerificationVerdictV2,
    observed_value: Option<Value>,
    reason: &str,
) -> PostconditionResultV2 {
    PostconditionResultV2 {
        criterion_id: criterion.criterion_id.clone(),
        target: criterion.target.clone(),
        verdict,
        required: criterion.required,
        observed_value,
        reason: reason.to_owned(),
        evidence: vec![format!("criterion:{}", criterion.criterion_id)],
    }
}

fn effective_action_verdict(
    status: ExecutionStatus,
    results: &[PostconditionResultV2],
    unexpected_changes: &[String],
) -> VerificationVerdictV2 {
    if unexpected_changes
        .iter()
        .any(|value| !value.starts_with("fail:"))
    {
        return VerificationVerdictV2::Unsafe;
    }
    if status == ExecutionStatus::Unsupported {
        return VerificationVerdictV2::Unsupported;
    }
    if status == ExecutionStatus::Timeout {
        return VerificationVerdictV2::Inconclusive;
    }
    if status != ExecutionStatus::Succeeded || !unexpected_changes.is_empty() {
        return VerificationVerdictV2::Failed;
    }
    for verdict in [
        VerificationVerdictV2::Unsafe,
        VerificationVerdictV2::Unsupported,
        VerificationVerdictV2::Inconclusive,
        VerificationVerdictV2::Failed,
    ] {
        if results
            .iter()
            .any(|result| result.required && result.verdict == verdict)
        {
            return verdict;
        }
    }
    VerificationVerdictV2::Passed
}

fn effective_goal_progress(
    action_verdict: VerificationVerdictV2,
    results: &[PostconditionResultV2],
) -> GoalProgress {
    if action_verdict != VerificationVerdictV2::Passed {
        return GoalProgress::Blocked;
    }
    if results
        .iter()
        .all(|result| !result.required || result.verdict == VerificationVerdictV2::Passed)
    {
        GoalProgress::Complete
    } else if results.iter().any(|result| {
        result.required
            && matches!(
                result.verdict,
                VerificationVerdictV2::Inconclusive
                    | VerificationVerdictV2::Unsupported
                    | VerificationVerdictV2::Unsafe
            )
    }) {
        GoalProgress::Blocked
    } else {
        GoalProgress::InProgress
    }
}

fn verdict_reason(verdict: VerificationVerdictV2) -> &'static str {
    match verdict {
        VerificationVerdictV2::Passed => "required-postconditions-and-guards-passed",
        VerificationVerdictV2::Failed => "required-postcondition-or-expected-delta-failed",
        VerificationVerdictV2::Inconclusive => "fresh-observation-evidence-inconclusive",
        VerificationVerdictV2::Unsupported => "verification-criterion-unsupported",
        VerificationVerdictV2::Unsafe => "protected-or-unexpected-change-unsafe",
    }
}

fn observed_target_value(
    observation: &ObservationSnapshot,
    target: &VerificationGuardTargetV1,
) -> Result<Value, DesktopError> {
    let matches = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == target.element_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DesktopError::Precondition(
            "guard target must resolve to exactly one source element".to_owned(),
        ));
    }
    Ok(match target.field {
        VerificationGuardFieldV1::Exists => Value::Bool(true),
        VerificationGuardFieldV1::Value => matches[0].value.clone(),
        VerificationGuardFieldV1::Kind => Value::String(matches[0].kind.clone()),
    })
}

fn element_map(
    observation: &ObservationSnapshot,
) -> Result<BTreeMap<String, &ObservableElement>, DesktopError> {
    let mut elements = BTreeMap::new();
    for element in &observation.observable_elements {
        if elements
            .insert(element.element_id.clone(), element)
            .is_some()
        {
            return Err(DesktopError::Integrity(
                "observation contains duplicate element IDs".to_owned(),
            ));
        }
    }
    Ok(elements)
}

fn delta_change(
    target: Option<VerificationGuardTargetV1>,
    kind: ObservationDeltaKindV1,
    before: Option<&Value>,
    after: Option<&Value>,
    reason_code: &str,
) -> Result<ObservationElementDeltaV1, DesktopError> {
    let before_sha256 = before.map(canonical_hash).transpose()?;
    let after_sha256 = after.map(canonical_hash).transpose()?;
    let before_type = before.map(value_type).map(str::to_owned);
    let after_type = after.map(value_type).map(str::to_owned);
    let delta_id = deterministic_id(
        "delta",
        &[
            &canonical_hash(&target)?,
            &canonical_hash(&kind)?,
            before_sha256.as_deref().unwrap_or("none"),
            after_sha256.as_deref().unwrap_or("none"),
            reason_code,
        ],
    )?;
    let value = ObservationElementDeltaV1 {
        delta_id,
        target,
        kind,
        before_sha256,
        after_sha256,
        before_type,
        after_type,
        reason_code: reason_code.to_owned(),
    };
    value.validate()?;
    Ok(value)
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn change_matches_guard_field(
    change: &ObservationElementDeltaV1,
    target: &VerificationGuardTargetV1,
) -> bool {
    matches!(
        (&target.field, &change.kind),
        (
            VerificationGuardFieldV1::Exists,
            ObservationDeltaKindV1::ElementAdded | ObservationDeltaKindV1::ElementRemoved
        ) | (
            VerificationGuardFieldV1::Value,
            ObservationDeltaKindV1::ValueChanged
        ) | (
            VerificationGuardFieldV1::Kind,
            ObservationDeltaKindV1::KindChanged
        )
    )
}

fn identity_binding_hashes(
    observation: &ObservationSnapshot,
) -> Result<(String, String), DesktopError> {
    let binding = &observation.target_binding;
    let required = |key: &str| {
        binding.get(key).cloned().ok_or_else(|| {
            DesktopError::Integrity(format!(
                "observation target binding omits required key {key}"
            ))
        })
    };
    match observation.source_kind {
        ObservationSourceKind::Uia => Ok((
            canonical_hash(&BTreeMap::from([
                ("executable_hash", required("executable_hash")?),
                ("process_id", required("process_id")?),
                ("session_id", required("session_id")?),
            ]))?,
            canonical_hash(&BTreeMap::from([(
                "window_title_hash",
                required("window_title_hash")?,
            )]))?,
        )),
        ObservationSourceKind::WebDriver => Ok((
            canonical_hash(&BTreeMap::from([
                ("browser_session_id", required("browser_session_id")?),
                ("edge_executable_hash", required("edge_executable_hash")?),
                (
                    "edge_driver_executable_hash",
                    required("edge_driver_executable_hash")?,
                ),
            ]))?,
            canonical_hash(&BTreeMap::from([
                ("expected_origin", required("expected_origin")?),
                ("wfp_policy_hash", required("wfp_policy_hash")?),
                ("wfp_attestation_hash", required("wfp_attestation_hash")?),
            ]))?,
        )),
        _ => Err(DesktopError::AccessDenied(
            "fresh proof supports only UIA or WebDriver observation".to_owned(),
        )),
    }
}

fn validate_logical_target_binding(
    source: &BTreeMap<String, String>,
    fresh_transport: &BTreeMap<String, String>,
) -> Result<(), DesktopError> {
    let mut source = source.clone();
    let mut fresh = fresh_transport.clone();
    for key in ACTIVATION_BINDING_KEYS {
        if source.remove(key).is_none() || fresh.remove(key).is_none() {
            return Err(DesktopError::Integrity(
                "observation activation binding is incomplete".to_owned(),
            ));
        }
    }
    if source != fresh {
        return Err(DesktopError::Integrity(
            "fresh observation process, session, origin, or runtime identity changed".to_owned(),
        ));
    }
    Ok(())
}

fn reobservation_policy(status: TrustedExecutionStatusV1) -> ReobservationPolicyV1 {
    match status {
        TrustedExecutionStatusV1::Succeeded
        | TrustedExecutionStatusV1::Failed
        | TrustedExecutionStatusV1::Aborted => ReobservationPolicyV1::Required,
        TrustedExecutionStatusV1::Cancelled => ReobservationPolicyV1::OptionalConfirmation,
        TrustedExecutionStatusV1::DeniedBeforeCommit => ReobservationPolicyV1::NoExecution,
    }
}

impl ReobservationRequestV1 {
    fn validate_lifetime(&self, now_unix_ms: u64) -> Result<(), DesktopError> {
        if now_unix_ms < self.requested_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(DesktopError::Replay(
                "reobservation request expired before collection".to_owned(),
            ));
        }
        Ok(())
    }
}

fn terminal_audit_kind(
    verdict: VerificationVerdictV2,
) -> (
    WindowsDeploymentAuditEventKind,
    WindowsDeploymentAuditStatus,
) {
    match verdict {
        VerificationVerdictV2::Passed => (
            WindowsDeploymentAuditEventKind::VerificationPassed,
            WindowsDeploymentAuditStatus::Succeeded,
        ),
        VerificationVerdictV2::Failed => (
            WindowsDeploymentAuditEventKind::VerificationFailed,
            WindowsDeploymentAuditStatus::Failed,
        ),
        VerificationVerdictV2::Inconclusive => (
            WindowsDeploymentAuditEventKind::VerificationInconclusive,
            WindowsDeploymentAuditStatus::Blocked,
        ),
        VerificationVerdictV2::Unsupported => (
            WindowsDeploymentAuditEventKind::VerificationUnsupported,
            WindowsDeploymentAuditStatus::Blocked,
        ),
        VerificationVerdictV2::Unsafe => (
            WindowsDeploymentAuditEventKind::VerificationUnsafe,
            WindowsDeploymentAuditStatus::Blocked,
        ),
    }
}

fn append_verification_audit(
    audit: &mut WindowsDeploymentAuditLedger,
    kind: WindowsDeploymentAuditEventKind,
    status: WindowsDeploymentAuditStatus,
    subject_id: &str,
    artifact_hashes: BTreeMap<String, String>,
    recorded_at_unix_ms: u64,
) -> Result<(), DesktopError> {
    validate_token(subject_id, "verification audit subject")?;
    let detail_hash = canonical_hash(&(kind, status, subject_id, &artifact_hashes))?;
    audit.append(WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id: deterministic_id(
            "verification-event",
            &[subject_id, &format!("{kind:?}"), &detail_hash],
        )?,
        kind,
        status,
        artifact_hashes,
        detail_hash,
        recorded_at_unix_ms,
    })?;
    Ok(())
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, DesktopError> {
    d2i_trusted_action_execution::canonical_sha256(value).map_err(contract_error)
}

fn canonical_hash_without<T: Serialize>(value: &T, field: &str) -> Result<String, DesktopError> {
    let mut value = serde_json::to_value(value).map_err(json_error)?;
    let object = value.as_object_mut().ok_or_else(|| {
        DesktopError::Json("canonical self-hash payload is not an object".to_owned())
    })?;
    if object.remove(field).is_none() {
        return Err(DesktopError::Json(format!(
            "canonical self-hash field {field} is absent"
        )));
    }
    canonical_hash(&value)
}

fn deterministic_id(prefix: &str, values: &[&str]) -> Result<String, DesktopError> {
    validate_token(prefix, "deterministic ID prefix")?;
    let digest = canonical_hash(&values)?;
    Ok(format!("{prefix}-{}", &digest[7..23]))
}

fn empty_hash() -> String {
    sha256_bytes(&[])
}

fn validate_schema(version: u32, label: &str) -> Result<(), DesktopError> {
    if version != COGNITIVE_REOBSERVE_SCHEMA_VERSION {
        return Err(DesktopError::Invalid(format!(
            "{label} schema_version must be {COGNITIVE_REOBSERVE_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

fn canonicalize_set(values: &mut Vec<String>) -> Result<(), DesktopError> {
    if values.len() > MAX_ITEMS {
        return Err(DesktopError::Invalid(
            "set-like collection exceeds its bound".to_owned(),
        ));
    }
    values.sort();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DesktopError::Invalid(
            "set-like collection contains duplicates".to_owned(),
        ));
    }
    for value in values {
        validate_token(value, "set-like identifier")?;
    }
    Ok(())
}

fn validate_sorted_tokens(
    values: &[String],
    label: &str,
    allow_empty: bool,
) -> Result<(), DesktopError> {
    if (!allow_empty && values.is_empty())
        || values.len() > MAX_ITEMS
        || !values.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(DesktopError::Invalid(format!(
            "{label} is empty, duplicated, unsorted, or oversized"
        )));
    }
    for value in values {
        validate_token(value, label)?;
    }
    Ok(())
}

fn validate_sorted_unique_targets(
    values: &[VerificationGuardTargetV1],
    label: &str,
) -> Result<(), DesktopError> {
    if values.len() > MAX_ITEMS || !is_sorted_unique(values) {
        return Err(DesktopError::Invalid(format!(
            "{label} is duplicated, unsorted, or oversized"
        )));
    }
    for value in values {
        value.validate()?;
    }
    Ok(())
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn reject_secret_value(value: &Value) -> Result<(), DesktopError> {
    fn walk(value: &Value) -> bool {
        match value {
            Value::String(value) => contains_secret_marker(value),
            Value::Array(values) => values.iter().any(walk),
            Value::Object(values) => values
                .iter()
                .any(|(key, value)| contains_secret_marker(key) || walk(value)),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    if walk(value) {
        return Err(DesktopError::AccessDenied(
            "verification expected_value contains credential-like material".to_owned(),
        ));
    }
    Ok(())
}

fn reject_forbidden_artifact<T: Serialize>(value: &T, label: &str) -> Result<(), DesktopError> {
    let value = serde_json::to_value(value).map_err(json_error)?;
    fn walk(value: &Value) -> bool {
        match value {
            Value::String(value) => {
                contains_secret_marker(value)
                    || value.contains(":\\")
                    || value.starts_with('/')
                    || value.starts_with("file:")
            }
            Value::Array(values) => values.iter().any(walk),
            Value::Object(values) => values.iter().any(|(key, value)| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "raw_locator" | "raw_payload" | "credential" | "secret_ref"
                ) || walk(value)
            }),
            Value::Null | Value::Bool(_) | Value::Number(_) => false,
        }
    }
    if walk(&value) {
        return Err(DesktopError::AccessDenied(format!(
            "{label} contains forbidden secret, path, locator, or payload material"
        )));
    }
    Ok(())
}

fn contains_secret_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "password",
        "credential",
        "secret",
        "bearer ",
        "api_key",
        "api-key",
        "access_token",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn json_integer(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn sealed_value_equals(actual: &Value, expected: &Value) -> Result<bool, DesktopError> {
    if matches!(actual, Value::Object(_) | Value::Array(_)) {
        if let Some(expected_hash) = expected
            .as_str()
            .filter(|value| value.starts_with("sha256:"))
        {
            validate_hash(expected_hash, "sealed expected observation value")?;
            return Ok(canonical_hash(actual)? == expected_hash);
        }
    }
    Ok(actual == expected)
}

fn bool_verdict(value: bool) -> VerificationVerdictV2 {
    if value {
        VerificationVerdictV2::Passed
    } else {
        VerificationVerdictV2::Failed
    }
}

fn missing_state() -> DesktopError {
    DesktopError::Integrity("cognitive verification state is incomplete".to_owned())
}

fn contract_error(error: d2i_trusted_action_execution::TrustedExecutionError) -> DesktopError {
    DesktopError::Integrity(error.to_string())
}

fn json_error(error: serde_json::Error) -> DesktopError {
    DesktopError::Json(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CognitiveRiskClass, ConfirmationPolicy, Reversibility, TrustLabel};
    use serde_json::json;

    fn digest(label: &str) -> String {
        canonical_hash(&label).unwrap_or_else(|error| panic!("hash failed: {error}"))
    }

    fn provenance() -> Provenance {
        Provenance {
            source: "bounded verifier fixture".to_owned(),
            source_hash: digest("fixture-source"),
            module_id: "reobserve-verifier-test".to_owned(),
        }
    }

    fn postcondition(target: &str, expected_value: Value, required: bool) -> Postcondition {
        Postcondition {
            target_state: target.to_owned(),
            op: ComparisonOp::Equals,
            expected_value,
            required,
            timeout_ms: 1_000,
        }
    }

    fn observation(action: bool, protected: bool, sequence: u64) -> ObservationSnapshot {
        let labels = BTreeSet::from([TrustLabel::Fixture, TrustLabel::ObservedUiState]);
        let mut snapshot = ObservationSnapshot {
            schema_version: 1,
            observation_id: format!("observation-{sequence}"),
            source_kind: ObservationSourceKind::Fixture,
            target_binding: BTreeMap::from([("fixture".to_owned(), "reobserve-v2".to_owned())]),
            state_hash: empty_hash(),
            sequence,
            trust_labels: labels.clone(),
            observable_elements: vec![
                ObservableElement {
                    element_id: "action-state".to_owned(),
                    kind: "boolean".to_owned(),
                    label: "action state".to_owned(),
                    value: Value::Bool(action),
                    trust_labels: labels.clone(),
                },
                ObservableElement {
                    element_id: "protected-state".to_owned(),
                    kind: "boolean".to_owned(),
                    label: "protected state".to_owned(),
                    value: Value::Bool(protected),
                    trust_labels: labels,
                },
            ],
            redactions: Vec::new(),
            provenance: provenance(),
        };
        snapshot.state_hash = snapshot
            .compute_state_hash()
            .unwrap_or_else(|error| panic!("snapshot hash failed: {error}"));
        snapshot
    }

    fn proposal(source: &ObservationSnapshot) -> ActionProposal {
        ActionProposal {
            schema_version: 1,
            proposal_id: "proposal-reobserve-v2".to_owned(),
            goal_id: "goal-reobserve-v2".to_owned(),
            plan_generation_id: "plan-reobserve-v2".to_owned(),
            source_observation_hash: source.state_hash.clone(),
            capability_id: "fixture.set-state".to_owned(),
            semantic_target: "action-state".to_owned(),
            arguments: json!({"value": true}),
            preconditions: Vec::new(),
            expected_postconditions: vec![postcondition(
                "element:action-state:value",
                Value::Bool(true),
                true,
            )],
            risk: CognitiveRiskClass::Reversible,
            reversibility: Reversibility::Reversible,
            confirmation_requirement: crate::ConfirmationRequirement::None,
            confidence: 1.0,
            evidence: vec!["fixture:proposal".to_owned()],
            valid_until_sequence: source.sequence,
        }
    }

    fn guard(source: &ObservationSnapshot) -> VerificationGuardProfileV1 {
        VerificationGuardProfileV1::new(
            "guard-reobserve-v2".to_owned(),
            &proposal(source),
            source,
            vec![VerificationGuardTargetV1 {
                element_id: "action-state".to_owned(),
                field: VerificationGuardFieldV1::Value,
            }],
            Vec::new(),
            vec![ProtectedInvariantV1 {
                target: VerificationGuardTargetV1 {
                    element_id: "protected-state".to_owned(),
                    field: VerificationGuardFieldV1::Value,
                },
                expected_source_value_hash: canonical_hash(&Value::Bool(false))
                    .unwrap_or_else(|error| panic!("protected hash failed: {error}")),
                severity: ProtectedInvariantSeverityV1::Unsafe,
                reason_code: "protected-state-stable".to_owned(),
            }],
            Vec::new(),
            0,
            vec!["fixture:guard".to_owned()],
        )
        .unwrap_or_else(|error| panic!("guard failed: {error}"))
    }

    fn result(verdict: VerificationVerdictV2, required: bool) -> PostconditionResultV2 {
        PostconditionResultV2 {
            criterion_id: "criterion-fixture".to_owned(),
            target: VerificationTargetV2 {
                element_id: "action-state".to_owned(),
                field: VerifiableObservationFieldV2::ElementValue,
            },
            verdict,
            required,
            observed_value: Some(Value::Bool(verdict == VerificationVerdictV2::Passed)),
            reason: "bounded comparison".to_owned(),
            evidence: vec!["fixture:evidence".to_owned()],
        }
    }

    #[test]
    fn closed_target_grammar_rejects_fuzzy_unknown_and_secret_values() {
        let source = observation(false, false, 7);
        let valid = postcondition("element:action-state:value", Value::Bool(true), true);
        let converted = convert_postconditions("action", &[valid], &source)
            .unwrap_or_else(|error| panic!("conversion failed: {error}"));
        assert_eq!(converted.len(), 1);
        assert_eq!(converted[0].target.element_id, "action-state");

        for invalid in [
            postcondition("action-state", Value::Bool(true), true),
            postcondition("element:action-state:label", Value::Bool(true), true),
            postcondition("element:missing:value", Value::Bool(true), true),
            postcondition(
                "element:action-state:value",
                json!({"access_token": "fixture-secret"}),
                true,
            ),
        ] {
            assert!(convert_postconditions("action", &[invalid], &source).is_err());
        }
    }

    #[test]
    fn delta_is_canonical_and_separates_expected_missing_and_unsafe_changes() {
        let source = observation(false, false, 7);
        let profile = guard(&source);
        let fresh = observation(true, false, 8);
        let delta = analyze_observation_delta(&source, &fresh, &profile)
            .unwrap_or_else(|error| panic!("delta failed: {error}"));
        assert_eq!(delta.expected_changes.len(), 1);
        assert!(delta.missing_expected_changes.is_empty());
        assert!(delta.protected_invariant_violations.is_empty());
        assert_eq!(
            delta.delta_sha256,
            analyze_observation_delta(&source, &fresh, &profile)
                .unwrap_or_else(|error| panic!("repeat delta failed: {error}"))
                .delta_sha256
        );
        let serialized = serde_json::to_string(&delta)
            .unwrap_or_else(|error| panic!("delta serialization failed: {error}"));
        assert!(!serialized.contains("before_value"));
        assert!(!serialized.contains("after_value"));

        let unchanged = observation(false, false, 8);
        let missing = analyze_observation_delta(&source, &unchanged, &profile)
            .unwrap_or_else(|error| panic!("missing delta failed: {error}"));
        assert_eq!(missing.missing_expected_changes.len(), 1);

        let unsafe_fresh = observation(true, true, 8);
        let unsafe_delta = analyze_observation_delta(&source, &unsafe_fresh, &profile)
            .unwrap_or_else(|error| panic!("unsafe delta failed: {error}"));
        assert_eq!(unsafe_delta.protected_invariant_violations.len(), 1);
        assert_eq!(unsafe_delta.security_relevant_changes.len(), 1);
    }

    #[test]
    fn verdict_matrix_keeps_verification_separate_from_execution_status() {
        assert_eq!(
            effective_action_verdict(
                ExecutionStatus::Succeeded,
                &[result(VerificationVerdictV2::Passed, true)],
                &[],
            ),
            VerificationVerdictV2::Passed
        );
        assert_eq!(
            effective_action_verdict(
                ExecutionStatus::Succeeded,
                &[result(VerificationVerdictV2::Failed, true)],
                &[],
            ),
            VerificationVerdictV2::Failed
        );
        assert_eq!(
            effective_action_verdict(
                ExecutionStatus::Failed,
                &[result(VerificationVerdictV2::Failed, true)],
                &["unsafe:protected".to_owned()],
            ),
            VerificationVerdictV2::Unsafe
        );
        assert_eq!(
            effective_action_verdict(
                ExecutionStatus::Timeout,
                &[result(VerificationVerdictV2::Inconclusive, true)],
                &[],
            ),
            VerificationVerdictV2::Inconclusive
        );
        assert_eq!(
            effective_action_verdict(
                ExecutionStatus::Succeeded,
                &[result(VerificationVerdictV2::Failed, false)],
                &[],
            ),
            VerificationVerdictV2::Passed
        );
        assert_eq!(
            effective_goal_progress(
                VerificationVerdictV2::Passed,
                &[result(VerificationVerdictV2::Passed, true)]
            ),
            GoalProgress::Complete
        );
        let _ = ConfirmationPolicy::Never;
    }

    #[test]
    fn reobservation_status_policy_and_guard_conflicts_are_fail_closed() {
        assert_eq!(
            reobservation_policy(TrustedExecutionStatusV1::Succeeded),
            ReobservationPolicyV1::Required
        );
        assert_eq!(
            reobservation_policy(TrustedExecutionStatusV1::Failed),
            ReobservationPolicyV1::Required
        );
        assert_eq!(
            reobservation_policy(TrustedExecutionStatusV1::Aborted),
            ReobservationPolicyV1::Required
        );
        assert_eq!(
            reobservation_policy(TrustedExecutionStatusV1::Cancelled),
            ReobservationPolicyV1::OptionalConfirmation
        );
        assert_eq!(
            reobservation_policy(TrustedExecutionStatusV1::DeniedBeforeCommit),
            ReobservationPolicyV1::NoExecution
        );

        let source = observation(false, false, 7);
        let action = proposal(&source);
        let target = VerificationGuardTargetV1 {
            element_id: "action-state".to_owned(),
            field: VerificationGuardFieldV1::Value,
        };
        assert!(VerificationGuardProfileV1::new(
            "empty-guard".to_owned(),
            &action,
            &source,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            vec!["fixture:guard".to_owned()],
        )
        .is_err());
        assert!(VerificationGuardProfileV1::new(
            "duplicate-guard".to_owned(),
            &action,
            &source,
            vec![target.clone(), target.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            0,
            vec!["fixture:guard".to_owned()],
        )
        .is_err());
        assert!(VerificationGuardProfileV1::new(
            "overlap-guard".to_owned(),
            &action,
            &source,
            vec![target.clone()],
            Vec::new(),
            vec![ProtectedInvariantV1 {
                target,
                expected_source_value_hash: canonical_hash(&Value::Bool(false))
                    .unwrap_or_else(|error| panic!("protected hash failed: {error}")),
                severity: ProtectedInvariantSeverityV1::Unsafe,
                reason_code: "overlap".to_owned(),
            }],
            Vec::new(),
            0,
            vec!["fixture:guard".to_owned()],
        )
        .is_err());
    }

    #[test]
    fn webdriver_identity_binding_is_exact_and_origin_changes_are_rejected() {
        let mut source = observation(false, false, 7);
        source.source_kind = ObservationSourceKind::WebDriver;
        source.target_binding = BTreeMap::from([
            ("binding_id".to_owned(), "source-activation".to_owned()),
            (
                "activation_record_hash".to_owned(),
                digest("source-activation-record"),
            ),
            (
                "browser_session_id".to_owned(),
                "browser-session-1".to_owned(),
            ),
            ("edge_executable_hash".to_owned(), digest("edge")),
            (
                "edge_driver_executable_hash".to_owned(),
                digest("edge-driver"),
            ),
            (
                "expected_origin".to_owned(),
                "http://127.0.0.1:4317".to_owned(),
            ),
            ("wfp_policy_hash".to_owned(), digest("wfp-policy")),
            ("wfp_attestation_hash".to_owned(), digest("wfp-attestation")),
        ]);
        source.provenance.source_hash = canonical_hash(&source.target_binding)
            .unwrap_or_else(|error| panic!("source binding hash failed: {error}"));
        source.state_hash = source
            .compute_state_hash()
            .unwrap_or_else(|error| panic!("source state hash failed: {error}"));

        let mut fresh_binding = source.target_binding.clone();
        fresh_binding.insert("binding_id".to_owned(), "fresh-activation".to_owned());
        fresh_binding.insert(
            "activation_record_hash".to_owned(),
            digest("fresh-activation-record"),
        );
        validate_logical_target_binding(&source.target_binding, &fresh_binding)
            .unwrap_or_else(|error| panic!("fresh activation should preserve target: {error}"));

        let source_identity = identity_binding_hashes(&source)
            .unwrap_or_else(|error| panic!("WebDriver identity failed: {error}"));
        assert_eq!(
            source_identity,
            identity_binding_hashes(&source)
                .unwrap_or_else(|error| panic!("repeat WebDriver identity failed: {error}"))
        );

        for (key, replacement) in [
            ("browser_session_id", "browser-session-2".to_owned()),
            ("expected_origin", "http://127.0.0.1:4318".to_owned()),
            ("wfp_policy_hash", digest("different-wfp-policy")),
        ] {
            let mut substituted = fresh_binding.clone();
            substituted.insert(key.to_owned(), replacement);
            assert!(
                validate_logical_target_binding(&source.target_binding, &substituted).is_err(),
                "{key} substitution must fail closed"
            );
        }
    }
}
