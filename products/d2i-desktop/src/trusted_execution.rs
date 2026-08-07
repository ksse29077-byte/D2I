use crate::approval::authorize_cognitive_prepared;
use crate::{
    hash_value, sha256_bytes, ActionOutcomeStatus, AdapterExecution, BoundActionExecutionV2,
    BrowserInteraction, DesktopActionIntent, DesktopAdapter, DesktopCapability, DesktopError,
    DesktopOperation, ExecutionStatus, PreparedAction, UiInteraction, WindowIdentity,
    WindowsActivationAdmission, WindowsAdapterConfiguration, WindowsAdapterKind,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditLedger,
    WindowsDeploymentAuditStatus, WindowsUiAutomationAdapter, WindowsUiaObservationTarget,
    WindowsWebDriverAdapter, WindowsWebObservationTarget,
};
use d2i_action_candidates::CandidateActionInput;
use d2i_cognitive_ir::{ObservationSnapshot, ObservationSourceKind};
use d2i_trusted_action_execution::{
    action_input, canonical_sha256, expected_input, operation_kind,
    sha256_bytes as canonical_sha256_bytes, AdapterKindV1, BoundDesktopActionV1,
    InputMaterialProofV1, PreparedBoundActionV1, SecretClassificationV1, TargetResolutionProofV1,
    TrustedActionExecutionReceiptV1, TrustedAdapterOutcomeStatusV1, TrustedDesktopOperationKindV1,
    TrustedExecutionBindingRequestV1, TrustedExecutionStatusV1, TrustedPlatformActivationV1,
    TrustedTargetSourceKindV1, TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};

const MAX_EPHEMERAL_INPUT_BYTES: usize = 8 * 1024 * 1024;

/// Trusted, non-serializable input to one target-resolution attempt.
pub enum TrustedTargetResolverInput {
    Uia {
        target: WindowsUiaObservationTarget,
    },
    WebDriver {
        target: WindowsWebObservationTarget,
        reviewed_css_locator: String,
    },
}

impl Debug for TrustedTargetResolverInput {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uia { target } => formatter
                .debug_struct("TrustedTargetResolverInput::Uia")
                .field("process_id", &target.process_id)
                .field("runtime_binding_digest", &target.runtime_binding_digest)
                .finish_non_exhaustive(),
            Self::WebDriver { target, .. } => formatter
                .debug_struct("TrustedTargetResolverInput::WebDriver")
                .field("browser_session_id", &target.browser_session_id)
                .field("runtime_binding_digest", &target.runtime_binding_digest)
                .field("reviewed_css_locator", &"<redacted>")
                .finish_non_exhaustive(),
        }
    }
}

/// Actual target material retained only inside one execution plan.
pub enum ResolvedTargetMaterial {
    Uia {
        window: WindowIdentity,
        automation_id: String,
    },
    WebDriver {
        browser_session_id: String,
        origin: String,
        locator: String,
    },
}

impl Debug for ResolvedTargetMaterial {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uia { window, .. } => formatter
                .debug_struct("ResolvedTargetMaterial::Uia")
                .field("process_id", &window.process_id)
                .field("automation_id", &"<redacted>")
                .finish(),
            Self::WebDriver {
                browser_session_id,
                origin,
                ..
            } => formatter
                .debug_struct("ResolvedTargetMaterial::WebDriver")
                .field("browser_session_id", browser_session_id)
                .field("origin", origin)
                .field("locator", &"<redacted>")
                .finish(),
        }
    }
}

/// Non-cloneable, non-serializable input bytes with eager zeroization on drop.
pub struct EphemeralActionPayload {
    bytes: Vec<u8>,
    material_source_id: String,
    resolved_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl Debug for EphemeralActionPayload {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralActionPayload")
            .field("byte_length", &self.bytes.len())
            .field("material_source_id", &self.material_source_id)
            .field("content", &"<redacted>")
            .finish()
    }
}

impl EphemeralActionPayload {
    /// Accepts bounded UTF-8 material from a trusted non-secret source.
    pub fn new(
        material_source_id: String,
        bytes: Vec<u8>,
        resolved_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        crate::validate_token(&material_source_id, "input material_source_id")?;
        if bytes.is_empty()
            || bytes.len() > MAX_EPHEMERAL_INPUT_BYTES
            || resolved_at_unix_ms >= expires_at_unix_ms
            || expires_at_unix_ms.saturating_sub(resolved_at_unix_ms) > 60_000
        {
            return Err(DesktopError::Invalid(
                "ephemeral input bounds or lifetime are invalid".to_owned(),
            ));
        }
        let text = std::str::from_utf8(&bytes).map_err(|error| {
            DesktopError::Invalid(format!("ephemeral input is not UTF-8: {error}"))
        })?;
        let lower_source = material_source_id.to_ascii_lowercase();
        let lower_text = text.to_ascii_lowercase();
        if [
            "password",
            "passwd",
            "credential",
            "secret",
            "token",
            "api_key",
            "private_key",
            "bearer ",
        ]
        .iter()
        .any(|needle| lower_source.contains(needle) || lower_text.contains(needle))
        {
            return Err(DesktopError::AccessDenied(
                "credential-like input is unsupported by trusted execution v1".to_owned(),
            ));
        }
        Ok(Self {
            bytes,
            material_source_id,
            resolved_at_unix_ms,
            expires_at_unix_ms,
        })
    }

    fn content_hash(&self) -> String {
        canonical_sha256_bytes(&self.bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for EphemeralActionPayload {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.bytes.clear();
    }
}

enum TrustedWindowsAdapter {
    Uia(WindowsUiAutomationAdapter),
    WebDriver(WindowsWebDriverAdapter),
}

impl TrustedWindowsAdapter {
    fn worker_process_id(&self) -> u32 {
        match self {
            Self::Uia(adapter) => adapter.worker_process_id(),
            Self::WebDriver(adapter) => adapter.worker_process_id(),
        }
    }

    fn trusted_resolution_snapshot(
        &mut self,
        operation: &DesktopOperation,
        now_unix_ms: u64,
    ) -> Result<String, DesktopError> {
        match self {
            Self::Uia(adapter) => adapter.trusted_resolution_snapshot(operation, now_unix_ms),
            Self::WebDriver(adapter) => adapter.trusted_resolution_snapshot(operation, now_unix_ms),
        }
    }

    fn prepare(
        &mut self,
        intent: &DesktopActionIntent,
        now_unix_ms: u64,
    ) -> Result<PreparedAction, DesktopError> {
        match self {
            Self::Uia(adapter) => adapter.prepare(intent, now_unix_ms),
            Self::WebDriver(adapter) => adapter.prepare(intent, now_unix_ms),
        }
    }

    fn execute(
        &mut self,
        intent: &DesktopActionIntent,
        prepared: &PreparedAction,
        permit: &crate::ExecutionPermit,
        payload: Option<&[u8]>,
        now_unix_ms: u64,
    ) -> Result<AdapterExecution, DesktopError> {
        match self {
            Self::Uia(adapter) => adapter.execute(intent, prepared, permit, payload, now_unix_ms),
            Self::WebDriver(adapter) => {
                adapter.execute(intent, prepared, permit, payload, now_unix_ms)
            }
        }
    }
}

struct PendingPreparation {
    adapter_preparation: PreparedAction,
    bound_preparation: PreparedBoundActionV1,
}

/// One non-serializable plan owning raw target, input, and adapter authority.
pub struct TrustedDesktopExecutionPlan {
    request: TrustedExecutionBindingRequestV1,
    bound_action: BoundDesktopActionV1,
    target_resolution: TargetResolutionProofV1,
    intent: DesktopActionIntent,
    target: ResolvedTargetMaterial,
    payload: Option<EphemeralActionPayload>,
    adapter: TrustedWindowsAdapter,
}

impl Debug for TrustedDesktopExecutionPlan {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedDesktopExecutionPlan")
            .field(
                "bound_action_sha256",
                &self.bound_action.bound_action_sha256,
            )
            .field("target", &self.target)
            .field(
                "payload",
                &self.payload.as_ref().map(|payload| payload.bytes.len()),
            )
            .field("adapter", &"<owned one-shot Windows adapter>")
            .finish()
    }
}

/// Projects one unconsumed Windows admission into the Core request contract.
pub fn project_windows_activation(
    admission: &WindowsActivationAdmission,
    configuration: &WindowsAdapterConfiguration,
) -> Result<TrustedPlatformActivationV1, DesktopError> {
    configuration.validate()?;
    if admission.verification.integration_id != admission.activation.integration_id()
        || configuration.configuration_hash()? != admission.activation.configuration_hash()
        || configuration.adapter_kind != admission.activation.adapter_kind()
        || configuration.descriptor()? != *admission.activation.adapter_descriptor()
    {
        return Err(DesktopError::Integrity(
            "Windows activation admission and configuration differ".to_owned(),
        ));
    }
    Ok(TrustedPlatformActivationV1 {
        activation_ledger_id: admission.verification.ledger_id.clone(),
        activation_ledger_chain_head: admission.verification.chain_head.clone(),
        integration_id: admission.activation.integration_id().to_owned(),
        binding_id: admission.activation.binding_id().to_owned(),
        activation_record_hash: admission.activation.activation_record_hash().to_owned(),
        runtime_binding_sha256: admission.activation.configuration_hash().to_owned(),
        adapter_kind: cognitive_adapter_kind(configuration.adapter_kind)?,
        adapter_descriptor_sha256: admission
            .activation
            .adapter_descriptor()
            .descriptor_hash()?,
        observed_at_unix_seconds: admission.activation.observed_at_unix_seconds(),
        expires_at_unix_seconds: admission.activation.expires_at_unix_seconds(),
    })
}

/// Builds a Cognitive-bound Desktop intent without synthesizing a DecisionEnvelope.
pub fn build_cognitive_desktop_action_intent(
    request: &TrustedExecutionBindingRequestV1,
    resolution: &TargetResolutionProofV1,
    input: Option<&InputMaterialProofV1>,
    operation: DesktopOperation,
    generated_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<DesktopActionIntent, DesktopError> {
    request.validate().map_err(contract_error)?;
    resolution
        .validate_against(request)
        .map_err(contract_error)?;
    if let Some(input) = input {
        input.validate_against(request).map_err(contract_error)?;
    }
    let operation_sha256 = hash_value(&operation)?;
    let identity_sha256 = canonical_sha256(&serde_json::json!({
        "request_sha256": request.request_sha256,
        "resolution_sha256": resolution.resolution_sha256,
        "input_material_proof_sha256": input.map(|proof| &proof.material_proof_sha256),
        "desktop_operation_sha256": operation_sha256
    }))
    .map_err(contract_error)?;
    let suffix = identity_sha256.strip_prefix("sha256:").ok_or_else(|| {
        DesktopError::Integrity("derived action hash prefix is absent".to_owned())
    })?;
    let action_id = format!("trusted-action-{}", &suffix[..24]);
    let ready = &request.policy_ready_action;
    let admission = &request.cognitive_activation_admission;
    let mut evidence_hashes = vec![
        request.request_sha256.clone(),
        ready.selection_sha256.clone(),
        ready.policy_ready_sha256.clone(),
        admission.authority_sha256.clone(),
        admission.policy_snapshot_sha256.clone(),
        admission.policy_decision_sha256.clone(),
        admission.admission_sha256.clone(),
        request.platform_activation.activation_record_hash.clone(),
        resolution.resolution_sha256.clone(),
    ];
    if let Some(input) = input {
        evidence_hashes.push(input.material_proof_sha256.clone());
    }
    evidence_hashes.sort();
    evidence_hashes.dedup();
    let intent = DesktopActionIntent {
        schema_version: 1,
        action_id: action_id.clone(),
        session_id: request.execution_session.execution_session_id.clone(),
        sequence: request.execution_session.action_sequence,
        generated_at_unix_ms,
        expires_at_unix_ms,
        request_id: ready.proposal.proposal_id.clone(),
        build_id: request.execution_session.runtime_build_id.clone(),
        package_content_hash: request.execution_session.runtime_package_sha256.clone(),
        decision_hash: admission.policy_decision_sha256.clone(),
        evidence_hashes,
        idempotency_key: action_id,
        rationale_hash: ready.policy_ready_sha256.clone(),
        operation,
    };
    intent.validate()?;
    Ok(intent)
}

/// Validates the additive Cognitive path independently of DecisionEnvelope.
pub fn validate_cognitive_desktop_action_intent(
    intent: &DesktopActionIntent,
    bound: &BoundDesktopActionV1,
    request: &TrustedExecutionBindingRequestV1,
    resolution: &TargetResolutionProofV1,
    input: Option<&InputMaterialProofV1>,
) -> Result<(), DesktopError> {
    intent.validate()?;
    bound
        .validate_against(request, resolution, input)
        .map_err(contract_error)?;
    if intent.action_hash()? != bound.desktop_action_intent_sha256
        || hash_value(&intent.operation)? != bound.desktop_operation_sha256
        || intent.session_id != request.execution_session.execution_session_id
        || intent.sequence != request.execution_session.action_sequence
        || intent.request_id != request.policy_ready_action.proposal.proposal_id
        || intent.build_id != request.execution_session.runtime_build_id
        || intent.package_content_hash != request.execution_session.runtime_package_sha256
        || intent.decision_hash
            != request
                .cognitive_activation_admission
                .policy_decision_sha256
        || intent.rationale_hash != request.policy_ready_action.policy_ready_sha256
        || intent.operation.capability() != desktop_capability(bound.desktop_capability)
    {
        return Err(DesktopError::Integrity(
            "DesktopActionIntent differs from its Cognitive binding".to_owned(),
        ));
    }
    Ok(())
}

/// Stateful owner of one admission, activation, worker, payload, and attempt.
pub struct CognitiveTrustedExecutionCoordinator {
    session_id: String,
    expected_sequence: u64,
    pending_bound_action_id: Option<String>,
    pending: Option<PendingPreparation>,
    consumed_proposal_ids: BTreeSet<String>,
    consumed_admission_hashes: BTreeSet<String>,
    consumed_activation_record_hashes: BTreeSet<String>,
    action_attempt_count: u32,
    poisoned: bool,
    terminal: bool,
    plan: Option<TrustedDesktopExecutionPlan>,
    receipt: Option<TrustedActionExecutionReceiptV1>,
    audit: WindowsDeploymentAuditLedger,
}

impl CognitiveTrustedExecutionCoordinator {
    /// Consumes one Windows activation, starts one adapter, resolves one exact
    /// target with the read-only worker snapshot command, and seals the action.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        request: TrustedExecutionBindingRequestV1,
        source_observation: &ObservationSnapshot,
        windows_admission: WindowsActivationAdmission,
        configuration: WindowsAdapterConfiguration,
        resolver_input: TrustedTargetResolverInput,
        payload: Option<EphemeralActionPayload>,
        mut audit: WindowsDeploymentAuditLedger,
        now_unix_ms: u64,
    ) -> Result<Self, DesktopError> {
        request.validate().map_err(contract_error)?;
        request
            .execution_session
            .validate_at(now_unix_ms)
            .map_err(contract_error)?;
        request
            .validate_source_observation(source_observation)
            .map_err(contract_error)?;
        if audit.session_id() != request.execution_session.execution_session_id {
            return Err(DesktopError::Integrity(
                "protected audit and trusted execution session differ".to_owned(),
            ));
        }
        let projected = project_windows_activation(&windows_admission, &configuration)?;
        if projected != request.platform_activation {
            return Err(DesktopError::Integrity(
                "actual Windows activation differs from trusted request".to_owned(),
            ));
        }
        let operation_kind =
            operation_kind(&request.policy_ready_action).map_err(contract_error)?;
        let mut adapter = bind_adapter(
            windows_admission,
            configuration,
            operation_kind,
            now_unix_ms / 1_000,
        )?;
        let target = resolve_target(&request, source_observation, resolver_input, operation_kind)?;
        let input_proof = resolve_input_proof(&request, payload.as_ref(), now_unix_ms)?;
        let operation = desktop_operation(&request, operation_kind, &target, input_proof.as_ref())?;
        let fresh_snapshot_hash = adapter.trusted_resolution_snapshot(&operation, now_unix_ms)?;
        let target_material_sha256 = target_material_sha256(&target)?;
        let resolution = TargetResolutionProofV1 {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            resolution_id: derived_id("resolution", &request.request_sha256)?,
            request_sha256: request.request_sha256.clone(),
            proposal_sha256: canonical_sha256(&request.policy_ready_action.proposal)
                .map_err(contract_error)?,
            grounded_target_binding_sha256: request.expected_grounded_target_binding_sha256.clone(),
            selected_element_id: request.policy_ready_action.selected_element_id.clone(),
            selected_element_kind: request.policy_ready_action.selected_element_kind.clone(),
            source_kind: operation_kind.source_kind(),
            source_observation_id: request.source_observation_id.clone(),
            source_observation_hash: request.source_observation_hash.clone(),
            source_observation_sequence: request.source_observation_sequence,
            fresh_resolution_observation_hash: fresh_snapshot_hash,
            runtime_binding_sha256: request.platform_activation.runtime_binding_sha256.clone(),
            integration_id: request.platform_activation.integration_id.clone(),
            binding_id: request.platform_activation.binding_id.clone(),
            activation_record_hash: request.platform_activation.activation_record_hash.clone(),
            adapter_descriptor_sha256: request
                .platform_activation
                .adapter_descriptor_sha256
                .clone(),
            target_material_sha256,
            unique_match_count: 1,
            resolved_at_unix_ms: now_unix_ms,
            expires_at_unix_ms: request
                .execution_session
                .expires_at_unix_ms
                .min(now_unix_ms.saturating_add(60_000)),
            evidence_ids: vec![
                "fresh-worker-snapshot".to_owned(),
                "trusted-target-resolution".to_owned(),
            ],
            resolution_sha256: empty_hash(),
        }
        .seal()
        .map_err(contract_error)?;
        resolution
            .validate_against(&request)
            .map_err(contract_error)?;
        let generated_at_unix_ms = [
            request.execution_session.generated_at_unix_ms,
            request
                .cognitive_activation_admission
                .admitted_at_unix_seconds
                .saturating_mul(1_000),
            request
                .platform_activation
                .observed_at_unix_seconds
                .saturating_mul(1_000),
            resolution.resolved_at_unix_ms,
            input_proof
                .as_ref()
                .map_or(0, |proof| proof.resolved_at_unix_ms),
        ]
        .into_iter()
        .max()
        .unwrap_or(now_unix_ms);
        let expires_at_unix_ms = [
            request.execution_session.expires_at_unix_ms,
            request
                .cognitive_activation_admission
                .expires_at_unix_seconds
                .saturating_mul(1_000),
            request
                .platform_activation
                .expires_at_unix_seconds
                .saturating_mul(1_000),
            resolution.expires_at_unix_ms,
            input_proof
                .as_ref()
                .map_or(u64::MAX, |proof| proof.expires_at_unix_ms),
        ]
        .into_iter()
        .min()
        .unwrap_or(0);
        if now_unix_ms < generated_at_unix_ms || now_unix_ms >= expires_at_unix_ms {
            return Err(DesktopError::AccessDenied(
                "trusted action validity intersection is not active".to_owned(),
            ));
        }
        let intent = build_cognitive_desktop_action_intent(
            &request,
            &resolution,
            input_proof.as_ref(),
            operation.clone(),
            generated_at_unix_ms,
            expires_at_unix_ms,
        )?;
        let operation_sha256 = hash_value(&operation)?;
        let intent_sha256 = intent.action_hash()?;
        let bound_action = BoundDesktopActionV1 {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            bound_action_id: intent.action_id.clone(),
            trusted_execution_request_sha256: request.request_sha256.clone(),
            policy_ready_sha256: request.policy_ready_action.policy_ready_sha256.clone(),
            selection_sha256: request.policy_ready_action.selection_sha256.clone(),
            proposal_id: request.policy_ready_action.proposal.proposal_id.clone(),
            proposal_sha256: canonical_sha256(&request.policy_ready_action.proposal)
                .map_err(contract_error)?,
            goal_id: request.policy_ready_action.goal_id.clone(),
            plan_generation_id: request.policy_ready_action.plan_generation_id.clone(),
            source_observation_id: request.source_observation_id.clone(),
            source_observation_hash: request.source_observation_hash.clone(),
            source_observation_sequence: request.source_observation_sequence,
            semantic_target_id: request.policy_ready_action.semantic_target_id.clone(),
            selected_element_id: request.policy_ready_action.selected_element_id.clone(),
            capability_id: request.policy_ready_action.capability_id.clone(),
            capability_binding_sha256: request
                .policy_ready_action
                .capability_binding_sha256
                .clone(),
            policy_decision_sha256: request
                .cognitive_activation_admission
                .policy_decision_sha256
                .clone(),
            cognitive_activation_admission_sha256: request
                .cognitive_activation_admission
                .admission_sha256
                .clone(),
            execution_session_sha256: request.execution_session.session_sha256.clone(),
            target_resolution_sha256: resolution.resolution_sha256.clone(),
            input_material_proof_sha256: input_proof
                .as_ref()
                .map(|proof| proof.material_proof_sha256.clone()),
            integration_id: request.platform_activation.integration_id.clone(),
            binding_id: request.platform_activation.binding_id.clone(),
            activation_record_hash: request.platform_activation.activation_record_hash.clone(),
            adapter_kind: request.platform_activation.adapter_kind,
            adapter_descriptor_sha256: request
                .platform_activation
                .adapter_descriptor_sha256
                .clone(),
            desktop_capability: operation_kind.desktop_capability(),
            desktop_operation_kind: operation_kind,
            desktop_operation_sha256: operation_sha256,
            desktop_action_intent_sha256: intent_sha256,
            generated_at_unix_ms,
            expires_at_unix_ms,
            evidence_ids: vec![
                "cognitive-activation-admission".to_owned(),
                "one-shot-windows-activation".to_owned(),
                "trusted-target-resolution".to_owned(),
            ],
            bound_action_sha256: empty_hash(),
        }
        .seal()
        .map_err(contract_error)?;
        validate_cognitive_desktop_action_intent(
            &intent,
            &bound_action,
            &request,
            &resolution,
            input_proof.as_ref(),
        )?;
        append_audit(
            &mut audit,
            WindowsDeploymentAuditEventKind::CognitiveBindingCreated,
            WindowsDeploymentAuditStatus::Succeeded,
            &bound_action.bound_action_id,
            BTreeMap::from([
                (
                    "bound_action".to_owned(),
                    bound_action.bound_action_sha256.clone(),
                ),
                (
                    "cognitive_admission".to_owned(),
                    request
                        .cognitive_activation_admission
                        .admission_sha256
                        .clone(),
                ),
                (
                    "activation_record".to_owned(),
                    request.platform_activation.activation_record_hash.clone(),
                ),
            ]),
            now_unix_ms,
        )?;
        append_audit(
            &mut audit,
            WindowsDeploymentAuditEventKind::TrustedTargetResolved,
            WindowsDeploymentAuditStatus::Succeeded,
            &bound_action.bound_action_id,
            BTreeMap::from([
                (
                    "target_resolution".to_owned(),
                    resolution.resolution_sha256.clone(),
                ),
                (
                    "target_material".to_owned(),
                    resolution.target_material_sha256.clone(),
                ),
            ]),
            now_unix_ms,
        )?;
        Ok(Self {
            session_id: request.execution_session.execution_session_id.clone(),
            expected_sequence: request.execution_session.action_sequence,
            pending_bound_action_id: None,
            pending: None,
            consumed_proposal_ids: BTreeSet::new(),
            consumed_admission_hashes: BTreeSet::new(),
            consumed_activation_record_hashes: BTreeSet::new(),
            action_attempt_count: 0,
            poisoned: false,
            terminal: false,
            plan: Some(TrustedDesktopExecutionPlan {
                request,
                bound_action,
                target_resolution: resolution,
                intent,
                target,
                payload,
                adapter,
            }),
            receipt: None,
            audit,
        })
    }

    /// Returns the audit-safe bound action.
    pub fn bound_action(&self) -> Result<&BoundDesktopActionV1, DesktopError> {
        self.plan
            .as_ref()
            .map(|plan| &plan.bound_action)
            .ok_or_else(|| DesktopError::Replay("trusted execution is terminal".to_owned()))
    }

    /// Performs a second side-effect-free adapter snapshot and seals preparation.
    pub fn prepare(&mut self, now_unix_ms: u64) -> Result<PreparedBoundActionV1, DesktopError> {
        self.validate_active(now_unix_ms)?;
        if self.pending.is_some() {
            return Err(DesktopError::Replay(
                "trusted execution already has a pending preparation".to_owned(),
            ));
        }
        let plan = self
            .plan
            .as_mut()
            .ok_or_else(|| DesktopError::Replay("trusted execution is terminal".to_owned()))?;
        let prepared = plan.adapter.prepare(&plan.intent, now_unix_ms)?;
        if prepared.precondition_hash != plan.target_resolution.fresh_resolution_observation_hash {
            return Err(DesktopError::Replay(
                "target state changed after trusted resolution".to_owned(),
            ));
        }
        let bound_preparation = PreparedBoundActionV1 {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            bound_action_sha256: plan.bound_action.bound_action_sha256.clone(),
            desktop_action_intent_sha256: plan.bound_action.desktop_action_intent_sha256.clone(),
            desktop_operation_sha256: plan.bound_action.desktop_operation_sha256.clone(),
            adapter_descriptor_sha256: plan.bound_action.adapter_descriptor_sha256.clone(),
            target_resolution_sha256: plan.bound_action.target_resolution_sha256.clone(),
            input_material_proof_sha256: plan.bound_action.input_material_proof_sha256.clone(),
            prepared_action_hash: prepared.preparation_hash.clone(),
            precondition_hash: prepared.precondition_hash.clone(),
            prepared_at_unix_ms: prepared.prepared_at_unix_ms,
            expires_at_unix_ms: prepared
                .expires_at_unix_ms
                .min(plan.bound_action.expires_at_unix_ms),
            reversible: prepared.reversible,
            evidence_ids: vec![
                "adapter-precondition-snapshot".to_owned(),
                "trusted-preparation".to_owned(),
            ],
            prepared_binding_sha256: empty_hash(),
        }
        .seal()
        .map_err(contract_error)?;
        bound_preparation
            .validate_against(&plan.bound_action)
            .map_err(contract_error)?;
        append_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::TrustedActionPrepared,
            WindowsDeploymentAuditStatus::Succeeded,
            &plan.bound_action.bound_action_id,
            BTreeMap::from([
                (
                    "prepared_binding".to_owned(),
                    bound_preparation.prepared_binding_sha256.clone(),
                ),
                (
                    "precondition".to_owned(),
                    bound_preparation.precondition_hash.clone(),
                ),
            ]),
            now_unix_ms,
        )?;
        self.pending_bound_action_id = Some(plan.bound_action.bound_action_id.clone());
        self.pending = Some(PendingPreparation {
            adapter_preparation: prepared,
            bound_preparation: bound_preparation.clone(),
        });
        Ok(bound_preparation)
    }

    /// Commits exactly one permit-bound adapter action and returns no raw output.
    pub fn commit(
        &mut self,
        preparation: &PreparedBoundActionV1,
        now_unix_ms: u64,
    ) -> Result<TrustedActionExecutionReceiptV1, DesktopError> {
        self.validate_active(now_unix_ms)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("no pending trusted preparation".to_owned()))?;
        if &pending.bound_preparation != preparation
            || self.pending_bound_action_id.as_deref()
                != self
                    .plan
                    .as_ref()
                    .map(|plan| plan.bound_action.bound_action_id.as_str())
        {
            return Err(DesktopError::Replay(
                "commit preparation differs from pending binding".to_owned(),
            ));
        }
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("trusted execution is terminal".to_owned()))?;
        self.ensure_unconsumed(plan)?;
        append_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::TrustedCommitStarted,
            WindowsDeploymentAuditStatus::Succeeded,
            &plan.bound_action.bound_action_id,
            BTreeMap::from([(
                "prepared_binding".to_owned(),
                preparation.prepared_binding_sha256.clone(),
            )]),
            now_unix_ms,
        )?;
        let action_hash = plan.intent.action_hash()?;
        let expires_at_unix_ms = preparation
            .expires_at_unix_ms
            .min(plan.bound_action.expires_at_unix_ms);
        let permit = authorize_cognitive_prepared(
            &action_hash,
            &plan.bound_action.bound_action_sha256,
            &plan.bound_action.policy_decision_sha256,
            &plan.bound_action.cognitive_activation_admission_sha256,
            &pending.adapter_preparation,
            &plan.bound_action.adapter_descriptor_sha256,
            &plan.bound_action.activation_record_hash,
            &plan.bound_action.target_resolution_sha256,
            plan.bound_action.input_material_proof_sha256.as_deref(),
            expires_at_unix_ms,
            now_unix_ms,
        )?;
        append_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::CognitivePermitMinted,
            WindowsDeploymentAuditStatus::Succeeded,
            &plan.bound_action.bound_action_id,
            BTreeMap::from([
                ("permit".to_owned(), permit.permit_hash().to_owned()),
                (
                    "prepared_binding".to_owned(),
                    preparation.prepared_binding_sha256.clone(),
                ),
            ]),
            now_unix_ms,
        )?;
        self.poisoned = true;
        let execution = {
            let plan = self
                .plan
                .as_mut()
                .ok_or_else(|| DesktopError::Replay("trusted execution is terminal".to_owned()))?;
            let payload = plan.payload.as_ref().map(EphemeralActionPayload::as_bytes);
            plan.adapter.execute(
                &plan.intent,
                &pending.adapter_preparation,
                &permit,
                payload,
                now_unix_ms,
            )
        };
        let completed_at_unix_ms = now_unix_ms;
        let receipt = self.execution_receipt(
            execution.as_ref().ok(),
            execution.as_ref().err(),
            preparation,
            permit.permit_hash(),
            now_unix_ms,
            completed_at_unix_ms,
        )?;
        self.consume_terminal()?;
        let (kind, status) = if receipt.status == TrustedExecutionStatusV1::Succeeded {
            (
                WindowsDeploymentAuditEventKind::TrustedExecutionSucceeded,
                WindowsDeploymentAuditStatus::Succeeded,
            )
        } else {
            (
                WindowsDeploymentAuditEventKind::TrustedExecutionFailed,
                WindowsDeploymentAuditStatus::Failed,
            )
        };
        let terminal_audit = append_audit(
            &mut self.audit,
            kind,
            status,
            &receipt.execution_id,
            BTreeMap::from([
                ("receipt".to_owned(), receipt.receipt_sha256.clone()),
                ("permit".to_owned(), permit.permit_hash().to_owned()),
                (
                    "output".to_owned(),
                    receipt
                        .adapter_output_sha256
                        .clone()
                        .unwrap_or_else(|| sha256_bytes(&[])),
                ),
            ]),
            completed_at_unix_ms,
        );
        self.plan.take();
        self.pending.take();
        self.pending_bound_action_id = None;
        self.terminal = true;
        self.receipt = Some(receipt.clone());
        terminal_audit?;
        self.poisoned = false;
        Ok(receipt)
    }

    /// Cancels one pending preparation without performing an adapter action.
    pub fn cancel(
        &mut self,
        preparation: &PreparedBoundActionV1,
        now_unix_ms: u64,
    ) -> Result<TrustedActionExecutionReceiptV1, DesktopError> {
        self.validate_active(now_unix_ms)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("no pending preparation to cancel".to_owned()))?;
        if &pending.bound_preparation != preparation {
            return Err(DesktopError::Replay(
                "cancel preparation differs from pending binding".to_owned(),
            ));
        }
        let receipt = self.nonexecuted_receipt(
            TrustedExecutionStatusV1::Cancelled,
            Some(preparation),
            now_unix_ms,
        )?;
        append_audit(
            &mut self.audit,
            WindowsDeploymentAuditEventKind::TrustedExecutionCancelled,
            WindowsDeploymentAuditStatus::Blocked,
            &receipt.execution_id,
            BTreeMap::from([("receipt".to_owned(), receipt.receipt_sha256.clone())]),
            now_unix_ms,
        )?;
        self.consume_terminal()?;
        self.plan.take();
        self.pending.take();
        self.pending_bound_action_id = None;
        self.terminal = true;
        self.receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Returns the terminal audit-safe receipt after commit or cancellation.
    #[must_use]
    pub fn terminal_receipt(&self) -> Option<&TrustedActionExecutionReceiptV1> {
        self.receipt.as_ref()
    }

    /// Reports whether an incomplete commit poisoned this coordinator.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Reports whether the one-shot adapter, target, or payload is still owned.
    #[must_use]
    pub const fn has_live_execution_material(&self) -> bool {
        self.plan.is_some()
    }

    /// Returns the exact owned worker PID while the one-shot plan is live.
    #[must_use]
    pub fn owned_worker_process_id(&self) -> Option<u32> {
        self.plan
            .as_ref()
            .map(|plan| plan.adapter.worker_process_id())
    }

    fn validate_active(&self, now_unix_ms: u64) -> Result<(), DesktopError> {
        if self.terminal {
            return Err(DesktopError::Replay(
                "trusted execution is already terminal".to_owned(),
            ));
        }
        if self.poisoned {
            return Err(DesktopError::Integrity(
                "trusted execution is poisoned after incomplete commit".to_owned(),
            ));
        }
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("trusted execution plan is absent".to_owned()))?;
        if self.session_id != plan.intent.session_id
            || self.expected_sequence != plan.intent.sequence
            || now_unix_ms < plan.bound_action.generated_at_unix_ms
            || now_unix_ms >= plan.bound_action.expires_at_unix_ms
        {
            return Err(DesktopError::Replay(
                "trusted execution session, sequence, or time differs".to_owned(),
            ));
        }
        Ok(())
    }

    fn ensure_unconsumed(&self, plan: &TrustedDesktopExecutionPlan) -> Result<(), DesktopError> {
        if self
            .consumed_proposal_ids
            .contains(&plan.bound_action.proposal_id)
            || self
                .consumed_admission_hashes
                .contains(&plan.bound_action.cognitive_activation_admission_sha256)
            || self
                .consumed_activation_record_hashes
                .contains(&plan.bound_action.activation_record_hash)
        {
            return Err(DesktopError::Replay(
                "proposal, admission, or activation was already consumed".to_owned(),
            ));
        }
        Ok(())
    }

    fn consume_terminal(&mut self) -> Result<(), DesktopError> {
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("trusted execution plan is absent".to_owned()))?;
        if !self
            .consumed_proposal_ids
            .insert(plan.bound_action.proposal_id.clone())
            || !self.consumed_admission_hashes.insert(
                plan.bound_action
                    .cognitive_activation_admission_sha256
                    .clone(),
            )
            || !self
                .consumed_activation_record_hashes
                .insert(plan.bound_action.activation_record_hash.clone())
        {
            return Err(DesktopError::Replay(
                "terminal trusted authority was consumed concurrently".to_owned(),
            ));
        }
        self.action_attempt_count = self.action_attempt_count.saturating_add(1);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn execution_receipt(
        &self,
        execution: Option<&AdapterExecution>,
        error: Option<&DesktopError>,
        preparation: &PreparedBoundActionV1,
        permit_hash: &str,
        started_at_unix_ms: u64,
        completed_at_unix_ms: u64,
    ) -> Result<TrustedActionExecutionReceiptV1, DesktopError> {
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("trusted execution plan is absent".to_owned()))?;
        let (status, outcome_status, output_hash, output_bytes, warnings) = match execution {
            Some(execution) if execution.outcome.status == ActionOutcomeStatus::Succeeded => (
                TrustedExecutionStatusV1::Succeeded,
                TrustedAdapterOutcomeStatusV1::Succeeded,
                execution.outcome.output_hash.clone(),
                execution.outcome.output_bytes,
                Vec::new(),
            ),
            Some(execution) => (
                TrustedExecutionStatusV1::Failed,
                TrustedAdapterOutcomeStatusV1::Failed,
                execution.outcome.output_hash.clone(),
                execution.outcome.output_bytes,
                vec!["adapter reported a failed execution attempt".to_owned()],
            ),
            None => (
                TrustedExecutionStatusV1::Failed,
                TrustedAdapterOutcomeStatusV1::Failed,
                sha256_bytes(&[]),
                0,
                vec![format!(
                    "adapter failure diagnostic hash {}",
                    sha256_bytes(
                        error
                            .map(ToString::to_string)
                            .unwrap_or_else(|| "unknown adapter failure".to_owned())
                            .as_bytes()
                    )
                )],
            ),
        };
        self.receipt_template(
            status,
            Some(preparation),
            Some(permit_hash.to_owned()),
            Some(outcome_status),
            Some(output_hash),
            output_bytes,
            Some(started_at_unix_ms),
            completed_at_unix_ms,
            warnings,
            plan,
        )
    }

    fn nonexecuted_receipt(
        &self,
        status: TrustedExecutionStatusV1,
        preparation: Option<&PreparedBoundActionV1>,
        completed_at_unix_ms: u64,
    ) -> Result<TrustedActionExecutionReceiptV1, DesktopError> {
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| DesktopError::Replay("trusted execution plan is absent".to_owned()))?;
        self.receipt_template(
            status,
            preparation,
            None,
            None,
            None,
            0,
            None,
            completed_at_unix_ms,
            Vec::new(),
            plan,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt_template(
        &self,
        status: TrustedExecutionStatusV1,
        preparation: Option<&PreparedBoundActionV1>,
        permit_hash: Option<String>,
        adapter_status: Option<TrustedAdapterOutcomeStatusV1>,
        output_hash: Option<String>,
        output_bytes: u64,
        started_at_unix_ms: Option<u64>,
        completed_at_unix_ms: u64,
        warnings: Vec<String>,
        plan: &TrustedDesktopExecutionPlan,
    ) -> Result<TrustedActionExecutionReceiptV1, DesktopError> {
        let bound = &plan.bound_action;
        let admission = &plan.request.cognitive_activation_admission;
        TrustedActionExecutionReceiptV1 {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            execution_id: derived_id("execution", &bound.bound_action_sha256)?,
            status,
            bound_action_sha256: bound.bound_action_sha256.clone(),
            prepared_binding_sha256: preparation.map(|value| value.prepared_binding_sha256.clone()),
            policy_ready_sha256: bound.policy_ready_sha256.clone(),
            proposal_id: bound.proposal_id.clone(),
            proposal_sha256: bound.proposal_sha256.clone(),
            goal_id: bound.goal_id.clone(),
            plan_generation_id: bound.plan_generation_id.clone(),
            source_observation_id: bound.source_observation_id.clone(),
            source_observation_hash: bound.source_observation_hash.clone(),
            source_observation_sequence: bound.source_observation_sequence,
            capability_id: bound.capability_id.clone(),
            semantic_target_id: bound.semantic_target_id.clone(),
            cognitive_activation_admission_sha256: bound
                .cognitive_activation_admission_sha256
                .clone(),
            policy_decision_sha256: bound.policy_decision_sha256.clone(),
            confirmation_grant_sha256: admission.confirmation_grant_sha256.clone(),
            activation_record_hash: bound.activation_record_hash.clone(),
            runtime_binding_sha256: plan
                .request
                .platform_activation
                .runtime_binding_sha256
                .clone(),
            adapter_descriptor_sha256: bound.adapter_descriptor_sha256.clone(),
            desktop_action_intent_sha256: bound.desktop_action_intent_sha256.clone(),
            desktop_operation_sha256: bound.desktop_operation_sha256.clone(),
            target_resolution_sha256: bound.target_resolution_sha256.clone(),
            input_material_proof_sha256: bound.input_material_proof_sha256.clone(),
            preparation_hash: preparation.map(|value| value.prepared_action_hash.clone()),
            precondition_hash: preparation.map(|value| value.precondition_hash.clone()),
            execution_permit_sha256: permit_hash,
            adapter_outcome_status: adapter_status,
            adapter_output_sha256: output_hash,
            adapter_output_bytes: output_bytes,
            started_at_unix_ms,
            completed_at_unix_ms,
            warnings,
            evidence_ids: vec![
                "adapter-attempt-only".to_owned(),
                "not-postcondition-verified".to_owned(),
                "trusted-action-execution".to_owned(),
            ],
            receipt_sha256: empty_hash(),
        }
        .seal()
        .map_err(contract_error)
    }
}

impl Drop for CognitiveTrustedExecutionCoordinator {
    fn drop(&mut self) {
        if !self.terminal && self.plan.is_some() {
            self.poisoned = true;
            if let Some(plan) = self.plan.as_ref() {
                let _ = append_audit(
                    &mut self.audit,
                    WindowsDeploymentAuditEventKind::TrustedExecutionAborted,
                    WindowsDeploymentAuditStatus::Failed,
                    &plan.bound_action.bound_action_id,
                    BTreeMap::from([(
                        "bound_action".to_owned(),
                        plan.bound_action.bound_action_sha256.clone(),
                    )]),
                    plan.bound_action.generated_at_unix_ms.max(1),
                );
            }
            self.plan.take();
            self.pending.take();
        }
    }
}

/// Deterministically projects an adapter-attempt receipt into Verification v2.
pub fn to_verification_bound_execution_v2(
    receipt: &TrustedActionExecutionReceiptV1,
) -> Result<BoundActionExecutionV2, DesktopError> {
    receipt.validate().map_err(contract_error)?;
    let status = match receipt.status {
        TrustedExecutionStatusV1::Succeeded => ExecutionStatus::Succeeded,
        TrustedExecutionStatusV1::Failed => ExecutionStatus::Failed,
        TrustedExecutionStatusV1::DeniedBeforeCommit => ExecutionStatus::Denied,
        TrustedExecutionStatusV1::Cancelled => ExecutionStatus::Unsupported,
        TrustedExecutionStatusV1::Aborted => ExecutionStatus::Timeout,
    };
    let mut evidence = vec![
        format!("receipt:{}", receipt.receipt_sha256),
        format!("bound_action:{}", receipt.bound_action_sha256),
        format!("activation_record:{}", receipt.activation_record_hash),
        format!("target_resolution:{}", receipt.target_resolution_sha256),
    ];
    if let Some(hash) = &receipt.execution_permit_sha256 {
        evidence.push(format!("execution_permit:{hash}"));
    }
    evidence.sort();
    let execution = BoundActionExecutionV2 {
        schema_version: 2,
        execution_id: receipt.execution_id.clone(),
        proposal_id: receipt.proposal_id.clone(),
        goal_id: receipt.goal_id.clone(),
        plan_generation_id: receipt.plan_generation_id.clone(),
        source_observation_id: receipt.source_observation_id.clone(),
        source_observation_hash: receipt.source_observation_hash.clone(),
        source_observation_sequence: receipt.source_observation_sequence,
        status,
        evidence,
        warnings: receipt.warnings.clone(),
    };
    execution.validate()?;
    Ok(execution)
}

fn bind_adapter(
    admission: WindowsActivationAdmission,
    configuration: WindowsAdapterConfiguration,
    operation: TrustedDesktopOperationKindV1,
    now_unix_seconds: u64,
) -> Result<TrustedWindowsAdapter, DesktopError> {
    match operation.adapter_kind() {
        AdapterKindV1::Uia => Ok(TrustedWindowsAdapter::Uia(
            WindowsUiAutomationAdapter::bind(
                admission.activation,
                configuration,
                now_unix_seconds,
            )?,
        )),
        AdapterKindV1::WebDriver => Ok(TrustedWindowsAdapter::WebDriver(
            WindowsWebDriverAdapter::bind(admission.activation, configuration, now_unix_seconds)?,
        )),
        AdapterKindV1::EnterpriseApi => Err(DesktopError::Precondition(
            "enterprise API activation cannot bind a Windows desktop adapter".to_owned(),
        )),
        AdapterKindV1::OfficeWorkspace => Err(DesktopError::Precondition(
            "office workspace activation cannot bind a Windows desktop adapter".to_owned(),
        )),
        AdapterKindV1::OfficeDocument => Err(DesktopError::Precondition(
            "office document activation cannot bind a Windows desktop adapter".to_owned(),
        )),
    }
}

fn resolve_target(
    request: &TrustedExecutionBindingRequestV1,
    observation: &ObservationSnapshot,
    resolver: TrustedTargetResolverInput,
    operation: TrustedDesktopOperationKindV1,
) -> Result<ResolvedTargetMaterial, DesktopError> {
    let matches = observation
        .observable_elements
        .iter()
        .filter(|element| element.element_id == request.policy_ready_action.selected_element_id)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(DesktopError::Precondition(
            "selected element did not resolve uniquely in source observation".to_owned(),
        ));
    }
    let element = matches[0];
    if element.kind != request.policy_ready_action.selected_element_kind {
        return Err(DesktopError::Integrity(
            "selected element kind changed".to_owned(),
        ));
    }
    let enabled = element
        .value
        .get("enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !enabled {
        return Err(DesktopError::Precondition(
            "selected element is disabled".to_owned(),
        ));
    }
    match (resolver, operation.source_kind(), observation.source_kind) {
        (
            TrustedTargetResolverInput::Uia { target },
            TrustedTargetSourceKindV1::Uia,
            ObservationSourceKind::Uia,
        ) => {
            target.validate()?;
            validate_uia_target_binding(observation, &target, request)?;
            let automation = bounded_observation_text(&element.value, "automation_id")?
                .ok_or_else(|| {
                    DesktopError::AdapterUnavailable(
                        "selected UIA element has no AutomationId".to_owned(),
                    )
                })?;
            if operation == TrustedDesktopOperationKindV1::UiaSetValue
                && element
                    .value
                    .get("value_read_only")
                    .and_then(Value::as_bool)
                    != Some(false)
            {
                return Err(DesktopError::Precondition(
                    "selected UIA value target is read-only or unknown".to_owned(),
                ));
            }
            if operation == TrustedDesktopOperationKindV1::UiaToggle
                && !supported_pattern(&element.value, "uia.toggle.read")
            {
                return Err(DesktopError::Precondition(
                    "selected UIA target lacks toggle support".to_owned(),
                ));
            }
            Ok(ResolvedTargetMaterial::Uia {
                window: WindowIdentity {
                    process_id: target.process_id,
                    executable_hash: target.executable_hash,
                    title_hash: target.window_title_hash,
                },
                automation_id: automation,
            })
        }
        (
            TrustedTargetResolverInput::WebDriver {
                target,
                reviewed_css_locator,
            },
            TrustedTargetSourceKindV1::WebDriver,
            ObservationSourceKind::WebDriver,
        ) => {
            target.validate()?;
            validate_web_target_binding(observation, &target, request)?;
            let locator_id = parse_reviewed_css_id(&reviewed_css_locator)?;
            let hints = element
                .value
                .get("locator_hints")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    DesktopError::AdapterUnavailable(
                        "selected Web element has no trusted locator hints".to_owned(),
                    )
                })?;
            let expected_hint = format!("id:{locator_id}");
            let exact_hint_count = hints
                .iter()
                .filter(|hint| {
                    bounded_text_value(hint)
                        .is_some_and(|value| value.as_str() == expected_hint.as_str())
                })
                .count();
            if exact_hint_count != 1 {
                return Err(DesktopError::Precondition(
                    "reviewed Web locator is absent or ambiguous in observation".to_owned(),
                ));
            }
            Ok(ResolvedTargetMaterial::WebDriver {
                browser_session_id: target.browser_session_id,
                origin: target.expected_origin,
                locator: reviewed_css_locator,
            })
        }
        _ => Err(DesktopError::Integrity(
            "resolver, operation, and observation source kinds differ".to_owned(),
        )),
    }
}

fn resolve_input_proof(
    request: &TrustedExecutionBindingRequestV1,
    payload: Option<&EphemeralActionPayload>,
    now_unix_ms: u64,
) -> Result<Option<InputMaterialProofV1>, DesktopError> {
    let (kind, expected_hash) =
        expected_input(&request.policy_ready_action).map_err(contract_error)?;
    match (kind, expected_hash, payload) {
        (None, None, None) => Ok(None),
        (None, None, Some(_)) => Err(DesktopError::Invalid(
            "operation does not accept input bytes".to_owned(),
        )),
        (Some(kind), Some(expected_hash), Some(payload)) => {
            if now_unix_ms < payload.resolved_at_unix_ms
                || now_unix_ms >= payload.expires_at_unix_ms
            {
                return Err(DesktopError::AccessDenied(
                    "ephemeral input is not active".to_owned(),
                ));
            }
            let supplied_hash = payload.content_hash();
            let proof = InputMaterialProofV1 {
                schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
                material_id: derived_id("material", &supplied_hash)?,
                request_sha256: request.request_sha256.clone(),
                proposal_sha256: canonical_sha256(&request.policy_ready_action.proposal)
                    .map_err(contract_error)?,
                input_kind: kind,
                expected_content_sha256: expected_hash,
                supplied_content_sha256: supplied_hash,
                byte_length: u64::try_from(payload.bytes.len()).unwrap_or(u64::MAX),
                secret_classification: SecretClassificationV1::NonSecret,
                material_source_id: payload.material_source_id.clone(),
                resolved_at_unix_ms: payload.resolved_at_unix_ms,
                expires_at_unix_ms: payload.expires_at_unix_ms,
                evidence_ids: vec!["trusted-non-secret-input".to_owned()],
                material_proof_sha256: empty_hash(),
            }
            .seal()
            .map_err(contract_error)?;
            proof.validate_against(request).map_err(contract_error)?;
            Ok(Some(proof))
        }
        _ => Err(DesktopError::Invalid(
            "operation input requirement is incomplete".to_owned(),
        )),
    }
}

fn desktop_operation(
    request: &TrustedExecutionBindingRequestV1,
    operation: TrustedDesktopOperationKindV1,
    target: &ResolvedTargetMaterial,
    input: Option<&InputMaterialProofV1>,
) -> Result<DesktopOperation, DesktopError> {
    let action_input = action_input(&request.policy_ready_action).map_err(contract_error)?;
    let operation = match (operation, target, &action_input, input) {
        (
            TrustedDesktopOperationKindV1::UiaInvoke,
            ResolvedTargetMaterial::Uia {
                window,
                automation_id,
            },
            CandidateActionInput::Invoke,
            None,
        ) => DesktopOperation::UiInteract {
            window: window.clone(),
            interaction: UiInteraction::Invoke {
                automation_id: automation_id.clone(),
            },
        },
        (
            TrustedDesktopOperationKindV1::UiaSetValue,
            ResolvedTargetMaterial::Uia {
                window,
                automation_id,
            },
            CandidateActionInput::SetText { text_hash },
            Some(proof),
        ) if text_hash == &proof.expected_content_sha256 => DesktopOperation::UiInteract {
            window: window.clone(),
            interaction: UiInteraction::SetText {
                automation_id: automation_id.clone(),
                text_hash: text_hash.clone(),
                secret_ref: None,
            },
        },
        (
            TrustedDesktopOperationKindV1::UiaToggle,
            ResolvedTargetMaterial::Uia {
                window,
                automation_id,
            },
            CandidateActionInput::Toggle { desired },
            None,
        ) => DesktopOperation::UiInteract {
            window: window.clone(),
            interaction: UiInteraction::Toggle {
                automation_id: automation_id.clone(),
                desired: *desired,
            },
        },
        (
            TrustedDesktopOperationKindV1::WebDriverClick,
            ResolvedTargetMaterial::WebDriver {
                browser_session_id,
                origin,
                locator,
            },
            CandidateActionInput::Click,
            None,
        ) => DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.clone(),
            origin: origin.clone(),
            interaction: BrowserInteraction::Click {
                locator: locator.clone(),
            },
        },
        (
            TrustedDesktopOperationKindV1::WebDriverType,
            ResolvedTargetMaterial::WebDriver {
                browser_session_id,
                origin,
                locator,
            },
            CandidateActionInput::TypeText { text_hash },
            Some(proof),
        ) if text_hash == &proof.expected_content_sha256 => DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.clone(),
            origin: origin.clone(),
            interaction: BrowserInteraction::TypeText {
                locator: locator.clone(),
                text_hash: text_hash.clone(),
                secret_ref: None,
            },
        },
        (
            TrustedDesktopOperationKindV1::WebDriverSelect,
            ResolvedTargetMaterial::WebDriver {
                browser_session_id,
                origin,
                locator,
            },
            CandidateActionInput::Select { value_hash },
            Some(proof),
        ) if value_hash == &proof.expected_content_sha256 => DesktopOperation::BrowserInteract {
            browser_session_id: browser_session_id.clone(),
            origin: origin.clone(),
            interaction: BrowserInteraction::Select {
                locator: locator.clone(),
                value_hash: value_hash.clone(),
            },
        },
        _ => {
            return Err(DesktopError::Integrity(
                "closed Cognitive-to-Desktop mapping differs".to_owned(),
            ));
        }
    };
    operation.validate()?;
    Ok(operation)
}

fn target_material_sha256(target: &ResolvedTargetMaterial) -> Result<String, DesktopError> {
    let digest = match target {
        ResolvedTargetMaterial::Uia {
            window,
            automation_id,
        } => serde_json::json!({
            "kind": "uia",
            "window": window,
            "automation_id": automation_id
        }),
        ResolvedTargetMaterial::WebDriver {
            browser_session_id,
            origin,
            locator,
        } => serde_json::json!({
            "kind": "web_driver",
            "browser_session_id": browser_session_id,
            "origin": origin,
            "locator": locator
        }),
    };
    canonical_sha256(&digest).map_err(contract_error)
}

fn validate_uia_target_binding(
    observation: &ObservationSnapshot,
    target: &WindowsUiaObservationTarget,
    request: &TrustedExecutionBindingRequestV1,
) -> Result<(), DesktopError> {
    let binding = &observation.target_binding;
    if binding.get("source_kind").map(String::as_str) != Some("uia")
        || binding.get("integration_id").map(String::as_str)
            != Some(request.platform_activation.integration_id.as_str())
        || binding.get("binding_id").map(String::as_str)
            != Some(request.platform_activation.binding_id.as_str())
        || binding.get("activation_record_hash").map(String::as_str)
            != Some(request.platform_activation.activation_record_hash.as_str())
        || binding.get("runtime_binding_digest").map(String::as_str)
            != Some(target.runtime_binding_digest.as_str())
        || binding.get("process_id").map(String::as_str)
            != Some(target.process_id.to_string().as_str())
        || binding.get("executable_path").map(String::as_str)
            != Some(target.executable_path.as_str())
        || binding.get("executable_hash").map(String::as_str)
            != Some(target.executable_hash.as_str())
        || binding.get("window_title_hash").map(String::as_str)
            != Some(target.window_title_hash.as_str())
        || binding.get("session_id").map(String::as_str)
            != Some(target.session_id.to_string().as_str())
        || target.runtime_binding_digest != request.platform_activation.runtime_binding_sha256
    {
        return Err(DesktopError::Integrity(
            "UIA source target binding differs from activation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_web_target_binding(
    observation: &ObservationSnapshot,
    target: &WindowsWebObservationTarget,
    request: &TrustedExecutionBindingRequestV1,
) -> Result<(), DesktopError> {
    let binding = &observation.target_binding;
    if binding.get("source_kind").map(String::as_str) != Some("web_driver")
        || binding.get("integration_id").map(String::as_str)
            != Some(request.platform_activation.integration_id.as_str())
        || binding.get("binding_id").map(String::as_str)
            != Some(request.platform_activation.binding_id.as_str())
        || binding.get("activation_record_hash").map(String::as_str)
            != Some(request.platform_activation.activation_record_hash.as_str())
        || binding.get("runtime_binding_digest").map(String::as_str)
            != Some(target.runtime_binding_digest.as_str())
        || binding.get("browser_session_id").map(String::as_str)
            != Some(target.browser_session_id.as_str())
        || binding.get("expected_origin").map(String::as_str)
            != Some(target.expected_origin.as_str())
        || binding.get("edge_executable_hash").map(String::as_str)
            != Some(target.edge_driver_pin.browser_executable_hash.as_str())
        || binding
            .get("edge_driver_executable_hash")
            .map(String::as_str)
            != Some(target.edge_driver_pin.driver_executable_hash.as_str())
        || target.runtime_binding_digest != request.platform_activation.runtime_binding_sha256
    {
        return Err(DesktopError::Integrity(
            "Web source target binding differs from activation".to_owned(),
        ));
    }
    Ok(())
}

fn bounded_observation_text(
    element_value: &Value,
    field: &str,
) -> Result<Option<String>, DesktopError> {
    let Some(value) = element_value.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let text = bounded_text_value(value)
        .ok_or_else(|| DesktopError::Integrity(format!("observed {field} is not bounded text")))?;
    Ok(Some(text))
}

fn bounded_text_value(value: &Value) -> Option<String> {
    let text = value.get("text")?.as_str()?;
    let text_hash = value.get("text_hash")?.as_str()?;
    let truncated = value.get("truncated")?.as_bool()?;
    (!truncated && !text.is_empty() && canonical_sha256_bytes(text.as_bytes()) == text_hash)
        .then(|| text.to_owned())
}

fn supported_pattern(element_value: &Value, expected: &str) -> bool {
    element_value
        .get("supported_read_patterns")
        .and_then(Value::as_array)
        .is_some_and(|patterns| {
            patterns
                .iter()
                .any(|value| value.as_str() == Some(expected))
        })
}

fn parse_reviewed_css_id(locator: &str) -> Result<&str, DesktopError> {
    let id = locator.strip_prefix("css:#").ok_or_else(|| {
        DesktopError::AccessDenied(
            "trusted Web resolver permits reviewed CSS ID locators only".to_owned(),
        )
    })?;
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(DesktopError::AccessDenied(
            "reviewed CSS ID locator is outside the closed safe subset".to_owned(),
        ));
    }
    Ok(id)
}

fn append_audit(
    audit: &mut WindowsDeploymentAuditLedger,
    kind: WindowsDeploymentAuditEventKind,
    status: WindowsDeploymentAuditStatus,
    action_id: &str,
    artifact_hashes: BTreeMap<String, String>,
    now_unix_ms: u64,
) -> Result<(), DesktopError> {
    let event_token = match kind {
        WindowsDeploymentAuditEventKind::CognitiveBindingCreated => "binding-created",
        WindowsDeploymentAuditEventKind::TrustedTargetResolved => "target-resolved",
        WindowsDeploymentAuditEventKind::TrustedActionPrepared => "prepared",
        WindowsDeploymentAuditEventKind::CognitivePermitMinted => "permit-minted",
        WindowsDeploymentAuditEventKind::TrustedCommitStarted => "commit-started",
        WindowsDeploymentAuditEventKind::TrustedExecutionSucceeded => "succeeded",
        WindowsDeploymentAuditEventKind::TrustedExecutionFailed => "failed",
        WindowsDeploymentAuditEventKind::TrustedExecutionCancelled => "cancelled",
        WindowsDeploymentAuditEventKind::TrustedExecutionAborted => "aborted",
        _ => "trusted-execution",
    };
    let event_id = format!(
        "trusted-{event_token}-{}",
        audit.record_count().saturating_add(1)
    );
    let detail_hash = hash_value(&serde_json::json!({
        "action_id": action_id,
        "event": event_token,
        "status": status
    }))?;
    audit.append(WindowsDeploymentAuditEvent {
        schema_version: 1,
        event_id,
        kind,
        status,
        artifact_hashes,
        detail_hash,
        recorded_at_unix_ms: now_unix_ms.max(1),
    })?;
    Ok(())
}

fn cognitive_adapter_kind(kind: WindowsAdapterKind) -> Result<AdapterKindV1, DesktopError> {
    match kind {
        WindowsAdapterKind::UiAutomation => Ok(AdapterKindV1::Uia),
        WindowsAdapterKind::WebDriver => Ok(AdapterKindV1::WebDriver),
        WindowsAdapterKind::FileWrite | WindowsAdapterKind::Process => {
            Err(DesktopError::AdapterUnavailable(
                "trusted execution v1 supports UIA and WebDriver only".to_owned(),
            ))
        }
    }
}

fn desktop_capability(
    value: d2i_trusted_action_execution::TrustedDesktopCapabilityV1,
) -> DesktopCapability {
    match value {
        d2i_trusted_action_execution::TrustedDesktopCapabilityV1::UiInteract => {
            DesktopCapability::UiInteract
        }
        d2i_trusted_action_execution::TrustedDesktopCapabilityV1::BrowserInteract => {
            DesktopCapability::BrowserInteract
        }
    }
}

fn derived_id(prefix: &str, hash: &str) -> Result<String, DesktopError> {
    crate::validate_hash(hash, "derived trusted execution ID hash")?;
    Ok(format!("{prefix}-{}", &hash[7..31]))
}

fn empty_hash() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()
}

fn contract_error(error: d2i_trusted_action_execution::TrustedExecutionError) -> DesktopError {
    match error {
        d2i_trusted_action_execution::TrustedExecutionError::Invalid(message) => {
            DesktopError::Invalid(message)
        }
        d2i_trusted_action_execution::TrustedExecutionError::Integrity(message) => {
            DesktopError::Integrity(message)
        }
        d2i_trusted_action_execution::TrustedExecutionError::Unsupported(message) => {
            DesktopError::AdapterUnavailable(message)
        }
        d2i_trusted_action_execution::TrustedExecutionError::Replay(message) => {
            DesktopError::Replay(message)
        }
        d2i_trusted_action_execution::TrustedExecutionError::Json(message) => {
            DesktopError::Json(message)
        }
    }
}
