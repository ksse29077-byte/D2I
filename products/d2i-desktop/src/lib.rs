//! Policy-gated contracts and adapters for auditable desktop autonomy.

mod adapter;
mod approval;
mod audit;
mod case_instance;
mod cognitive;
mod cognitive_kernel_task;
mod cognitive_recovery;
mod cognitive_reobserve_verify;
mod cognitive_verification_v2;
mod contract;
mod executor;
mod policy;
mod role_instance;
mod trusted_execution;
mod windows_activation;
mod windows_adapters;
mod windows_attestation;
mod windows_binding;
mod windows_deployment_audit;
mod windows_egress;
mod windows_keys;
mod windows_observation;
mod windows_observation_worker;
mod windows_post_activation_self_test;
mod windows_webdriver;
mod windows_wfp_broker;
mod windows_wfp_broker_runtime;
mod windows_wfp_self_test;
mod windows_worker;
mod work_intake;

pub use adapter::{
    ActionOutcome, ActionOutcomeStatus, AdapterExecution, DesktopAdapter, DesktopAdapterDescriptor,
    LocalReadOnlyDesktopAdapter, OfflineConformanceDesktopAdapter, PreparedAction,
    UnavailableDesktopAdapter,
};
pub use approval::{sign_approval, ExecutionPermit, HumanApproval};
pub use audit::{
    initialize_audit_ledger, replay_audit, verify_audit_ledger, AuditEvent, AuditEventKind,
    AuditLedger, AuditReplayExpectation, AuditReplayReport, AuditVerification,
};
pub use case_instance::{
    initialize_case_ledger, persist_new_case, verify_case_ledger, CaseKernelArtifactsV1,
    CaseLedgerEventKindV1, CaseLedgerRecordV1, CaseLedgerV1, CaseLedgerVerificationV1,
    WorkCaseCoordinatorV1,
};
pub use cognitive::{
    ActionCandidateProvider, ActionExecution, ActionExecutor, ActionPolicyEvaluator,
    ActionProposal, ActivationGate, AuditOutcome, CapabilityDescriptor, CapabilityRegistry,
    CognitiveAuditEvent, CognitiveAuditSink, CognitiveExecutor, CognitiveExecutorConfig,
    CognitiveIrBundle, CognitiveRecoveryKind, CognitiveRiskClass, CognitiveTiming, ComparisonOp,
    ConfirmationPolicy, ConfirmationRequirement, ExecutionStatus, GoalProgress, GoalSpec,
    ObservableElement, ObservationProvider, ObservationSnapshot, ObservationSourceKind, PlanEdge,
    PlanEdgeKind, PlanGraph, PlanNode, PlanNodeKind, Postcondition, PostconditionResult,
    PostconditionVerifier, Provenance, RecoveryDecision, RecoveryPolicy, RedactionMetadata,
    Reversibility, TrustLabel, VerificationResult, WorkReport, WorldFact, WorldFactKind,
    WorldState, WorldStateReducer,
};
pub use cognitive_kernel_task::{
    parse_authenticated_task_instruction_v1, ActionCycleRecordV1, AuthenticatedTaskInstructionV1,
    CognitiveKernelTaskRuntimeV1, FinalCriterionResultV1, FinalGoalVerificationV1,
    FinalVerificationVerdictV1, KernelFinalOutcomeV1, KernelTaskRunRecordV1,
    KernelTaskRuntimeStateV1, KernelTaskStageRecordV1, KernelTaskStageStatusV1,
    ModuleHostBindingV1, ModuleInvocationCoordinatorV1, ModuleInvocationRecordV1,
    ModuleInvocationTerminalStatusV1, KERNEL_TASK_RUNTIME_BUILD_ID, KERNEL_TASK_SCHEMA_VERSION,
};
pub use cognitive_recovery::{
    initialize_recovery_ledger, verify_recovery_ledger, CognitiveRecoveryCoordinatorStateV1,
    CognitiveRecoveryCoordinatorV1, RecoveryLedgerEventKindV1, RecoveryLedgerRecordV1,
    RecoveryLedgerV1, RecoveryLedgerVerificationV1,
};
pub use cognitive_reobserve_verify::{
    analyze_observation_delta, bind_actual_source_observation, parse_reobserve_json,
    CognitiveReobserveCoordinator, CognitiveVerificationCoordinatorV2,
    DeterministicPostconditionVerifierV2, FreshObservationBundleV1, FreshObservationProofV1,
    FreshObservationWorkerExitStatusV1, IgnoredVolatileTargetV1, ObservationDeltaKindV1,
    ObservationDeltaV1, ObservationElementDeltaV1, ProtectedInvariantSeverityV1,
    ProtectedInvariantV1, ReobservationPolicyV1, ReobservationRequestV1,
    TrustedReadOnlyObservationConfiguration, VerificationConsumptionLedgerV1,
    VerificationGuardFieldV1, VerificationGuardProfileV1, VerificationGuardTargetV1,
    VerificationSpecAdaptationV1, VerificationSpecAdapterV1, VerificationSpecBindingV1,
    VerifiedActionResultV1, COGNITIVE_REOBSERVE_SCHEMA_VERSION,
    COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA,
};
pub use cognitive_verification_v2::{
    BoundActionExecutionV2, PostconditionResultV2, PostconditionVerifierV2,
    VerifiableObservationFieldV2, VerifiablePostconditionV2, VerificationActionProposalV2,
    VerificationConfidenceV2, VerificationGoalSpecV2, VerificationRequestV2, VerificationResultV2,
    VerificationTargetV2, VerificationVerdictV2,
};
pub use contract::{
    BrowserInteraction, DesktopActionIntent, DesktopCapability, DesktopOperation, RiskClass,
    UiInteraction, WindowIdentity,
};
pub use d2i_action_candidates::{
    bridge_fixture_action_candidate, ActionCandidateBridgeRequest, ActionCandidateError,
    ActionCapabilityBinding, CandidateActionArguments, CandidateActionInput, CandidateActionKind,
    CandidateTargetBinding, CapabilityBoundActionProposal, ACTION_CANDIDATE_PROVIDER_V1_SCHEMA,
    ACTION_CANDIDATE_SCHEMA_VERSION,
};
pub use d2i_application_semantics::{
    bridge_observation_fixture, build_element_grounder_payload, ApplicationPack,
    ApplicationPackProvenance, ApplicationSemanticTarget, ApplicationSemanticsError,
    BridgedGroundingCase, ElementGrounderBridgeRequest, ElementGrounderPayload, ObservationFixture,
    ObservationFixtureBridge, ObservationGroundingCase, APPLICATION_SEMANTICS_SCHEMA_VERSION,
    APPLICATION_SEMANTICS_V1_SCHEMA, ELEMENT_GROUNDER_INPUT_SCHEMA_ID,
    ELEMENT_GROUNDER_INPUT_SCHEMA_VERSION,
};
pub use d2i_cognitive_recovery::{
    classify_recovery_trigger, decide_recovery, project_legacy_decision,
    AlternateCapabilityGroupV1, ClarificationAnswerV1, ClarificationQuestionCodeV1,
    ClarificationQuestionKindV1, ClarificationRequestV1, ClarificationResponseV1,
    DeterministicFixtureReplanner, EscalationRequestV1, EscalationSeverityV1,
    FreshRecoveryCycleEvidenceV1, FreshRecoveryCycleRequestV1, FreshRecoveryStrategyV1,
    RecommendedNextActionCodeV1, RecoveryAuthorityImpactV1, RecoveryBudgetV1,
    RecoveryClassificationV1, RecoveryCycleOutcomeV1, RecoveryCycleResultV1,
    RecoveryDecisionContextV1, RecoveryDecisionKindV1, RecoveryDecisionV1, RecoveryError,
    RecoveryFailureClassV1, RecoveryHistoryEntryV1, RecoveryHistoryOutcomeV1, RecoveryHistoryV1,
    RecoveryInformationGapV1, RecoveryPolicyProfileV1, RecoveryReasonCodeV1,
    RecoveryRetryabilityV1, RecoverySafetySeverityV1, RecoveryStageV1, RecoveryTriggerV1,
    RecoveryVerificationVerdictV1, ReplanConstraintCodeV1, ReplanRationaleCodeV1, ReplanRequestV1,
    ReplanResultV1, RequiredAuthorityClassV1, SafeStateSummaryCodeV1,
    COGNITIVE_RECOVERY_CONTROL_V1_SCHEMA, MAX_RECOVERY_CYCLES, RECOVERY_SCHEMA_VERSION,
};
pub use d2i_trusted_action_execution::{
    canonical_sha256 as trusted_execution_sha256, expected_input as trusted_expected_input,
    grounded_target_binding_sha256, operation_kind as trusted_operation_kind, BoundDesktopActionV1,
    InputMaterialKindV1, InputMaterialProofV1, PolicyReadyActionV1, PreparedBoundActionV1,
    SecretClassificationV1, TargetResolutionProofV1, TrustedActionExecutionReceiptV1,
    TrustedAdapterOutcomeStatusV1, TrustedDesktopCapabilityV1, TrustedDesktopOperationKindV1,
    TrustedExecutionBindingRequestV1, TrustedExecutionError, TrustedExecutionSessionV1,
    TrustedExecutionStatusV1, TrustedPlatformActivationV1, TrustedTargetSourceKindV1,
    TRUSTED_ACTION_EXECUTION_BINDING_V1_SCHEMA, TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
pub use executor::{DesktopActionPreparation, DesktopExecutor};
pub use policy::{
    evaluate_policy, AllowedExecutable, DesktopActor, DesktopPolicy, PolicyDecision,
    PolicyDecisionStatus,
};
pub use role_instance::{
    initialize_role_instance_ledger, verify_role_instance_ledger, RoleInstanceLedgerEventKindV1,
    RoleInstanceLedgerRecordV1, RoleInstanceLedgerV1, RoleInstanceLedgerVerificationV1,
};
pub use trusted_execution::{
    build_cognitive_desktop_action_intent, project_windows_activation,
    to_verification_bound_execution_v2, validate_cognitive_desktop_action_intent,
    CognitiveTrustedExecutionCoordinator, EphemeralActionPayload, ResolvedTargetMaterial,
    TrustedDesktopExecutionPlan, TrustedTargetResolverInput,
};
pub use windows_activation::{
    activate_certified_windows_binding, initialize_windows_activation_ledger,
    verify_windows_activation_ledger, ActivatedWindowsBinding, WindowsActivationAdmission,
    WindowsActivationLedgerPolicy, WindowsActivationLedgerVerification, WindowsActivationRecord,
};
pub use windows_adapters::{
    WindowsFileWriteAdapter, WindowsProcessAdapter, WindowsUiAutomationAdapter,
    WindowsWebDriverAdapter,
};
pub use windows_attestation::{
    create_windows_wfp_functional_attestation_v2,
    verify_windows_wfp_functional_attestation_context_v2,
    verify_windows_wfp_functional_attestation_v2, SignedWindowsWfpFunctionalAttestationV2,
    WindowsWfpFunctionalAttestationInputV2, WindowsWfpIpv6EgressResult,
    WINDOWS_WFP_REPORT_MAX_AGE_SECONDS,
};
pub use windows_binding::{
    certify_windows_binding, create_windows_binding_evidence,
    create_windows_browser_egress_evidence, current_windows_host_binding,
    verify_signed_windows_certification, ConcreteWindowsRuntimeBindingProbe,
    SignedWindowsBrowserEgressEvidence, SignedWindowsCertification, WindowsAdapterConfiguration,
    WindowsAdapterKind, WindowsBindingCertification, WindowsBindingEvidence, WindowsBindingInput,
    WindowsBrowserEgressInput, WindowsBrowserEgressRequirement, WindowsCapabilityObservation,
    WindowsCertificationIssue, WindowsCertificationReport, WindowsHostBinding,
    WindowsProcessIsolation, WindowsRuntimeBindingProbe, WindowsRuntimeManifest,
    WindowsWfpBrowserEgressPolicy,
};
pub use windows_deployment_audit::{
    initialize_windows_deployment_audit, verify_windows_deployment_audit,
    WindowsDeploymentAuditEvent, WindowsDeploymentAuditEventKind, WindowsDeploymentAuditLedger,
    WindowsDeploymentAuditStatus, WindowsDeploymentAuditVerification,
};
pub use windows_egress::{
    attest_windows_wfp_browser_egress, create_windows_wfp_browser_egress_policy,
    install_windows_wfp_browser_egress, remove_windows_wfp_browser_egress,
    run_windows_wfp_verifier_worker, verify_windows_wfp_browser_egress,
    verify_windows_wfp_browser_egress_runtime, WindowsWfpBrowserEgressObservation,
};
pub use windows_keys::{
    protect_windows_signing_key, unprotect_windows_signing_key, WindowsProtectedSigningKey,
    WindowsSigningKeyPurpose,
};
pub use windows_observation::{
    CompletedReadOnlyObservation, ObservationLimits, WindowsUiaObservationProvider,
    WindowsUiaObservationTarget, WindowsWebObservationProvider, WindowsWebObservationTarget,
};
pub use windows_post_activation_self_test::{
    run_windows_webdriver_post_activation_self_test, WindowsWebDriverPostActivationSelfTestReport,
};
pub use windows_webdriver::{create_windows_edge_driver_pin, WindowsEdgeDriverPin};
pub use windows_wfp_broker::{
    create_signed_wfp_verification_receipt, protect_wfp_verifier_signing_key,
    unprotect_wfp_verifier_signing_key, verify_wfp_verification_receipt_signature,
    SignedWfpVerificationReceipt, WfpExpectedObjectGuids, WfpObjectVerificationResult,
    WfpReceiptReplayLedger, WfpVerificationRequest, WfpVerificationStatus, WfpVerifierOperation,
    WindowsProtectedWfpVerifierKey, WindowsWfpVerifierBrokerBinding,
    WindowsWfpVerifierBrokerServiceConfiguration, WINDOWS_WFP_FILTER_GUIDS,
    WINDOWS_WFP_PROVIDER_GUID, WINDOWS_WFP_SUBLAYER_GUID,
    WINDOWS_WFP_VERIFIER_NETWORK_FILTER_GUIDS,
};
pub use windows_wfp_broker_runtime::{
    configure_windows_wfp_verifier_broker, provision_windows_wfp_verifier_broker,
    remove_windows_wfp_verifier_broker_artifacts, run_windows_wfp_broker_client_worker,
    run_windows_wfp_verifier_broker_service, verify_windows_wfp_browser_egress_through_broker,
    WindowsWfpBrokerRuntimeVerification,
};
pub use windows_wfp_self_test::{
    run_windows_wfp_browser_egress_self_test, WindowsWfpBrowserEgressSelfTestReport,
    WindowsWfpConnectionEvent, WindowsWfpConnectionOutcome, WindowsWfpNetworkProbe,
    WindowsWfpProbeDisposition, WindowsWfpProbeServerTelemetry, WindowsWfpSelfTestCleanup,
};
pub use work_intake::{
    initialize_work_intake_ledger, verify_work_intake_ledger, WorkIntakeLedgerEventKindV1,
    WorkIntakeLedgerRecordV1, WorkIntakeLedgerV1, WorkIntakeLedgerVerificationV1,
};

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;

const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACTION_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Structured desktop-autonomy failure.
#[derive(Debug)]
pub enum DesktopError {
    Invalid(String),
    Integrity(String),
    AccessDenied(String),
    Approval(String),
    AdapterUnavailable(String),
    Precondition(String),
    Replay(String),
    Json(String),
    Io { path: String, message: String },
}

impl Display for DesktopError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid desktop artifact: {message}"),
            Self::Integrity(message) => write!(formatter, "integrity failure: {message}"),
            Self::AccessDenied(message) => write!(formatter, "access denied: {message}"),
            Self::Approval(message) => write!(formatter, "approval failure: {message}"),
            Self::AdapterUnavailable(message) => {
                write!(formatter, "adapter unavailable: {message}")
            }
            Self::Precondition(message) => write!(formatter, "precondition failure: {message}"),
            Self::Replay(message) => write!(formatter, "replay failure: {message}"),
            Self::Json(message) => write!(formatter, "JSON failure: {message}"),
            Self::Io { path, message } => write!(formatter, "I/O failure at {path}: {message}"),
        }
    }
}

impl Error for DesktopError {}

impl From<d2i_cognitive_ir::CognitiveIrError> for DesktopError {
    fn from(error: d2i_cognitive_ir::CognitiveIrError) -> Self {
        match error {
            d2i_cognitive_ir::CognitiveIrError::Invalid(message) => Self::Invalid(message),
            d2i_cognitive_ir::CognitiveIrError::Integrity(message) => Self::Integrity(message),
            d2i_cognitive_ir::CognitiveIrError::AccessDenied(message) => {
                Self::AccessDenied(message)
            }
            d2i_cognitive_ir::CognitiveIrError::Json(message) => Self::Json(message),
        }
    }
}

impl From<d2i_cognitive_recovery::RecoveryError> for DesktopError {
    fn from(error: d2i_cognitive_recovery::RecoveryError) -> Self {
        match error {
            d2i_cognitive_recovery::RecoveryError::Invalid(message) => Self::Invalid(message),
            d2i_cognitive_recovery::RecoveryError::Integrity(message) => Self::Integrity(message),
            d2i_cognitive_recovery::RecoveryError::AccessDenied(message) => {
                Self::AccessDenied(message)
            }
            d2i_cognitive_recovery::RecoveryError::Unsupported(message) => {
                Self::AdapterUnavailable(message)
            }
            d2i_cognitive_recovery::RecoveryError::Json(message) => Self::Json(message),
        }
    }
}

fn json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let bytes = serde_json::to_vec(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    if bytes.len() > MAX_JSON_BYTES {
        return Err(DesktopError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn pretty_json_bytes<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, DesktopError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| DesktopError::Json(error.to_string()))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_JSON_BYTES {
        return Err(DesktopError::Invalid(format!(
            "serialized artifact exceeds {MAX_JSON_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn hash_value<T: serde::Serialize>(value: &T) -> Result<String, DesktopError> {
    Ok(sha256_bytes(&json_bytes(value)?))
}

fn validate_text(value: &str, field: &str) -> Result<(), DesktopError> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(DesktopError::Invalid(format!(
            "{field} is empty, contains NUL, or exceeds bounds"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<(), DesktopError> {
    validate_text(value, field)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
    }) {
        return Err(DesktopError::Invalid(format!(
            "{field} contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> Result<(), DesktopError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(DesktopError::Invalid(format!(
            "{field} must use sha256:<hex>"
        )));
    };
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Invalid(format!(
            "{field} has invalid SHA-256 syntax"
        )));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, DesktopError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(DesktopError::Integrity(
            "artifact must be a bounded regular file".to_owned(),
        ));
    }
    std::fs::read(path).map_err(|error| DesktopError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), DesktopError> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| DesktopError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str) -> Result<[u8; N], DesktopError> {
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DesktopError::Approval(
            "hex signature or key length is invalid".to_owned(),
        ));
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *slot = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|error| DesktopError::Approval(error.to_string()))?;
    }
    Ok(output)
}

/// Runs the private framed-protocol worker used by certified Windows adapters.
///
/// This is exposed only so the package binary can enter worker mode. It is not
/// a stable integration API and accepts no command-line or network requests.
#[doc(hidden)]
pub fn run_windows_adapter_worker() -> Result<(), DesktopError> {
    windows_worker::run_windows_worker_stdio()
}
