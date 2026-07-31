#![cfg(windows)]

use d2i_action_candidates::{
    CandidateActionArguments, CandidateActionInput, CandidateTargetBinding,
};
use d2i_cognitive_ir::{
    ActionProposal, CognitiveRiskClass, ComparisonOp, ConfirmationPolicy, ConfirmationRequirement,
    GoalSpec, ObservableElement, ObservationSnapshot, ObservationSourceKind, Postcondition,
    Provenance, Reversibility, TrustLabel,
};
use d2i_desktop::{
    activate_certified_windows_binding, analyze_observation_delta, bind_actual_source_observation,
    certify_windows_binding, initialize_windows_activation_ledger,
    initialize_windows_deployment_audit, project_windows_activation,
    to_verification_bound_execution_v2, trusted_execution_sha256,
    verify_signed_windows_certification, verify_windows_activation_ledger,
    verify_windows_deployment_audit, AlternateCapabilityGroupV1,
    CognitiveRecoveryCoordinatorStateV1, CognitiveRecoveryCoordinatorV1,
    CognitiveTrustedExecutionCoordinator, CognitiveVerificationCoordinatorV2,
    ConcreteWindowsRuntimeBindingProbe, DeterministicPostconditionVerifierV2,
    EphemeralActionPayload, EscalationRequestV1, EscalationSeverityV1, ExecutionStatus,
    FreshObservationProofV1, FreshObservationWorkerExitStatusV1, FreshRecoveryCycleEvidenceV1,
    FreshRecoveryCycleRequestV1, GoalProgress, IgnoredVolatileTargetV1, ObservationLimits,
    PolicyReadyActionV1, PostconditionVerifierV2, ProtectedInvariantSeverityV1,
    ProtectedInvariantV1, RecommendedNextActionCodeV1, RecoveryBudgetV1, RecoveryDecisionContextV1,
    RecoveryDecisionKindV1, RecoveryFailureClassV1, RecoveryHistoryEntryV1,
    RecoveryHistoryOutcomeV1, RecoveryHistoryV1, RecoveryPolicyProfileV1, RecoveryReasonCodeV1,
    RecoveryStageV1, RecoveryTriggerV1, RecoveryVerificationVerdictV1, ReobservationRequestV1,
    RequiredAuthorityClassV1, SafeStateSummaryCodeV1, TrustedExecutionBindingRequestV1,
    TrustedExecutionSessionV1, TrustedExecutionStatusV1, TrustedReadOnlyObservationConfiguration,
    TrustedTargetResolverInput, VerificationConsumptionLedgerV1, VerificationGuardFieldV1,
    VerificationGuardProfileV1, VerificationGuardTargetV1, VerificationRequestV2,
    VerificationSpecAdapterV1, VerificationVerdictV2, WindowsActivationAdmission,
    WindowsAdapterConfiguration, WindowsAdapterKind, WindowsRuntimeBindingProbe,
    WindowsRuntimeManifest, WindowsUiAutomationAdapter, WindowsUiaObservationProvider,
    WindowsUiaObservationTarget, COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA, RECOVERY_SCHEMA_VERSION,
    TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
use d2i_policy_admission::{
    admit_action, evaluate_policy, ActivationEligibilityContextV1, AdapterKindV1,
    AdmissionIssuanceV1, AuthorityScopeConstraintsV1, DelegatedAuthorityContextV1,
    GrantConsumptionLedgerV1, PolicyEvaluationRequestV1, RequestedAutonomyModeV1,
    TrustedPolicySnapshotV1, TrustedPolicyStateV1, POLICY_ADMISSION_SCHEMA_VERSION,
};
use ed25519_dalek::SigningKey;
use jsonschema::{Draft, JSONSchema};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static UIA_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "d2i-trusted-execution-{}-{sequence}",
            std::process::id()
        ));
        ok(fs::create_dir(&path));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn lock_uia_fixture() -> MutexGuard<'static, ()> {
    ok(UIA_FIXTURE_LOCK.lock())
}

fn assert_reobserve_schema<T: Serialize>(artifact: &T) {
    let schema: Value = ok(serde_json::from_str(COGNITIVE_REOBSERVE_VERIFIER_V2_SCHEMA));
    let compiled = ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema));
    let instance = ok(serde_json::to_value(artifact));
    assert!(
        compiled.is_valid(&instance),
        "artifact does not satisfy the reobserve verifier schema: {instance}"
    );
}

fn sha(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn digest(label: &str) -> String {
    ok(trusted_execution_sha256(&label))
}

fn empty_hash() -> String {
    sha(&[])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn now_seconds() -> u64 {
    ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_secs()
}

fn worker_identity() -> (String, String) {
    let path = ok(fs::canonicalize(env!("CARGO_BIN_EXE_d2i-desktop")));
    let hash = sha(&ok(fs::read(&path)));
    (path.display().to_string(), hash)
}

fn configuration(executable_hash: &str) -> WindowsAdapterConfiguration {
    let (worker_executable, worker_executable_hash) = worker_identity();
    WindowsAdapterConfiguration {
        schema_version: 1,
        adapter_kind: WindowsAdapterKind::UiAutomation,
        worker_executable,
        worker_executable_hash,
        request_timeout_ms: 10_000,
        active_process_limit: 1,
        per_process_memory_bytes: 256 * 1024 * 1024,
        write_roots: Vec::new(),
        webdriver_endpoint: None,
        browser_session_ids: BTreeSet::new(),
        browser_allowed_origins: BTreeSet::new(),
        browser_egress_policy: None,
        deployment_audit_root: None,
        ui_allowed_executable_hashes: BTreeSet::from([executable_hash.to_owned()]),
        process_isolation: None,
    }
}

fn certified_admission(
    configuration: &WindowsAdapterConfiguration,
    temp: &TempDirectory,
    observed_at: u64,
) -> (WindowsActivationAdmission, u32) {
    certified_admission_labeled(configuration, temp, observed_at, "execution")
}

fn certified_admission_labeled(
    configuration: &WindowsAdapterConfiguration,
    temp: &TempDirectory,
    observed_at: u64,
    label: &str,
) -> (WindowsActivationAdmission, u32) {
    let attestor_key = SigningKey::from_bytes(&[71_u8; 32]);
    let certifier_key = SigningKey::from_bytes(&[72_u8; 32]);
    let integration_id = "windows-trusted-execution".to_owned();
    let probe = ok(ConcreteWindowsRuntimeBindingProbe::new(
        configuration.clone(),
        format!("binding-trusted-execution-{label}"),
        integration_id.clone(),
        observed_at,
        observed_at + 600,
        "runtime-attestor".to_owned(),
        attestor_key.clone(),
    ));
    let evidence = ok(probe.collect_binding_evidence());
    let session_id = evidence.host.session_id;
    let manifest = WindowsRuntimeManifest {
        schema_version: 1,
        integration_id,
        adapter_kind: WindowsAdapterKind::UiAutomation,
        adapter_descriptor: ok(configuration.descriptor()),
        configuration_hash: ok(configuration.configuration_hash()),
        worker_executable_hash: configuration.worker_executable_hash.clone(),
        process_isolation: None,
        browser_egress_requirement: None,
        host: evidence.host.clone(),
        interactive_session_required: true,
        binding_attestor_id: "runtime-attestor".to_owned(),
        binding_attestor_public_key: hex(&attestor_key.verifying_key().to_bytes()),
        certifier_id: "release-certifier".to_owned(),
        certifier_public_key: hex(&certifier_key.verifying_key().to_bytes()),
    };
    let result = ok(certify_windows_binding(
        &manifest,
        &evidence,
        format!("certificate-trusted-execution-{label}"),
        "release-certifier".to_owned(),
        &certifier_key,
        observed_at + 1,
    ));
    assert!(result.report.certified, "{:?}", result.report.issues);
    let certification = result
        .signed_certification
        .unwrap_or_else(|| panic!("certification signature is absent"));
    let certified = ok(verify_signed_windows_certification(
        &manifest,
        &evidence,
        &certification,
        observed_at + 2,
    ));
    let ledger_root = temp.path().join(format!("activation-ledger-{label}"));
    let initialized = ok(initialize_windows_activation_ledger(
        &ledger_root,
        "trusted-execution-ledger",
        &manifest,
        BTreeSet::from(["trusted-execution-activator".to_owned()]),
        8,
    ));
    assert_eq!(initialized.entry_count, 0);
    let admission = ok(activate_certified_windows_binding(
        &ledger_root,
        "trusted-execution-activator",
        certified,
        observed_at + 2,
    ));
    assert_eq!(admission.verification.entry_count, 1);
    assert_eq!(
        ok(verify_windows_activation_ledger(&ledger_root)).chain_head,
        admission.verification.chain_head
    );
    (admission, session_id)
}

fn postcondition() -> Postcondition {
    Postcondition {
        target_state: "profile.name".to_owned(),
        op: ComparisonOp::Equals,
        expected_value: json!("hash-only"),
        required: true,
        timeout_ms: 5_000,
    }
}

fn source_observation(
    activation: &d2i_desktop::TrustedPlatformActivationV1,
    target: &WindowsUiaObservationTarget,
) -> ObservationSnapshot {
    let mut trust_labels = BTreeSet::new();
    trust_labels.insert(TrustLabel::ObservedUiState);
    trust_labels.insert(TrustLabel::UntrustedDocumentContent);
    let automation_id = "D2IText";
    let mut observation = ObservationSnapshot {
        schema_version: 1,
        observation_id: "trusted-uia-observation-1".to_owned(),
        source_kind: ObservationSourceKind::Uia,
        target_binding: BTreeMap::from([
            ("source_kind".to_owned(), "uia".to_owned()),
            (
                "integration_id".to_owned(),
                activation.integration_id.clone(),
            ),
            ("binding_id".to_owned(), activation.binding_id.clone()),
            (
                "activation_record_hash".to_owned(),
                activation.activation_record_hash.clone(),
            ),
            (
                "runtime_binding_digest".to_owned(),
                target.runtime_binding_digest.clone(),
            ),
            ("process_id".to_owned(), target.process_id.to_string()),
            ("executable_path".to_owned(), target.executable_path.clone()),
            ("executable_hash".to_owned(), target.executable_hash.clone()),
            (
                "window_title_hash".to_owned(),
                target.window_title_hash.clone(),
            ),
            ("session_id".to_owned(), target.session_id.to_string()),
        ]),
        state_hash: empty_hash(),
        sequence: 11,
        trust_labels: trust_labels.clone(),
        observable_elements: vec![ObservableElement {
            element_id: "uia-text-element".to_owned(),
            kind: "uia.edit".to_owned(),
            label: "Fixture text".to_owned(),
            value: json!({
                "automation_id": {
                    "text": automation_id,
                    "text_hash": sha(automation_id.as_bytes()),
                    "truncated": false
                },
                "enabled": true,
                "value_read_only": false,
                "supported_read_patterns": ["uia.value.read"]
            }),
            trust_labels,
        }],
        redactions: Vec::new(),
        provenance: Provenance {
            source: "trusted local UIA fixture".to_owned(),
            source_hash: digest("source-observation"),
            module_id: "windows-observation-plane".to_owned(),
        },
    };
    observation.state_hash = ok(observation.compute_state_hash());
    ok(observation.validate());
    observation
}

fn goal() -> GoalSpec {
    GoalSpec {
        schema_version: 1,
        goal_id: "goal-trusted-execution".to_owned(),
        objective: "Set one local fixture value".to_owned(),
        scope: BTreeMap::from([("fixture".to_owned(), json!("windows-uia"))]),
        required_outcomes: vec!["adapter action attempted".to_owned()],
        constraints: vec!["non-secret reversible local action".to_owned()],
        success_criteria: vec![postcondition()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "trusted execution integration fixture".to_owned(),
            source_hash: digest("goal-source"),
            module_id: "trusted-execution-test".to_owned(),
        },
    }
}

fn policy_ready(observation: &ObservationSnapshot, payload: &[u8]) -> PolicyReadyActionV1 {
    policy_ready_for_target(
        observation,
        payload,
        "uia-text-element",
        "uia.edit",
        postcondition(),
    )
}

fn policy_ready_for_target(
    observation: &ObservationSnapshot,
    payload: &[u8],
    element_id: &str,
    element_kind: &str,
    expected_postcondition: Postcondition,
) -> PolicyReadyActionV1 {
    policy_ready_for_target_labeled(
        observation,
        payload,
        element_id,
        element_kind,
        expected_postcondition,
        "trusted-execution",
    )
}

fn policy_ready_for_target_labeled(
    observation: &ObservationSnapshot,
    payload: &[u8],
    element_id: &str,
    element_kind: &str,
    expected_postcondition: Postcondition,
    label: &str,
) -> PolicyReadyActionV1 {
    let target = CandidateTargetBinding {
        application_pack_sha256: digest("application-pack"),
        observation_bridge_sha256: digest("observation-bridge"),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        grounding_case_id: format!("grounding-case-{label}"),
        semantic_target_id: "profile.name".to_owned(),
        element_id: element_id.to_owned(),
        element_kind: element_kind.to_owned(),
        capability_binding_sha256: digest("capability-binding"),
    };
    let arguments = CandidateActionArguments {
        schema_version: 1,
        operation: "uia.set_value".to_owned(),
        target,
        input: CandidateActionInput::SetText {
            text_hash: sha(payload),
        },
    };
    ok(arguments.validate());
    let proposal = ActionProposal {
        schema_version: 1,
        proposal_id: format!("proposal-{label}"),
        goal_id: "goal-trusted-execution".to_owned(),
        plan_generation_id: format!("plan-{label}"),
        source_observation_hash: observation.state_hash.clone(),
        capability_id: "uia.set_value".to_owned(),
        semantic_target: "profile.name".to_owned(),
        arguments: ok(serde_json::to_value(arguments)),
        preconditions: Vec::new(),
        expected_postconditions: vec![expected_postcondition.clone()],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["trusted fixture".to_owned()],
        valid_until_sequence: observation.sequence,
    };
    let mut ready = PolicyReadyActionV1 {
        schema_version: 1,
        selection_id: format!("selection-{label}"),
        selection_sha256: digest(&format!("selection-{label}")),
        candidate_set_sha256: digest(&format!("candidate-set-{label}")),
        goal_id: proposal.goal_id.clone(),
        world_state_id: format!("world-{label}"),
        plan_generation_id: proposal.plan_generation_id.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        application_pack_sha256: digest("application-pack"),
        grounding_result_sha256: digest(&format!("grounding-result-{label}")),
        semantic_target_id: proposal.semantic_target.clone(),
        selected_element_id: element_id.to_owned(),
        selected_element_kind: element_kind.to_owned(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: digest("capability-binding"),
        proposal,
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        expected_postconditions: vec![expected_postcondition],
        evidence_ids: vec![
            format!("grounding-result-{label}"),
            format!("selection-result-{label}"),
        ],
        policy_input_sha256: digest(&format!("policy-input-{label}")),
        policy_ready_sha256: empty_hash(),
    };
    ready.policy_ready_sha256 = ok(ready.compute_policy_ready_sha256());
    ready
}

fn policy_artifacts(
    ready: PolicyReadyActionV1,
    activation: &d2i_desktop::TrustedPlatformActivationV1,
    now: u64,
) -> (
    d2i_policy_admission::CognitiveActivationAdmissionV1,
    ActivationEligibilityContextV1,
) {
    policy_artifacts_for_goal(ready, activation, now, goal())
}

fn policy_artifacts_for_goal(
    ready: PolicyReadyActionV1,
    activation: &d2i_desktop::TrustedPlatformActivationV1,
    now: u64,
    goal: GoalSpec,
) -> (
    d2i_policy_admission::CognitiveActivationAdmissionV1,
    ActivationEligibilityContextV1,
) {
    policy_artifacts_for_goal_labeled(ready, activation, now, goal, "trusted-execution")
}

fn policy_artifacts_for_goal_labeled(
    ready: PolicyReadyActionV1,
    activation: &d2i_desktop::TrustedPlatformActivationV1,
    now: u64,
    goal: GoalSpec,
    label: &str,
) -> (
    d2i_policy_admission::CognitiveActivationAdmissionV1,
    ActivationEligibilityContextV1,
) {
    let capability = ready.capability_id.clone();
    let authority = ok(DelegatedAuthorityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        authority_id: "authority-trusted-execution".to_owned(),
        organization_id: "organization-1".to_owned(),
        actor_id: "actor-1".to_owned(),
        role_id: "role-1".to_owned(),
        policy_set_id: "policy-set-1".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("policy-set"),
        allowed_capability_ids: vec![capability.clone()],
        forbidden_capability_ids: Vec::new(),
        autonomous_capability_ids: vec![capability.clone()],
        confirmation_capability_ids: Vec::new(),
        maximum_autonomous_risk: CognitiveRiskClass::Reversible,
        maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
        allowed_application_pack_sha256: ready.application_pack_sha256.clone(),
        allowed_integration_ids: vec![activation.integration_id.clone()],
        scope_constraints: AuthorityScopeConstraintsV1 {
            application_pack_sha256: ready.application_pack_sha256.clone(),
            integration_ids: vec![activation.integration_id.clone()],
            semantic_target_ids: vec![ready.semantic_target_id.clone()],
        },
        valid_from_unix_seconds: now.saturating_sub(10),
        expires_at_unix_seconds: now + 600,
        evidence_ids: vec!["delegated-authority".to_owned()],
        authority_sha256: empty_hash(),
    }
    .seal());
    let policy = ok(TrustedPolicySnapshotV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        policy_set_id: "policy-set-1".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("policy-set"),
        organization_id: "organization-1".to_owned(),
        policy_state: TrustedPolicyStateV1::Effective,
        allowed_risk_classes: vec![
            CognitiveRiskClass::ReadOnly,
            CognitiveRiskClass::Reversible,
            CognitiveRiskClass::BusinessStateChange,
        ],
        denied_capability_ids: Vec::new(),
        mandatory_confirmation_capability_ids: Vec::new(),
        mandatory_escalation_capability_ids: Vec::new(),
        forbidden_semantic_targets: Vec::new(),
        effective_from_unix_seconds: now.saturating_sub(10),
        expires_at_unix_seconds: now + 600,
        evidence_ids: vec!["trusted-policy".to_owned()],
        snapshot_sha256: empty_hash(),
    }
    .seal());
    let request = ok(PolicyEvaluationRequestV1::new(
        ready.clone(),
        goal,
        authority,
        policy,
        now,
        RequestedAutonomyModeV1::AutonomousPreferred,
    ));
    let decision = ok(evaluate_policy(&request));
    let eligibility = ok(ActivationEligibilityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        eligibility_id: format!("eligibility-{label}"),
        organization_id: "organization-1".to_owned(),
        integration_id: activation.integration_id.clone(),
        application_pack_sha256: ready.application_pack_sha256.clone(),
        runtime_binding_id: activation.binding_id.clone(),
        runtime_binding_sha256: activation.runtime_binding_sha256.clone(),
        adapter_kind: AdapterKindV1::Uia,
        activation_scope_id: "activation-scope-1".to_owned(),
        activation_ledger_id: activation.activation_ledger_id.clone(),
        activation_ledger_chain_head: activation.activation_ledger_chain_head.clone(),
        eligible_capability_ids: vec![capability],
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        observed_at_unix_seconds: now,
        expires_at_unix_seconds: now + 300,
        evidence_ids: vec!["activation-eligibility".to_owned()],
        eligibility_sha256: empty_hash(),
    }
    .seal());
    let admission = ok(admit_action(
        &request,
        &decision,
        None,
        None,
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        AdmissionIssuanceV1 {
            admission_id: format!("admission-{label}"),
            admitted_at_unix_seconds: now + 2,
            expires_at_unix_seconds: now + 250,
            expected_runtime_binding_sha256: eligibility.runtime_binding_sha256.clone(),
            expected_activation_ledger_chain_head: eligibility.activation_ledger_chain_head.clone(),
            expected_adapter_kind: AdapterKindV1::Uia,
        },
    ));
    (admission, eligibility)
}

fn process_exists(process_id: u32) -> bool {
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "if (Get-Process -Id {process_id} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}"
            ),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[derive(Debug)]
struct ActualVerifiedCycle {
    source: ObservationSnapshot,
    fresh: ObservationSnapshot,
    proposal_id: String,
    proposal_sha256: String,
    plan_generation_id: String,
    policy_decision_sha256: String,
    admission_sha256: String,
    activation_record_hash: String,
    receipt_sha256: String,
    verified_result_sha256: String,
    verdict: VerificationVerdictV2,
}

#[allow(clippy::too_many_arguments)]
fn run_actual_text_cycle(
    temp: &TempDirectory,
    configuration: &WindowsAdapterConfiguration,
    target_template: &WindowsUiaObservationTarget,
    source_snapshot: &ObservationSnapshot,
    payload_bytes: &[u8],
    expected_bytes: &[u8],
    label: &str,
    action_sequence: u64,
    now: u64,
    time_offset_ms: u64,
) -> ActualVerifiedCycle {
    let now_ms = now.saturating_mul(1_000).saturating_add(time_offset_ms);
    let (execution_admission, session_id) =
        certified_admission_labeled(configuration, temp, now, &format!("{label}-mutation"));
    let platform_activation = ok(project_windows_activation(
        &execution_admission,
        configuration,
    ));
    let source = ok(bind_actual_source_observation(
        source_snapshot,
        &platform_activation,
    ));
    let text_element = source
        .observable_elements
        .iter()
        .find(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("D2IText")
        })
        .unwrap_or_else(|| panic!("actual recovery text element is absent"));
    let protected_element = source
        .observable_elements
        .iter()
        .find(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("D2ICheckbox")
        })
        .unwrap_or_else(|| panic!("actual recovery protected checkbox is absent"));
    let expected_text = std::str::from_utf8(expected_bytes)
        .unwrap_or_else(|error| panic!("expected fixture text is not UTF-8: {error}"));
    let mut expected_value = text_element.value.clone();
    *expected_value
        .pointer_mut("/current_value")
        .unwrap_or_else(|| panic!("recovery text current_value is absent")) = json!({
        "status": "present",
        "value": {
            "text": expected_text,
            "text_hash": sha(expected_bytes),
            "truncated": false
        }
    });
    let expected_postcondition = Postcondition {
        target_state: format!("element:{}:value", text_element.element_id),
        op: ComparisonOp::Equals,
        expected_value: ok(trusted_execution_sha256(&expected_value)).into(),
        required: true,
        timeout_ms: 5_000,
    };
    let verification_goal = GoalSpec {
        schema_version: 1,
        goal_id: "goal-trusted-execution".to_owned(),
        objective: "Recover one local fixture value through a fresh trust chain".to_owned(),
        scope: BTreeMap::from([("fixture".to_owned(), json!("windows-uia"))]),
        required_outcomes: vec!["fresh observation contains the expected value".to_owned()],
        constraints: vec!["protected checkbox remains unchanged".to_owned()],
        success_criteria: vec![expected_postcondition.clone()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "trusted recovery integration fixture".to_owned(),
            source_hash: digest(&format!("recovery-goal-{label}")),
            module_id: "cognitive-recovery-test".to_owned(),
        },
    };
    let ready = policy_ready_for_target_labeled(
        &source,
        payload_bytes,
        &text_element.element_id,
        &text_element.kind,
        expected_postcondition,
        label,
    );
    let proposal_sha256 = ok(trusted_execution_sha256(&ready.proposal));
    let arguments: CandidateActionArguments =
        ok(serde_json::from_value(ready.proposal.arguments.clone()));
    let grounded_target_sha256 = ok(trusted_execution_sha256(&arguments.target));
    let (cognitive_admission, eligibility) = policy_artifacts_for_goal_labeled(
        ready.clone(),
        &platform_activation,
        now,
        verification_goal.clone(),
        label,
    );
    let policy_decision_sha256 = cognitive_admission.policy_decision_sha256.clone();
    let admission_sha256 = cognitive_admission.admission_sha256.clone();
    let session = ok(TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: format!("recovery-session-{label}"),
        action_sequence,
        runtime_build_id: "runtime-build-recovery".to_owned(),
        runtime_package_sha256: digest("runtime-package-recovery"),
        generated_at_unix_ms: now_ms.saturating_add(1_000),
        expires_at_unix_ms: now_ms.saturating_add(120_000),
        expected_organization_id: "organization-1".to_owned(),
        expected_integration_id: platform_activation.integration_id.clone(),
        expected_adapter_kind: AdapterKindV1::Uia,
        expected_activation_ledger_id: platform_activation.activation_ledger_id.clone(),
        expected_activation_ledger_chain_head: platform_activation
            .activation_ledger_chain_head
            .clone(),
        evidence_ids: vec![format!("runtime-package-{label}")],
        session_sha256: empty_hash(),
    }
    .seal());
    let execution_binding = ok(TrustedExecutionBindingRequestV1::new(
        ready.clone(),
        cognitive_admission,
        eligibility,
        session,
        platform_activation.clone(),
        &source,
        grounded_target_sha256,
    ));
    let execution_target = WindowsUiaObservationTarget {
        session_id,
        runtime_binding_digest: ok(configuration.configuration_hash()),
        ..target_template.clone()
    };
    let mutation_audit_root = temp.path().join(format!("{label}-mutation-audit"));
    let mutation_audit = ok(initialize_windows_deployment_audit(
        &mutation_audit_root,
        &format!("{label}-mutation-audit"),
        &format!("recovery-session-{label}"),
        64,
        now_ms.max(1),
    ));
    let payload = ok(EphemeralActionPayload::new(
        format!("recovery-input-{label}"),
        payload_bytes.to_vec(),
        now_ms.saturating_add(1_000),
        now_ms.saturating_add(60_000),
    ));
    let mut executor = ok(CognitiveTrustedExecutionCoordinator::bind(
        execution_binding.clone(),
        &source,
        execution_admission,
        configuration.clone(),
        TrustedTargetResolverInput::Uia {
            target: execution_target,
        },
        Some(payload),
        mutation_audit,
        now_ms.saturating_add(2_000),
    ));
    let mutation_worker_id = executor
        .owned_worker_process_id()
        .unwrap_or_else(|| panic!("recovery mutation worker PID is absent"));
    let preparation = ok(executor.prepare(now_ms.saturating_add(3_000)));
    let receipt = ok(executor.commit(&preparation, now_ms.saturating_add(4_000)));
    assert_eq!(receipt.status, TrustedExecutionStatusV1::Succeeded);
    let execution = ok(to_verification_bound_execution_v2(&receipt));
    drop(executor);
    assert!(!process_exists(mutation_worker_id));

    let reobservation_request = ok(ReobservationRequestV1::new(
        &execution_binding,
        &receipt,
        &execution,
        &source,
        now_ms.saturating_add(5_000),
        now_ms.saturating_add(90_000),
    ));
    let guard = ok(VerificationGuardProfileV1::new(
        format!("guard-{label}"),
        &ready.proposal,
        &source,
        vec![VerificationGuardTargetV1 {
            element_id: text_element.element_id.clone(),
            field: VerificationGuardFieldV1::Value,
        }],
        Vec::new(),
        vec![ProtectedInvariantV1 {
            target: VerificationGuardTargetV1 {
                element_id: protected_element.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            },
            expected_source_value_hash: ok(trusted_execution_sha256(&protected_element.value)),
            severity: ProtectedInvariantSeverityV1::Unsafe,
            reason_code: "protected-checkbox-stable".to_owned(),
        }],
        vec![IgnoredVolatileTargetV1 {
            target: VerificationGuardTargetV1 {
                element_id: "observation.status".to_owned(),
                field: VerificationGuardFieldV1::Value,
            },
            approved_reason_code: "bounded-observation-metrics-volatile".to_owned(),
            evidence_id: "windows-observation-contract".to_owned(),
        }],
        0,
        vec![format!("actual-recovery-{label}")],
    ));
    let (fresh_admission, fresh_session_id) =
        certified_admission_labeled(configuration, temp, now, &format!("{label}-observer"));
    let fresh_adapter = ok(WindowsUiAutomationAdapter::bind(
        fresh_admission.activation,
        configuration.clone(),
        now + 2,
    ));
    let fresh_audit_root = temp.path().join(format!("{label}-observation-audit"));
    let fresh_audit = ok(initialize_windows_deployment_audit(
        &fresh_audit_root,
        &format!("{label}-observation-audit"),
        &format!("{label}-observation-session"),
        64,
        now_ms.max(1),
    ));
    let fresh_provider = ok(WindowsUiaObservationProvider::new(
        fresh_adapter,
        WindowsUiaObservationTarget {
            session_id: fresh_session_id,
            runtime_binding_digest: ok(configuration.configuration_hash()),
            ..target_template.clone()
        },
        ObservationLimits::default(),
        fresh_audit,
    ));
    let verification_audit_root = temp.path().join(format!("{label}-verification-audit"));
    let verification_audit = ok(initialize_windows_deployment_audit(
        &verification_audit_root,
        &format!("{label}-verification-audit"),
        &format!("recovery-session-{label}"),
        64,
        now_ms.max(1),
    ));
    let mut consumption = VerificationConsumptionLedgerV1::default();
    let mut verifier = ok(CognitiveVerificationCoordinatorV2::begin(
        execution_binding,
        verification_goal,
        ready.clone(),
        receipt.clone(),
        execution,
        source.clone(),
        reobservation_request,
        guard,
        verification_audit,
        &mut consumption,
        now_ms.saturating_add(5_000),
    ));
    let _ = ok(verifier.reobserve(
        TrustedReadOnlyObservationConfiguration::Uia(fresh_provider),
        now_ms.saturating_add(6_000),
    ));
    let fresh = verifier
        .fresh_observation()
        .cloned()
        .unwrap_or_else(|| panic!("recovery fresh observation is absent"));
    let fresh_worker_id = verifier
        .observation_worker_process_id()
        .unwrap_or_else(|| panic!("recovery observation worker PID is absent"));
    let _ = ok(verifier.analyze_delta(now_ms.saturating_add(7_000)));
    let _ = ok(verifier.build_verification_request());
    let result = ok(verifier.verify(now_ms.saturating_add(8_000))).clone();
    let terminal = ok(verifier.finalize(now_ms.saturating_add(9_000)));
    drop(verifier);
    assert!(!process_exists(fresh_worker_id));
    assert_eq!(terminal.action_verdict, result.action_verdict);
    ActualVerifiedCycle {
        source,
        fresh,
        proposal_id: ready.proposal.proposal_id,
        proposal_sha256,
        plan_generation_id: ready.proposal.plan_generation_id,
        policy_decision_sha256,
        admission_sha256,
        activation_record_hash: platform_activation.activation_record_hash,
        receipt_sha256: receipt.receipt_sha256,
        verified_result_sha256: terminal.result_sha256,
        verdict: terminal.action_verdict,
    }
}

fn run_actual_unsafe_toggle(
    temp: &TempDirectory,
    configuration: &WindowsAdapterConfiguration,
    target_template: &WindowsUiaObservationTarget,
    source_snapshot: &ObservationSnapshot,
    now: u64,
) -> ActualVerifiedCycle {
    let now_ms = now.saturating_mul(1_000).saturating_add(10_000);
    let label = "actual-unsafe-toggle";
    let (execution_admission, session_id) =
        certified_admission_labeled(configuration, temp, now, "unsafe-toggle-mutation");
    let platform_activation = ok(project_windows_activation(
        &execution_admission,
        configuration,
    ));
    let source = ok(bind_actual_source_observation(
        source_snapshot,
        &platform_activation,
    ));
    let protected_element = source
        .observable_elements
        .iter()
        .find(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("D2ICheckbox")
        })
        .unwrap_or_else(|| panic!("actual protected checkbox is absent"));
    let source_toggle_state = protected_element
        .value
        .pointer("/toggle_state")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("actual protected checkbox state is absent"));
    let desired = source_toggle_state != "on";
    let mut expected_value = protected_element.value.clone();
    expected_value
        .as_object_mut()
        .unwrap_or_else(|| panic!("protected checkbox value is not an object"))
        .insert(
            "toggle_state".to_owned(),
            Value::String(if desired { "on" } else { "off" }.to_owned()),
        );
    let postcondition = Postcondition {
        target_state: format!("element:{}:value", protected_element.element_id),
        op: ComparisonOp::Equals,
        expected_value: ok(trusted_execution_sha256(&expected_value)).into(),
        required: true,
        timeout_ms: 5_000,
    };
    let verification_goal = GoalSpec {
        schema_version: 1,
        goal_id: "goal-trusted-execution".to_owned(),
        objective: "Detect one actual protected invariant mutation".to_owned(),
        scope: BTreeMap::from([("fixture".to_owned(), json!("windows-uia"))]),
        required_outcomes: vec!["protected mutation is classified unsafe".to_owned()],
        constraints: vec!["no automatic second mutation".to_owned()],
        success_criteria: vec![postcondition.clone()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "trusted unsafe recovery fixture".to_owned(),
            source_hash: digest("unsafe-recovery-goal"),
            module_id: "cognitive-recovery-test".to_owned(),
        },
    };
    let target = CandidateTargetBinding {
        application_pack_sha256: digest("application-pack"),
        observation_bridge_sha256: digest("observation-bridge"),
        observation_id: source.observation_id.clone(),
        source_observation_hash: source.state_hash.clone(),
        source_observation_sequence: source.sequence,
        grounding_case_id: "grounding-case-unsafe-toggle".to_owned(),
        semantic_target_id: "fixture.protected_checkbox".to_owned(),
        element_id: protected_element.element_id.clone(),
        element_kind: protected_element.kind.clone(),
        capability_binding_sha256: digest("capability-binding-unsafe-toggle"),
    };
    let arguments = CandidateActionArguments {
        schema_version: 1,
        operation: "uia.toggle".to_owned(),
        target,
        input: CandidateActionInput::Toggle { desired },
    };
    ok(arguments.validate());
    let proposal = ActionProposal {
        schema_version: 1,
        proposal_id: "proposal-actual-unsafe-toggle".to_owned(),
        goal_id: "goal-trusted-execution".to_owned(),
        plan_generation_id: "plan-actual-unsafe-toggle".to_owned(),
        source_observation_hash: source.state_hash.clone(),
        capability_id: "uia.toggle".to_owned(),
        semantic_target: "fixture.protected_checkbox".to_owned(),
        arguments: ok(serde_json::to_value(arguments)),
        preconditions: Vec::new(),
        expected_postconditions: vec![postcondition.clone()],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["actual protected toggle fixture".to_owned()],
        valid_until_sequence: source.sequence,
    };
    let mut ready = PolicyReadyActionV1 {
        schema_version: 1,
        selection_id: "selection-actual-unsafe-toggle".to_owned(),
        selection_sha256: digest("selection-actual-unsafe-toggle"),
        candidate_set_sha256: digest("candidate-set-actual-unsafe-toggle"),
        goal_id: proposal.goal_id.clone(),
        world_state_id: "world-actual-unsafe-toggle".to_owned(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        observation_id: source.observation_id.clone(),
        source_observation_hash: source.state_hash.clone(),
        source_observation_sequence: source.sequence,
        application_pack_sha256: digest("application-pack"),
        grounding_result_sha256: digest("grounding-result-actual-unsafe-toggle"),
        semantic_target_id: proposal.semantic_target.clone(),
        selected_element_id: protected_element.element_id.clone(),
        selected_element_kind: protected_element.kind.clone(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: digest("capability-binding-unsafe-toggle"),
        proposal,
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        expected_postconditions: vec![postcondition],
        evidence_ids: vec![
            "grounding-result-actual-unsafe-toggle".to_owned(),
            "selection-result-actual-unsafe-toggle".to_owned(),
        ],
        policy_input_sha256: digest("policy-input-actual-unsafe-toggle"),
        policy_ready_sha256: empty_hash(),
    };
    ready.policy_ready_sha256 = ok(ready.compute_policy_ready_sha256());
    let proposal_sha256 = ok(trusted_execution_sha256(&ready.proposal));
    let arguments: CandidateActionArguments =
        ok(serde_json::from_value(ready.proposal.arguments.clone()));
    let grounded_target_sha256 = ok(trusted_execution_sha256(&arguments.target));
    let (cognitive_admission, eligibility) = policy_artifacts_for_goal_labeled(
        ready.clone(),
        &platform_activation,
        now,
        verification_goal.clone(),
        label,
    );
    let policy_decision_sha256 = cognitive_admission.policy_decision_sha256.clone();
    let admission_sha256 = cognitive_admission.admission_sha256.clone();
    let session = ok(TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: "recovery-session-actual-unsafe-toggle".to_owned(),
        action_sequence: 1,
        runtime_build_id: "runtime-build-recovery".to_owned(),
        runtime_package_sha256: digest("runtime-package-recovery"),
        generated_at_unix_ms: now_ms.saturating_add(1_000),
        expires_at_unix_ms: now_ms.saturating_add(120_000),
        expected_organization_id: "organization-1".to_owned(),
        expected_integration_id: platform_activation.integration_id.clone(),
        expected_adapter_kind: AdapterKindV1::Uia,
        expected_activation_ledger_id: platform_activation.activation_ledger_id.clone(),
        expected_activation_ledger_chain_head: platform_activation
            .activation_ledger_chain_head
            .clone(),
        evidence_ids: vec!["runtime-package-actual-unsafe-toggle".to_owned()],
        session_sha256: empty_hash(),
    }
    .seal());
    let execution_binding = ok(TrustedExecutionBindingRequestV1::new(
        ready.clone(),
        cognitive_admission,
        eligibility,
        session,
        platform_activation.clone(),
        &source,
        grounded_target_sha256,
    ));
    let mutation_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-unsafe-toggle-mutation-audit"),
        "actual-unsafe-toggle-mutation-audit",
        "recovery-session-actual-unsafe-toggle",
        64,
        now_ms,
    ));
    let mut executor = ok(CognitiveTrustedExecutionCoordinator::bind(
        execution_binding.clone(),
        &source,
        execution_admission,
        configuration.clone(),
        TrustedTargetResolverInput::Uia {
            target: WindowsUiaObservationTarget {
                session_id,
                runtime_binding_digest: ok(configuration.configuration_hash()),
                ..target_template.clone()
            },
        },
        None,
        mutation_audit,
        now_ms.saturating_add(2_000),
    ));
    let mutation_worker_id = executor
        .owned_worker_process_id()
        .unwrap_or_else(|| panic!("unsafe mutation worker PID is absent"));
    let preparation = ok(executor.prepare(now_ms.saturating_add(3_000)));
    let receipt = ok(executor.commit(&preparation, now_ms.saturating_add(4_000)));
    let execution = ok(to_verification_bound_execution_v2(&receipt));
    drop(executor);
    assert!(!process_exists(mutation_worker_id));

    let reobservation_request = ok(ReobservationRequestV1::new(
        &execution_binding,
        &receipt,
        &execution,
        &source,
        now_ms.saturating_add(5_000),
        now_ms.saturating_add(90_000),
    ));
    let guard = ok(VerificationGuardProfileV1::new(
        "guard-actual-unsafe-toggle".to_owned(),
        &ready.proposal,
        &source,
        Vec::new(),
        Vec::new(),
        vec![ProtectedInvariantV1 {
            target: VerificationGuardTargetV1 {
                element_id: protected_element.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            },
            expected_source_value_hash: ok(trusted_execution_sha256(&protected_element.value)),
            severity: ProtectedInvariantSeverityV1::Unsafe,
            reason_code: "protected-checkbox-stable".to_owned(),
        }],
        vec![IgnoredVolatileTargetV1 {
            target: VerificationGuardTargetV1 {
                element_id: "observation.status".to_owned(),
                field: VerificationGuardFieldV1::Value,
            },
            approved_reason_code: "bounded-observation-metrics-volatile".to_owned(),
            evidence_id: "windows-observation-contract".to_owned(),
        }],
        0,
        vec!["actual-protected-toggle".to_owned()],
    ));
    let (fresh_admission, fresh_session_id) =
        certified_admission_labeled(configuration, temp, now, "unsafe-toggle-observer");
    let fresh_adapter = ok(WindowsUiAutomationAdapter::bind(
        fresh_admission.activation,
        configuration.clone(),
        now + 2,
    ));
    let fresh_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-unsafe-toggle-observation-audit"),
        "actual-unsafe-toggle-observation-audit",
        "actual-unsafe-toggle-observation-session",
        64,
        now_ms,
    ));
    let fresh_provider = ok(WindowsUiaObservationProvider::new(
        fresh_adapter,
        WindowsUiaObservationTarget {
            session_id: fresh_session_id,
            runtime_binding_digest: ok(configuration.configuration_hash()),
            ..target_template.clone()
        },
        ObservationLimits::default(),
        fresh_audit,
    ));
    let verification_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-unsafe-toggle-verification-audit"),
        "actual-unsafe-toggle-verification-audit",
        "recovery-session-actual-unsafe-toggle",
        64,
        now_ms,
    ));
    let mut consumption = VerificationConsumptionLedgerV1::default();
    let mut verifier = ok(CognitiveVerificationCoordinatorV2::begin(
        execution_binding,
        verification_goal,
        ready.clone(),
        receipt.clone(),
        execution,
        source.clone(),
        reobservation_request,
        guard,
        verification_audit,
        &mut consumption,
        now_ms.saturating_add(5_000),
    ));
    let _ = ok(verifier.reobserve(
        TrustedReadOnlyObservationConfiguration::Uia(fresh_provider),
        now_ms.saturating_add(6_000),
    ));
    let fresh = verifier
        .fresh_observation()
        .cloned()
        .unwrap_or_else(|| panic!("unsafe fresh observation is absent"));
    let fresh_worker_id = verifier
        .observation_worker_process_id()
        .unwrap_or_else(|| panic!("unsafe observer worker PID is absent"));
    let delta = ok(verifier.analyze_delta(now_ms.saturating_add(7_000))).clone();
    assert_eq!(delta.protected_invariant_violations.len(), 1);
    let _ = ok(verifier.build_verification_request());
    let result = ok(verifier.verify(now_ms.saturating_add(8_000))).clone();
    let terminal = ok(verifier.finalize(now_ms.saturating_add(9_000)));
    drop(verifier);
    assert!(!process_exists(fresh_worker_id));
    assert_eq!(result.action_verdict, VerificationVerdictV2::Unsafe);
    assert_eq!(terminal.action_verdict, VerificationVerdictV2::Unsafe);
    ActualVerifiedCycle {
        source,
        fresh,
        proposal_id: ready.proposal.proposal_id,
        proposal_sha256,
        plan_generation_id: ready.proposal.plan_generation_id,
        policy_decision_sha256,
        admission_sha256,
        activation_record_hash: platform_activation.activation_record_hash,
        receipt_sha256: receipt.receipt_sha256,
        verified_result_sha256: terminal.result_sha256,
        verdict: terminal.action_verdict,
    }
}

fn actual_recovery_budget() -> RecoveryBudgetV1 {
    ok(RecoveryBudgetV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        budget_id: "actual-recovery-budget".to_owned(),
        goal_id: "goal-trusted-execution".to_owned(),
        maximum_total_cycles: 3,
        remaining_total_cycles: 3,
        maximum_reobservations: 1,
        remaining_reobservations: 1,
        maximum_fresh_retries: 1,
        remaining_fresh_retries: 1,
        maximum_alternate_capability_attempts: 1,
        remaining_alternate_capability_attempts: 1,
        maximum_replans: 1,
        remaining_replans: 1,
        maximum_clarifications: 1,
        remaining_clarifications: 1,
        started_at_unix_ms: 1,
        deadline_unix_ms: u64::MAX - 1,
        evidence_ids: vec!["actual-windows-recovery-budget".to_owned()],
        budget_sha256: empty_hash(),
    }
    .seal())
}

fn actual_recovery_profile() -> RecoveryPolicyProfileV1 {
    ok(RecoveryPolicyProfileV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        profile_id: "actual-windows-recovery-profile".to_owned(),
        policy_set_sha256: digest("policy-set"),
        authority_sha256: digest("actual-recovery-authority"),
        retryable_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        reobservable_failure_classes: vec![RecoveryFailureClassV1::VerificationInconclusive],
        alternate_capability_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        replannable_failure_classes: vec![RecoveryFailureClassV1::PostconditionFailed],
        clarifiable_failure_classes: Vec::new(),
        mandatory_escalation_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        forbidden_automatic_failure_classes: vec![
            RecoveryFailureClassV1::ProtectedInvariantViolation,
            RecoveryFailureClassV1::UnsafeSideEffect,
        ],
        retryable_capability_ids: vec!["uia.set_value".to_owned()],
        alternate_capability_groups: vec![AlternateCapabilityGroupV1 {
            group_id: "windows-text-entry".to_owned(),
            capability_ids: vec!["uia.set_value".to_owned()],
        }],
        maximum_same_capability_attempts: 2,
        allow_replan: true,
        allow_clarification: true,
        escalation_risk_threshold: CognitiveRiskClass::HighCriticality,
        evidence_ids: vec!["actual-windows-policy-profile".to_owned()],
        profile_sha256: empty_hash(),
    }
    .seal())
}

#[test]
fn actual_windows_uia_failure_recovers_through_a_wholly_fresh_second_cycle() {
    let _uia_fixture = lock_uia_fixture();
    let temp = TempDirectory::new();
    let now = now_seconds();
    let now_ms = now.saturating_mul(1_000);
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let powershell = ok(fs::canonicalize(
        Path::new(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&powershell)));
    let title = format!("D2I Actual Recovery {}", std::process::id());
    let output_path = temp.path().join("actual-recovery-value.txt");
    let script = ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("support")
            .join("windows_ui_fixture.ps1"),
    ));
    let child = ok(Command::new(&powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-WindowTitle")
        .arg(&title)
        .arg("-OutputPath")
        .arg(&output_path)
        .spawn());
    let process_id = child.id();
    let mut fixture_process = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(ok(fixture_process.0.try_wait()).is_none());

    let configuration = configuration(&executable_hash);
    let configuration_hash = ok(configuration.configuration_hash());
    let (source_admission, source_session_id) =
        certified_admission_labeled(&configuration, &temp, now, "recovery-source");
    let target = WindowsUiaObservationTarget {
        schema_version: 1,
        process_id,
        executable_path: powershell.display().to_string(),
        executable_hash,
        window_title_hash: sha(title.as_bytes()),
        session_id: source_session_id,
        runtime_binding_digest: configuration_hash,
    };
    let source_adapter = ok(WindowsUiAutomationAdapter::bind(
        source_admission.activation,
        configuration.clone(),
        now + 2,
    ));
    let source_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-recovery-source-audit"),
        "actual-recovery-source-audit",
        "actual-recovery-session",
        64,
        now_ms,
    ));
    let source_provider = ok(WindowsUiaObservationProvider::new(
        source_adapter,
        target.clone(),
        ObservationLimits::default(),
        source_audit,
    ));
    let source_completed = ok(source_provider.observe_once(&goal(), 11));
    assert!(source_completed.worker_exited_cleanly);
    assert_eq!(source_completed.read_only_side_effect_count, 0);
    assert!(!process_exists(source_completed.worker_process_id));

    let temporary_value = b"temporary fixture value";
    let final_value = b"final recovery value";
    let first = run_actual_text_cycle(
        &temp,
        &configuration,
        &target,
        &source_completed.snapshot,
        temporary_value,
        final_value,
        "actual-cycle-1",
        1,
        now,
        10_000,
    );
    assert_eq!(first.verdict, VerificationVerdictV2::Failed);
    assert_ne!(first.source.state_hash, first.fresh.state_hash);
    assert_eq!(ok(fs::read(&output_path)), temporary_value);

    let trigger = ok(RecoveryTriggerV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        trigger_id: "actual-recovery-trigger".to_owned(),
        stage: RecoveryStageV1::Verification,
        goal_id: "goal-trusted-execution".to_owned(),
        plan_generation_id: Some(first.plan_generation_id.clone()),
        proposal_id: Some(first.proposal_id.clone()),
        proposal_sha256: Some(first.proposal_sha256.clone()),
        capability_id: Some("uia.set_value".to_owned()),
        source_observation_id: first.source.observation_id.clone(),
        source_observation_hash: first.source.state_hash.clone(),
        source_observation_sequence: first.source.sequence,
        fresh_observation_id: Some(first.fresh.observation_id.clone()),
        fresh_observation_hash: Some(first.fresh.state_hash.clone()),
        fresh_observation_sequence: Some(first.fresh.sequence),
        execution_receipt_sha256: Some(first.receipt_sha256.clone()),
        verified_action_result_sha256: Some(first.verified_result_sha256.clone()),
        policy_decision_sha256: Some(first.policy_decision_sha256.clone()),
        activation_admission_sha256: Some(first.admission_sha256.clone()),
        reason_codes: vec![RecoveryReasonCodeV1::PostconditionFailed],
        evidence_ids: vec!["actual-first-verification".to_owned()],
        detected_at_unix_ms: now_ms.saturating_add(20_000),
        trigger_sha256: empty_hash(),
    }
    .seal());
    let classification = ok(d2i_desktop::classify_recovery_trigger(&trigger));
    let initial_history = ok(RecoveryHistoryV1::empty(
        "actual-recovery-history".to_owned(),
        "goal-trusted-execution".to_owned(),
    ));
    let initial_history = ok(initial_history.append(ok(RecoveryHistoryEntryV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        cycle_index: 1,
        trigger_sha256: trigger.trigger_sha256.clone(),
        classification_sha256: classification.classification_sha256,
        decision_sha256: digest("initial-action-decision"),
        plan_generation_id: Some(first.plan_generation_id.clone()),
        proposal_id: Some(first.proposal_id.clone()),
        proposal_sha256: Some(first.proposal_sha256.clone()),
        capability_id: Some("uia.set_value".to_owned()),
        input_sha256: Some(sha(temporary_value)),
        source_observation_hash: first.source.state_hash.clone(),
        source_observation_sequence: first.source.sequence,
        fresh_observation_hash: Some(first.fresh.state_hash.clone()),
        fresh_observation_sequence: Some(first.fresh.sequence),
        policy_decision_sha256: Some(first.policy_decision_sha256.clone()),
        cognitive_admission_sha256: Some(first.admission_sha256.clone()),
        activation_record_hash: Some(first.activation_record_hash.clone()),
        execution_receipt_sha256: Some(first.receipt_sha256.clone()),
        verified_action_result_sha256: Some(first.verified_result_sha256.clone()),
        terminal_outcome: RecoveryHistoryOutcomeV1::Failed,
        evidence_ids: vec!["actual-first-cycle".to_owned()],
        entry_sha256: empty_hash(),
    }
    .seal())));
    let recovery_ledger = ok(d2i_desktop::initialize_recovery_ledger(
        &temp.path().join("actual-recovery-ledger"),
        "actual-recovery-ledger",
        "actual-recovery-session",
        "goal-trusted-execution",
        64,
        now_ms,
    ));
    let recovery_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-recovery-audit"),
        "actual-recovery-audit",
        "actual-recovery-session",
        128,
        now_ms,
    ));
    let mut recovery = ok(CognitiveRecoveryCoordinatorV1::restore(
        "goal-trusted-execution".to_owned(),
        first.plan_generation_id.clone(),
        actual_recovery_budget(),
        initial_history,
        actual_recovery_profile(),
        recovery_ledger,
        recovery_audit,
    ));
    ok(recovery.begin(trigger, now_ms.saturating_add(20_001)));
    ok(recovery.classify(now_ms.saturating_add(20_002)));
    let decision = ok(recovery.decide(
        &RecoveryDecisionContextV1 {
            verification_verdict: Some(RecoveryVerificationVerdictV1::Failed),
            goal_progress: GoalProgress::InProgress,
            latest_observation_trusted: true,
            bounded_user_fact_missing: false,
            same_failure_count: 1,
            same_capability_attempts: 1,
            current_proposal_id: Some(first.proposal_id.clone()),
            current_proposal_sha256: Some(first.proposal_sha256.clone()),
            current_capability_id: Some("uia.set_value".to_owned()),
            current_risk: CognitiveRiskClass::Reversible,
            alternate_capability_ids: Vec::new(),
            replan_available: true,
        },
        now_ms.saturating_add(20_003),
    ))
    .clone();
    assert_eq!(
        decision.decision_kind,
        RecoveryDecisionKindV1::RetryFreshCycle
    );
    let request = ok(FreshRecoveryCycleRequestV1::from_decision(
        "actual-recovery-cycle-2".to_owned(),
        &decision,
        "goal-trusted-execution".to_owned(),
        first.plan_generation_id.clone(),
        Some(first.proposal_sha256.clone()),
        Some("uia.set_value".to_owned()),
        first.fresh.observation_id.clone(),
        first.fresh.state_hash.clone(),
        first.fresh.sequence,
        recovery.history(),
        digest("actual-recovery-authority"),
        digest("policy-set"),
        now_ms.saturating_add(20_004),
        now_ms.saturating_add(120_000),
        vec!["actual-fresh-second-cycle".to_owned()],
    ));
    let mut second = None;
    let recovered =
        ok(
            recovery.execute_fresh_cycle(&request, now_ms.saturating_add(20_005), || {
                let cycle = run_actual_text_cycle(
                    &temp,
                    &configuration,
                    &target,
                    &first.fresh,
                    final_value,
                    final_value,
                    "actual-cycle-2",
                    2,
                    now,
                    40_000,
                );
                let evidence = FreshRecoveryCycleEvidenceV1 {
                    schema_version: RECOVERY_SCHEMA_VERSION,
                    cycle_request_sha256: request.cycle_request_sha256.clone(),
                    observation_id: cycle.fresh.observation_id.clone(),
                    observation_hash: cycle.fresh.state_hash.clone(),
                    observation_sequence: cycle.fresh.sequence,
                    plan_generation_id: cycle.plan_generation_id.clone(),
                    proposal_id: cycle.proposal_id.clone(),
                    proposal_sha256: cycle.proposal_sha256.clone(),
                    capability_id: "uia.set_value".to_owned(),
                    input_sha256: sha(final_value),
                    policy_decision_sha256: cycle.policy_decision_sha256.clone(),
                    cognitive_admission_sha256: cycle.admission_sha256.clone(),
                    activation_record_hash: cycle.activation_record_hash.clone(),
                    execution_receipt_sha256: cycle.receipt_sha256.clone(),
                    verified_action_result_sha256: cycle.verified_result_sha256.clone(),
                    verification_verdict: match cycle.verdict {
                        VerificationVerdictV2::Passed => RecoveryVerificationVerdictV1::Passed,
                        VerificationVerdictV2::Failed => RecoveryVerificationVerdictV1::Failed,
                        VerificationVerdictV2::Inconclusive => {
                            RecoveryVerificationVerdictV1::Inconclusive
                        }
                        VerificationVerdictV2::Unsupported => {
                            RecoveryVerificationVerdictV1::Unsupported
                        }
                        VerificationVerdictV2::Unsafe => RecoveryVerificationVerdictV1::Unsafe,
                    },
                };
                second = Some(cycle);
                Ok(evidence)
            }),
        );
    let second = second.unwrap_or_else(|| panic!("second actual cycle was not retained"));
    assert_eq!(second.verdict, VerificationVerdictV2::Passed);
    assert_eq!(
        recovered.outcome,
        d2i_desktop::RecoveryCycleOutcomeV1::Recovered
    );
    assert_eq!(recovery.history().entries.len(), 2);
    assert_eq!(recovery.budget().remaining_fresh_retries, 0);
    assert_eq!(
        recovery.state(),
        CognitiveRecoveryCoordinatorStateV1::NextCycle
    );
    assert_ne!(first.proposal_id, second.proposal_id);
    assert_ne!(first.proposal_sha256, second.proposal_sha256);
    assert_ne!(first.admission_sha256, second.admission_sha256);
    assert_ne!(first.activation_record_hash, second.activation_record_hash);
    assert_ne!(first.receipt_sha256, second.receipt_sha256);
    assert_eq!(ok(fs::read(&output_path)), final_value);

    let unsafe_cycle = run_actual_unsafe_toggle(&temp, &configuration, &target, &second.fresh, now);
    assert_eq!(unsafe_cycle.verdict, VerificationVerdictV2::Unsafe);
    let unsafe_trigger = ok(RecoveryTriggerV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        trigger_id: "actual-unsafe-recovery-trigger".to_owned(),
        stage: RecoveryStageV1::Verification,
        goal_id: "goal-trusted-execution".to_owned(),
        plan_generation_id: Some(unsafe_cycle.plan_generation_id.clone()),
        proposal_id: Some(unsafe_cycle.proposal_id.clone()),
        proposal_sha256: Some(unsafe_cycle.proposal_sha256.clone()),
        capability_id: Some("uia.toggle".to_owned()),
        source_observation_id: unsafe_cycle.source.observation_id.clone(),
        source_observation_hash: unsafe_cycle.source.state_hash.clone(),
        source_observation_sequence: unsafe_cycle.source.sequence,
        fresh_observation_id: Some(unsafe_cycle.fresh.observation_id.clone()),
        fresh_observation_hash: Some(unsafe_cycle.fresh.state_hash.clone()),
        fresh_observation_sequence: Some(unsafe_cycle.fresh.sequence),
        execution_receipt_sha256: Some(unsafe_cycle.receipt_sha256.clone()),
        verified_action_result_sha256: Some(unsafe_cycle.verified_result_sha256.clone()),
        policy_decision_sha256: Some(unsafe_cycle.policy_decision_sha256.clone()),
        activation_admission_sha256: Some(unsafe_cycle.admission_sha256.clone()),
        reason_codes: vec![RecoveryReasonCodeV1::ProtectedInvariantViolation],
        evidence_ids: vec!["actual-protected-invariant-violation".to_owned()],
        detected_at_unix_ms: now_ms.saturating_add(80_000),
        trigger_sha256: empty_hash(),
    }
    .seal());
    let unsafe_ledger = ok(d2i_desktop::initialize_recovery_ledger(
        &temp.path().join("actual-unsafe-recovery-ledger"),
        "actual-unsafe-recovery-ledger",
        "actual-unsafe-recovery-session",
        "goal-trusted-execution",
        64,
        now_ms,
    ));
    let unsafe_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("actual-unsafe-recovery-audit"),
        "actual-unsafe-recovery-audit",
        "actual-unsafe-recovery-session",
        64,
        now_ms,
    ));
    let mut unsafe_recovery = ok(CognitiveRecoveryCoordinatorV1::restore(
        "goal-trusted-execution".to_owned(),
        unsafe_cycle.plan_generation_id.clone(),
        actual_recovery_budget(),
        ok(RecoveryHistoryV1::empty(
            "actual-unsafe-recovery-history".to_owned(),
            "goal-trusted-execution".to_owned(),
        )),
        actual_recovery_profile(),
        unsafe_ledger,
        unsafe_audit,
    ));
    ok(unsafe_recovery.begin(unsafe_trigger, now_ms.saturating_add(80_001)));
    ok(unsafe_recovery.classify(now_ms.saturating_add(80_002)));
    let unsafe_decision = ok(unsafe_recovery.decide(
        &RecoveryDecisionContextV1 {
            verification_verdict: Some(RecoveryVerificationVerdictV1::Unsafe),
            goal_progress: GoalProgress::InProgress,
            latest_observation_trusted: true,
            bounded_user_fact_missing: false,
            same_failure_count: 1,
            same_capability_attempts: 1,
            current_proposal_id: Some(unsafe_cycle.proposal_id.clone()),
            current_proposal_sha256: Some(unsafe_cycle.proposal_sha256.clone()),
            current_capability_id: Some("uia.toggle".to_owned()),
            current_risk: CognitiveRiskClass::Reversible,
            alternate_capability_ids: Vec::new(),
            replan_available: true,
        },
        now_ms.saturating_add(80_003),
    ))
    .clone();
    assert_eq!(
        unsafe_decision.decision_kind,
        RecoveryDecisionKindV1::Escalate
    );
    let second_mutation_called = AtomicBool::new(false);
    assert!(unsafe_recovery
        .execute_fresh_cycle(&request, now_ms.saturating_add(80_004), || {
            second_mutation_called.store(true, Ordering::SeqCst);
            Err(d2i_desktop::DesktopError::AccessDenied(
                "unsafe retry must never run".to_owned(),
            ))
        })
        .is_err());
    assert!(!second_mutation_called.load(Ordering::SeqCst));
    let escalation = ok(EscalationRequestV1 {
        schema_version: RECOVERY_SCHEMA_VERSION,
        escalation_id: "actual-unsafe-escalation".to_owned(),
        recovery_decision_sha256: unsafe_decision.decision_sha256,
        goal_id: "goal-trusted-execution".to_owned(),
        severity: EscalationSeverityV1::Critical,
        reason_codes: vec![RecoveryReasonCodeV1::ProtectedInvariantViolation],
        originating_stage: RecoveryStageV1::Verification,
        required_authority_class: RequiredAuthorityClassV1::SecurityOwner,
        blocked_capability_ids: vec!["uia.toggle".to_owned()],
        policy_set_sha256: digest("policy-set"),
        authority_sha256: digest("actual-recovery-authority"),
        latest_observation_hash: unsafe_cycle.fresh.state_hash,
        verified_action_result_sha256: Some(unsafe_cycle.verified_result_sha256),
        protected_violation_count: 1,
        unexpected_change_count: 0,
        safe_state_summary_codes: vec![
            SafeStateSummaryCodeV1::AutomaticMutationBlocked,
            SafeStateSummaryCodeV1::ProtectedInvariantViolated,
        ],
        recommended_next_action_codes: vec![RecommendedNextActionCodeV1::InspectProtectedEvidence],
        evidence_ids: vec!["actual-unsafe-verification".to_owned()],
        raised_at_unix_ms: now_ms.saturating_add(80_005),
        escalation_sha256: empty_hash(),
    }
    .seal());
    let escalated = ok(unsafe_recovery.escalate(&escalation, now_ms.saturating_add(80_005)));
    assert_eq!(
        escalated.outcome,
        d2i_desktop::RecoveryCycleOutcomeV1::Escalated
    );
    assert_eq!(
        unsafe_recovery.state(),
        CognitiveRecoveryCoordinatorStateV1::Terminal
    );
}

#[test]
fn cognitive_admission_binds_to_one_shot_windows_uia_execution() {
    let _uia_fixture = lock_uia_fixture();
    let temp = TempDirectory::new();
    let now = now_seconds();
    let now_ms = now * 1_000;
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let powershell = ok(fs::canonicalize(
        Path::new(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&powershell)));
    let title = format!("D2I Trusted Execution {}", std::process::id());
    let output_path = temp.path().join("trusted-uia-value.txt");
    let script = ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("support")
            .join("windows_ui_fixture.ps1"),
    ));
    let child = ok(Command::new(&powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-WindowTitle")
        .arg(&title)
        .arg("-OutputPath")
        .arg(&output_path)
        .spawn());
    let process_id = child.id();
    let mut fixture_process = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(
        ok(fixture_process.0.try_wait()).is_none(),
        "UIA fixture exited before trusted execution"
    );

    let configuration = configuration(&executable_hash);
    let (windows_admission, session_id) = certified_admission(&configuration, &temp, now);
    let platform_activation = ok(project_windows_activation(
        &windows_admission,
        &configuration,
    ));
    let target = WindowsUiaObservationTarget {
        schema_version: 1,
        process_id,
        executable_path: powershell.display().to_string(),
        executable_hash,
        window_title_hash: sha(title.as_bytes()),
        session_id,
        runtime_binding_digest: platform_activation.runtime_binding_sha256.clone(),
    };
    let observation = source_observation(&platform_activation, &target);
    let payload_bytes = b"trusted reversible UIA mutation".to_vec();
    let ready = policy_ready(&observation, &payload_bytes);
    let arguments: CandidateActionArguments =
        ok(serde_json::from_value(ready.proposal.arguments.clone()));
    let grounded_target_sha256 = ok(trusted_execution_sha256(&arguments.target));
    let (cognitive_admission, eligibility) =
        policy_artifacts(ready.clone(), &platform_activation, now);
    let session = ok(TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: "trusted-execution-session".to_owned(),
        action_sequence: 1,
        runtime_build_id: "runtime-build-fixture".to_owned(),
        runtime_package_sha256: digest("runtime-package-fixture"),
        generated_at_unix_ms: now_ms + 2_000,
        expires_at_unix_ms: now_ms + 120_000,
        expected_organization_id: "organization-1".to_owned(),
        expected_integration_id: platform_activation.integration_id.clone(),
        expected_adapter_kind: AdapterKindV1::Uia,
        expected_activation_ledger_id: platform_activation.activation_ledger_id.clone(),
        expected_activation_ledger_chain_head: platform_activation
            .activation_ledger_chain_head
            .clone(),
        evidence_ids: vec!["runtime-package".to_owned()],
        session_sha256: empty_hash(),
    }
    .seal());
    let request = ok(TrustedExecutionBindingRequestV1::new(
        ready,
        cognitive_admission,
        eligibility,
        session,
        platform_activation,
        &observation,
        grounded_target_sha256,
    ));
    let audit_root = temp.path().join("protected-audit");
    let audit = ok(initialize_windows_deployment_audit(
        &audit_root,
        "trusted-execution-audit",
        "trusted-execution-session",
        64,
        now_ms,
    ));
    let payload = ok(EphemeralActionPayload::new(
        "trusted-fixture-input".to_owned(),
        payload_bytes.clone(),
        now_ms + 2_000,
        now_ms + 60_000,
    ));
    let mut coordinator = ok(CognitiveTrustedExecutionCoordinator::bind(
        request,
        &observation,
        windows_admission,
        configuration,
        TrustedTargetResolverInput::Uia { target },
        Some(payload),
        audit,
        now_ms + 3_000,
    ));
    assert!(coordinator.has_live_execution_material());
    let worker_process_id = coordinator
        .owned_worker_process_id()
        .unwrap_or_else(|| panic!("owned Windows worker PID is absent"));
    assert!(process_exists(worker_process_id));
    assert!(!output_path.exists(), "bind performed a UI side effect");

    let preparation = ok(coordinator.prepare(now_ms + 4_000));
    assert!(!output_path.exists(), "prepare performed a UI side effect");
    assert!(
        coordinator.prepare(now_ms + 4_001).is_err(),
        "a second pending preparation was accepted"
    );
    let receipt = ok(coordinator.commit(&preparation, now_ms + 5_000));
    assert_eq!(receipt.status, TrustedExecutionStatusV1::Succeeded);
    assert!(!coordinator.has_live_execution_material());
    assert!(coordinator.owned_worker_process_id().is_none());
    assert!(!coordinator.is_poisoned());
    assert_eq!(coordinator.terminal_receipt(), Some(&receipt));
    assert!(
        coordinator.commit(&preparation, now_ms + 5_001).is_err(),
        "a terminal coordinator accepted a second commit"
    );
    let execution = ok(to_verification_bound_execution_v2(&receipt));
    assert_eq!(execution.status, ExecutionStatus::Succeeded);
    assert!(
        receipt
            .evidence_ids
            .iter()
            .any(|value| value == "not-postcondition-verified"),
        "adapter attempt was presented as a verified postcondition"
    );
    for _ in 0..50 {
        if fs::read(&output_path).is_ok_and(|bytes| bytes == payload_bytes) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(ok(fs::read(&output_path)), payload_bytes);
    for _ in 0..30 {
        if !process_exists(worker_process_id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !process_exists(worker_process_id),
        "owned Windows worker remained after terminal commit"
    );
    let audit_verification = ok(verify_windows_deployment_audit(&audit_root));
    assert!(audit_verification.record_count >= 6);
}

#[test]
fn ephemeral_payload_rejects_credentials_and_invalid_bounds() {
    assert!(EphemeralActionPayload::new(
        "credential-source".to_owned(),
        b"not retained".to_vec(),
        1,
        2,
    )
    .is_err());
    assert!(EphemeralActionPayload::new(
        "trusted-source".to_owned(),
        b"bearer token".to_vec(),
        1,
        2,
    )
    .is_err());
    assert!(EphemeralActionPayload::new("trusted-source".to_owned(), Vec::new(), 1, 2,).is_err());
}

#[test]
fn live_execution_is_freshly_reobserved_and_verified() {
    let _uia_fixture = lock_uia_fixture();
    let temp = TempDirectory::new();
    let now = now_seconds();
    let now_ms = now * 1_000;
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let powershell = ok(fs::canonicalize(
        Path::new(&system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    ));
    let executable_hash = sha(&ok(fs::read(&powershell)));
    let title = format!("D2I Reobserve Verification {}", std::process::id());
    let output_path = temp.path().join("reobserve-uia-value.txt");
    let script = ok(fs::canonicalize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("support")
            .join("windows_ui_fixture.ps1"),
    ));
    let child = ok(Command::new(&powershell)
        .args(["-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .arg("-WindowTitle")
        .arg(&title)
        .arg("-OutputPath")
        .arg(&output_path)
        .spawn());
    let process_id = child.id();
    let mut fixture_process = ChildGuard(child);
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(ok(fixture_process.0.try_wait()).is_none());

    let configuration = configuration(&executable_hash);
    let configuration_hash = ok(configuration.configuration_hash());
    let (source_admission, source_session_id) =
        certified_admission_labeled(&configuration, &temp, now, "source-observer");
    let source_target = WindowsUiaObservationTarget {
        schema_version: 1,
        process_id,
        executable_path: powershell.display().to_string(),
        executable_hash: executable_hash.clone(),
        window_title_hash: sha(title.as_bytes()),
        session_id: source_session_id,
        runtime_binding_digest: configuration_hash.clone(),
    };
    let source_adapter = ok(WindowsUiAutomationAdapter::bind(
        source_admission.activation,
        configuration.clone(),
        now + 2,
    ));
    let source_audit_root = temp.path().join("source-observation-audit");
    let source_audit = ok(initialize_windows_deployment_audit(
        &source_audit_root,
        "reobserve-source-audit",
        "reobserve-source-session",
        64,
        now_ms,
    ));
    let source_provider = ok(WindowsUiaObservationProvider::new(
        source_adapter,
        source_target.clone(),
        ObservationLimits::default(),
        source_audit,
    ));
    let source_completed = ok(source_provider.observe_once(&goal(), 11));
    assert!(source_completed.worker_exited_cleanly);
    assert_eq!(source_completed.read_only_side_effect_count, 0);
    assert!(!process_exists(source_completed.worker_process_id));

    let (execution_admission, session_id) =
        certified_admission_labeled(&configuration, &temp, now, "mutation");
    assert_eq!(session_id, source_target.session_id);
    let platform_activation = ok(project_windows_activation(
        &execution_admission,
        &configuration,
    ));
    let source = ok(bind_actual_source_observation(
        &source_completed.snapshot,
        &platform_activation,
    ));
    let text_element = source
        .observable_elements
        .iter()
        .find(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("D2IText")
        })
        .unwrap_or_else(|| panic!("actual UIA text element is absent"));
    let protected_element = source
        .observable_elements
        .iter()
        .find(|element| {
            element
                .value
                .pointer("/automation_id/text")
                .and_then(Value::as_str)
                == Some("D2ICheckbox")
        })
        .unwrap_or_else(|| panic!("actual UIA protected checkbox is absent"));
    let payload_bytes = b"verified fresh UIA mutation".to_vec();
    let payload_text = std::str::from_utf8(&payload_bytes)
        .unwrap_or_else(|error| panic!("fixture payload is not UTF-8: {error}"));
    let mut expected_text_value = text_element.value.clone();
    *expected_text_value
        .pointer_mut("/current_value")
        .unwrap_or_else(|| panic!("text current_value is absent")) = json!({
        "status": "present",
        "value": {
            "text": payload_text,
            "text_hash": sha(&payload_bytes),
            "truncated": false
        }
    });
    let expected_postcondition = Postcondition {
        target_state: format!("element:{}:value", text_element.element_id),
        op: ComparisonOp::Equals,
        expected_value: ok(trusted_execution_sha256(&expected_text_value)).into(),
        required: true,
        timeout_ms: 5_000,
    };
    let verification_goal = GoalSpec {
        schema_version: 1,
        goal_id: "goal-trusted-execution".to_owned(),
        objective: "Set and independently verify one local fixture value".to_owned(),
        scope: BTreeMap::from([("fixture".to_owned(), json!("windows-uia"))]),
        required_outcomes: vec!["fresh observation contains the expected value".to_owned()],
        constraints: vec!["protected checkbox remains unchanged".to_owned()],
        success_criteria: vec![expected_postcondition.clone()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "trusted reobserve integration fixture".to_owned(),
            source_hash: digest("reobserve-goal-source"),
            module_id: "reobserve-verifier-test".to_owned(),
        },
    };
    let ready = policy_ready_for_target(
        &source,
        &payload_bytes,
        &text_element.element_id,
        &text_element.kind,
        expected_postcondition,
    );
    let arguments: CandidateActionArguments =
        ok(serde_json::from_value(ready.proposal.arguments.clone()));
    let grounded_target_sha256 = ok(trusted_execution_sha256(&arguments.target));
    let (cognitive_admission, eligibility) = policy_artifacts_for_goal(
        ready.clone(),
        &platform_activation,
        now,
        verification_goal.clone(),
    );
    let session = ok(TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: "reobserve-execution-session".to_owned(),
        action_sequence: 1,
        runtime_build_id: "runtime-build-reobserve".to_owned(),
        runtime_package_sha256: digest("runtime-package-reobserve"),
        generated_at_unix_ms: now_ms + 2_000,
        expires_at_unix_ms: now_ms + 120_000,
        expected_organization_id: "organization-1".to_owned(),
        expected_integration_id: platform_activation.integration_id.clone(),
        expected_adapter_kind: AdapterKindV1::Uia,
        expected_activation_ledger_id: platform_activation.activation_ledger_id.clone(),
        expected_activation_ledger_chain_head: platform_activation
            .activation_ledger_chain_head
            .clone(),
        evidence_ids: vec!["runtime-package".to_owned()],
        session_sha256: empty_hash(),
    }
    .seal());
    let execution_binding = ok(TrustedExecutionBindingRequestV1::new(
        ready.clone(),
        cognitive_admission,
        eligibility,
        session,
        platform_activation,
        &source,
        grounded_target_sha256,
    ));
    let execution_target = WindowsUiaObservationTarget {
        session_id,
        runtime_binding_digest: configuration_hash.clone(),
        ..source_target.clone()
    };
    let mutation_audit_root = temp.path().join("mutation-audit");
    let mutation_audit = ok(initialize_windows_deployment_audit(
        &mutation_audit_root,
        "reobserve-mutation-audit",
        "reobserve-execution-session",
        64,
        now_ms,
    ));
    let payload = ok(EphemeralActionPayload::new(
        "reobserve-fixture-input".to_owned(),
        payload_bytes.clone(),
        now_ms + 2_000,
        now_ms + 60_000,
    ));
    let mut executor = ok(CognitiveTrustedExecutionCoordinator::bind(
        execution_binding.clone(),
        &source,
        execution_admission,
        configuration.clone(),
        TrustedTargetResolverInput::Uia {
            target: execution_target,
        },
        Some(payload),
        mutation_audit,
        now_ms + 3_000,
    ));
    let mutation_worker_id = executor
        .owned_worker_process_id()
        .unwrap_or_else(|| panic!("mutation worker PID is absent"));
    let preparation = ok(executor.prepare(now_ms + 4_000));
    let receipt = ok(executor.commit(&preparation, now_ms + 5_000));
    assert_eq!(receipt.status, TrustedExecutionStatusV1::Succeeded);
    let execution = ok(to_verification_bound_execution_v2(&receipt));
    drop(executor);
    assert!(!process_exists(mutation_worker_id));
    for _ in 0..50 {
        if fs::read(&output_path).is_ok_and(|bytes| bytes == payload_bytes) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(ok(fs::read(&output_path)), payload_bytes);

    let reobservation_request = ok(ReobservationRequestV1::new(
        &execution_binding,
        &receipt,
        &execution,
        &source,
        now_ms + 6_000,
        now_ms + 90_000,
    ));
    assert_reobserve_schema(&reobservation_request);
    assert_eq!(
        reobservation_request.request_sha256,
        ok(ReobservationRequestV1::new(
            &execution_binding,
            &receipt,
            &execution,
            &source,
            now_ms + 6_000,
            now_ms + 90_000,
        ))
        .request_sha256
    );
    assert!(reobservation_request
        .validate_against(
            &execution_binding,
            &receipt,
            &execution,
            &source,
            now_ms + 90_000,
        )
        .is_err());
    let mut substituted_source = source.clone();
    substituted_source.observation_id = "substituted-source".to_owned();
    assert!(reobservation_request
        .validate_against(
            &execution_binding,
            &receipt,
            &execution,
            &substituted_source,
            now_ms + 6_001,
        )
        .is_err());
    for mutate in [
        |request: &mut ReobservationRequestV1| {
            request.integration_id = "different-integration".to_owned();
        },
        |request: &mut ReobservationRequestV1| {
            request.runtime_binding_sha256 = digest("different-runtime");
        },
    ] {
        let mut substituted = reobservation_request.clone();
        mutate(&mut substituted);
        assert!(substituted
            .validate_against(
                &execution_binding,
                &receipt,
                &execution,
                &source,
                now_ms + 6_001,
            )
            .is_err());
    }
    let guard = ok(VerificationGuardProfileV1::new(
        "guard-live-uia".to_owned(),
        &ready.proposal,
        &source,
        vec![VerificationGuardTargetV1 {
            element_id: text_element.element_id.clone(),
            field: VerificationGuardFieldV1::Value,
        }],
        Vec::new(),
        vec![ProtectedInvariantV1 {
            target: VerificationGuardTargetV1 {
                element_id: protected_element.element_id.clone(),
                field: VerificationGuardFieldV1::Value,
            },
            expected_source_value_hash: ok(trusted_execution_sha256(&protected_element.value)),
            severity: ProtectedInvariantSeverityV1::Unsafe,
            reason_code: "protected-checkbox-stable".to_owned(),
        }],
        vec![IgnoredVolatileTargetV1 {
            target: VerificationGuardTargetV1 {
                element_id: "observation.status".to_owned(),
                field: VerificationGuardFieldV1::Value,
            },
            approved_reason_code: "bounded-observation-metrics-volatile".to_owned(),
            evidence_id: "windows-observation-contract".to_owned(),
        }],
        0,
        vec!["actual-windows-uia".to_owned()],
    ));
    assert_reobserve_schema(&guard);
    let (fresh_admission, fresh_session_id) =
        certified_admission_labeled(&configuration, &temp, now, "fresh-observer");
    assert_eq!(fresh_session_id, session_id);
    let fresh_adapter = ok(WindowsUiAutomationAdapter::bind(
        fresh_admission.activation,
        configuration.clone(),
        now + 2,
    ));
    let fresh_audit_root = temp.path().join("fresh-observation-audit");
    let fresh_audit = ok(initialize_windows_deployment_audit(
        &fresh_audit_root,
        "reobserve-fresh-audit",
        "reobserve-fresh-session",
        64,
        now_ms,
    ));
    let fresh_provider = ok(WindowsUiaObservationProvider::new(
        fresh_adapter,
        WindowsUiaObservationTarget {
            session_id: fresh_session_id,
            runtime_binding_digest: configuration_hash,
            ..source_target
        },
        ObservationLimits::default(),
        fresh_audit,
    ));
    let verification_audit_root = temp.path().join("verification-audit");
    let verification_audit = ok(initialize_windows_deployment_audit(
        &verification_audit_root,
        "cognitive-verification-audit",
        "reobserve-execution-session",
        64,
        now_ms,
    ));
    let mut consumption = VerificationConsumptionLedgerV1::default();
    let mut verifier = ok(CognitiveVerificationCoordinatorV2::begin(
        execution_binding.clone(),
        verification_goal.clone(),
        ready.clone(),
        receipt.clone(),
        execution.clone(),
        source.clone(),
        reobservation_request.clone(),
        guard.clone(),
        verification_audit,
        &mut consumption,
        now_ms + 6_000,
    ));
    let fresh_proof = ok(verifier.reobserve(
        TrustedReadOnlyObservationConfiguration::Uia(fresh_provider),
        now_ms + 7_000,
    ))
    .clone();
    assert_reobserve_schema(&fresh_proof);
    let fresh_snapshot = verifier
        .fresh_observation()
        .cloned()
        .unwrap_or_else(|| panic!("fresh UIA observation is absent"));
    let fresh_worker_id = verifier
        .observation_worker_process_id()
        .unwrap_or_else(|| panic!("fresh worker PID is absent"));
    assert_eq!(
        fresh_proof.proof_sha256,
        ok(FreshObservationProofV1::new(
            &reobservation_request,
            &source,
            &fresh_snapshot,
            fresh_proof.observation_transport_binding_sha256.clone(),
            fresh_proof.observation_activation_record_hash.clone(),
            fresh_proof.integration_id.clone(),
            fresh_proof.runtime_binding_sha256.clone(),
            fresh_proof.observed_at_unix_ms,
            fresh_proof.observation_duration_ms,
            0,
            FreshObservationWorkerExitStatusV1::Clean,
        ))
        .proof_sha256
    );
    let proof_inputs = |fresh: &ObservationSnapshot,
                        side_effects: u64,
                        exit_status: FreshObservationWorkerExitStatusV1| {
        FreshObservationProofV1::new(
            &reobservation_request,
            &source,
            fresh,
            fresh_proof.observation_transport_binding_sha256.clone(),
            fresh_proof.observation_activation_record_hash.clone(),
            fresh_proof.integration_id.clone(),
            fresh_proof.runtime_binding_sha256.clone(),
            fresh_proof.observed_at_unix_ms,
            fresh_proof.observation_duration_ms,
            side_effects,
            exit_status,
        )
    };
    let mut stale_sequence = fresh_snapshot.clone();
    stale_sequence.sequence = source.sequence;
    stale_sequence.state_hash = ok(stale_sequence.compute_state_hash());
    assert!(proof_inputs(
        &stale_sequence,
        0,
        FreshObservationWorkerExitStatusV1::Clean
    )
    .is_err());
    let mut reused_id = fresh_snapshot.clone();
    reused_id.observation_id = source.observation_id.clone();
    reused_id.state_hash = ok(reused_id.compute_state_hash());
    assert!(proof_inputs(&reused_id, 0, FreshObservationWorkerExitStatusV1::Clean).is_err());
    let mut wrong_kind = fresh_snapshot.clone();
    wrong_kind.source_kind = ObservationSourceKind::Fixture;
    wrong_kind.state_hash = ok(wrong_kind.compute_state_hash());
    assert!(proof_inputs(&wrong_kind, 0, FreshObservationWorkerExitStatusV1::Clean).is_err());
    let mut wrong_target = fresh_snapshot.clone();
    wrong_target
        .target_binding
        .insert("process_id".to_owned(), "1".to_owned());
    wrong_target.provenance.source_hash =
        ok(trusted_execution_sha256(&wrong_target.target_binding));
    wrong_target.state_hash = ok(wrong_target.compute_state_hash());
    assert!(proof_inputs(&wrong_target, 0, FreshObservationWorkerExitStatusV1::Clean).is_err());
    assert!(proof_inputs(
        &fresh_snapshot,
        1,
        FreshObservationWorkerExitStatusV1::Clean
    )
    .is_err());
    assert!(proof_inputs(
        &fresh_snapshot,
        0,
        FreshObservationWorkerExitStatusV1::Abnormal
    )
    .is_err());
    let delta = ok(verifier.analyze_delta(now_ms + 8_000)).clone();
    assert_reobserve_schema(&delta);
    assert_eq!(delta.expected_changes.len(), 1, "{delta:?}");
    assert!(delta.protected_invariant_violations.is_empty(), "{delta:?}");
    assert!(delta.unexpected_changes.is_empty(), "{delta:?}");
    assert!(delta.security_relevant_changes.is_empty(), "{delta:?}");
    let _ = ok(verifier.build_verification_request());
    let verification_result = ok(verifier.verify(now_ms + 9_000)).clone();
    assert_eq!(
        verification_result.action_verdict,
        VerificationVerdictV2::Passed,
        "verification result: {verification_result:#?}; expected value: {expected_text_value:#?}; fresh element: {:#?}",
        fresh_snapshot
            .observable_elements
            .iter()
            .find(|element| element.element_id == text_element.element_id)
    );
    assert_eq!(verification_result.goal_progress, GoalProgress::Complete);
    let terminal = ok(verifier.finalize(now_ms + 10_000));
    assert_reobserve_schema(&terminal);
    assert_eq!(terminal.action_verdict, VerificationVerdictV2::Passed);
    assert_eq!(terminal.goal_progress, GoalProgress::Complete);
    drop(verifier);
    assert!(consumption.is_terminal(&receipt.receipt_sha256));
    assert!(!process_exists(fresh_worker_id));
    assert!(ok(verify_windows_deployment_audit(&verification_audit_root)).record_count >= 6);

    let mut unsafe_snapshot = fresh_snapshot.clone();
    let unsafe_element = unsafe_snapshot
        .observable_elements
        .iter_mut()
        .find(|element| element.element_id == protected_element.element_id)
        .unwrap_or_else(|| panic!("protected element disappeared from fresh observation"));
    unsafe_element
        .value
        .as_object_mut()
        .unwrap_or_else(|| panic!("protected value is not an object"))
        .insert("checked".to_owned(), Value::Bool(true));
    unsafe_snapshot.state_hash = ok(unsafe_snapshot.compute_state_hash());
    let unsafe_delta = ok(analyze_observation_delta(&source, &unsafe_snapshot, &guard));
    assert_eq!(unsafe_delta.protected_invariant_violations.len(), 1);
    let unsafe_proof = ok(FreshObservationProofV1::new(
        &reobservation_request,
        &source,
        &unsafe_snapshot,
        fresh_proof.observation_transport_binding_sha256.clone(),
        fresh_proof.observation_activation_record_hash.clone(),
        fresh_proof.integration_id.clone(),
        fresh_proof.runtime_binding_sha256.clone(),
        fresh_proof.observed_at_unix_ms,
        fresh_proof.observation_duration_ms,
        0,
        FreshObservationWorkerExitStatusV1::Clean,
    ));
    let spec = ok(VerificationSpecAdapterV1::adapt(
        &verification_goal,
        &ready,
        &ready.proposal,
        &source,
        &receipt,
        &execution,
    ));
    let unsafe_request = VerificationRequestV2 {
        schema_version: 2,
        verification_id: "verification-unsafe-fixture".to_owned(),
        goal: spec.goal.clone(),
        proposal: spec.proposal.clone(),
        execution: execution.clone(),
        source_observation: source.clone(),
        fresh_observation: unsafe_snapshot,
    };
    ok(unsafe_request.validate());
    let mut deterministic = ok(DeterministicPostconditionVerifierV2::new(
        spec.binding,
        guard.clone(),
        unsafe_delta,
        unsafe_proof,
        Provenance {
            source: "unsafe protected-invariant fixture".to_owned(),
            source_hash: digest("unsafe-verifier-context"),
            module_id: "reobserve-verifier-test".to_owned(),
        },
    ));
    let unsafe_result = ok(deterministic.verify(&unsafe_request));
    assert_eq!(unsafe_result.action_verdict, VerificationVerdictV2::Unsafe);

    let replay_audit = ok(initialize_windows_deployment_audit(
        &temp.path().join("replay-audit"),
        "cognitive-verification-replay-audit",
        "reobserve-execution-session",
        16,
        now_ms,
    ));
    assert!(CognitiveVerificationCoordinatorV2::begin(
        execution_binding,
        verification_goal,
        ready,
        receipt,
        execution,
        source,
        reobservation_request,
        guard,
        replay_audit,
        &mut consumption,
        now_ms + 11_000,
    )
    .is_err());
}
