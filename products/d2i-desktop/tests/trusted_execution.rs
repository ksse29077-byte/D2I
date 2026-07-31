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
    activate_certified_windows_binding, certify_windows_binding,
    initialize_windows_activation_ledger, initialize_windows_deployment_audit,
    project_windows_activation, to_verification_bound_execution_v2, trusted_execution_sha256,
    verify_signed_windows_certification, verify_windows_activation_ledger,
    verify_windows_deployment_audit, CognitiveTrustedExecutionCoordinator,
    ConcreteWindowsRuntimeBindingProbe, EphemeralActionPayload, ExecutionStatus,
    PolicyReadyActionV1, TrustedExecutionBindingRequestV1, TrustedExecutionSessionV1,
    TrustedExecutionStatusV1, TrustedTargetResolverInput, WindowsActivationAdmission,
    WindowsAdapterConfiguration, WindowsAdapterKind, WindowsRuntimeBindingProbe,
    WindowsRuntimeManifest, WindowsUiaObservationTarget, TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
use d2i_policy_admission::{
    admit_action, evaluate_policy, ActivationEligibilityContextV1, AdapterKindV1,
    AdmissionIssuanceV1, AuthorityScopeConstraintsV1, DelegatedAuthorityContextV1,
    GrantConsumptionLedgerV1, PolicyEvaluationRequestV1, RequestedAutonomyModeV1,
    TrustedPolicySnapshotV1, TrustedPolicyStateV1, POLICY_ADMISSION_SCHEMA_VERSION,
};
use ed25519_dalek::SigningKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    let attestor_key = SigningKey::from_bytes(&[71_u8; 32]);
    let certifier_key = SigningKey::from_bytes(&[72_u8; 32]);
    let integration_id = "windows-trusted-execution".to_owned();
    let probe = ok(ConcreteWindowsRuntimeBindingProbe::new(
        configuration.clone(),
        "binding-trusted-execution".to_owned(),
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
        "certificate-trusted-execution".to_owned(),
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
    let ledger_root = temp.path().join("activation-ledger");
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
    let target = CandidateTargetBinding {
        application_pack_sha256: digest("application-pack"),
        observation_bridge_sha256: digest("observation-bridge"),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        grounding_case_id: "grounding-case-1".to_owned(),
        semantic_target_id: "profile.name".to_owned(),
        element_id: "uia-text-element".to_owned(),
        element_kind: "uia.edit".to_owned(),
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
        proposal_id: "proposal-trusted-execution".to_owned(),
        goal_id: "goal-trusted-execution".to_owned(),
        plan_generation_id: "plan-trusted-execution".to_owned(),
        source_observation_hash: observation.state_hash.clone(),
        capability_id: "uia.set_value".to_owned(),
        semantic_target: "profile.name".to_owned(),
        arguments: ok(serde_json::to_value(arguments)),
        preconditions: Vec::new(),
        expected_postconditions: vec![postcondition()],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["trusted fixture".to_owned()],
        valid_until_sequence: observation.sequence,
    };
    let mut ready = PolicyReadyActionV1 {
        schema_version: 1,
        selection_id: "selection-trusted-execution".to_owned(),
        selection_sha256: digest("selection"),
        candidate_set_sha256: digest("candidate-set"),
        goal_id: proposal.goal_id.clone(),
        world_state_id: "world-trusted-execution".to_owned(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        application_pack_sha256: digest("application-pack"),
        grounding_result_sha256: digest("grounding-result"),
        semantic_target_id: proposal.semantic_target.clone(),
        selected_element_id: "uia-text-element".to_owned(),
        selected_element_kind: "uia.edit".to_owned(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: digest("capability-binding"),
        proposal,
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        expected_postconditions: vec![postcondition()],
        evidence_ids: vec!["grounding-result".to_owned(), "selection-result".to_owned()],
        policy_input_sha256: digest("policy-input"),
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
        goal(),
        authority,
        policy,
        now,
        RequestedAutonomyModeV1::AutonomousPreferred,
    ));
    let decision = ok(evaluate_policy(&request));
    let eligibility = ok(ActivationEligibilityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        eligibility_id: "eligibility-trusted-execution".to_owned(),
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
            admission_id: "admission-trusted-execution".to_owned(),
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

#[test]
fn cognitive_admission_binds_to_one_shot_windows_uia_execution() {
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
