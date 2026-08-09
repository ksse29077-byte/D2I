use d2i_action_candidates::{
    CandidateActionArguments, CandidateActionInput, CandidateTargetBinding,
};
use d2i_action_selection::{
    canonical_sha256 as selection_sha256, GroundedActionArgumentsV1, GroundedTargetBindingV1,
    PolicyReadyActionV1,
};
use d2i_cognitive_ir::{
    ActionProposal, CognitiveRiskClass, ComparisonOp, ConfirmationPolicy, ConfirmationRequirement,
    GoalSpec, ObservableElement, ObservationSnapshot, ObservationSourceKind, Postcondition,
    Provenance, Reversibility, TrustLabel,
};
use d2i_policy_admission::{
    admit_action, evaluate_policy, ActivationEligibilityContextV1, AdmissionIssuanceV1,
    AuthorityScopeConstraintsV1, CognitiveActivationAdmissionV1, DelegatedAuthorityContextV1,
    GrantConsumptionLedgerV1, PolicyEvaluationRequestV1, RequestedAutonomyModeV1,
    TrustedPolicySnapshotV1, TrustedPolicyStateV1, POLICY_ADMISSION_SCHEMA_VERSION,
};
use d2i_trusted_action_execution::{
    action_input, canonical_sha256, expected_input, grounded_target_binding_sha256, operation_kind,
    parse_json_strict, sha256_bytes, AdapterKindV1, BoundDesktopActionV1, InputMaterialKindV1,
    InputMaterialProofV1, PreparedBoundActionV1, SecretClassificationV1, TargetResolutionProofV1,
    TrustedActionExecutionReceiptV1, TrustedAdapterOutcomeStatusV1, TrustedDesktopOperationKindV1,
    TrustedExecutionBindingRequestV1, TrustedExecutionSessionV1, TrustedExecutionStatusV1,
    TrustedPlatformActivationV1, TrustedTargetSourceKindV1,
    TRUSTED_ACTION_EXECUTION_BINDING_V1_SCHEMA, TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
};
use jsonschema::{Draft, JSONSchema};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

const NOW_SECONDS: u64 = 1_010;
const NOW_MS: u64 = NOW_SECONDS * 1_000;
type RequestMutation = Box<dyn Fn(&mut TrustedExecutionBindingRequestV1)>;

#[derive(Clone, Copy)]
enum OperationFixture {
    UiaInvoke,
    UiaSetValue,
    UiaToggle,
    WebClick,
    WebType,
    WebSelect,
}

impl OperationFixture {
    fn capability(self) -> &'static str {
        match self {
            Self::UiaInvoke => "uia.invoke",
            Self::UiaSetValue => "uia.set_value",
            Self::UiaToggle => "uia.toggle",
            Self::WebClick => "webdriver.click",
            Self::WebType => "webdriver.type",
            Self::WebSelect => "webdriver.select",
        }
    }

    fn operation(self) -> TrustedDesktopOperationKindV1 {
        match self {
            Self::UiaInvoke => TrustedDesktopOperationKindV1::UiaInvoke,
            Self::UiaSetValue => TrustedDesktopOperationKindV1::UiaSetValue,
            Self::UiaToggle => TrustedDesktopOperationKindV1::UiaToggle,
            Self::WebClick => TrustedDesktopOperationKindV1::WebDriverClick,
            Self::WebType => TrustedDesktopOperationKindV1::WebDriverType,
            Self::WebSelect => TrustedDesktopOperationKindV1::WebDriverSelect,
        }
    }

    fn adapter(self) -> AdapterKindV1 {
        self.operation().adapter_kind()
    }

    fn source(self) -> ObservationSourceKind {
        match self.adapter() {
            AdapterKindV1::Uia => ObservationSourceKind::Uia,
            AdapterKindV1::WebDriver => ObservationSourceKind::WebDriver,
            AdapterKindV1::EnterpriseApi => {
                panic!("desktop trusted-execution fixture cannot use enterprise API")
            }
            AdapterKindV1::OfficeWorkspace => {
                panic!("desktop trusted-execution fixture cannot use office workspace")
            }
            AdapterKindV1::OfficeDocument => {
                panic!("desktop trusted-execution fixture cannot use office document")
            }
            AdapterKindV1::OfficeSpreadsheet => {
                panic!("desktop trusted-execution fixture cannot use office spreadsheet")
            }
        }
    }

    fn source_contract(self) -> TrustedTargetSourceKindV1 {
        self.operation().source_kind()
    }

    fn element_kind(self) -> &'static str {
        match self {
            Self::UiaInvoke | Self::WebClick => "button",
            Self::UiaSetValue | Self::WebType => "edit",
            Self::UiaToggle => "checkbox",
            Self::WebSelect => "select",
        }
    }

    fn input(self) -> CandidateActionInput {
        match self {
            Self::UiaInvoke => CandidateActionInput::Invoke,
            Self::UiaSetValue => CandidateActionInput::SetText {
                text_hash: sha256_bytes(b"trusted input"),
            },
            Self::UiaToggle => CandidateActionInput::Toggle { desired: true },
            Self::WebClick => CandidateActionInput::Click,
            Self::WebType => CandidateActionInput::TypeText {
                text_hash: sha256_bytes(b"trusted input"),
            },
            Self::WebSelect => CandidateActionInput::Select {
                value_hash: sha256_bytes(b"trusted input"),
            },
        }
    }
}

struct Fixture {
    observation: ObservationSnapshot,
    request: TrustedExecutionBindingRequestV1,
}

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(label: &str) -> String {
    ok(canonical_sha256(&label))
}

fn empty_hash() -> String {
    sha256_bytes(&[])
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

fn goal() -> GoalSpec {
    GoalSpec {
        schema_version: 1,
        goal_id: "goal-1".to_owned(),
        objective: "Update one local fixture target".to_owned(),
        scope: BTreeMap::from([("application".to_owned(), json!("fixture"))]),
        required_outcomes: vec!["action attempted".to_owned()],
        constraints: vec!["local fixture only".to_owned()],
        success_criteria: vec![postcondition()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "trusted fixture".to_owned(),
            source_hash: digest("goal-source"),
            module_id: "trusted-execution-test".to_owned(),
        },
    }
}

fn observation(kind: OperationFixture) -> ObservationSnapshot {
    let mut trust_labels = BTreeSet::new();
    trust_labels.insert(TrustLabel::Fixture);
    let mut snapshot = ObservationSnapshot {
        schema_version: 1,
        observation_id: "observation-1".to_owned(),
        source_kind: kind.source(),
        target_binding: BTreeMap::from([
            ("binding_id".to_owned(), "binding-1".to_owned()),
            ("integration_id".to_owned(), "desktop-local".to_owned()),
            (
                "runtime_binding_digest".to_owned(),
                digest("runtime-binding"),
            ),
        ]),
        state_hash: empty_hash(),
        sequence: 7,
        trust_labels: trust_labels.clone(),
        observable_elements: vec![ObservableElement {
            element_id: "element-1".to_owned(),
            kind: kind.element_kind().to_owned(),
            label: "Local fixture target".to_owned(),
            value: json!({"enabled": true, "read_only": false}),
            trust_labels,
        }],
        redactions: Vec::new(),
        provenance: Provenance {
            source: "read-only observation fixture".to_owned(),
            source_hash: digest("observation-source"),
            module_id: "observation-plane".to_owned(),
        },
    };
    snapshot.state_hash = ok(snapshot.compute_state_hash());
    ok(snapshot.validate());
    snapshot
}

fn policy_ready(kind: OperationFixture, observation: &ObservationSnapshot) -> PolicyReadyActionV1 {
    let capability_binding_sha256 = digest("capability-binding");
    let target = CandidateTargetBinding {
        application_pack_sha256: digest("application-pack"),
        observation_bridge_sha256: digest("observation-bridge"),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        grounding_case_id: "grounding-case-1".to_owned(),
        semantic_target_id: "profile.name".to_owned(),
        element_id: "element-1".to_owned(),
        element_kind: kind.element_kind().to_owned(),
        capability_binding_sha256: capability_binding_sha256.clone(),
    };
    let arguments = CandidateActionArguments {
        schema_version: 1,
        operation: kind.capability().to_owned(),
        target,
        input: kind.input(),
    };
    ok(arguments.validate());
    let proposal = ActionProposal {
        schema_version: 1,
        proposal_id: "proposal-1".to_owned(),
        goal_id: "goal-1".to_owned(),
        plan_generation_id: "plan-1".to_owned(),
        source_observation_hash: observation.state_hash.clone(),
        capability_id: kind.capability().to_owned(),
        semantic_target: "profile.name".to_owned(),
        arguments: ok(serde_json::to_value(arguments)),
        preconditions: Vec::new(),
        expected_postconditions: vec![postcondition()],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["fixture".to_owned()],
        valid_until_sequence: observation.sequence,
    };
    let mut ready = PolicyReadyActionV1 {
        schema_version: 1,
        selection_id: "selection-1".to_owned(),
        selection_sha256: digest("selection"),
        candidate_set_sha256: digest("candidate-set"),
        goal_id: proposal.goal_id.clone(),
        world_state_id: "world-1".to_owned(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        observation_id: observation.observation_id.clone(),
        source_observation_hash: observation.state_hash.clone(),
        source_observation_sequence: observation.sequence,
        application_pack_sha256: digest("application-pack"),
        grounding_result_sha256: digest("grounding"),
        semantic_target_id: proposal.semantic_target.clone(),
        selected_element_id: "element-1".to_owned(),
        selected_element_kind: kind.element_kind().to_owned(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256,
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

fn authority(kind: OperationFixture) -> DelegatedAuthorityContextV1 {
    let capability = kind.capability().to_owned();
    ok(DelegatedAuthorityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        authority_id: "authority-1".to_owned(),
        organization_id: "organization-1".to_owned(),
        actor_id: "actor-1".to_owned(),
        role_id: "role-1".to_owned(),
        policy_set_id: "policy-set-1".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("policy-set"),
        allowed_capability_ids: vec![capability.clone()],
        forbidden_capability_ids: Vec::new(),
        autonomous_capability_ids: vec![capability],
        confirmation_capability_ids: Vec::new(),
        maximum_autonomous_risk: CognitiveRiskClass::Reversible,
        maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
        allowed_application_pack_sha256: digest("application-pack"),
        allowed_integration_ids: vec!["desktop-local".to_owned()],
        scope_constraints: AuthorityScopeConstraintsV1 {
            application_pack_sha256: digest("application-pack"),
            integration_ids: vec!["desktop-local".to_owned()],
            semantic_target_ids: vec!["profile.name".to_owned()],
        },
        valid_from_unix_seconds: 900,
        expires_at_unix_seconds: 2_000,
        evidence_ids: vec!["delegated-authority".to_owned()],
        authority_sha256: empty_hash(),
    }
    .seal())
}

fn policy() -> TrustedPolicySnapshotV1 {
    ok(TrustedPolicySnapshotV1 {
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
        effective_from_unix_seconds: 900,
        expires_at_unix_seconds: 2_000,
        evidence_ids: vec!["trusted-policy".to_owned()],
        snapshot_sha256: empty_hash(),
    }
    .seal())
}

fn eligibility(
    ready: &PolicyReadyActionV1,
    adapter: AdapterKindV1,
) -> ActivationEligibilityContextV1 {
    ok(ActivationEligibilityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        eligibility_id: "eligibility-1".to_owned(),
        organization_id: "organization-1".to_owned(),
        integration_id: "desktop-local".to_owned(),
        application_pack_sha256: ready.application_pack_sha256.clone(),
        runtime_binding_id: "runtime-binding-1".to_owned(),
        runtime_binding_sha256: digest("runtime-binding"),
        adapter_kind: adapter,
        activation_scope_id: "activation-scope-1".to_owned(),
        activation_ledger_id: "activation-ledger-1".to_owned(),
        activation_ledger_chain_head: digest("ledger-head"),
        eligible_capability_ids: vec![ready.capability_id.clone()],
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        observed_at_unix_seconds: 1_000,
        expires_at_unix_seconds: 1_200,
        evidence_ids: vec!["activation-eligibility".to_owned()],
        eligibility_sha256: empty_hash(),
    }
    .seal())
}

fn session(adapter: AdapterKindV1) -> TrustedExecutionSessionV1 {
    ok(TrustedExecutionSessionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_session_id: "execution-session-1".to_owned(),
        action_sequence: 1,
        runtime_build_id: "runtime-build-1".to_owned(),
        runtime_package_sha256: digest("runtime-package"),
        generated_at_unix_ms: NOW_MS - 1_000,
        expires_at_unix_ms: NOW_MS + 80_000,
        expected_organization_id: "organization-1".to_owned(),
        expected_integration_id: "desktop-local".to_owned(),
        expected_adapter_kind: adapter,
        expected_activation_ledger_id: "activation-ledger-1".to_owned(),
        expected_activation_ledger_chain_head: digest("ledger-head"),
        evidence_ids: vec!["runtime-package".to_owned()],
        session_sha256: empty_hash(),
    }
    .seal())
}

fn platform(adapter: AdapterKindV1) -> TrustedPlatformActivationV1 {
    TrustedPlatformActivationV1 {
        activation_ledger_id: "activation-ledger-1".to_owned(),
        activation_ledger_chain_head: digest("ledger-head"),
        integration_id: "desktop-local".to_owned(),
        binding_id: "binding-1".to_owned(),
        activation_record_hash: digest("activation-record"),
        runtime_binding_sha256: digest("runtime-binding"),
        adapter_kind: adapter,
        adapter_descriptor_sha256: digest("adapter-descriptor"),
        observed_at_unix_seconds: 1_000,
        expires_at_unix_seconds: 1_100,
    }
}

fn fixture(kind: OperationFixture) -> Fixture {
    let observation = observation(kind);
    let ready = policy_ready(kind, &observation);
    let policy_request = ok(PolicyEvaluationRequestV1::new(
        ready.clone(),
        goal(),
        authority(kind),
        policy(),
        1_000,
        RequestedAutonomyModeV1::AutonomousPreferred,
    ));
    let decision = ok(evaluate_policy(&policy_request));
    let eligibility = eligibility(&ready, kind.adapter());
    let admission: CognitiveActivationAdmissionV1 = ok(admit_action(
        &policy_request,
        &decision,
        None,
        None,
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        AdmissionIssuanceV1 {
            admission_id: "admission-1".to_owned(),
            admitted_at_unix_seconds: NOW_SECONDS,
            expires_at_unix_seconds: 1_090,
            expected_runtime_binding_sha256: eligibility.runtime_binding_sha256.clone(),
            expected_activation_ledger_chain_head: eligibility.activation_ledger_chain_head.clone(),
            expected_adapter_kind: kind.adapter(),
        },
    ));
    let arguments: CandidateActionArguments =
        ok(serde_json::from_value(ready.proposal.arguments.clone()));
    let grounded_target_sha256 = ok(canonical_sha256(&arguments.target));
    let request = ok(TrustedExecutionBindingRequestV1::new(
        ready,
        admission,
        eligibility,
        session(kind.adapter()),
        platform(kind.adapter()),
        &observation,
        grounded_target_sha256,
    ));
    Fixture {
        observation,
        request,
    }
}

fn resolution(fixture: &Fixture) -> TargetResolutionProofV1 {
    let request = &fixture.request;
    ok(TargetResolutionProofV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        resolution_id: "resolution-1".to_owned(),
        request_sha256: request.request_sha256.clone(),
        proposal_sha256: ok(canonical_sha256(&request.policy_ready_action.proposal)),
        grounded_target_binding_sha256: request.expected_grounded_target_binding_sha256.clone(),
        selected_element_id: request.policy_ready_action.selected_element_id.clone(),
        selected_element_kind: request.policy_ready_action.selected_element_kind.clone(),
        source_kind: operation_kind(&request.policy_ready_action)
            .unwrap_or(TrustedDesktopOperationKindV1::UiaInvoke)
            .source_kind(),
        source_observation_id: request.source_observation_id.clone(),
        source_observation_hash: request.source_observation_hash.clone(),
        source_observation_sequence: request.source_observation_sequence,
        fresh_resolution_observation_hash: digest("fresh-resolution"),
        runtime_binding_sha256: request.platform_activation.runtime_binding_sha256.clone(),
        integration_id: request.platform_activation.integration_id.clone(),
        binding_id: request.platform_activation.binding_id.clone(),
        activation_record_hash: request.platform_activation.activation_record_hash.clone(),
        adapter_descriptor_sha256: request
            .platform_activation
            .adapter_descriptor_sha256
            .clone(),
        target_material_sha256: digest("target-material"),
        unique_match_count: 1,
        resolved_at_unix_ms: NOW_MS + 1_000,
        expires_at_unix_ms: NOW_MS + 20_000,
        evidence_ids: vec!["fresh-resolution".to_owned()],
        resolution_sha256: empty_hash(),
    }
    .seal())
}

fn input_proof(fixture: &Fixture) -> Option<InputMaterialProofV1> {
    let request = &fixture.request;
    let (kind, expected) = ok(expected_input(&request.policy_ready_action));
    kind.map(|input_kind| {
        ok(InputMaterialProofV1 {
            schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
            material_id: "material-1".to_owned(),
            request_sha256: request.request_sha256.clone(),
            proposal_sha256: ok(canonical_sha256(&request.policy_ready_action.proposal)),
            input_kind,
            expected_content_sha256: expected.clone().unwrap_or_else(empty_hash),
            supplied_content_sha256: expected.unwrap_or_else(empty_hash),
            byte_length: b"trusted input".len() as u64,
            secret_classification: SecretClassificationV1::NonSecret,
            material_source_id: "trusted-input-1".to_owned(),
            resolved_at_unix_ms: NOW_MS + 1_000,
            expires_at_unix_ms: NOW_MS + 20_000,
            evidence_ids: vec!["trusted-input".to_owned()],
            material_proof_sha256: empty_hash(),
        }
        .seal())
    })
}

fn bound_action(
    fixture: &Fixture,
    resolution: &TargetResolutionProofV1,
    input: Option<&InputMaterialProofV1>,
) -> BoundDesktopActionV1 {
    let request = &fixture.request;
    let ready = &request.policy_ready_action;
    let operation = ok(operation_kind(ready));
    ok(BoundDesktopActionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        bound_action_id: "bound-action-1".to_owned(),
        trusted_execution_request_sha256: request.request_sha256.clone(),
        policy_ready_sha256: ready.policy_ready_sha256.clone(),
        selection_sha256: ready.selection_sha256.clone(),
        proposal_id: ready.proposal.proposal_id.clone(),
        proposal_sha256: ok(canonical_sha256(&ready.proposal)),
        goal_id: ready.goal_id.clone(),
        plan_generation_id: ready.plan_generation_id.clone(),
        source_observation_id: request.source_observation_id.clone(),
        source_observation_hash: request.source_observation_hash.clone(),
        source_observation_sequence: request.source_observation_sequence,
        semantic_target_id: ready.semantic_target_id.clone(),
        selected_element_id: ready.selected_element_id.clone(),
        capability_id: ready.capability_id.clone(),
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
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
        input_material_proof_sha256: input.map(|proof| proof.material_proof_sha256.clone()),
        integration_id: request.platform_activation.integration_id.clone(),
        binding_id: request.platform_activation.binding_id.clone(),
        activation_record_hash: request.platform_activation.activation_record_hash.clone(),
        adapter_kind: request.platform_activation.adapter_kind,
        adapter_descriptor_sha256: request
            .platform_activation
            .adapter_descriptor_sha256
            .clone(),
        desktop_capability: operation.desktop_capability(),
        desktop_operation_kind: operation,
        desktop_operation_sha256: digest("desktop-operation"),
        desktop_action_intent_sha256: digest("desktop-intent"),
        generated_at_unix_ms: NOW_MS + 1_000,
        expires_at_unix_ms: NOW_MS + 20_000,
        evidence_ids: vec!["target-resolution".to_owned()],
        bound_action_sha256: empty_hash(),
    }
    .seal())
}

fn prepared(bound: &BoundDesktopActionV1) -> PreparedBoundActionV1 {
    ok(PreparedBoundActionV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        bound_action_sha256: bound.bound_action_sha256.clone(),
        desktop_action_intent_sha256: bound.desktop_action_intent_sha256.clone(),
        desktop_operation_sha256: bound.desktop_operation_sha256.clone(),
        adapter_descriptor_sha256: bound.adapter_descriptor_sha256.clone(),
        target_resolution_sha256: bound.target_resolution_sha256.clone(),
        input_material_proof_sha256: bound.input_material_proof_sha256.clone(),
        prepared_action_hash: digest("prepared-action"),
        precondition_hash: digest("precondition"),
        prepared_at_unix_ms: NOW_MS + 2_000,
        expires_at_unix_ms: NOW_MS + 15_000,
        reversible: true,
        evidence_ids: vec!["adapter-preparation".to_owned()],
        prepared_binding_sha256: empty_hash(),
    }
    .seal())
}

fn receipt(
    fixture: &Fixture,
    bound: &BoundDesktopActionV1,
    prepared: Option<&PreparedBoundActionV1>,
    status: TrustedExecutionStatusV1,
) -> TrustedActionExecutionReceiptV1 {
    let executed = matches!(
        status,
        TrustedExecutionStatusV1::Succeeded | TrustedExecutionStatusV1::Failed
    );
    let ready = &fixture.request.policy_ready_action;
    ok(TrustedActionExecutionReceiptV1 {
        schema_version: TRUSTED_ACTION_EXECUTION_SCHEMA_VERSION,
        execution_id: "execution-1".to_owned(),
        status,
        bound_action_sha256: bound.bound_action_sha256.clone(),
        prepared_binding_sha256: prepared.map(|value| value.prepared_binding_sha256.clone()),
        policy_ready_sha256: ready.policy_ready_sha256.clone(),
        proposal_id: ready.proposal.proposal_id.clone(),
        proposal_sha256: ok(canonical_sha256(&ready.proposal)),
        goal_id: ready.goal_id.clone(),
        plan_generation_id: ready.plan_generation_id.clone(),
        source_observation_id: fixture.request.source_observation_id.clone(),
        source_observation_hash: fixture.request.source_observation_hash.clone(),
        source_observation_sequence: fixture.request.source_observation_sequence,
        capability_id: ready.capability_id.clone(),
        semantic_target_id: ready.semantic_target_id.clone(),
        cognitive_activation_admission_sha256: fixture
            .request
            .cognitive_activation_admission
            .admission_sha256
            .clone(),
        policy_decision_sha256: fixture
            .request
            .cognitive_activation_admission
            .policy_decision_sha256
            .clone(),
        confirmation_grant_sha256: fixture
            .request
            .cognitive_activation_admission
            .confirmation_grant_sha256
            .clone(),
        activation_record_hash: fixture
            .request
            .platform_activation
            .activation_record_hash
            .clone(),
        runtime_binding_sha256: fixture
            .request
            .platform_activation
            .runtime_binding_sha256
            .clone(),
        adapter_descriptor_sha256: bound.adapter_descriptor_sha256.clone(),
        desktop_action_intent_sha256: bound.desktop_action_intent_sha256.clone(),
        desktop_operation_sha256: bound.desktop_operation_sha256.clone(),
        target_resolution_sha256: bound.target_resolution_sha256.clone(),
        input_material_proof_sha256: bound.input_material_proof_sha256.clone(),
        preparation_hash: prepared.map(|value| value.prepared_action_hash.clone()),
        precondition_hash: prepared.map(|value| value.precondition_hash.clone()),
        execution_permit_sha256: executed.then(|| digest("permit")),
        adapter_outcome_status: executed.then_some(match status {
            TrustedExecutionStatusV1::Succeeded => TrustedAdapterOutcomeStatusV1::Succeeded,
            _ => TrustedAdapterOutcomeStatusV1::Failed,
        }),
        adapter_output_sha256: executed.then(|| digest("adapter-output")),
        adapter_output_bytes: u64::from(executed) * 32,
        started_at_unix_ms: executed.then_some(NOW_MS + 3_000),
        completed_at_unix_ms: NOW_MS + 4_000,
        warnings: if status == TrustedExecutionStatusV1::Failed {
            vec!["adapter execution failed closed".to_owned()]
        } else {
            Vec::new()
        },
        evidence_ids: vec!["terminal-adapter-attempt".to_owned()],
        receipt_sha256: empty_hash(),
    }
    .seal())
}

fn schema_validator() -> JSONSchema {
    let schema: Value = ok(serde_json::from_str(
        TRUSTED_ACTION_EXECUTION_BINDING_V1_SCHEMA,
    ));
    ok(JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema))
}

fn assert_schema<T: Serialize>(value: &T) {
    let value = ok(serde_json::to_value(value));
    let errors = match schema_validator().validate(&value) {
        Ok(()) => Vec::new(),
        Err(errors) => errors.map(|error| error.to_string()).collect::<Vec<_>>(),
    };
    assert!(errors.is_empty(), "schema errors: {errors:?}");
}

fn reseal_request(
    mut request: TrustedExecutionBindingRequestV1,
) -> TrustedExecutionBindingRequestV1 {
    request.request_sha256 = ok(request.compute_request_sha256());
    request
}

#[test]
fn session_is_stable_bounded_strict_and_time_checked() {
    let first = session(AdapterKindV1::Uia);
    assert_eq!(first, session(AdapterKindV1::Uia));
    assert!(first.validate_at(NOW_MS).is_ok());
    assert!(first.validate_at(first.expires_at_unix_ms).is_err());
    assert_schema(&first);

    let mut zero = first.clone();
    zero.action_sequence = 0;
    assert!(zero.seal().is_err());
    let mut ttl = first.clone();
    ttl.expires_at_unix_ms = ttl.generated_at_unix_ms + 15 * 60 * 1_000 + 1;
    assert!(ttl.seal().is_err());
    let mut hash = first.clone();
    hash.runtime_package_sha256 = "bad".to_owned();
    assert!(hash.seal().is_err());
    let mut duplicate = first.clone();
    duplicate.evidence_ids.push("runtime-package".to_owned());
    assert!(duplicate.seal().is_err());

    let mut json = ok(serde_json::to_value(&first));
    json.as_object_mut()
        .unwrap_or_else(|| panic!("session JSON is not an object"))
        .insert("unknown".to_owned(), json!(true));
    assert!(parse_json_strict::<TrustedExecutionSessionV1>(
        ok(serde_json::to_vec(&json)).as_slice()
    )
    .is_err());
    let duplicate_json = format!(
        "{{\"schema_version\":1,\"schema_version\":1,\"execution_session_id\":\"{}\"}}",
        first.execution_session_id
    );
    assert!(parse_json_strict::<Value>(duplicate_json.as_bytes()).is_err());
}

#[test]
fn six_closed_operations_bind_deterministically() {
    for kind in [
        OperationFixture::UiaInvoke,
        OperationFixture::UiaSetValue,
        OperationFixture::UiaToggle,
        OperationFixture::WebClick,
        OperationFixture::WebType,
        OperationFixture::WebSelect,
    ] {
        let fixture = fixture(kind);
        let resolution = resolution(&fixture);
        let input = input_proof(&fixture);
        let bound = bound_action(&fixture, &resolution, input.as_ref());
        assert_eq!(
            ok(operation_kind(&fixture.request.policy_ready_action)),
            kind.operation()
        );
        assert_eq!(resolution.source_kind, kind.source_contract());
        assert!(bound
            .validate_against(&fixture.request, &resolution, input.as_ref())
            .is_ok());
        assert_eq!(
            bound.bound_action_sha256,
            bound_action(&fixture, &resolution, input.as_ref()).bound_action_sha256
        );
        assert_schema(&fixture.request);
        assert_schema(&resolution);
        if let Some(input) = &input {
            assert_schema(input);
        }
        assert_schema(&bound);
    }
}

#[test]
fn binding_request_rejects_every_lifecycle_substitution_and_stale_state() {
    let fixture = fixture(OperationFixture::UiaInvoke);
    assert!(fixture.request.validate().is_ok());
    assert!(fixture
        .request
        .validate_source_observation(&fixture.observation)
        .is_ok());

    let mutations: Vec<RequestMutation> = vec![
        Box::new(|value| value.policy_ready_action.selection_id = "selection-2".to_owned()),
        Box::new(|value| value.policy_ready_action.selection_sha256 = digest("selection-2")),
        Box::new(|value| value.policy_ready_action.proposal.proposal_id = "proposal-2".to_owned()),
        Box::new(|value| value.policy_ready_action.goal_id = "goal-2".to_owned()),
        Box::new(|value| value.policy_ready_action.plan_generation_id = "plan-2".to_owned()),
        Box::new(|value| value.source_observation_id = "observation-2".to_owned()),
        Box::new(|value| value.source_observation_hash = digest("observation-2")),
        Box::new(|value| value.source_observation_sequence = 8),
        Box::new(|value| value.policy_ready_action.capability_id = "uia.toggle".to_owned()),
        Box::new(|value| value.policy_ready_action.semantic_target_id = "profile.other".to_owned()),
        Box::new(|value| value.policy_ready_action.selected_element_id = "element-2".to_owned()),
        Box::new(|value| value.policy_ready_action.application_pack_sha256 = digest("pack-2")),
        Box::new(|value| {
            value.expected_grounded_target_binding_sha256 = digest("grounded-target-2")
        }),
        Box::new(|value| value.expected_policy_decision_sha256 = digest("decision-2")),
        Box::new(|value| value.expected_activation_admission_sha256 = digest("admission-2")),
        Box::new(|value| value.platform_activation.integration_id = "desktop-other".to_owned()),
        Box::new(|value| value.platform_activation.adapter_kind = AdapterKindV1::WebDriver),
    ];
    for mutate in mutations {
        let mut changed = fixture.request.clone();
        mutate(&mut changed);
        changed = reseal_request(changed);
        assert!(changed.validate().is_err());
    }

    let mut stale = fixture.request.clone();
    stale.execution_session.expires_at_unix_ms = NOW_MS;
    stale.execution_session = ok(stale.execution_session.seal());
    stale = reseal_request(stale);
    assert!(stale.execution_session.validate_at(NOW_MS).is_err());

    let mut substituted_observation = fixture.observation.clone();
    substituted_observation.observation_id = "observation-2".to_owned();
    assert!(fixture
        .request
        .validate_source_observation(&substituted_observation)
        .is_err());
}

#[test]
fn native_grounded_action_arguments_are_bound_without_weakening_fixture_compatibility() {
    for kind in [
        OperationFixture::UiaInvoke,
        OperationFixture::UiaSetValue,
        OperationFixture::UiaToggle,
        OperationFixture::WebClick,
        OperationFixture::WebType,
        OperationFixture::WebSelect,
    ] {
        let observation = observation(kind);
        let mut ready = policy_ready(kind, &observation);
        let source_kind = match kind.adapter() {
            AdapterKindV1::Uia => ObservationSourceKind::Uia,
            AdapterKindV1::WebDriver => ObservationSourceKind::WebDriver,
            AdapterKindV1::EnterpriseApi => {
                panic!("desktop trusted-execution fixture cannot use enterprise API")
            }
            AdapterKindV1::OfficeWorkspace => {
                panic!("desktop trusted-execution fixture cannot use office workspace")
            }
            AdapterKindV1::OfficeDocument => {
                panic!("desktop trusted-execution fixture cannot use office document")
            }
            AdapterKindV1::OfficeSpreadsheet => {
                panic!("desktop trusted-execution fixture cannot use office spreadsheet")
            }
        };
        let mut target = GroundedTargetBindingV1 {
            schema_version: 1,
            application_pack_sha256: ready.application_pack_sha256.clone(),
            observation_id: ready.observation_id.clone(),
            source_observation_hash: ready.source_observation_hash.clone(),
            source_observation_sequence: ready.source_observation_sequence,
            grounding_result_sha256: ready.grounding_result_sha256.clone(),
            goal_id: ready.goal_id.clone(),
            plan_generation_id: ready.plan_generation_id.clone(),
            semantic_target_id: ready.semantic_target_id.clone(),
            selected_element_id: ready.selected_element_id.clone(),
            selected_element_kind: ready.selected_element_kind.clone(),
            source_kind,
            trust_labels: BTreeSet::from([TrustLabel::ObservedUiState]),
            evidence_ids: vec!["actual-grounding-result".to_owned()],
            binding_sha256: empty_hash(),
        };
        target.binding_sha256 = ok(target.compute_binding_sha256());
        ok(target.validate());
        let arguments = GroundedActionArgumentsV1 {
            schema_version: 1,
            operation: kind.capability().to_owned(),
            target: target.clone(),
            input: kind.input(),
        };
        ready.proposal.arguments = ok(serde_json::to_value(arguments));

        assert_eq!(ok(operation_kind(&ready)), kind.operation());
        assert_eq!(ok(action_input(&ready)), kind.input());
        assert_eq!(
            ok(grounded_target_binding_sha256(&ready)),
            target.binding_sha256
        );

        let mut changed = ready;
        changed.proposal.arguments["target"]["binding_sha256"] = json!(digest("substituted"));
        assert!(operation_kind(&changed).is_err());
    }
}

#[test]
fn target_resolution_is_unique_exact_hash_only_and_stable() {
    for kind in [OperationFixture::UiaInvoke, OperationFixture::WebClick] {
        let fixture = fixture(kind);
        let proof = resolution(&fixture);
        assert!(proof.validate_against(&fixture.request).is_ok());
        assert_eq!(proof, resolution(&fixture));
        let json = ok(serde_json::to_string(&proof));
        assert!(!json.contains("locator"));
        assert!(!json.contains("automation_id"));

        for count in [0, 2] {
            let mut changed = proof.clone();
            changed.unique_match_count = count;
            assert!(changed.seal().is_err());
        }
        for mutate in [
            (|value: &mut TargetResolutionProofV1| {
                value.runtime_binding_sha256 = digest("other-runtime")
            }) as fn(&mut TargetResolutionProofV1),
            |value| value.activation_record_hash = digest("other-activation"),
            |value| value.selected_element_id = "element-2".to_owned(),
            |value| value.selected_element_kind = "other-kind".to_owned(),
        ] {
            let mut changed = proof.clone();
            mutate(&mut changed);
            changed = ok(changed.seal());
            assert!(changed.validate_against(&fixture.request).is_err());
        }
    }
}

#[test]
fn input_proofs_require_exact_nonsecret_material_and_operation_shape() {
    for (kind, input_kind) in [
        (OperationFixture::UiaSetValue, InputMaterialKindV1::SetText),
        (OperationFixture::WebType, InputMaterialKindV1::TypeText),
        (OperationFixture::WebSelect, InputMaterialKindV1::Select),
    ] {
        let fixture = fixture(kind);
        let proof = input_proof(&fixture).unwrap_or_else(|| panic!("input proof absent"));
        assert_eq!(proof.input_kind, input_kind);
        assert!(proof.validate_against(&fixture.request).is_ok());
        assert_eq!(
            proof.material_proof_sha256,
            input_proof(&fixture)
                .unwrap_or_else(|| panic!("input proof absent"))
                .material_proof_sha256
        );
        let json = ok(serde_json::to_string(&proof));
        assert!(!json.contains("trusted input"));
        assert!(!json.contains("password"));

        let mut mismatch = proof.clone();
        mismatch.supplied_content_sha256 = digest("wrong-payload");
        assert!(mismatch.seal().is_err());
        let mut oversized = proof.clone();
        oversized.byte_length = 8 * 1024 * 1024 + 1;
        assert!(oversized.seal().is_err());
        let mut secret = ok(serde_json::to_value(&proof));
        secret
            .as_object_mut()
            .unwrap_or_else(|| panic!("input proof JSON is not an object"))
            .insert("secret_classification".to_owned(), json!("credential_like"));
        assert!(parse_json_strict::<InputMaterialProofV1>(
            ok(serde_json::to_vec(&secret)).as_slice()
        )
        .is_err());
    }

    let no_input = fixture(OperationFixture::UiaInvoke);
    assert!(input_proof(&no_input).is_none());
    let with_input = fixture(OperationFixture::UiaSetValue);
    let resolution = resolution(&with_input);
    let input = input_proof(&with_input).unwrap_or_else(|| panic!("input proof absent"));
    let mut missing = bound_action(&with_input, &resolution, Some(&input));
    missing.input_material_proof_sha256 = None;
    assert!(missing.seal().is_err());
}

#[test]
fn bound_and_prepared_bindings_reject_mutation_and_hide_execution_material() {
    let fixture = fixture(OperationFixture::WebType);
    let resolution = resolution(&fixture);
    let input = input_proof(&fixture).unwrap_or_else(|| panic!("input proof absent"));
    let bound = bound_action(&fixture, &resolution, Some(&input));
    let preparation = prepared(&bound);
    assert!(preparation.validate_against(&bound).is_ok());
    assert_schema(&preparation);
    let json = ok(serde_json::to_string(&bound));
    assert!(!json.contains("locator"));
    assert!(!json.contains("trusted input"));

    let mut operation_mutation = bound.clone();
    operation_mutation.desktop_operation_sha256 = digest("other-operation");
    assert!(operation_mutation
        .validate_against(&fixture.request, &resolution, Some(&input))
        .is_err());
    let mut target_mutation = bound.clone();
    target_mutation.target_resolution_sha256 = digest("other-resolution");
    target_mutation = ok(target_mutation.seal());
    assert!(target_mutation
        .validate_against(&fixture.request, &resolution, Some(&input))
        .is_err());
    let mut input_mutation = bound.clone();
    input_mutation.input_material_proof_sha256 = Some(digest("other-input"));
    input_mutation = ok(input_mutation.seal());
    assert!(input_mutation
        .validate_against(&fixture.request, &resolution, Some(&input))
        .is_err());

    for mutate in [
        (|value: &mut PreparedBoundActionV1| value.bound_action_sha256 = digest("other-action"))
            as fn(&mut PreparedBoundActionV1),
        |value| value.adapter_descriptor_sha256 = digest("other-descriptor"),
        |value| value.target_resolution_sha256 = digest("other-resolution"),
        |value| value.input_material_proof_sha256 = Some(digest("other-input")),
    ] {
        let mut changed = preparation.clone();
        mutate(&mut changed);
        changed = ok(changed.seal());
        assert!(changed.validate_against(&bound).is_err());
    }
    let mut precondition_mutation = preparation.clone();
    precondition_mutation.precondition_hash = digest("other-precondition");
    assert!(precondition_mutation.validate_against(&bound).is_err());
    let mut expired = preparation.clone();
    expired.expires_at_unix_ms = expired.prepared_at_unix_ms;
    assert!(expired.seal().is_err());
}

#[test]
fn receipts_have_terminal_shapes_exact_output_hashes_and_no_verification_claim() {
    let fixture = fixture(OperationFixture::WebClick);
    let resolution = resolution(&fixture);
    let bound = bound_action(&fixture, &resolution, None);
    let preparation = prepared(&bound);
    for status in [
        TrustedExecutionStatusV1::Succeeded,
        TrustedExecutionStatusV1::Failed,
        TrustedExecutionStatusV1::Cancelled,
        TrustedExecutionStatusV1::DeniedBeforeCommit,
        TrustedExecutionStatusV1::Aborted,
    ] {
        let prepared = matches!(
            status,
            TrustedExecutionStatusV1::Succeeded | TrustedExecutionStatusV1::Failed
        )
        .then_some(&preparation);
        let terminal_receipt = receipt(&fixture, &bound, prepared, status);
        assert_schema(&terminal_receipt);
        assert_eq!(
            terminal_receipt.receipt_sha256,
            receipt(&fixture, &bound, prepared, status).receipt_sha256
        );
        assert!(!ok(serde_json::to_string(&terminal_receipt)).contains("verified"));
        if prepared.is_some() {
            assert_eq!(
                terminal_receipt.adapter_output_sha256,
                Some(digest("adapter-output"))
            );
        } else {
            assert_eq!(terminal_receipt.adapter_output_bytes, 0);
        }
    }
}

#[test]
fn unsupported_mapping_raw_secrets_and_nonfinite_json_fail_closed() {
    let fixture = fixture(OperationFixture::UiaInvoke);
    let mut unsupported = fixture.request.policy_ready_action.clone();
    unsupported.capability_id = "uia.scroll".to_owned();
    unsupported.proposal.capability_id = unsupported.capability_id.clone();
    unsupported.policy_ready_sha256 = ok(unsupported.compute_policy_ready_sha256());
    assert!(operation_kind(&unsupported).is_err());

    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "std::process::Command",
        "std::fs::",
        "std::net::",
        "uiautomation",
        "WindowsActivationAdmission",
        "d2i_desktop",
        "ExecutionPermit",
    ] {
        assert!(
            !source.contains(forbidden),
            "side-effect authority found: {forbidden}"
        );
    }
    assert!(parse_json_strict::<Value>(br#"{"value":1e999}"#).is_err());
}

#[test]
fn schema_source_matches_disk_and_rejects_mixed_or_unknown_artifacts() {
    let disk =
        include_str!("../../../schemas/cognitive/trusted-action-execution-binding-v1.schema.json");
    assert_eq!(TRUSTED_ACTION_EXECUTION_BINDING_V1_SCHEMA, disk);
    let fixture = fixture(OperationFixture::UiaInvoke);
    assert_schema(&fixture.request);
    let mut unknown = ok(serde_json::to_value(&fixture.request));
    unknown
        .as_object_mut()
        .unwrap_or_else(|| panic!("request JSON is not an object"))
        .insert("raw_locator".to_owned(), json!("#unsafe"));
    assert!(schema_validator().validate(&unknown).is_err());
    assert!(parse_json_strict::<TrustedExecutionBindingRequestV1>(
        ok(serde_json::to_vec(&unknown)).as_slice()
    )
    .is_err());
}

#[test]
fn policy_ready_cross_field_substitution_is_rejected() {
    let fixture = fixture(OperationFixture::UiaInvoke);
    for mutate in [
        (|value: &mut PolicyReadyActionV1| value.risk = CognitiveRiskClass::ReadOnly)
            as fn(&mut PolicyReadyActionV1),
        |value| value.proposal.plan_generation_id = "plan-2".to_owned(),
        |value| value.proposal.semantic_target = "profile.other".to_owned(),
        |value| value.proposal.valid_until_sequence = 8,
        |value| value.proposal.confirmation_requirement = ConfirmationRequirement::Required,
    ] {
        let mut changed = fixture.request.clone();
        mutate(&mut changed.policy_ready_action);
        changed.policy_ready_action.policy_ready_sha256 =
            ok(changed.policy_ready_action.compute_policy_ready_sha256());
        changed.request_sha256 = ok(changed.compute_request_sha256());
        assert!(changed.validate().is_err());
    }
}

#[test]
fn canonical_hash_is_key_order_independent_and_payload_sensitive() {
    assert_eq!(
        ok(canonical_sha256(&json!({"b": 2, "a": 1}))),
        ok(canonical_sha256(&json!({"a": 1, "b": 2})))
    );
    assert_ne!(
        ok(selection_sha256(&json!({"a": 1}))),
        ok(selection_sha256(&json!({"a": 2})))
    );
}
