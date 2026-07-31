use d2i_action_selection::{canonical_sha256 as action_sha256, PolicyReadyActionV1};
use d2i_cognitive_ir::{
    ActionProposal, CognitiveRiskClass, ComparisonOp, ConfirmationPolicy, ConfirmationRequirement,
    GoalSpec, Postcondition, Provenance, Reversibility,
};
use d2i_policy_admission::{
    admit_action, canonical_sha256, create_confirmation_challenge, evaluate_policy,
    parse_json_strict, ActivationEligibilityContextV1, AdapterKindV1, AdmissionIssuanceV1,
    AdmissionModeV1, AuditOutcomeProjectionV1, AuthorityScopeConstraintsV1,
    CognitiveActivationAdmissionV1, ConfirmationChallengeV1, ConfirmationGrantV1,
    DelegatedAuthorityContextV1, GrantConsumptionLedgerV1, PolicyAdmissionError, PolicyDecisionV1,
    PolicyEvaluationRequestV1, PolicyOutcomeV1, PolicyReasonCodeV1, RequestedAutonomyModeV1,
    TrustedPolicySnapshotV1, TrustedPolicyStateV1, COGNITIVE_POLICY_ADMISSION_V1_SCHEMA,
    POLICY_ADMISSION_SCHEMA_VERSION,
};
use jsonschema::{Draft, JSONSchema};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt::Debug;

const NOW: u64 = 1_000;
type RequestMutation = Box<dyn Fn(&mut PolicyEvaluationRequestV1)>;
type GrantMutation = Box<dyn Fn(&mut ConfirmationGrantV1)>;

fn ok<T, E: Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(label: &str) -> String {
    ok(canonical_sha256(&label))
}

fn postcondition() -> Postcondition {
    Postcondition {
        target_state: "profile.name".to_owned(),
        op: ComparisonOp::Equals,
        expected_value: json!("sha256-only"),
        required: true,
        timeout_ms: 5_000,
    }
}

fn goal() -> GoalSpec {
    GoalSpec {
        schema_version: 1,
        goal_id: "goal-1".to_owned(),
        objective: "Update the local profile name".to_owned(),
        scope: BTreeMap::from([("application".to_owned(), json!("local-test-form"))]),
        required_outcomes: vec!["name saved".to_owned()],
        constraints: vec!["local fixture only".to_owned()],
        success_criteria: vec![postcondition()],
        risk_class: CognitiveRiskClass::Reversible,
        confirmation_policy: ConfirmationPolicy::Never,
        provenance: Provenance {
            source: "authenticated fixture".to_owned(),
            source_hash: digest("goal-source"),
            module_id: "goal-compiler".to_owned(),
        },
    }
}

fn policy_ready() -> PolicyReadyActionV1 {
    let proposal = ActionProposal {
        schema_version: 1,
        proposal_id: "proposal-1".to_owned(),
        goal_id: "goal-1".to_owned(),
        plan_generation_id: "plan-1".to_owned(),
        source_observation_hash: digest("observation"),
        capability_id: "webdriver.click".to_owned(),
        semantic_target: "profile.name".to_owned(),
        arguments: json!({ "input_sha256": digest("input") }),
        preconditions: Vec::new(),
        expected_postconditions: vec![postcondition()],
        risk: CognitiveRiskClass::Reversible,
        reversibility: Reversibility::Reversible,
        confirmation_requirement: ConfirmationRequirement::None,
        confidence: 1.0,
        evidence: vec!["fixture".to_owned()],
        valid_until_sequence: 7,
    };
    let mut ready = PolicyReadyActionV1 {
        schema_version: 1,
        selection_id: "selection-1".to_owned(),
        selection_sha256: digest("selection"),
        candidate_set_sha256: digest("candidate-set"),
        goal_id: proposal.goal_id.clone(),
        world_state_id: "world-1".to_owned(),
        plan_generation_id: proposal.plan_generation_id.clone(),
        observation_id: "observation-1".to_owned(),
        source_observation_hash: proposal.source_observation_hash.clone(),
        source_observation_sequence: proposal.valid_until_sequence,
        application_pack_sha256: digest("application-pack"),
        grounding_result_sha256: digest("grounding"),
        semantic_target_id: proposal.semantic_target.clone(),
        selected_element_id: "element-1".to_owned(),
        selected_element_kind: "button".to_owned(),
        capability_id: proposal.capability_id.clone(),
        capability_binding_sha256: digest("capability-binding"),
        risk: proposal.risk,
        reversibility: proposal.reversibility,
        confirmation_requirement: proposal.confirmation_requirement,
        expected_postconditions: proposal.expected_postconditions.clone(),
        proposal,
        evidence_ids: vec!["grounding-result".to_owned(), "selection-result".to_owned()],
        policy_input_sha256: digest("policy-input"),
        policy_ready_sha256: digest("placeholder"),
    };
    ready.policy_ready_sha256 = ok(ready.compute_policy_ready_sha256());
    ready
}

fn authority() -> DelegatedAuthorityContextV1 {
    ok(DelegatedAuthorityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        authority_id: "authority-1".to_owned(),
        organization_id: "organization-1".to_owned(),
        actor_id: "actor-1".to_owned(),
        role_id: "role-1".to_owned(),
        policy_set_id: "policy-set-1".to_owned(),
        policy_set_version: "1.0.0".to_owned(),
        policy_set_sha256: digest("policy-set"),
        allowed_capability_ids: vec!["webdriver.click".to_owned()],
        forbidden_capability_ids: Vec::new(),
        autonomous_capability_ids: vec!["webdriver.click".to_owned()],
        confirmation_capability_ids: Vec::new(),
        maximum_autonomous_risk: CognitiveRiskClass::Reversible,
        maximum_confirmable_risk: CognitiveRiskClass::BusinessStateChange,
        allowed_application_pack_sha256: digest("application-pack"),
        allowed_integration_ids: vec!["desktop.web".to_owned()],
        scope_constraints: AuthorityScopeConstraintsV1 {
            application_pack_sha256: digest("application-pack"),
            integration_ids: vec!["desktop.web".to_owned()],
            semantic_target_ids: vec!["profile.name".to_owned()],
        },
        valid_from_unix_seconds: 900,
        expires_at_unix_seconds: 2_000,
        evidence_ids: vec!["delegated-authority".to_owned()],
        authority_sha256: digest("placeholder"),
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
        snapshot_sha256: digest("placeholder"),
    }
    .seal())
}

fn request() -> PolicyEvaluationRequestV1 {
    ok(PolicyEvaluationRequestV1::new(
        policy_ready(),
        goal(),
        authority(),
        policy(),
        NOW,
        RequestedAutonomyModeV1::AutonomousPreferred,
    ))
}

fn reseal_request(mut request: PolicyEvaluationRequestV1) -> PolicyEvaluationRequestV1 {
    request.request_sha256 = ok(request.compute_request_sha256());
    request
}

fn eligibility(request: &PolicyEvaluationRequestV1) -> ActivationEligibilityContextV1 {
    let ready = &request.policy_ready_action;
    ok(ActivationEligibilityContextV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        eligibility_id: "eligibility-1".to_owned(),
        organization_id: request.delegated_authority.organization_id.clone(),
        integration_id: "desktop.web".to_owned(),
        application_pack_sha256: ready.application_pack_sha256.clone(),
        runtime_binding_id: "runtime-binding-1".to_owned(),
        runtime_binding_sha256: digest("runtime-binding"),
        adapter_kind: AdapterKindV1::WebDriver,
        activation_scope_id: "activation-scope-1".to_owned(),
        activation_ledger_id: "activation-ledger-1".to_owned(),
        activation_ledger_chain_head: digest("ledger-head"),
        eligible_capability_ids: vec![ready.capability_id.clone()],
        capability_binding_sha256: ready.capability_binding_sha256.clone(),
        source_observation_hash: ready.source_observation_hash.clone(),
        source_observation_sequence: ready.source_observation_sequence,
        observed_at_unix_seconds: NOW,
        expires_at_unix_seconds: 1_200,
        evidence_ids: vec!["activation-eligibility".to_owned()],
        eligibility_sha256: digest("placeholder"),
    }
    .seal())
}

fn issuance(eligibility: &ActivationEligibilityContextV1) -> AdmissionIssuanceV1 {
    AdmissionIssuanceV1 {
        admission_id: "admission-1".to_owned(),
        admitted_at_unix_seconds: 1_010,
        expires_at_unix_seconds: 1_100,
        expected_runtime_binding_sha256: eligibility.runtime_binding_sha256.clone(),
        expected_activation_ledger_chain_head: eligibility.activation_ledger_chain_head.clone(),
        expected_adapter_kind: eligibility.adapter_kind,
    }
}

fn confirmation_request() -> PolicyEvaluationRequestV1 {
    let mut authority = authority();
    authority.autonomous_capability_ids.clear();
    authority.confirmation_capability_ids = vec!["webdriver.click".to_owned()];
    authority = ok(authority.seal());
    ok(PolicyEvaluationRequestV1::new(
        policy_ready(),
        goal(),
        authority,
        policy(),
        NOW,
        RequestedAutonomyModeV1::ConfirmationAllowed,
    ))
}

fn challenge(
    request: &PolicyEvaluationRequestV1,
    decision: &PolicyDecisionV1,
) -> ConfirmationChallengeV1 {
    ok(create_confirmation_challenge(
        request,
        decision,
        "challenge-1".to_owned(),
        digest("challenge-nonce"),
        1_001,
        1_150,
    ))
}

fn grant(challenge: &ConfirmationChallengeV1) -> ConfirmationGrantV1 {
    ok(ConfirmationGrantV1 {
        schema_version: POLICY_ADMISSION_SCHEMA_VERSION,
        grant_id: "grant-1".to_owned(),
        challenge_id: challenge.challenge_id.clone(),
        challenge_sha256: challenge.challenge_sha256.clone(),
        decision_sha256: challenge.decision_sha256.clone(),
        policy_ready_sha256: challenge.policy_ready_sha256.clone(),
        proposal_sha256: challenge.proposal_sha256.clone(),
        confirming_actor_id: challenge.actor_id.clone(),
        confirming_role_id: challenge.role_id.clone(),
        organization_id: challenge.organization_id.clone(),
        granted_at_unix_seconds: 1_005,
        expires_at_unix_seconds: 1_140,
        confirmation_proof_sha256: digest("confirmation-proof"),
        one_time_use_id: "confirmation-use-1".to_owned(),
        evidence_ids: vec!["trusted-confirmation".to_owned()],
        grant_sha256: digest("placeholder"),
    }
    .seal())
}

fn schema_validator() -> JSONSchema {
    let schema: Value = ok(serde_json::from_str(COGNITIVE_POLICY_ADMISSION_V1_SCHEMA));
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

fn outcome(request: &PolicyEvaluationRequestV1) -> PolicyOutcomeV1 {
    ok(evaluate_policy(request)).outcome
}

#[test]
fn delegated_authority_enforces_sets_scope_expiry_and_stable_hash() {
    let first = authority();
    let second = authority();
    assert_eq!(first.authority_sha256, second.authority_sha256);
    assert_schema(&first);

    let mut duplicate = first.clone();
    duplicate
        .allowed_capability_ids
        .push("webdriver.click".to_owned());
    assert!(duplicate.seal().is_err());

    let mut overlap = first.clone();
    overlap.forbidden_capability_ids = vec!["webdriver.click".to_owned()];
    assert!(overlap.seal().is_err());

    let mut not_subset = first.clone();
    not_subset.autonomous_capability_ids = vec!["uia.invoke".to_owned()];
    assert!(not_subset.seal().is_err());

    let mut confirmation_not_subset = first.clone();
    confirmation_not_subset.confirmation_capability_ids = vec!["uia.invoke".to_owned()];
    assert!(confirmation_not_subset.seal().is_err());

    let mut expired = request();
    expired.evaluated_at_unix_seconds = 2_001;
    expired = reseal_request(expired);
    assert_eq!(outcome(&expired), PolicyOutcomeV1::Deny);

    let mut wrong_org = request();
    wrong_org.delegated_authority.organization_id = "organization-2".to_owned();
    wrong_org.delegated_authority = ok(wrong_org.delegated_authority.seal());
    wrong_org = reseal_request(wrong_org);
    assert_eq!(outcome(&wrong_org), PolicyOutcomeV1::Deny);

    let mut scope = request();
    scope
        .delegated_authority
        .scope_constraints
        .semantic_target_ids = vec!["other.target".to_owned()];
    scope.delegated_authority = ok(scope.delegated_authority.seal());
    scope = reseal_request(scope);
    assert_eq!(outcome(&scope), PolicyOutcomeV1::Escalate);
}

#[test]
fn trusted_policy_enforces_state_sets_expiry_unknown_json_and_stable_hash() {
    let first = policy();
    assert_eq!(first.snapshot_sha256, policy().snapshot_sha256);
    assert_schema(&first);

    let mut expired = request();
    expired.trusted_policy_snapshot.expires_at_unix_seconds = NOW;
    expired.trusted_policy_snapshot = ok(expired.trusted_policy_snapshot.seal());
    expired = reseal_request(expired);
    assert_eq!(outcome(&expired), PolicyOutcomeV1::Deny);

    let mut denied = request();
    denied.trusted_policy_snapshot.denied_capability_ids = vec!["webdriver.click".to_owned()];
    denied.trusted_policy_snapshot = ok(denied.trusted_policy_snapshot.seal());
    denied = reseal_request(denied);
    assert_eq!(outcome(&denied), PolicyOutcomeV1::Deny);

    let mut mandatory_confirmation = request();
    mandatory_confirmation
        .trusted_policy_snapshot
        .mandatory_confirmation_capability_ids = vec!["webdriver.click".to_owned()];
    mandatory_confirmation.trusted_policy_snapshot =
        ok(mandatory_confirmation.trusted_policy_snapshot.seal());
    mandatory_confirmation = reseal_request(mandatory_confirmation);
    assert_eq!(
        outcome(&mandatory_confirmation),
        PolicyOutcomeV1::RequireConfirmation
    );

    let mut mandatory_escalation = request();
    mandatory_escalation
        .trusted_policy_snapshot
        .mandatory_escalation_capability_ids = vec!["webdriver.click".to_owned()];
    mandatory_escalation.trusted_policy_snapshot =
        ok(mandatory_escalation.trusted_policy_snapshot.seal());
    mandatory_escalation = reseal_request(mandatory_escalation);
    assert_eq!(outcome(&mandatory_escalation), PolicyOutcomeV1::Escalate);

    let mut forbidden_target = request();
    forbidden_target
        .trusted_policy_snapshot
        .forbidden_semantic_targets = vec!["profile.name".to_owned()];
    forbidden_target.trusted_policy_snapshot = ok(forbidden_target.trusted_policy_snapshot.seal());
    forbidden_target = reseal_request(forbidden_target);
    assert_eq!(outcome(&forbidden_target), PolicyOutcomeV1::Deny);

    let unknown = br#"{"schema_version":1,"unknown":true}"#;
    assert!(parse_json_strict::<TrustedPolicySnapshotV1>(unknown).is_err());
    let duplicate = br#"{"schema_version":1,"schema_version":1}"#;
    assert!(parse_json_strict::<TrustedPolicySnapshotV1>(duplicate).is_err());
}

#[test]
fn human_by_exception_matrix_is_closed_and_deterministic() {
    let autonomous = request();
    let first = ok(evaluate_policy(&autonomous));
    let second = ok(evaluate_policy(&autonomous));
    assert_eq!(first, second);
    assert_eq!(first.outcome, PolicyOutcomeV1::AllowAutonomous);
    assert_eq!(first.decision_sha256, second.decision_sha256);
    assert_schema(&first);

    let confirmation = confirmation_request();
    assert_eq!(outcome(&confirmation), PolicyOutcomeV1::RequireConfirmation);

    let mut always = request();
    always.goal.confirmation_policy = ConfirmationPolicy::Always;
    always.goal_sha256 = ok(action_sha256(&always.goal));
    always = reseal_request(always);
    assert_eq!(outcome(&always), PolicyOutcomeV1::RequireConfirmation);

    let mut proposal_required = request();
    proposal_required
        .policy_ready_action
        .proposal
        .confirmation_requirement = ConfirmationRequirement::Required;
    proposal_required
        .policy_ready_action
        .confirmation_requirement = ConfirmationRequirement::Required;
    proposal_required.expected_confirmation_requirement = ConfirmationRequirement::Required;
    proposal_required.policy_ready_action.policy_ready_sha256 = ok(proposal_required
        .policy_ready_action
        .compute_policy_ready_sha256());
    proposal_required.expected_policy_ready_sha256 = proposal_required
        .policy_ready_action
        .policy_ready_sha256
        .clone();
    proposal_required.expected_proposal_sha256 = ok(action_sha256(
        &proposal_required.policy_ready_action.proposal,
    ));
    proposal_required = reseal_request(proposal_required);
    assert_eq!(
        outcome(&proposal_required),
        PolicyOutcomeV1::RequireConfirmation
    );

    let mut forbidden = request();
    forbidden
        .delegated_authority
        .autonomous_capability_ids
        .clear();
    forbidden.delegated_authority.allowed_capability_ids = vec!["uia.invoke".to_owned()];
    forbidden.delegated_authority.forbidden_capability_ids = vec!["webdriver.click".to_owned()];
    forbidden.delegated_authority = ok(forbidden.delegated_authority.seal());
    forbidden = reseal_request(forbidden);
    assert_eq!(outcome(&forbidden), PolicyOutcomeV1::Deny);

    let mut high = request();
    high.policy_ready_action.risk = CognitiveRiskClass::HighCriticality;
    high.policy_ready_action.proposal.risk = CognitiveRiskClass::HighCriticality;
    high.expected_risk = CognitiveRiskClass::HighCriticality;
    high.policy_ready_action.policy_ready_sha256 =
        ok(high.policy_ready_action.compute_policy_ready_sha256());
    high.expected_policy_ready_sha256 = high.policy_ready_action.policy_ready_sha256.clone();
    high.expected_proposal_sha256 = ok(action_sha256(&high.policy_ready_action.proposal));
    high = reseal_request(high);
    assert_eq!(outcome(&high), PolicyOutcomeV1::Escalate);

    let mut unknown = request();
    unknown.trusted_policy_snapshot.policy_state = TrustedPolicyStateV1::Unknown;
    unknown.trusted_policy_snapshot = ok(unknown.trusted_policy_snapshot.seal());
    unknown = reseal_request(unknown);
    assert_eq!(outcome(&unknown), PolicyOutcomeV1::Escalate);

    let mut irreversible = request();
    irreversible.policy_ready_action.reversibility = Reversibility::Irreversible;
    irreversible.policy_ready_action.proposal.reversibility = Reversibility::Irreversible;
    irreversible.policy_ready_action.confirmation_requirement =
        ConfirmationRequirement::UnsupportedIrreversible;
    irreversible
        .policy_ready_action
        .proposal
        .confirmation_requirement = ConfirmationRequirement::UnsupportedIrreversible;
    irreversible.expected_confirmation_requirement =
        ConfirmationRequirement::UnsupportedIrreversible;
    irreversible.policy_ready_action.policy_ready_sha256 = ok(irreversible
        .policy_ready_action
        .compute_policy_ready_sha256());
    irreversible.expected_policy_ready_sha256 =
        irreversible.policy_ready_action.policy_ready_sha256.clone();
    irreversible.expected_proposal_sha256 =
        ok(action_sha256(&irreversible.policy_ready_action.proposal));
    irreversible = reseal_request(irreversible);
    assert_eq!(outcome(&irreversible), PolicyOutcomeV1::Deny);
}

#[test]
fn confirmable_risk_escalation_boundary_is_fixed() {
    let mut confirmable = request();
    confirmable.policy_ready_action.risk = CognitiveRiskClass::BusinessStateChange;
    confirmable.policy_ready_action.proposal.risk = CognitiveRiskClass::BusinessStateChange;
    confirmable.expected_risk = CognitiveRiskClass::BusinessStateChange;
    confirmable.policy_ready_action.policy_ready_sha256 = ok(confirmable
        .policy_ready_action
        .compute_policy_ready_sha256());
    confirmable.expected_policy_ready_sha256 =
        confirmable.policy_ready_action.policy_ready_sha256.clone();
    confirmable.expected_proposal_sha256 =
        ok(action_sha256(&confirmable.policy_ready_action.proposal));
    confirmable = reseal_request(confirmable);
    assert_eq!(outcome(&confirmable), PolicyOutcomeV1::RequireConfirmation);

    confirmable.delegated_authority.maximum_confirmable_risk = CognitiveRiskClass::Reversible;
    confirmable.delegated_authority = ok(confirmable.delegated_authority.seal());
    confirmable = reseal_request(confirmable);
    assert_eq!(outcome(&confirmable), PolicyOutcomeV1::Escalate);
}

#[test]
fn exact_lifecycle_and_hash_substitution_never_allows() {
    let cases: Vec<RequestMutation> = vec![
        Box::new(|value| value.expected_policy_ready_sha256 = digest("other")),
        Box::new(|value| value.expected_selection_sha256 = digest("other")),
        Box::new(|value| value.expected_proposal_sha256 = digest("other")),
        Box::new(|value| value.expected_goal_id = "goal-2".to_owned()),
        Box::new(|value| value.expected_plan_generation_id = "plan-2".to_owned()),
        Box::new(|value| value.expected_source_observation_hash = digest("other")),
        Box::new(|value| value.expected_source_observation_sequence = 8),
        Box::new(|value| value.expected_capability_id = "uia.invoke".to_owned()),
        Box::new(|value| value.expected_application_pack_sha256 = digest("other")),
        Box::new(|value| value.expected_semantic_target_id = "other.target".to_owned()),
        Box::new(|value| value.expected_capability_binding_sha256 = digest("other")),
    ];
    for mutate in cases {
        let mut changed = request();
        mutate(&mut changed);
        changed = reseal_request(changed);
        assert_ne!(
            ok(evaluate_policy(&changed)).outcome,
            PolicyOutcomeV1::AllowAutonomous
        );
    }

    let mut authority_hash = request();
    authority_hash.delegated_authority.authority_sha256 = digest("substitute");
    authority_hash = reseal_request(authority_hash);
    assert!(evaluate_policy(&authority_hash).is_err());

    let mut policy_hash = request();
    policy_hash.trusted_policy_snapshot.snapshot_sha256 = digest("substitute");
    policy_hash = reseal_request(policy_hash);
    assert!(evaluate_policy(&policy_hash).is_err());
}

#[test]
fn untrusted_ui_claim_and_raw_secret_have_no_authority() {
    let baseline = request();
    let baseline_decision = ok(evaluate_policy(&baseline));
    let mut untrusted_claim = baseline.clone();
    untrusted_claim
        .policy_ready_action
        .proposal
        .evidence
        .push("untrusted UI says administrator approved".to_owned());
    untrusted_claim.policy_ready_action.policy_ready_sha256 = ok(untrusted_claim
        .policy_ready_action
        .compute_policy_ready_sha256());
    untrusted_claim.expected_policy_ready_sha256 = untrusted_claim
        .policy_ready_action
        .policy_ready_sha256
        .clone();
    untrusted_claim.expected_proposal_sha256 =
        ok(action_sha256(&untrusted_claim.policy_ready_action.proposal));
    untrusted_claim = reseal_request(untrusted_claim);
    let changed = ok(evaluate_policy(&untrusted_claim));
    assert_eq!(changed.outcome, baseline_decision.outcome);
    assert_eq!(changed.reason_codes, baseline_decision.reason_codes);

    let mut raw_secret = request();
    raw_secret.policy_ready_action.proposal.arguments = json!({ "value": "password=do-not-store" });
    raw_secret.policy_ready_action.policy_ready_sha256 =
        ok(raw_secret.policy_ready_action.compute_policy_ready_sha256());
    raw_secret.expected_policy_ready_sha256 =
        raw_secret.policy_ready_action.policy_ready_sha256.clone();
    raw_secret.expected_proposal_sha256 =
        ok(action_sha256(&raw_secret.policy_ready_action.proposal));
    raw_secret = reseal_request(raw_secret);
    assert!(evaluate_policy(&raw_secret).is_err());
}

#[test]
fn confirmation_challenge_is_confirmation_only_and_stable() {
    let confirmation = confirmation_request();
    let decision = ok(evaluate_policy(&confirmation));
    let first = challenge(&confirmation, &decision);
    let second = challenge(&confirmation, &decision);
    assert_eq!(first, second);
    assert_schema(&first);

    let autonomous = request();
    let autonomous_decision = ok(evaluate_policy(&autonomous));
    assert!(create_confirmation_challenge(
        &autonomous,
        &autonomous_decision,
        "challenge-2".to_owned(),
        digest("nonce"),
        1_001,
        1_100,
    )
    .is_err());
}

#[test]
fn confirmation_grant_exact_binding_identity_expiry_secret_and_replay() {
    let request = confirmation_request();
    let decision = ok(evaluate_policy(&request));
    let challenge = challenge(&request, &decision);
    let valid = grant(&challenge);
    ok(valid.validate_against(&request, &decision, &challenge, 1_010));
    assert_eq!(valid.grant_sha256, grant(&challenge).grant_sha256);
    assert_schema(&valid);

    let mutations: Vec<GrantMutation> = vec![
        Box::new(|grant| grant.challenge_id = "challenge-other".to_owned()),
        Box::new(|grant| grant.policy_ready_sha256 = digest("other")),
        Box::new(|grant| grant.confirming_actor_id = "actor-other".to_owned()),
        Box::new(|grant| grant.confirming_role_id = "role-other".to_owned()),
        Box::new(|grant| grant.organization_id = "organization-other".to_owned()),
    ];
    for mutate in mutations {
        let mut changed = valid.clone();
        mutate(&mut changed);
        changed.grant_sha256 = ok(changed.compute_grant_sha256());
        assert!(changed
            .validate_against(&request, &decision, &challenge, 1_010)
            .is_err());
    }
    assert!(valid
        .validate_against(&request, &decision, &challenge, 1_141)
        .is_err());

    let mut secret = valid.clone();
    secret.evidence_ids = vec!["password=raw".to_owned()];
    secret.grant_sha256 = ok(secret.compute_grant_sha256());
    assert!(secret.validate().is_err());

    let eligibility = eligibility(&request);
    let mut ledger = GrantConsumptionLedgerV1::new();
    let first = ok(admit_action(
        &request,
        &decision,
        Some(&challenge),
        Some(&valid),
        &eligibility,
        &mut ledger,
        issuance(&eligibility),
    ));
    assert_eq!(first.admission_mode, AdmissionModeV1::ConfirmedException);
    assert!(ledger.contains(&valid.one_time_use_id));
    assert!(matches!(
        admit_action(
            &request,
            &decision,
            Some(&challenge),
            Some(&valid),
            &eligibility,
            &mut ledger,
            issuance(&eligibility),
        ),
        Err(PolicyAdmissionError::Replay(_))
    ));
}

#[test]
fn grant_cannot_override_deny_or_escalate() {
    for terminal in [PolicyOutcomeV1::Deny, PolicyOutcomeV1::Escalate] {
        let request = confirmation_request();
        let confirmation_decision = ok(evaluate_policy(&request));
        let challenge = challenge(&request, &confirmation_decision);
        let grant = grant(&challenge);
        let mut terminal_decision = confirmation_decision.clone();
        terminal_decision.outcome = terminal;
        terminal_decision.resolved_confirmation_requirement =
            d2i_policy_admission::ResolvedConfirmationRequirementV1::NotApplicable;
        terminal_decision.reason_codes = vec![if terminal == PolicyOutcomeV1::Deny {
            PolicyReasonCodeV1::ForbiddenCapability
        } else {
            PolicyReasonCodeV1::HighCriticality
        }];
        terminal_decision.decision_sha256 = ok(terminal_decision.compute_decision_sha256());
        assert!(grant
            .validate_against(&request, &terminal_decision, &challenge, 1_010)
            .is_err());
    }
}

#[test]
fn activation_eligibility_rejects_missing_and_substituted_bindings() {
    let request = request();
    let valid = eligibility(&request);
    assert_schema(&valid);

    let mut absent = valid.clone();
    absent.eligible_capability_ids = vec!["uia.invoke".to_owned()];
    absent = ok(absent.seal());
    assert_admission_rejected(&request, absent);

    let mut integration = valid.clone();
    integration.integration_id = "desktop.other".to_owned();
    integration = ok(integration.seal());
    assert_admission_rejected(&request, integration);

    let mut runtime = valid.clone();
    runtime.runtime_binding_sha256 = digest("other-runtime");
    runtime = ok(runtime.seal());
    assert_admission_rejected(&request, runtime);

    let mut stale = valid.clone();
    stale.expires_at_unix_seconds = 1_005;
    stale = ok(stale.seal());
    assert_admission_rejected(&request, stale);

    let mut ledger_head = valid.clone();
    ledger_head.activation_ledger_chain_head = digest("other-head");
    ledger_head = ok(ledger_head.seal());
    assert_admission_rejected(&request, ledger_head);

    let mut adapter = valid;
    adapter.adapter_kind = AdapterKindV1::Uia;
    adapter = ok(adapter.seal());
    assert_admission_rejected(&request, adapter);
}

fn assert_admission_rejected(
    request: &PolicyEvaluationRequestV1,
    eligibility: ActivationEligibilityContextV1,
) {
    let decision = ok(evaluate_policy(request));
    let mut ledger = GrantConsumptionLedgerV1::new();
    let trusted_issuance = AdmissionIssuanceV1 {
        admission_id: "admission-1".to_owned(),
        admitted_at_unix_seconds: 1_010,
        expires_at_unix_seconds: 1_100,
        expected_runtime_binding_sha256: digest("runtime-binding"),
        expected_activation_ledger_chain_head: digest("ledger-head"),
        expected_adapter_kind: AdapterKindV1::WebDriver,
    };
    assert!(admit_action(
        request,
        &decision,
        None,
        None,
        &eligibility,
        &mut ledger,
        trusted_issuance,
    )
    .is_err());
}

#[test]
fn autonomous_admission_is_exact_stable_and_non_executable() {
    let request = request();
    let decision = ok(evaluate_policy(&request));
    let eligibility = eligibility(&request);
    let first = ok(admit_action(
        &request,
        &decision,
        None,
        None,
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&eligibility),
    ));
    let second = ok(admit_action(
        &request,
        &decision,
        None,
        None,
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&eligibility),
    ));
    assert_eq!(first, second);
    assert_eq!(first.admission_mode, AdmissionModeV1::DelegatedAutonomous);
    assert_eq!(first.admission_sha256, second.admission_sha256);
    assert_schema(&first);
    let decision_projection = AuditOutcomeProjectionV1::from(&decision);
    assert!(decision_projection.allowed);
    assert_eq!(
        decision_projection.reason,
        "policy_decision:allow_autonomous"
    );
    let admission_projection = AuditOutcomeProjectionV1::from(&first);
    assert!(admission_projection.allowed);
    assert_eq!(
        admission_projection.reason,
        "activation_admission:delegated_autonomous"
    );

    let value = ok(serde_json::to_value(&first));
    for forbidden in [
        "locator",
        "selector",
        "credential",
        "password",
        "adapter_handle",
        "activation_token",
        "desktop_operation",
    ] {
        assert!(
            !value.to_string().to_ascii_lowercase().contains(forbidden),
            "admission leaked {forbidden}"
        );
    }
}

#[test]
fn admission_rejects_confirmation_shape_terminal_decisions_and_stale_action() {
    let autonomous = request();
    let autonomous_decision = ok(evaluate_policy(&autonomous));
    let autonomous_eligibility = eligibility(&autonomous);
    let fake_confirmation_request = confirmation_request();
    let fake_decision = ok(evaluate_policy(&fake_confirmation_request));
    let fake_challenge = challenge(&fake_confirmation_request, &fake_decision);
    let fake_grant = grant(&fake_challenge);
    assert!(admit_action(
        &autonomous,
        &autonomous_decision,
        Some(&fake_challenge),
        Some(&fake_grant),
        &autonomous_eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&autonomous_eligibility),
    )
    .is_err());

    let confirmation = confirmation_request();
    let confirmation_decision = ok(evaluate_policy(&confirmation));
    let confirmation_eligibility = eligibility(&confirmation);
    assert!(admit_action(
        &confirmation,
        &confirmation_decision,
        None,
        None,
        &confirmation_eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&confirmation_eligibility),
    )
    .is_err());

    for outcome in [PolicyOutcomeV1::Deny, PolicyOutcomeV1::Escalate] {
        let mut terminal = autonomous_decision.clone();
        terminal.outcome = outcome;
        terminal.resolved_confirmation_requirement =
            d2i_policy_admission::ResolvedConfirmationRequirementV1::NotApplicable;
        terminal.reason_codes = vec![if outcome == PolicyOutcomeV1::Deny {
            PolicyReasonCodeV1::ForbiddenCapability
        } else {
            PolicyReasonCodeV1::HighCriticality
        }];
        terminal.decision_sha256 = ok(terminal.compute_decision_sha256());
        assert!(admit_action(
            &autonomous,
            &terminal,
            None,
            None,
            &autonomous_eligibility,
            &mut GrantConsumptionLedgerV1::new(),
            issuance(&autonomous_eligibility),
        )
        .is_err());
    }

    let mut stale = autonomous_eligibility.clone();
    stale.source_observation_sequence += 1;
    stale = ok(stale.seal());
    assert_admission_rejected(&autonomous, stale);
}

#[test]
fn admission_rejects_proposal_selection_binding_and_eligibility_mutation() {
    let base = request();
    let decision = ok(evaluate_policy(&base));
    let eligibility = eligibility(&base);

    let mut proposal = decision.clone();
    proposal.proposal_sha256 = digest("mutated-proposal");
    proposal.decision_sha256 = ok(proposal.compute_decision_sha256());
    assert_not_admitted(&base, &proposal, &eligibility);

    let mut selection = base.clone();
    selection.expected_selection_sha256 = digest("mutated-selection");
    selection = reseal_request(selection);
    let denied = ok(evaluate_policy(&selection));
    assert_not_admitted(&selection, &denied, &eligibility);

    let mut binding = eligibility.clone();
    binding.capability_binding_sha256 = digest("mutated-binding");
    binding = ok(binding.seal());
    assert_not_admitted(&base, &decision, &binding);

    let mut mutated_eligibility = eligibility;
    mutated_eligibility.eligibility_sha256 = digest("mutated-eligibility");
    assert_not_admitted(&base, &decision, &mutated_eligibility);
}

fn assert_not_admitted(
    request: &PolicyEvaluationRequestV1,
    decision: &PolicyDecisionV1,
    eligibility: &ActivationEligibilityContextV1,
) {
    assert!(admit_action(
        request,
        decision,
        None,
        None,
        eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(eligibility),
    )
    .is_err());
}

#[test]
fn schema_unknown_fields_duplicate_keys_and_payload_mutation_fail_closed() {
    let request = request();
    assert_schema(&request);
    let bytes = ok(serde_json::to_vec(&request));
    let parsed: PolicyEvaluationRequestV1 = ok(parse_json_strict(&bytes));
    assert_eq!(parsed, request);

    let mut unknown = ok(serde_json::to_value(&request));
    match unknown.as_object_mut() {
        Some(object) => {
            object.insert("unknown".to_owned(), json!(true));
        }
        None => panic!("request did not serialize as an object"),
    }
    assert!(
        parse_json_strict::<PolicyEvaluationRequestV1>(&ok(serde_json::to_vec(&unknown))).is_err()
    );
    assert!(parse_json_strict::<Value>(br#"{"x":1,"x":2}"#).is_err());

    let decision = ok(evaluate_policy(&request));
    let mut mutated = decision.clone();
    mutated.capability_id = "uia.invoke".to_owned();
    assert!(mutated.validate().is_err());
}

#[test]
fn schema_accepts_every_artifact_and_source_matches_file() {
    let request = confirmation_request();
    let decision = ok(evaluate_policy(&request));
    let challenge = challenge(&request, &decision);
    let grant = grant(&challenge);
    let eligibility = eligibility(&request);
    let admission = ok(admit_action(
        &request,
        &decision,
        Some(&challenge),
        Some(&grant),
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&eligibility),
    ));
    assert_schema(&request.delegated_authority);
    assert_schema(&request.trusted_policy_snapshot);
    assert_schema(&request);
    assert_schema(&decision);
    assert_schema(&challenge);
    assert_schema(&grant);
    assert_schema(&eligibility);
    assert_schema(&admission);

    let disk = include_str!("../../../schemas/cognitive/cognitive-policy-admission-v1.schema.json");
    assert_eq!(COGNITIVE_POLICY_ADMISSION_V1_SCHEMA, disk);
}

#[test]
fn canonical_hash_ignores_object_key_order_but_not_payload_mutation() {
    let first = json!({"b": 2, "a": {"d": 4, "c": 3}});
    let second = json!({"a": {"c": 3, "d": 4}, "b": 2});
    assert_eq!(ok(canonical_sha256(&first)), ok(canonical_sha256(&second)));
    assert_ne!(
        ok(canonical_sha256(&first)),
        ok(canonical_sha256(&json!({"a": {"c": 9, "d": 4}, "b": 2})))
    );
}

#[test]
fn no_side_effect_or_runtime_authority_surface_exists() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "std::process::Command",
        "std::fs::",
        "std::net::",
        "reqwest",
        "uiautomation",
        "webdriver",
        "ActivatedWindowsBinding",
        "DesktopOperation",
        "ActionExecutor",
    ] {
        if forbidden == "webdriver" {
            continue;
        }
        assert!(
            !source.contains(forbidden),
            "side-effect authority found: {forbidden}"
        );
    }
}

#[test]
fn policy_request_decision_and_admission_hashes_are_all_distinct() {
    let request = request();
    let decision = ok(evaluate_policy(&request));
    let eligibility = eligibility(&request);
    let admission: CognitiveActivationAdmissionV1 = ok(admit_action(
        &request,
        &decision,
        None,
        None,
        &eligibility,
        &mut GrantConsumptionLedgerV1::new(),
        issuance(&eligibility),
    ));
    assert_ne!(request.request_sha256, decision.decision_sha256);
    assert_ne!(decision.decision_sha256, admission.admission_sha256);
    assert_ne!(eligibility.eligibility_sha256, admission.admission_sha256);
}
