#![cfg(windows)]

use d2i_desktop::{
    initialize_episodic_memory_store, initialize_shadow_store, recover_episodic_memory_store,
    verify_episodic_memory_store, verify_shadow_store, ShadowDivergenceCandidateV1,
    ShadowStoreArtifactV1, ShadowStoreV1,
};
use d2i_episodic_memory::{CrossCaseReusePolicyV1, EpisodeMemoryNamespaceV1};
use d2i_shadow_mode::*;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[43_u8; 32])
}

fn root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "d2i-shadow-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

struct RootGuard(PathBuf);

impl Drop for RootGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn profile() -> ShadowModeProfileV1 {
    let policy = ok(general_office_readiness_policy(
        "example-office-organization".to_owned(),
        digest('a'),
        vec![
            "fixture-general-office".to_owned(),
            "fixture-hr".to_owned(),
            "fixture-it".to_owned(),
            "fixture-safety".to_owned(),
        ],
        vec!["kernel-name-save-shadow".to_owned()],
    ));
    ok(ShadowModeProfileV1 {
        schema_version: 1,
        profile_id: "office-shadow-profile".to_owned(),
        profile_version: "1.0.0".to_owned(),
        organization_id: policy.organization_id.clone(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.3.0".to_owned(),
        role_contract_sha256: policy.role_contract_sha256.clone(),
        delegation_sha256: digest('b'),
        role_instance_scope: vec!["office-shadow-instance".to_owned()],
        policy_set_sha256: digest('c'),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["internal-record-maintenance".to_owned()],
        allowed_application_pack_hashes: vec![digest('d')],
        allowed_integration_ids: vec!["internal-records-read".to_owned()],
        allowed_observation_source_ids: vec!["internal-records".to_owned()],
        allowed_semantic_target_ids: vec!["employee_name_input".to_owned()],
        allowed_capability_ids: vec!["uia.set_value".to_owned()],
        provider_descriptor_sha256: digest('e'),
        model_sha256: digest('f'),
        runtime_sha256: digest('1'),
        prompt_template_hashes: vec![digest('2')],
        allowed_reference_operator_class_ids: vec!["approved-office-operator".to_owned()],
        allowed_recorder_modes: vec![ShadowRecorderModeV1::InteractiveHuman],
        blinding_mode: ShadowBlindingModeV1::ProposalCommittedAndHiddenUntilReferenceDurable,
        approved_equivalence_bindings: Vec::new(),
        maximum_cases: 128,
        maximum_cycles_per_case: 8,
        maximum_proposals_per_cycle: 1,
        maximum_observation_bytes: 1_048_576,
        maximum_report_bytes: 1_048_576,
        maximum_store_bytes: 67_108_864,
        retention_class_id: "office-audit".to_owned(),
        maximum_retention_days: 30,
        readiness_policy_sha256: policy.policy_sha256,
        internal_routing_class_id: "office-supervision".to_owned(),
        evidence_ids: vec!["approved-shadow-profile".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn proposal() -> ShadowProposalV1 {
    ok(ShadowProposalV1 {
        schema_version: 1,
        proposal_id: "proposal-session-a-0".to_owned(),
        session_id: "session-a".to_owned(),
        cycle_index: 0,
        case_enrollment_sha256: digest('3'),
        goal_spec_sha256: digest('4'),
        situation_model_sha256: digest('5'),
        plan_generation_sha256: digest('6'),
        source_observation_id: "observation-a-0".to_owned(),
        source_observation_sha256: digest('7'),
        source_observation_sequence: 1,
        provider_invocation_sha256: digest('8'),
        provider_result_sha256: digest('9'),
        decision_class: ShadowDecisionClassV1::Act,
        semantic_intent_class_id: "set-value".to_owned(),
        capability_id: Some("uia.set_value".to_owned()),
        semantic_target_id: Some("employee_name_input".to_owned()),
        approved_argument_artifact_sha256: Some(digest('a')),
        required_precondition_hashes: vec![digest('b')],
        expected_postcondition_hashes: vec![digest('c')],
        predicted_risk_class_id: "reversible".to_owned(),
        predicted_policy_disposition: CounterfactualDispositionV1::WouldAllow,
        predicted_case_progress_class_id: "bounded-progress".to_owned(),
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        confidence_millionths: Some(990_000),
        uncertainty_class_ids: Vec::new(),
        evidence_ids: vec!["actual-qwen-provider-result".to_owned()],
        proposal_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn counterfactual(proposal: &ShadowProposalV1) -> CounterfactualPolicyAssessmentV1 {
    ok(CounterfactualPolicyAssessmentV1 {
        schema_version: 1,
        assessment_id: "counterfactual-session-a-0".to_owned(),
        shadow_proposal_sha256: proposal.proposal_sha256.clone(),
        role_contract_sha256: digest('a'),
        delegation_sha256: digest('b'),
        policy_set_sha256: digest('c'),
        case_contract_sha256: digest('c'),
        capability_id: proposal.capability_id.clone(),
        semantic_target_id: proposal.semantic_target_id.clone(),
        risk_class_id: proposal.predicted_risk_class_id.clone(),
        disposition: CounterfactualDispositionV1::WouldAllow,
        reason_codes: vec!["pure-policy-evaluation".to_owned()],
        execution_forbidden: true,
        admission_artifact_absent: true,
        activation_artifact_absent: true,
        evidence_ids: vec!["counterfactual-only".to_owned()],
        assessment_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn human_step(start: u64) -> HumanReferenceStepV1 {
    ok(HumanReferenceStepV1 {
        schema_version: 1,
        step_id: "human-step-session-a-0".to_owned(),
        session_id: "session-a".to_owned(),
        cycle_index: 0,
        assignment_sha256: digest('e'),
        actor_class_id: "approved-office-operator".to_owned(),
        recorder_mode: ShadowRecorderModeV1::InteractiveHuman,
        decision_class: ShadowDecisionClassV1::Act,
        reference_operation_class_id: Some("set-value".to_owned()),
        capability_classification_id: Some("uia.set_value".to_owned()),
        semantic_target_id: Some("employee_name_input".to_owned()),
        approved_argument_artifact_sha256: Some(digest('a')),
        pre_action_observation_id: "observation-a-0".to_owned(),
        pre_action_observation_sha256: digest('7'),
        pre_action_observation_sequence: 1,
        post_action_observation_id: "observation-a-1".to_owned(),
        post_action_observation_sha256: digest('f'),
        post_action_observation_sequence: 2,
        action_started_at_unix_ms: start,
        action_completed_at_unix_ms: start + 10,
        verification_result_sha256: Some(digest('1')),
        policy_assessment_sha256: digest('2'),
        result_class: ShadowResultClassV1::Applied,
        evidence_ids: vec!["app-local-semantic-event".to_owned()],
        step_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

fn new_store(label: &str) -> (RootGuard, ShadowStoreV1) {
    let root = root(label);
    let guard = RootGuard(root.clone());
    let profile = profile();
    let store = ok(initialize_shadow_store(
        &root,
        profile.organization_id.clone(),
        profile.role_contract_sha256.clone(),
        profile.profile_sha256,
        digest('3'),
        32 * 1024 * 1024,
        1,
    ));
    (guard, store)
}

fn memory_namespace() -> EpisodeMemoryNamespaceV1 {
    ok(EpisodeMemoryNamespaceV1 {
        schema_version: 1,
        namespace_id: "office-approved-summaries".to_owned(),
        organization_id: "example-office-organization".to_owned(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.3.0".to_owned(),
        role_contract_sha256: digest('a'),
        role_instance_scope: vec!["office-shadow-instance".to_owned()],
        memory_boundary_sha256: digest('b'),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["internal-record-maintenance".to_owned()],
        allowed_data_class_ids: vec!["approved-metadata".to_owned()],
        prohibited_data_class_ids: vec!["credential".to_owned(), "raw-ui-payload".to_owned()],
        retention_class_id: "office-audit".to_owned(),
        maximum_retention_days: 30,
        cross_case_reuse_policy: CrossCaseReusePolicyV1::ApprovedSummaryOnly,
        learning_candidate_allowed: true,
        maximum_episodes: 128,
        maximum_store_bytes: 32 * 1024 * 1024,
        maximum_query_results: 16,
        valid_from_unix_ms: 1,
        valid_to_unix_ms: 100_000,
        evidence_ids: vec!["shadow-quarantine-role-binding".to_owned()],
        namespace_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn divergence_candidate(namespace: &EpisodeMemoryNamespaceV1) -> ShadowDivergenceCandidateV1 {
    ok(ShadowDivergenceCandidateV1 {
        schema_version: 1,
        candidate_id: "shadow-divergence-50".to_owned(),
        organization_id: namespace.organization_id.clone(),
        memory_namespace_id: namespace.namespace_id.clone(),
        memory_namespace_sha256: namespace.namespace_sha256.clone(),
        role_contract_sha256: namespace.role_contract_sha256.clone(),
        work_class_id: "office.record.update".to_owned(),
        source_shadow_session_sha256: digest('1'),
        source_shadow_evaluation_sha256: digest('2'),
        source_comparison_sha256: digest('3'),
        source_adjudication_sha256: digest('4'),
        source_model_holdout_report_sha256: digest('5'),
        candidate_kind_id: "evaluation-case-candidate".to_owned(),
        quarantine_status_id: "work600-quarantined-shadow-ingress".to_owned(),
        production_eligible: false,
        production_mutation_count: 0,
        data_class_ids: vec!["approved-metadata".to_owned()],
        redaction_proof_ids: vec!["no-raw-human-input".to_owned()],
        evidence_ids: vec!["shadow-divergence-never-production".to_owned()],
        candidate_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn protected_store_enforces_complete_blinded_phase_order() {
    let (guard, mut store) = new_store("ordered");
    let proposal = proposal();
    let counterfactual = counterfactual(&proposal);
    let commitment = ok(commit_proposal(
        &proposal,
        &counterfactual,
        100,
        digest('4'),
    ));
    let human = human_step(200);
    let reveal = ok(reveal_proposal(
        &commitment,
        &proposal,
        &human,
        220,
        230,
        240,
    ));
    let comparison = ok(compare_steps(
        &proposal,
        &human,
        &counterfactual,
        &profile(),
        ShadowCorrectnessV1::Correct,
        ShadowCorrectnessV1::Correct,
    ));
    let adjudication = ok(adjudicate(IndependentAdjudicationInputV1 {
        role_contract_sha256: &digest('a'),
        delegation_sha256: &digest('b'),
        case_contract_sha256: &digest('c'),
        case_success_criteria_sha256: &digest('d'),
        proposal: &proposal,
        counterfactual: &counterfactual,
        human_step: &human,
        actual_policy_assessment_sha256: &digest('e'),
        verification_result_sha256: &digest('f'),
        actual_policy_compliant: true,
        verification_satisfied: true,
        required_decision: ShadowDecisionClassV1::Act,
        evidence_sufficient: true,
        evidence_ids: vec!["independent-verifier".to_owned()],
    }));

    ok(store.store(ShadowStoreArtifactV1::Proposal(proposal), 10));
    ok(store.store(ShadowStoreArtifactV1::Commitment(commitment), 20));
    ok(store.store_human_step(human, &key().verifying_key(), 30));
    ok(store.store(ShadowStoreArtifactV1::Reveal(reveal), 40));
    ok(store.store(ShadowStoreArtifactV1::Comparison(comparison), 50));
    ok(store.store(ShadowStoreArtifactV1::Adjudication(adjudication), 60));

    let verification = ok(verify_shadow_store(
        &guard.0,
        Some(&store.verification().ledger_terminal_sha256),
    ));
    assert_eq!(verification.ledger_record_count, 6);
    assert_eq!(verification.orphan_object_count, 0);
    assert!(!verification.stale_index);
    assert!(!verification.poisoned);
    assert!(!verification.residual_lock_present);
}

#[test]
fn human_step_before_commitment_fails_without_poisoning_clean_store() {
    let (guard, mut store) = new_store("early-human");
    let error = store.store_human_step(human_step(200), &key().verifying_key(), 10);
    assert!(error.is_err());
    assert!(!guard.0.join("poisoned").exists());
    let verification = ok(verify_shadow_store(&guard.0, None));
    assert_eq!(verification.ledger_record_count, 0);
    assert_eq!(verification.orphan_object_count, 0);
    assert!(!verification.poisoned);
}

#[test]
fn object_mutation_and_rollback_pin_fail_closed() {
    let (guard, mut store) = new_store("tamper");
    let proposal = proposal();
    ok(store.store(ShadowStoreArtifactV1::Proposal(proposal), 10));
    let terminal = store.verification().ledger_terminal_sha256.clone();
    assert!(verify_shadow_store(&guard.0, Some(&digest('f'))).is_err());
    let object = std::fs::read_dir(guard.0.join("sealed-proposals"))
        .unwrap_or_else(|error| panic!("read object directory: {error}"))
        .next()
        .unwrap_or_else(|| panic!("missing object"))
        .unwrap_or_else(|error| panic!("read object: {error}"))
        .path();
    let mut bytes = std::fs::read(&object).unwrap_or_else(|error| panic!("read object: {error}"));
    bytes.push(b' ');
    std::fs::write(&object, bytes).unwrap_or_else(|error| panic!("mutate object: {error}"));
    assert!(verify_shadow_store(&guard.0, Some(&terminal)).is_err());
}

#[test]
fn stale_index_is_repaired_without_replaying_any_action() {
    let (guard, mut store) = new_store("stale-index");
    let original_index = std::fs::read(guard.0.join("index.json"))
        .unwrap_or_else(|error| panic!("read index: {error}"));
    ok(store.store(ShadowStoreArtifactV1::Proposal(proposal()), 10));
    std::fs::write(guard.0.join("index.json"), original_index)
        .unwrap_or_else(|error| panic!("restore stale index: {error}"));
    assert!(ok(verify_shadow_store(&guard.0, None)).stale_index);
    let opened = ok(ShadowStoreV1::open(&guard.0, None));
    assert!(opened.verification().index_repaired);
    assert_eq!(opened.verification().ledger_record_count, 1);
}

#[test]
fn existing_writer_lock_is_preserved_and_rejected() {
    let (guard, mut store) = new_store("concurrent");
    std::fs::write(guard.0.join("coordinator.lock"), b"existing")
        .unwrap_or_else(|error| panic!("create lock: {error}"));
    assert!(store
        .store(ShadowStoreArtifactV1::Proposal(proposal()), 10)
        .is_err());
    assert!(guard.0.join("coordinator.lock").exists());
}

#[test]
fn crash_j_repairs_exactly_one_work600_shadow_quarantine_record() {
    let root = root("crash-j");
    let guard = RootGuard(root.clone());
    let namespace = memory_namespace();
    let candidate = divergence_candidate(&namespace);
    let mut store = ok(initialize_episodic_memory_store(&root, namespace, 10));
    let old_ledger = ok(std::fs::read(root.join("ledger.json")));
    let old_index = ok(std::fs::read(root.join("index.json")));

    ok(store.quarantine_shadow_candidate(&candidate, 20));
    drop(store);
    ok(std::fs::write(root.join("ledger.json"), old_ledger));
    ok(std::fs::write(root.join("index.json"), old_index));

    let recovered = ok(recover_episodic_memory_store(&root, 30));
    assert_eq!(recovered.shadow_candidate_count, 1);
    assert_eq!(recovered.candidate_count, 0);
    let ledger: serde_json::Value = ok(serde_json::from_slice(&ok(std::fs::read(
        root.join("ledger.json"),
    ))));
    let records = ledger["records"]
        .as_array()
        .unwrap_or_else(|| panic!("memory ledger records missing"));
    assert_eq!(
        records
            .iter()
            .filter(|record| {
                record["record_kind"].as_str() == Some("shadow_candidate_quarantined")
            })
            .count(),
        1
    );
    let terminal = recovered.ledger_terminal_sha256;
    assert_eq!(
        ok(verify_episodic_memory_store(&guard.0, Some(&terminal))).shadow_candidate_count,
        1
    );
}
