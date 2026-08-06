use super::*;
use d2i_episodic_memory::{
    derive_episode_id, CrossCaseReusePolicyV1, EpisodeEventKindV1, EpisodeEventReferenceV1,
    RequirementStateReferenceV1, SourceLedgerClassV1, ZERO_HASH,
};

fn hash(seed: u8) -> String {
    format!("sha256:{:064x}", seed)
}

fn namespace(learning: bool) -> EpisodeMemoryNamespaceV1 {
    EpisodeMemoryNamespaceV1 {
        schema_version: 1,
        namespace_id: "office-memory-v1".to_owned(),
        organization_id: "org-d2i".to_owned(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.1.0".to_owned(),
        role_contract_sha256: hash(1),
        role_instance_scope: vec!["role-office".to_owned()],
        memory_boundary_sha256: hash(2),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["office.records".to_owned()],
        allowed_data_class_ids: vec!["approved-metadata".to_owned()],
        prohibited_data_class_ids: vec!["credential".to_owned()],
        retention_class_id: "office-audit".to_owned(),
        maximum_retention_days: 30,
        cross_case_reuse_policy: CrossCaseReusePolicyV1::ApprovedSummaryOnly,
        learning_candidate_allowed: learning,
        maximum_episodes: 100,
        maximum_store_bytes: 1_000_000,
        maximum_query_results: 10,
        valid_from_unix_ms: 1,
        valid_to_unix_ms: 1_000_000,
        evidence_ids: vec!["evidence-namespace".to_owned()],
        namespace_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("namespace: {error}"))
}

fn episode(namespace: &EpisodeMemoryNamespaceV1, suffix: u8) -> CaseEpisodeV1 {
    let final_hash = hash(20 + suffix);
    let make_event = |sequence, kind, time| {
        EpisodeEventReferenceV1 {
            schema_version: 1,
            event_sequence: sequence,
            event_kind: kind,
            occurred_at_unix_ms: time,
            source_ledger_class: if kind == EpisodeEventKindV1::AuditTerminal {
                SourceLedgerClassV1::ProtectedAudit
            } else {
                SourceLedgerClassV1::Case
            },
            source_ledger_id: "ledger".to_owned(),
            source_ledger_sequence: u64::from(sequence),
            source_ledger_head_sha256: hash(30 + sequence as u8),
            source_artifact_type: "reference".to_owned(),
            source_artifact_id: format!("artifact-{sequence}"),
            source_artifact_sha256: hash(40 + sequence as u8),
            trust_class: "verified_reference".to_owned(),
            evidence_ids: vec![format!("evidence-{sequence}")],
            event_reference_sha256: ZERO_HASH.to_owned(),
        }
        .seal()
        .unwrap_or_else(|error| panic!("event: {error}"))
    };
    let case_id = format!("case-{suffix}");
    CaseEpisodeV1 {
        schema_version: 1,
        episode_id: derive_episode_id(&case_id, &final_hash)
            .unwrap_or_else(|error| panic!("id: {error}")),
        episode_generation: 1,
        organization_id: namespace.organization_id.clone(),
        memory_namespace_id: namespace.namespace_id.clone(),
        memory_namespace_sha256: namespace.namespace_sha256.clone(),
        role_contract_id: namespace.role_contract_id.clone(),
        role_contract_version: namespace.role_contract_version.clone(),
        role_contract_sha256: namespace.role_contract_sha256.clone(),
        role_instance_id: "role-office".to_owned(),
        role_instance_sha256: hash(4),
        delegation_sha256: hash(5),
        memory_boundary_sha256: namespace.memory_boundary_sha256.clone(),
        case_id,
        case_contract_sha256: hash(6),
        final_case_instance_sha256: final_hash,
        work_item_sha256: hash(7),
        intake_receipt_sha256: hash(8),
        queue_ownership_terminal_sha256: hash(9),
        case_work_grant_sha256: Some(hash(10)),
        terminal_outcome: TerminalCaseOutcomeV1::VerifiedComplete,
        opened_at_unix_ms: 100,
        terminal_at_unix_ms: 200 + u64::from(suffix),
        priority_class: "normal".to_owned(),
        work_class_id: "office.record.update".to_owned(),
        responsibility_id: "office.records".to_owned(),
        application_pack_ids: vec!["krn-name-save".to_owned()],
        integration_ids: vec!["windows-uia".to_owned()],
        capability_ids: vec!["uia.invoke".to_owned()],
        semantic_target_ids: vec!["save".to_owned()],
        terminal_evidence_index_sha256: hash(11),
        event_references: vec![
            make_event(1, EpisodeEventKindV1::CaseOpened, 100),
            make_event(2, EpisodeEventKindV1::CaseTerminal, 199),
            make_event(3, EpisodeEventKindV1::AuditTerminal, 200),
        ],
        final_requirement_states: vec![RequirementStateReferenceV1 {
            requirement_id: "saved".to_owned(),
            status: "verified".to_owned(),
            evidence_sha256: hash(12),
        }],
        blocker_class_ids: Vec::new(),
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        provider_descriptor_hashes: vec![hash(13)],
        provider_invocation_hashes: vec![hash(14)],
        provider_result_hashes: vec![hash(15)],
        situation_generation_hashes: vec![hash(16)],
        plan_generation_hashes: vec![hash(17)],
        kernel_run_hashes: vec![hash(18)],
        verified_action_hashes: vec![hash(19)],
        verification_result_hashes: vec![hash(20)],
        recovery_result_hashes: Vec::new(),
        protected_audit_terminal_sha256: hash(21),
        data_class_ids: vec!["approved-metadata".to_owned()],
        redaction_proof_ids: vec!["redaction-1".to_owned()],
        retention_record_sha256: hash(22),
        approved_summary_sha256: None,
        evidence_ids: vec!["evidence-terminal".to_owned()],
        canonical_episode_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("episode: {error}"))
}

fn request<'a>(
    namespace: &'a EpisodeMemoryNamespaceV1,
    episodes: &'a [CaseEpisodeV1],
) -> CandidateRequestV1<'a> {
    CandidateRequestV1 {
        candidate_kind: LearningCandidateKindV1::PlannerExampleCandidate,
        namespace,
        episodes,
        source_approved_summary_hashes: vec![hash(60), hash(61)],
        observed_pattern_class_ids: vec!["state-aware-action-omission".to_owned()],
        proposed_semantic_change_class: "offline-evaluation-fixture".to_owned(),
        expected_benefit_class: "unnecessary-action-reduction".to_owned(),
        risk_class: "bounded-review".to_owned(),
        critical_error_relevance: false,
        required_offline_evaluation_ids: vec!["planner-regression-v1".to_owned()],
        quarantine_reason_codes: vec!["offline-review-required".to_owned()],
        evidence_ids: vec!["evidence-pattern".to_owned()],
    }
}

#[test]
fn two_independent_episodes_create_only_a_quarantined_candidate() {
    let namespace = namespace(true);
    let episodes = [episode(&namespace, 1), episode(&namespace, 2)];
    let candidate = create_learning_candidate(request(&namespace, &episodes))
        .unwrap_or_else(|error| panic!("candidate: {error}"));
    assert_eq!(candidate.status, LearningCandidateStatusV1::Quarantined);
    assert_eq!(candidate.source_episode_hashes.len(), 2);
    assert_ne!(candidate.candidate_sha256, ZERO_HASH);
}

#[test]
fn one_success_is_not_a_general_planner_pattern() {
    let namespace = namespace(true);
    let episodes = [episode(&namespace, 1)];
    assert!(matches!(
        create_learning_candidate(request(&namespace, &episodes)),
        Err(CaseLearningError::ResourceLimit(_))
    ));
}

#[test]
fn canonical_role_cannot_generate_candidates() {
    let namespace = namespace(false);
    let episodes = [episode(&namespace, 1), episode(&namespace, 2)];
    assert!(matches!(
        create_learning_candidate(request(&namespace, &episodes)),
        Err(CaseLearningError::Unauthorized(_))
    ));
}

#[test]
fn production_mutating_export_is_rejected() {
    let bundle = LearningCandidateExportBundleV1 {
        schema_version: 1,
        bundle_id: "bundle-1".to_owned(),
        organization_id: "org-d2i".to_owned(),
        namespace_sha256: hash(1),
        candidate_hashes: vec![hash(2)],
        candidate_object_hashes: vec![hash(3)],
        evaluation_schema_ids: vec!["planner-eval-v1".to_owned()],
        production_package_hashes_before: vec![hash(4)],
        production_package_hashes_after: vec![hash(5)],
        production_mutation_count: 1,
        exported_at_unix_ms: 1_000,
        bundle_sha256: ZERO_HASH.to_owned(),
    };
    assert!(matches!(
        bundle.seal(),
        Err(CaseLearningError::Unauthorized(_))
    ));
}

#[test]
fn offline_export_with_zero_mutation_is_deterministic() {
    let bundle = LearningCandidateExportBundleV1 {
        schema_version: 1,
        bundle_id: "bundle-1".to_owned(),
        organization_id: "org-d2i".to_owned(),
        namespace_sha256: hash(1),
        candidate_hashes: vec![hash(2)],
        candidate_object_hashes: vec![hash(3)],
        evaluation_schema_ids: vec!["planner-eval-v1".to_owned()],
        production_package_hashes_before: vec![hash(4)],
        production_package_hashes_after: vec![hash(4)],
        production_mutation_count: 0,
        exported_at_unix_ms: 1_000,
        bundle_sha256: ZERO_HASH.to_owned(),
    };
    let first = bundle
        .clone()
        .seal()
        .unwrap_or_else(|error| panic!("export: {error}"));
    let second = bundle
        .seal()
        .unwrap_or_else(|error| panic!("export: {error}"));
    assert_eq!(first.bundle_sha256, second.bundle_sha256);
}

#[test]
fn learning_schemas_are_strict_and_candidate_round_trips() {
    for schema in [
        CASE_LEARNING_RECORD_V1_SCHEMA,
        LEARNING_CANDIDATE_V1_SCHEMA,
        LEARNING_CANDIDATE_EVALUATION_V1_SCHEMA,
        LEARNING_CANDIDATE_REVIEW_DECISION_V1_SCHEMA,
        LEARNING_CANDIDATE_EXPORT_BUNDLE_V1_SCHEMA,
    ] {
        let value: serde_json::Value =
            serde_json::from_str(schema).unwrap_or_else(|error| panic!("schema JSON: {error}"));
        assert_eq!(value["additionalProperties"], false);
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&value)
            .unwrap_or_else(|error| panic!("schema compile: {error}"));
    }
    let namespace = namespace(true);
    let episodes = [episode(&namespace, 1), episode(&namespace, 2)];
    let candidate = create_learning_candidate(request(&namespace, &episodes))
        .unwrap_or_else(|error| panic!("candidate: {error}"));
    let schema: serde_json::Value = serde_json::from_str(LEARNING_CANDIDATE_V1_SCHEMA)
        .unwrap_or_else(|error| panic!("candidate schema: {error}"));
    let compiled = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("candidate compile: {error}"));
    let value =
        serde_json::to_value(candidate).unwrap_or_else(|error| panic!("candidate value: {error}"));
    assert!(compiled.is_valid(&value));
}

#[test]
fn opaque_cross_domain_ids_share_one_candidate_engine() {
    for (offset, work_class) in [
        "office.record.update",
        "hr.employee.onboarding.review",
        "it.service.request.triage",
        "safety.observation.review",
    ]
    .into_iter()
    .enumerate()
    {
        let mut namespace = namespace(true);
        namespace.allowed_work_class_ids = vec![work_class.to_owned()];
        namespace.namespace_id = format!("opaque-memory-{offset}");
        namespace.namespace_sha256 = ZERO_HASH.to_owned();
        namespace = namespace
            .seal()
            .unwrap_or_else(|error| panic!("namespace: {error}"));
        let mut episodes = [episode(&namespace, 1), episode(&namespace, 2)];
        for episode in &mut episodes {
            episode.work_class_id = work_class.to_owned();
            episode.canonical_episode_sha256 = ZERO_HASH.to_owned();
            *episode = episode
                .clone()
                .seal()
                .unwrap_or_else(|error| panic!("Episode: {error}"));
        }
        let candidate = create_learning_candidate(request(&namespace, &episodes))
            .unwrap_or_else(|error| panic!("candidate: {error}"));
        assert_eq!(candidate.work_class_id, work_class);
    }
}
