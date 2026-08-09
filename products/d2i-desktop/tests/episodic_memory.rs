use d2i_case_learning::{create_learning_candidate, CandidateRequestV1, LearningCandidateKindV1};
use d2i_desktop::{
    initialize_episodic_memory_store, recover_episodic_memory_store, verify_episodic_memory_store,
};
use d2i_episodic_memory::{
    derive_episode_id, hash_without, ApprovedEpisodeSummaryV1, CaseEpisodeV1,
    CrossCaseReusePolicyV1, EpisodeEventKindV1, EpisodeEventReferenceV1, EpisodeMemoryNamespaceV1,
    EpisodeTombstoneV1, RequirementStateReferenceV1, SourceLedgerClassV1, TerminalCaseOutcomeV1,
    ZERO_HASH,
};
use ed25519_dalek::SigningKey;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

fn hash(seed: u8) -> String {
    format!("sha256:{seed:064x}")
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[9_u8; 32])
}

fn temporary_root(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "d2i-work600-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos())
    ))
}

fn namespace() -> EpisodeMemoryNamespaceV1 {
    EpisodeMemoryNamespaceV1 {
        schema_version: 1,
        namespace_id: "office-memory-v11".to_owned(),
        organization_id: "org-d2i".to_owned(),
        role_contract_id: "general-office-operations-employee".to_owned(),
        role_contract_version: "1.1.0".to_owned(),
        role_contract_sha256: hash(1),
        role_instance_scope: vec!["role-office-v11".to_owned()],
        memory_boundary_sha256: hash(2),
        allowed_work_class_ids: vec!["office.record.update".to_owned()],
        allowed_responsibility_ids: vec!["office.records".to_owned()],
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
        valid_to_unix_ms: 10_000_000,
        evidence_ids: vec!["evidence-namespace".to_owned()],
        namespace_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("namespace: {error}"))
}

fn event(sequence: u32, kind: EpisodeEventKindV1, time: u64) -> EpisodeEventReferenceV1 {
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
}

fn episode(
    namespace: &EpisodeMemoryNamespaceV1,
    suffix: u8,
    already_correct: bool,
) -> CaseEpisodeV1 {
    let final_hash = hash(60 + suffix);
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
        role_instance_id: "role-office-v11".to_owned(),
        role_instance_sha256: hash(3),
        delegation_sha256: hash(4),
        memory_boundary_sha256: namespace.memory_boundary_sha256.clone(),
        case_id,
        case_contract_sha256: hash(5),
        final_case_instance_sha256: final_hash,
        work_item_sha256: hash(6),
        intake_receipt_sha256: hash(7),
        queue_ownership_terminal_sha256: hash(8),
        case_work_grant_sha256: Some(hash(9)),
        terminal_outcome: TerminalCaseOutcomeV1::VerifiedComplete,
        opened_at_unix_ms: 1_000,
        terminal_at_unix_ms: 2_000 + u64::from(suffix),
        priority_class: "normal".to_owned(),
        work_class_id: "office.record.update".to_owned(),
        responsibility_id: "office.records".to_owned(),
        application_pack_ids: vec!["krn-name-save".to_owned()],
        integration_ids: vec!["windows-uia".to_owned()],
        capability_ids: if already_correct {
            vec!["uia.invoke".to_owned()]
        } else {
            vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()]
        },
        semantic_target_ids: vec!["employee-name".to_owned(), "save".to_owned()],
        terminal_evidence_index_sha256: hash(10),
        event_references: vec![
            event(1, EpisodeEventKindV1::CaseOpened, 1_000),
            event(2, EpisodeEventKindV1::CaseTerminal, 1_999),
            event(3, EpisodeEventKindV1::AuditTerminal, 2_000),
        ],
        final_requirement_states: vec![RequirementStateReferenceV1 {
            requirement_id: "saved".to_owned(),
            status: "verified".to_owned(),
            evidence_sha256: hash(11),
        }],
        blocker_class_ids: Vec::new(),
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        provider_descriptor_hashes: vec![hash(12)],
        provider_invocation_hashes: vec![hash(13)],
        provider_result_hashes: vec![hash(14)],
        situation_generation_hashes: vec![hash(15)],
        plan_generation_hashes: vec![hash(16)],
        kernel_run_hashes: vec![hash(17)],
        verified_action_hashes: vec![hash(18)],
        verification_result_hashes: vec![hash(19)],
        recovery_result_hashes: if already_correct {
            Vec::new()
        } else {
            vec![hash(20)]
        },
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

fn summary(episode: &CaseEpisodeV1) -> ApprovedEpisodeSummaryV1 {
    ApprovedEpisodeSummaryV1 {
        schema_version: 1,
        summary_id: format!("summary-{}", episode.episode_id),
        summary_generation: 1,
        episode_sha256: episode.canonical_episode_sha256.clone(),
        organization_id: episode.organization_id.clone(),
        namespace_sha256: episode.memory_namespace_sha256.clone(),
        role_contract_sha256: episode.role_contract_sha256.clone(),
        work_class_id: episode.work_class_id.clone(),
        responsibility_id: episode.responsibility_id.clone(),
        terminal_outcome: episode.terminal_outcome,
        situation_class_ids: vec!["current-state-checked".to_owned()],
        completed_subgoal_ids: vec!["saved".to_owned()],
        recovery_class_ids: vec!["fresh-observation-replan".to_owned()],
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        semantic_target_ids: episode.semantic_target_ids.clone(),
        capability_ids: episode.capability_ids.clone(),
        verified_outcome_class_ids: vec!["record-saved".to_owned()],
        concise_summary: "Fresh state determined whether an input action was necessary.".to_owned(),
        data_class_ids: episode.data_class_ids.clone(),
        redaction_proof_ids: episode.redaction_proof_ids.clone(),
        valid_from_unix_ms: 1,
        valid_to_unix_ms: 10_000_000,
        signer_id: "memory-reviewer".to_owned(),
        signing_key_id: "memory-key-v1".to_owned(),
        evidence_ids: vec!["evidence-summary".to_owned()],
        summary_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key())
    .unwrap_or_else(|error| panic!("summary: {error}"))
}

fn overwrite_json(path: &Path, value: &Value) {
    let bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|error| panic!("json: {error}"));
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open: {error}"));
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .unwrap_or_else(|error| panic!("write: {error}"));
}

#[test]
fn protected_store_is_exactly_once_and_tombstone_blocks_publication() {
    let root = temporary_root("store");
    let namespace = namespace();
    let mut store = initialize_episodic_memory_store(&root, namespace.clone(), 100)
        .unwrap_or_else(|error| panic!("init: {error}"));
    let first = episode(&namespace, 1, false);
    let second = episode(&namespace, 2, true);
    store
        .store_episode(&first, 2_100)
        .unwrap_or_else(|error| panic!("store first: {error}"));
    store
        .store_episode(&first, 2_101)
        .unwrap_or_else(|error| panic!("duplicate: {error}"));
    store
        .store_episode(&second, 2_102)
        .unwrap_or_else(|error| panic!("store second: {error}"));
    let approved = summary(&first);
    store
        .publish_summary(&approved, &key().verifying_key(), 2_103)
        .unwrap_or_else(|error| panic!("summary: {error}"));
    let tombstone = EpisodeTombstoneV1 {
        schema_version: 1,
        episode_id: first.episode_id.clone(),
        episode_sha256: first.canonical_episode_sha256.clone(),
        namespace_sha256: namespace.namespace_sha256.clone(),
        tombstoned_at_unix_ms: 2_104,
        reason_code: "retention-expired".to_owned(),
        protected_audit_sha256: hash(90),
        tombstone_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .unwrap_or_else(|error| panic!("tombstone: {error}"));
    store
        .tombstone_episode(&tombstone, 2_104)
        .unwrap_or_else(|error| panic!("tombstone store: {error}"));
    let verification =
        verify_episodic_memory_store(&root, Some(&store.verification().ledger_terminal_sha256))
            .unwrap_or_else(|error| panic!("verify: {error}"));
    assert_eq!(verification.episode_count, 2);
    assert_eq!(verification.summary_count, 0);
    assert_eq!(verification.tombstone_count, 1);
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn stale_index_is_rejected_and_rebuilt_without_replaying_work() {
    let root = temporary_root("recovery");
    let namespace = namespace();
    let mut store = initialize_episodic_memory_store(&root, namespace.clone(), 100)
        .unwrap_or_else(|error| panic!("init: {error}"));
    let first = episode(&namespace, 3, false);
    store
        .store_episode(&first, 3_000)
        .unwrap_or_else(|error| panic!("store: {error}"));
    let index_path = root.join("index.json");
    let mut index: Value = serde_json::from_slice(
        &std::fs::read(&index_path).unwrap_or_else(|error| panic!("read: {error}")),
    )
    .unwrap_or_else(|error| panic!("parse: {error}"));
    index["episodes"] = Value::Array(Vec::new());
    index["ledger_record_count"] = Value::from(0);
    index["ledger_terminal_sha256"] = Value::from(ZERO_HASH);
    index["index_sha256"] = Value::from(ZERO_HASH);
    let repaired_hash =
        hash_without(&index, &["index_sha256"]).unwrap_or_else(|error| panic!("hash: {error}"));
    index["index_sha256"] = Value::from(repaired_hash);
    overwrite_json(&index_path, &index);
    assert!(verify_episodic_memory_store(&root, None).is_err());
    let recovered = recover_episodic_memory_store(&root, 3_001)
        .unwrap_or_else(|error| panic!("recover: {error}"));
    assert_eq!(recovered.episode_count, 1);
    assert_eq!(recovered.candidate_count, 0);
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn candidate_is_quarantined_and_recovery_keeps_one_object() {
    let root = temporary_root("candidate");
    let namespace = namespace();
    let mut store = initialize_episodic_memory_store(&root, namespace.clone(), 100)
        .unwrap_or_else(|error| panic!("init: {error}"));
    let episodes = [episode(&namespace, 4, false), episode(&namespace, 5, true)];
    for (offset, episode) in episodes.iter().enumerate() {
        store
            .store_episode(episode, 4_000 + offset as u64)
            .unwrap_or_else(|error| panic!("episode: {error}"));
    }
    let candidate = create_learning_candidate(CandidateRequestV1 {
        candidate_kind: LearningCandidateKindV1::PlannerExampleCandidate,
        namespace: &namespace,
        episodes: &episodes,
        source_approved_summary_hashes: Vec::new(),
        observed_pattern_class_ids: vec!["state-aware-action-omission".to_owned()],
        proposed_semantic_change_class: "offline-evaluation-fixture".to_owned(),
        expected_benefit_class: "unnecessary-action-reduction".to_owned(),
        risk_class: "bounded-review".to_owned(),
        critical_error_relevance: false,
        required_offline_evaluation_ids: vec!["planner-regression-v1".to_owned()],
        quarantine_reason_codes: vec!["offline-review-required".to_owned()],
        evidence_ids: vec!["evidence-pattern".to_owned()],
    })
    .unwrap_or_else(|error| panic!("candidate: {error}"));
    store
        .quarantine_candidate(&candidate, 4_002)
        .unwrap_or_else(|error| panic!("candidate store: {error}"));
    store
        .quarantine_candidate(&candidate, 4_003)
        .unwrap_or_else(|error| panic!("candidate duplicate: {error}"));
    assert_eq!(store.verification().candidate_count, 1);
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}

#[test]
fn concurrent_writer_lock_fails_closed_and_existing_user_processes_are_untouched() {
    let root = temporary_root("lock");
    let namespace = namespace();
    let mut store = initialize_episodic_memory_store(&root, namespace.clone(), 100)
        .unwrap_or_else(|error| panic!("init: {error}"));
    let lock = root.join(".episodic-memory.lock");
    std::fs::write(&lock, b"owned-by-test").unwrap_or_else(|error| panic!("lock: {error}"));
    assert!(store
        .store_episode(&episode(&namespace, 6, false), 5_000)
        .is_err());
    std::fs::remove_file(lock).unwrap_or_else(|error| panic!("unlock: {error}"));
    std::fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("cleanup: {error}"));
}
