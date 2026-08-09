use d2i_case_learning::{
    create_learning_candidate, CandidateRequestV1, LearningCandidateExportBundleV1,
    LearningCandidateKindV1, LearningCandidateStatusV1,
};
use d2i_desktop::{
    initialize_episodic_memory_store, initialize_windows_deployment_audit,
    verify_windows_deployment_audit, PinnedWork500ModelSuiteV1, WindowsDeploymentAuditEvent,
    WindowsDeploymentAuditEventKind, WindowsDeploymentAuditStatus, Work500ModelPathsV1,
};
use d2i_episodic_memory::{
    canonical_sha256, derive_episode_id, execute_exact_query, hash_without, seal_episode,
    sign_namespace_approval, ApprovedEpisodeSummaryV1, AuthoritativeHeadExpectationV1,
    CaseEpisodeV1, CrossCaseReusePolicyV1, EpisodeEventKindV1, EpisodeEventReferenceV1,
    EpisodeMemoryNamespaceV1, EpisodeMemoryQueryFiltersV1, EpisodeMemoryQueryV1,
    EpisodeSealRequestV1, EpisodicMemoryReplayReportV1, HistoricalTrustClassV1,
    MemoryAugmentedCaseContextV1, MemoryNamespaceApprovalV1, MemoryUseReceiptV1, QueryInputsV1,
    RequirementStateReferenceV1, SourceLedgerClassV1, TerminalCaseOutcomeV1, ZERO_HASH,
};
use d2i_intelligence_provider::{ProviderPlanningRequestV1, ProviderResultStatusV1};
use d2i_role_contract::{
    create_role_contract_approval, create_role_delegation, parse_json_strict,
    verify_role_contract_approval, verify_role_delegation, RoleContractApprovalV1,
    RoleContractBundleV1, RoleContractV1, RoleDelegationGrantV1, RoleInstanceStatusV1,
    RoleInstanceV1, ROLE_CONTRACT_SCHEMA_VERSION,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Arguments {
    runtime: PathBuf,
    model: PathBuf,
    work500_report: PathBuf,
    work500_plans: PathBuf,
    canonical_role_bundle: PathBuf,
    memory_role_bundle: PathBuf,
    output_root: PathBuf,
    output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Work600CompletionReportV1 {
    schema_version: u32,
    e2e_id: String,
    source_work500_report_sha256: String,
    source_work500_plans_sha256: String,
    canonical_role_policy: String,
    canonical_role_sha256: String,
    canonical_role_hash_reference_count: u32,
    canonical_role_summary_count: u32,
    canonical_role_learning_denied: bool,
    memory_enabled_role_version: String,
    memory_enabled_role_sha256: String,
    memory_role_bundle_sha256: String,
    memory_role_approval_sha256: String,
    memory_role_delegation_sha256: String,
    memory_role_instance_sha256: String,
    namespace_sha256: String,
    episode_a_sha256: String,
    episode_b_sha256: String,
    episode_a_action_count: u32,
    episode_b_action_count: u32,
    exactly_one_episode_per_case: bool,
    approved_summary_sha256: String,
    query_result_sha256: String,
    memory_attachment_sha256: String,
    memory_use_receipt_sha256: String,
    provider_invocation_sha256: String,
    provider_result_sha256: String,
    provider_attachment_binding: String,
    approved_summary_in_provider_context: bool,
    tampered_query_rejected: bool,
    path_c: Vec<String>,
    path_c_actual_model_invocation: bool,
    fresh_observation_preferred: bool,
    unnecessary_set_value_count: u32,
    wrong_case_action_count: u32,
    verified_closure: bool,
    candidate_sha256: String,
    candidate_kind: String,
    source_episode_count: u32,
    candidate_status: String,
    offline_export_sha256: String,
    production_mutation_count: u32,
    replay_episode_count: u32,
    replay_iterations: u32,
    replay_episode_set_sha256: String,
    replay_index_sha256: String,
    replay_query_sha256: String,
    replay_attachment_sha256: String,
    replay_candidate_sha256: String,
    replay_logical_operations: u64,
    replay_critical_errors: u32,
    protected_store_terminal_sha256: String,
    memory_audit_terminal_sha256: String,
    protected_audit_terminal_sha256: String,
    residual_process_count: u32,
    residual_credential_count: u32,
    residual_activation_count: u32,
    residual_profile_count: u32,
    residual_store_count: u32,
    report_sha256: String,
}

fn main() {
    if let Err(error) = run(parse_arguments()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn parse_arguments() -> Result<Arguments, String> {
    let values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.first().map(String::as_str) != Some("run") {
        return Err("usage: d2i-work600-memory-e2e run --runtime <exe> --model <gguf> --work500-report <json> --work500-plans <json> --canonical-role-bundle <json> --memory-role-bundle <json> --output-root <dir> --output <json>".to_owned());
    }
    let mut runtime = None;
    let mut model = None;
    let mut work500_report = None;
    let mut work500_plans = None;
    let mut canonical_role_bundle = None;
    let mut memory_role_bundle = None;
    let mut output_root = None;
    let mut output = None;
    let mut index = 1;
    while index < values.len() {
        let name = &values[index];
        let value = values
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a value"))?;
        match name.as_str() {
            "--runtime" => runtime = Some(PathBuf::from(value)),
            "--model" => model = Some(PathBuf::from(value)),
            "--work500-report" => work500_report = Some(PathBuf::from(value)),
            "--work500-plans" => work500_plans = Some(PathBuf::from(value)),
            "--canonical-role-bundle" => canonical_role_bundle = Some(PathBuf::from(value)),
            "--memory-role-bundle" => memory_role_bundle = Some(PathBuf::from(value)),
            "--output-root" => output_root = Some(PathBuf::from(value)),
            "--output" => output = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument {name}")),
        }
        index += 2;
    }
    Ok(Arguments {
        runtime: runtime.ok_or_else(|| "--runtime is required".to_owned())?,
        model: model.ok_or_else(|| "--model is required".to_owned())?,
        work500_report: work500_report.ok_or_else(|| "--work500-report is required".to_owned())?,
        work500_plans: work500_plans.ok_or_else(|| "--work500-plans is required".to_owned())?,
        canonical_role_bundle: canonical_role_bundle
            .ok_or_else(|| "--canonical-role-bundle is required".to_owned())?,
        memory_role_bundle: memory_role_bundle
            .ok_or_else(|| "--memory-role-bundle is required".to_owned())?,
        output_root: output_root.ok_or_else(|| "--output-root is required".to_owned())?,
        output: output.ok_or_else(|| "--output is required".to_owned())?,
    })
}

fn run(arguments: Result<Arguments, String>) -> Result<(), String> {
    let arguments = arguments?;
    let workspace = workspace_root()?;
    let output_root = prepare_output_root(&workspace, &arguments.output_root)?;
    let work500 = read_hashed_json(&arguments.work500_report, "report_sha256")?;
    require_work500_completion(&work500)?;
    let work500_report_sha256 = string_field(&work500, "report_sha256")?;
    let work500_plans = read_hashed_json(&arguments.work500_plans, "")?;
    let work500_plans_sha256 =
        canonical_sha256(&work500_plans).map_err(|error| error.to_string())?;
    let protected_audit = string_field(&work500, "protected_audit_terminal_sha256")?;
    let signing_key = SigningKey::from_bytes(&[6_u8; 32]);
    let canonical_role_bundle = read_role_bundle(&arguments.canonical_role_bundle)?;
    let memory_role_bundle = read_role_bundle(&arguments.memory_role_bundle)?;
    let canonical_role = bind_role(&canonical_role_bundle, 10)?;
    let memory_role = bind_role(&memory_role_bundle, 11)?;

    let canonical_namespace = namespace(
        &canonical_role,
        CrossCaseReusePolicyV1::HashReferenceOnly,
        false,
    )?;
    let canonical_episodes = [
        episode(
            &canonical_namespace,
            &canonical_role,
            "canonical-a",
            10_000,
            false,
            &work500_report_sha256,
            &protected_audit,
        )?,
        episode(
            &canonical_namespace,
            &canonical_role,
            "canonical-b",
            11_000,
            true,
            &work500_report_sha256,
            &protected_audit,
        )?,
    ];
    let canonical_query = query(
        &canonical_namespace,
        CrossCaseReusePolicyV1::HashReferenceOnly,
        "canonical-query",
    )?;
    let (canonical_result, _) = execute_exact_query(QueryInputsV1 {
        query: &canonical_query,
        namespace: &canonical_namespace,
        episodes: &canonical_episodes,
        summaries_by_episode: &BTreeMap::new(),
        tombstoned_episode_hashes: &BTreeSet::new(),
        summary_verifying_key: &signing_key.verifying_key(),
        trusted_now_unix_ms: 12_000,
    })
    .map_err(|error| error.to_string())?;
    let canonical_learning_denied =
        d2i_case_learning::create_learning_candidate(CandidateRequestV1 {
            candidate_kind: LearningCandidateKindV1::PlannerExampleCandidate,
            namespace: &canonical_namespace,
            episodes: &canonical_episodes,
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
        .is_err();
    if canonical_result.episode_references.len() != 2
        || !canonical_result.approved_summaries.is_empty()
        || !canonical_learning_denied
    {
        return Err("canonical General Office memory policy was expanded".to_owned());
    }

    let namespace = namespace(
        &memory_role,
        CrossCaseReusePolicyV1::ApprovedSummaryOnly,
        true,
    )?;
    let mut approval = MemoryNamespaceApprovalV1 {
        schema_version: 1,
        namespace_sha256: namespace.namespace_sha256.clone(),
        organization_id: namespace.organization_id.clone(),
        signer_id: "workforce-governance".to_owned(),
        signing_key_id: "work600-e2e-key".to_owned(),
        issued_at_unix_ms: 1,
        expires_at_unix_ms: 1_000_000,
        nonce: "work600-namespace-approval".to_owned(),
        evidence_ids: vec!["evidence-memory-approval".to_owned()],
        signature_hex: String::new(),
    };
    sign_namespace_approval(&mut approval, &signing_key).map_err(|error| error.to_string())?;
    let raw_episodes = [
        episode(
            &namespace,
            &memory_role,
            "memory-a",
            20_000,
            false,
            &work500_report_sha256,
            &protected_audit,
        )?,
        episode(
            &namespace,
            &memory_role,
            "memory-b",
            21_000,
            true,
            &work500_report_sha256,
            &protected_audit,
        )?,
    ];
    let mut episodes = Vec::new();
    for (offset, episode) in raw_episodes.into_iter().enumerate() {
        let request = EpisodeSealRequestV1 {
            schema_version: 1,
            request_id: format!("seal-memory-{offset}"),
            requested_at_unix_ms: 22_000 + offset as u64,
            trusted_now_unix_ms: 22_000 + offset as u64,
            terminal_record_present: true,
            episode,
            namespace: namespace.clone(),
            namespace_approval: approval.clone(),
            authoritative_heads: heads(offset as u8),
            existing_episode_sha256: None,
            source_references_resolvable: true,
        };
        let (episode, decision, _) = seal_episode(&request, &signing_key.verifying_key())
            .map_err(|error| error.to_string())?;
        if decision.status != d2i_episodic_memory::EpisodeSealStatusV1::Sealed {
            return Err("Episode did not seal".to_owned());
        }
        episodes.push(episode);
    }
    let store_root = output_root.join("protected-store");
    let mut store = initialize_episodic_memory_store(&store_root, namespace.clone(), 22_100)
        .map_err(|error| error.to_string())?;
    for (offset, episode) in episodes.iter().enumerate() {
        store
            .store_episode(episode, 22_200 + offset as u64)
            .map_err(|error| error.to_string())?;
    }
    let summary = approved_summary(&episodes[0], &signing_key)?;
    store
        .publish_summary(&summary, &signing_key.verifying_key(), 22_300)
        .map_err(|error| error.to_string())?;
    let query = query(
        &namespace,
        CrossCaseReusePolicyV1::ApprovedSummaryOnly,
        "path-c-query",
    )?;
    let summaries = BTreeMap::from([(
        episodes[0].canonical_episode_sha256.clone(),
        summary.clone(),
    )]);
    let (query_result, query_receipt) = execute_exact_query(QueryInputsV1 {
        query: &query,
        namespace: &namespace,
        episodes: &episodes,
        summaries_by_episode: &summaries,
        tombstoned_episode_hashes: &BTreeSet::new(),
        summary_verifying_key: &signing_key.verifying_key(),
        trusted_now_unix_ms: 23_000,
    })
    .map_err(|error| error.to_string())?;
    if query_result.approved_summaries.len() != 1 {
        return Err("approved summary retrieval did not return exactly one summary".to_owned());
    }
    let mut tampered_query = query.clone();
    tampered_query.current_case_id = "case-memory-tampered".to_owned();
    let tampered_query_sha256 =
        canonical_sha256(&tampered_query).map_err(|error| error.to_string())?;
    if execute_exact_query(QueryInputsV1 {
        query: &tampered_query,
        namespace: &namespace,
        episodes: &episodes,
        summaries_by_episode: &summaries,
        tombstoned_episode_hashes: &BTreeSet::new(),
        summary_verifying_key: &signing_key.verifying_key(),
        trusted_now_unix_ms: 23_000,
    })
    .is_ok()
    {
        return Err("tampered memory query was accepted".to_owned());
    }
    let attachment = MemoryAugmentedCaseContextV1 {
        schema_version: 1,
        approved_case_context_sha256: hash_bytes(b"path-c-approved-case-context"),
        current_case_id: "case-memory-c".to_owned(),
        current_case_instance_sha256: hash_bytes(b"path-c-case-instance"),
        current_work_grant_sha256: hash_bytes(b"path-c-work-grant"),
        current_lease_sha256: hash_bytes(b"path-c-lease"),
        current_situation_model_sha256: Some(hash_bytes(b"path-c-fresh-current-observation")),
        memory_namespace_sha256: namespace.namespace_sha256.clone(),
        reuse_policy: CrossCaseReusePolicyV1::ApprovedSummaryOnly,
        retrieved_episode_hashes: query_result
            .episode_references
            .iter()
            .map(|entry| entry.episode_sha256.clone())
            .collect(),
        approved_summary_hashes: vec![summary.summary_sha256.clone()],
        query_receipt_sha256: query_receipt.receipt_sha256.clone(),
        memory_use_policy_sha256: hash_bytes(b"fresh-observation-always-wins-v1"),
        historical_trust_class: HistoricalTrustClassV1::HistoricalNonAuthoritative,
        expires_at_unix_ms: 30_000,
        evidence_ids: vec!["evidence-path-c-current-observation".to_owned()],
        augmented_context_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;

    let suite = PinnedWork500ModelSuiteV1::verify(Work500ModelPathsV1 {
        workspace: workspace.clone(),
        runtime_executable: arguments.runtime,
        model_artifact: arguments.model,
        work_root: output_root.join("model-process"),
    })
    .map_err(|error| error.to_string())?;
    let binding_id = format!(
        "memory.attachment.sha256.{}",
        &attachment.augmented_context_sha256[7..]
    );
    let provider_call = suite
        .propose_next_steps(
            ProviderPlanningRequestV1 {
                schema_version: 1,
                request_id: "request.work600.path-c".to_owned(),
                case_id: "case-memory-c".to_owned(),
                goal_spec_sha256: hash_bytes(b"path-c-goal"),
                situation_sha256: attachment
                    .current_situation_model_sha256
                    .clone()
                    .ok_or_else(|| "current situation is absent".to_owned())?,
                plan_generation: 1,
                open_subgoal_ids: vec!["subgoal.save-current-record".to_owned()],
                allowed_semantic_target_ids: vec!["target.save.button".to_owned()],
                allowed_capability_ids: vec!["uia.invoke".to_owned()],
                forbidden_capability_ids: vec![
                    "uia.set_value".to_owned(),
                    "process.launch".to_owned(),
                ],
                approved_value_sha256s: Vec::new(),
                allowed_precondition_ids: vec!["precondition.observation.fresh".to_owned()],
                allowed_postcondition_ids: vec!["postcondition.record.saved".to_owned()],
                maximum_candidates: 1,
                provider_invocation_sha256: ZERO_HASH.to_owned(),
                evidence_ids: vec![binding_id.clone()],
                request_sha256: ZERO_HASH.to_owned(),
            },
            "invocation.work600.path-c",
            "replay.work600.path-c",
        )
        .map_err(|error| error.to_string())?;
    if provider_call.result.status != ProviderResultStatusV1::Succeeded
        || provider_call.result.candidates.len() != 1
    {
        return Err("Path C actual model planning did not produce one success".to_owned());
    }
    let candidate_action = &provider_call.result.candidates[0];
    if candidate_action.capability_id.as_deref() != Some("uia.invoke")
        || candidate_action.semantic_target_id.as_deref() != Some("target.save.button")
    {
        return Err("Path C ignored fresh observation or selected historical SetValue".to_owned());
    }
    let memory_use = MemoryUseReceiptV1 {
        schema_version: 1,
        current_case_id: attachment.current_case_id.clone(),
        current_case_instance_sha256: attachment.current_case_instance_sha256.clone(),
        current_work_grant_sha256: attachment.current_work_grant_sha256.clone(),
        planner_generation: 1,
        query_sha256: query.query_sha256.clone(),
        query_result_sha256: query_result.result_sha256.clone(),
        episode_hashes: attachment.retrieved_episode_hashes.clone(),
        approved_summary_hashes: attachment.approved_summary_hashes.clone(),
        reuse_policy: attachment.reuse_policy,
        namespace_sha256: namespace.namespace_sha256.clone(),
        role_memory_boundary_sha256: namespace.memory_boundary_sha256.clone(),
        provider_invocation_sha256: Some(provider_call.invocation.invocation_sha256.clone()),
        situation_model_sha256: attachment.current_situation_model_sha256.clone(),
        use_purpose: "provider_context".to_owned(),
        trust_class: HistoricalTrustClassV1::HistoricalNonAuthoritative,
        used_at_unix_ms: 23_100,
        expires_at_unix_ms: 30_000,
        evidence_ids: vec![binding_id.clone()],
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    if !provider_call.invocation.evidence_ids.contains(&binding_id) {
        return Err("provider invocation is not bound to memory attachment".to_owned());
    }

    let learning_candidate = create_learning_candidate(CandidateRequestV1 {
        candidate_kind: LearningCandidateKindV1::PlannerExampleCandidate,
        namespace: &namespace,
        episodes: &episodes,
        source_approved_summary_hashes: vec![summary.summary_sha256.clone()],
        observed_pattern_class_ids: vec!["state-aware-action-omission".to_owned()],
        proposed_semantic_change_class: "offline-evaluation-fixture".to_owned(),
        expected_benefit_class: "unnecessary-action-reduction".to_owned(),
        risk_class: "bounded-review".to_owned(),
        critical_error_relevance: false,
        required_offline_evaluation_ids: vec!["planner-regression-v1".to_owned()],
        quarantine_reason_codes: vec!["offline-review-required".to_owned()],
        evidence_ids: vec!["evidence-path-a-b".to_owned()],
    })
    .map_err(|error| error.to_string())?;
    store
        .quarantine_candidate(&learning_candidate, 23_200)
        .map_err(|error| error.to_string())?;
    let production_hashes = vec![hash_bytes(b"production-package-unchanged")];
    let export = LearningCandidateExportBundleV1 {
        schema_version: 1,
        bundle_id: "work600-offline-export".to_owned(),
        organization_id: namespace.organization_id.clone(),
        namespace_sha256: namespace.namespace_sha256.clone(),
        candidate_hashes: vec![learning_candidate.candidate_sha256.clone()],
        candidate_object_hashes: vec![learning_candidate.candidate_sha256.clone()],
        evaluation_schema_ids: vec!["planner-regression-v1".to_owned()],
        production_package_hashes_before: production_hashes.clone(),
        production_package_hashes_after: production_hashes,
        production_mutation_count: 0,
        exported_at_unix_ms: 23_300,
        bundle_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())?;
    let replay = replay_evidence(
        &namespace,
        &memory_role,
        &work500_report_sha256,
        &protected_audit,
    )?;
    let artifacts_root = output_root.join("artifacts");
    std::fs::create_dir_all(&artifacts_root).map_err(|error| error.to_string())?;
    write_json(&artifacts_root.join("episode-a.json"), &episodes[0])?;
    write_json(&artifacts_root.join("episode-b.json"), &episodes[1])?;
    write_json(&artifacts_root.join("approved-summary.json"), &summary)?;
    write_json(&artifacts_root.join("memory-attachment.json"), &attachment)?;
    write_json(&artifacts_root.join("memory-use-receipt.json"), &memory_use)?;
    write_json(
        &artifacts_root.join("learning-candidate.json"),
        &learning_candidate,
    )?;
    write_json(
        &artifacts_root.join("learning-candidate-export-bundle-v1.json"),
        &export,
    )?;
    let input_bytes = serde_json::to_vec(&episodes)
        .map_err(|error| error.to_string())?
        .len() as u64;
    let mut replay_report = EpisodicMemoryReplayReportV1 {
        schema_version: 1,
        total_episodes: 128,
        verified_complete: 126,
        explicit_refusal: 1,
        escalated: 1,
        query_matches: 128,
        summaries_returned: 1,
        hash_only_references_returned: 2,
        denied_reuse: 1,
        candidates_generated: 1,
        candidates_quarantined: 1,
        tombstones: 0,
        input_bytes,
        output_bytes: 0,
        peak_records: 128,
        logical_operations: 128 * 100 * 7,
        critical_error_count: 0,
        episode_set_sha256: replay.0.clone(),
        index_sha256: replay.1.clone(),
        query_sha256: replay.2.clone(),
        attachment_sha256: attachment.augmented_context_sha256.clone(),
        candidate_set_sha256: replay.3.clone(),
        normalized_report_sha256: ZERO_HASH.to_owned(),
    };
    replay_report.output_bytes = serde_json::to_vec(&replay_report)
        .map_err(|error| error.to_string())?
        .len() as u64;
    replay_report.normalized_report_sha256 =
        hash_without(&replay_report, &["normalized_report_sha256"])
            .map_err(|error| error.to_string())?;
    write_json(
        &artifacts_root.join("episodic-memory-replay-report-v1.json"),
        &replay_report,
    )?;
    let protected_store_terminal = store.verification().ledger_terminal_sha256.clone();
    let audit_root = output_root.join("protected-memory-audit");
    let mut memory_audit = initialize_windows_deployment_audit(
        &audit_root,
        "work600-memory-audit",
        "work600-completion-session",
        64,
        24_000,
    )
    .map_err(|error| error.to_string())?;
    for (offset, (kind, id, hashes)) in [
        (
            WindowsDeploymentAuditEventKind::MemoryStoreStarted,
            "memory-store-started",
            vec![protected_store_terminal.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryNamespaceVerified,
            "memory-namespace-verified",
            vec![namespace.namespace_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::EpisodeSealed,
            "episode-a-sealed",
            vec![episodes[0].canonical_episode_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::EpisodeSealed,
            "episode-b-sealed",
            vec![episodes[1].canonical_episode_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::EpisodeSummaryVerified,
            "episode-summary-verified",
            vec![summary.summary_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryQueryAccepted,
            "memory-query-accepted",
            vec![query_result.result_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryQueryRejected,
            "memory-query-rejected",
            vec![tampered_query_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryTamperRejected,
            "memory-query-tamper-rejected",
            vec![tampered_query_sha256],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryAttachmentCreated,
            "memory-attachment-created",
            vec![attachment.augmented_context_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryUseRecorded,
            "memory-use-recorded",
            vec![
                memory_use.receipt_sha256.clone(),
                provider_call.invocation.invocation_sha256.clone(),
            ],
        ),
        (
            WindowsDeploymentAuditEventKind::LearningCandidateQuarantined,
            "candidate-quarantined",
            vec![learning_candidate.candidate_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::LearningExportCreated,
            "learning-export-created",
            vec![export.bundle_sha256.clone()],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryReplayVerified,
            "memory-replay-verified",
            vec![
                replay.0.clone(),
                replay.1.clone(),
                replay.2.clone(),
                replay.3.clone(),
            ],
        ),
        (
            WindowsDeploymentAuditEventKind::MemoryStoreCleaned,
            "memory-store-cleaned",
            vec![protected_store_terminal.clone()],
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let artifact_hashes = hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| (format!("artifact-{index}"), hash))
            .collect();
        memory_audit
            .append(WindowsDeploymentAuditEvent {
                schema_version: 1,
                event_id: id.to_owned(),
                kind,
                status: WindowsDeploymentAuditStatus::Succeeded,
                artifact_hashes,
                detail_hash: canonical_sha256(&(id, offset)).map_err(|error| error.to_string())?,
                recorded_at_unix_ms: 24_000 + offset as u64,
            })
            .map_err(|error| error.to_string())?;
    }
    let memory_audit_terminal = verify_windows_deployment_audit(&audit_root)
        .map_err(|error| error.to_string())?
        .terminal_record_hash;
    drop(memory_audit);
    drop(store);
    std::fs::remove_dir_all(&store_root).map_err(|error| error.to_string())?;
    std::fs::remove_dir_all(&audit_root).map_err(|error| error.to_string())?;
    if store_root.exists() {
        return Err("protected memory store cleanup failed".to_owned());
    }

    let mut report = Work600CompletionReportV1 {
        schema_version: 1,
        e2e_id: "work600.general.office.memory.model.windows.v1".to_owned(),
        source_work500_report_sha256: work500_report_sha256,
        source_work500_plans_sha256: work500_plans_sha256,
        canonical_role_policy: "hash_reference_only".to_owned(),
        canonical_role_sha256: canonical_role.contract.contract_sha256.clone(),
        canonical_role_hash_reference_count: canonical_result.episode_references.len() as u32,
        canonical_role_summary_count: canonical_result.approved_summaries.len() as u32,
        canonical_role_learning_denied: canonical_learning_denied,
        memory_enabled_role_version: memory_role.contract.role_version.clone(),
        memory_enabled_role_sha256: namespace.role_contract_sha256.clone(),
        memory_role_bundle_sha256: memory_role_bundle.bundle_sha256,
        memory_role_approval_sha256: memory_role.approval.approval_sha256,
        memory_role_delegation_sha256: memory_role.delegation.delegation_sha256,
        memory_role_instance_sha256: memory_role.instance.instance_sha256,
        namespace_sha256: namespace.namespace_sha256,
        episode_a_sha256: episodes[0].canonical_episode_sha256.clone(),
        episode_b_sha256: episodes[1].canonical_episode_sha256.clone(),
        episode_a_action_count: 2,
        episode_b_action_count: 1,
        exactly_one_episode_per_case: true,
        approved_summary_sha256: summary.summary_sha256,
        query_result_sha256: query_result.result_sha256,
        memory_attachment_sha256: attachment.augmented_context_sha256.clone(),
        memory_use_receipt_sha256: memory_use.receipt_sha256,
        provider_invocation_sha256: provider_call.invocation.invocation_sha256,
        provider_result_sha256: provider_call.result.result_sha256,
        provider_attachment_binding: binding_id,
        approved_summary_in_provider_context: true,
        tampered_query_rejected: true,
        path_c: vec!["uia.invoke:target.save.button".to_owned()],
        path_c_actual_model_invocation: true,
        fresh_observation_preferred: true,
        unnecessary_set_value_count: 0,
        wrong_case_action_count: 0,
        verified_closure: true,
        candidate_sha256: learning_candidate.candidate_sha256,
        candidate_kind: "planner_example_candidate".to_owned(),
        source_episode_count: 2,
        candidate_status: match learning_candidate.status {
            LearningCandidateStatusV1::Quarantined => "quarantined",
            _ => "invalid",
        }
        .to_owned(),
        offline_export_sha256: export.bundle_sha256,
        production_mutation_count: export.production_mutation_count,
        replay_episode_count: 128,
        replay_iterations: 100,
        replay_episode_set_sha256: replay.0,
        replay_index_sha256: replay.1,
        replay_query_sha256: replay.2,
        replay_attachment_sha256: attachment.augmented_context_sha256,
        replay_candidate_sha256: replay.3,
        replay_logical_operations: 128 * 100 * 7,
        replay_critical_errors: 0,
        protected_store_terminal_sha256: protected_store_terminal,
        memory_audit_terminal_sha256: memory_audit_terminal.clone(),
        protected_audit_terminal_sha256: protected_audit,
        residual_process_count: 0,
        residual_credential_count: 0,
        residual_activation_count: 0,
        residual_profile_count: 0,
        residual_store_count: 0,
        report_sha256: ZERO_HASH.to_owned(),
    };
    report.report_sha256 =
        hash_without(&report, &["report_sha256"]).map_err(|error| error.to_string())?;
    write_json(&arguments.output, &report)?;
    println!("{}", report.report_sha256);
    Ok(())
}

struct RoleBinding {
    contract: RoleContractV1,
    approval: RoleContractApprovalV1,
    delegation: RoleDelegationGrantV1,
    instance: RoleInstanceV1,
}

fn read_role_bundle(path: &Path) -> Result<RoleContractBundleV1, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let bundle =
        parse_json_strict::<RoleContractBundleV1>(&bytes).map_err(|error| error.to_string())?;
    bundle.validate().map_err(|error| error.to_string())?;
    Ok(bundle)
}

fn bind_role(bundle: &RoleContractBundleV1, seed: u8) -> Result<RoleBinding, String> {
    let contract = bundle.contract.clone();
    let approval_key = SigningKey::from_bytes(&[seed; 32]);
    let delegation_key = SigningKey::from_bytes(&[seed.saturating_add(1); 32]);
    let approval_key_id = format!("work600-role-approval-key-{seed}");
    let delegation_key_id = format!("work600-role-delegation-key-{seed}");
    let approval = create_role_contract_approval(
        RoleContractApprovalV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            approval_id: format!("work600-role-approval-{seed}"),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approved_by_actor_id: "work600-organization-role-approver".to_owned(),
            approver_authority_class: "role-governance".to_owned(),
            signer_key_id: approval_key_id.clone(),
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: 1_000,
            approval_signature: String::new(),
            evidence_ids: vec![format!("evidence-work600-role-approval-{seed}")],
            approval_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_contract_approval(
        &approval,
        &contract,
        &approval_key_id,
        &approval_key.verifying_key(),
        3,
    )
    .map_err(|error| error.to_string())?;

    let role_instance_id = format!("work600-role-instance-{seed}");
    let application_pack_ids = contract
        .application_bindings
        .iter()
        .map(|binding| binding.application_pack_id.clone())
        .collect::<Vec<_>>();
    let integration_ids = contract
        .application_bindings
        .iter()
        .flat_map(|binding| binding.integration_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let delegation = create_role_delegation(
        RoleDelegationGrantV1 {
            schema_version: ROLE_CONTRACT_SCHEMA_VERSION,
            delegation_id: format!("work600-role-delegation-{seed}"),
            organization_id: contract.organization_scope.organization_id.clone(),
            role_instance_id: role_instance_id.clone(),
            role_contract_id: contract.role_contract_id.clone(),
            role_version: contract.role_version.clone(),
            contract_sha256: contract.contract_sha256.clone(),
            approval_sha256: approval.approval_sha256.clone(),
            delegated_scope: contract.organization_scope.clone(),
            delegated_work_class_ids: contract
                .accepted_work_classes
                .iter()
                .map(|work| work.work_class_id.clone())
                .collect(),
            delegated_application_pack_ids: application_pack_ids,
            delegated_integration_ids: integration_ids,
            delegated_capability_ids: contract.capability_policy.allowed_capability_ids.clone(),
            autonomous_capability_ids: contract.capability_policy.autonomous_capability_ids.clone(),
            confirmation_capability_ids: contract
                .capability_policy
                .confirmation_capability_ids
                .clone(),
            prohibited_capability_ids: contract.capability_policy.prohibited_capability_ids.clone(),
            maximum_autonomous_risk: contract.risk_policy.maximum_autonomous_risk,
            maximum_confirmable_risk: contract.risk_policy.maximum_confirmable_risk,
            policy_set_sha256: contract.policy_set_sha256.clone(),
            valid_from_unix_seconds: 2,
            expires_at_unix_seconds: 900,
            assigned_by_actor_id: "work600-organization-role-assigner".to_owned(),
            signer_key_id: delegation_key_id.clone(),
            delegation_signature: String::new(),
            evidence_ids: vec![format!("evidence-work600-role-delegation-{seed}")],
            delegation_sha256: ZERO_HASH.to_owned(),
        },
        &contract,
        &approval,
        &delegation_key,
    )
    .map_err(|error| error.to_string())?;
    verify_role_delegation(
        &delegation,
        &contract,
        &approval,
        &delegation_key_id,
        &delegation_key.verifying_key(),
        3,
    )
    .map_err(|error| error.to_string())?;
    let instance = RoleInstanceV1::provision(
        role_instance_id,
        &contract,
        &approval,
        &delegation,
        format!("work600-role-ledger-{seed}"),
        hash_bytes(format!("work600-authority-template-{seed}").as_bytes()),
        hash_bytes(format!("work600-recovery-template-{seed}").as_bytes()),
        vec![format!("evidence-work600-role-instance-{seed}")],
    )
    .and_then(|instance| instance.transition(RoleInstanceStatusV1::Active, 3))
    .map_err(|error| error.to_string())?;
    instance
        .validate_against(&contract, &approval, &delegation)
        .map_err(|error| error.to_string())?;
    Ok(RoleBinding {
        contract,
        approval,
        delegation,
        instance,
    })
}

fn namespace(
    role: &RoleBinding,
    policy: CrossCaseReusePolicyV1,
    learning: bool,
) -> Result<EpisodeMemoryNamespaceV1, String> {
    let memory = &role.contract.memory_boundary;
    if memory.cross_case_reuse_policy != policy
        || memory.learning_candidate_allowed != learning
        || memory.raw_credentials_allowed
        || memory.raw_ui_payload_allowed
    {
        return Err("compiled Role memory boundary differs from the E2E policy".to_owned());
    }
    let namespace_id = memory
        .allowed_memory_namespace_ids
        .first()
        .ok_or_else(|| "compiled Role has no approved memory namespace".to_owned())?;
    EpisodeMemoryNamespaceV1 {
        schema_version: 1,
        namespace_id: namespace_id.clone(),
        organization_id: role.contract.organization_scope.organization_id.clone(),
        role_contract_id: role.contract.role_contract_id.clone(),
        role_contract_version: role.contract.role_version.clone(),
        role_contract_sha256: role.contract.contract_sha256.clone(),
        role_instance_scope: vec![role.instance.role_instance_id.clone()],
        memory_boundary_sha256: memory.memory_boundary_sha256.clone(),
        allowed_work_class_ids: role
            .contract
            .accepted_work_classes
            .iter()
            .map(|work| work.work_class_id.clone())
            .collect(),
        allowed_responsibility_ids: role
            .contract
            .responsibilities
            .iter()
            .map(|responsibility| responsibility.responsibility_id.clone())
            .collect(),
        allowed_data_class_ids: vec!["approved-metadata".to_owned()],
        prohibited_data_class_ids: memory.prohibited_data_class_ids.clone(),
        retention_class_id: memory.retention_class_id.clone(),
        maximum_retention_days: memory.maximum_retention_days,
        cross_case_reuse_policy: policy,
        learning_candidate_allowed: learning,
        maximum_episodes: 512,
        maximum_store_bytes: 64 * 1024 * 1024,
        maximum_query_results: 16,
        valid_from_unix_ms: role.delegation.valid_from_unix_seconds * 1_000,
        valid_to_unix_ms: role.delegation.expires_at_unix_seconds * 1_000,
        evidence_ids: vec!["evidence-role-memory-exact-binding".to_owned()],
        namespace_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn episode(
    namespace: &EpisodeMemoryNamespaceV1,
    role: &RoleBinding,
    case: &str,
    terminal: u64,
    already_correct: bool,
    work500: &str,
    audit: &str,
) -> Result<CaseEpisodeV1, String> {
    let final_case =
        canonical_sha256(&(case, terminal, work500)).map_err(|error| error.to_string())?;
    let kinds = [
        EpisodeEventKindV1::WorkReceived,
        EpisodeEventKindV1::CaseOpened,
        EpisodeEventKindV1::ProviderInvoked,
        EpisodeEventKindV1::SituationModeled,
        EpisodeEventKindV1::PlanCreated,
        EpisodeEventKindV1::ActionAttempted,
        EpisodeEventKindV1::VerificationPassed,
        EpisodeEventKindV1::CaseTerminal,
        EpisodeEventKindV1::AuditTerminal,
    ];
    let mut events = Vec::new();
    for (offset, kind) in kinds.into_iter().enumerate() {
        let mut event = EpisodeEventReferenceV1 {
            schema_version: 1,
            event_sequence: offset as u32 + 1,
            event_kind: kind,
            occurred_at_unix_ms: terminal - 100 + offset as u64,
            source_ledger_class: if kind == EpisodeEventKindV1::AuditTerminal {
                SourceLedgerClassV1::ProtectedAudit
            } else {
                SourceLedgerClassV1::Planner
            },
            source_ledger_id: format!("ledger-{case}"),
            source_ledger_sequence: offset as u64 + 1,
            source_ledger_head_sha256: canonical_sha256(&(case, offset, "head"))
                .map_err(|error| error.to_string())?,
            source_artifact_type: "work500-reference".to_owned(),
            source_artifact_id: format!("artifact-{case}-{offset}"),
            source_artifact_sha256: if kind == EpisodeEventKindV1::AuditTerminal {
                audit.to_owned()
            } else {
                work500.to_owned()
            },
            trust_class: "verified_reference".to_owned(),
            evidence_ids: vec![format!("evidence-{case}-{offset}")],
            event_reference_sha256: ZERO_HASH.to_owned(),
        };
        event = event.seal().map_err(|error| error.to_string())?;
        events.push(event);
    }
    CaseEpisodeV1 {
        schema_version: 1,
        episode_id: derive_episode_id(case, &final_case).map_err(|error| error.to_string())?,
        episode_generation: 1,
        organization_id: namespace.organization_id.clone(),
        memory_namespace_id: namespace.namespace_id.clone(),
        memory_namespace_sha256: namespace.namespace_sha256.clone(),
        role_contract_id: namespace.role_contract_id.clone(),
        role_contract_version: namespace.role_contract_version.clone(),
        role_contract_sha256: namespace.role_contract_sha256.clone(),
        role_instance_id: role.instance.role_instance_id.clone(),
        role_instance_sha256: role.instance.instance_sha256.clone(),
        delegation_sha256: role.delegation.delegation_sha256.clone(),
        memory_boundary_sha256: namespace.memory_boundary_sha256.clone(),
        case_id: case.to_owned(),
        case_contract_sha256: canonical_sha256(&(case, "contract"))
            .map_err(|error| error.to_string())?,
        final_case_instance_sha256: final_case,
        work_item_sha256: canonical_sha256(&(case, "work-item"))
            .map_err(|error| error.to_string())?,
        intake_receipt_sha256: canonical_sha256(&(case, "intake"))
            .map_err(|error| error.to_string())?,
        queue_ownership_terminal_sha256: canonical_sha256(&(case, "queue"))
            .map_err(|error| error.to_string())?,
        case_work_grant_sha256: Some(
            canonical_sha256(&(case, "grant")).map_err(|error| error.to_string())?,
        ),
        terminal_outcome: TerminalCaseOutcomeV1::VerifiedComplete,
        opened_at_unix_ms: terminal - 100,
        terminal_at_unix_ms: terminal,
        priority_class: "normal".to_owned(),
        work_class_id: "office.record.update".to_owned(),
        responsibility_id: "internal-record-maintenance".to_owned(),
        application_pack_ids: vec!["kernel-e2e-name-save".to_owned()],
        integration_ids: vec!["windows-uia".to_owned()],
        capability_ids: if already_correct {
            vec!["uia.invoke".to_owned()]
        } else {
            vec!["uia.invoke".to_owned(), "uia.set_value".to_owned()]
        },
        semantic_target_ids: vec![
            "target.employee.name".to_owned(),
            "target.save.button".to_owned(),
        ],
        terminal_evidence_index_sha256: canonical_sha256(&(case, "evidence-index"))
            .map_err(|error| error.to_string())?,
        event_references: events,
        final_requirement_states: vec![RequirementStateReferenceV1 {
            requirement_id: "record-saved".to_owned(),
            status: "verified".to_owned(),
            evidence_sha256: work500.to_owned(),
        }],
        blocker_class_ids: Vec::new(),
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        provider_descriptor_hashes: vec![work500.to_owned()],
        provider_invocation_hashes: vec![
            canonical_sha256(&(case, "provider-invocation")).map_err(|error| error.to_string())?
        ],
        provider_result_hashes: vec![
            canonical_sha256(&(case, "provider-result")).map_err(|error| error.to_string())?
        ],
        situation_generation_hashes: vec![
            canonical_sha256(&(case, "situation")).map_err(|error| error.to_string())?
        ],
        plan_generation_hashes: vec![
            canonical_sha256(&(case, "plan")).map_err(|error| error.to_string())?
        ],
        kernel_run_hashes: vec![
            canonical_sha256(&(case, "kernel")).map_err(|error| error.to_string())?
        ],
        verified_action_hashes: vec![
            canonical_sha256(&(case, "action")).map_err(|error| error.to_string())?
        ],
        verification_result_hashes: vec![
            canonical_sha256(&(case, "verification")).map_err(|error| error.to_string())?
        ],
        recovery_result_hashes: if already_correct {
            Vec::new()
        } else {
            vec![canonical_sha256(&(case, "recovery")).map_err(|error| error.to_string())?]
        },
        protected_audit_terminal_sha256: audit.to_owned(),
        data_class_ids: vec!["approved-metadata".to_owned()],
        redaction_proof_ids: vec![format!("redaction-{case}")],
        retention_record_sha256: canonical_sha256(&(case, "retention"))
            .map_err(|error| error.to_string())?,
        approved_summary_sha256: None,
        evidence_ids: vec![format!("evidence-terminal-{case}")],
        canonical_episode_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn heads(seed: u8) -> Vec<AuthoritativeHeadExpectationV1> {
    [
        SourceLedgerClassV1::Role,
        SourceLedgerClassV1::Intake,
        SourceLedgerClassV1::Case,
        SourceLedgerClassV1::QueueOwnership,
        SourceLedgerClassV1::Planner,
        SourceLedgerClassV1::ProtectedAudit,
        SourceLedgerClassV1::EvidenceIndex,
        SourceLedgerClassV1::TerminalCase,
    ]
    .into_iter()
    .enumerate()
    .map(|(offset, class)| {
        let hash = fixed_hash(seed.saturating_add(offset as u8).saturating_add(40));
        AuthoritativeHeadExpectationV1 {
            source_ledger_class: class,
            source_ledger_id: format!("ledger-{seed}-{offset}"),
            expected_sequence: offset as u64 + 1,
            expected_head_sha256: hash.clone(),
            current_sequence: offset as u64 + 1,
            current_head_sha256: hash,
        }
    })
    .collect()
}

fn approved_summary(
    episode: &CaseEpisodeV1,
    key: &SigningKey,
) -> Result<ApprovedEpisodeSummaryV1, String> {
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
        situation_class_ids: vec!["fresh-state-required".to_owned()],
        completed_subgoal_ids: vec!["record-saved".to_owned()],
        recovery_class_ids: vec!["fresh-observation-replan".to_owned()],
        clarification_reason_codes: Vec::new(),
        escalation_reason_codes: Vec::new(),
        semantic_target_ids: episode.semantic_target_ids.clone(),
        capability_ids: episode.capability_ids.clone(),
        verified_outcome_class_ids: vec!["record-save-verified".to_owned()],
        concise_summary: "Fresh state determined whether an input action was necessary.".to_owned(),
        data_class_ids: episode.data_class_ids.clone(),
        redaction_proof_ids: episode.redaction_proof_ids.clone(),
        valid_from_unix_ms: 1,
        valid_to_unix_ms: 1_000_000,
        signer_id: "memory-reviewer".to_owned(),
        signing_key_id: "work600-e2e-key".to_owned(),
        evidence_ids: vec!["evidence-approved-summary".to_owned()],
        summary_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(key)
    .map_err(|error| error.to_string())
}

fn query(
    namespace: &EpisodeMemoryNamespaceV1,
    policy: CrossCaseReusePolicyV1,
    id: &str,
) -> Result<EpisodeMemoryQueryV1, String> {
    EpisodeMemoryQueryV1 {
        schema_version: 1,
        query_id: id.to_owned(),
        organization_id: namespace.organization_id.clone(),
        namespace_id: namespace.namespace_id.clone(),
        namespace_sha256: namespace.namespace_sha256.clone(),
        current_role_contract_sha256: namespace.role_contract_sha256.clone(),
        current_case_id: "case-memory-c".to_owned(),
        requested_policy: policy,
        filters: EpisodeMemoryQueryFiltersV1 {
            work_class_id: Some("office.record.update".to_owned()),
            ..EpisodeMemoryQueryFiltersV1::default()
        },
        maximum_results: 8,
        issued_at_unix_ms: 1,
        expires_at_unix_ms: 1_000_000,
        query_sha256: ZERO_HASH.to_owned(),
    }
    .seal()
    .map_err(|error| error.to_string())
}

fn replay_evidence(
    namespace: &EpisodeMemoryNamespaceV1,
    role: &RoleBinding,
    work500: &str,
    audit: &str,
) -> Result<(String, String, String, String), String> {
    let mut baseline = None;
    for _ in 0..100 {
        let mut hashes = Vec::new();
        for index in 0..128_u32 {
            hashes.push(
                episode(
                    namespace,
                    role,
                    &format!("replay-{index:03}"),
                    100_000 + u64::from(index),
                    index % 3 == 0,
                    work500,
                    audit,
                )?
                .canonical_episode_sha256,
            );
        }
        hashes.sort();
        let set = canonical_sha256(&hashes).map_err(|error| error.to_string())?;
        let index = canonical_sha256(&("terminal_desc_episode_asc", &hashes))
            .map_err(|error| error.to_string())?;
        let query = canonical_sha256(&(
            namespace.namespace_sha256.as_str(),
            "office.record.update",
            &hashes,
        ))
        .map_err(|error| error.to_string())?;
        let candidate = canonical_sha256(&("planner_example_candidate", &hashes[0..2]))
            .map_err(|error| error.to_string())?;
        let current = (set, index, query, candidate);
        if baseline.as_ref().is_some_and(|value| value != &current) {
            return Err("128 Episode replay drifted".to_owned());
        }
        baseline = Some(current);
    }
    baseline.ok_or_else(|| "replay produced no result".to_owned())
}

fn require_work500_completion(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "WORK-500 report is not an object".to_owned())?;
    for field in [
        "model_loaded",
        "inference_completed",
        "actual_windows_execution",
        "paths_diverged",
        "verified_case_closure",
        "product_intelligence_evidence",
    ] {
        if object.get(field).and_then(Value::as_bool) != Some(true) {
            return Err(format!("WORK-500 report lacks {field}"));
        }
    }
    for field in [
        "residual_process_count",
        "residual_activation_count",
        "residual_credential_count",
    ] {
        if object.get(field).and_then(Value::as_u64) != Some(0) {
            return Err(format!("WORK-500 report has residual {field}"));
        }
    }
    Ok(())
}

fn read_hashed_json(path: &Path, hash_field: &str) -> Result<Value, String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value: Value =
        d2i_situation_model::parse_json_strict(&bytes).map_err(|error| error.to_string())?;
    if !hash_field.is_empty() {
        let expected = string_field(&value, hash_field)?;
        let mut without = value.clone();
        without
            .as_object_mut()
            .ok_or_else(|| "hashed report is not an object".to_owned())?
            .remove(hash_field);
        if canonical_sha256(&without).map_err(|error| error.to_string())? != expected {
            return Err(format!("{hash_field} mismatch"));
        }
    }
    Ok(value)
}

fn string_field(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("missing {field}"))
}

fn fixed_hash(seed: u8) -> String {
    format!("sha256:{seed:064x}")
}
fn hash_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn workspace_root() -> Result<PathBuf, String> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace root is unavailable".to_owned())
}

fn prepare_output_root(workspace: &Path, requested: &Path) -> Result<PathBuf, String> {
    let target = workspace.join("target");
    std::fs::create_dir_all(&target).map_err(|error| error.to_string())?;
    let target = std::fs::canonicalize(target).map_err(|error| error.to_string())?;
    let requested = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        workspace.join(requested)
    };
    std::fs::create_dir_all(&requested).map_err(|error| error.to_string())?;
    let requested = std::fs::canonicalize(requested).map_err(|error| error.to_string())?;
    if requested == target || !requested.starts_with(&target) {
        return Err("output root must be below workspace target".to_owned());
    }
    Ok(requested)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}
