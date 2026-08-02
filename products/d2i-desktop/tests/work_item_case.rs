#[path = "support/work_case_fixture.rs"]
mod work_case_fixture;

use d2i_desktop::{
    initialize_case_ledger, persist_new_case, verify_case_ledger, CaseKernelArtifactsV1,
    FinalGoalVerificationV1, KernelTaskRunRecordV1, WorkCaseCoordinatorV1, WorkReport,
};
use d2i_role_contract::{RoleBoundKernelTaskContextV1, RoleInstanceStatusV1};
use d2i_work_case::{
    CaseClosureEvaluationOutcomeV1, CaseEvidenceProducerKindV1, CaseEvidenceRefV1,
    CaseEvidenceTrustFloorV1, CaseLifecycleStatusV1, CaseSlaStatusSnapshotV1,
    CaseTaskAttemptOutcomeV1, CaseTaskRequestV1,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use work_case_fixture::{digest, fixture, ok, PACK_HASH, ZERO_HASH};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("d2i-work-case-test-{label}-{}", std::process::id()));
        if path.exists() {
            let removed = std::fs::remove_dir_all(&path);
            assert!(removed.is_ok());
        }
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn persisted_fixture(label: &str) -> (TempRoot, work_case_fixture::Fixture) {
    let root = TempRoot::new(label);
    let fixture = fixture();
    let mut ledger = ok(initialize_case_ledger(
        &root.0,
        "case-ledger-example",
        &fixture.work_item.organization_id,
        1_024,
        1_785_000_000_000,
    ));
    ok(persist_new_case(
        &mut ledger,
        &fixture.work_item,
        &fixture.dedup_key,
        &fixture.admission,
        &fixture.case_contract,
        &fixture.case_instance,
        &digest('a'),
        &digest('b'),
        1_785_000_011_000,
    ));
    (root, fixture)
}

#[test]
fn case_ledger_append_reopen_and_cross_references_are_exact() {
    let (root, fixture) = persisted_fixture("reopen");
    assert_eq!(
        fixture.role_contract.contract_sha256,
        fixture.case_contract.role_contract_sha256
    );
    let verification = ok(verify_case_ledger(&root.0));
    assert_eq!(verification.record_count, 3);
    assert_eq!(verification.deduplication_entries.len(), 1);
    assert_eq!(
        verification
            .case_contract_hashes
            .get(&fixture.case_contract.case_id),
        Some(&fixture.case_contract.contract_sha256)
    );
    assert_eq!(
        verification
            .current_instances
            .get(&fixture.case_contract.case_id)
            .map(|instance| instance.instance_sha256.as_str()),
        Some(fixture.case_instance.instance_sha256.as_str())
    );
    assert_eq!(verification.latest_role_ledger_chain_head, digest('a'));
    assert_eq!(verification.latest_kernel_audit_chain_head, digest('b'));
}

#[test]
fn duplicate_work_item_is_rejected_without_ledger_mutation() {
    let (root, fixture) = persisted_fixture("duplicate");
    let mut ledger = ok(d2i_desktop::CaseLedgerV1::open(&root.0));
    let before = ledger.verification().clone();
    let duplicate = persist_new_case(
        &mut ledger,
        &fixture.work_item,
        &fixture.dedup_key,
        &fixture.admission,
        &fixture.case_contract,
        &fixture.case_instance,
        &digest('a'),
        &digest('b'),
        1_785_000_012_000,
    );
    assert!(duplicate.is_err());
    assert_eq!(ok(verify_case_ledger(&root.0)), before);
}

#[test]
fn corrupted_case_ledger_fails_closed_on_reopen() {
    let (root, _) = persisted_fixture("corrupt");
    let path = root.0.join("case-ledger-state.json");
    let mut value: Value = ok(serde_json::from_slice(&ok(std::fs::read(&path))));
    if let Some(records) = value.get_mut("records").and_then(Value::as_array_mut) {
        if let Some(record) = records.last_mut().and_then(Value::as_object_mut) {
            record.insert("record_hash".to_owned(), Value::String(digest('f')));
        }
    }
    assert!(std::fs::write(&path, ok(serde_json::to_vec_pretty(&value))).is_ok());
    assert!(verify_case_ledger(&root.0).is_err());
}

#[test]
fn suspended_role_blocks_fresh_task_and_preserves_case() {
    let (root, fixture) = persisted_fixture("suspended");
    let ledger = ok(d2i_desktop::CaseLedgerV1::open(&root.0));
    let mut coordinator = ok(WorkCaseCoordinatorV1::open(
        ledger,
        fixture.case_contract.clone(),
        fixture.evidence_index.clone(),
        Vec::new(),
        digest('a'),
        digest('b'),
    ));
    let active_owner = ok(fixture.role_instance.bind_ledger_head(digest('a')));
    ok(coordinator.activate(&active_owner, 1_785_000_020));
    let request = case_request(
        &fixture,
        coordinator.instance(),
        &digest('c'),
        &digest('d'),
        &digest('e'),
        &digest('f'),
        1_785_000_021,
    );
    let suspended_owner =
        ok(active_owner.transition(RoleInstanceStatusV1::Suspended, 1_785_000_021));
    assert!(coordinator.begin_task(request, &suspended_owner).is_err());
    assert_eq!(
        coordinator.instance().current_status,
        CaseLifecycleStatusV1::Active
    );
    assert_eq!(ok(verify_case_ledger(&root.0)).record_count, 4);
}

#[test]
fn owner_role_identity_and_ledger_head_are_rechecked_before_activation() {
    let (root, fixture) = persisted_fixture("owner-substitution");
    let ledger = ok(d2i_desktop::CaseLedgerV1::open(&root.0));
    let mut coordinator = ok(WorkCaseCoordinatorV1::open(
        ledger,
        fixture.case_contract.clone(),
        fixture.evidence_index.clone(),
        Vec::new(),
        digest('a'),
        digest('b'),
    ));
    let substituted_owner = ok(fixture.role_instance.bind_ledger_head(digest('c')));
    assert!(coordinator
        .activate(&substituted_owner, 1_785_000_020)
        .is_err());
    assert_eq!(
        coordinator.instance().current_status,
        CaseLifecycleStatusV1::Opened
    );
    assert_eq!(ok(verify_case_ledger(&root.0)).record_count, 3);
}

#[test]
fn clarification_unsafe_and_revoked_paths_do_not_false_close_cases() {
    let (root, fixture) = persisted_fixture("nonterminal-boundaries");
    let ledger = ok(d2i_desktop::CaseLedgerV1::open(&root.0));
    let mut coordinator = ok(WorkCaseCoordinatorV1::open(
        ledger,
        fixture.case_contract.clone(),
        fixture.evidence_index.clone(),
        Vec::new(),
        digest('a'),
        digest('b'),
    ));
    let active_owner = ok(fixture.role_instance.bind_ledger_head(digest('a')));
    ok(coordinator.activate(&active_owner, 1_785_000_020));
    ok(coordinator.transition_boundary(
        CaseLifecycleStatusV1::AwaitingClarification,
        None,
        1_785_000_021,
    ));
    assert_eq!(
        coordinator.instance().current_status,
        CaseLifecycleStatusV1::AwaitingClarification
    );
    assert_eq!(coordinator.instance().terminal_outcome, None);
    ok(coordinator.transition_boundary(CaseLifecycleStatusV1::Active, None, 1_785_000_022));
    let unsafe_evaluation = ok(coordinator.evaluate_current(
        &[],
        &["protected-invariant-violation".to_owned()],
        true,
        1_785_000_023,
    ));
    assert_eq!(
        unsafe_evaluation.outcome,
        CaseClosureEvaluationOutcomeV1::Unsafe
    );
    assert_eq!(unsafe_evaluation.terminal_candidate, None);

    let request = case_request(
        &fixture,
        coordinator.instance(),
        &digest('c'),
        &digest('d'),
        &digest('e'),
        &digest('f'),
        1_785_000_024,
    );
    let revoked_owner = ok(active_owner.transition(RoleInstanceStatusV1::Revoked, 1_785_000_024));
    assert!(coordinator.begin_task(request, &revoked_owner).is_err());
    let revoked_evaluation = ok(coordinator.evaluate_current(&[], &[], false, 1_785_000_025));
    assert_eq!(
        revoked_evaluation.outcome,
        CaseClosureEvaluationOutcomeV1::EscalationRequired
    );
    ok(coordinator.transition_boundary(
        CaseLifecycleStatusV1::EscalationPending,
        None,
        1_785_000_026,
    ));
    assert_eq!(coordinator.instance().terminal_outcome, None);
    assert!(ok(verify_case_ledger(&root.0)).terminal_case_ids.is_empty());
}

#[test]
fn actual_role_bound_kernel_artifacts_close_verified_case_when_supplied() {
    let Some(kernel_root) = std::env::var_os("D2I_WORK_CASE_KERNEL_OUTPUT") else {
        return;
    };
    let kernel_root = PathBuf::from(kernel_root);
    let result: Value = read_json(&kernel_root.join("result.json"));
    let run_record: KernelTaskRunRecordV1 =
        read_json(&kernel_root.join("kernel-task-run-record.json"));
    let report: WorkReport = read_json(&kernel_root.join("work-report.json"));
    let final_goal: FinalGoalVerificationV1 =
        read_json(&kernel_root.join("final-goal-verification.json"));
    let role_context: RoleBoundKernelTaskContextV1 =
        read_json(&kernel_root.join("role-bound-kernel-context.json"));
    let role_instance: d2i_role_contract::RoleInstanceV1 =
        read_json(&kernel_root.join("role-instance.json"));
    let terminal_role_instance: d2i_role_contract::RoleInstanceV1 =
        read_json(&kernel_root.join("role-terminal-instance.json"));
    let role_contract: d2i_role_contract::RoleContractV1 =
        read_json(&kernel_root.join("role-contract.json"));
    let delegation: d2i_role_contract::RoleDelegationGrantV1 =
        read_json(&kernel_root.join("role-delegation.json"));
    assert_eq!(result["actual_outcome"], "completed");
    assert_eq!(result["mutation_count"], 2);
    assert!(result["actual_module_invocations"]
        .as_u64()
        .is_some_and(|count| count >= 3));

    let root = TempRoot::new("actual-kernel");
    let started_seconds = run_record.started_at_unix_ms / 1_000;
    let completed_seconds = run_record.completed_at_unix_ms / 1_000;
    let fixture = work_case_fixture::fixture_with_governance(
        role_contract,
        delegation,
        role_instance.clone(),
        started_seconds.saturating_sub(10),
    );
    let role_head = role_instance.ledger_chain_head.clone();
    assert_eq!(
        result_string(&result, "role_ledger_chain_head"),
        terminal_role_instance.ledger_chain_head
    );
    let audit_head = result_string(&result, "audit_chain_head");
    let opened_ms = fixture
        .case_contract
        .opened_at_unix_seconds
        .saturating_mul(1_000);
    let mut ledger = ok(initialize_case_ledger(
        &root.0,
        "case-ledger-example",
        &fixture.work_item.organization_id,
        1_024,
        opened_ms.saturating_sub(1),
    ));
    ok(persist_new_case(
        &mut ledger,
        &fixture.work_item,
        &fixture.dedup_key,
        &fixture.admission,
        &fixture.case_contract,
        &fixture.case_instance,
        &role_head,
        &audit_head,
        opened_ms,
    ));
    let mut coordinator = ok(WorkCaseCoordinatorV1::open(
        ledger,
        fixture.case_contract.clone(),
        fixture.evidence_index.clone(),
        Vec::new(),
        role_head,
        audit_head,
    ));
    ok(coordinator.activate(&role_instance, started_seconds.saturating_sub(2)));
    let request = case_request(
        &fixture,
        coordinator.instance(),
        &run_record.authenticated_instruction_sha256,
        &run_record.goal_spec_sha256,
        &role_context.role_task_admission_sha256,
        &role_context.context_sha256,
        started_seconds.saturating_sub(1),
    );
    ok(coordinator.begin_task(request.clone(), &role_instance));
    let evidence = vec![
        evidence_ref(
            "actual-kernel-run",
            "kernel-task-run-record",
            "kernel-task-run-record",
            &run_record.run_record_sha256,
            CaseEvidenceProducerKindV1::KernelTaskRun,
            completed_seconds,
        ),
        evidence_ref(
            "actual-final-verification",
            "final-goal-verification",
            "final-goal-verification",
            &final_goal.final_verification_sha256,
            CaseEvidenceProducerKindV1::FinalGoalVerification,
            completed_seconds,
        ),
        evidence_ref(
            "actual-work-report",
            "work-report",
            "work-report",
            &run_record.work_report_sha256,
            CaseEvidenceProducerKindV1::KernelTaskRun,
            completed_seconds,
        ),
    ];
    let attempt = ok(coordinator.bind_kernel_artifacts(
        &request,
        CaseKernelArtifactsV1 {
            run_record,
            work_report: report,
            final_goal_verification: Some(final_goal),
            terminal_role_instance,
            outcome: CaseTaskAttemptOutcomeV1::VerifiedGoalComplete,
            produced_evidence_refs: evidence,
            started_at_unix_seconds: started_seconds,
            completed_at_unix_seconds: completed_seconds,
        },
    ));
    assert_eq!(
        attempt.outcome,
        CaseTaskAttemptOutcomeV1::VerifiedGoalComplete
    );
    ok(coordinator.transition_boundary(
        CaseLifecycleStatusV1::AwaitingVerification,
        None,
        completed_seconds.saturating_add(1),
    ));
    let evaluation =
        ok(coordinator.evaluate_current(&[], &[], true, completed_seconds.saturating_add(2)));
    let terminal = ok(coordinator.close_verified(
        &evaluation,
        completed_seconds.saturating_add(3),
        CaseSlaStatusSnapshotV1::NotEvaluated,
        vec!["actual-terminal-evidence".to_owned()],
    ));
    assert_eq!(
        terminal.terminal_outcome,
        d2i_work_case::CaseTerminalOutcomeV1::VerifiedComplete
    );
    let reopened = ok(verify_case_ledger(&root.0));
    assert!(reopened
        .terminal_case_ids
        .contains(&fixture.case_contract.case_id));
    assert_eq!(
        reopened
            .current_instances
            .get(&fixture.case_contract.case_id)
            .map(|instance| instance.current_status),
        Some(CaseLifecycleStatusV1::Terminal)
    );
}

fn case_request(
    fixture: &work_case_fixture::Fixture,
    instance: &d2i_work_case::CaseInstanceV1,
    instruction_hash: &str,
    goal_hash: &str,
    admission_hash: &str,
    context_hash: &str,
    requested_at: u64,
) -> CaseTaskRequestV1 {
    ok(CaseTaskRequestV1 {
        schema_version: 1,
        case_task_id: "case-task-name-save-1".to_owned(),
        case_id: fixture.case_contract.case_id.clone(),
        case_contract_sha256: fixture.case_contract.contract_sha256.clone(),
        case_instance_sha256: instance.instance_sha256.clone(),
        task_sequence: instance.latest_task_sequence.saturating_add(1),
        role_instance_id: fixture.role_instance.role_instance_id.clone(),
        ownership_sha256: fixture
            .case_contract
            .ownership_binding
            .ownership_sha256
            .clone(),
        work_class_id: fixture.work_item.work_class_id.clone(),
        responsibility_id: fixture.case_contract.responsibility_id.clone(),
        authenticated_instruction_sha256: instruction_hash.to_owned(),
        goal_spec_sha256: goal_hash.to_owned(),
        role_task_admission_sha256: admission_hash.to_owned(),
        role_bound_kernel_context_sha256: context_hash.to_owned(),
        application_pack_sha256: PACK_HASH.to_owned(),
        integration_id: "windows-kernel-e2e".to_owned(),
        required_capability_ids: fixture.case_contract.allowed_capability_ids.clone(),
        addressed_requirement_ids: vec!["goal-complete".to_owned()],
        evidence_requirement_ids: fixture
            .case_contract
            .evidence_requirements
            .iter()
            .map(|item| item.evidence_requirement_id.clone())
            .collect(),
        requested_at_unix_seconds: requested_at,
        expires_at_unix_seconds: requested_at.saturating_add(120),
        evidence_ids: vec!["case-task-request-evidence".to_owned()],
        request_sha256: ZERO_HASH.to_owned(),
    }
    .seal_against(&fixture.case_contract, instance))
}

fn evidence_ref(
    id: &str,
    class: &str,
    artifact_type: &str,
    artifact_hash: &str,
    producer: CaseEvidenceProducerKindV1,
    observed_at: u64,
) -> CaseEvidenceRefV1 {
    ok(CaseEvidenceRefV1 {
        evidence_id: id.to_owned(),
        evidence_class_id: class.to_owned(),
        artifact_type_id: artifact_type.to_owned(),
        artifact_sha256: artifact_hash.to_owned(),
        producer_kind: producer,
        producer_id: "actual-role-bound-kernel-run".to_owned(),
        trust_floor: CaseEvidenceTrustFloorV1::Protected,
        trust_labels: vec!["protected-kernel-evidence".to_owned()],
        observed_at_unix_seconds: observed_at,
        created_at_unix_seconds: observed_at,
        retention_class_id: "test-evidence".to_owned(),
        redacted: true,
        source_case_id: Some("case-kernel-name-save".to_owned()),
        supersedes_evidence_id: None,
        evidence_ref_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    ok(serde_json::from_slice(&ok(std::fs::read(path))))
}

fn result_string(value: &Value, key: &str) -> String {
    match value.get(key).and_then(Value::as_str) {
        Some(value) => value.to_owned(),
        None => panic!("kernel result field absent: {key}"),
    }
}
