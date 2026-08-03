#[path = "support/work_radar_intake_fixture.rs"]
mod work_radar_intake_fixture;

use d2i_desktop::{
    initialize_case_ledger, initialize_work_intake_ledger, persist_new_case, verify_case_ledger,
    verify_role_instance_ledger, verify_work_intake_ledger, CaseLedgerV1, WorkCaseCoordinatorV1,
    WorkIntakeLedgerV1,
};
use d2i_work_case::{WorkItemDeduplicationResultV1, WorkItemV1};
use d2i_work_intake::{
    canonical_sha256, FixtureRadarSourceV1, RadarCheckpointV1, RadarCycleReportV1,
    RadarScanRequestV1, RadarSourceAdapterV1, RadarSourceApprovalVerificationV1,
    WorkIntakeDispositionV1, WorkIntakeReceiptV1, WorkSourceApprovalV1, ZERO_HASH,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use work_radar_intake_fixture::{
    activate_governance, digest, evaluate, mapping, new_case, ok, registration, signal,
    source_approval, NOW,
};

struct TempTree(PathBuf);

impl TempTree {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(1, |duration| duration.as_nanos());
        let root = std::env::temp_dir().join(format!(
            "d2i-work-intake-{label}-{}-{nonce}",
            std::process::id()
        ));
        ok(std::fs::create_dir_all(&root));
        Self(root)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[allow(clippy::too_many_arguments)]
fn initialize_intake(
    root: &Path,
    role_instance_id: &str,
    organization_id: &str,
    registration_id: &str,
    registration_sha256: &str,
    source_approval_sha256: &str,
    checkpoint: RadarCheckpointV1,
    role_head: &str,
    case_head: &str,
) -> WorkIntakeLedgerV1 {
    let mut ledger = ok(initialize_work_intake_ledger(
        root,
        "work-intake-ledger-general-office",
        organization_id,
        role_instance_id,
        registration_id,
        registration_sha256,
        source_approval_sha256,
        4096,
        (NOW - 100) * 1000,
    ));
    ok(ledger.initialize_checkpoint(
        checkpoint,
        role_head.to_owned(),
        case_head.to_owned(),
        (NOW - 20) * 1000,
    ));
    ledger
}

#[allow(clippy::too_many_arguments)]
fn receipt(
    signal: &d2i_work_intake::WorkSignalV1,
    source_approval: &WorkSourceApprovalV1,
    evaluation: &d2i_work_intake::WorkIntakeEvaluationV1,
    checkpoint_before: &RadarCheckpointV1,
    checkpoint_after: &RadarCheckpointV1,
    disposition: WorkIntakeDispositionV1,
    duplicate: WorkItemDeduplicationResultV1,
    case_id: &str,
    case_contract_sha256: &str,
    case_instance_sha256: &str,
    case_head: &str,
    role_head: &str,
    intake_head: &str,
) -> WorkIntakeReceiptV1 {
    ok(WorkIntakeReceiptV1 {
        schema_version: 1,
        receipt_id: format!("receipt:{}", signal.signal_id),
        cycle_id: format!("cycle:{}", signal.source_sequence),
        cycle_sequence: checkpoint_after.cycle_sequence,
        signal_id: signal.signal_id.clone(),
        signal_sha256: signal.signal_sha256.clone(),
        source_approval_sha256: source_approval.source_approval_sha256.clone(),
        source_envelope_sha256: evaluation
            .source_envelope
            .as_ref()
            .map(|value| value.envelope_sha256.clone()),
        work_item_sha256: evaluation
            .work_item
            .as_ref()
            .map(|value| value.work_item_sha256.clone()),
        admission_sha256: evaluation
            .admission
            .as_ref()
            .map(|value| value.decision_sha256.clone()),
        case_id: Some(case_id.to_owned()),
        case_contract_sha256: Some(case_contract_sha256.to_owned()),
        case_instance_sha256: Some(case_instance_sha256.to_owned()),
        duplicate_result: Some(duplicate),
        disposition,
        reason_codes: if evaluation.reason_codes.is_empty() {
            vec!["intake-admitted".to_owned()]
        } else {
            evaluation.reason_codes.clone()
        },
        checkpoint_before_sha256: checkpoint_before.checkpoint_sha256.clone(),
        checkpoint_after_sha256: checkpoint_after.checkpoint_sha256.clone(),
        case_ledger_chain_head: case_head.to_owned(),
        role_ledger_chain_head: role_head.to_owned(),
        intake_ledger_chain_head: intake_head.to_owned(),
        evidence_ids: vec!["protected-intake-receipt".to_owned()],
        decided_at_unix_seconds: NOW + 2,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn general_office_signal_creates_exactly_one_persistent_case_and_commits_checkpoint() {
    let root = TempTree::new("general-office-e2e");
    let role_root = root.0.join("role");
    let case_root = root.0.join("case");
    let intake_root = root.0.join("intake");
    let governance = activate_governance(&role_root);
    let registration = registration(&governance);
    let source_approval = source_approval(&governance, &registration);
    let mapping = mapping(&governance, &registration);
    let fixture_signal = signal(&registration, "internal-record-event-1", 1, 'f');
    let initial = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["initial-source-checkpoint".to_owned()],
    ));
    let request = ok(RadarScanRequestV1::create(
        "cycle-general-office-1".to_owned(),
        1,
        &registration,
        &source_approval,
        &initial,
        NOW - 1,
        NOW + 10,
    ));
    let mut adapter = ok(FixtureRadarSourceV1::new(vec![fixture_signal], 1024, NOW));
    let batch = ok(adapter.scan_once(
        &registration,
        RadarSourceApprovalVerificationV1 {
            source_approval: &source_approval,
            expected_signer_key_id: "office-source-approval-key-v1",
            verifying_key: &governance.source_approval_key.verifying_key(),
            now_unix_seconds: NOW,
        },
        &initial,
        &request,
    ));
    let signal = batch
        .signals
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("General Office Radar emitted no signal"));
    let mut case_ledger = ok(initialize_case_ledger(
        &case_root,
        "case-ledger-general-office",
        &registration.organization_id,
        4096,
        (NOW - 100) * 1000,
    ));
    let initial_case_head = case_ledger.verification().terminal_record_hash.clone();
    let evaluation = evaluate(
        &governance,
        &registration,
        &source_approval,
        &mapping,
        &initial,
        &signal,
        case_ledger.verification().deduplication_entries.as_slice(),
    );
    assert!(evaluation.requires_case_creation());
    let case = new_case(&governance, &evaluation, "case-ledger-general-office");
    ok(persist_new_case(
        &mut case_ledger,
        evaluation
            .work_item
            .as_ref()
            .unwrap_or_else(|| panic!("Work Item absent")),
        evaluation
            .deduplication_key
            .as_ref()
            .unwrap_or_else(|| panic!("dedup key absent")),
        evaluation
            .admission
            .as_ref()
            .unwrap_or_else(|| panic!("admission absent")),
        &case.contract,
        &case.instance,
        &governance.role_ledger_head,
        &digest('8'),
        (NOW + 1) * 1000,
    ));
    assert_eq!(case_ledger.verification().current_instances.len(), 1);
    let coordinator = ok(WorkCaseCoordinatorV1::open(
        case_ledger,
        case.contract.clone(),
        case.evidence_index.clone(),
        Vec::new(),
        governance.role_ledger_head.clone(),
        digest('8'),
    ));
    assert_eq!(coordinator.instance().task_attempt_count, 0);
    drop(coordinator);
    let case_ledger = ok(CaseLedgerV1::open(&case_root));

    let mut intake = initialize_intake(
        &intake_root,
        &governance.instance.role_instance_id,
        &registration.organization_id,
        &registration.registration_id,
        &registration.registration_sha256,
        &source_approval.source_approval_sha256,
        initial.clone(),
        &governance.role_ledger_head,
        &initial_case_head,
    );
    let intake_head = intake.verification().terminal_record_hash.clone();
    let advanced = ok(initial.advance(
        &registration,
        &signal,
        1,
        intake_head.clone(),
        vec!["source-checkpoint-advanced".to_owned()],
    ));
    let receipt = receipt(
        &signal,
        &source_approval,
        &evaluation,
        &initial,
        &advanced,
        WorkIntakeDispositionV1::AdmittedCaseCreated,
        WorkItemDeduplicationResultV1::New,
        &case.contract.case_id,
        &case.contract.contract_sha256,
        &case.instance.instance_sha256,
        &case_ledger.verification().terminal_record_hash,
        &governance.role_ledger_head,
        &intake_head,
    );
    ok(intake.append_receipt(
        signal.signal_id.clone(),
        signal.event_id.clone(),
        receipt.clone(),
        (NOW + 2) * 1000,
    ));
    ok(intake.advance_checkpoint(advanced.clone(), false, (NOW + 3) * 1000));
    let report = ok(RadarCycleReportV1 {
        schema_version: 1,
        cycle_id: "cycle:1".to_owned(),
        cycle_sequence: 1,
        role_instance_id: governance.instance.role_instance_id.clone(),
        role_instance_sha256: governance.instance.instance_sha256.clone(),
        registration_id: registration.registration_id.clone(),
        registration_sha256: registration.registration_sha256.clone(),
        source_approval_sha256: source_approval.source_approval_sha256.clone(),
        checkpoint_before_sha256: initial.checkpoint_sha256.clone(),
        checkpoint_after_sha256: advanced.checkpoint_sha256.clone(),
        observed_signals: 1,
        accepted_signals: 1,
        cases_created: 1,
        duplicate_open: 0,
        duplicate_terminal: 0,
        denied: 0,
        clarification_required: 0,
        escalation_required: 0,
        quarantined: 0,
        logical_operations: 20,
        ticks_consumed: 1,
        retries: 0,
        receipt_hashes: vec![receipt.receipt_sha256.clone()],
        cycle_sha256: ZERO_HASH.to_owned(),
    }
    .seal());
    ok(intake.append_cycle_report(report.clone(), (NOW + 4) * 1000));
    drop(intake);

    let verified_intake = ok(verify_work_intake_ledger(&intake_root));
    let verified_case = ok(verify_case_ledger(&case_root));
    let verified_role = ok(verify_role_instance_ledger(&role_root));
    assert_eq!(verified_intake.current_checkpoint, Some(advanced));
    assert_eq!(
        verified_intake.consumed_receipt_hashes,
        vec![receipt.receipt_sha256]
    );
    assert_eq!(
        verified_intake.cycle_report_hashes,
        vec![report.cycle_sha256]
    );
    assert_eq!(verified_case.current_instances.len(), 1);
    assert_eq!(verified_case.consumed_task_attempt_hashes.len(), 0);
    assert_eq!(
        verified_role.terminal_record_hash,
        governance.role_ledger_head
    );
}

#[test]
fn crash_after_case_before_receipt_recovers_as_duplicate_without_second_case() {
    let root = TempTree::new("crash-recovery");
    let role_root = root.0.join("role");
    let case_root = root.0.join("case");
    let intake_root = root.0.join("intake");
    let governance = activate_governance(&role_root);
    let registration = registration(&governance);
    let source_approval = source_approval(&governance, &registration);
    let mapping = mapping(&governance, &registration);
    let signal = signal(&registration, "internal-record-event-crash", 1, '6');
    let initial = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["crash-initial-checkpoint".to_owned()],
    ));
    let mut case_ledger = ok(initialize_case_ledger(
        &case_root,
        "case-ledger-general-office",
        &registration.organization_id,
        4096,
        (NOW - 100) * 1000,
    ));
    let initial_case_head = case_ledger.verification().terminal_record_hash.clone();
    let intake = initialize_intake(
        &intake_root,
        &governance.instance.role_instance_id,
        &registration.organization_id,
        &registration.registration_id,
        &registration.registration_sha256,
        &source_approval.source_approval_sha256,
        initial.clone(),
        &governance.role_ledger_head,
        &initial_case_head,
    );
    let evaluation = evaluate(
        &governance,
        &registration,
        &source_approval,
        &mapping,
        &initial,
        &signal,
        &[],
    );
    let case = new_case(&governance, &evaluation, "case-ledger-general-office");
    ok(persist_new_case(
        &mut case_ledger,
        evaluation
            .work_item
            .as_ref()
            .unwrap_or_else(|| panic!("Work Item absent")),
        evaluation
            .deduplication_key
            .as_ref()
            .unwrap_or_else(|| panic!("key absent")),
        evaluation
            .admission
            .as_ref()
            .unwrap_or_else(|| panic!("admission absent")),
        &case.contract,
        &case.instance,
        &governance.role_ledger_head,
        &digest('8'),
        (NOW + 1) * 1000,
    ));
    drop(case_ledger);
    drop(intake);

    let case_ledger = ok(CaseLedgerV1::open(&case_root));
    let duplicate = evaluate(
        &governance,
        &registration,
        &source_approval,
        &mapping,
        &initial,
        &signal,
        case_ledger.verification().deduplication_entries.as_slice(),
    );
    assert_eq!(
        duplicate.disposition,
        Some(WorkIntakeDispositionV1::DuplicateOpen)
    );
    assert!(!duplicate.requires_case_creation());
    for _ in 0..100 {
        let replay = evaluate(
            &governance,
            &registration,
            &source_approval,
            &mapping,
            &initial,
            &signal,
            case_ledger.verification().deduplication_entries.as_slice(),
        );
        assert_eq!(
            ok(canonical_sha256(&replay.work_item)),
            ok(canonical_sha256(&duplicate.work_item))
        );
        assert_eq!(
            replay.disposition,
            Some(WorkIntakeDispositionV1::DuplicateOpen)
        );
    }
    assert_eq!(case_ledger.verification().current_instances.len(), 1);

    let mut intake = ok(WorkIntakeLedgerV1::open(&intake_root));
    let intake_head = intake.verification().terminal_record_hash.clone();
    let advanced = ok(initial.advance(
        &registration,
        &signal,
        1,
        intake_head.clone(),
        vec!["recovered-checkpoint".to_owned()],
    ));
    let receipt = receipt(
        &signal,
        &source_approval,
        &duplicate,
        &initial,
        &advanced,
        WorkIntakeDispositionV1::DuplicateOpen,
        WorkItemDeduplicationResultV1::DuplicateOpen,
        &case.contract.case_id,
        &case.contract.contract_sha256,
        &case.instance.instance_sha256,
        &case_ledger.verification().terminal_record_hash,
        &governance.role_ledger_head,
        &intake_head,
    );
    ok(intake.append_receipt(
        signal.signal_id.clone(),
        signal.event_id.clone(),
        receipt.clone(),
        (NOW + 2) * 1000,
    ));
    ok(intake.advance_checkpoint(advanced, true, (NOW + 3) * 1000));
    assert!(intake
        .append_receipt(
            signal.signal_id.clone(),
            signal.event_id.clone(),
            receipt,
            (NOW + 4) * 1000,
        )
        .is_err());
    assert_eq!(
        ok(verify_case_ledger(&case_root)).current_instances.len(),
        1
    );
}

#[test]
fn ledger_rejects_tamper_duplicate_keys_concurrent_writer_and_event_substitution() {
    let root = TempTree::new("negative");
    let role_root = root.0.join("role");
    let intake_root = root.0.join("intake");
    let governance = activate_governance(&role_root);
    let registration = registration(&governance);
    let source_approval = source_approval(&governance, &registration);
    let initial = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["negative-checkpoint".to_owned()],
    ));
    let ledger = initialize_intake(
        &intake_root,
        &governance.instance.role_instance_id,
        &registration.organization_id,
        &registration.registration_id,
        &registration.registration_sha256,
        &source_approval.source_approval_sha256,
        initial,
        &governance.role_ledger_head,
        ZERO_HASH,
    );
    let stale = ok(WorkIntakeLedgerV1::open(&intake_root));
    drop(ledger);
    drop(stale);

    let state = intake_root.join("work-intake-ledger-state.json");
    let bytes = ok(std::fs::read(&state));
    let mut value: Value = ok(serde_json::from_slice(&bytes));
    value["records"][0]["record_hash"] = Value::String(digest('4'));
    ok(std::fs::write(
        &state,
        ok(serde_json::to_vec_pretty(&value)),
    ));
    assert!(verify_work_intake_ledger(&intake_root).is_err());

    let duplicate_root = TempTree::new("duplicate-key");
    let duplicate_intake = duplicate_root.0.join("intake");
    let ledger = initialize_intake(
        &duplicate_intake,
        &governance.instance.role_instance_id,
        &registration.organization_id,
        &registration.registration_id,
        &registration.registration_sha256,
        &source_approval.source_approval_sha256,
        ok(RadarCheckpointV1::initial(
            &registration,
            ZERO_HASH.to_owned(),
            vec!["duplicate-checkpoint".to_owned()],
        )),
        &governance.role_ledger_head,
        ZERO_HASH,
    );
    drop(ledger);
    let state = duplicate_intake.join("work-intake-ledger-state.json");
    let text = ok(std::fs::read_to_string(&state));
    let duplicate = text.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"schema_version\": 1,",
        1,
    );
    ok(std::fs::write(&state, duplicate));
    assert!(verify_work_intake_ledger(&duplicate_intake).is_err());

    let writer_root = TempTree::new("stale-writer");
    let writer_intake = writer_root.0.join("intake");
    let initial = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["writer-checkpoint".to_owned()],
    ));
    let mut writer = initialize_intake(
        &writer_intake,
        &governance.instance.role_instance_id,
        &registration.organization_id,
        &registration.registration_id,
        &registration.registration_sha256,
        &source_approval.source_approval_sha256,
        initial.clone(),
        &governance.role_ledger_head,
        ZERO_HASH,
    );
    let mut stale_writer = ok(WorkIntakeLedgerV1::open(&writer_intake));
    let mapping = mapping(&governance, &registration);
    let first_signal = signal(&registration, "internal-record-event-conflict", 1, '6');
    let first_evaluation = evaluate(
        &governance,
        &registration,
        &source_approval,
        &mapping,
        &initial,
        &first_signal,
        &[],
    );
    let first_head = writer.verification().terminal_record_hash.clone();
    let first_advanced = ok(initial.advance(
        &registration,
        &first_signal,
        1,
        first_head.clone(),
        vec!["writer-checkpoint-advanced".to_owned()],
    ));
    let first_receipt = receipt(
        &first_signal,
        &source_approval,
        &first_evaluation,
        &initial,
        &first_advanced,
        WorkIntakeDispositionV1::AdmittedCaseCreated,
        WorkItemDeduplicationResultV1::New,
        "case-office-negative",
        &digest('7'),
        &digest('8'),
        &digest('9'),
        &governance.role_ledger_head,
        &first_head,
    );
    ok(writer.append_receipt(
        first_signal.signal_id.clone(),
        first_signal.event_id.clone(),
        first_receipt.clone(),
        (NOW + 2) * 1000,
    ));
    assert!(stale_writer
        .append_receipt(
            first_signal.signal_id.clone(),
            first_signal.event_id.clone(),
            first_receipt,
            (NOW + 2) * 1000,
        )
        .is_err());
    ok(writer.advance_checkpoint(first_advanced.clone(), false, (NOW + 3) * 1000));

    let substituted = signal(&registration, "internal-record-event-conflict", 2, '7');
    let second_head = writer.verification().terminal_record_hash.clone();
    assert!(first_advanced
        .advance(
            &registration,
            &substituted,
            2,
            second_head,
            vec!["substituted-checkpoint".to_owned()],
        )
        .is_err());
}

#[test]
fn no_task_activation_credential_or_process_authority_is_created() {
    let root = TempTree::new("authority-zero");
    let governance = activate_governance(&root.0.join("role"));
    let registration = registration(&governance);
    let source_approval = source_approval(&governance, &registration);
    let mapping = mapping(&governance, &registration);
    let signal = signal(&registration, "internal-record-event-authority", 1, '5');
    let checkpoint = ok(RadarCheckpointV1::initial(
        &registration,
        ZERO_HASH.to_owned(),
        vec!["authority-checkpoint".to_owned()],
    ));
    let evaluation = evaluate(
        &governance,
        &registration,
        &source_approval,
        &mapping,
        &checkpoint,
        &signal,
        &[],
    );
    let serialized = String::from_utf8(ok(d2i_work_intake::canonical_json_bytes(
        evaluation
            .work_item
            .as_ref()
            .unwrap_or_else(|| panic!("Work Item absent")),
    )))
    .unwrap_or_else(|error| panic!("UTF-8 failed: {error}"));
    for forbidden in [
        "credential",
        "activation",
        "process_command",
        "raw_payload",
        "locator",
        "task_request",
    ] {
        assert!(!serialized.to_ascii_lowercase().contains(forbidden));
    }
    assert_eq!(
        evaluation.work_item.as_ref().map(WorkItemV1::validate),
        Some(Ok(()))
    );
}
