#![cfg(windows)]

use d2i_desktop::{
    initialize_role_operations_store, verify_role_operations_store, RoleOperationsArtifactV1,
    RoleOperationsStoreV1,
};
use d2i_role_operations::{
    canonical_json_bytes, EscalationItemStatusV1, EscalationKindV1, ReportPublicationEnvelopeV1,
    ReportPublicationReceiptV1, ReportPublicationStatusV1, RoleEscalationItemV1,
    RoleEscalationSeverityV1, SlaBreachRecordV1, SlaMilestoneV1, ZERO_HASH,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn temporary_store(label: &str) -> PathBuf {
    let nonce = ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_nanos();
    std::env::temp_dir().join(format!(
        "d2i-work700-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn breach(case_id: &str, suffix: char) -> SlaBreachRecordV1 {
    ok(SlaBreachRecordV1 {
        schema_version: 1,
        breach_id: format!("sla-breach-{case_id}-resolved"),
        case_id: case_id.to_owned(),
        sla_state_sha256: digest(suffix),
        sla_binding_sha256: digest('b'),
        milestone: SlaMilestoneV1::Resolved,
        baseline_deadline_unix_seconds: 1_000,
        effective_deadline_unix_seconds: 1_100,
        detected_at_unix_seconds: 1_200,
        actual_milestone_at_unix_seconds: None,
        breach_duration_seconds: 100,
        severity: RoleEscalationSeverityV1::High,
        reason_codes: vec!["sla_resolved_deadline_exceeded".to_owned()],
        mandatory_escalation: true,
        source_ledger_heads: vec![digest('1'), digest('2'), digest('3')],
        evidence_ids: vec!["authoritative-sla-runtime-state".to_owned()],
        breach_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn initialize(root: &Path) -> RoleOperationsStoreV1 {
    ok(initialize_role_operations_store(
        root,
        "example-office-organization".to_owned(),
        digest('a'),
        digest('c'),
        16 * 1024 * 1024,
        100,
    ))
}

fn publication(id: usize) -> ReportPublicationEnvelopeV1 {
    ok(ReportPublicationEnvelopeV1 {
        schema_version: 1,
        publication_id: format!("publication-{id}"),
        report_sha256: digest('4'),
        reporting_obligation_id: "report-office-work".to_owned(),
        report_class_id: "office-work-result".to_owned(),
        routing_class_id: "office-supervision".to_owned(),
        internal_inbox_id: "protected-inbox-office-supervision".to_owned(),
        registry_sha256: digest('5'),
        published_at_unix_seconds: 200,
        retention_class_id: "office-audit".to_owned(),
        evidence_ids: vec![digest('4')],
        publication_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn publication_receipt(id: usize) -> ReportPublicationReceiptV1 {
    ok(ReportPublicationReceiptV1 {
        schema_version: 1,
        publication_sha256: digest(if id % 2 == 0 { '6' } else { '7' }),
        internal_inbox_ledger_head_sha256: digest('8'),
        durable_object_sha256: digest('9'),
        publication_sequence: id as u64 + 1,
        status: ReportPublicationStatusV1::PublishedToInternalRoute,
        recorded_at_unix_seconds: 201 + id as u64,
        receipt_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn escalation(id: usize) -> RoleEscalationItemV1 {
    ok(RoleEscalationItemV1 {
        schema_version: 1,
        escalation_item_id: format!("escalation-item-{id}"),
        organization_id: "example-office-organization".to_owned(),
        role_contract_sha256: digest('a'),
        case_id: Some(format!("case-{id}")),
        escalation_kind: EscalationKindV1::OperationalAttention,
        source_trigger_sha256: digest(if id % 2 == 0 { 'c' } else { 'd' }),
        reason_codes: vec!["sla_resolved_deadline_exceeded".to_owned()],
        severity: RoleEscalationSeverityV1::Elevated,
        routing_class_id: Some("office-supervision".to_owned()),
        internal_inbox_id: Some("protected-inbox-office-supervision".to_owned()),
        created_at_unix_seconds: 200,
        acknowledge_due_at_unix_seconds: 300,
        resolution_due_at_unix_seconds: 400,
        status: EscalationItemStatusV1::Routed,
        source_case_ledger_head_sha256: digest('1'),
        source_role_ledger_head_sha256: digest('2'),
        source_queue_ledger_head_sha256: digest('3'),
        evidence_ids: vec!["authoritative-escalation-trigger".to_owned()],
        previous_escalation_sha256: None,
        item_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn artifact_for_window(index: usize) -> RoleOperationsArtifactV1 {
    match index % 4 {
        0 => RoleOperationsArtifactV1::SlaBreach(breach(&format!("case-{index}"), 'd')),
        1 => RoleOperationsArtifactV1::Publication(publication(index)),
        2 => RoleOperationsArtifactV1::PublicationReceipt(publication_receipt(index)),
        _ => RoleOperationsArtifactV1::Escalation(escalation(index)),
    }
}

fn artifact_hash(artifact: &RoleOperationsArtifactV1) -> String {
    match artifact {
        RoleOperationsArtifactV1::SlaBreach(value) => value.breach_sha256.clone(),
        RoleOperationsArtifactV1::Publication(value) => value.publication_sha256.clone(),
        RoleOperationsArtifactV1::PublicationReceipt(value) => value.receipt_sha256.clone(),
        RoleOperationsArtifactV1::Escalation(value) => value.item_sha256.clone(),
        _ => panic!("unexpected crash fixture artifact"),
    }
}

fn pretty_artifact(artifact: &RoleOperationsArtifactV1) -> Vec<u8> {
    let canonical = ok(canonical_json_bytes(artifact));
    let value: serde_json::Value = ok(serde_json::from_slice(&canonical));
    ok(serde_json::to_vec_pretty(&value))
}

#[test]
fn protected_store_is_exactly_once_and_repairs_only_the_derived_index() {
    let root = temporary_store("repair");
    let mut store = initialize(&root);
    let artifact = breach("case-c", 'd');
    let hash = ok(store.store(RoleOperationsArtifactV1::SlaBreach(artifact.clone()), 200));
    assert_eq!(hash, artifact.breach_sha256);
    let terminal = store.verification().ledger_terminal_sha256.clone();
    let records = store.verification().ledger_record_count;
    assert_eq!(
        ok(store.store(RoleOperationsArtifactV1::SlaBreach(artifact), 201)),
        hash
    );
    assert_eq!(store.verification().ledger_record_count, records);
    assert!(!store.verification().residual_lock_present);
    assert!(!root.join("coordinator.lock").exists());

    let index_path = root.join("index.json");
    let mut index_file = ok(OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&index_path));
    ok(index_file.write_all(b"{}"));
    ok(index_file.sync_all());
    drop(index_file);
    let repaired = ok(RoleOperationsStoreV1::open(&root, Some(&terminal)));
    assert!(repaired.verification().index_repaired);
    assert!(!repaired.verification().stale_index);
    assert_eq!(repaired.verification().ledger_record_count, records);
    assert!(!root.join("coordinator.lock").exists());

    assert!(RoleOperationsStoreV1::open(&root, Some(&digest('f'))).is_err());
    ok(std::fs::remove_dir_all(&root));
}

#[test]
fn store_rejects_concurrent_writer_conflict_and_object_tamper() {
    let root = temporary_store("tamper");
    let mut store = initialize(&root);
    let artifact = breach("case-c", 'd');
    let hash = ok(store.store(RoleOperationsArtifactV1::SlaBreach(artifact.clone()), 200));

    let lock_path = root.join("coordinator.lock");
    ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path));
    assert!(store
        .store(RoleOperationsArtifactV1::SlaBreach(artifact), 201)
        .is_err());
    ok(std::fs::remove_file(&lock_path));

    let object = root.join("objects").join(format!(
        "{}.json",
        hash.strip_prefix("sha256:").unwrap_or_default()
    ));
    let mut file = ok(OpenOptions::new().write(true).truncate(true).open(&object));
    ok(file.write_all(b"{\"tampered\":true}"));
    ok(file.sync_all());
    drop(file);
    assert!(verify_role_operations_store(&root, None).is_err());
    ok(std::fs::remove_dir_all(&root));
}

#[test]
fn crash_windows_a_through_h_recover_without_duplicate_artifacts() {
    for window in 0..8 {
        let root = temporary_store(&format!("crash-{window}"));
        let mut store = initialize(&root);
        let artifact = artifact_for_window(window);
        let hash = artifact_hash(&artifact);
        if window % 2 == 0 {
            // A/C/E/G: immutable object is durable before its ledger record.
            let object = root.join("objects").join(format!(
                "{}.json",
                hash.strip_prefix("sha256:").unwrap_or_default()
            ));
            ok(std::fs::write(&object, pretty_artifact(&artifact)));
            store = ok(RoleOperationsStoreV1::open(&root, None));
            assert_eq!(store.verification().orphan_object_count, 1);
            ok(store.store(artifact.clone(), 200));
        } else {
            // B/D/F/H: ledger/object are durable while the derived index is stale.
            ok(store.store(artifact.clone(), 200));
            let index = root.join("index.json");
            let mut file = ok(OpenOptions::new().write(true).truncate(true).open(&index));
            ok(file.write_all(b"{}"));
            ok(file.sync_all());
            drop(file);
            store = ok(RoleOperationsStoreV1::open(&root, None));
            assert!(store.verification().index_repaired);
        }
        let records = store.verification().ledger_record_count;
        assert_eq!(records, 1);
        assert_eq!(ok(store.store(artifact, 201)), hash);
        assert_eq!(store.verification().ledger_record_count, records);
        assert!(!root.join("coordinator.lock").exists());
        ok(std::fs::remove_dir_all(&root));
    }
}
