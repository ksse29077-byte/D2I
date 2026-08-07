use d2i_desktop::{
    initialize_autonomy_store, recover_autonomy_store, verify_autonomy_store,
    AutonomyStoreArtifactV1, AutonomyStoreV1,
};
use d2i_limited_autonomy::{AutonomyReadinessBindingV1, AutonomyReadinessStatusV1, ZERO_HASH};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn digest(value: char) -> String {
    format!("sha256:{}", value.to_string().repeat(64))
}

fn temp_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "d2i-autonomy-{label}-{}-{nonce}",
        std::process::id()
    ))
}

fn cleanup(path: &Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}

fn readiness(id: &str) -> AutonomyReadinessBindingV1 {
    ok(AutonomyReadinessBindingV1 {
        schema_version: 1,
        binding_id: id.to_owned(),
        organization_id: "example-office-organization".to_owned(),
        target_role_contract_id: "general-office-operations-employee".to_owned(),
        target_role_contract_version: "1.4.0".to_owned(),
        shadow_role_sha256: digest('1'),
        shadow_profile_sha256: digest('2'),
        shadow_cohort_sha256: digest('3'),
        shadow_readiness_policy_sha256: digest('4'),
        shadow_readiness_assessment_sha256: digest('5'),
        readiness_status: AutonomyReadinessStatusV1::EligibleForWork900Design,
        model_sha256: digest('6'),
        runtime_sha256: digest('7'),
        provider_descriptor_sha256: digest('8'),
        prompt_template_hashes: vec![digest('9')],
        application_pack_hashes: vec![digest('a')],
        policy_set_sha256: digest('b'),
        trusted_execution_compatibility_sha256: digest('c'),
        evidence_coverage_sha256: digest('d'),
        critical_error_count: 0,
        false_completion_count: 0,
        escalation_miss_count: 0,
        forbidden_capability_count: 0,
        authority_expansion_count: 0,
        assessed_at_unix_ms: 1_000,
        valid_until_unix_ms: 20_000,
        evidence_ids: vec!["work800-readiness".to_owned()],
        binding_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

#[test]
fn protected_store_is_content_addressed_hash_chained_and_recoverable() {
    let root = temp_root("store");
    let mut store = ok(initialize_autonomy_store(
        &root,
        "example-office-organization".to_owned(),
        digest('e'),
        digest('f'),
        8 * 1024 * 1024,
        1_000,
    ));
    let artifact = readiness("readiness-1");
    let stored = ok(store.store(AutonomyStoreArtifactV1::Readiness(artifact.clone()), 2_000));
    assert_eq!(stored, artifact.binding_sha256);
    assert_eq!(store.verification().ledger_record_count, 1);
    assert_eq!(store.verification().orphan_object_count, 0);

    let duplicate = ok(store.store(AutonomyStoreArtifactV1::Readiness(artifact), 2_001));
    assert_eq!(duplicate, stored);
    assert_eq!(store.verification().ledger_record_count, 1);

    let terminal = store.verification().ledger_terminal_sha256.clone();
    drop(store);
    let reopened = ok(AutonomyStoreV1::open(&root, Some(&terminal)));
    assert!(!reopened.verification().residual_lock_present);
    assert!(AutonomyStoreV1::open(&root, Some(&digest('0'))).is_err());
    cleanup(&root);
}

#[test]
fn stale_index_repairs_but_object_tamper_fails_closed() {
    let root = temp_root("recovery");
    let mut store = ok(initialize_autonomy_store(
        &root,
        "example-office-organization".to_owned(),
        digest('e'),
        digest('f'),
        8 * 1024 * 1024,
        1_000,
    ));
    let artifact = readiness("readiness-1");
    ok(store.store(AutonomyStoreArtifactV1::Readiness(artifact.clone()), 2_000));
    let terminal = store.verification().ledger_terminal_sha256.clone();
    drop(store);

    fs::write(root.join("index.json"), b"{}\n").unwrap_or_else(|error| panic!("write: {error}"));
    let repaired = ok(AutonomyStoreV1::open(&root, Some(&terminal)));
    assert!(repaired.verification().index_repaired);
    drop(repaired);

    let hex = artifact.binding_sha256.trim_start_matches("sha256:");
    let object = root.join("objects").join(format!("{hex}.json"));
    let mut bytes = ok(fs::read(&object));
    bytes[0] ^= 1;
    ok(fs::write(&object, bytes));
    assert!(verify_autonomy_store(&root, Some(&terminal)).is_err());
    cleanup(&root);
}

#[test]
fn recovery_removes_only_unreferenced_objects_and_leaves_no_lock() {
    let root = temp_root("orphan");
    let store = ok(initialize_autonomy_store(
        &root,
        "example-office-organization".to_owned(),
        digest('e'),
        digest('f'),
        8 * 1024 * 1024,
        1_000,
    ));
    drop(store);
    let orphan = root
        .join("objects")
        .join(format!("{}.json", "a".repeat(64)));
    ok(fs::write(&orphan, b"{}\n"));
    let _ = d2i_windows_host::harden_path_for_current_user(&orphan)
        .unwrap_or_else(|error| panic!("harden orphan: {error}"));
    let before = ok(verify_autonomy_store(&root, None));
    assert_eq!(before.orphan_object_count, 1);
    let recovered = ok(recover_autonomy_store(&root));
    assert_eq!(recovered.orphan_object_count, 0);
    assert!(!recovered.residual_lock_present);
    assert!(!orphan.exists());
    cleanup(&root);
}
