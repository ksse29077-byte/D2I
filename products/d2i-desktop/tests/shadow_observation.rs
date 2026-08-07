#![cfg(windows)]

use d2i_desktop::collect_shadow_fixture_observation;
use d2i_shadow_mode::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
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

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[49_u8; 32])
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
        vec!["shadow-reference-winforms".to_owned()],
    ));
    ok(ShadowModeProfileV1 {
        schema_version: 1,
        profile_id: "office-shadow-observation-profile".to_owned(),
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
        allowed_observation_source_ids: vec!["shadow-reference-winforms".to_owned()],
        allowed_semantic_target_ids: vec!["employee_name_input".to_owned()],
        allowed_capability_ids: vec!["uia.set_value".to_owned()],
        provider_descriptor_sha256: digest('e'),
        model_sha256: digest('f'),
        runtime_sha256: digest('1'),
        prompt_template_hashes: vec![digest('2')],
        allowed_reference_operator_class_ids: vec!["approved-office-operator".to_owned()],
        allowed_recorder_modes: vec![ShadowRecorderModeV1::InstrumentedReferenceOperator],
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
        evidence_ids: vec!["approved-shadow-observation-profile".to_owned()],
        profile_sha256: ZERO_HASH.to_owned(),
    }
    .seal())
}

fn grant(profile: &ShadowModeProfileV1, now: u64) -> ShadowObservationGrantV1 {
    ok(ShadowObservationGrantV1 {
        schema_version: 1,
        grant_id: "grant-shadow-observation-test".to_owned(),
        organization_id: profile.organization_id.clone(),
        role_contract_sha256: profile.role_contract_sha256.clone(),
        case_id: "case-shadow-observation-test".to_owned(),
        case_sha256: digest('3'),
        enrollment_sha256: digest('4'),
        allowed_observation_source_ids: profile.allowed_observation_source_ids.clone(),
        application_pack_hashes: profile.allowed_application_pack_hashes.clone(),
        allowed_semantic_target_ids: profile.allowed_semantic_target_ids.clone(),
        maximum_snapshots: 4,
        maximum_bytes: 524_288,
        valid_from_unix_ms: now.saturating_sub(1_000),
        valid_to_unix_ms: now.saturating_add(60_000),
        execution_forbidden: true,
        activation_forbidden: true,
        adapter_mutation_forbidden: true,
        evidence_ids: vec!["signed-read-only-observation".to_owned()],
        grant_sha256: ZERO_HASH.to_owned(),
        signature_hex: String::new(),
    }
    .seal_and_sign(&key()))
}

struct FixtureGuard {
    child: Child,
    root: PathBuf,
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn signed_grant_collects_fresh_hash_only_uia_before_and_after_reference_action() {
    let root = std::env::temp_dir().join(format!(
        "d2i-shadow-observation-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    ok(std::fs::create_dir(&root));
    let state = root.join("state.json");
    let events = root.join("events.jsonl");
    let ready = root.join("ready");
    let command = root.join("command.json");
    let arm = root.join("arm.json");
    let arm_token = digest('9');
    let title = format!("D2I Shadow Observation {}", std::process::id());
    let powershell = powershell_path();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support/shadow_reference_fixture.ps1");
    let child = ok(Command::new(&powershell)
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .args(["-WindowTitle", &title, "-Scenario", "normal"])
        .args(["-ReferenceMode", "Instrumented", "-StatePath"])
        .arg(&state)
        .arg("-EventPath")
        .arg(&events)
        .arg("-ReadyPath")
        .arg(&ready)
        .arg("-CommandPath")
        .arg(&command)
        .arg("-ArmPath")
        .arg(&arm)
        .arg("-ArmToken")
        .arg(&arm_token)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn());
    let process_id = child.id();
    let guard = FixtureGuard { child, root };
    wait_for(&ready, Duration::from_secs(15));

    let profile = profile();
    let now = unix_time_millis();
    let grant = grant(&profile, now);
    let executable_hash = sha256_bytes(&ok(std::fs::read(&powershell)));
    let title_hash = sha256_bytes(title.as_bytes());
    let pre = ok(collect_shadow_fixture_observation(
        &grant,
        &profile,
        &key().verifying_key(),
        now,
        "observation-shadow-pre".to_owned(),
        1,
        process_id,
        &executable_hash,
        &title_hash,
    ));
    assert_eq!(pre.observation_side_effect_count, 0);
    assert_eq!(pre.save_status_id, "idle");
    assert_eq!(pre.save_revision, 0);

    ok(std::fs::write(
        &command,
        br#"{"schema_version":1,"operation":"save"}"#,
    ));
    thread::sleep(Duration::from_millis(500));
    let still_gated: Value = ok(serde_json::from_slice(&ok(std::fs::read(&state))));
    assert_eq!(
        still_gated.get("save_status_id").and_then(Value::as_str),
        Some("idle")
    );
    assert!(!events.exists());
    ok(std::fs::write(
        &arm,
        ok(serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "operation": "enable_reference_action",
            "arm_token": arm_token,
        }))),
    ));
    wait_for_state(&state, "saved", Duration::from_secs(15));
    let post = ok(collect_shadow_fixture_observation(
        &grant,
        &profile,
        &key().verifying_key(),
        now.saturating_add(1_000),
        "observation-shadow-post".to_owned(),
        2,
        process_id,
        &executable_hash,
        &title_hash,
    ));
    assert_eq!(post.observation_side_effect_count, 0);
    assert_eq!(post.save_status_id, "saved");
    assert_eq!(post.save_revision, 1);
    assert_ne!(pre.saved_value_sha256, post.saved_value_sha256);

    let event = ok(std::fs::read_to_string(&events));
    assert_eq!(event.lines().count(), 1);
    assert!(!event.contains("D2I-SHADOW-APPROVED"));
    assert!(!event.contains("INITIAL-VALUE"));
    assert!(event.contains("\"keylogging_used\":false"));
    assert!(event.contains("\"screenshot_used\":false"));
    drop(guard);
}

fn wait_for(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.is_file() {
        assert!(Instant::now() < deadline, "timed out waiting for fixture");
        thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_state(path: &Path, expected: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                if value.get("save_status_id").and_then(Value::as_str) == Some(expected) {
                    return;
                }
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for state");
        thread::sleep(Duration::from_millis(50));
    }
}

fn powershell_path() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe")
}

fn unix_time_millis() -> u64 {
    ok(SystemTime::now().duration_since(UNIX_EPOCH)).as_millis() as u64
}
